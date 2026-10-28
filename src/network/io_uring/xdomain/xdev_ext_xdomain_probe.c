// SPDX-License-Identifier: GPL-2.0
/* Transport-owned startup challenge. Scratch never enters a business pool. */
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/random.h>
#include "xdev_ext_xdomain.h"
#include "xdev_ext_xdomain_probe_core.h"

/* A retained allocation has no executable pointer or reference to a link. */
struct xdev_ext_xd_probe_allocation {
	struct list_head node;
	struct pci_dev *pdev;
	u8 *cpu;
	dma_addr_t dma;
	u64 generation;
	size_t bytes;
};
struct xdev_ext_xd_probe_frame {
	struct ring_frame frame;
	struct xdev_ext_xd_link *xl;
	u64 epoch;
	u32 channel, slot, actual_len, flags;
	u8 sof, eof;
	bool pending, completed, processed, canceled;
};
struct xdev_ext_xd_probe_channel {
	struct xdev_ext_xd_probe_allocation *allocation;
	struct xdev_ext_xd_probe_frame frames[4];
	u8 nonce[16], peer_nonce[16], done_src[16], done_dst[16];
	u64 accepted, retired;
	bool ready_sent, peer_ready, peer_done, done_sent;
	bool rx_ping_ok, rx_pong_ok, tx_ping_done, tx_pong_done;
	bool reusable;
};
struct xdev_ext_xd_probe {
	u64 epoch, local_inc, remote_inc, events;
	unsigned long deadline;
	u32 channels;
	u8 direction;
	bool closed, control_ready, failure_counted;
	int first_error;
	struct xdev_ext_xd_probe_channel chan[XDEV_EXT_XD_MAX_CHANNELS];
};
static LIST_HEAD(xdev_ext_xd_probe_quarantine);
static DEFINE_SPINLOCK(xdev_ext_xd_probe_quarantine_lock);

static bool xdev_ext_xd_probe_closing(struct xdev_ext_xd_link *xl)
{
	return xl->going_away || xl->suspended || xl->gone || xl->nhi_gone;
}
/* xl->lock held. Events replace a pending deadline, never move its value. */
void xdev_ext_xd_probe_wake_locked(struct xdev_ext_xd_link *xl)
{
	if (xl->probe && !xl->probe->closed && !xdev_ext_xd_probe_closing(xl)) {
		xl->probe->events++;
		if (xl->probe_phase != XD_PROBE_VERIFIED || xl->probe->first_error)
			mod_delayed_work(system_long_wq, &xl->probe_work, 0);
	}
}
static void xdev_ext_xd_probe_error(struct xdev_ext_xd_probe *p, int error)
{
	if (!p->first_error)
		p->first_error = error;
}
/* The current native control frame owns these facts, even when its payload
 * identity was corrupted. Business control keeps its established policy once
 * startup has handed over the data rings.
 */
void xdev_ext_xd_probe_ctl_error_locked(struct xdev_ext_xd_link *xl, int error)
{
	struct xdev_ext_xd_probe *p = xl->probe;

	lockdep_assert_held(&xl->lock);
	if (!error || !p || p->closed || xl->probe_phase == XD_PROBE_VERIFIED ||
	    xdev_ext_xd_probe_closing(xl))
		return;
	xdev_ext_xd_probe_error(p, error);
	xdev_ext_xd_probe_wake_locked(xl);
}
void xdev_ext_xd_probe_ctl_complete_locked(struct xdev_ext_xd_link *xl, bool canceled)
{
	if (canceled && xl->probe && !xl->probe->closed)
		xdev_ext_xd_probe_error(xl->probe, -ECANCELED);
	xdev_ext_xd_probe_wake_locked(xl);
}
static void xdev_ext_xd_probe_callback(struct tb_ring *ring, struct ring_frame *frame,
				       bool canceled)
{
	struct xdev_ext_xd_probe_frame *f = container_of(frame, struct xdev_ext_xd_probe_frame, frame);
	struct xdev_ext_xd_link *xl = f->xl;
	struct xdev_ext_xd_probe *p;
	struct xdev_ext_xd_probe_channel *ch;
	unsigned long flags;

	(void)ring;
	spin_lock_irqsave(&xl->lock, flags);
	p = xl->probe;
	if (!p || f->epoch != p->epoch || f->channel >= p->channels || !f->pending)
		goto out;
	ch = &p->chan[f->channel];
	f->pending = false;
	f->completed = true;
	f->canceled = canceled;
	ch->retired++;
	if (f->slot < 2) {
		f->actual_len = canceled ? 0 : (frame->size ? frame->size : XD_PROBE_PONG_LEN);
		f->flags = frame->flags;
		f->sof = frame->sof;
		f->eof = frame->eof;
		if (!canceled) {
			int error = f->flags & RING_DESC_CRC_ERROR ? -EBADMSG :
				f->flags & RING_DESC_BUFFER_OVERRUN ? -EOVERFLOW :
				f->actual_len != XD_PROBE_PING_LEN && f->actual_len != XD_PROBE_PONG_LEN ? -EMSGSIZE :
				f->sof != XDEV_EXT_XD_PDF_START || f->eof != XDEV_EXT_XD_PDF_END ? -EPROTO : 0;

			if (error)
				xdev_ext_xd_probe_error(p, error);
		}
	} else if (!canceled) {
		if (f->slot == 2)
			ch->tx_ping_done = true;
		else
			ch->tx_pong_done = true;
	}
	if (canceled)
		xdev_ext_xd_probe_error(p, -ECANCELED);
	xdev_ext_xd_probe_wake_locked(xl);
out:
	spin_unlock_irqrestore(&xl->lock, flags);
}
/* Caller holds ctl_mutex and xl->lock. Reservation precedes native acceptance. */
static int xdev_ext_xd_probe_post(struct xdev_ext_xd_link *xl, u32 channel, u32 slot)
{
	struct xdev_ext_xd_probe *p = xl->probe;
	struct xdev_ext_xd_probe_channel *ch = &p->chan[channel];
	struct xdev_ext_xd_probe_frame *f = &ch->frames[slot];
	int ret;

	if (p->closed || xdev_ext_xd_probe_closing(xl) || f->pending || f->completed)
		return -ENOLINK;
	f->pending = true;
	ret = slot < 2 ? tb_ring_rx(xl->chan[channel].rx, &f->frame) :
			 tb_ring_tx(xl->chan[channel].tx, &f->frame);
	if (ret)
		f->pending = false;
	else
		ch->accepted++;
	return ret;
}
int xdev_ext_xd_probe_prepare(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_login *peer)
{
	struct xdev_ext_xd_probe *p = xl->probe;
	unsigned long flags;
	u64 epoch;
	u32 c, i;
	int direction, ret;

	lockdep_assert_held(&xl->ctl_mutex);
	direction = memcmp(xl->local_uuid.b, xl->remote_uuid.b, 16);
	if (!direction)
		return -EPROTO;
	if (!p) {
		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		spin_lock_irqsave(&xl->lock, flags);
		xl->probe = p;
		spin_unlock_irqrestore(&xl->lock, flags);
	}
	for (c = 0; c < p->channels; c++)
		if (p->chan[c].allocation && !p->chan[c].reusable)
			return -EBUSY;
	epoch = p->epoch + 1;
	if (!epoch)
		return -EOVERFLOW;
	p->epoch = epoch;
	p->channels = xl->channels;
	p->local_inc = xl->local_inc;
	p->remote_inc = peer->incarnation;
	p->direction = direction > 0;
	p->deadline = 0;
	p->closed = false;
	p->control_ready = false;
	p->failure_counted = false;
	p->first_error = 0;
	xl->probe_error = 0;
	xl->probe_phase = XD_PROBE_PREPOSTED;
	for (c = 0; c < p->channels; c++) {
		struct xdev_ext_xd_probe_channel *ch = &p->chan[c];
		struct xdev_ext_xd_probe_allocation *a = ch->allocation;

		memset(ch, 0, sizeof(*ch));
		ch->allocation = a;
		if (!a) {
			a = kzalloc(sizeof(*a), GFP_KERNEL);
			if (!a)
				return -ENOMEM;
			a->pdev = pci_dev_get(xl->nhi_pdev);
			a->bytes = XD_PROBE_BYTES;
			a->generation = epoch;
			INIT_LIST_HEAD(&a->node);
			a->cpu = dma_alloc_coherent(&a->pdev->dev, a->bytes, &a->dma, GFP_KERNEL);
			if (!a->cpu) {
				pci_dev_put(a->pdev);
				kfree(a);
				return -ENOMEM;
			}
			ch->allocation = a;
		}
		get_random_bytes(ch->nonce, sizeof(ch->nonce));
		if (!xdev_ext_xd_probe_nonce_nonzero(ch->nonce))
			get_random_bytes(ch->nonce, sizeof(ch->nonce));
		if (!xdev_ext_xd_probe_nonce_nonzero(ch->nonce))
			return -EAGAIN;
		for (i = 0; i < 4; i++)
			ch->frames[i] = (struct xdev_ext_xd_probe_frame) {
				.xl = xl, .epoch = epoch, .channel = c, .slot = i,
				.frame = { .buffer_phy = a->dma + i * XD_PROBE_PONG_LEN,
				.callback = xdev_ext_xd_probe_callback,
				.size = i == 2 ? XD_PROBE_PING_LEN : 0,
				.sof = XDEV_EXT_XD_PDF_START, .eof = XDEV_EXT_XD_PDF_END },
			};
		for (i = 0; i < 2; i++) {
			spin_lock_irqsave(&xl->lock, flags);
			ret = xdev_ext_xd_probe_post(xl, c, i);
			spin_unlock_irqrestore(&xl->lock, flags);
			if (ret)
				return ret;
		}
	}
	return 0;
}
void xdev_ext_xd_probe_login_exhausted(struct xdev_ext_xd_link *xl)
{
	unsigned long flags;

	lockdep_assert_held(&xl->ctl_mutex);
	spin_lock_irqsave(&xl->lock, flags);
	if (xl->probe && !xl->probe->closed && !xl->up) {
		xdev_ext_xd_probe_error(xl->probe, -ETIMEDOUT);
		xdev_ext_xd_probe_wake_locked(xl);
	}
	spin_unlock_irqrestore(&xl->lock, flags);
}
void xdev_ext_xd_probe_control_ready(struct xdev_ext_xd_link *xl)
{
	unsigned long flags;
	struct xdev_ext_xd_probe *p;

	lockdep_assert_held(&xl->ctl_mutex);
	spin_lock_irqsave(&xl->lock, flags);
	p = xl->probe;
	if (p && !p->closed && xl->up && p->local_inc == xl->local_inc &&
	    p->remote_inc == xl->remote_inc) {
		if (!p->control_ready) {
			p->control_ready = true;
			p->deadline = jiffies + msecs_to_jiffies(10000);
			xl->probe_phase = XD_PROBE_RUNNING;
		}
		xdev_ext_xd_probe_wake_locked(xl);
	}
	spin_unlock_irqrestore(&xl->lock, flags);
}
bool xdev_ext_xd_probe_ctl_rx(struct xdev_ext_xd_link *xl, const u8 *buf, u32 len)
{
	struct xdev_ext_xd_probe_msg m;
	struct xdev_ext_xd_probe *p;
	struct xdev_ext_xd_probe_channel *ch;
	unsigned long flags;
	int ret;

	if (len < 4 || xdev_ext_xd_get(buf, 4) != XD_PROBE_CTL_MAGIC)
		return false;
	ret = xdev_ext_xd_probe_ctl_decode(buf, len, xdev_ext_xd_crc, &m);
	spin_lock_irqsave(&xl->lock, flags);
	p = xl->probe;
	if (!p || p->closed || xdev_ext_xd_probe_closing(xl))
		goto out;
	/* Only a valid wire message can establish that it belongs to an old
	 * pair. Corrupted identity cannot hide the current frame's error.
	 */
	if (ret)
		goto error;
	if (m.src_inc != p->remote_inc || m.dst_inc != p->local_inc) {
		xl->probe_stale++;
		goto out;
	}
	if (m.channel >= p->channels || m.direction != (p->direction ^ 1)) {
		ret = -EPROTO;
		goto error;
	}
	ch = &p->chan[m.channel];
	if (m.type == XD_PROBE_READY) {
		if (ch->peer_ready && memcmp(ch->peer_nonce, m.src_nonce, 16)) {
			ret = -EBADMSG;
			goto error;
		}
		memcpy(ch->peer_nonce, m.src_nonce, 16);
		ch->peer_ready = true;
	} else {
		if (memcmp(ch->nonce, m.dst_nonce, 16) ||
		    (ch->peer_ready && memcmp(ch->peer_nonce, m.src_nonce, 16)) ||
		    (ch->peer_done && (memcmp(ch->done_src, m.src_nonce, 16) ||
				     memcmp(ch->done_dst, m.dst_nonce, 16)))) {
			ret = -EBADMSG;
			goto error;
		}
		memcpy(ch->done_src, m.src_nonce, 16);
		memcpy(ch->done_dst, m.dst_nonce, 16);
		ch->peer_done = true;
	}
	xdev_ext_xd_probe_wake_locked(xl);
	goto out;
error:
	xdev_ext_xd_probe_error(p, ret);
	xdev_ext_xd_probe_wake_locked(xl);
out:
	spin_unlock_irqrestore(&xl->lock, flags);
	return true;
}
static struct xdev_ext_xd_probe_msg xdev_ext_xd_probe_message(struct xdev_ext_xd_probe *p,
							     u32 c, u8 type, bool ready)
{
	struct xdev_ext_xd_probe_msg m = { .src_inc = p->local_inc, .dst_inc = p->remote_inc,
		.type = type, .channel = c, .direction = p->direction,
		.origin = p->direction ^ (type == XD_PROBE_PONG) };

	memcpy(m.src_nonce, p->chan[c].nonce, 16);
	if (!ready)
		memcpy(m.dst_nonce, p->chan[c].peer_nonce, 16);
	return m;
}
/* ctl_mutex held. Heavy payload checks deliberately run outside xl->lock. */
static int xdev_ext_xd_probe_process_rx(struct xdev_ext_xd_link *xl, u32 c, u32 slot)
{
	struct xdev_ext_xd_probe *p = xl->probe;
	struct xdev_ext_xd_probe_channel *ch = &p->chan[c];
	struct xdev_ext_xd_probe_frame *f = &ch->frames[slot];
	struct xdev_ext_xd_probe_msg m;
	unsigned long flags;
	bool process;
	int ret;

	spin_lock_irqsave(&xl->lock, flags);
	process = f->completed && !f->processed && ch->peer_ready;
	if (process)
		f->processed = true;
	spin_unlock_irqrestore(&xl->lock, flags);
	if (!process)
		return 0;
	if (f->canceled)
		return -ECANCELED;
	ret = xdev_ext_xd_rx_frame(f->flags, f->actual_len == 4096 ? 0 : f->actual_len,
				 f->actual_len);
	if (ret)
		return ret;
	if (f->sof != XDEV_EXT_XD_PDF_START || f->eof != XDEV_EXT_XD_PDF_END)
		return -EPROTO;
	if (f->actual_len != XD_PROBE_PING_LEN && f->actual_len != XD_PROBE_PONG_LEN)
		return -EMSGSIZE;
	ret = xdev_ext_xd_probe_data_decode(ch->allocation->cpu + slot * 4096,
					 f->actual_len, xdev_ext_xd_crc, &m);
	if (ret)
		return ret;
	if (m.src_inc != p->remote_inc || m.dst_inc != p->local_inc) {
		spin_lock_irqsave(&xl->lock, flags);
		xl->probe_stale++;
		spin_unlock_irqrestore(&xl->lock, flags);
		return 0;
	}
	if (m.channel != c || m.direction != (p->direction ^ 1))
		return -EPROTO;
	if (memcmp(m.src_nonce, ch->peer_nonce, 16) || memcmp(m.dst_nonce, ch->nonce, 16))
		return -EBADMSG;
	spin_lock_irqsave(&xl->lock, flags);
	if (m.type == XD_PROBE_PING) {
		ret = ch->rx_ping_ok ? -EPROTO : 0;
		ch->rx_ping_ok = true;
	} else {
		ret = ch->rx_pong_ok ? -EPROTO : 0;
		ch->rx_pong_ok = true;
	}
	spin_unlock_irqrestore(&xl->lock, flags);
	return ret;
}
void xdev_ext_xd_probe_work(struct work_struct *work)
{
	struct xdev_ext_xd_link *xl = container_of(to_delayed_work(work), struct xdev_ext_xd_link, probe_work);
	struct xdev_ext_xd_probe *p;
	unsigned long flags;
	u32 c, i, required;
	u64 events;
	int ret = 0;

	mutex_lock(&xl->ctl_mutex);
	p = xl->probe;
	if (!p || p->closed || xdev_ext_xd_probe_closing(xl) ||
	    p->local_inc != xl->local_inc)
		goto out;
	spin_lock_irqsave(&xl->lock, flags);
	events = p->events;
	if (p->control_ready && xl->probe_phase != XD_PROBE_VERIFIED &&
	    time_after_eq(jiffies, p->deadline))
		xdev_ext_xd_probe_error(p, -ETIMEDOUT);
	ret = p->first_error;
	spin_unlock_irqrestore(&xl->lock, flags);
	if (ret)
		goto failed;
	if (xl->probe_phase == XD_PROBE_VERIFIED)
		goto out;
	for (c = 0; c < p->channels; c++) {
		struct xdev_ext_xd_probe_channel *ch = &p->chan[c];
		struct xdev_ext_xd_probe_msg m;
		u8 control[128];
		bool send, local_done;

		if (!p->control_ready)
			continue;
		m = xdev_ext_xd_probe_message(p, c, XD_PROBE_READY, true);
		xdev_ext_xd_probe_ctl_encode(control, &m, xdev_ext_xd_crc);
		spin_lock_irqsave(&xl->lock, flags);
		if (!ch->ready_sent) {
			ret = xdev_ext_xd_probe_ctl_tx_locked(xl, control);
			if (!ret)
				ch->ready_sent = true;
		}
		if (ret == -EAGAIN)
			ret = 0;
		send = ch->peer_ready;
		if (ch->peer_done && ch->peer_ready && memcmp(ch->done_src, ch->peer_nonce, 16))
			ret = -EBADMSG;
		spin_unlock_irqrestore(&xl->lock, flags);
		if (ret)
			goto failed;
		if (!send)
			continue;
		for (i = 0; i < 2; i++) {
			ret = xdev_ext_xd_probe_process_rx(xl, c, i);
			if (ret)
				goto failed;
		}
		for (i = 2; i < 4; i++) {
			spin_lock_irqsave(&xl->lock, flags);
			send = !ch->frames[i].pending && !ch->frames[i].completed &&
				(i == 2 || ch->rx_ping_ok) && !p->first_error;
			spin_unlock_irqrestore(&xl->lock, flags);
			if (!send)
				continue;
			m = xdev_ext_xd_probe_message(p, c, i == 2 ? XD_PROBE_PING : XD_PROBE_PONG, false);
			ret = xdev_ext_xd_probe_data_encode(ch->allocation->cpu + i * 4096,
							 i == 2 ? 128 : 4096, &m, xdev_ext_xd_crc);
			if (ret)
				goto failed;
			spin_lock_irqsave(&xl->lock, flags);
			ret = xdev_ext_xd_probe_post(xl, c, i);
			spin_unlock_irqrestore(&xl->lock, flags);
			if (ret)
				goto failed;
		}
		spin_lock_irqsave(&xl->lock, flags);
		local_done = ch->rx_ping_ok && ch->rx_pong_ok && ch->tx_ping_done &&
			ch->tx_pong_done && ch->accepted == ch->retired && !p->first_error;
		spin_unlock_irqrestore(&xl->lock, flags);
		if (local_done) {
			m = xdev_ext_xd_probe_message(p, c, XD_PROBE_DONE, false);
			xdev_ext_xd_probe_ctl_encode(control, &m, xdev_ext_xd_crc);
			spin_lock_irqsave(&xl->lock, flags);
			if (!ch->done_sent) {
				ret = xdev_ext_xd_probe_ctl_tx_locked(xl, control);
				if (!ret)
					ch->done_sent = true;
			}
			if (!p->first_error && ch->done_sent && ch->peer_done && xl->up &&
			    !xdev_ext_xd_probe_closing(xl) && p->local_inc == xl->local_inc &&
			    p->remote_inc == xl->remote_inc)
				xl->data_verified_mask |= BIT(c);
			spin_unlock_irqrestore(&xl->lock, flags);
			if (ret == -EAGAIN)
				ret = 0;
			if (ret)
				goto failed;
		}
	}
	required = BIT(p->channels) - 1;
	spin_lock_irqsave(&xl->lock, flags);
	ret = p->first_error;
	if (!ret && xl->data_verified_mask == required) {
		if (xl->probe_phase != XD_PROBE_VERIFIED)
			xl->probe_successes++;
		xl->probe_phase = XD_PROBE_VERIFIED;
		xl->retry_failures = 0;
		xl->retry_delay_ms = 0;
		xl->retry_pending = false;
	} else if (!ret && p->control_ready) {
		mod_delayed_work(system_long_wq, &xl->probe_work,
				 p->events != events ? 0 :
				 (time_before(jiffies, p->deadline) ? p->deadline - jiffies : 0));
	}
	spin_unlock_irqrestore(&xl->lock, flags);
	if (!ret)
		goto out;
failed:
	spin_lock_irqsave(&xl->lock, flags);
	xdev_ext_xd_probe_error(p, ret);
	xl->probe_error = p->first_error;
	xl->probe_phase = XD_PROBE_FAILED;
	xl->data_verified_mask = 0;
	if (!p->failure_counted) {
		p->failure_counted = true;
		xl->probe_failures++;
		xl->retry_failures++;
		xl->retry_delay_ms = xl->retry_delay_ms ?
			min_t(u32, xl->retry_delay_ms * 2, XDEV_EXT_XD_RELOGIN_MS * XDEV_EXT_XD_LOGIN_RETRIES) : XDEV_EXT_XD_RELOGIN_MS;
		xl->retry_pending = true;
		xl->retry_after = jiffies + msecs_to_jiffies(xl->retry_delay_ms);
		if (xl->retry_failures == XDEV_EXT_XD_LOGIN_RETRIES)
			xl->retries_exhausted++;
	}
	xl->down_err = p->first_error;
	xl->down_local_inc = p->local_inc;
	queue_work(system_long_wq, &xl->down_work);
	spin_unlock_irqrestore(&xl->lock, flags);
out:
	mutex_unlock(&xl->ctl_mutex);
}
void xdev_ext_xd_probe_close(struct xdev_ext_xd_link *xl)
{
	unsigned long flags;

	spin_lock_irqsave(&xl->lock, flags);
	xl->data_verified_mask = 0;
	if (xl->probe)
		xl->probe->closed = true;
	if (xl->probe_phase != XD_PROBE_FAILED)
		xl->probe_phase = XD_PROBE_CLOSED;
	spin_unlock_irqrestore(&xl->lock, flags);
	cancel_delayed_work(&xl->probe_work);
}
u64 xdev_ext_xd_probe_retire(struct xdev_ext_xd_link *xl, u32 stopped_rx,
				 u32 stopped_tx, bool requester_gone)
{
	struct xdev_ext_xd_probe *p = xl->probe;
	u64 retained = 0;
	u32 c;
	unsigned long flags;

	if (!p)
		return 0;
	for (c = 0; c < p->channels; c++) {
		struct xdev_ext_xd_probe_channel *ch = &p->chan[c];
		struct xdev_ext_xd_probe_allocation *a = ch->allocation;

		if (!a)
			continue;
		ch->reusable = !ch->accepted || (!requester_gone &&
			(stopped_rx & BIT(c)) && (stopped_tx & BIT(c)) &&
			ch->accepted == ch->retired);
		if (ch->reusable)
			continue;
		retained += a->bytes;
		spin_lock_irqsave(&xdev_ext_xd_probe_quarantine_lock, flags);
		list_add_tail(&a->node, &xdev_ext_xd_probe_quarantine);
		spin_unlock_irqrestore(&xdev_ext_xd_probe_quarantine_lock, flags);
		ch->allocation = NULL;
	}
	return retained;
}
void xdev_ext_xd_probe_free(struct xdev_ext_xd_link *xl)
{
	struct xdev_ext_xd_probe *p = xl->probe;
	u32 c;

	if (!p)
		return;
	for (c = 0; c < p->channels; c++) {
		struct xdev_ext_xd_probe_allocation *a = p->chan[c].allocation;

		if (!a)
			continue;
		dma_free_coherent(&a->pdev->dev, a->bytes, a->cpu, a->dma);
		pci_dev_put(a->pdev);
		kfree(a);
	}
	xl->probe = NULL;
	kfree(p);
}

ssize_t xdev_ext_xd_probe_show(struct xdev_ext_xd_link *xl, char *buf)
{
	struct xdev_ext_xd_probe *p = xl->probe;
	unsigned long flags;
	ssize_t len;
	u32 c;

	lockdep_assert_held(&xl->ctl_mutex);
	spin_lock_irqsave(&xl->lock, flags);
	len = sysfs_emit(buf, "version=1 control_ready=%u data_verified_mask=%u required_mask=%u phase=%u error=%d backing_qualified=not_queried local_inc=%llu remote_inc=%llu startup_successes=%llu startup_failures=%llu stale=%llu\n",
		xl->up, xl->data_verified_mask, (u32)(BIT(xl->channels) - 1), xl->probe_phase,
		xl->probe_error, xl->local_inc, xl->remote_inc, xl->probe_successes,
		xl->probe_failures, xl->probe_stale);
	if (p)
		for (c = 0; c < p->channels; c++) {
			struct xdev_ext_xd_probe_channel *ch = &p->chan[c];

			len += sysfs_emit_at(buf, len,
				"channel=%u rx0_actual_len=%u rx0_flags=%u rx0_canceled=%u rx1_actual_len=%u rx1_flags=%u rx1_canceled=%u rx_ping_ok=%u rx_pong_ok=%u tx_ping_submitted_len=%u tx_pong_submitted_len=%u tx_ping_complete=%u tx_pong_complete=%u\n",
				c, ch->frames[0].actual_len, ch->frames[0].flags, ch->frames[0].canceled,
				ch->frames[1].actual_len, ch->frames[1].flags, ch->frames[1].canceled,
				ch->rx_ping_ok, ch->rx_pong_ok,
				ch->frames[2].pending || ch->frames[2].completed ? 128 : 0,
				ch->frames[3].pending || ch->frames[3].completed ? 4096 : 0,
				ch->tx_ping_done, ch->tx_pong_done);
		}
	spin_unlock_irqrestore(&xl->lock, flags);
	return len;
}
