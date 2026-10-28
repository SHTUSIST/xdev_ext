// SPDX-License-Identifier: GPL-2.0
/* XDOMAIN device vtable: NHI data rings carry only device-memory elements;
 * a host-memory control ring pair carries protocol messages. */
#include <linux/bitmap.h>
#include <linux/crc32.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/xdev_ext_requester_retention.h>
#include "xdev_ext_xdomain.h"
#include "xdev_ext_xdomain_probe_core.h"

static_assert(sizeof(struct ring_frame) <= XDEV_EXT_NET_DEV_AREA);
static_assert(XDEV_EXT_XD_DESC_CRC_ERROR == RING_DESC_CRC_ERROR &&
	      XDEV_EXT_XD_DESC_BUFFER_OVERRUN == RING_DESC_BUFFER_OVERRUN);
#define XDEV_EXT_XD_CTL_BUF	4096U
#define XDEV_EXT_XD_CTL_TX_BUF	XDEV_EXT_XD_MSG_LEN

u32 xdev_ext_xd_crc(u32 crc, const void *p, size_t len) { return crc32c(crc, p, len); }

/* xdomain ring begin */
enum xdev_ext_xd_native_disposition {
	XDEV_EXT_XD_NATIVE_UNUSED,
	XDEV_EXT_XD_NATIVE_STOPPED,
	XDEV_EXT_XD_NATIVE_UNKNOWN,
};
struct xdev_ext_xd_native {
	struct tb_ring **slot;
	enum xdev_ext_xd_native_disposition disposition;
	bool started;
};
struct xdev_ext_xd_rings {
	/* Path teardown follows UNKNOWN retirement, so keep scalar native HopIDs
	 * independently of the consumed ring objects until paths_disable.
	 */
	int ctl_tx_hop, ctl_rx_hop;
	int data_tx_hop[XDEV_EXT_XD_MAX_CHANNELS];
	int data_rx_hop[XDEV_EXT_XD_MAX_CHANNELS];
	struct xdev_ext_xd_native native[2 + 2 * XDEV_EXT_XD_MAX_CHANNELS];
	u32 count;
	u64 generation;
	struct xdev_ext_requester_retention *retention;
	u64 retained_bytes;
	bool starting, retention_sealed;
};
/* Each direction is one coherent allocation. A canceled accepted slot taints
 * the whole allocation. The record is prepared before any DMA acceptance.
 * Once quarantined this object has no link, frame or executable pointer.
 */
struct xdev_ext_xd_ctl_allocation {
	struct list_head node;
	struct pci_dev *pdev;
	u8 *cpu;
	dma_addr_t dma;
	size_t bytes;
	u64 generation;
	u64 accepted, retired;
	bool pending[XDEV_EXT_XD_CTL_RING];
	bool unknown, callbacks_drained, ever_started, rx;
};
static LIST_HEAD(xdev_ext_xd_ctl_quarantine);
static DEFINE_SPINLOCK(xdev_ext_xd_ctl_quarantine_lock);

static void xdev_ext_xd_ctl_tx_cb(struct tb_ring *, struct ring_frame *, bool);
static void xdev_ext_xd_ctl_rx_cb(struct tb_ring *, struct ring_frame *, bool);

static bool xdev_ext_xd_closing(struct xdev_ext_xd_link *xl)
{
	return xl->going_away || xl->suspended || xl->gone || xl->nhi_gone;
}

/* Also read by post/callback paths under xl->lock. */
static void xdev_ext_xd_mark_nhi_gone(struct xdev_ext_xd_link *xl)
{
	unsigned long flags;

	spin_lock_irqsave(&xl->lock, flags);
	xl->nhi_gone = true;
	spin_unlock_irqrestore(&xl->lock, flags);
}

static int xdev_ext_xd_ctl_alloc(struct xdev_ext_xd_link *xl, bool rx)
{
	struct xdev_ext_xd_ctl_allocation *a;
	struct xdev_ext_xd_ctl_frame *frames = rx ? xl->ctl_rx_frames : xl->ctl_tx_frames;
	u32 stride = rx ? XDEV_EXT_XD_CTL_BUF : XDEV_EXT_XD_CTL_TX_BUF;
	u32 i;

	if (rx ? !!xl->ctl_rx_alloc : !!xl->ctl_tx_alloc)
		return 0;
	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;
	a->pdev = pci_dev_get(xl->nhi_pdev);
	a->bytes = XDEV_EXT_XD_CTL_RING * stride;
	a->rx = rx;
	a->cpu = dma_alloc_coherent(&a->pdev->dev, a->bytes, &a->dma, GFP_KERNEL);
	if (!a->cpu) {
		pci_dev_put(a->pdev);
		kfree(a);
		return -ENOMEM;
	}
	a->generation = ++xl->rings->generation;
	a->callbacks_drained = true;
	INIT_LIST_HEAD(&a->node);
	for (i = 0; i < XDEV_EXT_XD_CTL_RING; i++)
		frames[i] = (struct xdev_ext_xd_ctl_frame) {
			.xl = xl, .index = i, .buf = a->cpu + i * stride,
			.frame = { .buffer_phy = a->dma + i * stride,
			.callback = rx ? xdev_ext_xd_ctl_rx_cb : xdev_ext_xd_ctl_tx_cb },
		};
	if (rx) {
		xl->ctl_rx_alloc = a;
		xl->ctl_rx_buf = a->cpu;
		xl->ctl_rx_dma = a->dma;
	} else {
		xl->ctl_tx_alloc = a;
		xl->ctl_tx_buf = a->cpu;
		xl->ctl_tx_dma = a->dma;
		bitmap_fill(xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING);
	}
	return 0;
}

/* Only after the native callback barrier, never from a frame callback. */
static void xdev_ext_xd_ctl_release(struct xdev_ext_xd_link *xl, bool rx)
{
	struct xdev_ext_xd_ctl_allocation **ap = rx ? &xl->ctl_rx_alloc : &xl->ctl_tx_alloc;
	struct xdev_ext_xd_ctl_allocation *a = *ap;
	unsigned long flags;

	if (!a)
		return;
	if (a->accepted != a->retired)
		a->unknown = true;
	if (a->unknown) {
		xl->rings->retained_bytes += a->bytes;
		spin_lock_irqsave(&xdev_ext_xd_ctl_quarantine_lock, flags);
		list_add_tail(&a->node, &xdev_ext_xd_ctl_quarantine);
		spin_unlock_irqrestore(&xdev_ext_xd_ctl_quarantine_lock, flags);
	} else {
		dma_free_coherent(&a->pdev->dev, a->bytes, a->cpu, a->dma);
		pci_dev_put(a->pdev);
		kfree(a);
	}
	*ap = NULL;
	if (rx) {
		xl->ctl_rx_buf = NULL;
		xl->ctl_rx_dma = 0;
	} else {
		xl->ctl_tx_buf = NULL;
		xl->ctl_tx_dma = 0;
		bitmap_zero(xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING);
	}
}

static struct ring_frame *xdev_ext_xd_frame(struct xdev_ext_net_elem *e)
{
	return (struct ring_frame *)e->dev.bytes;
}
static struct xdev_ext_net_elem *xdev_ext_xd_elem(struct ring_frame *f)
{
	return container_of((void *)f, struct xdev_ext_net_elem, dev);
}

static void xdev_ext_xd_tx_cb(struct tb_ring *ring, struct ring_frame *f, bool canceled)
{
	struct xdev_ext_net_elem *e = xdev_ext_xd_elem(f);

	(void)ring;
	/* Canceled frames may have been read in part or not at all: unknown. */
	xdev_ext_net_elem_done(e, canceled ? -ECANCELED : 0, canceled ? 0 : e->len, 0, !canceled);
}

static void xdev_ext_xd_rx_cb(struct tb_ring *ring, struct ring_frame *f, bool canceled)
{
	struct xdev_ext_net_elem *e = xdev_ext_xd_elem(f);
	int status;

	(void)ring;
	if (canceled) {
		xdev_ext_net_elem_done(e, -ECANCELED, 0, 0, false);
		return;
	}
	status = xdev_ext_xd_rx_frame(f->flags, f->size, e->len);
	if (status == -EBADMSG)
		e->dev_flags |= 1;	/* counted as crc_errors in the CQE */
	xdev_ext_net_elem_done(e, status, status ? 0 : e->len, 0, true);
}

static int xdev_ext_xd_post(void *lk, struct xdev_ext_net_elem *e, u32 n, bool rx)
{
	struct xdev_ext_xd_ep *ep = lk;
	struct xdev_ext_xd_link *xl = ep->xl;
	unsigned long flags;
	struct tb_ring *ring;
	u32 i;
	int ret = 0;

	if (!n || n > XDEV_EXT_XDOMAIN_MAX_ELEMS)
		return -EINVAL;
	for (i = 0; i < n; i++)
		if (!e[i].len || e[i].len > XDEV_EXT_XDOMAIN_MAX_FRAME ||
		    (rx && e[i].buf_len != XDEV_EXT_XDOMAIN_MAX_FRAME))
			return -EINVAL;
	spin_lock_irqsave(&xl->lock, flags);
	/* Rings exist and run only while up; gone: freed in remove; detached:
	 * this stage belongs to an earlier incarnation. */
	if (!xl->up || xdev_ext_xd_closing(xl) || ep->detached) {
		ret = -ENOLINK;
		goto out;
	}
	if (!(xl->data_verified_mask & BIT(ep->chan))) {
		ret = -EAGAIN;
		goto out;
	}
	ring = rx ? xl->chan[ep->chan].rx : xl->chan[ep->chan].tx;
	for (i = 0; i < n; i++) {
		struct ring_frame *f = xdev_ext_xd_frame(&e[i]);

		*f = (struct ring_frame){
			.buffer_phy = e[i].lease.lease.dma_address,
			.callback = rx ? xdev_ext_xd_rx_cb : xdev_ext_xd_tx_cb,
			.size = rx || e[i].len == XDEV_EXT_XDOMAIN_MAX_FRAME ? 0 : e[i].len,
			.sof = XDEV_EXT_XD_PDF_START,
			.eof = XDEV_EXT_XD_PDF_END,
		};
		/* The native API only rejects a stopped ring. Stop clears up
		 * under xl->lock before touching any ring, so this whole group
		 * shares one running window. Hardware fullness queues the same
		 * preallocated frame; it is not a submission failure.
		 */
		WARN_ON_ONCE(rx ? tb_ring_rx_more(ring, f) : tb_ring_tx_more(ring, f));
	}
	tb_ring_notify(ring);
out:
	spin_unlock_irqrestore(&xl->lock, flags);
	return ret;
}
static int xdev_ext_xd_post_tx(void *lk, struct xdev_ext_net_elem *e, u32 n)
{
	return xdev_ext_xd_post(lk, e, n, false);
}
static int xdev_ext_xd_post_rx(void *lk, struct xdev_ext_net_elem *e, u32 n)
{
	return xdev_ext_xd_post(lk, e, n, true);
}

static void xdev_ext_xd_ctl_tx_cb(struct tb_ring *ring, struct ring_frame *f, bool canceled)
{
	struct xdev_ext_xd_ctl_frame *cf = container_of(f, struct xdev_ext_xd_ctl_frame, frame);
	struct xdev_ext_xd_link *xl = cf->xl;
	struct xdev_ext_xd_ctl_allocation *a;
	unsigned long flags;

	(void)ring;
	spin_lock_irqsave(&xl->lock, flags);
	a = xl->ctl_tx_alloc;
	if (a && a->pending[cf->index]) {
		a->pending[cf->index] = false;
		a->retired++;
		if (canceled)
			a->unknown = true;
		else if (!xdev_ext_xd_closing(xl) && xl->up && !a->unknown)
			__set_bit(cf->index, xl->ctl_tx_free);
	}
	xdev_ext_xd_probe_ctl_complete_locked(xl, canceled);
	spin_unlock_irqrestore(&xl->lock, flags);
}

/* xl->lock covers reservation, native acceptance, and callback retirement. */
static int xdev_ext_xd_ctl_tx_locked(struct xdev_ext_xd_link *xl, const u8 *msg, u32 len)
{
	struct xdev_ext_xd_ctl_allocation *a = xl->ctl_tx_alloc;
	struct xdev_ext_xd_ctl_frame *cf;
	unsigned int i;
	int ret;

	if (len != XDEV_EXT_XD_MSG_LEN)
		return -EINVAL;
	if (!a || a->unknown)
		return -ENOLINK;
	i = find_first_bit(xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING);
	if (i >= XDEV_EXT_XD_CTL_RING)
		return -EAGAIN;
	__clear_bit(i, xl->ctl_tx_free);
	cf = &xl->ctl_tx_frames[i];
	memcpy(cf->buf, msg, len);
	cf->frame.size = len;
	cf->frame.sof = XDEV_EXT_XD_PDF_START;
	cf->frame.eof = XDEV_EXT_XD_PDF_END;
	a->pending[i] = true;
	ret = tb_ring_tx(xl->ctl_tx, &cf->frame);
	if (ret) {
		a->pending[i] = false;
		__set_bit(i, xl->ctl_tx_free);
		return ret;
	}
	a->accepted++;
	a->callbacks_drained = false;
	return 0;
}

int xdev_ext_xd_probe_ctl_tx_locked(struct xdev_ext_xd_link *xl, const u8 buf[128])
{
	lockdep_assert_held(&xl->lock);
	if (!xl->probe || !xl->up || xdev_ext_xd_closing(xl))
		return -ENOLINK;
	if (xdev_ext_xd_get(buf, 4) != XD_PROBE_CTL_MAGIC ||
	    xdev_ext_xd_get(buf + 8, 8) != xl->local_inc ||
	    xdev_ext_xd_get(buf + 16, 8) != xl->remote_inc || buf[6] >= xl->channels)
		return -ESTALE;
	return xdev_ext_xd_ctl_tx_locked(xl, buf, 128);
}

/* Raw family primitive (CHANNEL): send one already encoded message. */
static int xdev_ext_xd_ctl_send(void *lk, const u8 *msg, u32 len)
{
	struct xdev_ext_xd_ep *ep = lk;
	struct xdev_ext_xd_link *xl = ep->xl;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&xl->lock, flags);
	ret = !xl->up || xdev_ext_xd_closing(xl) || ep->detached ? -ENOLINK : xdev_ext_xd_ctl_tx_locked(xl, msg, len);
	spin_unlock_irqrestore(&xl->lock, flags);
	return ret;
}

int xdev_ext_xd_msg_send(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_ep *ep, u32 chan,
			 struct xdev_ext_xd_msg *m)
{
	u8 buf[XDEV_EXT_XD_MSG_LEN];
	unsigned long flags;
	int ret;

	if (chan >= xl->channels)
		return -EINVAL;
	spin_lock_irqsave(&xl->lock, flags);
	if (!xl->up || xdev_ext_xd_closing(xl) || (ep && ep->detached)) {
		ret = -ENOLINK;
		goto out;
	}
	m->src_inc = xl->local_inc;
	m->dst_inc = xl->remote_inc;
	m->channel = chan;
	/* data_seq: elements announced on this channel before this RTS (section 4.8). */
	m->data_seq = m->type == XDEV_EXT_XD_RTS ? xl->chan[chan].announced : 0;
	ret = xdev_ext_xd_msg_encode(buf, m, xdev_ext_xd_crc);
	if (!ret)
		ret = xdev_ext_xd_ctl_tx_locked(xl, buf, sizeof(buf));
	if (!ret && m->type == XDEV_EXT_XD_RTS)
		xl->chan[chan].announced += m->count;
out:
	spin_unlock_irqrestore(&xl->lock, flags);
	return ret;
}

int xdev_ext_xd_seq_consume(struct xdev_ext_xd_link *xl, u32 chan, u64 data_seq, u32 count)
{
	unsigned long flags;
	int ret = 0;

	if (chan >= xl->channels)
		return -EINVAL;
	spin_lock_irqsave(&xl->lock, flags);
	if (!xl->up || xdev_ext_xd_closing(xl))
		ret = -ENOLINK;
	else if (data_seq != xl->chan[chan].consumed)
		ret = -EPROTO;
	else
		xl->chan[chan].consumed += count;
	spin_unlock_irqrestore(&xl->lock, flags);
	return ret;
}

/* ep_mutex held: no receiving worker can retain this RTS obligation. */
void xdev_ext_xd_refuse_rts(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_msg *rts)
{
	struct xdev_ext_xd_msg f = { .type = XDEV_EXT_XD_FAIL, .stream = rts->stream,
				     .group = rts->group, .status = ENODEV };
	unsigned long flags;
	u64 consumed;
	int ret;

	spin_lock_irqsave(&xl->lock, flags);
	/* Teardown can retain records from an incarnation already ended by
	 * link down. They cannot debit, or fail, its successor. ep_mutex keeps
	 * the successor from starting until this refusal has finished. */
	if (!xl->up || xdev_ext_xd_closing(xl) ||
	    rts->src_inc != xl->remote_inc || rts->dst_inc != xl->local_inc) {
		spin_unlock_irqrestore(&xl->lock, flags);
		return;
	}
	consumed = xl->chan[rts->channel].consumed;
	spin_unlock_irqrestore(&xl->lock, flags);
	/* Already refused records are informational. No second sequence debit. */
	if (rts->data_seq < consumed) return;
	if (rts->data_seq != consumed || rts->count > ~0ULL - consumed ||
	    rts->group > ~0ULL - XDEV_EXT_REL_MAX_WINDOW) {
		xdev_ext_xd_link_fail(xl, NULL, -EPROTO); return;
	}
	/* A new binding initializes its own stream/window. This finite credit
	 * closes only this sender's refused group; it is not a future promise. */
	f.credit = rts->group + XDEV_EXT_REL_MAX_WINDOW;
	ret = xdev_ext_xd_msg_send(xl, NULL, rts->channel, &f);
	if (!ret) ret = xdev_ext_xd_seq_consume(xl, rts->channel, rts->data_seq, rts->count);
	/* There is no bound stage to retain a reply obligation. Failure must be
	 * terminal and observable rather than silently dropping the RTS. */
	if (ret) xdev_ext_xd_link_fail(xl, NULL, ret);
}

/* Control RX callback, ring work (process context): decode, check the link
 * incarnation, hand to the bound stage under ep_mutex, repost the buffer. */
static void xdev_ext_xd_ctl_dispatch(struct xdev_ext_xd_link *xl, const u8 *buf, u32 len)
{
	struct xdev_ext_xd_msg m;
	struct xdev_ext_xd_ep *ep;
	u64 local, remote;
	unsigned long flags;
	bool to_rx;

	spin_lock_irqsave(&xl->lock, flags);
	local = xl->local_inc;
	remote = xl->remote_inc;
	if (len >= XDEV_EXT_XD_MSG_LEN &&
	    (u32)xdev_ext_xd_get(buf + 124, 4) != (u32)~xdev_ext_xd_crc(~0U, buf, 124))
		xl->crc_errors++;
	if (len >= 5 && buf[4] != XDEV_EXT_XD_MSG_VERSION)
		xl->version_errors++;
	spin_unlock_irqrestore(&xl->lock, flags);
	if (xdev_ext_xd_msg_decode(buf, len, xdev_ext_xd_crc, &m) ||
	    xdev_ext_xd_msg_for_us(&m, local, remote, xl->channels)) {
		WRITE_ONCE(xl->ctl_dropped, xl->ctl_dropped + 1);
		return;
	}
	/* RTS and CANCEL go to the receiving stage, everything else to the sender. */
	to_rx = m.type == XDEV_EXT_XD_RTS || m.type == XDEV_EXT_XD_CANCEL;
	mutex_lock(&xl->ep_mutex);
	spin_lock_irqsave(&xl->lock, flags);
	if (!xl->up || xdev_ext_xd_closing(xl) ||
	    local != xl->local_inc || remote != xl->remote_inc) {
		spin_unlock_irqrestore(&xl->lock, flags);
		mutex_unlock(&xl->ep_mutex);
		return;
	}
	spin_unlock_irqrestore(&xl->lock, flags);
	ep = xl->chan[m.channel].ep[to_rx];
	if (ep)
		xdev_ext_xd_class_ctl(ep->st, &m);
	else if (m.type == XDEV_EXT_XD_RTS)
		xdev_ext_xd_refuse_rts(xl, &m);
	else
		WRITE_ONCE(xl->ctl_dropped, xl->ctl_dropped + 1);
	mutex_unlock(&xl->ep_mutex);
}

static void xdev_ext_xd_ctl_rx_cb(struct tb_ring *ring, struct ring_frame *f, bool canceled)
{
	struct xdev_ext_xd_ctl_frame *cf = container_of(f, struct xdev_ext_xd_ctl_frame, frame);
	struct xdev_ext_xd_link *xl = cf->xl;
	struct xdev_ext_xd_ctl_allocation *a;
	unsigned long flags;
	bool dispatch = false;

	spin_lock_irqsave(&xl->lock, flags);
	a = xl->ctl_rx_alloc;
	if (!canceled && (f->flags & RING_DESC_CRC_ERROR))
		xl->crc_errors++;
	if (a && a->pending[cf->index]) {
		a->pending[cf->index] = false;
		a->retired++;
		if (canceled) {
			a->unknown = true;
			xdev_ext_xd_probe_ctl_error_locked(xl, -ECANCELED);
		} else {
			u32 actual_len = f->size ? f->size : XDEV_EXT_XD_CTL_BUF;
			int error = f->flags & RING_DESC_CRC_ERROR ? -EBADMSG :
				f->flags & RING_DESC_BUFFER_OVERRUN ? -EOVERFLOW :
				actual_len != XDEV_EXT_XD_MSG_LEN ? -EMSGSIZE :
				f->sof != XDEV_EXT_XD_PDF_START || f->eof != XDEV_EXT_XD_PDF_END ? -EPROTO : 0;

			xdev_ext_xd_probe_ctl_error_locked(xl, error);
			dispatch = (xl->up || xl->receive_ready) && !xdev_ext_xd_closing(xl);
		}
	}
	spin_unlock_irqrestore(&xl->lock, flags);
	if (dispatch && !(f->flags & (RING_DESC_CRC_ERROR | RING_DESC_BUFFER_OVERRUN))) {
		u32 len = f->size ? f->size : XDEV_EXT_XD_CTL_BUF;

		if (!xdev_ext_xd_probe_ctl_rx(xl, cf->buf, len) && READ_ONCE(xl->up))
			xdev_ext_xd_ctl_dispatch(xl, cf->buf, len);
	}
	/* Stop first clears starting/up under this lock; context is not rebound
	 * until stop/free has drained this whole callback, including dispatch.
	 */
	spin_lock_irqsave(&xl->lock, flags);
	if (a && a == xl->ctl_rx_alloc && !canceled && !a->unknown &&
	    !xdev_ext_xd_closing(xl) && (xl->up || xl->receive_ready || xl->rings->starting)) {
		a->pending[cf->index] = true;
		if (!tb_ring_rx(ring, f)) {
			a->accepted++;
			a->callbacks_drained = false;
		} else {
			a->pending[cf->index] = false;
		}
	}
	spin_unlock_irqrestore(&xl->lock, flags);
}

/* ctl_mutex serializes the entire native lifecycle. */
int xdev_ext_xd_rings_start(struct xdev_ext_xd_link *xl)
{
	struct xdev_ext_xd_rings *rs = xl->rings;
	struct xdev_ext_xd_ctl_allocation *a;
	unsigned long flags;
	u32 i;
	int ret;

	if (xl->nhi_gone || xl->gone || !rs)
		return -ENODEV;
	ret = xdev_ext_xd_ctl_alloc(xl, true);
	if (ret)
		return ret;
	ret = xdev_ext_xd_ctl_alloc(xl, false);
	if (ret) {
		xdev_ext_xd_ctl_release(xl, true);
		return ret;
	}
	spin_lock_irqsave(&xl->lock, flags);
	rs->starting = true;
	spin_unlock_irqrestore(&xl->lock, flags);
	for (i = 0; i < rs->count; i++) {
		u32 index = i < 2 ? rs->count - 1 - i :
			((i - 2) / 2) + ((i & 1) ? 0 : xl->channels);
		struct xdev_ext_xd_native *n = &rs->native[index];

		/* Start each TX before its paired E2E RX. */
		tb_ring_start(*n->slot);
		if (!(*n->slot)->running) {
			xdev_ext_xd_mark_nhi_gone(xl);
			xdev_ext_xd_rings_stop(xl);
			return -ENODEV;
		}
		n->started = true;
		if (n->slot == &xl->ctl_rx)
			xl->ctl_rx_alloc->ever_started = true;
		if (n->slot == &xl->ctl_tx)
			xl->ctl_tx_alloc->ever_started = true;
	}
	spin_lock_irqsave(&xl->lock, flags);
	a = xl->ctl_rx_alloc;
	for (i = 0; i < XDEV_EXT_XD_CTL_RING - 1; i++) {
		a->pending[i] = true;
		ret = tb_ring_rx(xl->ctl_rx, &xl->ctl_rx_frames[i].frame);
		if (ret) {
			a->pending[i] = false;
			break;
		}
		a->accepted++;
		a->callbacks_drained = false;
	}
	spin_unlock_irqrestore(&xl->lock, flags);
	if (ret) {
		xdev_ext_xd_rings_stop(xl);
		return -EIO;
	}
	return 0;
}

/* ctl_mutex held, never from a frame callback, never with ep_mutex or a
 * spinlock held.  Data RX first: its posted device-memory buffers are
 * reported canceled (unknown) before the control ring that could still
 * deliver their acknowledgements stops. */
void xdev_ext_xd_rings_stop(struct xdev_ext_xd_link *xl)
{
	struct xdev_ext_xd_rings *rs = xl->rings;
	unsigned long flags;
	u32 i, stopped_rx = 0, stopped_tx = 0;
	bool requester_gone = xl->nhi_gone;

	xdev_ext_xd_probe_close(xl);
	spin_lock_irqsave(&xl->lock, flags);
	xl->up = false;
	if (rs)
		rs->starting = false;
	spin_unlock_irqrestore(&xl->lock, flags);
	if (!rs)
		return;
	/* Native array is ordered data RX, data TX, control RX, control TX. */
	for (i = 0; i < rs->count; i++) {
		struct xdev_ext_xd_native *n = &rs->native[i];
		struct tb_ring *r = *n->slot;

		if (!r || !n->started)
			continue;
		tb_ring_stop(r);
		if (r->running) {
			n->disposition = XDEV_EXT_XD_NATIVE_UNKNOWN;
			rs->retained_bytes += tb_ring_descriptor_bytes(r->size);
			xdev_ext_xd_mark_nhi_gone(xl);
			tb_ring_free_quarantined(r);
			*n->slot = NULL;
		} else {
			n->disposition = XDEV_EXT_XD_NATIVE_STOPPED;
		}
		n->started = false;
	}
	for (i = 0; i < xl->channels; i++) {
		struct tb_ring *rx = xl->chan[i].rx, *tx = xl->chan[i].tx;

		if (rs->native[i].disposition == XDEV_EXT_XD_NATIVE_STOPPED && rx && !rx->nhi->going_away)
			stopped_rx |= BIT(i);
		if (rs->native[xl->channels + i].disposition == XDEV_EXT_XD_NATIVE_STOPPED && tx && !tx->nhi->going_away)
			stopped_tx |= BIT(i);
	}
	requester_gone |= xl->nhi_gone;
	rs->retained_bytes += xdev_ext_xd_probe_retire(xl, stopped_rx, stopped_tx, requester_gone);
	for (i = 0; i < 2; i++) {
		bool rx = !i;
		struct xdev_ext_xd_ctl_allocation *a = rx ? xl->ctl_rx_alloc : xl->ctl_tx_alloc;
		struct xdev_ext_xd_native *n = &rs->native[rs->count - 2 + i];

		if (!a)
			continue;
		a->callbacks_drained = true;
		if (a->accepted != a->retired)
			a->unknown = true;
		/* Cancellation alone proves nothing about DMA.  A healthy native
		 * STOPPED barrier, however, disables the host ring and drains its
		 * callbacks.  This backing contains control messages only; payload
		 * device-memory custody remains UNKNOWN in the data callbacks.
		 */
		if (n->disposition == XDEV_EXT_XD_NATIVE_STOPPED &&
		    !xl->nhi_gone && *n->slot && !(*n->slot)->nhi->going_away &&
		    a->accepted == a->retired)
			a->unknown = false;
		if (a->unknown)
			xdev_ext_xd_ctl_release(xl, rx);
		else if (!rx)
			bitmap_fill(xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING);
	}
	if (rs->retained_bytes && !rs->retention_sealed) {
		/* UNKNOWN data descriptors count even if startup failed before
		 * any control buffer was posted. The built-in ledger survives
		 * this module's exit without retaining a callback into it.
		 */
		xdev_ext_xd_mark_nhi_gone(xl);
		xdev_ext_requester_retention_retain(rs->retention, rs->retained_bytes);
		rs->retention_sealed = true;
	}
}

int xdev_ext_xd_rings_alloc(struct xdev_ext_xd_link *xl)
{
	struct tb_nhi *nhi = xl->xd->tb->nhi;
	unsigned int flags = RING_FLAG_FRAME | (xl->e2e ? RING_FLAG_E2E : 0);
	u16 sof = BIT(XDEV_EXT_XD_PDF_START), eof = BIT(XDEV_EXT_XD_PDF_END);
	struct xdev_ext_xd_rings *rs;
	u32 c, generations;
	u64 bytes;
	int ret = -ENOMEM;

	xl->ctl_in_hopid = xl->ctl_out_hopid = -1;
	for (c = 0; c < xl->channels; c++)
		xl->chan[c].in_hopid = xl->chan[c].out_hopid = -1;
	rs = kzalloc(sizeof(*rs), GFP_KERNEL);
	if (!rs)
		return -ENOMEM;
	/* Reserve every possible descriptor and control byte before its first
	 * allocation. Each generation needs channels+1 hops in each direction;
	 * configuration hop zero is unavailable to services.
	 */
	generations = nhi->hop_count > 1 ?
		(nhi->hop_count - 1) / (xl->channels + 1) : 0;
	if (!generations) {
		kfree(rs);
		return -ENOSPC;
	}
	bytes = 2ULL * tb_ring_descriptor_bytes(XDEV_EXT_XD_CTL_RING) +
		2ULL * xl->channels * tb_ring_descriptor_bytes(XDEV_EXT_XD_DATA_RING) +
		(u64)XDEV_EXT_XD_CTL_RING * (XDEV_EXT_XD_CTL_BUF + XDEV_EXT_XD_CTL_TX_BUF) +
		xdev_ext_xd_probe_worst_bytes(xl->channels);
	rs->retention = xdev_ext_requester_retention_reserve(xl->nhi_pdev, generations, bytes);
	if (IS_ERR(rs->retention)) {
		ret = PTR_ERR(rs->retention);
		kfree(rs);
		return ret;
	}
	xl->rings = rs;
	/* Explicit records exist even for partial allocation failure. */
	for (c = 0; c < xl->channels; c++)
		rs->native[rs->count++].slot = &xl->chan[c].rx;
	for (c = 0; c < xl->channels; c++)
		rs->native[rs->count++].slot = &xl->chan[c].tx;
	rs->native[rs->count++].slot = &xl->ctl_rx;
	rs->native[rs->count++].slot = &xl->ctl_tx;
	xl->ctl_tx = tb_ring_alloc_tx(nhi, -1, XDEV_EXT_XD_CTL_RING, RING_FLAG_FRAME);
	if (!xl->ctl_tx)
		goto fail;
	xl->ctl_rx = tb_ring_alloc_rx(nhi, -1, XDEV_EXT_XD_CTL_RING, flags,
				     xl->ctl_tx->hop, sof, eof, NULL, NULL);
	if (!xl->ctl_rx)
		goto fail;
	rs->ctl_tx_hop = xl->ctl_tx->hop;
	rs->ctl_rx_hop = xl->ctl_rx->hop;
	for (c = 0; c < xl->channels; c++) {
		xl->chan[c].tx = tb_ring_alloc_tx(nhi, -1, XDEV_EXT_XD_DATA_RING, RING_FLAG_FRAME);
		if (!xl->chan[c].tx)
			goto fail;
		xl->chan[c].rx = tb_ring_alloc_rx(nhi, -1, XDEV_EXT_XD_DATA_RING, flags,
					       xl->chan[c].tx->hop, sof, eof, NULL, NULL);
		if (!xl->chan[c].rx)
			goto fail;
		rs->data_tx_hop[c] = xl->chan[c].tx->hop;
		rs->data_rx_hop[c] = xl->chan[c].rx->hop;
		xl->chan[c].out_hopid = tb_xdomain_alloc_out_hopid(xl->xd, -1);
		if (xl->chan[c].out_hopid < 0)
			goto fail;
	}
	xl->ctl_out_hopid = tb_xdomain_alloc_out_hopid(xl->xd, -1);
	if (xl->ctl_out_hopid < 0)
		goto fail;
	ret = xdev_ext_xd_ctl_alloc(xl, true);
	if (ret)
		goto fail;
	ret = xdev_ext_xd_ctl_alloc(xl, false);
	if (ret)
		goto fail;
	return 0;
fail:
	xdev_ext_xd_rings_free(xl);
	return ret;
}

void xdev_ext_xd_rings_free(struct xdev_ext_xd_link *xl)
{
	struct xdev_ext_xd_rings *rs = xl->rings;
	u32 c, i;

	xdev_ext_xd_rings_stop(xl);
	if (rs) {
		for (i = 0; i < rs->count; i++) {
			struct xdev_ext_xd_native *n = &rs->native[i];

			if (*n->slot)
				tb_ring_free(*n->slot);
			*n->slot = NULL;
		}
	}
	/* All normal free and unknown retirement callbacks have now finished. */
	xdev_ext_xd_probe_free(xl);
	xdev_ext_xd_ctl_release(xl, true);
	xdev_ext_xd_ctl_release(xl, false);
	if (xl->ctl_out_hopid >= 0)
		tb_xdomain_release_out_hopid(xl->xd, xl->ctl_out_hopid);
	xl->ctl_out_hopid = -1;
	for (c = 0; c < xl->channels; c++) {
		if (xl->chan[c].out_hopid >= 0)
			tb_xdomain_release_out_hopid(xl->xd, xl->chan[c].out_hopid);
		xl->chan[c].out_hopid = -1;
	}
	/* Healthy stop can reuse backing. Account for it until the actual
	 * free; release is deliberately inert for a retained generation.
	 */
	if (rs)
		xdev_ext_requester_retention_release(rs->retention);
	kfree(rs);
	xl->rings = NULL;
}

static atomic64_t xdev_ext_xd_path_scope = ATOMIC64_INIT(0);

/* ctl_mutex keeps xd and the path operation alive. Snapshot the scalar link
 * identity under its lock; both records bind the same synchronous operation.
 */
static int xdev_ext_xd_path_enable(struct xdev_ext_xd_link *xl,
				 const char *role, u32 channel,
				 int tx_path, int tx_ring, int rx_path, int rx_ring)
{
	u64 scope = atomic64_inc_return(&xdev_ext_xd_path_scope);
	const char *name = dev_name(&xl->xd->dev);
	u64 token, local_inc, remote_inc;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&xl->lock, flags);
	token = xl->token;
	local_inc = xl->local_inc;
	remote_inc = xl->remote_inc;
	spin_unlock_irqrestore(&xl->lock, flags);
	dev_info(&xl->nhi_pdev->dev,
		 "XDEV_EXT_XDOMAIN_PATH phase=BEGIN scope=%llu token=%llu local_inc=%llu remote_inc=%llu xdomain=%s role=%s channel=%u\n",
		 (unsigned long long)scope, (unsigned long long)token,
		 (unsigned long long)local_inc, (unsigned long long)remote_inc,
		 name, role, channel);
	ret = tb_xdomain_enable_paths(xl->xd, tx_path, tx_ring, rx_path, rx_ring);
	dev_info(&xl->nhi_pdev->dev,
		 "XDEV_EXT_XDOMAIN_PATH phase=END scope=%llu token=%llu local_inc=%llu remote_inc=%llu xdomain=%s role=%s channel=%u result=%d\n",
		 (unsigned long long)scope, (unsigned long long)token,
		 (unsigned long long)local_inc, (unsigned long long)remote_inc,
		 name, role, channel, ret);
	return ret;
}

/* ctl_mutex held.  Data paths first, control last: the first DMA tunnel gets
 * the larger credit reservation (section 4.8). */
int xdev_ext_xd_paths_enable(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_login *l)
{
	u32 c;
	int ret;

	for (c = 0; c < xl->channels; c++) {
		struct xdev_ext_xd_chan *ch = &xl->chan[c];

		ch->in_hopid = tb_xdomain_alloc_in_hopid(xl->xd, l->data_tx_path[c]);
		if (ch->in_hopid != (int)l->data_tx_path[c]) {
			ret = ch->in_hopid < 0 ? ch->in_hopid : -EPROTO;
			goto fail;
		}
		ret = xdev_ext_xd_path_enable(xl, "data", c, ch->out_hopid, ch->tx->hop,
					    ch->in_hopid, ch->rx->hop);
		if (ret)
			goto fail;
		ch->paths = true;
	}
	xl->ctl_in_hopid = tb_xdomain_alloc_in_hopid(xl->xd, l->ctl_tx_path);
	if (xl->ctl_in_hopid != (int)l->ctl_tx_path) {
		ret = xl->ctl_in_hopid < 0 ? xl->ctl_in_hopid : -EPROTO;
		goto fail;
	}
	ret = xdev_ext_xd_path_enable(xl, "control", 0, xl->ctl_out_hopid, xl->ctl_tx->hop,
				    xl->ctl_in_hopid, xl->ctl_rx->hop);
	if (ret)
		goto fail;
	xl->ctl_paths = true;
	return 0;
fail:
	xdev_ext_xd_paths_disable(xl);
	return ret;
}

/* ctl_mutex held: every enabled pair, then every allocated in-HopID.  The
 * plan never disables one pair while keeping another, so the firmware
 * connection manager's whole-port teardown is not a semantic change; H0
 * still requires the software connection manager. */
void xdev_ext_xd_paths_disable(struct xdev_ext_xd_link *xl)
{
	struct xdev_ext_xd_rings *rs = xl->rings;
	u32 c;

	if (xl->ctl_paths)
		tb_xdomain_disable_paths(xl->xd, xl->ctl_out_hopid, rs->ctl_tx_hop,
					 xl->ctl_in_hopid, rs->ctl_rx_hop);
	xl->ctl_paths = false;
	if (xl->ctl_in_hopid >= 0)
		tb_xdomain_release_in_hopid(xl->xd, xl->ctl_in_hopid);
	xl->ctl_in_hopid = -1;
	for (c = 0; c < xl->channels; c++) {
		struct xdev_ext_xd_chan *ch = &xl->chan[c];

		if (ch->paths)
			tb_xdomain_disable_paths(xl->xd, ch->out_hopid, rs->data_tx_hop[c],
						 ch->in_hopid, rs->data_rx_hop[c]);
		ch->paths = false;
		if (ch->in_hopid >= 0)
			tb_xdomain_release_in_hopid(xl->xd, ch->in_hopid);
		ch->in_hopid = -1;
	}
}

/* ctl_mutex pins allocation/retirement; each native sample has its own instant. */
int xdev_ext_xd_link_diag(struct xdev_ext_xd_ep *ep,
                         struct xdev_ext_mech_stage_diag *out)
{
	struct xdev_ext_xd_link *xl = ep->xl;
	struct xdev_ext_mech_stage_diag d = *out;
	struct xdev_ext_requester_retention_stats retention;
	struct tb_ring_snapshot native;
	struct tb_ring *ring;
	unsigned long flags;
	int ret = 0;

	lockdep_assert_held(&xl->ctl_mutex);
	spin_lock_irqsave(&xl->lock, flags);
	if (ep->detached || ep->bound_local_inc != xl->local_inc ||
	    ep->bound_remote_inc != xl->remote_inc) {
		ret = -ESTALE;
		goto unlock;
	}
	d.token = xl->token;
	d.local_inc = xl->local_inc;
	d.remote_inc = xl->remote_inc;
	d.valid |= XDEV_EXT_MECH_DIAG_IDENTITY | XDEV_EXT_MECH_DIAG_CONTROL;
	d.readiness = XDEV_EXT_MECH_DIAG_STAGE_INC_MATCH |
		(xl->up ? XDEV_EXT_MECH_DIAG_CONTROL_UP : 0) |
		(xl->receive_ready ? XDEV_EXT_MECH_DIAG_RECEIVE_READY : 0) |
		(xdev_ext_xd_closing(xl) ? XDEV_EXT_MECH_DIAG_CLOSING : 0) |
		(xl->nhi_gone ? XDEV_EXT_MECH_DIAG_NHI_GONE : 0) |
		((xl->data_verified_mask & BIT(ep->chan)) ? XDEV_EXT_MECH_DIAG_DATA_VERIFIED : 0);
	d.ctl_tx_free = xl->ctl_tx_alloc && !xl->ctl_tx_alloc->unknown ?
		bitmap_weight(xl->ctl_tx_free, XDEV_EXT_XD_CTL_RING) : 0;
	d.valid &= ~(XDEV_EXT_MECH_DIAG_NATIVE | XDEV_EXT_MECH_DIAG_RX_POSTED);
	d.native_inflight = d.software_pending = d.rx_native_posted = 0;
	ring = ep->rx ? xl->chan[ep->chan].rx : xl->chan[ep->chan].tx;
	if (ring) {
		tb_ring_snapshot(ring, &native);
		d.native_inflight = native.in_flight;
		d.software_pending = native.software_pending;
		d.valid |= XDEV_EXT_MECH_DIAG_NATIVE;
		if (ep->rx) {
			d.rx_native_posted = native.in_flight;
			d.valid |= XDEV_EXT_MECH_DIAG_RX_POSTED;
		}
	}
unlock:
	spin_unlock_irqrestore(&xl->lock, flags);
	if (ret)
		return ret;
	/* The requester ledger may include other links and services. */
	xdev_ext_requester_retention_snapshot(xl->nhi_pdev, &retention);
	d.retention = (struct xdev_ext_mech_retention_diag) {
		.generations = retention.generations,
		.retained_generations = retention.retained_generations,
		.reserved_bytes = retention.reserved_bytes,
		.retained_bytes = retention.retained_bytes,
		.global_reserved_bytes = retention.global_reserved_bytes,
		.global_retained_bytes = retention.global_retained_bytes,
		.global_limit = retention.global_limit,
	};
	d.valid |= XDEV_EXT_MECH_DIAG_RETENTION;
	spin_lock_irqsave(&xl->lock, flags);
	if (ep->detached || ep->bound_local_inc != xl->local_inc ||
	    ep->bound_remote_inc != xl->remote_inc)
		ret = -ESTALE;
	spin_unlock_irqrestore(&xl->lock, flags);
	if (!ret)
		*out = d;
	return ret;
}

static void *xdev_ext_xd_bind(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u,
			      void (*dead)(void *), void *arg)
{
	struct xdev_ext_xd_link *xl;
	struct xdev_ext_xd_ep *ep;
	bool rx = st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE;
	int ret = 0;

	(void)dead;	/* link down calls xdev_ext_mech_stage_dead() on ep->st directly */
	(void)arg;
	xl = xdev_ext_xd_link_get(u->arg0);
	if (!xl)
		return ERR_PTR(-ENODEV);
	if (u->arg1 >= xl->channels) {
		xdev_ext_xd_link_put(xl);
		return ERR_PTR(-EINVAL);
	}
	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (!ep) {
		xdev_ext_xd_link_put(xl);
		return ERR_PTR(-ENOMEM);
	}
	*ep = (struct xdev_ext_xd_ep){ .xl = xl, .st = st, .chan = (u32)u->arg1, .rx = rx };
	mutex_lock(&xl->ep_mutex);
	spin_lock_irq(&xl->lock);
	if (!xl->up || xdev_ext_xd_closing(xl))
		ret = -ENOLINK;
	else if (!(xl->data_verified_mask & BIT(ep->chan)))
		ret = -EAGAIN;
	else if (xl->chan[ep->chan].ep[rx])
		ret = -EBUSY;
	else {
		ep->bound_local_inc = xl->local_inc;
		ep->bound_remote_inc = xl->remote_inc;
		xl->chan[ep->chan].ep[rx] = ep;
	}
	spin_unlock_irq(&xl->lock);
	mutex_unlock(&xl->ep_mutex);
	if (ret) {
		kfree(ep);
		xdev_ext_xd_link_put(xl);
		return ERR_PTR(ret);
	}
	return ep;
}
static void xdev_ext_xd_unbind(void *lk)
{
	struct xdev_ext_xd_ep *ep = lk;
	struct xdev_ext_xd_link *xl = ep->xl;

	mutex_lock(&xl->ep_mutex);
	/* A link down may have detached us, and a later stage may own the slot. */
	if (xl->chan[ep->chan].ep[ep->rx] == ep)
		xl->chan[ep->chan].ep[ep->rx] = NULL;
	/* The core destroys the worker before unbind. Wait out every ingress
	 * under ep_mutex, then settle RTS queued after its last progress pass.
	 * A link-down-detached endpoint belongs to an already ended epoch. */
	if (ep->rx && !ep->detached)
		xdev_ext_xd_class_detach(ep->st);
	mutex_unlock(&xl->ep_mutex);	/* no dispatch or dead notification reaches the stage after this */
	kfree(ep);
	xdev_ext_xd_link_put(xl);	/* may free the link memory after remove */
}
static struct pci_dev *xdev_ext_xd_requester(void *lk)
{
	/* The cached NHI function: never a ring, which remove frees. */
	return ((struct xdev_ext_xd_ep *)lk)->xl->nhi_pdev;
}
static u32 xdev_ext_xd_max_payload(void *lk)
{
	return READ_ONCE(((struct xdev_ext_xd_ep *)lk)->xl->up) ? XDEV_EXT_XDOMAIN_MAX_FRAME : 0;
}
const struct xdev_ext_net_dev_ops xdev_ext_xd_dev_ops = {
	.owner = THIS_MODULE, .hdr_policy = XDEV_EXT_NET_HDR_CHANNEL,
	.max_elems = XDEV_EXT_XDOMAIN_MAX_ELEMS,
	.bind = xdev_ext_xd_bind, .unbind = xdev_ext_xd_unbind,
	.requester = xdev_ext_xd_requester, .max_payload = xdev_ext_xd_max_payload,
	.post_tx = xdev_ext_xd_post_tx, .post_rx = xdev_ext_xd_post_rx,
	.ctl_send = xdev_ext_xd_ctl_send,
};

/* xdomain ring end */
