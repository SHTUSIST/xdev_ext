// SPDX-License-Identifier: GPL-2.0
/* XDOMAIN class device code: XDomain service "xdevext", login, the link
 * registry and the link lifetime. Uses exported Thunderbolt symbols;
 * X3a supplies the synchronous protocol-handler unregister barrier. */
#include <linux/module.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/pci.h>
#include <linux/pm.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/uuid.h>
#include <linux/xdev_ext_requester_retention.h>
#include "xdev_ext_xdomain.h"

/* Property directory: aff120c8-4435-4bfd-a46b-30cb3c52f92d (generated for
 * this project, 2026-10-25).  Protocol: 90b54f9d-abd0-4881-ba1f-31898917b27e. */
static const uuid_t xdev_ext_xd_dir_uuid =
	UUID_INIT(0xaff120c8, 0x4435, 0x4bfd, 0xa4, 0x6b, 0x30, 0xcb, 0x3c, 0x52, 0xf9, 0x2d);
static const uuid_t xdev_ext_xd_proto_uuid =
	UUID_INIT(0x90b54f9d, 0xabd0, 0x4881, 0xba, 0x1f, 0x31, 0x89, 0x89, 0x17, 0xb2, 0x7e);
#define XDEV_EXT_XD_KEY			"xdevext"
#define XDEV_EXT_XD_LOGIN_TIMEOUT_MS	1000

static bool xdev_ext_xd_e2e = true;
module_param_named(e2e, xdev_ext_xd_e2e, bool, 0444);
MODULE_PARM_DESC(e2e, "request end-to-end flow control on receive rings (default true)");

static bool poll_completions;
module_param(poll_completions, bool, 0444);
MODULE_PARM_DESC(poll_completions, "collect all native ring completions in bounded process-context passes (default false)");

static struct tb_property_dir *xdev_ext_xd_dir;
static DEFINE_MUTEX(xdev_ext_xd_links_lock);
static LIST_HEAD(xdev_ext_xd_links);
static u64 xdev_ext_xd_next_token;	/* under xdev_ext_xd_links_lock; never reused */

static void xdev_ext_xd_link_release(struct kref *ref)
{
	struct xdev_ext_xd_link *xl = container_of(ref, struct xdev_ext_xd_link, ref);

	/* Rings, HopIDs and the XDomain were let go in remove (or probe failure). */
	pci_dev_put(xl->nhi_pdev);
	kfree(xl);
}
void xdev_ext_xd_link_put(struct xdev_ext_xd_link *xl)
{
	kref_put(&xl->ref, xdev_ext_xd_link_release);
}
struct xdev_ext_xd_link *xdev_ext_xd_link_get(u64 token)
{
	struct xdev_ext_xd_link *xl, *found = NULL;

	mutex_lock(&xdev_ext_xd_links_lock);
	list_for_each_entry(xl, &xdev_ext_xd_links, node)
		if (xl->token == token) {
			kref_get(&xl->ref);
			found = xl;
			break;
		}
	mutex_unlock(&xdev_ext_xd_links_lock);
	return found;
}

/* xdomain login begin */
static void xdev_ext_xd_new_incarnation(struct xdev_ext_xd_link *xl)
{
	u64 inc;

	do
		inc = get_random_u64();
	while (!inc || inc == xl->local_inc);
	spin_lock_irq(&xl->lock);
	xl->local_inc = inc;
	atomic_set(&xl->command_id, 0);
	spin_unlock_irq(&xl->lock);
}

/* ctl_mutex serializes locally originated commands with incarnation changes. */
static int xdev_ext_xd_next_command_id(struct xdev_ext_xd_link *xl, u32 *id)
{
	lockdep_assert_held(&xl->ctl_mutex);
	/* Leave an exhausted counter saturated until a fresh incarnation is published.
	 * Neither a retry nor a peer change permits same-incarnation reuse.
	 */
	if ((u32)atomic_read(&xl->command_id) == ~0U)
		return -EOVERFLOW;
	*id = (u32)atomic_inc_return(&xl->command_id);
	return 0;
}

static void xdev_ext_xd_fill_hdr(struct xdev_ext_xd_link *xl, void *pkt, size_t size, u32 type,
				 const uuid_t *initiator, const uuid_t *target, u32 command_id)
{
	struct xdev_ext_xd_login *h = pkt;	/* every packet starts with the same header */

	h->route_hi = upper_32_bits(xl->route);
	h->route_lo = lower_32_bits(xl->route);
	h->length_sn = (size - 3 * 4) / 4;
	memcpy(h->uuid, &xdev_ext_xd_proto_uuid, 16);
	memcpy(h->initiator_uuid, initiator, 16);
	memcpy(h->target_uuid, target, 16);
	h->type = type;
	h->command_id = command_id;
}

static int xdev_ext_xd_login_reply_check(const struct xdev_ext_xd_login *req,
				       const struct xdev_ext_xd_login_response *reply)
{
	/* The common matcher validates transport size, route and protocol, but
	 * does not associate our command or endpoint UUIDs. Check the complete
	 * identity before interpreting status or changing confirmation state.
	 */
	if (!req->command_id || !reply->command_id ||
	    reply->command_id != req->command_id ||
	    !req->incarnation || reply->requester_incarnation != req->incarnation ||
	    (reply->length_sn & 0x3f) != (sizeof(*reply) - 12) / 4 ||
	    (reply->route_hi & ~BIT(31)) != req->route_hi ||
	    reply->route_lo != req->route_lo ||
	    !uuid_equal((const uuid_t *)reply->uuid, &xdev_ext_xd_proto_uuid) ||
	    !uuid_equal((const uuid_t *)reply->uuid, (const uuid_t *)req->uuid) ||
	    !uuid_equal((const uuid_t *)reply->initiator_uuid,
			(const uuid_t *)req->target_uuid) ||
	    !uuid_equal((const uuid_t *)reply->target_uuid,
			(const uuid_t *)req->initiator_uuid) ||
	    reply->type != XDEV_EXT_XD_LOGIN_RESPONSE || !reply->incarnation ||
	    reply->status > MAX_ERRNO)
		return -EPROTO;
	return reply->status ? -(int)reply->status : 0;
}

/* Under xdev_ext_xd_links_lock: the link of this XDomain, or NULL.  Same
 * route and UUID checks as thunderbolt-net (drivers/net/thunderbolt/main.c:427-438). */
static struct xdev_ext_xd_link *xdev_ext_xd_link_find_locked(u64 route, const uuid_t *initiator,
							     const uuid_t *target)
{
	struct xdev_ext_xd_link *xl;

	list_for_each_entry(xl, &xdev_ext_xd_links, node)
		if (xl->route == route && uuid_equal(initiator, &xl->remote_uuid) &&
		    uuid_equal(target, &xl->local_uuid))
			return xl;
	return NULL;
}

/* One handler for the module.  Everything it does to a link happens under
 * xdev_ext_xd_links_lock, and remove() takes the link off the list first, so
 * a handler never reaches a link that is being removed (section 4.8). */
static int xdev_ext_xd_handle_packet(const void *buf, size_t size, void *data)
{
	const struct xdev_ext_xd_login *l = buf;
	struct xdev_ext_xd_login_response r = {};
	struct xdev_ext_xd_link *xl;
	u32 status;
	u64 route;
	int ret = 1;

	(void)data;
	if (size < offsetof(struct xdev_ext_xd_login, proto_version) ||
	    !uuid_equal((const uuid_t *)l->uuid, &xdev_ext_xd_proto_uuid))
		return 0;
	route = (((u64)l->route_hi << 32) | l->route_lo) & ~BIT_ULL(63);
	mutex_lock(&xdev_ext_xd_links_lock);
	xl = xdev_ext_xd_link_find_locked(route, (const uuid_t *)l->initiator_uuid,
					  (const uuid_t *)l->target_uuid);
	if (!xl) {
		ret = 0;
		goto out;
	}
	spin_lock_irq(&xl->lock);
	if (xl->going_away || xl->suspended || xl->gone || xl->nhi_gone) {
		spin_unlock_irq(&xl->lock);
		goto out;
	}
	if (l->type == XDEV_EXT_XD_LOGOUT) {
		if (size == sizeof(*l) &&
		    (l->length_sn & 0x3f) == (sizeof(*l) - 12) / 4 &&
		    l->command_id && xl->up && l->incarnation == xl->remote_inc) {
			if (!xl->down_err || xl->down_local_inc != xl->local_inc) {
				xl->down_err = -ENOLINK;
				xl->down_local_inc = xl->local_inc;
			}
			queue_work(system_long_wq, &xl->down_work);
		}
		spin_unlock_irq(&xl->lock);
		goto out;
	}
	if (l->type != XDEV_EXT_XD_LOGIN) {
		spin_unlock_irq(&xl->lock);
		ret = 0;
		goto out;
	}
	ret = xdev_ext_xd_login_check(l, size, xl->channels);
	status = ret ? -ret : (!l->command_id || l->channels != xl->channels ? EPROTO : 0);
	ret = 1;
	if (size >= offsetof(struct xdev_ext_xd_login, proto_version) + sizeof(l->proto_version) &&
	    l->proto_version != XDEV_EXT_XD_PROTO_VERSION)
		xl->version_errors++;
	if (!status) {
		/* Positive acknowledgement owns one immutable advertisement slot.
		 * A late current-peer repeat cannot erase a changed candidate. */
		if (xl->up && l->incarnation == xl->remote_inc) {
			/* Idempotent current-peer repeat: preserve any pending change. */
		} else if (xl->candidate_pending) {
			if (l->incarnation != xl->remote_login.incarnation)
				status = EAGAIN;
		} else {
			xl->remote_login = *l;
			xl->candidate_pending = true;
			xl->candidate_probe_started = false;
		}
		if (!status) {
			queue_work(system_long_wq, &xl->connect_work);
			/* Accept the advertisement before its paths exist, but only
			 * acknowledge readiness once this exact peer can reach our
			 * receive rings. Do not require UP: both peers must be able
			 * to build paths before either gets its positive response.
			 */
			if (!xl->receive_ready || !xl->remote_logged_in ||
			    xl->accepted_inc != l->incarnation)
				status = EAGAIN;
		}
	}
	r.incarnation = xl->local_inc;
	spin_unlock_irq(&xl->lock);
	xdev_ext_xd_fill_hdr(xl, &r, sizeof(r), XDEV_EXT_XD_LOGIN_RESPONSE,
			     (const uuid_t *)l->target_uuid,
			     (const uuid_t *)l->initiator_uuid, l->command_id);
	if (size >= offsetof(struct xdev_ext_xd_login, incarnation) + sizeof(l->incarnation))
		r.requester_incarnation = l->incarnation;
	r.status = status;
	tb_xdomain_response(xl->xd, &r, sizeof(r), TB_CFG_PKG_XDOMAIN_RESP);
out:
	mutex_unlock(&xdev_ext_xd_links_lock);
	return ret;
}

/* ctl_mutex held: both directions logged in with matching incarnations. */
static void xdev_ext_xd_maybe_up(struct xdev_ext_xd_link *xl)
{
	u32 c;

	lockdep_assert_held(&xl->ctl_mutex);
	if (!xl->logged_in || !xl->remote_logged_in ||
	    !xl->response_inc || xl->response_inc != xl->accepted_inc)
		return;
	spin_lock_irq(&xl->lock);
	if (!xl->up && !xl->going_away && !xl->suspended &&
	    !xl->gone && !xl->nhi_gone) {
		for (c = 0; c < xl->channels; c++)
			xl->chan[c].announced = xl->chan[c].consumed = 0;
		xl->remote_inc = xl->accepted_inc;
		xl->up = true;
		xl->link_ups++;
		xl->last_error = 0;
	}
	spin_unlock_irq(&xl->lock);
	xdev_ext_xd_probe_control_ready(xl);
}

static void xdev_ext_xd_login_work(struct work_struct *work)
{
	struct xdev_ext_xd_link *xl = container_of(to_delayed_work(work), struct xdev_ext_xd_link,
						   login_work);
	struct xdev_ext_xd_login_response reply = {};
	struct xdev_ext_xd_login req = {};
	struct xdev_ext_xd_login candidate;
	bool pending_candidate, rejected_candidate = false;
	unsigned long now;
	u32 c, command_id;
	int ret;

	mutex_lock(&xl->ctl_mutex);
	if (READ_ONCE(xl->going_away) || READ_ONCE(xl->suspended) ||
	    READ_ONCE(xl->gone) || READ_ONCE(xl->nhi_gone))
		goto out;
	/* Setup failures consume one link-wide budget. A changed nonce or a
	 * new advertisement cannot accelerate the pending retry or reset it.
	 */
	if (xl->retry_pending) {
		if (xl->retry_failures >= XDEV_EXT_XD_LOGIN_RETRIES)
			goto out;
		now = jiffies;
		if (time_before(now, xl->retry_after)) {
			mod_delayed_work(system_long_wq, &xl->login_work,
					 xl->retry_after - now);
			goto out;
		}
		if (!xl->remote_logged_in) {
			spin_lock_irq(&xl->lock);
			pending_candidate = xl->candidate_pending || xl->confirmed_pending;
			spin_unlock_irq(&xl->lock);
			if (pending_candidate) {
				queue_work(system_long_wq, &xl->connect_work);
				goto out;
			}
		}
	}
	if (xl->login_retries >= XDEV_EXT_XD_LOGIN_RETRIES ||
	    !xl->channels || xl->channels > XDEV_EXT_XD_MAX_CHANNELS)
		goto out;
	/* A response before the peer's LOGIN waits for connect_work. Once
	 * accepted, a different response incarnation still needs recovery. */
	if (xl->logged_in && (!xl->remote_logged_in ||
	    xl->response_inc == xl->accepted_inc))
		goto out;
	ret = xdev_ext_xd_next_command_id(xl, &command_id);
	if (ret) {
		spin_lock_irq(&xl->lock);
		xl->login_errors++;
		xl->last_error = ret;
		spin_unlock_irq(&xl->lock);
		goto out;
	}
	xdev_ext_xd_fill_hdr(xl, &req, sizeof(req), XDEV_EXT_XD_LOGIN, &xl->local_uuid,
			     &xl->remote_uuid, command_id);
	req.proto_version = XDEV_EXT_XD_PROTO_VERSION;
	req.channels = xl->channels;
	req.ctl_tx_path = xl->ctl_out_hopid;
	for (c = 0; c < xl->channels; c++)
		req.data_tx_path[c] = xl->chan[c].out_hopid;
	spin_lock_irq(&xl->lock);
	req.incarnation = xl->local_inc;
	/* The request confirms this complete advertisement, even if a late
	 * unsolicited LOGIN arrives before its response. */
	candidate = xl->remote_login;
	pending_candidate = xl->candidate_pending;
	spin_unlock_irq(&xl->lock);
	req.caps = XDEV_EXT_XD_CAP_DATA_CHALLENGE | (xl->e2e ? XDEV_EXT_XD_CAP_E2E : 0);
	/* Every request consumes the budget, including successful mismatches. */
	xl->login_retries++;
	spin_lock_irq(&xl->lock);
	xl->login_attempts++;
	spin_unlock_irq(&xl->lock);
	ret = tb_xdomain_request(xl->xd, &req, sizeof(req), TB_CFG_PKG_XDOMAIN_RESP, &reply,
				 sizeof(reply), TB_CFG_PKG_XDOMAIN_RESP, XDEV_EXT_XD_LOGIN_TIMEOUT_MS);
	if (!ret)
		ret = xdev_ext_xd_login_reply_check(&req, &reply);
	if (ret || (xl->remote_logged_in && reply.incarnation != xl->accepted_inc)) {
		spin_lock_irq(&xl->lock);
		xl->login_errors++;
		xl->last_error = ret ? ret : -EPROTO;
		spin_unlock_irq(&xl->lock);
	}
	if (!ret) {
		xl->logged_in = true;
		xl->response_inc = reply.incarnation;
		if (xl->remote_logged_in && xl->response_inc != xl->accepted_inc) {
			if (pending_candidate && candidate.incarnation == xl->response_inc) {
				spin_lock_irq(&xl->lock);
				xl->confirmed_login = candidate;
				xl->confirmed_pending = true;
				spin_unlock_irq(&xl->lock);
				queue_work(system_long_wq, &xl->connect_work);
				goto out;
			}
		}
		if (pending_candidate && candidate.incarnation != reply.incarnation) {
			spin_lock_irq(&xl->lock);
			if (xl->candidate_pending &&
			    xl->remote_login.incarnation == candidate.incarnation) {
				xl->candidate_pending = false;
				xl->candidate_probe_started = false;
			}
			spin_unlock_irq(&xl->lock);
			rejected_candidate = true;
		}
		xdev_ext_xd_maybe_up(xl);
		if (rejected_candidate || !xl->remote_logged_in ||
		    xl->response_inc == xl->accepted_inc)
			goto out;
	}
	if (xl->login_retries < XDEV_EXT_XD_LOGIN_RETRIES) {
		queue_delayed_work(system_long_wq, &xl->login_work,
				   msecs_to_jiffies(XDEV_EXT_XD_RELOGIN_MS));
	} else if (pending_candidate) {
		spin_lock_irq(&xl->lock);
		if (xl->candidate_pending &&
		    xl->remote_login.incarnation == candidate.incarnation) {
			xl->candidate_pending = false;
			xl->candidate_probe_started = false;
		}
		spin_unlock_irq(&xl->lock);
	}
	if (xl->login_retries == XDEV_EXT_XD_LOGIN_RETRIES) {
		spin_lock_irq(&xl->lock);
		xl->retries_exhausted++;
		spin_unlock_irq(&xl->lock);
		xdev_ext_xd_probe_login_exhausted(xl);
	}
out:
	mutex_unlock(&xl->ctl_mutex);
}

/* ctl_mutex held.  Ends the current link incarnation; see section 4.8. */
static void xdev_ext_xd_link_down_locked(struct xdev_ext_xd_link *xl, int err,
                                         bool renew_local)
{
	u32 c, i;

	lockdep_assert_held(&xl->ctl_mutex);
	if (xl->gone)
		return;
	xdev_ext_xd_probe_close(xl);
	spin_lock_irq(&xl->lock);
	xl->up = false;
	xl->last_error = err;
	xl->receive_ready = false;
	xl->remote_inc = 0;
	/* Faults queued for the detached peer epoch cannot end its successor. */
	xl->down_err = 0;
	xl->down_local_inc = 0;
	xl->confirmed_pending = false;
	if (renew_local) {
		xl->candidate_pending = false;
		xl->candidate_probe_started = false;
	}
	spin_unlock_irq(&xl->lock);
	mutex_lock(&xl->ep_mutex);
	for (c = 0; c < xl->channels; c++)
		for (i = 0; i < 2; i++) {
			struct xdev_ext_xd_ep *ep = xl->chan[c].ep[i];

			if (!ep)
				continue;
			/* A quarantined stage is never unbound: free its slot now. */
			spin_lock_irq(&xl->lock);
			ep->detached = true;
			spin_unlock_irq(&xl->lock);
			xl->chan[c].ep[i] = NULL;
			xdev_ext_mech_stage_dead(ep->st, err);	/* never blocks */
		}
	mutex_unlock(&xl->ep_mutex);
	/* Not under ep_mutex: stopping a ring waits for its frame callbacks,
	 * and the control callback takes ep_mutex. */
	xdev_ext_xd_rings_stop(xl);
	xdev_ext_xd_paths_disable(xl);
	spin_lock_irq(&xl->lock);
	xl->remote_logged_in = false;
	xl->accepted_inc = 0;
	spin_unlock_irq(&xl->lock);
	xl->logged_in = false;
	xl->response_inc = 0;
	if (READ_ONCE(xl->going_away) || READ_ONCE(xl->suspended) ||
	    READ_ONCE(xl->nhi_gone))
		return;
	if (renew_local)
		xdev_ext_xd_new_incarnation(xl);
	xl->login_retries = 0;
	queue_delayed_work(system_long_wq, &xl->login_work, msecs_to_jiffies(XDEV_EXT_XD_RELOGIN_MS));
}

void xdev_ext_xd_link_down(struct xdev_ext_xd_link *xl, int err)
{
	mutex_lock(&xl->ctl_mutex);
	xdev_ext_xd_link_down_locked(xl, err, true);
	mutex_unlock(&xl->ctl_mutex);
}

/* Any context but hardirq: end the current incarnation from a work item.
 * @ep, when set, must still be attached: a stage of an earlier incarnation
 * cannot end the current one. */
void xdev_ext_xd_link_fail(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_ep *ep, int err)
{
	unsigned long flags;

	spin_lock_irqsave(&xl->lock, flags);
	if (xl->up && !xl->going_away && !xl->suspended &&
	    !xl->gone && !xl->nhi_gone && !(ep && ep->detached)) {
		if (!xl->down_err || xl->down_local_inc != xl->local_inc) {
			xl->down_err = err;
			xl->down_local_inc = xl->local_inc;
		}
		queue_work(system_long_wq, &xl->down_work);
	}
	spin_unlock_irqrestore(&xl->lock, flags);
}

static void xdev_ext_xd_connect_work(struct work_struct *work)
{
	struct xdev_ext_xd_link *xl = container_of(work, struct xdev_ext_xd_link, connect_work);
	struct xdev_ext_xd_login l;
	bool confirmed, pending, start_probe = false;
	unsigned long now;
	int ret;

	mutex_lock(&xl->ctl_mutex);
	if (READ_ONCE(xl->going_away) || READ_ONCE(xl->suspended) ||
	    READ_ONCE(xl->gone) || READ_ONCE(xl->nhi_gone))
		goto out;
	if (xl->retry_failures >= XDEV_EXT_XD_LOGIN_RETRIES)
		goto out;
	now = jiffies;
	if (xl->retry_pending && time_before(now, xl->retry_after)) {
		mod_delayed_work(system_long_wq, &xl->login_work, xl->retry_after - now);
		goto out;
	}
	spin_lock_irq(&xl->lock);
	confirmed = xl->confirmed_pending &&
		    xl->confirmed_login.incarnation == xl->response_inc;
	l = confirmed ? xl->confirmed_login : xl->remote_login;
	pending = xl->candidate_pending;
	xl->confirmed_pending = false;
	spin_unlock_irq(&xl->lock);
	if (xl->remote_logged_in && !confirmed && !pending)
		goto out;
	if (xdev_ext_xd_login_check(&l, sizeof(l), xl->channels) ||
	    l.channels != xl->channels)
		goto out;
	/* The peer repeats LOGIN until it sees our response: same incarnation, nothing to do. */
	if (xl->remote_logged_in && l.incarnation == xl->accepted_inc) {
		spin_lock_irq(&xl->lock);
		if (xl->candidate_pending &&
		    xl->remote_login.incarnation == l.incarnation) {
			xl->candidate_pending = false;
			xl->candidate_probe_started = false;
		}
		spin_unlock_irq(&xl->lock);
		goto out;
	}
	/* Confirm a changed unsolicited LOGIN with our own request before
	 * disturbing an active connection. A delayed old LOGIN is not proof
	 * that the peer has changed its incarnation. */
	if (xl->remote_logged_in && !confirmed) {
		spin_lock_irq(&xl->lock);
		if (xl->candidate_pending && !xl->candidate_probe_started &&
		    xl->remote_login.incarnation == l.incarnation) {
			xl->candidate_probe_started = true;
			start_probe = true;
		}
		spin_unlock_irq(&xl->lock);
		if (start_probe) {
			xl->logged_in = false;
			xl->login_retries = 0;
		}
		mod_delayed_work(system_long_wq, &xl->login_work, 0);
		goto out;
	}
	/* The peer changed; our own nonce and advertised outgoing HopID
	 * leases did not. Renewing both peers here causes recovery ping-pong. */
	if (xl->remote_logged_in)
		xdev_ext_xd_link_down_locked(xl, -ENOLINK, false);
	/* stop may discover that the NHI is going away. */
	if (xl->nhi_gone)
		goto out;
	ret = xdev_ext_xd_rings_start(xl);
	if (ret)
		goto fail;			/* rings_start stopped what it started */
	ret = xdev_ext_xd_probe_prepare(xl, &l);
	if (ret)
		goto fail;
	ret = xdev_ext_xd_paths_enable(xl, &l);
	if (ret)
		goto fail;			/* paths_enable disabled what it enabled */
	spin_lock_irq(&xl->lock);
	xl->remote_logged_in = true;
	xl->accepted_inc = l.incarnation;
	xl->receive_ready = true;
	if (xl->candidate_pending && xl->remote_login.incarnation == l.incarnation) {
		xl->candidate_pending = false;
		xl->candidate_probe_started = false;
	}
	spin_unlock_irq(&xl->lock);
	xl->logged_in = false;		/* our login is repeated against the new incarnation */
	xl->login_retries = 0;
	mod_delayed_work(system_long_wq, &xl->login_work, 0);
	xdev_ext_xd_maybe_up(xl);
	goto out;
fail:
	/* Keep the admitted advertisement and local incarnation.  Requiring
	 * another unsolicited LOGIN here loses recovery when the peer has
	 * already received a response. The budget spans all advertisements.
	 */
	spin_lock_irq(&xl->lock);
	xl->receive_ready = false;
	xl->remote_logged_in = false;
	xl->accepted_inc = 0;
	spin_unlock_irq(&xl->lock);
	xdev_ext_xd_rings_stop(xl);
	xdev_ext_xd_paths_disable(xl);
	spin_lock_irq(&xl->lock);
	if (confirmed && !xl->candidate_pending) {
		xl->confirmed_login = l;
		xl->confirmed_pending = true;
	}
	xl->connect_errors++;
	xl->last_error = ret;
	xl->retry_failures++;
	xl->retry_delay_ms = xl->retry_delay_ms ?
		min_t(u32, xl->retry_delay_ms * 2,
		      XDEV_EXT_XD_RELOGIN_MS * XDEV_EXT_XD_LOGIN_RETRIES) :
		XDEV_EXT_XD_RELOGIN_MS;
	xl->retry_pending = true;
	xl->retry_after = jiffies + msecs_to_jiffies(xl->retry_delay_ms);
	if (xl->retry_failures == XDEV_EXT_XD_LOGIN_RETRIES)
		xl->retries_exhausted++;
	spin_unlock_irq(&xl->lock);
	if (xl->retry_failures < XDEV_EXT_XD_LOGIN_RETRIES && !xl->nhi_gone)
		mod_delayed_work(system_long_wq, &xl->login_work,
				 msecs_to_jiffies(xl->retry_delay_ms));
out:
	mutex_unlock(&xl->ctl_mutex);
}

static void xdev_ext_xd_down_work(struct work_struct *work)
{
	struct xdev_ext_xd_link *xl = container_of(work, struct xdev_ext_xd_link, down_work);
	bool same_inc;
	int err;

	mutex_lock(&xl->ctl_mutex);
	spin_lock_irq(&xl->lock);
	err = xl->down_err ? xl->down_err : -ENOLINK;
	same_inc = xl->down_local_inc && xl->down_local_inc == xl->local_inc;
	xl->down_err = 0;
	xl->down_local_inc = 0;
	spin_unlock_irq(&xl->lock);
	/* ctl_mutex keeps a new connection from changing incarnation between
	 * the comparison and teardown. A queued old fault cannot end it. */
	if (same_inc && !READ_ONCE(xl->going_away) && !READ_ONCE(xl->suspended) &&
	    !READ_ONCE(xl->gone) && !READ_ONCE(xl->nhi_gone))
		xdev_ext_xd_link_down_locked(xl, err, true);
	mutex_unlock(&xl->ctl_mutex);
}

/* ctl_mutex held: tell the peer we leave (best effort, not waited for). */
static void xdev_ext_xd_send_logout(struct xdev_ext_xd_link *xl)
{
	struct xdev_ext_xd_login req = {};
	u32 command_id;
	int ret;

	if (!xl->up || xl->gone || xl->nhi_gone)
		return;
	ret = xdev_ext_xd_next_command_id(xl, &command_id);
	if (ret) {
		spin_lock_irq(&xl->lock);
		xl->last_error = ret;
		spin_unlock_irq(&xl->lock);
		return;
	}
	xdev_ext_xd_fill_hdr(xl, &req, sizeof(req), XDEV_EXT_XD_LOGOUT, &xl->local_uuid,
			     &xl->remote_uuid, command_id);
	spin_lock_irq(&xl->lock);
	req.incarnation = xl->local_inc;
	spin_unlock_irq(&xl->lock);
	tb_xdomain_response(xl->xd, &req, sizeof(req), TB_CFG_PKG_XDOMAIN_RESP);
}

/* Set @flag (going_away or suspended) and stop every work item. */
static void xdev_ext_xd_quiesce_work(struct xdev_ext_xd_link *xl, bool *flag)
{
	/* Publish cancellation before waiting for ctl_mutex or a worker.
	 * The CM may already hold tb->lock while it unbinds this service.
	 */
	spin_lock_irq(&xl->lock);
	WRITE_ONCE(*flag, true);
	spin_unlock_irq(&xl->lock);
	cancel_delayed_work_sync(&xl->probe_work);
	cancel_delayed_work_sync(&xl->login_work);
	cancel_work_sync(&xl->connect_work);
	cancel_work_sync(&xl->down_work);
	/* A connect/down worker already running when cancellation was
	 * published can have queued a final retry after the first cancel.
	 * Both producers are now stopped. Drain that retry before the link
	 * is removed; login_work observes the published cancellation flag.
	 */
	cancel_delayed_work_sync(&xl->probe_work);
	cancel_delayed_work_sync(&xl->login_work);
}
/* xdomain login end */

static ssize_t xdev_ext_link_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(tb_to_service(dev));

	(void)attr;
	return sysfs_emit(buf, "%llu\n", xl->token);
}
static DEVICE_ATTR_RO(xdev_ext_link);
static ssize_t xdev_ext_link_state_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(tb_to_service(dev));
	u64 token, local_inc, remote_inc;
	u32 up, closing, nhi_gone, channels;

	(void)attr;
	mutex_lock(&xl->ctl_mutex);
	spin_lock_irq(&xl->lock);
	token = xl->token;
	local_inc = xl->local_inc;
	remote_inc = xl->remote_inc;
	up = xl->up;
	closing = xl->going_away || xl->suspended || xl->gone;
	nhi_gone = xl->nhi_gone;
	channels = xl->channels;
	spin_unlock_irq(&xl->lock);
	mutex_unlock(&xl->ctl_mutex);
	return sysfs_emit(buf,
		"version=1 token=%llu local_inc=%llu remote_inc=%llu up=%u closing=%u nhi_gone=%u channels=%u\n",
		token, local_inc, remote_inc, up, closing, nhi_gone, channels);
}
static DEVICE_ATTR_RO(xdev_ext_link_state);
static ssize_t xdev_ext_link_stats_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(tb_to_service(dev));
	struct xdev_ext_requester_retention_stats retained;
	u64 token, login_attempts, login_errors, version_errors, crc_errors;
	u64 connect_errors, retries_exhausted, link_ups;
	u32 retry_delay_ms, e2e_rx;
	int last_error;

	(void)attr;
	mutex_lock(&xl->ctl_mutex);
	xdev_ext_requester_retention_snapshot(xl->nhi_pdev, &retained);
	spin_lock_irq(&xl->lock);
	token = xl->token;
	login_attempts = xl->login_attempts;
	login_errors = xl->login_errors;
	version_errors = xl->version_errors;
	crc_errors = xl->crc_errors;
	connect_errors = xl->connect_errors;
	retries_exhausted = xl->retries_exhausted;
	link_ups = xl->link_ups;
	last_error = xl->last_error;
	retry_delay_ms = xl->retry_delay_ms;
	e2e_rx = xl->e2e;
	spin_unlock_irq(&xl->lock);
	mutex_unlock(&xl->ctl_mutex);
	return sysfs_emit(buf,
		"version=1 token=%llu login_attempts=%llu login_errors=%llu "
		"version_errors=%llu crc_errors=%llu connect_errors=%llu "
		"retries_exhausted=%llu link_ups=%llu last_error=%d retry_delay_ms=%u "
		"e2e_rx=%u e2e_tx=0 generations=%u retained_generations=%u "
		"reserved_bytes=%llu retained_bytes=%llu global_reserved_bytes=%llu "
		"global_retained_bytes=%llu global_limit=%llu\n",
		token, login_attempts, login_errors, version_errors, crc_errors,
		connect_errors, retries_exhausted, link_ups, last_error, retry_delay_ms,
		e2e_rx, retained.generations, retained.retained_generations,
		retained.reserved_bytes, retained.retained_bytes,
		retained.global_reserved_bytes, retained.global_retained_bytes, retained.global_limit);
}
static DEVICE_ATTR_RO(xdev_ext_link_stats);
static ssize_t xdev_ext_data_state_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(tb_to_service(dev));
	ssize_t len;

	(void)attr;
	mutex_lock(&xl->ctl_mutex);
	len = xdev_ext_xd_probe_show(xl, buf);
	mutex_unlock(&xl->ctl_mutex);
	return len;
}
static DEVICE_ATTR_RO(xdev_ext_data_state);
static struct attribute *xdev_ext_xd_attrs[] = {
	&dev_attr_xdev_ext_link.attr,
	&dev_attr_xdev_ext_link_state.attr,
	&dev_attr_xdev_ext_link_stats.attr,
	&dev_attr_xdev_ext_data_state.attr,
	NULL,
};
ATTRIBUTE_GROUPS(xdev_ext_xd);

static int xdev_ext_xd_probe(struct tb_service *svc, const struct tb_service_id *id)
{
	struct xdev_ext_xd_link *xl = kzalloc(sizeof(*xl), GFP_KERNEL);
	struct tb_xdomain *xd = tb_service_parent(svc);
	int ret;

	(void)id;
	if (!xl)
		return -ENOMEM;
	kref_init(&xl->ref);
	spin_lock_init(&xl->lock);
	mutex_init(&xl->ctl_mutex);
	mutex_init(&xl->ep_mutex);
	mutex_init(&xl->poll_mutex);
	xl->poll_completions = poll_completions;
	INIT_DELAYED_WORK(&xl->poll_work, xdev_ext_xd_poll_work);
	xl->svc = svc;
	xl->xd = xd;
	xl->route = xd->route;
	uuid_copy(&xl->local_uuid, xd->local_uuid);
	uuid_copy(&xl->remote_uuid, xd->remote_uuid);
	xl->nhi_pdev = pci_dev_get(xd->tb->nhi->pdev);	/* what tb_ring_dma_device() returns */
	xl->channels = XDEV_EXT_XD_CHANNELS_V1;
	xl->e2e = xdev_ext_xd_e2e && (svc->prtcstns & XDEV_EXT_XD_CAP_E2E);
	xdev_ext_xd_new_incarnation(xl);
	INIT_DELAYED_WORK(&xl->probe_work, xdev_ext_xd_probe_work);
	INIT_DELAYED_WORK(&xl->login_work, xdev_ext_xd_login_work);
	INIT_WORK(&xl->connect_work, xdev_ext_xd_connect_work);
	INIT_WORK(&xl->down_work, xdev_ext_xd_down_work);
	ret = xdev_ext_xd_rings_alloc(xl);	/* frees what it allocated on failure */
	if (ret)
		goto free;
	tb_service_set_drvdata(svc, xl);
	mutex_lock(&xdev_ext_xd_links_lock);
	if (xdev_ext_xd_next_token == ~0ULL) {
		mutex_unlock(&xdev_ext_xd_links_lock);
		tb_service_set_drvdata(svc, NULL);
		xdev_ext_xd_rings_free(xl);
		ret = -EOVERFLOW;
		goto free;
	}
	xl->token = ++xdev_ext_xd_next_token;
	list_add_tail(&xl->node, &xdev_ext_xd_links);	/* from here the handler may find it */
	mutex_unlock(&xdev_ext_xd_links_lock);
	queue_delayed_work(system_long_wq, &xl->login_work, 0);
	return 0;
free:
	pci_dev_put(xl->nhi_pdev);
	kfree(xl);
	return ret;
}

/* xdomain lifetime begin */
static void xdev_ext_xd_remove(struct tb_service *svc)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(svc);

	/* 1. No packet handler can reach the link once it is off the list. */
	mutex_lock(&xdev_ext_xd_links_lock);
	list_del(&xl->node);
	mutex_unlock(&xdev_ext_xd_links_lock);
	/* 2. No work item runs or is queued after this. */
	xdev_ext_xd_quiesce_work(xl, &xl->going_away);
	/* 3. Tell the peer, then end the link: stages die, rings stop, paths go. */
	mutex_lock(&xl->ctl_mutex);
	xdev_ext_xd_send_logout(xl);
	xdev_ext_xd_link_down_locked(xl, -ENOLINK, true);
	/* 4. Rings and HopIDs belong to the NHI and the XDomain: free them now.
	 *    A stage still bound keeps only the link memory (section 4.8). */
	spin_lock_irq(&xl->lock);
	xl->gone = true;
	spin_unlock_irq(&xl->lock);
	xdev_ext_xd_rings_free(xl);
	xl->xd = NULL;
	xl->svc = NULL;
	mutex_unlock(&xl->ctl_mutex);
	xdev_ext_xd_link_put(xl);
}

static int xdev_ext_xd_suspend(struct device *dev)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(tb_to_service(dev));

	/* The NHI core does not stop service rings across sleep
	 * (drivers/thunderbolt/nhi.c:964-1044): stop them here.  Posted
	 * device-memory elements are reported canceled and quarantined. */
	xdev_ext_xd_quiesce_work(xl, &xl->suspended);
	xdev_ext_xd_link_down(xl, -ESHUTDOWN);
	return 0;
}

static int xdev_ext_xd_resume(struct device *dev)
{
	struct xdev_ext_xd_link *xl = tb_service_get_drvdata(tb_to_service(dev));

	mutex_lock(&xl->ctl_mutex);
	if (xl->going_away || xl->gone || xl->nhi_gone)
		goto out;
	spin_lock_irq(&xl->lock);
	xl->suspended = false;
	spin_unlock_irq(&xl->lock);
	xdev_ext_xd_new_incarnation(xl);
	xl->login_retries = 0;
	queue_delayed_work(system_long_wq, &xl->login_work, 0);
out:
	mutex_unlock(&xl->ctl_mutex);
	return 0;
}
/* xdomain lifetime end */
static DEFINE_SIMPLE_DEV_PM_OPS(xdev_ext_xd_pm_ops, xdev_ext_xd_suspend, xdev_ext_xd_resume);

static const struct tb_service_id xdev_ext_xd_ids[] = {
	{ TB_SERVICE(XDEV_EXT_XD_KEY, 1) },
	{ },
};
MODULE_DEVICE_TABLE(tbsvc, xdev_ext_xd_ids);

static struct tb_service_driver xdev_ext_xd_driver = {
	.driver = { .owner = THIS_MODULE, .name = "xdev_ext_xdomain", .dev_groups = xdev_ext_xd_groups,
		    .pm = pm_sleep_ptr(&xdev_ext_xd_pm_ops) },
	.probe = xdev_ext_xd_probe,
	.remove = xdev_ext_xd_remove,
	.id_table = xdev_ext_xd_ids,
};

static struct tb_protocol_handler xdev_ext_xd_handler = {
	.uuid = &xdev_ext_xd_proto_uuid,
	.callback = xdev_ext_xd_handle_packet,
};

static int __init xdev_ext_xd_init(void)
{
	int ret;

	xdev_ext_xd_dir = tb_property_create_dir(&xdev_ext_xd_dir_uuid);
	if (!xdev_ext_xd_dir)
		return -ENOMEM;
	ret = tb_property_add_immediate(xdev_ext_xd_dir, "prtcid", 1);
	if (ret)
		goto dir;
	ret = tb_property_add_immediate(xdev_ext_xd_dir, "prtcvers", 1);
	if (ret)
		goto dir;
	ret = tb_property_add_immediate(xdev_ext_xd_dir, "prtcrevs", 1);
	if (ret)
		goto dir;
	ret = tb_property_add_immediate(xdev_ext_xd_dir, "prtcstns",
					XDEV_EXT_XD_CAP_DATA_CHALLENGE |
					(xdev_ext_xd_e2e ? XDEV_EXT_XD_CAP_E2E : 0));
	if (ret)
		goto dir;
	ret = xdev_ext_xd_class_register();
	if (ret)
		goto dir;
	ret = tb_register_protocol_handler(&xdev_ext_xd_handler);
	if (ret)
		goto class;
	ret = tb_register_property_dir(XDEV_EXT_XD_KEY, xdev_ext_xd_dir);
	if (ret)
		goto handler;
	ret = tb_register_service_driver(&xdev_ext_xd_driver);
	if (ret)
		goto prop;
	return 0;
prop:
	tb_unregister_property_dir(XDEV_EXT_XD_KEY, xdev_ext_xd_dir);
handler:
	tb_unregister_protocol_handler(&xdev_ext_xd_handler);
class:
	xdev_ext_xd_class_unregister();
dir:
	tb_property_free_dir(xdev_ext_xd_dir);
	return ret;
}
module_init(xdev_ext_xd_init);

static void __exit xdev_ext_xd_exit(void)
{
	tb_unregister_service_driver(&xdev_ext_xd_driver);	/* removes every link */
	tb_unregister_property_dir(XDEV_EXT_XD_KEY, xdev_ext_xd_dir);
	/* X3a makes unregister synchronous with every running callback.
	 * It must land before this module's X7 load/unload acceptance. */
	tb_unregister_protocol_handler(&xdev_ext_xd_handler);
	xdev_ext_xd_class_unregister();
	tb_property_free_dir(xdev_ext_xd_dir);
}
module_exit(xdev_ext_xd_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("XDEV_EXT XDOMAIN class: Thunderbolt/USB4 host-to-host device-memory transport");
