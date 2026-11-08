// SPDX-License-Identifier: GPL-2.0
/* Storage-family ownership and native completion handoff. */
#include <linux/err.h>
#include <linux/export.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_storfam_runtime.h>

void xdev_ext_stor_leases_retire(struct xdev_ext_peer_fd_lease *leases,
			       u32 nr, bool quiesced)
{
	u32 i;

	for (i = 0; i < nr; i++)
		xdev_ext_peer_fd_release(&leases[i], quiesced);
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_leases_retire);

/* Process context: UNKNOWN outcome of one native command that @rq received
 * in @epoch. Every lease is retired; true when a later proven epoch of that
 * requester already covers the command, its own resources and every lease. */
bool xdev_ext_stor_leases_retire_unknown(struct xdev_ext_peer_fd_lease *leases, u32 nr,
					 struct xdev_ext_peer_requester *rq, u64 epoch)
{
	bool quiesced = xdev_ext_peer_requester_evidence(rq, epoch) ==
			XDEV_EXT_PEER_EVIDENCE_COVERED;
	u32 i;

	for (i = 0; i < nr; i++)
		quiesced &= xdev_ext_peer_fd_release_unknown(&leases[i], rq, epoch);
	return quiesced;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_leases_retire_unknown);

/* CREATE adds exactly one node for each member-owned depth slot. */
void xdev_ext_stor_slot_add(struct xdev_ext_stor_pool *pool,
			  struct xdev_ext_stor_slot *slot)
{
	slot->busy = false;
	slot->next = pool->free;
	pool->free = slot;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_slot_add);

/* Worker only: accepted commands cannot share their native context. */
struct xdev_ext_stor_slot *
xdev_ext_stor_slot_get(struct xdev_ext_stor_pool *pool, bool occupied)
{
	struct xdev_ext_stor_slot *slot;

	if (occupied)
		return ERR_PTR(-EBUSY);
	slot = pool->free;
	if (!slot)
		return ERR_PTR(-EAGAIN);
	pool->free = slot->next;
	slot->next = NULL;
	slot->busy = true;
	return slot;
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_slot_get);

/* Worker only, after native completion consumption or preaccept unwind. */
void xdev_ext_stor_slot_put(struct xdev_ext_stor_pool *pool,
			  struct xdev_ext_stor_slot *slot, bool uncertain)
{
	if (uncertain)
		return;
	xdev_ext_stor_slot_add(pool, slot);
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_slot_put);

/* Any native completion context. Claim precedes all mutable batch access. */
void xdev_ext_stor_done(struct xdev_ext_stor_completion *done,
		       int transport_status, void *native,
		       int (*complete)(struct xdev_ext_mech_batch *, void *, int, bool *),
		       void (*ready)(struct xdev_ext_mech_batch *, int, bool))
{
	struct xdev_ext_mech_batch *b = done->b;
	int status;

	WRITE_ONCE(done->poll_live, false);
	if (xdev_ext_mech_batch_completion_claim(b, done->ticket))
		return;
	status = complete(b, native, transport_status, &done->uncertain);
	xdev_ext_mech_trace_native_complete(b, done->ticket, status);
	if (ready)
		ready(b, status, done->uncertain);
	xdev_ext_mech_batch_completion_publish(b, done->ticket, status, done->uncertain);
}
EXPORT_SYMBOL_GPL(xdev_ext_stor_done);
