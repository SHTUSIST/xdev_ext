/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_STORFAM_BLOCK_H
#define _LINUX_XDEV_EXT_STORFAM_BLOCK_H

#include <linux/xdev_ext_storfam_core.h>

struct request_queue;
struct request;
struct bio;
struct xdev_ext_mech_pool;
struct xdev_ext_mech_batch;

/* Worker: snapshot the current queue limits for a validated LBA shift. */
struct xdev_ext_stor_queue_caps
xdev_ext_stor_block_caps(struct request_queue *queue, __u8 lba_shift);

/* Worker: return the positive page-piece count, or -errno, without mapping. */
int xdev_ext_stor_block_preflight(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch,
		const struct xdev_ext_stor_queue_caps *caps);

/* Worker, after preflight of the same exclusively owned batch: add its pages
 * to the caller-initialized bio and append it to request. All arguments are
 * borrowed synchronously; the caller retains bio init/uninit and ownership.
 */
int xdev_ext_stor_block_append(struct xdev_ext_mech_pool *pool,
		struct xdev_ext_mech_batch *batch, struct request *request,
		struct bio *bio);

#ifdef CONFIG_BLOCK
#include <linux/atomic.h>
#include <linux/blk_types.h>
#include <linux/xdev_ext_requester.h>
#include <linux/xdev_ext_storfam_runtime.h>

struct xdev_ext_stor_completion;

/* CREATE: require an existing hardware poll queue, without IRQ fallback. */
bool xdev_ext_stor_block_poll_capable(const struct request_queue *queue);

static inline blk_opf_t xdev_ext_stor_block_poll_opf(bool poll, blk_opf_t opf)
{
	return poll ? opf | REQ_POLLED : opf;
}

/* Worker: check the allocated request before claiming or mapping a slot. */
int xdev_ext_stor_block_poll_check(bool poll, struct request *request);

/* Worker: arm after the completion context and end_io_data are ready. */
void xdev_ext_stor_block_poll_arm(bool poll, struct request *request,
		struct xdev_ext_stor_completion *done);

/* Borrowed slot array: first is the first embedded completion, stride is
 * sizeof the owning slot. Empty views may have first == NULL.
 */
struct xdev_ext_stor_poll_view {
	struct xdev_ext_stor_completion *first;
	size_t stride;
	__u32 count;
};

struct pci_dev;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_stage_uapi;
struct xdev_ext_stor_stage;
struct xdev_ext_stor_io;
struct xdev_ext_stor_peer_resources;
struct xdev_ext_peer_fd_lease;
struct xdev_ext_peer_requester;
struct page;

struct xdev_ext_stor_command {
	__u8 bytes[64];
} __aligned(8);

struct xdev_ext_stor_geometry {
	__u64 capacity_lbas;
	__u8 lba_shift;
};

enum xdev_ext_stor_host_path {
	XDEV_EXT_STOR_HOST_NATIVE_RQ = 0,
	XDEV_EXT_STOR_HOST_BIO = 1,
};

/* Native member boundaries consumed by the block family runtime. */
struct xdev_ext_stor_dev_ops {
	/* Zero preserves the original native-request route. */
	enum xdev_ext_stor_host_path host_path;
	/* Borrowed opened device; required only for the ordinary BIO route. */
	struct block_device *(*bdev)(void *member);
	int (*bind)(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		struct xdev_ext_stor_stage **family, void **member);
	void (*unbind)(void *member);
	int (*identity)(void *member, bool final,
		struct xdev_ext_stor_geometry *geometry);
	struct pci_dev *(*requester)(void *member);
	struct request_queue *(*queue)(void *member);
	int (*decode)(void *member, struct xdev_ext_mech_batch *batch,
		const __u8 sqe[64], const struct xdev_ext_stor_window *window,
		__u32 bytes, struct xdev_ext_stor_rw *rw);
	int (*encode)(void *member, const struct xdev_ext_stor_rw *admitted,
		const __u8 admitted_sqe[64], __u32 batch_bytes, bool peer,
		struct xdev_ext_stor_rw *posting, struct xdev_ext_stor_command *cmd);
	int (*encode_dptr)(void *member, struct xdev_ext_stor_command *cmd,
		const struct xdev_ext_stor_extent *spans, __u32 nr,
		struct xdev_ext_stor_extent *work, __u32 capacity,
		void *list_cpu, __u64 list_dma, __u32 list_bytes);
	/* HOST: before slot/map. PEER: after lease/DPTR/drift admission. */
	void (*request_init)(void *member, struct request *request,
		struct xdev_ext_stor_command *cmd, bool peer);
	/* BIO passes NULL request/command and peer=false; io->bio is initialized.
	 * Accept exactly once; end_io may free request before this void call returns.
	 * post retains no command pointer and performs no fallible preaccept work.
	 */
	void (*post)(void *member, struct request *request,
		struct xdev_ext_stor_io *io, struct xdev_ext_mech_batch *batch,
		const struct xdev_ext_stor_command *cmd, bool peer);
	/* Worker, after handle retirement and before clearing nr_leases. */
	void (*retire_peer)(void *member, struct xdev_ext_stor_io *io,
		bool quiesced);
	/* Optional; after the command's completion was consumed: the requester
	 * record and the DMA-stop epoch the command became visible to the device
	 * in, read from io->peer_native (a device-memory slot, or a host-page
	 * slot when host_native_bytes is set).  NULL and
	 * XDEV_EXT_PEER_EPOCH_NONE when it never reached a queue.  Without it an
	 * UNKNOWN command can never be released. */
	void (*peer_evidence)(void *member, const struct xdev_ext_stor_io *io,
		struct xdev_ext_peer_requester **rq, __u64 *epoch);
	__u32 peer_slot_bytes;
	__u32 peer_native_offset;
	/* Native-request host-page slots: bytes of member state per slot, at
	 * io->peer_native; 0 for none (no evidence for those slots). */
	__u32 host_native_bytes;
	int (*poll)(void *member, const struct xdev_ext_stor_poll_view *views,
		__u32 nr_views);
};

/* Family owns both depth arrays; stage file and class owner pin the member. */
struct xdev_ext_stor_io {
	struct xdev_ext_stor_completion done;
	struct xdev_ext_stor_slot runtime;
	struct bio *bio;
	struct page **bounce;
	__u32 nr_bounce;
	bool bio_live;
	struct xdev_ext_peer_fd_lease *leases;
	struct xdev_ext_stor_extent *spans;
	void *list_cpu;
	__u64 list_dma;
	__u32 nr_leases;
	void *peer_native;
};

/* PEER only: spans and the member's native tail share one slot allocation. */
struct xdev_ext_stor_peer_io {
	struct xdev_ext_stor_io io;
	struct xdev_ext_stor_extent spans[512];
};

struct xdev_ext_stor_stage {
	struct xdev_ext_mech_stage *st;
	const struct xdev_ext_stor_dev_ops *dev;
	void *member;
	struct xdev_ext_requester requester;
	struct xdev_ext_stor_window window;
	struct xdev_ext_stor_geometry geometry;
	atomic_t dead;
	struct xdev_ext_stor_poll_view poll_views[2];
	struct xdev_ext_stor_io *slots;
	void *host_native;	/* nr_slots * dev->host_native_bytes, or NULL */
	struct xdev_ext_stor_pool pool;
	__u32 nr_slots;
	__u16 nr_vecs;
	struct xdev_ext_stor_peer_resources *peer;
};

struct xdev_ext_stor_batch {
	__u8 sqe[64];
	struct xdev_ext_stor_rw rw;
	__u64 batch_id;
	bool validated;
	/* Pinned with the batch, including UNKNOWN/ZOMBIE retention. */
	struct xdev_ext_stor_command command;
	struct xdev_ext_stor_rw posting;
	struct xdev_ext_stor_io *host_io, *peer_io;
	struct bio *bio;
	struct page **bounce;
	__u32 nr_bounce;
};

/* CREATE: publish st->priv as the native member only after binding its window. */
int xdev_ext_storfam_bind(struct xdev_ext_mech_stage *st,
		const struct xdev_ext_mech_stage_uapi *u,
		const struct xdev_ext_stor_dev_ops *dev);
int xdev_ext_storfam_validate(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb,
		const __u8 scratch[64], __u32 nr_slots);
int xdev_ext_storfam_submit_check(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb);
int xdev_ext_storfam_submit(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb);
void xdev_ext_storfam_consume(struct xdev_ext_stor_stage *ss,
		struct xdev_ext_mech_batch *batch, struct xdev_ext_stor_batch *sb);
bool xdev_ext_storfam_unbind(struct xdev_ext_stor_stage *ss);
/* Process context, quarantined session, nothing in flight and no worker:
 * the worst enum xdev_ext_peer_evidence over the host-page and device-memory
 * slots retained after UNKNOWN outcomes, and, once COVERED, their return (0,
 * or -errno while any stays retained). */
int xdev_ext_storfam_evidence(struct xdev_ext_stor_stage *ss);
int xdev_ext_storfam_evidence_release(struct xdev_ext_stor_stage *ss);
void xdev_ext_storfam_host_ready(struct xdev_ext_mech_batch *batch,
		int status, bool uncertain);
int xdev_ext_storfam_poll(struct xdev_ext_stor_stage *ss);
void xdev_ext_storfam_mark_dead(struct xdev_ext_stor_stage *ss);

/* Worker: one queue-number pass over all views, without retaining requests. */
int xdev_ext_stor_block_poll(struct request_queue *queue,
		const struct xdev_ext_stor_poll_view *views, __u32 nr_views);
#endif

#endif
