#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual GPU-memory NVMe stage functions under deterministic native shims.

The real nvme_xdev_ext_peer_* functions, the stage/batch structures and the
class fill_cqe are extracted from drivers/nvme/host/xdev_ext_mech_nvme.c and
compiled against a software block queue: blk_execute_rq_nowait() only records
the request; the test plays the controller by calling the request's end_io
later, in a simulated interrupt context. Provider leases are bookkeeping
records keyed by allocation offset. No GPU, controller, bio or DMA exists, so
this certifies submission ownership, completion publication and lease
lifetime only. Physical NVMe<->GPU validation remains pending hardware.

Contract checked: depth-N sessions keep N native commands outstanding and the
worker never waits; the completion is published only by end_io; leases are
released only by the worker after the completion, quiesced only on success;
an accepted failure is never resubmitted and keeps its slot; preaccept refusal
leaves no lease and no request; GPU pages are described by one inline SGL data
block or a last-segment list when they are not DMA-contiguous.

XDEV_EXT_NVME_TEST_SOURCE may select another copy of the production file.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
RELATIVE = "drivers/nvme/host/xdev_ext_mech_nvme.c"

SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/linux/nvme_xdev_ext_passthru.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int atomic_t; typedef int blk_status_t; typedef u64 dma_addr_t; typedef u32 gfp_t;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
#define XDEV_EXT_PEER_HOST_TEST 1
#include "include/linux/xdev_ext_peer.h"
#include "include/linux/xdev_ext_requester_core.h"
#include "include/uapi/linux/xdev_ext_peer.h"
#include "drivers/nvme/host/xdev_ext_peer_nvme_core.h"
#define GFP_KERNEL 0U
#define SZ_4K 4096U
#define SECTOR_SHIFT 9
#define BLK_MQ_REQ_NOWAIT 1U
#define NVME_REQ_CANCELLED 1U
#define NVME_REQ_USERCMD 2U
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_CMD_SGL_ALL 0xc0
#define NVME_SGL_FMT_DATA_DESC 0x00
#define NVME_SGL_FMT_LAST_SEG_DESC 0x03
#define REQ_FAILFAST_MASK 0x700U
#define NVME_CTRL_LIVE 1
#define NVME_NS_READY 1
#define NVME_NS_REMOVING 2
#define cpu_to_le16(v) (v)
#define cpu_to_le32(v) (v)
#define cpu_to_le64(v) (v)
#define le32_to_cpu(v) (v)
#define le64_to_cpu(v) (v)
#define le16_to_cpu(v) (v)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define WARN_ON_ONCE(x) (!!(x))
#define atomic_read(p) (*(p))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ALIGN_DOWN(x, a) ((x) & ~((__typeof__(x))(a) - 1))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((__typeof__(x))(a) - 1))
#define nvme_req(r) (&(r)->nr)
#define nvme_req_op(c) ((c)->rw.opcode & 1)
/* Stage polling: these sessions never set the bit; the helpers are verbatim. */
typedef u32 blk_opf_t;
#define REQ_POLLED (1U << 21)
#define WRITE_ONCE(x, v) ((x) = (v))
struct blk_mq_hw_ctx { unsigned int queue_num; };
struct device { int is_pci; };
struct pci_dev { struct device dev; };
#define to_pci_dev(d) ((struct pci_dev *)(d))
#define dev_is_pci(d) ((d)->is_pci)
struct file { int unused; };
struct nvme_sgl_desc { u64 addr; u32 length; u8 rsvd[3]; u8 type; };
struct nvme_command {
 union {
  struct { u8 opcode, flags; u16 command_id; u32 nsid; u64 rsvd2, metadata;
           union { struct nvme_sgl_desc sgl; struct { u64 prp1, prp2; }; } dptr; u64 slba; u16 length, control; } rw;
  struct { u8 opcode, flags; u16 command_id; u32 nsid; u32 cdw2[2]; u64 metadata;
           union { struct nvme_sgl_desc sgl; struct { u64 prp1, prp2; }; } dptr; u32 cdw10, cdw11, cdw12; } common;
 };
};
struct nvme_ns;
struct ctrl_ops { const char *name;
 int (*peer_rw)(struct nvme_ns *, const struct xdev_ext_peer_nvme_rw *, struct file *, bool *); };
struct nvme_ctrl { int state; struct device *dev; const struct ctrl_ops *ops; };
struct nvme_ns_head { u8 lba_shift; u16 ms; struct { u8 csi; } ids; u32 ns_id; };
struct gendisk { u64 sectors; bool ro; };
struct request_queue { u32 max_hw_sectors; };
struct nvme_ns { struct nvme_ctrl *ctrl; unsigned long flags; struct nvme_ns_head *head;
                 struct gendisk *disk; struct request_queue *queue; };
enum rq_end_io_ret { RQ_END_IO_NONE, RQ_END_IO_FREE };
struct request {
 struct { struct nvme_command *cmd; u32 flags; u16 status; struct { u64 u64; } result; } nr;
 u32 cmd_flags;
 struct blk_mq_hw_ctx *mq_hctx;
 enum rq_end_io_ret (*end_io)(struct request *, blk_status_t);
 void *end_io_data;
 struct nvme_command storage;
 bool allocated, executed, ended;
};
struct xdev_ext_mech_pool { u32 kind, frame_size, nr_frames; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; struct xdev_ext_mech_layout l; u32 depth, state; };
struct xdev_ext_mech_stage { void *priv; struct xdev_ext_mech_session *s; bool poll; };
struct xdev_ext_mech_frame { void *kaddr; u64 umem_addr; u32 index, data_off, data_len; void *pool_priv; };
struct nvme_xdev_ext_mech_batch;
#define MAX_TEST_FRAMES 4
struct xdev_ext_mech_batch { void *priv; struct xdev_ext_mech_frame f[MAX_TEST_FRAMES]; u32 nr, bytes;
 u64 ticket, id; int claims, publishes, status; bool sequester; };
/* PRODUCTION_TYPES */
static struct file authority;
static struct device pci_device = { 1 };
static int in_irq, blocked_worker, host_slot_puts, host_bounce_releases, executes, frees, allocs, tag_full;
static int live_leases, quiesced_releases, unquiesced_releases, irq_releases, acquire_calls;
static int coherent_live, acquire_error;
static u32 provider_page = 65536;
static u64 provider_dma(u64 off)
{ /* GPU page n maps at 0x40000000 + n*page, except page 2 which is remote. */
 u64 page = off / provider_page; u64 base = 0x40000000ULL + page * provider_page;
 if (page == 2) base += 0x10000000ULL;
 return base + off % provider_page; }
static enum dma_data_direction last_dir;
static u64 last_offset;
int xdev_ext_peer_file_acquire(struct file *f, struct pci_dev *p, u64 generation, u64 offset,
                              u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h)
{
 assert(!in_irq && f == &authority && p == (struct pci_dev *)&pci_device && generation == 87);
 acquire_calls++;
 if (!h || h->file || h->lease.mapping) return -EINVAL;
 if (acquire_error) return acquire_error;
 if (!len || len > provider_page - offset % provider_page) return -ERANGE;
 h->file = f; h->lease.mapping = (struct xdev_ext_peer_mapping *)(uintptr_t)1;
 h->lease.dma_address = provider_dma(offset); h->lease.len = len;
 last_dir = dir; last_offset = offset; live_leases++;
 return 0;
}
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool quiesced)
{
 if (in_irq) irq_releases++;
 if (!h || !h->file) return;
 h->file = NULL; h->lease.mapping = NULL; h->lease.dma_address = 0; h->lease.len = 0;
 live_leases--; if (quiesced) quiesced_releases++; else unquiesced_releases++;
}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->l; }
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s) { return s->depth; }
static u32 xdev_ext_mech_session_state(struct xdev_ext_mech_session *s) { return s->state; }
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return b->priv; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { return b->nr; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { return b->bytes; }
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { return b->ticket; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { return b->id; }
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b, u32 pos, struct xdev_ext_mech_frame *f)
{ if (pos >= b->nr) return -ERANGE; *f = b->f[pos]; return 0; }
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p) { assert(p->kind == 3); return 87; }
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p) { assert(p->kind == 3); return &authority; }
static void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,
 u64 cookie, u64 lba, u32 bytes, u32 plan)
{ (void)b; (void)cookie; (void)lba; (void)bytes; (void)plan; }
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,
 u64 ticket, int status)
{ (void)b; (void)ticket; (void)status; }
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, u64 ticket)
{ if (ticket != b->ticket || b->claims) return -ESTALE; b->claims++; return 0; }
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b, u64 ticket, int err, bool sequester)
{ assert(ticket == b->ticket && b->claims == 1 && !b->publishes); b->publishes++; b->status = err; b->sequester = sequester; }
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b, u64 ticket, int err)
{ if (!xdev_ext_mech_batch_completion_claim(b, ticket)) xdev_ext_mech_batch_completion_publish(b, ticket, err, false); }
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b, u64 ticket, int err)
{ if (!xdev_ext_mech_batch_completion_claim(b, ticket)) xdev_ext_mech_batch_completion_publish(b, ticket, err, true); }
static int nvme_ctrl_state(struct nvme_ctrl *c) { return c->state; }
/* Never polled here: a polled stage would refuse an interrupt-queue request. */
static bool blk_rq_is_poll(struct request *r) { (void)r; abort(); }
static bool test_bit(unsigned bit, const unsigned long *p) { return (*p >> bit) & 1; }
static bool get_disk_ro(struct gendisk *d) { return d->ro; }
static u64 get_capacity(struct gendisk *d) { return d->sectors; }
static u32 queue_max_hw_sectors(struct request_queue *q) { return q->max_hw_sectors; }
static int blk_status_to_errno(blk_status_t s) { return s ? -EIO : 0; }
static void *kzalloc(size_t n, gfp_t g) { (void)g; return calloc(1, n); }
static void *kcalloc(size_t n, size_t s, gfp_t g) { (void)g; return calloc(n, s); }
static void kfree(const void *p) { free((void *)p); }
static void *kvcalloc(size_t n, size_t s, gfp_t g) { (void)g; return calloc(n, s); }
static void kvfree(const void *p) { free((void *)p); }
static u64 coherent_base = 0x9000000ULL;
static void *dma_alloc_coherent(struct device *d, size_t n, dma_addr_t *dma, gfp_t g)
{ (void)g; assert(d == &pci_device); coherent_live++; *dma = coherent_base; return calloc(1, n); }
static void dma_free_coherent(struct device *d, size_t n, void *p, dma_addr_t dma)
{ (void)n; assert(d == &pci_device && dma == coherent_base); coherent_live--; free(p); }
#define NREQ 64
static struct request requests[NREQ];
static struct request *blk_mq_alloc_request(struct request_queue *q, int op, u32 flags)
{
 (void)q; (void)op; assert(!in_irq);
 if (!(flags & BLK_MQ_REQ_NOWAIT)) { blocked_worker++; return ERR_PTR(-ETIMEDOUT); }
 if (tag_full) return ERR_PTR(-EWOULDBLOCK);
 for (int i = 0; i < NREQ; i++) if (!requests[i].allocated) {
  memset(&requests[i], 0, sizeof(requests[i])); requests[i].allocated = true;
  requests[i].nr.cmd = &requests[i].storage; allocs++; return &requests[i]; }
 return ERR_PTR(-EWOULDBLOCK);
}
static void blk_mq_free_request(struct request *r) { assert(r->allocated && !r->executed); r->allocated = false; frees++; }
static void nvme_init_request(struct request *r, struct nvme_command *c)
{ c->common.flags &= ~NVME_CMD_SGL_ALL; *r->nr.cmd = *c; }
static void blk_execute_rq_nowait(struct request *r, bool at_head)
{ assert(!at_head && r->allocated && !r->executed && r->end_io); r->executed = true; executes++; }
static int nvme_execute_rq(struct request *r, bool at_head)
{ (void)r; (void)at_head; blocked_worker++; return 0; }
/* Controller side: the request ends exactly once, in interrupt context. */
static void controller_complete(struct request *r, u16 status, u32 flags, blk_status_t err)
{
 assert(r->executed && !r->ended); r->ended = true; r->nr.status = status; r->nr.flags |= flags;
 in_irq = 1; assert(r->end_io(r, err) == RQ_END_IO_FREE); in_irq = 0;
 r->allocated = false;
}
static int allocated(void)
{ int n = 0; for (int i = 0; i < NREQ; i++) n += requests[i].allocated; return n; }
static int outstanding(void)
{ int n = 0; for (int i = 0; i < NREQ; i++) n += requests[i].executed && !requests[i].ended; return n; }
static struct request *nth_outstanding(int k)
{ for (int i = 0; i < NREQ; i++) if (requests[i].executed && !requests[i].ended && !k--) return &requests[i]; return NULL; }
/* Pre-async code reached the controller through the synchronous ioctl
 * operation from the session worker. */
static int sync_peer_rw(struct nvme_ns *ns, const struct xdev_ext_peer_nvme_rw *u, struct file *f, bool *accepted)
{ (void)ns; (void)u; (void)f; blocked_worker++; executes++; if (accepted) *accepted = true; return 0; }
/* The host-page completion must never run for a GPU-memory batch. */
static void nvme_xdev_ext_class_bounce_release(struct xdev_ext_mech_batch *b, struct nvme_xdev_ext_mech_batch *bp, bool c)
{ (void)b; (void)bp; (void)c; host_bounce_releases++; }
static void nvme_xdev_ext_class_slot_put(struct xdev_ext_mech_stage *st, struct nvme_xdev_ext_mech_batch *bp)
{ (void)st; (void)bp; host_slot_puts++; }
/* PRP/SGL capability shim: production now selects either data pointer. */
static bool ctrl_sgl = true;
static bool nvme_ctrl_sgl_supported(struct nvme_ctrl *c) { (void)c; return ctrl_sgl; }
/* PRODUCTION_FUNCTIONS */
'''

MAIN = r'''
static const struct ctrl_ops ops = { "pcie", sync_peer_rw };
static struct nvme_ctrl ctrl = { NVME_CTRL_LIVE, &pci_device, &ops };
static struct nvme_ns_head head = { .lba_shift = 9, .ns_id = 7 };
static struct gendisk disk = { 1U << 30, false };
static struct request_queue queue = { 4096 };
static struct nvme_ns ns = { &ctrl, 1UL << NVME_NS_READY, &head, &disk, &queue };
static struct xdev_ext_mech_session session;
static struct nvme_xdev_ext_mech_stage priv;
static struct xdev_ext_mech_stage st = { &priv, &session, false };
#define DEPTH 4
static struct nvme_xdev_ext_mech_batch bps[8];
static struct xdev_ext_mech_batch bs[8];
static int failures;
#define CHECK(cond, text) do { if (!(cond)) { printf("not ok - %s (%s:%d)\n", text, __FILE__, __LINE__); failures++; return; } } while (0)
static void batch_init(int i, u32 frame, u32 off, u32 len, u64 slba)
{
 memset(&bps[i], 0, sizeof(bps[i])); memset(&bs[i], 0, sizeof(bs[i]));
 bs[i].priv = &bps[i]; bs[i].nr = 1; bs[i].bytes = len; bs[i].ticket = 100 + i; bs[i].id = 200 + i;
 bs[i].f[0] = (struct xdev_ext_mech_frame){ .umem_addr = (u64)frame * 65536, .index = frame,
   .data_off = off, .data_len = len };
 bps[i].validated = true; bps[i].batch_id = bs[i].id;
 bps[i].sqe[40] = slba & 0xff; bps[i].sqe[41] = (slba >> 8) & 0xff;
 bps[i].sqe[42] = (slba >> 16) & 0xff; bps[i].sqe[43] = (slba >> 24) & 0xff;
}
static void worker_consume(int i)
{ struct xdev_ext_nvme_mech_cqe cqe; memset(&cqe, 0, sizeof(cqe)); FILL_CQE(&st, &bs[i], &cqe);
  assert(cqe.status == bps[i].cqe.status && cqe.err == bps[i].cqe.err); }
static void case_depth(void)
{
 for (int i = 0; i < DEPTH; i++) { batch_init(i, i, 512, 4096, 16 * i); CHECK(!SUBMIT(&st, &bs[i]), "accepted submit returns 0"); }
 printf("# after %d submits: outstanding=%d worker_waits=%d published=%d\n", DEPTH, outstanding(),
        blocked_worker, bs[0].publishes + bs[1].publishes + bs[2].publishes + bs[3].publishes);
 CHECK(outstanding() == DEPTH && !blocked_worker,
       "depth-4 GPU-memory submits leave four native commands outstanding without a worker wait");
 for (int i = 0; i < DEPTH; i++) CHECK(!bs[i].publishes, "no completion is published before the native end_io");
 CHECK(live_leases == DEPTH, "each outstanding command holds its provider lease");
 struct request *r = nth_outstanding(0);
 struct nvme_command *c = r->nr.cmd;
 CHECK(c->rw.opcode == 2 && c->rw.nsid == 7 && c->rw.slba == 0 && c->rw.length == 7 &&
       c->rw.dptr.sgl.addr == provider_dma(512) && c->rw.dptr.sgl.length == 4096 &&
       c->rw.dptr.sgl.type == (NVME_SGL_FMT_DATA_DESC << 4) && c->common.flags == NVME_CMD_SGL_METABUF &&
       (r->cmd_flags & REQ_FAILFAST_MASK) == REQ_FAILFAST_MASK && (r->nr.flags & NVME_REQ_USERCMD),
       "one-page command carries an inline SGL data block at the leased subspan, fail-fast, no bio");
 CHECK(last_dir == DMA_FROM_DEVICE && last_offset == 3 * 65536 + 512, "read leases the frame subspan from-device");
 /* Out of order, from interrupt context. */
 int order[DEPTH] = { 2, 0, 3, 1 };
 for (int k = 0; k < DEPTH; k++) {
  int i = order[k];
  struct request *q = NULL;
  for (int j = 0; j < NREQ; j++)
   if (requests[j].executed && !requests[j].ended &&
       ((struct nvme_xdev_ext_mech_completion *)requests[j].end_io_data)->b == &bs[i]) q = &requests[j];
  CHECK(q, "end_io context names its own batch");
  q->nr.result.u64 = 0x55 + i;
  controller_complete(q, 0, 0, 0);
  CHECK(bs[i].publishes == 1 && !bs[i].status && !bs[i].sequester, "end_io publishes success exactly once");
  CHECK(bps[i].cqe.result == (u64)0x55 + i, "native result reaches the CQE");
 }
 CHECK(!irq_releases && live_leases == DEPTH, "leases are never released from end_io");
 for (int i = 0; i < DEPTH; i++) worker_consume(i);
 CHECK(!live_leases && quiesced_releases == DEPTH && !unquiesced_releases,
       "worker releases each successful lease quiesced after the completion");
 CHECK(!host_slot_puts && !host_bounce_releases, "GPU-memory completion never runs host-page cleanup");
 for (int i = 0; i < DEPTH; i++) { batch_init(i, i, 0, 65536, 0); CHECK(!SUBMIT(&st, &bs[i]), "freed slots are reusable"); }
 CHECK(outstanding() == DEPTH, "second round outstanding");
 for (int i = 0; i < DEPTH; i++) { controller_complete(nth_outstanding(0), 0, 0, 0); }
 for (int i = 0; i < DEPTH; i++) worker_consume(i);
 CHECK(!live_leases, "second round released");
 puts("ok 1 - depth-4 GPU-memory NVMe commands stay outstanding together; end_io publishes, worker releases leases");
}
static void case_slots(void)
{
 for (int i = 0; i < DEPTH; i++) { batch_init(i, i, 0, 4096, 0); CHECK(!SUBMIT(&st, &bs[i]), "fill depth"); }
 batch_init(4, 0, 0, 4096, 0);
 CHECK(SUBMIT(&st, &bs[4]) == -EAGAIN && allocated() == DEPTH &&
       live_leases == DEPTH && outstanding() == DEPTH && !bs[4].publishes,
       "a depth+1 submit is preaccept backpressure without a lease, request or completion");
 for (int i = 0; i < DEPTH; i++) controller_complete(nth_outstanding(0), 0, 0, 0);
 for (int i = 0; i < DEPTH; i++) worker_consume(i);
 tag_full = 1; batch_init(0, 0, 0, 4096, 0);
 CHECK(SUBMIT(&st, &bs[0]) == -EAGAIN && !live_leases && !outstanding() && !bs[0].publishes && !blocked_worker,
       "native tag pressure is preaccept retry without waiting or leasing");
 tag_full = 0; acquire_error = -ESTALE; batch_init(0, 0, 0, 4096, 0);
 int f0 = frees;
 CHECK(SUBMIT(&st, &bs[0]) == -ESTALE && frees == f0 + 1 && !live_leases && !outstanding() && !bs[0].publishes,
       "a stale allocation generation refuses before acceptance and frees the request");
 acquire_error = 0; batch_init(0, 0, 0, 4096, 0);
 CHECK(!SUBMIT(&st, &bs[0]), "slot returned after a refused lease");
 controller_complete(nth_outstanding(0), 0, 0, 0); worker_consume(0);
 CHECK(!live_leases, "drained");
 puts("ok 2 - slot exhaustion, tag pressure and stale generation are preaccept refusals with nothing leased or issued");
}
static void case_failures(void)
{
 const u16 status[] = { 0, 0x182, 0 };
 const u32 flags[] = { 0, 0, NVME_REQ_CANCELLED };
 const blk_status_t err[] = { 10, 0, 0 };
 const int expect[] = { -EIO, 0x182, -EINTR };
 for (int i = 0; i < 3; i++) {
  int ex = executes, unq = unquiesced_releases;
  batch_init(i, i, 0, 4096, 0); CHECK(!SUBMIT(&st, &bs[i]), "accepted");
  controller_complete(nth_outstanding(0), status[i], flags[i], err[i]);
  CHECK(bs[i].publishes == 1 && bs[i].status == expect[i] && bs[i].sequester,
        "an accepted failure publishes its native status and sequesters the batch");
  CHECK(live_leases == 1, "the failed command keeps its lease until the worker consumes it");
  worker_consume(i);
  CHECK(executes == ex + 1 && unquiesced_releases == unq + 1 && !live_leases,
        "never resubmitted; the lease retires unquiesced, which quarantines the allocation");
  CHECK(bps[i].cqe.status == (expect[i] > 0 ? expect[i] : 0) && bps[i].cqe.err == (expect[i] < 0 ? expect[i] : 0),
        "status convention: NVMe status positive, errno negative");
 }
 /* Three slots are retained for ever; one remains usable. */
 batch_init(3, 3, 0, 4096, 0); CHECK(!SUBMIT(&st, &bs[3]), "one slot left");
 batch_init(4, 0, 0, 4096, 0); CHECK(SUBMIT(&st, &bs[4]) == -EAGAIN, "uncertain slots never rejoin the pool");
 controller_complete(nth_outstanding(0), 0, 0, 0);
 session.state = XDEV_EXT_MECH_SESSION_ZOMBIE; worker_consume(3); session.state = 0;
 CHECK(live_leases == 1 && !irq_releases, "a zombie session retains even a completed lease");
#ifdef HAVE_PEER_RES
 CHECK(!nvme_xdev_ext_peer_resources_free(&priv) && priv.peer && coherent_live == 1,
       "teardown refuses to free descriptor memory or slots of an uncertain command");
#endif
 puts("ok 5 - accepted errno, NVMe status and cancellation are never resubmitted; uncertain slots and zombie leases stay retained");
}
/* The descriptor list a last-segment SGL points at, in the slot that owns it. */
static const struct nvme_sgl_desc *sgl_list(u64 dma)
{
#ifdef HAVE_PEER_RES
 for (u32 i = 0; priv.peer && i < priv.peer->nr_slots; i++)
  if (priv.peer->slots[i].sgl_dma == dma) return priv.peer->slots[i].sgl;
#endif
 (void)dma; return NULL;
}
static void case_pages(void)
{
 /* 4 KiB provider pages; page 2 is not DMA-contiguous with page 1. */
 provider_page = 4096; head.lba_shift = 12;
 batch_init(0, 0, 0, 65536, 3);
 CHECK(!SUBMIT(&st, &bs[0]), "multi-page frame accepted");
 struct request *r = nth_outstanding(0);
 struct nvme_command *c = r->nr.cmd;
 CHECK(live_leases == 16, "one lease per provider page");
 CHECK(c->rw.dptr.sgl.type == (NVME_SGL_FMT_LAST_SEG_DESC << 4) && c->rw.slba == 3 && c->rw.length == 15,
       "non-contiguous GPU pages use a last-segment SGL");
 u32 n = c->rw.dptr.sgl.length / sizeof(struct nvme_sgl_desc);
 const struct nvme_sgl_desc *d = sgl_list(c->rw.dptr.sgl.addr);
 CHECK(d && n == 3, "contiguous pages merge: [0,2) [2,3) [3,16) are three data blocks");
 CHECK(!(c->rw.dptr.sgl.addr % 512) && !(c->rw.dptr.sgl.addr % 256),
       "the descriptor list keeps nvme-pci list alignment (512 bytes, quirk included)");
 CHECK(d[0].addr == provider_dma(0) && d[0].length == 8192 && d[1].addr == provider_dma(8192) &&
       d[1].length == 4096 && d[2].addr == provider_dma(12288) && d[2].length == 53248 &&
       d[0].type == (NVME_SGL_FMT_DATA_DESC << 4) && d[2].type == (NVME_SGL_FMT_DATA_DESC << 4),
       "descriptor addresses and lengths follow the leased pages in order");
 controller_complete(r, 0, 0, 0); worker_consume(0);
 CHECK(!live_leases, "all page leases released by the worker");
 /* Two frames in one batch, 64 KiB pages: two data blocks; write direction. */
 provider_page = 65536; priv.write = true;
 batch_init(1, 0, 0, 65536, 8); bs[1].nr = 2; bs[1].bytes = 2 * 65536;
 bs[1].f[1] = (struct xdev_ext_mech_frame){ .umem_addr = 2 * 65536, .index = 2, .data_len = 65536 };
 CHECK(!SUBMIT(&st, &bs[1]), "two-frame batch accepted");
 r = nth_outstanding(0); c = r->nr.cmd; d = sgl_list(c->rw.dptr.sgl.addr);
 CHECK(c->rw.opcode == 1 && last_dir == DMA_TO_DEVICE && d && c->rw.dptr.sgl.length == 32 &&
       d[0].addr == provider_dma(0) && d[1].addr == provider_dma(2 * 65536) && c->rw.length == 31,
       "frames concatenate in batch order; write leases to-device");
 controller_complete(r, 0, 0, 0); worker_consume(1);
 disk.ro = true; batch_init(2, 0, 0, 4096, 0); int a = acquire_calls;
 CHECK(SUBMIT(&st, &bs[2]) == -EROFS && acquire_calls == a, "read-only namespace refuses a write before leasing");
 disk.ro = false; priv.write = false; head.lba_shift = 9;
 puts("ok 3 - GPU pages become merged multi-entry SGLs across pages and frames; direction is explicit");
}
static void case_malformed(void)
{
 for (int k = 0; k < 6; k++) {
  int e = executes;
  batch_init(0, 1, 512, 1024, 0);
  switch (k) {
  case 0: bs[0].nr = 0; break;
  case 1: bs[0].f[0].kaddr = (void *)1; break;
  case 2: bs[0].f[0].data_len = 0; break;
  case 3: bs[0].f[0].umem_addr++; break;
  case 4: bs[0].f[0].data_off = 65537; break;
  case 5: bs[0].bytes++; break;
  }
  CHECK(SUBMIT(&st, &bs[0]) < 0 && executes == e && !allocated() && !live_leases && !bs[0].publishes,
        "malformed or CPU-backed span refused before any native request");
 }
 puts("ok 4 - CPU-backed, empty, misplaced or mismatched spans are refused before acceptance");
}
int main(void)
{
 int rc;
 session.pool = (struct xdev_ext_mech_pool){ 3, 65536, 8 };
 session.l.frame_size = 65536; session.l.seg_len = 65536; session.l.group_bytes = 65536 * 2;
 session.depth = DEPTH;
 priv.ns = &ns; priv.identity.nsid = 7; /* nvme_xdev_ext_capture_identity(): head->ns_id */
 INIT_RESOURCES;
 assert(!rc);
 case_depth(); if (failures) return 1;
 case_slots(); if (failures) return 1;
 case_pages(); if (failures) return 1;
 case_malformed(); if (failures) return 1;
 /* Last: it retires every slot as uncertain or zombie-retained. */
 case_failures(); if (failures) return 1;
 return 0;
}
'''


def production_source():
    path = Path(os.environ.get("XDEV_EXT_NVME_TEST_SOURCE", str(KERNEL / RELATIVE)))
    return path.read_text()


def extract(source):
    """Production structures and GPU-memory stage functions, in file order."""
    types = []
    for name in ("nvme_xdev_ext_mech_stage", "nvme_xdev_ext_mech_batch",
                 "nvme_xdev_ext_mech_completion", "nvme_xdev_ext_mech_slot",
                 "nvme_xdev_ext_peer_slot", "nvme_xdev_ext_peer_res"):
        m = re.search(r"^struct " + name + r" \{.*?^\};", source, re.M | re.S)
        if m:
            types.append((m.start(), m[0]))
    fill = re.search(r"\.fill_cqe = (\w+),", source)[1]
    wanted = (r"(?:nvme_xdev_ext_peer_\w+|nvme_xdev_ext_poll_(?:opf|check|arm)|"
              r"nvme_xdev_ext_class_fill_cqe|" + fill + r")")
    functions = [(m.start(), m[0]) for m in re.finditer(
        r"^static [^;{}=]*\b" + wanted + r"\([^;{]*\)\s*\{.*?^\}", source, re.M | re.S)]
    submit = "nvme_xdev_ext_peer_submit"
    have_res = "nvme_xdev_ext_peer_resources_init(" in source
    types += [(m.start(), m[0]) for m in
              re.finditer(r"^#define NVME_XDEV_EXT_PEER_\w+\s.*$", source, re.M)]
    text = "\n".join(t for _, t in sorted(types))
    code = "\n\n".join(t for _, t in sorted(functions))
    # NVMe's lease wrapper delegates to the requester base. Execute that real
    # dependency too, so the page-splitting cases and mutation still exercise
    # production code rather than substituting a successful lease stub.
    requester = (KERNEL / "io_uring/family/xdev_ext_requester.c").read_text()
    split = requester[requester.index("int xdev_ext_peer_lease_split("):
                      requester.index("EXPORT_SYMBOL_GPL(xdev_ext_peer_lease_split);")]
    code = split + "\n\n" + code
    return text, code, fill, submit, have_res


def build(text, code, fill, submit, have_res, directory, name):
    defines = ["#define FILL_CQE " + fill, "#define SUBMIT " + submit]
    if have_res:
        defines += ["#define HAVE_PEER_RES 1",
                    "#define INIT_RESOURCES rc = nvme_xdev_ext_peer_resources_init(&st)"]
    else:
        defines += ["#define INIT_RESOURCES rc = 0"]
    shim = SHIM.replace("/* PRODUCTION_TYPES */", text)
    shim = shim.replace("/* PRODUCTION_FUNCTIONS */", code)
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text("\n".join(defines) + "\n" + shim + MAIN)
    compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                               "-Werror", "-Wno-unused-function", "-fsanitize=undefined",
                               "-fno-sanitize-recover=undefined", "-I" + str(KERNEL),
                               str(source), "-o", str(binary)], capture_output=True, text=True)
    if compiled.returncode:
        raise SystemExit("host shim compile failed:\n" + compiled.stderr)
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)


def main():
    text, code, fill, submit, have_res = extract(production_source())
    mutations = [
        ("accepted failure published as an ordinary completion",
         "xdev_ext_mech_batch_completion_publish(b, ticket, status, done->uncertain);",
         "xdev_ext_mech_batch_completion_publish(b, ticket, status, false);"),
        ("uncertain lease released quiesced",
         "xdev_ext_peer_fd_release(&slot->leases[i], quiesced);",
         "xdev_ext_peer_fd_release(&slot->leases[i], true);"),
        ("GPU subspan offset omitted", "off = f.umem_addr + f.data_off", "off = f.umem_addr"),
        ("native write direction reversed",
         "p->write ? DMA_TO_DEVICE : DMA_FROM_DEVICE", "p->write ? DMA_FROM_DEVICE : DMA_TO_DEVICE"),
        # Merging moved into the pure builder; perturb its input adjacency instead.
        ("DMA-contiguous pages not merged", "slot->spans, NVME_XDEV_EXT_PEER_MAX_PIECES, &n);",
         "slot->spans, NVME_XDEV_EXT_PEER_MAX_PIECES, &n);\n\t\tif (!ret && n < slot->nr_leases) return -EPROTO;"),
        ("provider page refusal not split", "if (ret != -ERANGE)", "if (true)"),
    ]
    with tempfile.TemporaryDirectory(prefix="nvme-peer-async-") as tmp:
        directory = Path(tmp)
        result = build(text, code, fill, submit, have_res, directory, "actual")
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr, end="", file=sys.stderr)
            raise SystemExit("not ok - production GPU-memory NVMe stage violates the asynchronous contract")
        for i, (name, old, new) in enumerate(mutations):
            if old not in code:
                raise SystemExit("not ok - mutation anchor missing: " + name)
            result = build(text, code.replace(old, new), fill, submit, have_res, directory,
                           "mutation%d" % i)
            if result.returncode == 0:
                raise SystemExit("not ok - mutation survived: " + name)
            print("ok mutation - " + name + " rejected by behavior checks")


if __name__ == "__main__":
    main()
