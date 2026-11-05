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

XDEV_EXT_NVME_TEST_SOURCE selects a file only with its matching
XDEV_EXT_NVME_TEST_ROOT. Foreign source bytes never borrow current headers.
"""
import os
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

KERNEL = next(p for p in Path(__file__).resolve().parents
              if (p / 'source-layout.json').is_file())
sys.path.insert(0, str(KERNEL / 'tools'))
import layout as _layout


class SourceSelection:
    """One explicit canonical checkout, receipt owner, or complete native tree.

    Unlike read_native's compatibility API, this boundary has no environment
    hint fallback. A copied source file alone is not a dependency authority.
    """
    def __init__(self, root):
        self.root = Path(root).resolve()
        try:
            canonical = _layout.canonical_root(self.root)
        except _layout.LayoutError:
            self.mapping = None
        else:
            self.root = canonical
            self.mapping = _layout.load_layout(canonical)
        self.inputs = {}

    def file(self, native):
        if self.mapping is None:
            return _layout.safe_file(self.root, native)
        source = self.mapping.source('linux', native)
        return _layout.safe_file(self.root, source.relative_to(self.root).as_posix())

    def read(self, native):
        value = self.file(native).read_text()
        previous = self.inputs.setdefault(native, value)
        if previous != value:
            raise AssertionError('SETUP selected source changed: ' + native)
        return value

    def verify(self):
        for native, expected in self.inputs.items():
            if self.file(native).read_text() != expected:
                raise AssertionError('SETUP selected dependency changed: ' + native)


class ProductionSource(str):
    def __new__(cls, value, selection):
        instance = super().__new__(cls, value)
        instance.selection = selection
        return instance


class ExtractedTypes(str):
    """String-compatible five-item API, carrying the selected dependency owner."""
    def __new__(cls, value, selection, common=False):
        instance = super().__new__(cls, value)
        instance.selection = selection
        instance.common = common
        return instance


def positional_replace(value, old, new, count=1, edits=None):
    """Replace counted source spans and prove their complete byte inverse."""
    starts = [m.start() for m in re.finditer(re.escape(old), value)]
    if len(starts) != count:
        raise AssertionError('SETUP fixture anchor count %d != %d: %s' %
                             (len(starts), count, old))
    result, records, shift = value, [], 0
    for start in starts:
        target = start + shift
        result = result[:target] + new + result[target + len(old):]
        records.append(dict(offset=target, old=old, new=new))
        shift += len(new) - len(old)
    restored = result
    for record in reversed(records):
        start = record['offset']
        if restored[start:start + len(new)] != new:
            raise AssertionError('SETUP fixture inverse span mismatch')
        restored = restored[:start] + old + restored[start + len(new):]
    if restored != value:
        raise AssertionError('SETUP fixture inverse bytes differ')
    if edits is not None:
        edits.append(dict(before_length=len(value), after_length=len(result),
                          replacements=records))
    return result


def inverse_fixture(value, edits):
    for edit in reversed(edits):
        if len(value) != edit['after_length']:
            raise AssertionError('SETUP fixture inverse step mismatch')
        for record in reversed(edit['replacements']):
            start, old, new = record['offset'], record['old'], record['new']
            if value[start:start + len(new)] != new:
                raise AssertionError('SETUP fixture inverse bytes mismatch')
            value = value[:start] + old + value[start + len(new):]
        if len(value) != edit['before_length']:
            raise AssertionError('SETUP fixture inverse preimage mismatch')
    return value


def read_native(root, native):
    """Read an explicit native tree or its canonical Layout.by_native file."""
    path = Path(root) / native
    try:
        # A selected checkout or genuine view receipt owns every dependency.
        # A foreign hint must not replace its mapping or hide a missing file.
        canonical = _layout.canonical_root(root)
    except _layout.LayoutError:
        if path.is_file():
            return path.read_text()
        hint = os.environ.get('XDEV_EXT_CANONICAL_ROOT')
        if not hint:
            raise
        # Minimal native fixtures may omit moved dependencies. Only these
        # roots, with no canonical authority, can use the explicit hint.
        canonical = Path(hint)
    mapping = _layout.load_layout(canonical)
    return mapping.source('linux', native).read_text()


def host_headers(root, output):
    """Only portable project headers, under a disposable test include boundary.

    This is not an assembled Linux tree and emits no source-view receipt.
    Linux scalar types and errno continue to come from the host OS headers.
    """
    output = Path(output)
    try:
        mapping = _layout.load_layout(root)
    except _layout.LayoutError:
        return Path(root)
    for (component, native), source in mapping.by_native.items():
        if component != 'linux' or not native.endswith('.h'):
            continue
        if (native.startswith(('include/linux/xdev_ext_', 'include/uapi/linux/xdev_ext_'))
            or native in ('include/linux/nvme_xdev_ext_passthru.h', 'include/uapi/linux/nvme_ioctl.h')
            or native.startswith(('drivers/nvme/host/xdev_ext_', 'io_uring/xdev_ext_'))):
            target = output / native
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((mapping.repo / source).read_bytes())
    return output


def definition(text, name):
    match = re.search(r'^[A-Za-z_][^;{}]*\b' + re.escape(name) +
                      r'\([^;{}]*\)\s*\{.*?^\}', text, re.M | re.S)
    if not match:
        raise AssertionError('production definition missing: ' + name)
    return match[0]


def family_types(root):
    text = read_native(root, 'include/linux/xdev_ext_storfam_block.h')
    names = ('xdev_ext_stor_poll_view', 'xdev_ext_stor_geometry',
             'xdev_ext_stor_dev_ops', 'xdev_ext_stor_stage', 'xdev_ext_stor_batch')
    return ('struct xdev_ext_mech_stage; struct xdev_ext_mech_stage_uapi; '
            'struct xdev_ext_mech_batch; struct xdev_ext_stor_stage; struct pci_dev;\n' +
            '\n'.join(re.search(r'^struct ' + name + r' \{.*?^\};', text, re.M | re.S)[0]
                      for name in names))


def worker_runtime(root, native, poll=False):
    """Actual worker common gates and native callbacks (no recheck stub)."""
    block = read_native(root, 'io_uring/family/xdev_ext_storfam_block.c')
    header = read_native(root, 'drivers/nvme/host/nvme.h')
    code = '\n\n'.join([definition(header, 'nvme_xdev_ext_capture_identity'),
        definition(native, 'nvme_xdev_ext_member_identity'),
        definition(native, 'nvme_xdev_ext_member_queue'),
        definition(native, 'nvme_xdev_ext_member_decode'),
        definition(block, 'xdev_ext_storfam_validate'),
        definition(block, 'xdev_ext_storfam_submit_check')])
    if poll:
        code += '\n' + definition(native, 'nvme_xdev_ext_member_poll') + '\n' + definition(block, 'xdev_ext_storfam_poll')
    return code + ('\n#define FIXTURE_POLL_OP .poll=nvme_xdev_ext_member_poll,\n' if poll else '\n#define FIXTURE_POLL_OP\n') + r'''
static const struct xdev_ext_stor_dev_ops fixture_member_ops = {
 .identity = nvme_xdev_ext_member_identity,
 .queue = nvme_xdev_ext_member_queue,
 .decode = nvme_xdev_ext_member_decode,
 FIXTURE_POLL_OP
};
'''

def identity_boundary():
    """OS namespace objects read by the actual nvme.h capture inline."""
    return r'''
typedef u64 sector_t;
#ifndef READ_ONCE
#define READ_ONCE(x) (x)
#endif
#define SECTOR_SHIFT 9
#define NVME_NS_READY 0
#define NVME_NS_REMOVING 1
struct nvme_ns_head { u32 ns_id; u8 lba_shift,pi_type; u16 ms,pi_size;
 struct { u8 csi,eui64[8],nguid[16],uuid[16]; } ids; };
struct gendisk { u64 capacity,diskseq; };
struct request_queue;
struct nvme_ns { struct request_queue *queue; struct nvme_ns_head *head;
 struct gendisk *disk; unsigned long flags; };
static sector_t get_capacity(struct gendisk *disk) { return disk->capacity; }
static bool test_bit(unsigned bit,const unsigned long *flags) { return !!(*flags & (1UL << bit)); }
'''


def worker_fixture_init():
    """Populate namespace facts only at the fixture's bypassed bind boundary."""
    return r'''
static void fixture_worker_init(struct nvme_xdev_ext_mech_stage *p,
 struct xdev_ext_mech_stage *st)
{
 static struct nvme_ns_head head = { .ns_id=7,.lba_shift=9 };
 static struct gendisk disk = { .capacity=32,.diskseq=1 };
 static char queue_identity;
 p->ns->head=&head; p->ns->disk=&disk; p->ns->flags=1UL << NVME_NS_READY;
 if (!p->ns->queue) p->ns->queue=(void *)&queue_identity;
 p->family.st=st; p->family.dev=&fixture_member_ops; p->family.member=p;
 if(nvme_xdev_ext_capture_identity(p->ns,&p->identity,&p->head,&p->disk,&p->queue))abort();
}
'''

RELATIVE = "drivers/nvme/host/xdev_ext_mech_nvme.c"

SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "include/linux/xdev_ext_storfam_runtime.h"
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ERR_CAST(p) ((void *)(p))
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
#define NVME_REQ_XDEV_EXT_PEER (1U << 5)
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
 struct { struct nvme_command *cmd; u32 flags; struct nvme_xdev_ext_peer_trace *peer_trace;
          u16 status; struct { u64 u64; } result; } nr;
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
/* PEER_TRACE_RELEASE */
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
static int immediate_complete;
static void controller_complete(struct request *r, u16 status, u32 flags, blk_status_t err);
static void blk_execute_rq_nowait(struct request *r, bool at_head)
{ assert(!at_head && r->allocated && !r->executed && r->end_io); r->executed = true; executes++;
 if (immediate_complete) controller_complete(r,0,0,0); }
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
static void batch_admitted_rw(int i, u64 slba, u32 len)
{
 /* Metadata of the fixture's already-validated literal request. Never refresh
  * this after a negative case mutates the live batch geometry or byte count. */
 bps[i].rw = (struct xdev_ext_stor_rw){ .slba = slba,
   .nlb = (u64)len >> head.lba_shift, .byte_offset = slba << head.lba_shift,
   .byte_length = len, .write = priv.write };
}
static void batch_init(int i, u32 frame, u32 off, u32 len, u64 slba)
{
 memset(&bps[i], 0, sizeof(bps[i])); memset(&bs[i], 0, sizeof(bs[i]));
 bs[i].priv = &bps[i]; bs[i].nr = 1; bs[i].bytes = len; bs[i].ticket = 100 + i; bs[i].id = 200 + i;
 bs[i].f[0] = (struct xdev_ext_mech_frame){ .umem_addr = (u64)frame * 65536, .index = frame,
   .data_off = off, .data_len = len };
 bps[i].validated = true; bps[i].batch_id = bs[i].id;
 batch_admitted_rw(i, slba, len);
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
       ((struct xdev_ext_stor_completion *)requests[j].end_io_data)->b == &bs[i]) q = &requests[j];
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
static void case_early_and_stale(void)
{
 struct xdev_ext_stor_completion saved;
 struct request duplicate = {};
 int unq=unquiesced_releases, ex=executes;
 batch_init(0,0,0,4096,0);
 immediate_complete=1;
 CHECK(!SUBMIT(&st,&bs[0]), "immediate native completion accepted");
 immediate_complete=0;
 CHECK(bs[0].publishes==1 && !bs[0].sequester && !outstanding(),
       "end_io before post returns publishes exactly once");
 CHECK(live_leases==1 && !irq_releases, "end_io leaves native leases for the worker");
 saved=bps[0].peer_slot->done;
 duplicate.end_io_data=&saved;
 duplicate.nr.status=0x182;
 duplicate.nr.result.u64=0xdeadbeef;
 in_irq=1; nvme_xdev_ext_peer_end_io(&duplicate,0); in_irq=0;
 CHECK(bs[0].publishes==1 && bps[0].cqe.status==0 && bps[0].cqe.result!=0xdeadbeef,
       "duplicate ticket cannot mutate CQE or publish again");
 worker_consume(0);
 batch_init(0,0,0,4096,0); bs[0].ticket++;
 CHECK(!SUBMIT(&st,&bs[0]), "new batch takes a released slot");
 in_irq=1; nvme_xdev_ext_peer_end_io(&duplicate,0); in_irq=0;
 CHECK(!bs[0].publishes && !bs[0].claims && !bps[0].cqe.status,
       "stale native ticket cannot claim or alter the replacement batch");
 controller_complete(nth_outstanding(0),0,0,0); worker_consume(0);
 CHECK(executes==ex+2 && !live_leases && unquiesced_releases==unq,
       "only two accepted commands and success leases release quiesced");
 puts("ok 6 - immediate end_io, duplicate and stale tickets preserve CQE and lease ownership");
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
 batch_admitted_rw(1, 8, 2 * 65536);
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
static void case_admitted_rw_drift(void)
{
 for (int k = 0; k < 2; k++) {
  int e = executes, a = acquire_calls;
  batch_init(0, 0, 0, 4096, 8);
  if (k == 0) bps[0].rw.byte_length--;
  else bps[0].rw.nlb--;
  CHECK(SUBMIT(&st, &bs[0]) == -EPROTO && acquire_calls > a && executes == e &&
        !allocated() && !outstanding() && !live_leases && !bs[0].publishes,
        "admitted RW drift refuses after valid mapping without retaining a request or lease");
  batch_init(0, 0, 0, 4096, 8);
  CHECK(!SUBMIT(&st, &bs[0]), "admitted RW drift refusal returns its slot for a valid request");
  controller_complete(nth_outstanding(0), 0, 0, 0); worker_consume(0);
  CHECK(!live_leases && !allocated(), "valid request after admitted RW drift releases its resources");
 }
 puts("ok 7 - admitted byte length and NLB drift refuse before acceptance and release mapped resources");
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
 case_admitted_rw_drift(); if (failures) return 1;
 /* Last: it retires every slot as uncertain or zombie-retained. */
 case_early_and_stale(); if (failures) return 1;
 case_failures(); if (failures) return 1;
 return 0;
}
'''


def storage_runtime(root):
    content = read_native(root, 'io_uring/family/xdev_ext_storfam.c')
    found = []
    for name in ('xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get',
                 'xdev_ext_stor_slot_put', 'xdev_ext_stor_done'):
        match = re.search(r'^[A-Za-z_][^;{}]*\b' + name +
                          r'\([^;{}]*\)\s*\{.*?^\}', content, re.M | re.S)
        if not match:
            raise AssertionError('production storage runtime symbol missing: ' + name)
        found.append(match[0])
    return '\n\n'.join(found)



def storage_poll_runtime(root, names=("xdev_ext_stor_block_poll_opf",
                                      "xdev_ext_stor_block_poll_check",
                                      "xdev_ext_stor_block_poll_arm")):
    """The real block-family helpers, including the public inline opf helper."""
    content = read_native(root, "include/linux/xdev_ext_storfam_block.h")
    content += "\n" + read_native(root, "io_uring/family/xdev_ext_storfam_block.c")
    found = []
    for name in names:
        match = re.search(r"^[A-Za-z_][^;{}]*\b" + name +
                          r"\([^;{}]*\)\s*\{.*?^\}", content, re.M | re.S)
        if not match:
            raise AssertionError("production storage polling symbol missing: " + name)
        found.append(match[0])
    return "\n\n".join(found)


def production_source(root=None):
    override = os.environ.get('XDEV_EXT_NVME_TEST_SOURCE')
    if override and root is None and 'XDEV_EXT_NVME_TEST_ROOT' not in os.environ:
        raise AssertionError('SETUP XDEV_EXT_NVME_TEST_SOURCE requires matching XDEV_EXT_NVME_TEST_ROOT')
    selected = SourceSelection(root or os.environ.get('XDEV_EXT_NVME_TEST_ROOT', KERNEL))
    value = selected.read(RELATIVE)
    if override and (Path(override).resolve() != selected.file(RELATIVE).resolve() or
                     Path(override).read_text() != value):
        raise AssertionError('SETUP selected NVMe source/dependency root mismatch')
    return ProductionSource(value, selected)


def extract(source, root=None):
    """Require a coherent selected owner, then retain the five-item API."""
    selected = SourceSelection(root) if root is not None else getattr(source, 'selection', None)
    if selected is None:
        raise AssertionError('SETUP extract requires production_source() or explicit root=')
    if str(source) != selected.read(RELATIVE):
        raise AssertionError('SETUP production text differs from selected NVMe owner')
    common = 'return xdev_ext_storfam_submit(&p->family, b, &bp->family);' in definition(
        source, 'nvme_xdev_ext_class_submit')
    if common:
        text, code, fill, submit, have_res = extract_common(source, selected)
    else:
        # The compatibility helpers below must not invoke their minimal-tree
        # hint fallback for any dependency of a selected historical source.
        for native in ('include/linux/xdev_ext_mech.h',
                       'include/linux/xdev_ext_storfam.h',
                       'drivers/nvme/host/xdev_ext_native_peer_trace.h',
                       'io_uring/family/xdev_ext_requester.c',
                       'io_uring/family/xdev_ext_storfam.c'):
            selected.read(native)
        if 'struct xdev_ext_stor_stage family;' in source or 'xdev_ext_stor_block_poll_opf(' in source:
            selected.read('include/linux/xdev_ext_storfam_block.h')
            selected.read('io_uring/family/xdev_ext_storfam_block.c')
        text, code, fill, submit, have_res = extract_legacy(source, selected.root)
    return ExtractedTypes(text, selected, common), code, fill, submit, have_res


def extract_common(source, selected):
    """Whole current family/native definitions; no fused replacement function."""
    selected.definitions = []

    def record(native, name, structure=False, content=None):
        original = selected.read(native)
        content = original if content is None else content
        if structure:
            close = r'\}[^;]*;' if structure == 'inline' else r'^\}[^;]*;'
            match = re.search(r'^struct ' + re.escape(name) + r' \{.*?' + close,
                              content, re.M | re.S)
            if not match:
                raise AssertionError('SETUP production structure missing: ' + name)
            body = match[0]
        else:
            body = definition(content, name)
        offset = original.find(body)
        if offset < 0:
            raise AssertionError('SETUP definition not owned by source: ' + name)
        selected.definitions.append(dict(native=native, symbol=name,
                                         offset=offset, length=len(body)))
        return body

    block_path = 'io_uring/family/xdev_ext_storfam_block.c'
    header_path = 'include/linux/xdev_ext_storfam_block.h'
    block = selected.read(block_path)
    header = selected.read(header_path)
    selected.read('include/linux/xdev_ext_storfam_runtime.h')
    # Portable headers are included directly, from this selected owner.
    for native in ('include/linux/nvme_xdev_ext_passthru.h',
                   'include/linux/xdev_ext_peer.h',
                   'include/linux/xdev_ext_requester_core.h',
                   'include/linux/xdev_ext_storfam_core.h',
                   'include/uapi/linux/xdev_ext_peer.h',
                   'drivers/nvme/host/xdev_ext_peer_nvme_core.h'):
        selected.read(native)
    forward = ('struct xdev_ext_mech_stage; struct xdev_ext_mech_stage_uapi; '
               'struct xdev_ext_mech_batch; struct xdev_ext_stor_stage; '
               'struct xdev_ext_stor_io; struct xdev_ext_stor_peer_resources; '
               'struct pci_dev; struct bio; struct page;\n')
    declarations = [forward]
    peer_header = 'drivers/nvme/host/xdev_ext_peer_nvme_core.h'
    declarations.append(record(peer_header, 'xdev_ext_peer_nvme_plan', 'inline'))
    for macro in ('XDEV_EXT_PEER_NVME_DPTR', 'xdev_ext_peer_nvme_seg'):
        match = re.search(r'^#define ' + macro + r'\s+[^\n]+$', selected.read(peer_header), re.M)
        if not match:
            raise AssertionError('SETUP actual peer macro missing: ' + macro)
        declarations.append(match[0])
    for name in ('xdev_ext_stor_poll_view', 'xdev_ext_stor_command',
                 'xdev_ext_stor_geometry', 'xdev_ext_stor_dev_ops',
                 'xdev_ext_stor_io', 'xdev_ext_stor_peer_io',
                 'xdev_ext_stor_stage', 'xdev_ext_stor_batch'):
        declarations.append(record(header_path, name, True))
    declarations.append(record(block_path, 'xdev_ext_stor_peer_resources', True))
    limit = re.search(r'^#define XDEV_EXT_STOR_PEER_MAX_SPANS\s+[^\n]+$', block, re.M)
    if not limit:
        raise AssertionError('SETUP actual peer span limit missing')
    declarations.append(limit[0])
    declarations.append(record('drivers/nvme/host/xdev_ext_native_peer_trace.h',
                               'nvme_xdev_ext_peer_trace', True))
    for name in ('nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_batch',
                 'nvme_xdev_ext_peer_slot'):
        declarations.append(record(RELATIVE, name, True))
    for native, name in (('include/linux/xdev_ext_mech.h', 'xdev_ext_family_hooks_hdr'),
                         ('include/linux/xdev_ext_storfam.h', 'xdev_ext_stor_hooks')):
        declarations.append(record(native, name, True))
    for match in re.finditer(r'^#define NVME_XDEV_EXT_PEER_\w+\s.*$', source, re.M):
        declarations.append(match[0])
    match = re.search(r'^static const struct xdev_ext_stor_hooks '
                      r'nvme_xdev_ext_stor_hooks = \{.*?^\};', source, re.M | re.S)
    if not match:
        raise AssertionError('SETUP production storage hooks missing')
    declarations.append(match[0])
    # Every body remains separately identifiable and byte-exact. The two
    # fallback bodies are selected under the same strict/no-bounce profile.
    # Native W1 uses -Wno-sign-compare. Keep this scope around actual kernel
    # definitions only; fixture/oracle diagnostics retain the original flags.
    code = ['#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored "-Wunused-parameter"\n'
            '#pragma GCC diagnostic ignored "-Wsign-compare"']
    for name in ('xdev_ext_peer_nvme_plan', 'xdev_ext_peer_nvme_sgl_build',
                 'xdev_ext_peer_nvme_prp_build'):
        code.append(record(peer_header, name))
    for name in ('xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get',
                 'xdev_ext_stor_slot_put', 'xdev_ext_stor_done'):
        code.append(record('io_uring/family/xdev_ext_storfam.c', name))
    code.append(record('io_uring/family/xdev_ext_requester.c', 'xdev_ext_peer_lease_split'))
    code.append(record(header_path, 'xdev_ext_stor_block_poll_opf'))
    for name in ('xdev_ext_stor_block_caps', 'xdev_ext_stor_block_walk',
                 'xdev_ext_stor_block_preflight', 'xdev_ext_stor_block_append',
                 'xdev_ext_stor_block_poll_check', 'xdev_ext_stor_block_poll_arm',
                 'xdev_ext_storfam_host_resources_free', 'xdev_ext_storfam_host_resources_init',
                 'xdev_ext_storfam_host_get', 'xdev_ext_storfam_host_put',
                 'xdev_ext_storfam_peer_io', 'xdev_ext_storfam_peer_resources_free',
                 'xdev_ext_storfam_peer_resources_init', 'xdev_ext_storfam_peer_get',
                 'xdev_ext_storfam_peer_put', 'xdev_ext_storfam_peer_map'):
        code.append(record(block_path, name))
        if name == 'xdev_ext_storfam_host_put':
            # Preserve the existing assertion that PEER never takes HOST
            # cleanup. The observer still calls the real, unchanged body.
            code.append('#define xdev_ext_storfam_host_put(...) '
                        '(host_slot_puts++, (xdev_ext_storfam_host_put)(__VA_ARGS__))')
    fallback = block[block.index('#ifndef XDEV_EXT_STOR_BOUNCE_AVAILABLE'):]
    for name in ('xdev_ext_storfam_bounce', 'xdev_ext_storfam_bounce_release'):
        code.append(record(block_path, name, content=fallback))
    code.append('#define xdev_ext_storfam_bounce_release(...) '
                '(host_bounce_releases++, (xdev_ext_storfam_bounce_release)(__VA_ARGS__))')
    for name in ('xdev_ext_storfam_host_map', 'xdev_ext_storfam_submit_check',
                 'xdev_ext_storfam_submit', 'xdev_ext_storfam_host_ready',
                 'xdev_ext_storfam_consume'):
        code.append(record(block_path, name))
    code.append(record('drivers/nvme/host/nvme.h', 'nvme_xdev_ext_capture_identity'))
    for name in ('nvme_xdev_ext_member_requester', 'nvme_xdev_ext_member_queue',
                 'nvme_xdev_ext_member_identity', 'nvme_xdev_ext_class_complete',
                 'nvme_xdev_ext_class_end_io', 'nvme_xdev_ext_peer_complete',
                 'nvme_xdev_ext_peer_end_io', 'nvme_xdev_ext_member_encode',
                 'nvme_xdev_ext_member_encode_dptr', 'nvme_xdev_ext_member_request_init',
                 'nvme_xdev_ext_member_post', 'nvme_xdev_ext_member_retire_peer',
                 'nvme_xdev_ext_class_submit', 'nvme_xdev_ext_stage_fill_cqe'):
        code.append(record(RELATIVE, name))
    # This suite bypasses CREATE/poll/validate. Select only the actual member
    # initializer fields reached by submit/consume; never invent a callback.
    ops = re.search(r'^static const struct xdev_ext_stor_dev_ops '
                    r'nvme_xdev_ext_member_ops = \{.*?^\};', source, re.M | re.S)
    if not ops:
        raise AssertionError('SETUP actual member initializer missing')
    fields = []
    for field in ('identity', 'requester', 'queue', 'encode', 'encode_dptr',
                  'request_init', 'post', 'retire_peer', 'peer_slot_bytes',
                  'peer_native_offset'):
        lines = re.findall(r'^\s*\.' + field + r' = [^\n]+,$', ops[0], re.M)
        if len(lines) != 1:
            raise AssertionError('SETUP member initializer field missing: ' + field)
        fields.append(lines[0])
    code.append('static const struct xdev_ext_stor_dev_ops fixture_peer_ops = {\n' +
                '\n'.join(fields) + '\n};\n#pragma GCC diagnostic pop')
    return ('\n'.join(declarations), '\n\n'.join(code),
            'nvme_xdev_ext_stage_fill_cqe', 'nvme_xdev_ext_class_submit', True)


def extract_legacy(source, root):
    """Production structures and GPU-memory stage functions, in file order."""
    types = []
    for name in ("nvme_xdev_ext_mech_stage", "nvme_xdev_ext_mech_batch",
                 "nvme_xdev_ext_mech_slot",
                 "nvme_xdev_ext_peer_slot", "nvme_xdev_ext_peer_res"):
        m = re.search(r"^struct " + name + r" \{.*?^\};", source, re.M | re.S)
        if not m:
            raise AssertionError("production structure missing: " + name)
        types.append((m.start(), m[0]))
    fill = re.search(r"\.fill_cqe = (\w+),", source)[1]
    wanted = (r"(?:nvme_xdev_ext_peer_\w+|nvme_xdev_ext_poll_(?:opf|check|arm)|"
              r"nvme_xdev_ext_class_fill_cqe|" + fill + r")")
    functions = [(m.start(), m[0]) for m in re.finditer(
        r"^static [^;{}=]*\b" + wanted + r"\([^;{]*\)\s*\{.*?^\}", source, re.M | re.S)]
    required = ('nvme_xdev_ext_peer_resources_free', 'nvme_xdev_ext_peer_resources_init',
                'nvme_xdev_ext_peer_slot_get', 'nvme_xdev_ext_peer_slot_put',
                'nvme_xdev_ext_peer_lease', 'nvme_xdev_ext_peer_map',
                'nvme_xdev_ext_peer_complete', 'nvme_xdev_ext_peer_end_io',
                'nvme_xdev_ext_peer_submit', 'nvme_xdev_ext_peer_fill_cqe',
                'nvme_xdev_ext_class_fill_cqe')
    family_poll = 'xdev_ext_stor_block_poll_opf(' in source
    if not family_poll:
        required += ('nvme_xdev_ext_poll_opf', 'nvme_xdev_ext_poll_check',
                     'nvme_xdev_ext_poll_arm')
    for name in required:
        if not any(re.match(r"^static [^;{}=]*\b" + name + r"\(", body, re.S)
                   for _, body in functions):
            raise AssertionError("production NVMe function missing: " + name)
    submit = "nvme_xdev_ext_peer_submit"
    have_res = "nvme_xdev_ext_peer_resources_init(" in source
    types += [(m.start(), m[0]) for m in
              re.finditer(r"^#define NVME_XDEV_EXT_PEER_\w+\s.*$", source, re.M)]
    hooks = re.search(r"^static const struct xdev_ext_stor_hooks "
                      r"nvme_xdev_ext_stor_hooks = \{.*?^\};", source, re.M | re.S)
    if not hooks:
        raise AssertionError("production storage hooks missing")
    types.append((hooks.start(), hooks[0]))
    # These are real declarations from the production headers. Pull only the
    # dependencies needed by the extracted object: the full mechanism header
    # also declares stage/batch types supplied by this deterministic shim.
    declarations = []
    if 'struct xdev_ext_stor_stage family;' in source:
        declarations.append(family_types(root))
    trace = read_native(root, "drivers/nvme/host/xdev_ext_native_peer_trace.h")
    declarations.append(re.search(r"^struct nvme_xdev_ext_peer_trace \{.*?^\};",
                                  trace, re.M | re.S)[0])
    for header, name in (("xdev_ext_mech.h", "xdev_ext_family_hooks_hdr"),
                         ("xdev_ext_storfam.h", "xdev_ext_stor_hooks")):
        content = read_native(root, "include/linux/" + header)
        declarations.append(re.search(r"^struct " + name + r" \{.*?^\};",
                                      content, re.M | re.S)[0])
    text = "\n".join(declarations + [t for _, t in sorted(types)])
    code = "\n\n".join(t for _, t in sorted(functions))
    # NVMe's lease wrapper delegates to the requester base. Execute that real
    # dependency too, so the page-splitting cases and mutation still exercise
    # production code rather than substituting a successful lease stub.
    requester = read_native(root, "io_uring/family/xdev_ext_requester.c")
    split = requester[requester.index("int xdev_ext_peer_lease_split("):
                      requester.index("EXPORT_SYMBOL_GPL(xdev_ext_peer_lease_split);")]
    poll = storage_poll_runtime(root) + "\n\n" if family_poll else ""
    if 'struct xdev_ext_stor_stage family;' in source:
        code = '\n\n'.join(definition(source, name) for name in
                            ('nvme_xdev_ext_member_requester', 'nvme_xdev_ext_member_queue')) + r'''
static const struct xdev_ext_stor_dev_ops fixture_peer_ops = {
 .requester=nvme_xdev_ext_member_requester, .queue=nvme_xdev_ext_member_queue,
};
''' + code
    code = storage_runtime(root) + "\n\n" + poll + split + "\n\n" + code
    return text, code, fill, submit, have_res


COMMON_EXTERNAL = r'''
/* OS boundaries only. These fixtures run PEER; a HOST-only OS operation
 * aborts instead of furnishing an untested successful mapping algorithm. */
#define PAGE_SIZE 4096U
#define PAGE_SHIFT 12
#define BIO_MAX_INLINE_VECS 1024
#define NVME_REQ_XDEV_EXT_ZC (1U << 4)
#define REQ_OP_DRV_IN 0U
#define REQ_OP_DRV_OUT 1U
#define __aligned(n) __attribute__((aligned(n)))
#define READ_ONCE(x) (x)
typedef u64 sector_t;
struct page { u8 data[4096]; };
struct bio { int bi_inline_vecs[256]; };
static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,
 const struct xdev_ext_mech_frame *f, u32 off, u32 *page_off, u32 *len)
{ (void)p; (void)f; (void)off; (void)page_off; (void)len; abort(); }
static struct bio *bio_kmalloc(u32 nr, gfp_t flags)
{ (void)nr; (void)flags; abort(); }
static void bio_uninit(struct bio *b) { (void)b; abort(); }
static void bio_init(struct bio *b, void *dev, void *vec, u32 nr, u32 op)
{ (void)b; (void)dev; (void)vec; (void)nr; (void)op; abort(); }
static int bio_add_page(struct bio *b, struct page *p, u32 len, u32 off)
{ (void)b; (void)p; (void)len; (void)off; abort(); }
static int blk_rq_append_bio(struct request *r, struct bio *b)
{ (void)r; (void)b; abort(); }
static unsigned long queue_virt_boundary(struct request_queue *q)
{ (void)q; abort(); }
#define blk_lim_dma_alignment_and_pad(l) ((void)(l), 0U)
static u32 queue_max_segments(struct request_queue *q) { (void)q; abort(); }
static u32 queue_max_segment_size(struct request_queue *q) { (void)q; abort(); }
static u32 blk_rq_bytes(struct request *r) { return r->residual; }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st, int error)
{ (void)st; (void)error; abort(); }
'''

COMMON_BIND_FACTS = r'''
/* Test-only CREATE facts for the already admitted literal cases. Identity is
 * captured by the real inline, never replaced with a successful recheck. */
static void fixture_peer_identity(struct nvme_xdev_ext_mech_stage *p)
{
 assert(!nvme_xdev_ext_capture_identity(p->ns, &p->identity,
                                     &p->head, &p->disk, &p->queue));
 p->family.geometry = (struct xdev_ext_stor_geometry){
  .capacity_lbas=p->identity.capacity_lbas, .lba_shift=p->identity.lba_shift };
 p->family.window = (struct xdev_ext_stor_window){ .slba=0,
  .nlb=p->identity.capacity_lbas, .capacity_lbas=p->identity.capacity_lbas,
  .lba_shift=p->identity.lba_shift, .write=p->write };
}
static void fixture_peer_bind(struct nvme_xdev_ext_mech_stage *p,
                              struct xdev_ext_mech_stage *st)
{
 p->family.st=st; p->family.dev=&fixture_peer_ops; p->family.member=p;
 fixture_peer_identity(p);
}
'''


def common_fixture(shim, main_source):
    """Only external type/setup and fixture-lvalue transformations."""
    original_shim, original_main = shim, main_source
    shim_edits, main_edits = [], []

    def s(old, new, count=1):
        nonlocal shim
        shim = positional_replace(shim, old, new, count, shim_edits)

    def m(old, new, count=1):
        nonlocal main_source
        main_source = positional_replace(main_source, old, new, count, main_edits)

    # The selected public dev_ops uses __u64. On LP64, uint64_t may instead
    # name unsigned long; native kernel u64 and __u64 are unsigned long long.
    # Preserve the original SHIM literal and record this external type edit.
    s('typedef uint64_t u64;', 'typedef __u64 u64;')
    # The portable header's non-kernel preamble typedefs u64 to uint64_t.
    # Extract its unchanged actual declarations/functions instead, so this
    # native-profile fixture uses the kernel scalar type without a cast.
    peer_include = re.findall(r'^#include "[^"\n]*xdev_ext_peer_nvme_core\.h"$', shim, re.M)
    if len(peer_include) != 1:
        raise AssertionError('SETUP selected peer header include count changed')
    s(peer_include[0], '/* Actual peer NVMe plan/DPTR definitions are extracted below. */')
    s('struct nvme_ns_head { u8 lba_shift; u16 ms; struct { u8 csi; } ids; u32 ns_id; };',
      'struct nvme_ns_head { u8 lba_shift; u16 ms; struct { u8 csi,eui64[8],nguid[16],uuid[16]; } ids; u32 ns_id; u8 pi_type; u16 pi_size; };')
    s('struct gendisk { u64 sectors; bool ro; };',
      'struct gendisk { u64 sectors; bool ro; u64 diskseq; };')
    s('struct request_queue { u32 max_hw_sectors; };',
      'struct request_queue { u32 max_hw_sectors; struct { u32 unused; } limits; };')
    s(' struct nvme_command storage;',
      ' struct nvme_command storage;\n struct bio *bio; u32 residual;')
    s('/* PRODUCTION_TYPES */', COMMON_EXTERNAL + '\n/* PRODUCTION_TYPES */')
    # The original external struct definitions precede COMMON_EXTERNAL.
    # Forward declarations make the pointer-only request additions explicit.
    s('struct request {', 'struct bio;\nstruct request {')
    multi = '#define FRAMES 16' in main_source
    traced = 'static void case_sync_trace(void)' in main_source
    expected = dict(rw=1 if multi else 3, validated=1, batch_id=1, sqe=4,
                    peer_slot=0 if multi else 2 if traced else 1)
    for field, count in expected.items():
        pattern = r'\bbps\[[^]]+\]\.' + field + r'\b'
        matches = re.findall(pattern, main_source)
        if len(matches) != count:
            raise AssertionError('SETUP original fixture field count changed: ' + field)
        for old in sorted(set(matches)):
            new = old.rsplit('.', 1)[0] + '.family.' + ('peer_io' if field == 'peer_slot' else field)
            m(old, new, matches.count(old))
    m('static struct gendisk disk = { 1U << 30, false };',
      'static struct gendisk disk = { .sectors=1U << 30, .ro=false, .diskseq=1 };')
    m('static struct request_queue queue = { 4096 };',
      'static struct request_queue queue = { .max_hw_sectors=4096 };')
    m(' INIT_RESOURCES;', ' fixture_peer_bind(&priv, &st);\n INIT_RESOURCES;')
    m(' bps[i].family.rw =', ' priv.family.window.write=priv.write;\n bps[i].family.rw =')
    if multi:
        m('nvme_xdev_ext_peer_resources_free(&priv)',
          'xdev_ext_storfam_peer_resources_free(&priv.family)')
        m('nvme_xdev_ext_peer_resources_init(&st)',
          'xdev_ext_storfam_peer_resources_init(&priv.family)')
    else:
        m('nvme_xdev_ext_peer_resources_free(&priv)',
          'xdev_ext_storfam_peer_resources_free(&priv.family)')
        m('priv.peer->slots[i].sgl_dma',
          'xdev_ext_storfam_peer_io(&priv.family, i)->list_dma')
        m('priv.peer->slots[i].sgl',
          '(const struct nvme_sgl_desc *)xdev_ext_storfam_peer_io(&priv.family, i)->list_cpu')
        m('priv.peer', 'priv.family.peer', 3)
        m('provider_page = 4096; head.lba_shift = 12;',
          'provider_page = 4096; head.lba_shift = 12; fixture_peer_identity(&priv);')
        m('disk.ro = false; priv.write = false; head.lba_shift = 9;',
          'disk.ro = false; priv.write = false; head.lba_shift = 9; fixture_peer_identity(&priv);')
    if traced:
        m('bps[i].family.peer_io->trace.cookie',
          '((struct nvme_xdev_ext_peer_trace *)bps[i].family.peer_io->peer_native)->cookie')
    if inverse_fixture(shim, shim_edits) != original_shim or inverse_fixture(main_source, main_edits) != original_main:
        raise AssertionError('SETUP complete fixture inverse differs from original literals')
    return shim, main_source, dict(shim=shim_edits, main=main_edits)


def build(text, code, fill, submit, have_res, directory, name):
    defines = ["#define FILL_CQE " + fill, "#define SUBMIT " + submit]
    selected = getattr(text, 'selection', None)
    if selected is None:
        raise AssertionError('SETUP build requires extraction with source authority')
    selected.verify()
    common = getattr(text, 'common', False)
    if common:
        defines += ['#define CONFIG_XDEV_EXT_MECH_ZEROCOPY 1', '#define HAVE_PEER_RES 1',
                    '#define INIT_RESOURCES rc = xdev_ext_storfam_peer_resources_init(&priv.family)']
    elif have_res:
        defines += ["#define HAVE_PEER_RES 1",
                    "#define INIT_RESOURCES rc = nvme_xdev_ext_peer_resources_init(&st)"]
    else:
        defines += ["#define INIT_RESOURCES rc = 0"]
    shim = SHIM
    main_source = MAIN
    if common:
        shim, main_source, edits = common_fixture(shim, main_source)
        (directory / (name + '.fixture-edits.json')).write_text(json.dumps(edits, indent=2) + '\n')
        (directory / (name + '.source-owner.json')).write_text(json.dumps(dict(
            root=str(selected.root), inputs={path: len(value) for path, value in selected.inputs.items()},
            definitions=selected.definitions), indent=2) + '\n')
        code += '\n' + COMMON_BIND_FACTS
    elif 'struct xdev_ext_stor_stage family;' in text:
        for field in ('rw', 'validated', 'batch_id', 'sqe'):
            main_source = re.sub(r'(bps\[[^]]+\])\.' + field + r'\b', r'\1.family.' + field, main_source)
        main_source = main_source.replace('INIT_RESOURCES;', 'priv.family.dev=&fixture_peer_ops; priv.family.member=&priv; priv.family.st=&st;\n INIT_RESOURCES;')
    shim = positional_replace(shim, "/* PRODUCTION_TYPES */", str(text))
    # This ownership suite does not inspect observation events. The native
    # trace suite consumes SHIM directly and supplies the real trace helper.
    shim = shim.replace("/* PEER_TRACE_RELEASE */", """
static void nvme_xdev_ext_peer_trace_release(
 const struct nvme_xdev_ext_peer_trace *ctx, bool quiesced)
{ (void)ctx; (void)quiesced; }
""")
    shim = shim.replace("/* PRODUCTION_FUNCTIONS */", code)
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text("\n".join(defines) + "\n" + shim + main_source)
    compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                               "-Werror", "-Wno-unused-function", "-fsanitize=undefined",
                               "-fno-sanitize-recover=undefined", "-I" + str(host_headers(selected.root, directory / "headers")),
                               str(source), "-o", str(binary)], capture_output=True, text=True)
    if compiled.returncode:
        raise SystemExit("host shim compile failed:\n" + compiled.stderr)
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)


def main():
    text, code, fill, submit, have_res = extract(production_source())
    mutations = [
        ("completion claim removed", "if (xdev_ext_mech_batch_completion_claim(b, done->ticket))", "if (0)"),
        ("accepted failure published as an ordinary completion",
         "xdev_ext_mech_batch_completion_publish(b, done->ticket, status, done->uncertain);",
         "xdev_ext_mech_batch_completion_publish(b, done->ticket, status, false);"),
        ("uncertain lease released quiesced",
         "xdev_ext_peer_fd_release(&slot->leases[i], quiesced);",
         "xdev_ext_peer_fd_release(&slot->leases[i], true);"),
        ("GPU subspan offset omitted", "off = f.umem_addr + f.data_off", "off = f.umem_addr"),
        ("native write direction reversed",
         "p->write ? DMA_TO_DEVICE : DMA_FROM_DEVICE", "p->write ? DMA_FROM_DEVICE : DMA_TO_DEVICE"),
        # Merging moved into the pure builder; perturb its input adjacency instead.
        ("DMA-contiguous pages not merged", "nvme_xdev_ext_stor_hooks.extent_align_mask, &n);",
         "nvme_xdev_ext_stor_hooks.extent_align_mask, &n);\n\t\tif (!ret && n < slot->nr_leases) return -EPROTO;"),
        ("provider page refusal not split", "if (ret != -ERANGE)", "if (true)"),
        ("admitted byte length drift accepted", "bp->rw.byte_length != plan.bytes", "false"),
        ("admitted NLB drift accepted", "bp->rw.nlb != (u64)plan.nlb + 1", "false"),
    ]
    with tempfile.TemporaryDirectory(prefix="nvme-peer-async-") as tmp:
        directory = Path(tmp)
        result = build(text, code, fill, submit, have_res, directory, "actual")
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr, end="", file=sys.stderr)
            raise SystemExit("not ok - production GPU-memory NVMe stage violates the asynchronous contract")
        for i, (name, old, new) in enumerate(mutations):
            if getattr(text, 'common', False):
                candidate = common_mutation(code, name, old, new)
            else:
                if "struct xdev_ext_stor_stage family;" in text:
                    old = old.replace("bp->rw.", "bp->family.rw.")
                if code.count(old) != 1:
                    raise SystemExit("SETUP mutation anchor missing or repeated: " + name)
                candidate = positional_replace(code, old, new)
            result = build(text, candidate, fill, submit, have_res, directory,
                           "mutation%d" % i)
            if result.returncode == 0:
                raise SystemExit("not ok - mutation survived: " + name)
            print("ok mutation - " + name + " rejected by behavior checks")


def common_mutation(code, name, old, new):
    """Rehome the original nine faults into one actual owning definition."""
    owners = {
        'completion claim removed': 'xdev_ext_stor_done',
        'accepted failure published as an ordinary completion': 'xdev_ext_stor_done',
        'uncertain lease released quiesced': 'xdev_ext_storfam_peer_put',
        'GPU subspan offset omitted': 'xdev_ext_storfam_peer_map',
        'native write direction reversed': 'xdev_ext_storfam_peer_map',
        'DMA-contiguous pages not merged': 'nvme_xdev_ext_member_encode_dptr',
        'provider page refusal not split': 'xdev_ext_peer_lease_split',
        'admitted byte length drift accepted': 'xdev_ext_storfam_submit',
        'admitted NLB drift accepted': 'xdev_ext_storfam_submit',
    }
    if name == 'uncertain lease released quiesced':
        old, new = 'xdev_ext_peer_fd_release(&io->leases[i], quiesced);', 'xdev_ext_peer_fd_release(&io->leases[i], true);'
    elif name == 'native write direction reversed':
        old = 'ss->window.write ? DMA_TO_DEVICE : DMA_FROM_DEVICE'
        new = 'ss->window.write ? DMA_FROM_DEVICE : DMA_TO_DEVICE'
    elif name == 'DMA-contiguous pages not merged':
        new = old + '\n\t\tif (!ret && n < nr) return -EPROTO;'
    elif name == 'admitted byte length drift accepted':
        old, new = 'sb->rw.byte_length != sb->posting.byte_length', 'false'
    elif name == 'admitted NLB drift accepted':
        old, new = 'sb->rw.nlb != sb->posting.nlb', 'false'
    body = definition(code, owners[name])
    changed = positional_replace(body, old, new)
    return positional_replace(code, body, changed)


if __name__ == "__main__":
    main()
