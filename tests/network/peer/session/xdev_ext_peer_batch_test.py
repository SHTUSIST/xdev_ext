#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Synchronous peer NVMe batch (42-PEER-BATCH, 42-RANDOM) under a software queue.

The real nvme_peer_ioctl (ioctl.c), the PCI batch block (pci.c), the shared
command builder (core.c), the lease split (xdev_ext_requester.c) and the
provider lease acquire/release (xdev_ext_peer.c, xdev_ext_peer_fd.c) are
extracted from the source and compiled against a software block queue. The
test plays the NVMe controller: it decodes each issued command, walks its SGL
(inline data block or last-segment list in coherent memory), resolves every
DMA address through the provider page table and moves the bytes between a
software disk and software device memory. Completion order, failures and
request-allocation failures are chosen by the test. Every case compares the
whole device memory and the whole disk with an image computed here from the
plan. This certifies command construction, admission and lifetime only; no
physical DMA, GPU or timing is involved.
"""
from pathlib import Path
import os
import re
import resource
import subprocess
import sys
import tempfile

def source_owner():
    """Find the canonical owner of this test or its ordinary registered copy."""
    for parent in Path(__file__).resolve().parents:
        marker = parent / 'view.json'
        if marker.is_file():
            import json
            receipt = json.loads(marker.read_text())
            if receipt.get('kind') == 'host-source-view':
                return Path(receipt['canonical_root']).resolve()
        if (parent / 'source-layout.json').is_file():
            return parent
    raise RuntimeError('SETUP: no canonical owner or registered source view')


# Production paths below are canonical (src/core, src/storage), so resolve the
# canonical root from either the canonical file or its registered view copy.
KERNEL = source_owner()
HERE = Path(__file__).resolve().parent


def read(rel):
    base = 'src/storage' if rel.startswith('drivers/nvme/') else 'src/core'
    return (KERNEL / base / rel).read_text()


def braced(source, name):
    """A definition of NAME starting at a line start, through its matching brace."""
    match = re.search(r'^[A-Za-z_][^\n;{}()]*\b' + re.escape(name) + r'\(', source, re.M)
    if not match:
        raise LookupError('missing actual definition: ' + name)
    start = match.start()
    depth, pos = 0, source.index('{', match.end())
    while True:
        c = source[pos]
        depth += c == '{'
        depth -= c == '}'
        pos += 1
        if not depth:
            return source[start:pos]


def structure(source, name):
    match = re.search(r'^struct ' + name + r' \{\n.*?^};', source, re.M | re.S)
    if not match:
        raise LookupError('missing actual structure: ' + name)
    return match.group()


def mech_block(source, needle):
    """The CONFIG_XDEV_EXT_MECH block of SOURCE that contains NEEDLE."""
    pos = source.index(needle)
    begin = source.rindex('#ifdef CONFIG_XDEV_EXT_MECH\n', 0, pos) + len('#ifdef CONFIG_XDEV_EXT_MECH\n')
    return source[begin:source.index('\n#endif', pos)]


def production():
    pci = read('drivers/nvme/host/pci.c')
    ioctl = read('drivers/nvme/host/ioctl.c')
    if 'static int nvme_pci_peer_batch(' not in pci:
        raise LookupError('missing actual definition: nvme_pci_peer_batch (pci.c)')
    peer = read('io_uring/xdev_ext_peer.c')
    core_include = '#include "../include/linux/xdev_ext_peer.h"'
    if peer.count(core_include) != 1:
        raise LookupError('missing actual host-test include of the peer core')
    requester_core = read('include/linux/xdev_ext_requester_core.h')
    parts = {
        'LEASE_CORE': peer.replace(core_include, '#include "' + str(
            KERNEL / 'src/core/include/linux/xdev_ext_peer.h') + '"'),
        'FD_RELEASE': braced(read('io_uring/xdev_ext_peer_fd.c'), 'xdev_ext_peer_fd_release') + '\n' +
            braced(read('io_uring/xdev_ext_peer_fd.c'), 'xdev_ext_peer_fd_release_unknown').replace(
                'bool xdev_ext_peer_fd_release_unknown(', 'bool actual_fd_release_unknown(', 1),
        'LEASE_SHRINK': re.search(r'^#define XDEV_EXT_LEASE_MIN_SHIFT .*$', requester_core, re.M).group()
                        + '\n' + braced(requester_core, 'xdev_ext_lease_shrink'),
        'LEASE_SPLIT': braced(read('io_uring/family/xdev_ext_requester.c'), 'xdev_ext_peer_lease_split'),
        'BUILD_CMD': braced(read('drivers/nvme/host/core.c'), 'nvme_xdev_ext_peer_build_cmd'),
        'EVENT_TYPE': structure(read('include/trace/events/xdev_ext.h'), 'xdev_ext_native_event'),
        'TRACE_HEADER': re.sub(r'^#include[^\n]*\n', '',
                               read('drivers/nvme/host/xdev_ext_native_peer_trace.h'), flags=re.M),
        'PEER_FLAG': re.search(r'NVME_REQ_XDEV_EXT_PEER\s*=\s*([^,]+),', read('drivers/nvme/host/nvme.h')).group(1),
        'NVME_CORE': read('drivers/nvme/host/xdev_ext_peer_nvme_core.h').replace(
            '"../../../include/linux/xdev_ext_storfam_core.h"',
            '"' + str(KERNEL / 'src/storage/include/linux/xdev_ext_storfam_core.h') + '"'),
        'PCI_BATCH': mech_block(pci, 'static int nvme_pci_peer_batch('),
        'NOTE_SUBMIT': braced(pci, 'nvme_pci_peer_note_submit'),
        'IOCTL': ioctl[ioctl.index('static int nvme_peer_rw_allowed('):ioctl.index('\n#endif', ioctl.index('static int nvme_peer_rw_allowed('))],
    }
    return parts


SHIM = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <linux/types.h>
#include "xdev_ext_peer_test_shim.h"
#define XDEV_EXT_PEER_HOST_TEST
#include "@KERNEL@/src/core/include/linux/xdev_ext_peer.h"
#include "@KERNEL@/src/core/include/uapi/linux/xdev_ext_peer.h"
@NVME_CORE@
typedef int64_t s64;
typedef uint64_t dma_addr_t;
typedef int blk_status_t;
typedef unsigned int gfp_t;
#define U64_MAX UINT64_MAX
#define SECTOR_SHIFT 9
#define SZ_4K 4096U
#define HZ 100
#define __user
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define likely(x) (x)
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define pr_warn_once(...) ((void)0)
#define pr_warn(...) ((void)0)
#define fallthrough do {} while (0)
#define array_size(a, b) ((size_t)(a) * (size_t)(b))
#define struct_size(p, m, n) (sizeof(*(p)) + sizeof((p)->m[0]) * (size_t)(n))
static int warnings;
#define WARN_ON_ONCE(x) ({ bool _w = !!(x); if (_w) warnings++; _w; })
#define WARN_ON(x) WARN_ON_ONCE(x)
#define MAX_ERRNO 4095
static inline void *ERR_PTR(long e) { return (void *)e; }
static inline long PTR_ERR(const void *p) { return (long)p; }
static inline bool IS_ERR(const void *p) { return (unsigned long)p >= (unsigned long)-MAX_ERRNO; }
static inline bool IS_ERR_OR_NULL(const void *p) { return !p || IS_ERR(p); }
#define ERR_CAST(p) ((void *)(p))
static void fail(const char *why) { fprintf(stderr, "FATAL: %s\n", why); abort(); }

/* atomic_t and completions; the test is single threaded, the controller runs
 * in the calling thread exactly where the block layer could complete. */
typedef struct { int counter; } atomic_t;
#define ATOMIC_INIT(i) { (i) }
static inline void atomic_set(atomic_t *a, int v) { a->counter = v; }
static inline int atomic_read(const atomic_t *a) { return a->counter; }
static inline void atomic_inc(atomic_t *a) { a->counter++; }
static inline void atomic_dec(atomic_t *a) { a->counter--; }
static inline int atomic_inc_return(atomic_t *a) { return ++a->counter; }
static inline int atomic_dec_return(atomic_t *a) { return --a->counter; }
static inline bool atomic_dec_and_test(atomic_t *a) { return --a->counter == 0; }
static inline int atomic_xchg(atomic_t *a, int v) { int o = a->counter; a->counter = v; return o; }
static inline int atomic_cmpxchg(atomic_t *a, int o, int n) { int c = a->counter; if (c == o) a->counter = n; return c; }
struct completion { unsigned int done; };
static inline void init_completion(struct completion *x) { x->done = 0; }
static inline void reinit_completion(struct completion *x) { x->done = 0; }
static int complete_calls;
static inline void complete(struct completion *x) { x->done++; complete_calls++; }
static unsigned long wait_for_completion_io_timeout(struct completion *x, unsigned long t);
static void wait_for_completion_io(struct completion *x) { while (!wait_for_completion_io_timeout(x, HZ)) {} }
static void wait_for_completion(struct completion *x) { wait_for_completion_io(x); }

/* Allocations, tracked for leaks. */
static int kv_live;
static void *kvcalloc(size_t n, size_t s, gfp_t f) { (void)f; kv_live++; return calloc(n ? n : 1, s ? s : 1); }
static void *kvzalloc(size_t s, gfp_t f) { return kvcalloc(1, s, f); }
static void *kvmalloc_array(size_t n, size_t s, gfp_t f) { return kvcalloc(n, s, f); }
static void *kcalloc(size_t n, size_t s, gfp_t f) { return kvcalloc(n, s, f); }
static void *kmalloc_array(size_t n, size_t s, gfp_t f) { return kvcalloc(n, s, f); }
static void kvfree(const void *p) { if (p) kv_live--; free((void *)p); }

/* NVMe command and request shapes used by the production code. */
#define NVME_CTRL_PAGE_SHIFT 12
#define NVME_CTRL_PAGE_SIZE (1 << NVME_CTRL_PAGE_SHIFT)
#define NVME_SGL_FMT_DATA_DESC 0x00
#define NVME_SGL_FMT_LAST_SEG_DESC 0x03
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_CMD_SGL_ALL 0xc0
#define nvme_cmd_write 0x01
#define nvme_cmd_read 0x02
#define NVME_CTRL_LIVE 1
#define NVME_NS_READY 1
#define NVME_NS_REMOVING 2
#define NVME_IOCTL_PARTITION (1 << 1)
#define CAP_SYS_RAWIO 17
#define NVME_REQ_CANCELLED (1 << 0)
#define NVME_REQ_USERCMD (1 << 1)
#define NVME_REQ_XDEV_EXT_PEER (@PEER_FLAG@)
#define REQ_FAILFAST_DEV (1U << 8)
#define REQ_FAILFAST_TRANSPORT (1U << 9)
#define REQ_FAILFAST_DRIVER (1U << 10)
#define REQ_FAILFAST_MASK (REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#define REQ_OP_DRV_IN 34
#define REQ_OP_DRV_OUT 35
#define BLK_MQ_REQ_NOWAIT (1U << 0)
#define BLK_STS_IOERR 10
struct nvme_sgl_desc { u64 addr; u32 length; u8 rsvd[3]; u8 type; };
struct nvme_command {
 union {
  struct { u8 opcode, flags; u16 command_id; u32 nsid; u64 rsvd2, metadata;
           union { struct nvme_sgl_desc sgl; struct { u64 prp1, prp2; }; } dptr;
           u64 slba; u16 length, control; u32 dsmgmt, reftag; u16 apptag, appmask; } rw;
  struct { u8 opcode, flags; u16 command_id; u32 nsid; u32 cdw2[2]; u64 metadata;
           union { struct nvme_sgl_desc sgl; struct { u64 prp1, prp2; }; } dptr;
           u32 cdw10, cdw11, cdw12, cdw13, cdw14, cdw15; } common;
 };
};
_Static_assert(sizeof(struct nvme_command) == 64, "NVMe SQE");
enum rq_end_io_ret { RQ_END_IO_NONE, RQ_END_IO_FREE };
struct request;
typedef enum rq_end_io_ret (rq_end_io_fn)(struct request *, blk_status_t);
struct nvme_xdev_ext_peer_trace;
struct nvme_request { struct nvme_command *cmd; u8 flags; u16 status; struct nvme_xdev_ext_peer_trace *peer_trace; };
struct request {
 struct nvme_request pdu;
 struct nvme_command storage;
 unsigned int cmd_flags;
 rq_end_io_fn *end_io;
 void *end_io_data;
 bool allocated, executed, ended;
 int seq, op;
};
#define nvme_req(r) (&(r)->pdu)
static inline int nvme_req_op(struct nvme_command *c) { return (c->common.opcode & 1) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN; }
static inline int blk_status_to_errno(blk_status_t s) { return s ? -EIO : 0; }
struct request_queue { u32 max_hw_sectors; };
struct gendisk { u64 sectors; bool ro; };
struct nvme_ns_head { u8 lba_shift; u16 ms; struct { u8 csi; } ids; u32 ns_id; };
struct nvme_dev { struct pci_dev *dev; struct xdev_ext_peer_requester *peer_requester; };
static struct nvme_dev *dispatch_dev;
struct nvme_ns;
struct nvme_ctrl_ops {
 int (*peer_rw)(struct nvme_ns *, const struct xdev_ext_peer_nvme_rw *, struct file *, bool *);
 int (*peer_batch)(struct nvme_ns *, struct xdev_ext_peer_nvme_batch *, struct file *);
};
struct nvme_ctrl { int state; bool sgl; struct nvme_dev *dev; const struct nvme_ctrl_ops *ops; };
struct nvme_ns { struct nvme_ctrl *ctrl; unsigned long flags; struct nvme_ns_head *head;
                 struct gendisk *disk; struct request_queue *queue; };
#define to_pci_dev(p) (p)
static struct nvme_dev *to_nvme_dev(struct nvme_ctrl *c) { return c->dev; }
static int nvme_ctrl_state(struct nvme_ctrl *c) { return c->state; }
static bool test_bit(unsigned bit, const unsigned long *p) { return (*p >> bit) & 1; }
static bool nvme_ctrl_sgl_supported(struct nvme_ctrl *c) { return c->sgl; }
static bool get_disk_ro(struct gendisk *d) { return d->ro; }
static u64 get_capacity(struct gendisk *d) { return d->sectors; }
static u32 queue_max_hw_sectors(struct request_queue *q) { return q->max_hw_sectors; }

/* Trace observation, recorded. */
@EVENT_TYPE@
#define MAX_EVENTS 4096
static struct xdev_ext_native_event events[MAX_EVENTS];
static int nr_events;
static bool trace_native_event_enabled(void) { return true; }
static void trace_native_event(const struct xdev_ext_native_event *e)
{ if (nr_events == MAX_EVENTS) fail("too many events"); events[nr_events++] = *e; }
@TRACE_HEADER@

/* Real provider lease core on one test mapping. */
@LEASE_CORE@
static struct file alloc_file = { .refs = 1 }, provider_file = { .refs = 1 };
static struct pci_dev pci = { .refs = 1 };
static struct xdev_ext_peer_region region;
static struct xdev_ext_peer_mapping mapping;
static struct xdev_ext_peer_requester *requester;
static int unknown_release_calls, prove_after_unknown;
static int acquire_calls;
int xdev_ext_peer_file_acquire(struct file *file, struct pci_dev *peer, u64 generation, u64 offset,
                               u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *handle)
{
 int ret;
 acquire_calls++;
 if (!handle || handle->file || handle->lease.mapping) return -EINVAL;
 if (!file) return -EBADF;
 if (file != &alloc_file || peer != &pci) fail("lease for a foreign file or requester");
 get_file(file);
 ret = xdev_ext_peer_acquire(&mapping, generation, offset, len, dir, &handle->lease);
 if (!ret) handle->file = file; else fput(file);
 return ret;
}
@FD_RELEASE@
bool xdev_ext_peer_fd_release_unknown(struct xdev_ext_peer_fd_lease *h,
                                     struct xdev_ext_peer_requester *rq, u64 epoch)
{
 bool quiesced = actual_fd_release_unknown(h, rq, epoch);
 if (++unknown_release_calls == prove_after_unknown)
  xdev_ext_peer_requester_quiesced(rq, xdev_ext_peer_requester_begin(rq));
 return quiesced;
}
@LEASE_SHRINK@
@LEASE_SPLIT@
@BUILD_CMD@

/* ioctl boundary. */
static bool cmd_allowed = true;
static bool capable(int cap) { if (cap != CAP_SYS_RAWIO) fail("capability"); return true; }
static bool nvme_cmd_allowed(struct nvme_ns *ns, struct nvme_command *c, unsigned f, bool w)
{ (void)ns; (void)c; (void)f; (void)w; return cmd_allowed; }
static int copyouts;
static int copy_from_user(void *d, const void *s, size_t n) { memcpy(d, s, n); return 0; }
static int copy_to_user(void *d, const void *s, size_t n) { copyouts++; memcpy(d, s, n); return 0; }
static void *memdup_user(const void *s, size_t n) { void *p = malloc(n); memcpy(p, s, n); return p; }
static struct file *fd3 = &alloc_file;
static struct file *fget(int fd) { if (fd != 3 || !fd3) return NULL; get_file(fd3); return fd3; }

/* Software disk, software device memory and the controller. */
#define DISK_BYTES (16U << 20)
#define DISK_LBAS (DISK_BYTES >> 9)
#define REGION_LEN (4U << 20)
#define NSID 7
#define GEN 0x55
static u8 disk[DISK_BYTES], vram[REGION_LEN], disk_expect[DISK_BYTES], vram_expect[REGION_LEN];
static u64 addresses[REGION_LEN >> 12];
static u32 page_shift;
enum { CONTIG, SCATTER, RUNS3 };
#define NREQ 256
static struct request reqs[NREQ];
static int tag_limit = NREQ, issued, inflight, max_outstanding, alloc_calls, fail_alloc_at, fail_alloc_err;
enum { OK, NVME_ERR, BLK_ERR, CANCEL };
static int outcome[64], immediate[64], exec_count[64], cmd_extents[64], cmd_inline[64];
static int no_dispatch[64], prove_on_completion;
static u64 submitted_epoch[64];
static u64 cmd_list_dma[64];
static int order_mode; /* 0 FIFO, 1 LIFO, 2 permutation */
static int perm[64], nr_perm;
static struct xdev_ext_peer_nvme_batch *user_batch;
static int mutate_on_first;
struct coherent { void *cpu; dma_addr_t dma; size_t size; bool live; };
static struct coherent coh[1024];
static int nr_coh, coh_live;
static void *dma_alloc_coherent(void *dev, size_t size, dma_addr_t *dma, gfp_t g)
{
 (void)g;
 if (dev != &pci) fail("list for a foreign device");
 if (nr_coh == 1024) fail("too many coherent lists");
 coh[nr_coh] = (struct coherent){ calloc(1, size), 0x7e0000000000ULL + (u64)nr_coh * 0x10000, size, true };
 *dma = coh[nr_coh].dma; coh_live++;
 return coh[nr_coh++].cpu;
}
static void dma_free_coherent(void *dev, size_t size, void *cpu, dma_addr_t dma)
{
 int i;
 if (dev != &pci) fail("free on a foreign device");
 for (i = 0; i < nr_coh; i++)
  if (coh[i].cpu == cpu) {
   if (!coh[i].live || coh[i].dma != dma || coh[i].size != size) fail("bad coherent free");
   coh[i].live = false; coh_live--; free(cpu); return;
  }
 fail("free of unknown coherent memory");
}
static struct coherent *coherent_at(u64 dma, u32 len)
{
 int i;
 for (i = 0; i < nr_coh; i++)
  if (coh[i].live && dma >= coh[i].dma && dma - coh[i].dma + len <= coh[i].size) return &coh[i];
 return NULL;
}
static u64 vram_offset(u64 addr, u64 left, u64 *piece)
{
 u64 page = 1ULL << page_shift, p;
 for (p = 0; p < (REGION_LEN >> page_shift); p++)
  if (addr >= addresses[p] && addr < addresses[p] + page) {
   *piece = addresses[p] + page - addr < left ? addresses[p] + page - addr : left;
   return (p << page_shift) + (addr - addresses[p]);
  }
 fail("controller DMA outside the provider mapping");
 return 0;
}
/* Decode and validate every issued command; move bytes only for a success. */
static void controller_execute(struct request *r, bool move)
{
 struct nvme_command *c = r->pdu.cmd;
 struct nvme_sgl_desc inl = c->rw.dptr.sgl, *d = &inl;
 u64 total, sum = 0, at;
 u32 n = 1, i;
 if ((c->rw.opcode != nvme_cmd_read && c->rw.opcode != nvme_cmd_write) || c->rw.nsid != NSID) fail("opcode/nsid");
 if (!(c->common.flags & NVME_CMD_SGL_METABUF)) fail("command does not select SGL");
 total = ((u64)c->rw.length + 1) << 9;
 if (c->rw.slba >= DISK_LBAS || c->rw.length + 1ULL > DISK_LBAS - c->rw.slba) fail("LBA past the disk");
 if ((inl.type >> 4) == NVME_SGL_FMT_LAST_SEG_DESC) {
  struct coherent *l = coherent_at(inl.addr, inl.length);
  if (!l || inl.length % 16 || inl.length / 16 < 2 || inl.length / 16 > 256) fail("bad SGL segment");
  d = (struct nvme_sgl_desc *)((u8 *)l->cpu + (inl.addr - l->dma));
  n = inl.length / 16;
  cmd_list_dma[r->seq] = inl.addr;
 } else if ((inl.type >> 4) != NVME_SGL_FMT_DATA_DESC) fail("bad SGL descriptor type");
 cmd_extents[r->seq] = n; cmd_inline[r->seq] = n == 1;
 for (i = 0; i < n; i++) {
  if ((d[i].type >> 4) != NVME_SGL_FMT_DATA_DESC || !d[i].length || (d[i].addr & 3) || (d[i].length & 3))
   fail("bad SGL data block");
  sum += d[i].length;
 }
 if (sum != total) fail("SGL length differs from NLB");
 if (!move) return;
 at = c->rw.slba << 9;
 for (i = 0; i < n; i++) {
  u64 a = d[i].addr, left = d[i].length, piece, off;
  while (left) {
   off = vram_offset(a, left, &piece);
   if (c->rw.opcode == nvme_cmd_read) memcpy(vram + off, disk + at, piece);
   else memcpy(disk + at, vram + off, piece);
   a += piece; left -= piece; at += piece;
  }
 }
}
static int in_flight_pick(void)
{
 int i, best = -1;
 if (order_mode == 2) {
  for (i = 0; i < nr_perm; i++)
   for (int k = 0; k < NREQ; k++)
    if (reqs[k].executed && !reqs[k].ended && reqs[k].seq == perm[i]) return k;
 }
 for (i = 0; i < NREQ; i++)
  if (reqs[i].executed && !reqs[i].ended &&
      (best < 0 || (order_mode == 1 ? reqs[i].seq > reqs[best].seq : reqs[i].seq < reqs[best].seq)))
   best = i;
 return best;
}
static void controller_complete(struct request *r)
{
 blk_status_t err = 0;
 int o = r->seq < 64 ? outcome[r->seq] : OK;
 if (!r->executed || r->ended) fail("completion of an idle request");
 exec_count[r->seq]++;
 if (!no_dispatch[r->seq]) controller_execute(r, o == OK);
 if (o == NVME_ERR) { r->pdu.status = 0x281; err = BLK_STS_IOERR; }
 else if (o == CANCEL) { r->pdu.status = 0x371; r->pdu.flags |= NVME_REQ_CANCELLED; err = BLK_STS_IOERR; }
 else if (o == BLK_ERR) err = BLK_STS_IOERR;
 if (prove_on_completion)
  xdev_ext_peer_requester_quiesced(requester, xdev_ext_peer_requester_begin(requester));
 r->ended = true; inflight--;
 if (r->end_io(r, err) == RQ_END_IO_FREE) r->allocated = false;
}
static bool controller_complete_one(void)
{
 int k = in_flight_pick();
 if (k < 0) return false;
 controller_complete(&reqs[k]);
 return true;
}
static int stuck;
static unsigned long wait_for_completion_io_timeout(struct completion *x, unsigned long t)
{
 (void)t;
 while (!x->done && controller_complete_one()) {}
 if (x->done) { x->done--; stuck = 0; return 1; }
 if (++stuck > 3) fail("waiting with no command in flight");
 return 0;
}
static int tags_in_use(void) { int i, n = 0; for (i = 0; i < NREQ; i++) n += reqs[i].allocated; return n; }
static struct request *blk_mq_alloc_request(struct request_queue *q, int op, unsigned int flags)
{
 int i;
 (void)q;
 if (++alloc_calls == fail_alloc_at) return ERR_PTR(fail_alloc_err);
 while (tags_in_use() >= tag_limit) {
  if (flags & BLK_MQ_REQ_NOWAIT) return ERR_PTR(-EWOULDBLOCK);
  if (!controller_complete_one()) fail("deadlock: no free tag and no command in flight");
 }
 for (i = 0; i < NREQ; i++)
  if (!reqs[i].allocated) {
   memset(&reqs[i], 0, sizeof(reqs[i]));
   reqs[i].allocated = true; reqs[i].op = op; reqs[i].pdu.cmd = &reqs[i].storage; reqs[i].seq = -1;
   return &reqs[i];
  }
 fail("request pool exhausted");
 return NULL;
}
static void blk_mq_free_request(struct request *r)
{ if (!r->allocated || (r->executed && !r->ended)) fail("bad request free"); r->allocated = false; }
static void nvme_init_request(struct request *r, struct nvme_command *c)
{
 if (!r->allocated) fail("init of a free request");
 c->common.flags &= ~NVME_CMD_SGL_ALL;
 r->cmd_flags |= REQ_FAILFAST_DRIVER;
 r->pdu.flags = 0; r->pdu.status = 0; r->pdu.peer_trace = NULL;
 *r->pdu.cmd = *c;
}
@NOTE_SUBMIT@
static void blk_execute_rq_nowait(struct request *r, bool at_head)
{
 struct nvme_xdev_ext_peer_trace *t = r->pdu.peer_trace;
 u64 sum = 0;
 u32 i;
 if (at_head || !r->allocated || r->executed || !r->end_io) fail("bad native execute");
 if ((r->cmd_flags & REQ_FAILFAST_MASK) != REQ_FAILFAST_MASK) fail("accepted command could be retried");
 if ((r->pdu.flags & (NVME_REQ_USERCMD | NVME_REQ_XDEV_EXT_PEER)) != (NVME_REQ_USERCMD | NVME_REQ_XDEV_EXT_PEER))
  fail("peer request flags");
 if (r->op != nvme_req_op(r->pdu.cmd)) fail("request op differs from command");
 if (!t || t->cookie != (u64)(uintptr_t)r || !t->nr_leases || strcmp(t->origin, "U")) fail("peer trace context");
 for (i = 0; i < t->nr_leases; i++) {
  if (!t->leases[i].file || !t->leases[i].lease.mapping) fail("issued with a released lease");
  sum += t->leases[i].lease.len;
 }
 if (sum != t->bytes || t->bytes != (((u64)r->pdu.cmd->rw.length + 1) << 9)) fail("trace bytes");
 r->executed = true; r->seq = issued++; inflight++;
 if (t->submit_epoch != XDEV_EXT_PEER_EPOCH_NONE) fail("trace epoch was not initialized as never dispatched");
 if (!no_dispatch[r->seq]) nvme_pci_peer_note_submit(dispatch_dev, r);
 submitted_epoch[r->seq] = t->submit_epoch;
 if (inflight > max_outstanding) max_outstanding = inflight;
 if (r->seq >= 64) fail("more commands than descriptors");
 if (user_batch && r->pdu.cmd->rw.slba != user_batch->desc[r->seq].slba && !mutate_on_first)
  fail("commands not issued in descriptor order");
 if (r->seq == 0 && mutate_on_first) {
  user_batch->desc[1].offset = 123; user_batch->desc[1].bytes = 1; user_batch->generation = 99;
  fput(fd3); fd3 = NULL; /* close(3) while the batch runs */
 }
 if (immediate[r->seq]) controller_complete(r);
}
@PCI_BATCH@
@IOCTL@
'''

MAIN = r'''
static const struct nvme_ctrl_ops ops = { .peer_rw = NULL, .peer_batch = nvme_pci_peer_batch };
static struct nvme_dev dev = { .dev = &pci };
static struct nvme_ctrl ctrl = { NVME_CTRL_LIVE, true, &dev, &ops };
static struct nvme_ns_head head = { .lba_shift = 9, .ns_id = NSID };
static struct gendisk gdisk = { DISK_LBAS, false };
static struct request_queue queue = { 2048 };
static struct nvme_ns ns = { &ctrl, 1UL << NVME_NS_READY, &head, &gdisk, &queue };
static struct xdev_ext_peer_provider_ops provider_ops;
static u64 provider_tag;
static int failures, checks;
#define CHECK(c, text) do { checks++; if (!(c)) { printf("not ok %d - %s (line %d)\n", checks, text, __LINE__); \
	failures++; } else printf("ok %d - %s\n", checks, text); } while (0)

static u8 pattern_disk(u64 i) { return (u8)(((i * 2654435761u) >> 13) ^ (i >> 9) ^ 0x3c); }
static u8 pattern_vram(u64 i) { return (u8)(((i * 40503u) >> 7) ^ (i >> 12) ^ 0xa7); }
static void device_reset(u32 shift, int layout)
{
 u64 p, page = 1ULL << shift;
 memset(&region, 0, sizeof(region)); memset(&mapping, 0, sizeof(mapping));
 mutex_init(&region.lock); INIT_LIST_HEAD(&region.maps);
 region.ops = &provider_ops; region.file = &provider_file; region.allocation = &provider_tag;
 region.len = REGION_LEN; region.generation = GEN;
 page_shift = shift;
 for (p = 0; p < (REGION_LEN >> shift); p++) {
  if (layout == CONTIG) addresses[p] = 0x40000000ULL + p * page;
  else if (layout == SCATTER) addresses[p] = 0x200000000ULL + ((p * 37) % (REGION_LEN >> shift)) * page * 2;
  else addresses[p] = 0x900000000ULL + (p / 3) * 0x1000000ULL + (p % 3) * page;
 }
 mapping.region = &region; mapping.peer = &pci; mapping.direction = DMA_BIDIRECTIONAL; mapping.users = 1;
 mapping.dma = (struct xdev_ext_peer_dma){ .addresses = addresses, .entries = REGION_LEN >> shift, .page_shift = (u8)shift };
 list_add_tail(&mapping.node, &region.maps);
 for (p = 0; p < DISK_BYTES; p++) disk[p] = disk_expect[p] = pattern_disk(p);
 for (p = 0; p < REGION_LEN; p++) vram[p] = vram_expect[p] = pattern_vram(p);
}
static void queue_reset(void)
{
 memset(reqs, 0, sizeof(reqs));
 tag_limit = NREQ; issued = inflight = max_outstanding = alloc_calls = fail_alloc_at = 0; fail_alloc_err = 0;
 memset(outcome, 0, sizeof(outcome)); memset(immediate, 0, sizeof(immediate)); memset(exec_count, 0, sizeof(exec_count));
 memset(cmd_extents, 0, sizeof(cmd_extents)); memset(cmd_inline, 0, sizeof(cmd_inline));
 memset(cmd_list_dma, 0, sizeof(cmd_list_dma));
 order_mode = 0; nr_perm = 0; nr_events = 0; acquire_calls = 0; mutate_on_first = 0; copyouts = 0;
 complete_calls = unknown_release_calls = prove_after_unknown = prove_on_completion = 0;
 memset(no_dispatch, 0, sizeof(no_dispatch)); memset(submitted_epoch, 0, sizeof(submitted_epoch));
 ctrl.state = NVME_CTRL_LIVE; ctrl.sgl = true; gdisk.ro = false; queue.max_hw_sectors = 2048; head.ms = 0;
 ns.flags = 1UL << NVME_NS_READY;
}
static struct xdev_ext_peer_nvme_batch ub;
static void batch_init(bool write, u32 nr)
{
 memset(&ub, 0, sizeof(ub));
 ub.allocation_fd = 3; ub.generation = GEN; ub.nr = nr; ub.flags = write ? XDEV_EXT_PEER_NVME_F_WRITE : 0;
}
static void desc(u32 i, u64 offset, u64 slba, u32 bytes) { ub.desc[i] = (struct xdev_ext_peer_nvme_desc){ offset, slba, bytes, 0 }; }
/* The plan's effect on the images if descriptor i ran. */
static void expect(u32 i)
{
 if (ub.flags & XDEV_EXT_PEER_NVME_F_WRITE) memcpy(disk_expect + (ub.desc[i].slba << 9), vram_expect + ub.desc[i].offset, ub.desc[i].bytes);
 else memcpy(vram_expect + ub.desc[i].offset, disk_expect + (ub.desc[i].slba << 9), ub.desc[i].bytes);
}
static int run(void)
{
 int ret;
 user_batch = &ub;
 ret = nvme_peer_ioctl(&ns, XDEV_EXT_PEER_NVME_BATCH, &ub, 0, true);
 user_batch = NULL;
 return ret;
}
static bool images_match(void)
{ return !memcmp(vram, vram_expect, REGION_LEN) && !memcmp(disk, disk_expect, DISK_BYTES); }
static bool images_match_except(u64 voff, u64 vlen)
{
 /* A failed command's own destination is unspecified; every other byte is exact. */
 return !memcmp(vram, vram_expect, voff) &&
        !memcmp(vram + voff + vlen, vram_expect + voff + vlen, REGION_LEN - voff - vlen) &&
        !memcmp(disk, disk_expect, DISK_BYTES);
}
static int exec_total(void) { int i, n = 0; for (i = 0; i < 64; i++) n += exec_count[i]; return n; }
static bool once_each(int n) { int i; for (i = 0; i < 64; i++) if (exec_count[i] != (i < n)) return false; return true; }
static int release_events(int accepted)
{ int i, n = 0; for (i = 0; i < nr_events; i++) n += !strcmp(events[i].phase, "peer_dma_release") && events[i].accepted == accepted; return n; }
static u64 seed = 42;
static u32 rnd(void) { seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; return (u32)(seed >> 33); }
static int coh_base;
static bool clean(int retained_lists)
{
 int i, alloc = 0;
 for (i = 0; i < NREQ; i++) alloc += reqs[i].allocated;
 return !mapping.active && !mapping.leases && alloc_file.refs == 1 && !kv_live && !alloc && !inflight &&
        coh_live == coh_base + retained_lists && !warnings;
}
static bool list_live(u64 dma) { int i; for (i = 0; i < nr_coh; i++) if (coh[i].dma == dma) return coh[i].live; return false; }
static void begin(u32 shift, int layout)
{
 if (requester) {
  xdev_ext_peer_requester_quiesced(requester, xdev_ext_peer_requester_begin(requester));
  while (host_run_pending_work()) {}
  if (mapping.unknown || region.queued) fail("previous fixture retained a recovery record");
  xdev_ext_peer_requester_unregister(requester);
 }
 device_reset(shift, layout); queue_reset(); coh_base = coh_live; fd3 = &alloc_file;
 requester = xdev_ext_peer_requester_register(&pci);
 if (!requester) fail("requester allocation");
 /* Zero is a valid epoch; a nonzero snapshot catches a lost submit hook. */
 xdev_ext_peer_requester_begin(requester);
 xdev_ext_peer_requester_begin(requester);
 xdev_ext_peer_requester_begin(requester);
 dev.peer_requester = requester;
 dispatch_dev = &dev;
}

int main(void)
{
 int ret;
 u32 i;
 setbuf(stdout, NULL);

 /* --- 1 MiB: one native command over real, partly discontiguous extents. --- */
 begin(16, RUNS3);
 batch_init(false, 1); desc(0, 0, 1000, 1U << 20); expect(0);
 ret = run();
 CHECK(!ret && ub.completed == 1 && !ub.status && issued == 1 && once_each(1),
       "1 MiB read is one command and completes (64 KiB provider pages)");
 CHECK(reqs[0].storage.rw.length == 2047 && cmd_extents[0] == 6 && !cmd_inline[0],
       "1 MiB over 16 pages in runs of three is one last-segment list of six real extents");
 CHECK(images_match(), "whole device memory and disk equal the plan (1 MiB read)");
 CHECK(clean(0) && release_events(1) == 1 && !region.quarantined, "every lease, request and list released after success");
 begin(12, SCATTER);
 batch_init(false, 1); desc(0, 1U << 20, 2000, 1U << 20); expect(0);
 ret = run();
 CHECK(!ret && ub.completed == 1 && cmd_extents[0] == 256 && images_match() && clean(0),
       "1 MiB over 256 discontiguous 4 KiB pages fills one 256-entry list exactly");
 begin(12, SCATTER);
 batch_init(false, 2); desc(0, 0, 10, 4096); desc(1, (1U << 20) + 512, 2000, 1U << 20);
 ret = run();
 CHECK(ret == -EREMOTEIO && !ub.completed && ub.status == -EREMOTEIO && !issued && images_match() && clean(0),
       "257 discontiguous extents exceed one list: whole batch refused before any command");
 begin(12, CONTIG);
 batch_init(false, 1); desc(0, 0, 3000, 1U << 20); expect(0);
 ret = run();
 CHECK(!ret && ub.completed == 1 && cmd_extents[0] == 1 && cmd_inline[0] && images_match() && clean(0),
       "1 MiB over contiguous pages is one inline SGL data block");
 begin(16, RUNS3);
 queue.max_hw_sectors = 1024;
 batch_init(false, 2); desc(0, 0, 10, 4096); desc(1, 1U << 20, 2000, 1U << 20);
 ret = run();
 CHECK(ret == -E2BIG && !ub.completed && !issued && images_match() && clean(0),
       "request above the queue transfer limit refuses the whole batch");
 begin(16, RUNS3);
 batch_init(false, 4);
 for (i = 0; i < 4; i++) { desc(i, (u64)i << 20, 4000 + 4096 * i, 1U << 20); expect(i); }
 order_mode = 1;
 ret = run();
 CHECK(!ret && ub.completed == 4 && issued == 4 && max_outstanding == 4 && once_each(4),
       "four 1 MiB commands are all in flight before the first completes (queue depth 4)");
 CHECK(images_match() && clean(0), "four 1 MiB reads completed in reverse order equal the plan");

 /* --- Page tails: requests start and end inside provider pages. --- */
 begin(16, SCATTER);
 batch_init(false, 4);
 desc(0, (64U << 10) - 1024, 50, 3072); desc(1, (192U << 10) - 512, 60, 512);
 desc(2, (256U << 10) + 4096, 70, (64U << 10) + 512); desc(3, (512U << 10) + 2048, 300, 1024);
 for (i = 0; i < 4; i++) expect(i);
 ret = run();
 CHECK(!ret && ub.completed == 4 && cmd_extents[0] == 2 && cmd_extents[1] == 1 && cmd_extents[2] == 2 &&
       cmd_extents[3] == 1, "page-tail requests become the exact head/tail extents");
 CHECK(images_match() && clean(0), "page tails land exactly; every neighbouring byte unchanged");

 /* --- Writes from device memory across pages. --- */
 begin(12, SCATTER);
 batch_init(true, 3);
 desc(0, 5 * 4096 + 1024, 9000, 3 * 4096); desc(1, 5 * 4096 + 1024, 9100, 3 * 4096);
 desc(2, (2U << 20) + 512, 9500, (128U << 10) + 1536);
 for (i = 0; i < 3; i++) expect(i);
 ret = run();
 CHECK(!ret && ub.completed == 3 && cmd_extents[0] == 4 && cmd_extents[2] == 33 && images_match() && clean(0),
       "write batch: one device-memory source read twice, multi-page tail source; whole disk equals the plan");

 /* --- Out-of-order completion. --- */
 begin(12, RUNS3);
 batch_init(false, 8);
 {
  static const u32 slot[8] = {5, 2, 7, 0, 3, 6, 1, 4};
  for (i = 0; i < 8; i++) { desc(i, slot[i] * (192U << 10) + 1536, 7000 + 300 * (7 - i), (64U << 10) + 512); expect(i); }
 }
 order_mode = 2; nr_perm = 8;
 { static const int p[8] = {5, 2, 7, 0, 3, 6, 1, 4}; memcpy(perm, p, sizeof(p)); }
 ret = run();
 CHECK(!ret && ub.completed == 8 && max_outstanding == 8 && once_each(8) && images_match() && clean(0),
       "eight commands in flight complete in a shuffled order; completed is the full count");
 begin(12, RUNS3);
 batch_init(false, 16);
 for (i = 0; i < 16; i++) { desc(i, i * (64U << 10), 100 + 200 * i, 32U << 10); expect(i); }
 tag_limit = 4;
 ret = run();
 CHECK(!ret && ub.completed == 16 && max_outstanding == 4 && once_each(16) && images_match() && clean(0),
       "sixteen commands through four tags: allocation waits for completions, nothing is lost");

 /* One tag repeatedly completes while the issuer is still allocating. The
  * issuer bias must prevent those intermediate end_io calls completing done. */
 begin(12, SCATTER);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) { desc(i, i * (64U << 10), 100 + 200 * i, 32U << 10); expect(i); }
 tag_limit = 1;
 ret = run();
 CHECK(!ret && ub.completed == 6 && !ub.status && issued == 6 && max_outstanding == 1 && once_each(6),
       "one tag reused for six successes: all descriptors complete exactly once");
 CHECK(complete_calls == 1 && images_match() && clean(0),
       "issuer bias suppresses intermediate completion; only the last end_io publishes done");
 begin(12, SCATTER);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) {
  desc(i, i * (64U << 10), 100 + 200 * i, 32U << 10); expect(i); immediate[i] = 1;
 }
 tag_limit = 1;
 ret = run();
 CHECK(!ret && ub.completed == 6 && issued == 6 && max_outstanding == 1 && once_each(6) && !complete_calls &&
       images_match() && clean(0), "all synchronous completions leave the issuer bias as the last reference");

 /* Real FD/core UNKNOWN retirement, not a mock of its boolean result. */
 begin(12, SCATTER);
 batch_init(false, 1); desc(0, 4096, 100, 3 * 4096);
 outcome[0] = NVME_ERR;
 ret = run();
 CHECK(ret == 0x281 && !ub.completed && issued == 1 && submitted_epoch[0] == 3 && unknown_release_calls == 3 &&
       mapping.unknown == requester && mapping.unknown_epoch == 3 && region.pending == 1 &&
       region.quarantined && !region.permanent && clean(1),
       "accepted error retires every lease into the real requester's dispatch epoch");
 CHECK(images_match_except(4096, 3 * 4096) && list_live(cmd_list_dma[0]) && release_events(0) == 1,
       "UNKNOWN retains its descriptor list and reports no DMA-stop evidence");
 xdev_ext_peer_requester_quiesced(requester, xdev_ext_peer_requester_begin(requester));
 while (host_run_pending_work()) {}
 CHECK(!mapping.unknown && !region.pending && !region.quarantined && region.invalid && list_live(cmd_list_dma[0]),
       "later actual requester proof recovers mapping quarantine; retained descriptor memory is not reused");

 begin(12, SCATTER);
 batch_init(false, 1); desc(0, 4096, 100, 3 * 4096);
 outcome[0] = NVME_ERR; prove_on_completion = 1;
 ret = run();
 CHECK(ret == 0x281 && !ub.completed && unknown_release_calls == 3 && submitted_epoch[0] == 3 &&
       !mapping.unknown && !region.quarantined && clean(0) && !list_live(cmd_list_dma[0]) && release_events(1) == 1,
       "later epoch proven before retirement permits all leases and the descriptor list to be released");

 begin(12, SCATTER);
 batch_init(false, 1); desc(0, 4096, 100, 3 * 4096);
 outcome[0] = NVME_ERR; prove_after_unknown = 1;
 ret = run();
 CHECK(ret == 0x281 && unknown_release_calls == 3 && clean(1) && list_live(cmd_list_dma[0]) && release_events(0) == 1,
       "proof arriving between leases cannot override an earlier uncovered lease or short-circuit retirement");

 begin(12, SCATTER);
 batch_init(false, 1); desc(0, 4096, 100, 3 * 4096);
 dev.peer_requester = NULL; outcome[0] = CANCEL;
 ret = run();
 CHECK(ret == -EINTR && submitted_epoch[0] == XDEV_EXT_PEER_EPOCH_NONE && unknown_release_calls == 3 &&
       !mapping.unknown && region.permanent && region.quarantined && clean(1),
       "missing requester keeps an accepted cancellation permanently UNKNOWN");

 begin(12, SCATTER);
 batch_init(false, 1); desc(0, 4096, 100, 3 * 4096);
 outcome[0] = CANCEL; no_dispatch[0] = 1; prove_on_completion = 1;
 ret = run();
 CHECK(ret == -EINTR && submitted_epoch[0] == XDEV_EXT_PEER_EPOCH_NONE && unknown_release_calls == 3 &&
       region.permanent && region.quarantined && !mapping.unknown && clean(1) && images_match(),
       "cancellation before SQ publication cannot turn an uninitialized epoch zero into DMA-stop evidence");

 /* --- Partial accept: request allocation fails after two accepted commands. --- */
 begin(16, RUNS3);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) desc(i, i * (256U << 10) + 512, 800 + 64 * i, (128U << 10) + 1024);
 expect(0); expect(1);
 fail_alloc_at = 3; fail_alloc_err = -ENODEV;
 ret = run();
 CHECK(ret == -ENODEV && ub.completed == 2 && ub.status == -ENODEV && issued == 2 && once_each(2),
       "allocation failure at the third command: two accepted and completed, the rest never issued");
 CHECK(images_match() && clean(0) && !region.quarantined,
       "never-issued destinations untouched; their leases and lists released; allocation reusable");
 queue_reset(); coh_base = coh_live;
 batch_init(false, 1); desc(0, 3U << 20, 50, 4096); expect(0);
 ret = run();
 CHECK(!ret && ub.completed == 1 && images_match() && clean(0), "the same allocation serves the next batch");

 /* --- Partial accept when the failure completes while an allocation waits. --- */
 begin(16, RUNS3);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) desc(i, (6 * i + 1) * (64U << 10), 900 + 512 * i, 192U << 10);
 expect(0); expect(1);
 tag_limit = 1; outcome[2] = NVME_ERR;
 ret = run();
 CHECK(ret == 0x281 && ub.completed == 2 && ub.status == 0x281 && issued == 3 && once_each(3),
       "one tag: the failure completes during the next allocation, so nothing after it is issued");
 CHECK(images_match_except(13 * (64U << 10), 192U << 10) && region.quarantined && clean(1),
       "requests after the failure untouched; the failed command's list retained");

 /* --- Partial accept after an observed failure; UNKNOWN retention. --- */
 begin(16, RUNS3);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) desc(i, i * (512U << 10) + 1024, 900 + 512 * i, 256U << 10);
 expect(0);
 outcome[1] = NVME_ERR; immediate[1] = 1;
 ret = run();
 CHECK(ret == 0x281 && ub.completed == 1 && ub.status == 0x281 && issued == 2 && once_each(2),
       "a failure seen during issue stops issue: later descriptors are never accepted");
 CHECK(cmd_extents[1] == 3 && images_match_except((512U << 10) + 1024, 256U << 10) && region.quarantined && region.invalid,
       "accepted native failure quarantines the allocation; other bytes exact");
 CHECK(list_live(cmd_list_dma[1]) && !list_live(cmd_list_dma[0]) && clean(1),
       "the failed command's SGL list is retained (unknown DMA), every other list freed");
 CHECK(release_events(0) == 1 && release_events(1) == 1, "release events: failed command not quiesced, success quiesced");
 queue_reset(); coh_base = coh_live;
 batch_init(false, 1); desc(0, 0, 1, 4096);
 ret = run();
 CHECK(ret == -ESTALE && !ub.completed && !issued && clean(0), "quarantined allocation refuses the next batch before any command");

 /* --- Failures after every command was accepted. --- */
 begin(16, RUNS3);
 batch_init(false, 3);
 for (i = 0; i < 3; i++) desc(i, (18 * i + 1) * (64U << 10), 100 + 4096 * i, 192U << 10);
 expect(1); expect(2);
 outcome[0] = BLK_ERR;
 ret = run();
 CHECK(ret == -EIO && !ub.completed && ub.status == -EIO && issued == 3 && once_each(3) &&
       cmd_extents[0] == 2 && images_match_except(64U << 10, 192U << 10) && region.quarantined && clean(1),
       "transport error on the first of three accepted commands: completed 0, never resent, unknown retained");
 begin(16, RUNS3);
 batch_init(false, 3);
 for (i = 0; i < 3; i++) { desc(i, (18 * i + 1) * (64U << 10), 100 + 4096 * i, 192U << 10); if (i < 2) expect(i); }
 outcome[2] = CANCEL;
 ret = run();
 CHECK(ret == -EINTR && ub.completed == 2 && ub.status == -EINTR && once_each(3) && cmd_extents[2] == 2 &&
       images_match_except(37 * (64U << 10), 192U << 10) && region.quarantined && clean(1),
       "cancelled last command: completed prefix 2, -EINTR, retained");
 begin(16, RUNS3);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) { desc(i, (6 * i + 1) * (64U << 10), 3000 + 1024 * i, 192U << 10); if (i != 2) expect(i); }
 outcome[2] = NVME_ERR; order_mode = 1;
 ret = run();
 CHECK(ret == 0x281 && ub.completed == 2 && ub.status == 0x281 && max_outstanding == 6 && once_each(6) &&
       cmd_extents[2] == 2 && images_match_except(13 * (64U << 10), 192U << 10) && region.quarantined && clean(1),
       "out-of-order completion: later successes do not extend the prefix past a failed command");

 /* --- 42-RANDOM: refusals before any device sees the batch. --- */
 begin(16, RUNS3);
 batch_init(false, 4);
 for (i = 0; i < 4; i++) desc(i, i * (256U << 10), 10 + 100 * i, 64U << 10);
 ub.desc[3].offset = ub.desc[1].offset;
 ret = run();
 CHECK(ret == -EINVAL && !ub.completed && ub.status == -EINVAL && !issued && images_match() && clean(0),
       "duplicate target: whole batch refused, nothing issued");
 begin(16, RUNS3);
 batch_init(false, 6);
 for (i = 0; i < 6; i++) desc(i, (5 - i) * (256U << 10), 10 + 200 * i, 64U << 10);
 ub.desc[5].offset = ub.desc[0].offset + (64U << 10) - 512;
 ret = run();
 CHECK(ret == -EINVAL && !ub.completed && !issued && images_match() && clean(0),
       "last target overlapping the first by 512 bytes: refused, the five valid ones are not executed either");
 begin(12, SCATTER);
 batch_init(false, 2); desc(0, 4096 * 3, 77, 8192); desc(1, 4096 * 100 + 512, 77, 8192); expect(0); expect(1);
 ret = run();
 CHECK(!ret && ub.completed == 2 && images_match() && clean(0), "duplicate source LBA into two targets is admitted");
 begin(16, RUNS3);
 batch_init(false, 5);
 for (i = 0; i < 5; i++) desc(i, i * (512U << 10), 10 + 200 * i, 64U << 10);
 ub.desc[4].offset = REGION_LEN - 4096;
 ret = run();
 CHECK(ret == -ERANGE && !ub.completed && ub.status == -ERANGE && !issued && images_match() && clean(0) &&
       !region.quarantined, "target past the allocation: refused before any command, allocation still usable");
 begin(16, RUNS3);
 batch_init(false, 3);
 for (i = 0; i < 3; i++) desc(i, i * (512U << 10), 10 + 200 * i, 4096);
 ub.desc[2].slba = DISK_LBAS - 1; ub.desc[2].bytes = 1024;
 ret = run();
 CHECK(ret == -ERANGE && !ub.completed && !issued && images_match() && clean(0), "LBA past the namespace: refused, nothing issued");
 begin(16, RUNS3);
 batch_init(false, 2); desc(0, 0, 10, 4096); desc(1, UINT64_MAX - 4095, 20, 8192);
 ret = run();
 CHECK(ret == -EOVERFLOW && !ub.completed && !issued && images_match() && clean(0), "device-memory span wrapping u64: refused");
 begin(16, RUNS3);
 batch_init(false, 2); desc(0, 0, 10, 4096); desc(1, 8192, UINT64_MAX - 7, 4096);
 ret = run();
 CHECK(ret == -ERANGE && !ub.completed && !issued && images_match() && clean(0), "LBA wrapping u64: refused");
 begin(16, RUNS3);
 batch_init(false, 2); desc(0, 0, 10, 4096); desc(1, 8192, 20, 4096); ub.generation = GEN + 1;
 ret = run();
 CHECK(ret == -ESTALE && !ub.completed && !issued && images_match() && clean(0), "wrong generation: refused before any command");
 begin(16, RUNS3);
 batch_init(true, 2); desc(0, 0, 100, 8192); desc(1, 1U << 20, 115, 1024);
 ret = run();
 CHECK(ret == -EINVAL && !ub.completed && !issued && images_match() && clean(0), "write LBA destinations overlapping: refused");

 /* --- 42-RANDOM: many random targets, full-byte oracle for reads and writes. --- */
 {
  u32 slots[48];
  for (i = 0; i < 48; i++) slots[i] = i;
  for (i = 47; i > 0; i--) { u32 j = rnd() % (i + 1), t = slots[i]; slots[i] = slots[j]; slots[j] = t; }
  begin(12, SCATTER);
  batch_init(false, 48);
  for (i = 0; i < 48; i++) {
   u32 bytes = 512 * (1 + rnd() % 120), head = 512 * (rnd() % 16), lba = rnd() % (DISK_LBAS - 128);
   desc(i, (u64)slots[i] * (80U << 10) + head, lba, bytes);
   expect(i);
  }
  order_mode = 2; nr_perm = 48;
  for (i = 0; i < 48; i++) perm[i] = (int)slots[47 - i];
  ret = run();
  CHECK(!ret && ub.completed == 48 && max_outstanding == 48 && once_each(48) && images_match() && clean(0),
        "48 random disjoint read targets with page tails, shuffled order: whole device memory equals the plan");
  begin(12, SCATTER);
  batch_init(true, 48);
  for (i = 0; i < 48; i++) {
   u32 bytes = 512 * (1 + rnd() % 120), source = 512 * (rnd() % 7000), lba = slots[i] * 200 + rnd() % 64;
   desc(i, source, lba, bytes);
   expect(i);
  }
  order_mode = 1;
  ret = run();
  CHECK(!ret && ub.completed == 48 && once_each(48) && images_match() && clean(0),
        "48 random disjoint LBA write targets from overlapping sources: whole disk equals the plan");
 }

 /* --- Snapshot and file lifetime across a concurrent close. --- */
 begin(16, RUNS3);
 batch_init(false, 3);
 for (i = 0; i < 3; i++) { desc(i, i * (512U << 10), 10 + 200 * i, 16U << 10); expect(i); }
 mutate_on_first = 1;
 ret = run();
 CHECK(!ret && ub.completed == 3 && ub.desc[1].offset == 512U << 10 && ub.desc[1].bytes == 16U << 10 &&
       ub.generation == GEN && images_match(), "descriptors are a kernel snapshot; user mutation during the batch has no effect");
 CHECK(alloc_file.refs == 0 && !mapping.active && !kv_live && copyouts == 1,
       "the batch held its own allocation reference across close(); every lease reference returned");
 alloc_file.refs = 1;

 /* --- Device state is checked before any lease or command. --- */
 begin(16, RUNS3); batch_init(false, 1); desc(0, 0, 1, 4096); ctrl.state = 0;
 CHECK(run() == -ENODEV && !issued && !acquire_calls && clean(0), "controller not live: refused before any lease");
 begin(16, RUNS3); batch_init(false, 1); desc(0, 0, 1, 4096); ctrl.sgl = false;
 CHECK(run() == -EOPNOTSUPP && !issued && !acquire_calls && clean(0), "controller without SGL: refused before any lease");
 begin(16, RUNS3); batch_init(true, 1); desc(0, 0, 1, 4096); gdisk.ro = true;
 CHECK(run() == -EROFS && !issued && !acquire_calls && clean(0), "write to a read-only namespace: refused before any lease");

 xdev_ext_peer_requester_unregister(requester);
 requester = NULL;
 printf("1..%d\n", checks);
 return failures ? 1 : 0;
}
'''


# Each mutant is a defect the behaviour checks must reject (part, old, new).
MUTANTS = [
    ('destination overlap admitted', 'NVME_CORE', '   return -EINVAL;\n dst[i] =', '   (void)0;\n dst[i] ='),
    ('device-memory wrap admitted', 'NVME_CORE', ' if (offset > ~(u64)0 - bytes) return -EOVERFLOW;\n', '\n'),
    ('one provider page per command', 'PCI_BATCH', 'ret = xdev_ext_peer_lease_split(allocation,',
     'ret = xdev_ext_peer_file_acquire(allocation,'),
    ('issue continues after an observed failure', 'PCI_BATCH',
     '\t\tif (atomic_read(&b->failed)) {\n\t\t\tblk_mq_free_request(req);\n\t\t\tbreak;\n\t\t}\n', ''),
    ('failure checked only before the allocation', 'PCI_BATCH',
     '\t\treq = blk_mq_alloc_request(ns->queue, nvme_req_op(&c->cmd), 0);\n'
     '\t\tif (IS_ERR(req)) {\n\t\t\tissue_err = PTR_ERR(req);\n\t\t\tbreak;\n\t\t}\n'
     '\t\t/* Checked after the allocation, which may wait for a failed completion. */\n'
     '\t\tif (atomic_read(&b->failed)) {\n\t\t\tblk_mq_free_request(req);\n\t\t\tbreak;\n\t\t}\n',
     '\t\tif (atomic_read(&b->failed))\n\t\t\tbreak;\n'
     '\t\treq = blk_mq_alloc_request(ns->queue, nvme_req_op(&c->cmd), 0);\n'
     '\t\tif (IS_ERR(req)) {\n\t\t\tissue_err = PTR_ERR(req);\n\t\t\tbreak;\n\t\t}\n'),
    ('one command in flight at a time', 'PCI_BATCH', '\t\tblk_execute_rq_nowait(req, false);\n',
     '\t\tblk_execute_rq_nowait(req, false);\n\t\twhile (atomic_read(&b->pending) > 1)\n'
     '\t\t\twait_for_completion_io_timeout(&b->done, 1);\n'),
    ('accepted failure released as quiesced', 'PCI_BATCH',
     'bool unknown = c->accepted && c->status;', 'bool unknown = false;'),
    ('UNKNOWN loses requester binding', 'PCI_BATCH',
     'dev->peer_requester, c->trace.submit_epoch', 'NULL, c->trace.submit_epoch'),
    ('UNKNOWN loses dispatch epoch', 'PCI_BATCH',
     'dev->peer_requester, c->trace.submit_epoch', 'dev->peer_requester, XDEV_EXT_PEER_EPOCH_NONE'),
    ('unsubmitted trace starts in a real epoch', 'PCI_BATCH',
     '.submit_epoch = XDEV_EXT_PEER_EPOCH_NONE,', '.submit_epoch = 0,'),
    ('last lease overrides an earlier UNKNOWN', 'PCI_BATCH',
     'quiesced &= stopped;', 'quiesced = stopped;'),
    ('UNKNOWN retirement short-circuits after one uncovered lease', 'PCI_BATCH',
     'bool stopped = xdev_ext_peer_fd_release_unknown(',
     'bool stopped = quiesced && xdev_ext_peer_fd_release_unknown('),
    ('issuer has no pending bias', 'PCI_BATCH',
     'atomic_set(&b->pending, 1);', 'atomic_set(&b->pending, 0);'),
    ('UNKNOWN command list reused', 'PCI_BATCH', 'if (c->list && quiesced)', 'if (c->list)'),
    ('later successes extend the prefix', 'PCI_BATCH',
     '\t\tret = c->accepted ? c->status : issue_err;\n\t\tif (WARN_ON_ONCE(!ret))\n\t\t\tret = -EIO;\n\t\tbreak;\n',
     '\t\tif (!ret)\n\t\t\tret = c->accepted ? c->status : issue_err;\n\t\tcontinue;\n'),
    ('request kept until the batch ends', 'PCI_BATCH', '\treturn RQ_END_IO_FREE;\n}', '\treturn RQ_END_IO_NONE;\n}'),
    ('refused batch keeps its leases', 'PCI_BATCH',
     'out_retire:\n\tfor (i = nr; i--; )\n\t\tnvme_pci_peer_batch_retire(dev, &b->cmd[i]);\n',
     'out_retire:\n\tfor (i = nr; ret == 0 && i--; )\n\t\tnvme_pci_peer_batch_retire(dev, &b->cmd[i]);\n'),
]


def build(parts, directory, name, main=MAIN):
    code = SHIM.replace('@KERNEL@', str(KERNEL))
    for key, value in parts.items():
        code = code.replace('@' + key + '@', value)
    path = directory / (name + '.c')
    path.write_text(code + main)
    binary = directory / name
    compiled = subprocess.run(['cc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                               '-Wno-unused-function', '-fsanitize=address,undefined',
                               '-fno-sanitize-recover=undefined',
                               '-I' + str(HERE), '-I' + str(KERNEL / 'src/storage/drivers/nvme/host'),
                               str(path), '-o', str(binary)], capture_output=True, text=True)
    return compiled, binary


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        parts = production()
    except (LookupError, ValueError) as error:
        print('not ok 1 - concurrent multi-page peer batch:', error)
        return 1
    with tempfile.TemporaryDirectory(prefix='xdev-peer-batch-') as tmp:
        directory = Path(tmp)
        compiled, binary = build(parts, directory, 'batch')
        if compiled.returncode:
            print(compiled.stdout + compiled.stderr)
            print('not ok 1 - concurrent multi-page peer batch does not compile against the queue')
            return 1
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=600)
        print(result.stdout, end='')
        if os.environ.get('XDEV_EXT_TEST_ARTIFACTS'):
            artifacts = Path(os.environ['XDEV_EXT_TEST_ARTIFACTS'])
            artifacts.mkdir(parents=True, exist_ok=True)
            (artifacts / 'batch.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            print(result.stderr[-4000:], end='')
            return 1
        for index, (name, part, old, new) in enumerate(MUTANTS):
            changed = dict(parts)
            changed[part] = parts[part].replace(old, new)
            if changed[part] == parts[part]:
                print('not ok mutation - ' + name + ': production text not found')
                return 1
            compiled, binary = build(changed, directory, 'mutant%d' % index)
            if compiled.returncode:
                print(compiled.stderr[-2000:])
                print('not ok mutation - ' + name + ': does not compile')
                return 1
            try:
                mutant = subprocess.run([str(binary)], capture_output=True, text=True, timeout=120)
                rejected = mutant.returncode != 0
            except subprocess.TimeoutExpired:
                rejected = True
            if not rejected:
                print('not ok mutation - ' + name + ' passed every behaviour check')
                return 1
            print('ok mutation - ' + name + ' rejected by behaviour checks')
    return 0


if __name__ == '__main__':
    sys.exit(main())
