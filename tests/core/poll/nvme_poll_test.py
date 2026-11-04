#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NVMe class polling: bind capability, REQ_POLLED submit, end_io and the pass.

The production functions of drivers/nvme/host/xdev_ext_mech_nvme.c run
verbatim against a fixture that models only the block-layer objects they
touch: request allocation (which hardware queue type a request landed on),
blk_rq_is_poll(), execute, and blk_mq_poll_hw_queue() as a recorder. The
model does not reproduce nvme-pci queues, DMA or timing.
"""
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from poll_extract import KERNEL, _helpers as HELPERS, body, compile_and_run, fields, function, source

NVME = 'drivers/nvme/host/xdev_ext_mech_nvme.c'
BLK = 'block/blk-mq.c'
BLK_H = 'include/linux/blk-mq.h'


def structure(text, name):
    match = re.search(r'^struct ' + name + r' \{\n.*?^\};', text, re.M | re.S)
    if not match:
        raise AssertionError('production structure missing: ' + name)
    return match[0]


FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "include/linux/xdev_ext_storfam_runtime.h"
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define ERR_CAST(p) ((void *)(p))
#include "include/uapi/linux/xdev_ext_mech.h"
#include "include/linux/nvme_xdev_ext_passthru.h"

typedef int atomic_t;
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
typedef unsigned int blk_opf_t; typedef int blk_status_t; typedef u64 dma_addr_t;
#define atomic_read(p) (*(p))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define le64_to_cpu(v) (v)
#define le16_to_cpu(v) (v)
#define cpu_to_le32(v) (v)
#define cpu_to_le64(v) (v)
#define cpu_to_le16(v) (v)
#define REQ_POLLED (1U << 21)
#define REQ_FAILFAST_MASK (7U << 8)
#define BLK_MQ_REQ_NOWAIT (1U << 0)
#define BLK_FEAT_POLL (1U << 3)
#define NVME_REQ_CANCELLED (1U << 0)
#define NVME_REQ_USERCMD (1U << 1)
#define NVME_REQ_XDEV_EXT_PEER (1U << 5)
#define NVME_CMD_SGL_METABUF (1U << 6)
#define GFP_KERNEL 0
#define NVME_XDEV_EXT_PEER_MAX_SPANS 4
#define XDEV_EXT_MECH_POOL_PEER 3
enum rq_end_io_ret { RQ_END_IO_NONE, RQ_END_IO_FREE };
enum hctx_type { HCTX_TYPE_DEFAULT, HCTX_TYPE_READ, HCTX_TYPE_POLL, HCTX_MAX_TYPES };
struct blk_mq_queue_map { unsigned int nr_queues; };
struct blk_mq_tag_set { unsigned int nr_maps; struct blk_mq_queue_map map[HCTX_MAX_TYPES]; };
struct queue_limits { unsigned int features; };
struct request_queue { struct queue_limits limits; struct blk_mq_tag_set *tag_set; };
struct blk_mq_hw_ctx { unsigned int queue_num; enum hctx_type type; };
struct bio { int unused; };
struct page;
struct io_comp_batch;
struct xdev_ext_peer_nvme_seg { u64 unused; };
struct xdev_ext_peer_fd_lease { u64 unused; };
struct nvme_sgl_desc { u64 unused; };
struct nvme_command {
	struct { u8 opcode; u32 nsid; u64 slba; u16 length; } rw;
	struct { u32 cdw10, cdw11, cdw12; u8 flags; } common;
};
struct nvme_request { unsigned int flags; u16 status; union { u64 u64; } result; struct nvme_command *cmd;
	struct nvme_xdev_ext_peer_trace *peer_trace; };
struct request {
	blk_opf_t cmd_flags;
	struct blk_mq_hw_ctx *mq_hctx;
	struct nvme_request nvme;
	enum rq_end_io_ret (*end_io)(struct request *, blk_status_t);
	void *end_io_data;
	struct bio *bio;
	unsigned int bytes;
};
#define nvme_req(r) (&(r)->nvme)
struct xdev_ext_mech_session { unsigned int pool_kind; };
struct xdev_ext_mech_stage {
	struct xdev_ext_mech_session *s;
	void *priv;
	u32 direction;
	bool poll;
};
struct xdev_ext_mech_pool { unsigned int kind; };
static struct xdev_ext_mech_pool host_pool = { .kind = 2 }, peer_pool = { .kind = 3 };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ return s->pool_kind == 3 ? &peer_pool : &host_pool; }
struct xdev_ext_mech_batch;
/* IDENTITY_OS_TYPES */
/* FAMILY_TYPES */

/* PRODUCTION_STRUCTS */

struct nvme_xdev_ext_mech_stage {
	struct nvme_ns *ns;
#ifdef FIXTURE_MEMBER_FAMILY
 struct xdev_ext_stor_stage family;
 struct nvme_xdev_ext_identity identity;
 const struct nvme_ns_head *head;
 const struct gendisk *disk;
 const struct request_queue *queue;
 bool write;
#else
 int dead;
 struct nvme_xdev_ext_identity identity;
 struct xdev_ext_stor_window window;
#endif
	struct nvme_xdev_ext_mech_slot *slots, *free;
	u32 nr_slots;
	struct nvme_xdev_ext_peer_res *peer;
};
struct nvme_xdev_ext_mech_batch {
#ifdef FIXTURE_MEMBER_FAMILY
 struct xdev_ext_stor_batch family;
#else
 u8 sqe[NVME_XDEV_EXT_SQE_SIZE];
 struct xdev_ext_stor_rw rw;
 u64 batch_id;
 bool validated;
#endif
	struct bio *bio;
	struct nvme_xdev_ext_mech_slot *slot;
	struct page **bounce;
	struct xdev_ext_nvme_mech_cqe cqe;
};
struct xdev_ext_mech_batch { struct nvme_xdev_ext_mech_batch priv; u64 ticket; };

/* Recorders and the modelled block layer. */
static const char *mode;
static struct request native_request;
static struct blk_mq_hw_ctx poll_hctx = { .queue_num = 5, .type = HCTX_TYPE_POLL };
static struct blk_mq_hw_ctx default_hctx = { .queue_num = 1, .type = HCTX_TYPE_DEFAULT };
static blk_opf_t alloc_opf;
static int allocs, frees, maps, executes, slot_gets, slot_puts, publishes, claims_failed;
static int live_at_execute = -1; static u32 queue_at_execute;
static unsigned polled_queue[16], polled_n; static struct request_queue *polled_q; static int polled_iob_null = 1;
static bool blk_rq_is_poll(struct request *rq) { return rq->mq_hctx && rq->mq_hctx->type == HCTX_TYPE_POLL; }
static struct request *blk_mq_alloc_request(struct request_queue *q, blk_opf_t opf, unsigned int flags)
{
	(void)q; (void)flags;
	allocs++;
	alloc_opf = opf;
	memset(&native_request, 0, sizeof(native_request));
	native_request.cmd_flags = opf;
	/* REQ_POLLED lands on a poll queue unless the queue map lost them. */
	native_request.mq_hctx = (opf & REQ_POLLED) && strcmp(mode, "lost") ? &poll_hctx : &default_hctx;
	return &native_request;
}
static void blk_mq_free_request(struct request *req) { (void)req; frees++; }
static void nvme_init_request(struct request *req, struct nvme_command *cmd) { (void)req; (void)cmd; }
static void blk_execute_rq_nowait(struct request *req, bool at_head)
{
	struct xdev_ext_stor_completion *done = req->end_io_data;
	(void)at_head;
	executes++;
	live_at_execute = done->poll_live;
	queue_at_execute = done->poll_queue;
	if (!strcmp(mode,"early")) req->end_io(req,0);
}
static int blk_mq_poll_hw_queue(struct request_queue *q, unsigned int queue_num, struct io_comp_batch *iob)
{
	polled_q = q;
	polled_iob_null &= !iob;
	if (polled_n < 16)
		polled_queue[polled_n] = queue_num;
	polled_n++;
	return (int)queue_num;
}
static int blk_status_to_errno(blk_status_t s) { return s ? -5 : 0; }
static unsigned int blk_rq_bytes(struct request *rq) { return rq->bytes; }
#ifdef FIXTURE_MEMBER_FAMILY
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s)
{ static const struct xdev_ext_mech_layout layout={.group_bytes=4096};(void)s;return &layout; }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int ret) { (void)st;(void)ret;abort(); }
#else
/* The original pre-extraction fixture boundary, only for old production. */
static int nvme_xdev_ext_class_recheck(struct xdev_ext_mech_stage *st) { (void)st; return 0; }
#endif
static blk_opf_t nvme_req_op(struct nvme_command *cmd) { (void)cmd; return 1; }
static int nvme_xdev_ext_peer_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{ (void)st; (void)b; abort(); }
static struct nvme_xdev_ext_mech_slot slot_storage;
static struct nvme_xdev_ext_mech_slot *nvme_xdev_ext_class_slot_get(struct xdev_ext_mech_stage *st,
								 struct nvme_xdev_ext_mech_batch *bp)
{ (void)st; slot_gets++; bp->slot = &slot_storage; return &slot_storage; }
static void nvme_xdev_ext_class_slot_put(struct xdev_ext_mech_stage *st, struct nvme_xdev_ext_mech_batch *bp)
{ (void)st; slot_puts++; bp->slot = NULL; }
static int nvme_xdev_ext_class_map(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
				   struct request *req, struct nvme_xdev_ext_mech_batch *bp)
{ (void)st; (void)b; (void)req; (void)bp; maps++; return 0; }
static struct nvme_xdev_ext_mech_batch *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return &b->priv; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { (void)b; return 7; }
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { return b->ticket; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b; return 4096; }
static void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b, u64 c, u64 l, u32 n, u32 o)
{ (void)b; (void)c; (void)l; (void)n; (void)o; }
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b, u64 t, int s)
{ (void)b; (void)t; (void)s; }
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, u64 ticket)
{ if (ticket != b->ticket) { claims_failed++; return -1; } return 0; }
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b, u64 t, int e, bool q)
{ (void)b; (void)t; (void)e; (void)q; publishes++; }
static enum rq_end_io_ret nvme_xdev_ext_peer_end_io(struct request *req, blk_status_t err);

static void xdev_ext_mech_trace_plan(struct xdev_ext_mech_batch *b,u64 lba,u32 bytes,u32 plan,int ret)
{ (void)b;(void)lba;(void)bytes;(void)plan;(void)ret; }

/* PRODUCTION */

static void report(int rc)
{
	printf("rc=%d polled_opf=%d allocs=%d frees=%d maps=%d executes=%d slot_gets=%d slot_puts=%d "
	       "live=%d queue=%u publishes=%d live_after=%d\n", rc, !!(alloc_opf & REQ_POLLED), allocs, frees, maps,
	       executes, slot_gets, slot_puts, live_at_execute, queue_at_execute, publishes,
	       native_request.end_io_data ? ((struct xdev_ext_stor_completion *)native_request.end_io_data)->poll_live : -1);
}

static int submit_case(bool poll)
{
	struct nvme_ns ns = { 0 };
	struct nvme_xdev_ext_mech_stage p = { .ns = &ns,
#ifdef FIXTURE_MEMBER_FAMILY
  .family={.window={.slba=0,.nlb=32,.capacity_lbas=32,.lba_shift=9}}
#else
  .window={.slba=0,.nlb=32,.capacity_lbas=32,.lba_shift=9}
#endif
 };
	struct xdev_ext_mech_session s = { .pool_kind = 2 };
	struct xdev_ext_mech_stage st = { .s = &s, .priv = &p, .poll = poll };
	static struct xdev_ext_mech_batch b;

	const u8 sqe[NVME_XDEV_EXT_SQE_SIZE] = { [0]=NVME_XDEV_EXT_NVM_READ,[48]=7 };
#ifdef FIXTURE_MEMBER_FAMILY
 fixture_worker_init(&p,&st);
#endif
 if (nvme_xdev_ext_class_validate(&st,&b,sqe,1))
  abort();
	b.ticket = 11;
	report(nvme_xdev_ext_class_submit(&st, &b));
	return 0;
}

static int end_io_case(bool peer)
{
	static struct xdev_ext_mech_batch b;
	struct nvme_xdev_ext_peer_trace trace = { 0 };
	struct xdev_ext_stor_completion done = { .b = &b, .ticket = 11, .poll_live = true, .poll_queue = 5 };
	struct request req = { .end_io_data = &done };

	b.ticket = !strcmp(mode,"stale") ? 12 : 11;
	if (peer) {
		req.nvme.flags |= NVME_REQ_XDEV_EXT_PEER;
		req.nvme.peer_trace = &trace;
	}
	if (peer)
		nvme_xdev_ext_peer_end_io(&req, 0);
	else
		nvme_xdev_ext_class_end_io(&req, 0);
	printf("live=%d publishes=%d trace_flag=%d trace_ptr=%d\n", done.poll_live, publishes,
	       !!(req.nvme.flags & NVME_REQ_XDEV_EXT_PEER), !!req.nvme.peer_trace);
	return 0;
}

static int pass_case(bool peer)
{
	struct request_queue q;
	struct nvme_ns ns = { .queue = &q };
	struct nvme_xdev_ext_mech_slot host[4] = { 0 };
	struct nvme_xdev_ext_peer_slot peers[3];
	struct nvme_xdev_ext_peer_res res = { 0 };
	struct nvme_xdev_ext_mech_stage p = { .ns = &ns,
#ifdef FIXTURE_MEMBER_FAMILY
  .family={.window={.slba=0,.nlb=32,.capacity_lbas=32,.lba_shift=9}}
#else
  .window={.slba=0,.nlb=32,.capacity_lbas=32,.lba_shift=9}
#endif
 };
	struct xdev_ext_mech_stage st = { .priv = &p, .poll = true };
	u32 qs[4] = { 2, 3, 2, 9 };
	unsigned i;
	int ret;

	memset(peers, 0, sizeof(peers));
	for (i = 0; i < 4; i++) {
		host[i].done.poll_queue = qs[i];
		host[i].done.poll_live = i != 3;
	}
	if (peer) {
		peers[0].done.poll_queue = 4; peers[0].done.poll_live = true;
		peers[1].done.poll_queue = 4; peers[1].done.poll_live = true;
		peers[2].done.poll_queue = 8; peers[2].done.poll_live = false;
		res.slots = peers;
		res.nr_slots = 3;
		p.peer = &res;
	} else {
		p.slots = host;
		p.nr_slots = 4;
	}
#ifdef FIXTURE_MEMBER_FAMILY
 fixture_worker_init(&p,&st);
 /* This fixture injects resources instead of executing CREATE. Install its
  * borrowed views once here, exactly where those arrays are injected. */
 p.family.poll_views[0]=(struct xdev_ext_stor_poll_view){.first=p.nr_slots?&host[0].done:NULL,.stride=sizeof(host[0]),.count=p.nr_slots};
 p.family.poll_views[1]=(struct xdev_ext_stor_poll_view){.first=p.peer?&peers[0].done:NULL,.stride=sizeof(peers[0]),.count=p.peer?p.peer->nr_slots:0};
#endif
 ret = nvme_xdev_ext_class_poll(&st);
	printf("ret=%d n=%u q0=%u q1=%u q2=%u same_queue=%d iob_null=%d\n", ret, polled_n,
	       polled_queue[0], polled_queue[1], polled_queue[2], polled_q == &q, polled_iob_null);
	return 0;
}

static int capable_case(void)
{
	struct blk_mq_tag_set set = { .nr_maps = 3, .map = { { 4 }, { 0 }, { 2 } } };
	struct request_queue q = { .limits = { .features = BLK_FEAT_POLL }, .tag_set = &set };
	int full, no_feature, no_queues, two_maps, no_set;

	full = nvme_xdev_ext_poll_capable(&q);
	q.limits.features = 0; no_feature = nvme_xdev_ext_poll_capable(&q); q.limits.features = BLK_FEAT_POLL;
	set.map[HCTX_TYPE_POLL].nr_queues = 0; no_queues = nvme_xdev_ext_poll_capable(&q);
	set.map[HCTX_TYPE_POLL].nr_queues = 2; set.nr_maps = 2; two_maps = nvme_xdev_ext_poll_capable(&q);
	set.nr_maps = 3; q.tag_set = NULL; no_set = nvme_xdev_ext_poll_capable(&q);
	printf("full=%d no_feature=%d no_queues=%d two_maps=%d no_set=%d\n", full, no_feature, no_queues,
	       two_maps, no_set);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	mode = argv[1];
	if (!strcmp(mode, "plain")) return submit_case(false);
	if (!strcmp(mode, "poll") || !strcmp(mode, "lost") || !strcmp(mode,"early")) return submit_case(true);
	if (!strcmp(mode, "end_io") || !strcmp(mode,"stale")) return end_io_case(false);
	if (!strcmp(mode, "peer_end_io")) return end_io_case(true);
	if (!strcmp(mode, "pass")) return pass_case(false);
	if (!strcmp(mode, "peer_pass")) return pass_case(true);
	if (!strcmp(mode, "capable")) return capable_case();
	return 2;
}
'''

PRODUCTION = ('nvme_xdev_ext_poll_capable', 'nvme_xdev_ext_poll_opf', 'nvme_xdev_ext_poll_check',
              'nvme_xdev_ext_poll_arm', 'nvme_xdev_ext_class_complete', 'nvme_xdev_ext_class_ready',
              'nvme_xdev_ext_peer_complete', 'nvme_xdev_ext_class_end_io', 'nvme_xdev_ext_peer_end_io',
              'nvme_xdev_ext_class_validate', 'nvme_xdev_ext_class_submit', 'nvme_xdev_ext_class_poll')


def storage_runtime(root):
    content = HELPERS['read_native'](root, 'io_uring/family/xdev_ext_storfam.c')
    found = []
    for name in ('xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get',
                 'xdev_ext_stor_slot_put', 'xdev_ext_stor_done'):
        match = re.search(r'^[A-Za-z_][^;{}]*\b' + name +
                          r'\([^;{}]*\)\s*\{.*?^\}', content, re.M | re.S)
        if not match:
            raise AssertionError('production storage runtime symbol missing: ' + name)
        found.append(match[0])
    return '\n\n'.join(found)


def family_owns_io(text):
    # Old native sources need not carry the newer family header at all.
    # Read it only when the selected class actually delegates submission.
    if 'xdev_ext_storfam_submit(&p->family, b, &bp->family)' not in function(
            text, 'nvme_xdev_ext_class_submit'):
        return False
    return bool(re.search(r'^struct xdev_ext_stor_io \{',
                          source('include/linux/xdev_ext_storfam_block.h'), re.M))


FAMILY_IO_FIXTURE = r'''
#define __aligned(n) __attribute__((aligned(n)))
#define REQ_OP_DRV_IN 34U
#define REQ_OP_DRV_OUT 35U
#define SZ_4K 4096U
#define XDEV_EXT_STOR_PEER_MAX_SPANS 512U
#define NVME_CTRL_LIVE 1
struct nvme_ctrl { int state; };
static int nvme_ctrl_state(struct nvme_ctrl *ctrl) { return ctrl->state; }
static bool nvme_ctrl_sgl_supported(struct nvme_ctrl *ctrl) { (void)ctrl; return false; }
static int get_disk_ro(struct gendisk *disk) { (void)disk; return 0; }
static unsigned queue_max_hw_sectors(struct request_queue *q) { (void)q; return 1024; }

/* FAMILY_IO_TYPES */

/* These are the original fixture's bypassed slot/map operations, now owned
 * by the family. No submit, post, completion or polling decision lives here. */
static struct xdev_ext_stor_io slot_storage;
static struct xdev_ext_stor_io *xdev_ext_storfam_host_get(struct xdev_ext_stor_stage *ss,
                                                        struct xdev_ext_stor_batch *sb)
{ (void)ss; slot_gets++; sb->host_io = &slot_storage; return &slot_storage; }
static void xdev_ext_storfam_host_put(struct xdev_ext_stor_stage *ss, struct xdev_ext_stor_batch *sb)
{ (void)ss; slot_puts++; sb->host_io = NULL; }
static int xdev_ext_storfam_host_map(struct xdev_ext_stor_stage *ss, struct xdev_ext_mech_batch *b,
                                    struct request *req, struct xdev_ext_stor_batch *sb)
{ (void)ss; (void)b; (void)req; (void)sb; maps++; return 0; }
/* Existing runtime submit cases are HOST. An accidental PEER submission
 * must abort at the unchanged resource boundary, never silently succeed. */
static struct xdev_ext_stor_io *xdev_ext_storfam_peer_get(struct xdev_ext_stor_stage *ss,
                                                        struct xdev_ext_stor_batch *sb)
{ (void)ss; (void)sb; abort(); }
static void xdev_ext_storfam_peer_put(struct xdev_ext_stor_stage *ss, struct xdev_ext_stor_batch *sb)
{ (void)ss; (void)sb; abort(); }
static int xdev_ext_storfam_peer_map(struct xdev_ext_stor_stage *ss, struct xdev_ext_mech_batch *b,
                                    struct xdev_ext_stor_io *io, u32 bytes)
{ (void)ss; (void)b; (void)io; (void)bytes; abort(); }
static int fixture_encode_dptr(void *member, struct xdev_ext_stor_command *command,
                               const struct xdev_ext_stor_extent *spans, u32 nr,
                               struct xdev_ext_stor_extent *work, u32 capacity,
                               void *cpu, __u64 dma, u32 bytes)
{ (void)member; (void)command; (void)spans; (void)nr; (void)work; (void)capacity;
  (void)cpu; (void)dma; (void)bytes; abort(); }

/* FAMILY_IO_PRODUCTION */

static const struct xdev_ext_stor_dev_ops fixture_member_ops = {
 .identity = nvme_xdev_ext_member_identity,
 .queue = nvme_xdev_ext_member_queue,
 .decode = nvme_xdev_ext_member_decode,
 .encode = nvme_xdev_ext_member_encode,
 .encode_dptr = fixture_encode_dptr,
 .request_init = nvme_xdev_ext_member_request_init,
 .post = nvme_xdev_ext_member_post,
 .poll = nvme_xdev_ext_member_poll,
};
'''


def build_family_io_fixture(text):
    """Actual common submit/native post chain; original OS/resource boundary."""
    header = source('include/linux/xdev_ext_storfam_block.h')
    block = source('io_uring/family/xdev_ext_storfam_block.c')
    plan = source('drivers/nvme/host/xdev_ext_peer_nvme_core.h')
    trace = structure(source('drivers/nvme/host/xdev_ext_native_peer_trace.h'),
                      'nvme_xdev_ext_peer_trace')
    command = re.search(r'^struct xdev_ext_stor_command \{.*?^\} __aligned\(8\);',
                        header, re.M | re.S)
    if not command:
        raise AssertionError('production aligned structure missing: xdev_ext_stor_command')
    types = command[0] + '\n' + '\n'.join(structure(header, n) for n in (
        'xdev_ext_stor_poll_view', 'xdev_ext_stor_geometry',
        'xdev_ext_stor_dev_ops', 'xdev_ext_stor_io', 'xdev_ext_stor_peer_io',
        'xdev_ext_stor_stage', 'xdev_ext_stor_batch'))
    types += '\n' + trace + '\n' + '\n'.join(structure(text, n) for n in (
        'nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_batch', 'nvme_xdev_ext_peer_slot'))
    types += '\nstruct xdev_ext_mech_batch { struct nvme_xdev_ext_mech_batch priv; u64 ticket; };'
    # Reuse unchanged recorders, but remove the original owner-specific resource
    # shims; their moved signatures are supplied in FAMILY_IO_FIXTURE instead.
    recorders = FIXTURE[FIXTURE.index('/* Recorders and the modelled block layer. */'):
                       FIXTURE.index('/* PRODUCTION */')]
    start = recorders.index('static int nvme_xdev_ext_peer_submit(')
    end = recorders.index('static struct nvme_xdev_ext_mech_batch *xdev_ext_mech_batch_priv(')
    recorders = recorders[:start] + recorders[end:]
    recorders = recorders.replace('(void)req; (void)cmd; }',
                                  'req->nvme.cmd = cmd; }')
    recorders = recorders.replace(
        'static struct nvme_xdev_ext_mech_batch *xdev_ext_mech_batch_priv(',
        'static void *xdev_ext_mech_batch_priv(')
    identity = HELPERS['identity_boundary']().replace(
        'struct nvme_ns { struct request_queue *queue;',
        'struct nvme_ctrl;\nstruct nvme_ns { struct nvme_ctrl *ctrl; struct request_queue *queue;')
    prefix = FIXTURE[:FIXTURE.index('/* IDENTITY_OS_TYPES */')]
    prefix += identity + '''
#define FIXTURE_MEMBER_FAMILY 1
struct pci_dev; struct xdev_ext_mech_stage_uapi;
struct xdev_ext_stor_stage; struct xdev_ext_stor_io;
'''
    # Type declarations must precede recorders and complete batch consumers.
    setup, remainder = FAMILY_IO_FIXTURE.split('/* FAMILY_IO_TYPES */')
    boundary, ops = remainder.split('/* FAMILY_IO_PRODUCTION */')
    code = ''
    # This portable structure is one line in the selected header.
    plan_type = re.search(r'^struct xdev_ext_peer_nvme_plan \{[^\n]*\};', plan, re.M)
    if not plan_type:
        raise AssertionError('production structure missing: xdev_ext_peer_nvme_plan')
    code += plan_type[0] + '\n' + function(plan, 'xdev_ext_peer_nvme_plan')
    code += '\n' + storage_runtime(KERNEL) + '\n' + HELPERS['storage_poll_runtime'](KERNEL, (
        'xdev_ext_stor_block_poll_capable', 'xdev_ext_stor_block_poll_opf',
        'xdev_ext_stor_block_poll_check', 'xdev_ext_stor_block_poll_arm',
        'xdev_ext_stor_block_poll'))
    code += '\n' + function(source('drivers/nvme/host/nvme.h'), 'nvme_xdev_ext_capture_identity')
    native_names = ('nvme_xdev_ext_member_identity', 'nvme_xdev_ext_member_queue',
                    'nvme_xdev_ext_member_decode', 'nvme_xdev_ext_member_encode',
                    'nvme_xdev_ext_class_complete', 'nvme_xdev_ext_peer_complete',
                    'nvme_xdev_ext_class_end_io', 'nvme_xdev_ext_peer_end_io',
                    'nvme_xdev_ext_member_request_init', 'nvme_xdev_ext_member_post',
                    'nvme_xdev_ext_member_poll', 'nvme_xdev_ext_class_validate',
                    'nvme_xdev_ext_class_submit', 'nvme_xdev_ext_class_poll')
    common_names = ('xdev_ext_storfam_validate', 'xdev_ext_storfam_submit_check',
                    'xdev_ext_storfam_submit', 'xdev_ext_storfam_poll',
                    'xdev_ext_storfam_host_ready')
    definitions = [function(block, n) for n in common_names]
    definitions += [function(text, n) for n in native_names]
    # Original function signatures, not handwritten behavioral wrappers.
    prototypes = '\n'.join(d[:d.index('{')].rstrip() + ';' for d in definitions)
    code += '\n' + prototypes + '\n' + '\n\n'.join(definitions)
    cases = FIXTURE[FIXTURE.index('static void report(int rc)'):]
    # Replace complete fixture case functions at their resource-injection
    # boundary. Reports, command modes and Python assertions stay unchanged.
    old_pass = function(cases, 'pass_case')
    new_pass = old_pass.replace('struct nvme_xdev_ext_mech_slot host[4]',
                               'struct xdev_ext_stor_io host[4]')
    new_pass = new_pass.replace('\n\tstruct nvme_xdev_ext_peer_res res = { 0 };', '')
    new_pass = new_pass.replace('peers[0].done', 'peers[0].common.io.done')
    new_pass = new_pass.replace('peers[1].done', 'peers[1].common.io.done')
    new_pass = new_pass.replace('peers[2].done', 'peers[2].common.io.done')
    old_resources = '''\t\tres.slots = peers;
\t\tres.nr_slots = 3;
\t\tp.peer = &res;
\t} else {
\t\tp.slots = host;
\t\tp.nr_slots = 4;
\t}'''
    new_pass = new_pass.replace(old_resources, '\t}')
    old_views = ''' p.family.poll_views[0]=(struct xdev_ext_stor_poll_view){.first=p.nr_slots?&host[0].done:NULL,.stride=sizeof(host[0]),.count=p.nr_slots};
 p.family.poll_views[1]=(struct xdev_ext_stor_poll_view){.first=p.peer?&peers[0].done:NULL,.stride=sizeof(peers[0]),.count=p.peer?p.peer->nr_slots:0};'''
    new_views = ''' p.family.poll_views[0]=(struct xdev_ext_stor_poll_view){.first=peer?NULL:&host[0].done,.stride=sizeof(host[0]),.count=peer?0:4};
 p.family.poll_views[1]=(struct xdev_ext_stor_poll_view){.first=peer?&peers[0].common.io.done:NULL,.stride=sizeof(peers[0]),.count=peer?3:0};'''
    # Match the original injection after migrating the peer completion field.
    migrated_views = old_views.replace('peers[0].done', 'peers[0].common.io.done')
    if migrated_views not in new_pass or old_resources not in old_pass:
        raise AssertionError('family IO fixture resource-injection boundary changed')
    new_pass = new_pass.replace(migrated_views, new_views)
    cases = cases.replace(old_pass, new_pass)
    cases = cases.replace('nvme_xdev_ext_poll_capable(', 'xdev_ext_stor_block_poll_capable(')
    return (prefix + setup + types + '\n' + recorders + boundary + code + ops +
            HELPERS['worker_fixture_init']() + '\n' + cases)


def build_fixture():
    text = source(NVME)
    if family_owns_io(text):
        return build_family_io_fixture(text)
    trace = structure(source('drivers/nvme/host/xdev_ext_native_peer_trace.h'),
                      'nvme_xdev_ext_peer_trace')
    structs = trace + '\n' + '\n'.join(structure(text, n) for n in (
        'nvme_xdev_ext_mech_slot',
        'nvme_xdev_ext_peer_slot', 'nvme_xdev_ext_peer_res'))
    structs = structs.replace('struct device *dma_dev;', 'void *dma_dev;')
    names = PRODUCTION
    dependencies = ''
    fixture = FIXTURE
    if 'xdev_ext_stor_block_poll_opf(' in text:
        names = tuple(n for n in names if not n.startswith('nvme_xdev_ext_poll_'))

        dependencies = HELPERS['storage_poll_runtime'](KERNEL, (
            'xdev_ext_stor_block_poll_capable', 'xdev_ext_stor_block_poll_opf',
            'xdev_ext_stor_block_poll_check', 'xdev_ext_stor_block_poll_arm',
            'xdev_ext_stor_block_poll'))
        fixture = fixture.replace('nvme_xdev_ext_poll_capable(', 'xdev_ext_stor_block_poll_capable(')
    api = HELPERS
    if 'struct xdev_ext_stor_stage family;' in text:
        fixture = '#define FIXTURE_MEMBER_FAMILY 1\n' + fixture
        fixture = fixture.replace('/* IDENTITY_OS_TYPES */', api['identity_boundary']())
        fixture = fixture.replace('/* FAMILY_TYPES */', api['family_types'](KERNEL))
        dependencies += '\n' + api['worker_runtime'](KERNEL, text, poll=True) + '\n' + api['worker_fixture_init']()
    else:
        # Pre-7A production owns its window/gates and builds the borrowed views.
        # Keep the original namespace, private fields and recheck boundary.
        fixture = fixture.replace('/* IDENTITY_OS_TYPES */', 'struct nvme_ns { struct request_queue *queue; };')
        fixture = fixture.replace('/* FAMILY_TYPES */', '')
        if 'xdev_ext_stor_block_poll_opf(' in text:
            structs += '\n' + structure(source('include/linux/xdev_ext_storfam_block.h'),
                                        'xdev_ext_stor_poll_view')
    production = storage_runtime(KERNEL) + '\n' + dependencies + '\n' + '\n'.join(
        function(text, n) for n in names)
    return fixture.replace('/* PRODUCTION_STRUCTS */', structs).replace('/* PRODUCTION */', production)


class NativeSourceSelection(unittest.TestCase):
    """Filesystem source selection only; marker inputs are never compiled."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nvme-source-selection-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.first = self.canonical('first', '/* explicit root */\n')
        self.other = self.canonical('other', '/* environment hint */\n')

    def canonical(self, name, marker):
        root = self.directory / name
        native = root / 'src/storage/input.c'
        header = root / 'src/storage/include/linux/xdev_ext_boundary.h'
        header.parent.mkdir(parents=True)
        native.write_text(marker)
        header.write_text(marker)
        (root / 'source-layout.json').write_text(json.dumps({'schema': 1, 'files': [
            {'component': 'linux', 'native_path': NVME, 'source': 'src/storage/input.c'},
            {'component': 'linux', 'native_path': 'include/linux/xdev_ext_boundary.h',
             'source': 'src/storage/include/linux/xdev_ext_boundary.h'}]}))
        return root

    def test_explicit_canonical_source_and_headers_ignore_foreign_hint(self):
        with patch.dict(os.environ, {'XDEV_EXT_CANONICAL_ROOT': str(self.other)}):
            selected = HELPERS['read_native'](self.first, NVME)
            headers = HELPERS['host_headers'](self.first, self.directory / 'headers')
        self.assertEqual(selected, '/* explicit root */\n')
        self.assertEqual((headers / 'include/linux/xdev_ext_boundary.h').read_text(), selected)

    def test_canonical_mapping_keeps_code_with_its_headers(self):
        native_alias = self.first / NVME
        native_alias.parent.mkdir(parents=True)
        native_alias.write_text('/* unselected native alias */\n')
        with patch.dict(os.environ, {'XDEV_EXT_CANONICAL_ROOT': str(self.other)}):
            selected = HELPERS['read_native'](self.first, NVME)
            headers = HELPERS['host_headers'](self.first, self.directory / 'headers')
        self.assertEqual(selected, '/* explicit root */\n')
        self.assertEqual((headers / 'include/linux/xdev_ext_boundary.h').read_text(), selected)

    def test_explicit_canonical_child_ignores_foreign_hint(self):
        child = self.first / 'nested'
        child.mkdir()
        with patch.dict(os.environ, {'XDEV_EXT_CANONICAL_ROOT': str(self.other)}):
            selected = HELPERS['read_native'](child, NVME)
        self.assertEqual(selected, '/* explicit root */\n')

    def test_missing_selected_mapping_does_not_borrow_foreign_source(self):
        selected = self.directory / 'missing'
        selected.mkdir()
        (selected / 'source-layout.json').write_text(json.dumps({'schema': 1, 'files': []}))
        with patch.dict(os.environ, {'XDEV_EXT_CANONICAL_ROOT': str(self.other)}):
            with self.assertRaises(ValueError):
                HELPERS['read_native'](selected, NVME)

    def test_minimal_native_dependency_hint_is_only_fallback(self):
        minimal = self.directory / 'minimal'
        minimal.mkdir()
        with patch.dict(os.environ, {'XDEV_EXT_CANONICAL_ROOT': str(self.other)}):
            self.assertEqual(HELPERS['read_native'](minimal, NVME), '/* environment hint */\n')
            explicit = minimal / NVME
            explicit.parent.mkdir(parents=True)
            explicit.write_text('/* explicit native file */\n')
            self.assertEqual(HELPERS['read_native'](minimal, NVME), '/* explicit native file */\n')


class NvmePoll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build_fixture()

    def run_case(self, case):
        code, out = compile_and_run(self.fixture, (case,))
        self.assertEqual(code, 0, out)
        return fields(out)

    def test_unpolled_submit_unchanged(self):
        r = self.run_case('plain')
        self.assertEqual((r['rc'], r['polled_opf'], r['executes'], r['live']), (0, 0, 1, 0), r)
        self.assertEqual((r['allocs'], r['frees'], r['maps']), (1, 0, 1), r)

    def test_polled_submit_records_its_poll_queue_before_execute(self):
        r = self.run_case('poll')
        self.assertEqual((r['rc'], r['polled_opf'], r['executes']), (0, 1, 1), r)
        self.assertEqual((r['live'], r['queue']), (1, 5), 'the pass can find the request when it is issued')

    def test_polled_submit_never_falls_back_to_an_interrupt_queue(self):
        r = self.run_case('lost')
        self.assertEqual(r['rc'], -95, r)  # -EOPNOTSUPP
        self.assertEqual((r['executes'], r['frees'], r['maps']), (0, 1, 0), r)
        self.assertEqual(r['slot_gets'], r['slot_puts'], 'no slot stays taken')

    def test_end_io_retires_the_poll_record(self):
        r = self.run_case('end_io')
        self.assertEqual((r['live'], r['publishes']), (0, 1), r)

    def test_immediate_completion_clears_poll_record_before_submit_returns(self):
        r = self.run_case('early')
        self.assertEqual((r['rc'], r['executes'], r['live'], r['live_after'], r['publishes']),
                         (0, 1, 1, 0, 1), r)

    def test_stale_completion_retires_record_without_publishing(self):
        r = self.run_case('stale')
        self.assertEqual((r['live'], r['publishes']), (0, 0), r)

    def test_peer_end_io_retires_the_poll_record(self):
        r = self.run_case('peer_end_io')
        self.assertEqual((r['live'], r['publishes']), (0, 1), r)
        self.assertEqual((r['trace_flag'], r['trace_ptr']), (0, 0), r)

    def test_pass_polls_each_live_queue_once(self):
        r = self.run_case('pass')
        self.assertEqual((r['n'], r['q0'], r['q1']), (2, 2, 3), r)
        self.assertEqual((r['ret'], r['same_queue'], r['iob_null']), (5, 1, 1), r)

    def test_pass_covers_device_memory_slots(self):
        r = self.run_case('peer_pass')
        self.assertEqual((r['n'], r['q0'], r['ret']), (1, 4, 4), r)

    def test_bind_capability_requires_poll_queues(self):
        r = self.run_case('capable')
        self.assertEqual((r['full'], r['no_feature'], r['no_queues'], r['two_maps'], r['no_set']),
                         (1, 0, 0, 0, 0), r)


class NvmePollStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = source(NVME)

    def test_bind_refuses_an_unpollable_namespace_before_allocating(self):
        bind = body(self.text, 'nvme_xdev_ext_member_bind' if 'nvme_xdev_ext_member_bind(' in self.text else 'nvme_xdev_ext_class_bind')
        check = bind.index('if (st->poll && !xdev_ext_stor_block_poll_capable(ns->queue))')
        self.assertLess(check, bind.index('kzalloc('))
        self.assertIn('return -EOPNOTSUPP;', bind[check:check + 120])

    def test_peer_submit_uses_the_same_poll_steps_in_order(self):
        if family_owns_io(self.text):
            common = source('io_uring/family/xdev_ext_storfam_block.c')
            submit = body(common, 'xdev_ext_storfam_submit')
            post = body(self.text, 'nvme_xdev_ext_member_post')
            class_submit = body(self.text, 'nvme_xdev_ext_class_submit')
            self.assertIn('return xdev_ext_storfam_submit(&p->family, b, &bp->family);', class_submit)
            bind = body(self.text, 'nvme_xdev_ext_class_bind')
            self.assertIn('xdev_ext_storfam_bind(st, u, &nvme_xdev_ext_member_ops)', bind)
            common_bind = body(common, 'xdev_ext_storfam_bind')
            self.assertIn('ss->dev = dev;', common_bind)
            self.assertIn('ss->member = member;', common_bind)
            table = re.search(r'^static const struct xdev_ext_stor_dev_ops '
                              r'nvme_xdev_ext_member_ops = \{.*?^\};', self.text, re.M | re.S)
            self.assertIsNotNone(table, 'native callback table must own the common submit boundaries')
            self.assertIn('.post = nvme_xdev_ext_member_post,', table[0])
            self.assertIn('.queue = nvme_xdev_ext_member_queue,', table[0])
            self.assertIn('return p->ns->queue;', body(self.text, 'nvme_xdev_ext_member_queue'))
            alloc = submit.index('blk_mq_alloc_request(ss->dev->queue(ss->member),')
            opf = submit.index('xdev_ext_stor_block_poll_opf(ss->st->poll,')
            check = submit.index('xdev_ext_stor_block_poll_check(ss->st->poll, req)')
            get = submit.index('io = peer ? xdev_ext_storfam_peer_get(ss, sb)')
            mapping = submit.index('xdev_ext_storfam_peer_map(ss, b, io, sb->posting.byte_length)')
            call = submit.index('ss->dev->post(ss->member, req, io, b, &sb->command, peer);')
            self.assertTrue(alloc < opf < check < get < mapping < call)
            self.assertIn('if (ret)\n\t\tgoto free_request;', submit[check:get])
            self.assertIn('blk_mq_free_request(req);', submit[submit.index('free_request:'):])
            self.assertEqual(submit.count('ss->dev->post('), 1)
            peer_done = submit.index('if (peer) {\n\t\tio->done.b = b;')
            ticket = submit.index('io->done.ticket = xdev_ext_mech_batch_ticket(b);', peer_done)
            self.assertTrue(mapping < peer_done < ticket < call)
            peer_branch = post[post.index('if (peer) {'):post.index('} else {')]
            self.assertIn('req->end_io = nvme_xdev_ext_peer_end_io;', peer_branch)
            context = post.index('req->end_io_data = &io->done;')
            arm = post.index('xdev_ext_stor_block_poll_arm(p->family.st->poll, req, &io->done);')
            execute = post.index('blk_execute_rq_nowait(req, false);')
            self.assertTrue(context < arm < execute)
            return
        peer = body(self.text, 'nvme_xdev_ext_peer_submit')
        queue = 'p->family.dev->queue(p->family.member)' if 'struct xdev_ext_stor_stage family;' in self.text else 'ns->queue'
        alloc = peer.index('blk_mq_alloc_request(' + queue + ',\n\t\t\t\t   xdev_ext_stor_block_poll_opf(st->poll,')
        check = peer.index('xdev_ext_stor_block_poll_check(st->poll, req)')
        arm = peer.index('xdev_ext_stor_block_poll_arm(st->poll, req, &slot->done);')
        execute = peer.index('blk_execute_rq_nowait(req, false);')
        self.assertTrue(alloc < check < arm < execute)
        self.assertLess(peer.index('req->end_io_data = &slot->done;'), arm)

    def test_class_registers_poll(self):
        table = self.text[self.text.index('static const struct xdev_ext_mech_class_ops nvme_xdev_ext_mech_class'):]
        self.assertIn('.poll = nvme_xdev_ext_class_poll,', table[:table.index('};')])


class BlockHelper(unittest.TestCase):
    def test_helper_polls_only_a_current_poll_queue_under_a_queue_reference(self):
        helper = function(source(BLK), 'blk_mq_poll_hw_queue')
        self.assertIn('percpu_ref_tryget(&q->q_usage_counter)', helper)
        self.assertIn('xa_load(&q->hctx_table, queue_num)', helper)
        self.assertRegex(helper, r'hctx->type == HCTX_TYPE_POLL')
        self.assertIn('blk_mq_can_poll(q)', helper)
        self.assertIn('q->mq_ops->poll(hctx, iob)', helper)
        self.assertLess(helper.index('percpu_ref_tryget'), helper.index('xa_load'))
        self.assertLess(helper.index('q->mq_ops->poll(hctx, iob)'), helper.index('blk_queue_exit(q);'))
        self.assertIn('EXPORT_SYMBOL_GPL(blk_mq_poll_hw_queue);', source(BLK))
        self.assertRegex(source(BLK_H), r'int blk_mq_poll_hw_queue\(struct request_queue \*q, unsigned int queue_num,')


if __name__ == '__main__':
    unittest.main(verbosity=2)
