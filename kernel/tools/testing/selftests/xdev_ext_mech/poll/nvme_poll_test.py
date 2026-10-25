#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NVMe class polling: bind capability, REQ_POLLED submit, end_io and the pass.

The production functions of drivers/nvme/host/xdev_ext_mech_nvme.c run
verbatim against a fixture that models only the block-layer objects they
touch: request allocation (which hardware queue type a request landed on),
blk_rq_is_poll(), execute, and blk_mq_poll_hw_queue() as a recorder. The
model does not reproduce nvme-pci queues, DMA or timing.
"""
import re
import unittest

from poll_extract import body, compile_and_run, fields, function, source

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
#include "include/uapi/linux/xdev_ext_mech.h"

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
#define NVME_CMD_SGL_METABUF (1U << 6)
#define GFP_KERNEL 0
#define NVME_XDEV_EXT_SQE_SIZE 64
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
struct nvme_request { unsigned int flags; u16 status; union { u64 u64; } result; struct nvme_command *cmd; };
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
struct nvme_ns { struct request_queue *queue; };

/* PRODUCTION_STRUCTS */

struct nvme_xdev_ext_mech_stage {
	struct nvme_ns *ns;
	int dead;
	struct { u32 nsid; } identity;
	struct nvme_xdev_ext_mech_slot *slots, *free;
	u32 nr_slots;
	struct nvme_xdev_ext_peer_res *peer;
};
struct nvme_xdev_ext_mech_batch {
	u8 sqe[NVME_XDEV_EXT_SQE_SIZE];
	u64 batch_id;
	bool validated;
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
	struct nvme_xdev_ext_mech_completion *done = req->end_io_data;
	(void)at_head;
	executes++;
	live_at_execute = done->poll_live;
	queue_at_execute = done->poll_queue;
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
static int nvme_xdev_ext_class_recheck(struct xdev_ext_mech_stage *st) { (void)st; return 0; }
static u32 nvme_xdev_ext_sqe_dw(const u8 *sqe, unsigned int dw) { (void)sqe; (void)dw; return 0; }
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
static void nvme_xdev_ext_mech_cqe(int status, u64 result, struct xdev_ext_nvme_mech_cqe *cqe)
{ cqe->err = status; cqe->result = result; }
static enum rq_end_io_ret nvme_xdev_ext_peer_end_io(struct request *req, blk_status_t err);

/* PRODUCTION */

static void report(int rc)
{
	printf("rc=%d polled_opf=%d allocs=%d frees=%d maps=%d executes=%d slot_gets=%d slot_puts=%d "
	       "live=%d queue=%u publishes=%d\n", rc, !!(alloc_opf & REQ_POLLED), allocs, frees, maps,
	       executes, slot_gets, slot_puts, live_at_execute, queue_at_execute, publishes);
}

static int submit_case(bool poll)
{
	struct nvme_ns ns = { 0 };
	struct nvme_xdev_ext_mech_stage p = { .ns = &ns };
	struct xdev_ext_mech_session s = { .pool_kind = 2 };
	struct xdev_ext_mech_stage st = { .s = &s, .priv = &p, .poll = poll };
	static struct xdev_ext_mech_batch b;

	b.priv.validated = true;
	b.priv.batch_id = 7;
	b.ticket = 11;
	report(nvme_xdev_ext_class_submit(&st, &b));
	return 0;
}

static int end_io_case(bool peer)
{
	static struct xdev_ext_mech_batch b;
	struct nvme_xdev_ext_mech_completion done = { .b = &b, .ticket = 11, .poll_live = true, .poll_queue = 5 };
	struct request req = { .end_io_data = &done };

	b.ticket = 11;
	if (peer)
		nvme_xdev_ext_peer_end_io(&req, 0);
	else
		nvme_xdev_ext_class_end_io(&req, 0);
	printf("live=%d publishes=%d\n", done.poll_live, publishes);
	return 0;
}

static int pass_case(bool peer)
{
	struct request_queue q;
	struct nvme_ns ns = { .queue = &q };
	struct nvme_xdev_ext_mech_slot host[4] = { 0 };
	struct nvme_xdev_ext_peer_slot peers[3];
	struct nvme_xdev_ext_peer_res res = { 0 };
	struct nvme_xdev_ext_mech_stage p = { .ns = &ns };
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
	if (!strcmp(mode, "poll") || !strcmp(mode, "lost")) return submit_case(true);
	if (!strcmp(mode, "end_io")) return end_io_case(false);
	if (!strcmp(mode, "peer_end_io")) return end_io_case(true);
	if (!strcmp(mode, "pass")) return pass_case(false);
	if (!strcmp(mode, "peer_pass")) return pass_case(true);
	if (!strcmp(mode, "capable")) return capable_case();
	return 2;
}
'''

PRODUCTION = ('nvme_xdev_ext_poll_capable', 'nvme_xdev_ext_poll_opf', 'nvme_xdev_ext_poll_check',
              'nvme_xdev_ext_poll_arm', 'nvme_xdev_ext_class_end_io', 'nvme_xdev_ext_peer_end_io',
              'nvme_xdev_ext_class_submit', 'nvme_xdev_ext_class_poll')


def build_fixture():
    text = source(NVME)
    structs = '\n'.join(structure(text, n) for n in (
        'nvme_xdev_ext_mech_completion', 'nvme_xdev_ext_mech_slot',
        'nvme_xdev_ext_peer_slot', 'nvme_xdev_ext_peer_res'))
    structs = structs.replace('struct device *dma_dev;', 'void *dma_dev;')
    production = '\n'.join(function(text, n) for n in PRODUCTION)
    return FIXTURE.replace('/* PRODUCTION_STRUCTS */', structs).replace('/* PRODUCTION */', production)


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

    def test_peer_end_io_retires_the_poll_record(self):
        r = self.run_case('peer_end_io')
        self.assertEqual((r['live'], r['publishes']), (0, 1), r)

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
        bind = body(self.text, 'nvme_xdev_ext_class_bind')
        check = bind.index('if (st->poll && !nvme_xdev_ext_poll_capable(ns->queue))')
        self.assertLess(check, bind.index('kzalloc('))
        self.assertIn('return -EOPNOTSUPP;', bind[check:check + 120])

    def test_peer_submit_uses_the_same_poll_steps_in_order(self):
        peer = body(self.text, 'nvme_xdev_ext_peer_submit')
        alloc = peer.index('blk_mq_alloc_request(ns->queue, nvme_xdev_ext_poll_opf(st,')
        check = peer.index('nvme_xdev_ext_poll_check(st, req)')
        arm = peer.index('nvme_xdev_ext_poll_arm(st, req, &slot->done);')
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
