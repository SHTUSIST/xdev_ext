#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Core stage polling: CREATE binding, the worker's poll pass and teardown order.

xdev_ext_mech_session_bind(), xdev_ext_mech_poll_kick() and
xdev_ext_mech_poll_work() are compiled verbatim from io_uring/xdev_ext_mech.c
with the pure rules of io_uring/xdev_ext_mech_poll.h; the fixture supplies
only kernel types and recorders. Structural checks cover the places a
behavioural fixture cannot reach without the whole core: every worker
destruction cancels poll_work after worker_gone, STOP leaves it queued, and an
accepted submit to a polled stage starts it.
"""
import re
import unittest

from poll_extract import body, compile_and_run, fields, function, source

CORE = 'io_uring/xdev_ext_mech.c'

FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_poll.h"

typedef uint32_t u32; typedef uint64_t u64;
#define U32_MAX UINT32_MAX
#define READ_ONCE(v) (v)
#define smp_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
typedef struct { int held; } spinlock_t;
static int lock_depth;
#define spin_lock_irqsave(l, f) do { (void)(f); (l)->held++; lock_depth++; } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(f); (l)->held--; lock_depth--; } while (0)
struct kthread_work { int queued; };
struct kthread_delayed_work { struct kthread_work work; long delay; };
struct kthread_worker { int alive; };
struct file { int fd; };
struct eventfd_ctx { int unused; };
struct module;
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops {
	u32 class_id;
	int (*bind)(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u);
	int (*unbind_checked)(struct xdev_ext_mech_stage *st);
	int (*poll)(struct xdev_ext_mech_stage *st);
};
struct xdev_ext_mech_stage {
	struct xdev_ext_mech_session *s;
	const struct xdev_ext_mech_class_ops *cls;
	struct file *file;
	void *priv;
	u64 arg0, arg1;
	u32 class_id, direction, flags, index;
	bool poll, create_reporting;
 u32 create_phase;
};
struct sess { u32 state, inflight; };
struct xdev_ext_mech_session {
	spinlock_t lock;
	struct sess ss;
	bool worker_gone, poll_rx, create_reporting, create_pending_publish;
	u64 id;
	u32 nr_stages, nr_bound, create_phase, create_failed_stage;
	struct xdev_ext_mech_stage st[XDEV_EXT_MECH_MAX_STAGES];
	const void *ops[XDEV_EXT_MECH_CLASS_MAX];
	bool pinned[XDEV_EXT_MECH_CLASS_MAX];
	struct module *c_owner[XDEV_EXT_MECH_CLASS_MAX];
	struct eventfd_ctx *evfd;
	struct kthread_worker *worker;
	struct kthread_delayed_work poll_work;
};

/* Recorders. */
static unsigned queues, queues_unlocked, poll_calls[4], bind_calls[4];
static long last_delay = -100;
static u32 bind_flags[4];
static int bind_saw_poll[4];
static void kthread_queue_delayed_work(struct kthread_worker *w, struct kthread_delayed_work *d,
				       unsigned long delay)
{ (void)w; queues++; queues_unlocked += !lock_depth; d->delay = (long)delay; last_delay = (long)delay; }
static int polling_class_poll(struct xdev_ext_mech_stage *st) { poll_calls[st->index]++; return 1; }
static int record_bind(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u)
{ bind_calls[st->index]++; bind_flags[st->index] = u->flags; bind_saw_poll[st->index] = st->poll; return 0; }
static const struct xdev_ext_mech_class_ops polling_nvme = { .class_id = XDEV_EXT_MECH_CLASS_NVME,
	.bind = record_bind, .poll = polling_class_poll };
static const struct xdev_ext_mech_class_ops polling_afxdp = { .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
	.bind = record_bind, .poll = polling_class_poll };
static const struct xdev_ext_mech_class_ops plain_ce = { .class_id = XDEV_EXT_MECH_CLASS_CE,
	.bind = record_bind };
static const struct xdev_ext_mech_class_ops *xdev_ext_mech_class_get(u32 id)
{ return id == XDEV_EXT_MECH_CLASS_NVME ? &polling_nvme : id == XDEV_EXT_MECH_CLASS_AFXDP ?
	&polling_afxdp : id == XDEV_EXT_MECH_CLASS_CE ? &plain_ce : NULL; }
static int ops_token;
static const void *current_ops[XDEV_EXT_MECH_CLASS_MAX];
static const void *xdev_ext_mech_ops_get(u32 id, bool *pinned, struct module **owner)
{ *pinned = false; *owner = NULL; current_ops[id] = &ops_token; return &ops_token; }
/* Registry boundary records the currently published class table. Admission
 * itself remains the complete production function, including report delivery. */
static bool xdev_ext_mech_ops_current(u32 id, const void *ops, bool pinned)
{ (void)pinned; return id < XDEV_EXT_MECH_CLASS_MAX && current_ops[id] == ops; }
static int xdev_ext_mech_session_buffers(struct xdev_ext_mech_session *s) { (void)s; return 0; }
static struct eventfd_ctx *eventfd_ctx_fdget(int fd) { (void)fd; return NULL; }
static struct kthread_worker worker_object;
#define kthread_run_worker(flags, fmt, ...) (&worker_object)
static int xdev_ext_mech_pool_bind(struct xdev_ext_mech_session *s, const struct xdev_ext_mech_create *c)
{ (void)s; (void)c; return 0; }
static struct file files[8];
static struct file *fget(int fd) { return fd >= 0 && fd < 8 ? &files[fd] : NULL; }
static int xdev_ext_mech_prepare(struct xdev_ext_mech_session *s, struct xdev_ext_mech_stage *st)
{ (void)s; (void)st; return 0; }

/* F3 initializes capability defaults in this wrapper. This fixture keeps
 * testing POLL/FANOUT flag stripping; capability behavior has its own test. */
static int xdev_ext_mech_class_bind(struct xdev_ext_mech_stage *st,
                                    const struct xdev_ext_mech_stage_uapi *u, __u32 pool_kind)
{
 (void)pool_kind;
 return st->cls->bind(st, u);
}

/* PRODUCTION */

static struct xdev_ext_mech_create chain(u32 c0, u32 d0, u32 f0, u32 c1, u32 d1, u32 f1)
{
	struct xdev_ext_mech_create c = { .nr_stages = 2, .eventfd = -1 };
	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = c0, .direction = d0, .fd = 1, .flags = f0 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = c1, .direction = d1, .fd = 2, .flags = f1,
		.arg0 = 7, .arg1 = 9 };
	return c;
}

static int bind_case(const char *mode)
{
	static struct xdev_ext_mech_session s;
	struct xdev_ext_mech_create c;
	const u32 P = XDEV_EXT_MECH_STAGE_F_POLL, R = XDEV_EXT_AFXDP_F_RELIABLE;
	int ret;

	memset(&s, 0, sizeof(s));
	if (!strcmp(mode, "nic-nvme"))
		c = chain(XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_DIR_FROM_DEVICE, P | R,
			  XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_TO_DEVICE, P);
	else if (!strcmp(mode, "nvme-only"))
		c = chain(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE, P,
			  XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_TO_DEVICE, 0);
	else if (!strcmp(mode, "unpollable"))
		c = chain(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE, P,
			  XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE, P);
	else if (!strcmp(mode, "fanout")) {
		/* xdev_ext_mech_ctl fanout: NVMe READ -> {NVMe WRITE, AF_XDP TX}. */
		c = chain(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0,
			  XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_TO_DEVICE, 0);
		c.nr_stages = 3;
		c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 3,
			.flags = XDEV_EXT_MECH_STAGE_F_FANOUT | P };
	} else
		c = chain(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0,
			  XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE, 0);
	s.nr_stages = c.nr_stages;
	ret = xdev_ext_mech_session_bind(&s, &c);
	printf("ret=%d poll0=%d poll1=%d flags0=%u flags1=%u bind0=%u bind1=%u bflags0=%u bflags1=%u "
	       "bpoll0=%d bpoll1=%d poll_rx=%d nr_bound=%u caller0=%u caller1=%u\n",
	       ret, s.st[0].poll, s.st[1].poll, s.st[0].flags, s.st[1].flags, bind_calls[0], bind_calls[1],
	       bind_flags[0], bind_flags[1], bind_saw_poll[0], bind_saw_poll[1], s.poll_rx, s.nr_bound,
	       c.st[0].flags, c.st[1].flags);
	if (c.nr_stages == 3)	/* last line: the fields of the third stage */
		printf("ret=%d nr_bound=%u poll2=%d flags2=%u bind2=%u bflags2=%u caller2=%u\n", ret,
		       s.nr_bound, s.st[2].poll, s.st[2].flags, bind_calls[2], bind_flags[2], c.st[2].flags);
	return 0;
}

static int pass_case(const char *mode)
{
	static struct xdev_ext_mech_session s;
	memset(&s, 0, sizeof(s));
	s.worker = &worker_object;
	s.nr_stages = 3;
	s.st[0] = (struct xdev_ext_mech_stage){ .s = &s, .cls = &polling_nvme, .index = 0, .poll = true };
	/* A class that can poll, on a stage that did not ask for it. */
	s.st[1] = (struct xdev_ext_mech_stage){ .s = &s, .cls = &polling_nvme, .index = 1, .poll = false };
	s.st[2] = (struct xdev_ext_mech_stage){ .s = &s, .cls = &polling_afxdp, .index = 2, .poll = true };
	s.ss.state = XDEV_EXT_MECH_SESSION_ACTIVE;
	s.ss.inflight = 2;
	if (!strcmp(mode, "zombie"))
		s.ss.state = XDEV_EXT_MECH_SESSION_ZOMBIE;
	if (!strcmp(mode, "stopping"))
		s.ss.state = XDEV_EXT_MECH_SESSION_STOPPING;
	if (!strcmp(mode, "idle"))
		s.ss.inflight = 0;
	if (!strcmp(mode, "rx")) {
		s.ss.inflight = 0;
		s.poll_rx = true;
	}
	if (!strcmp(mode, "gone"))
		s.worker_gone = true;
	if (!strcmp(mode, "kick")) {
		xdev_ext_mech_poll_kick(&s);
		s.worker_gone = true;
		xdev_ext_mech_poll_kick(&s);
	} else {
		xdev_ext_mech_poll_work(&s.poll_work.work);
	}
	printf("p0=%u p1=%u p2=%u queues=%u unlocked=%u delay=%ld lock=%d\n", poll_calls[0], poll_calls[1],
	       poll_calls[2], queues, queues_unlocked, last_delay, lock_depth);
	return 0;
}

static int admission_case(void)
{
 struct xdev_ext_mech_session s = {0};
 int active, pending, published, stale, stopped;
 s.ss.state = XDEV_EXT_MECH_SESSION_ACTIVE;
 s.ops[XDEV_EXT_MECH_CLASS_NVME] = &ops_token;
 current_ops[XDEV_EXT_MECH_CLASS_NVME] = &ops_token;
 active = xdev_ext_mech_session_admits(&s);
 s.create_pending_publish = true;
 pending = xdev_ext_mech_session_admits(&s);
 s.create_pending_publish = false;
 published = xdev_ext_mech_session_admits(&s);
 current_ops[XDEV_EXT_MECH_CLASS_NVME] = NULL;
 stale = xdev_ext_mech_session_admits(&s);
 current_ops[XDEV_EXT_MECH_CLASS_NVME] = &ops_token;
 s.ss.state = XDEV_EXT_MECH_SESSION_STOPPING;
 stopped = xdev_ext_mech_session_admits(&s);
 printf("active=%d pending=%d published=%d stale=%d stopped=%d\n",
        active, pending, published, stale, stopped);
 return 0;
}

int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	if (!strcmp(argv[1], "admission"))
  return admission_case();
 return !strcmp(argv[1], "bind") ? bind_case(argv[2]) : pass_case(argv[2]);
}
'''


def build_fixture():
    text = source(CORE)
    production = '\n'.join(function(text, n) for n in (
        'xdev_ext_mech_session_admits', 'xdev_ext_mech_rx_first', 'xdev_ext_mech_session_bind',
        'xdev_ext_mech_poll_kick', 'xdev_ext_mech_poll_work'))
    return FIXTURE.replace('/* PRODUCTION */', production)


class CorePoll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build_fixture()

    def run_case(self, *args):
        code, out = compile_and_run(self.fixture, args)
        self.assertEqual(code, 0, out)
        return fields(out)

    def test_pending_publication_cannot_admit_receive_polling(self):
        r = self.run_case('admission', 'publication')
        self.assertEqual((r['active'], r['pending'], r['published'], r['stale'], r['stopped']),
                         (1, 0, 1, 0, 0), r)

    def test_bind_strips_poll_before_class_bind(self):
        r = self.run_case('bind', 'nic-nvme')
        self.assertEqual(r['ret'], 0, r)
        self.assertEqual((r['poll0'], r['poll1']), (1, 1), r)
        rel = 1  # XDEV_EXT_AFXDP_F_RELIABLE
        self.assertEqual((r['bflags0'], r['bflags1']), (rel, 0), r)
        self.assertEqual((r['flags0'], r['flags1']), (rel, 0), r)
        self.assertEqual((r['bpoll0'], r['bpoll1']), (1, 1), 'st->poll is visible to ->bind')
        self.assertEqual(r['poll_rx'], 1, 'polled AF_XDP stage 0 is a receive source')
        self.assertEqual(r['caller0'], (1 << 29) | rel, 'caller CREATE input not modified')

    def test_bind_strips_fanout_before_class_bind(self):
        # FANOUT is a generic stage bit like POLL (uapi xdev_ext_mech.h): the
        # core keeps it in s->plan, and no class ->bind accepts it as a class
        # flag (AF_XDP and NVMe refuse unknown flags with -EINVAL).
        r = self.run_case('bind', 'fanout')
        self.assertEqual((r['ret'], r['nr_bound'], r['bind2']), (0, 3, 1), r)
        self.assertEqual(r['bflags2'], 0, '->bind of the fanout member sees no generic bit')
        self.assertEqual(r['flags2'], 0, 'st->flags holds class flags only')
        self.assertEqual(r['poll2'], 1, 'POLL on the fanout member is still honoured')
        self.assertEqual(r['caller2'], (1 << 31) | (1 << 29), 'caller CREATE input not modified')

    def test_bind_only_flagged_stage_polls(self):
        r = self.run_case('bind', 'nvme-only')
        self.assertEqual((r['ret'], r['poll0'], r['poll1'], r['poll_rx']), (0, 1, 0, 0), r)
        self.assertEqual((r['bind0'], r['bind1']), (1, 1), r)

    def test_bind_refuses_class_without_poll(self):
        r = self.run_case('bind', 'unpollable')
        self.assertEqual(r['ret'], -95, r)  # -EOPNOTSUPP
        self.assertEqual(r['bind0'] + r['bind1'], 0, 'no ->bind runs before the refusal')

    def test_bind_without_poll_unchanged(self):
        r = self.run_case('bind', 'plain')
        self.assertEqual((r['ret'], r['poll0'], r['poll1'], r['poll_rx']), (0, 0, 0, 0), r)
        self.assertEqual((r['bind0'], r['bind1'], r['nr_bound']), (1, 1, 2), r)

    def test_pass_polls_only_polled_stages_and_rearms_immediately(self):
        r = self.run_case('pass', 'active')
        self.assertEqual((r['p0'], r['p1'], r['p2']), (1, 0, 1), r)
        self.assertEqual((r['queues'], r['unlocked'], r['delay'], r['lock']), (1, 0, 0, 0), r)

    def test_pass_keeps_polling_while_stopping(self):
        r = self.run_case('pass', 'stopping')
        self.assertEqual((r['queues'], r['delay']), (1, 0), r)

    def test_pass_backs_off_when_zombie(self):
        r = self.run_case('pass', 'zombie')
        self.assertEqual((r['queues'], r['delay']), (1, 1), r)

    def test_pass_stops_without_live_batches(self):
        r = self.run_case('pass', 'idle')
        self.assertEqual((r['p0'], r['p2'], r['queues']), (1, 1, 0), r)

    def test_receive_source_keeps_polling(self):
        r = self.run_case('pass', 'rx')
        self.assertEqual((r['queues'], r['delay']), (1, 0), r)

    def test_no_rearm_after_worker_gone(self):
        r = self.run_case('pass', 'gone')
        self.assertEqual(r['queues'], 0, r)

    def test_kick_under_lock_and_never_after_worker_gone(self):
        r = self.run_case('pass', 'kick')
        self.assertEqual((r['queues'], r['unlocked'], r['delay'], r['p0']), (1, 0, 0, 0), r)


class CorePollStructure(unittest.TestCase):
    """Places the behavioural fixture cannot reach without the whole core."""

    @classmethod
    def setUpClass(cls):
        cls.text = source(CORE)

    def test_session_init_prepares_poll_work(self):
        self.assertRegex(body(self.text, 'xdev_ext_mech_session_init'),
                         r'kthread_init_delayed_work\(&s->poll_work, xdev_ext_mech_poll_work\);')

    def test_every_worker_destruction_cancels_poll_work_first(self):
        functions = re.findall(r'^\w[^;{}()]*?\b(xdev_ext_mech_\w+)\([^;{}]*\)\s*\{', self.text, re.M)
        seen = 0
        for name in functions:
            text = body(self.text, name)
            for match in re.finditer(r'kthread_destroy_worker\(s->worker\);', text):
                seen += 1
                before = text[:match.start()]
                cancel = before.rfind('kthread_cancel_delayed_work_sync(&s->poll_work);')
                self.assertGreaterEqual(cancel, 0, name + ' destroys the worker without cancelling poll_work')
                self.assertGreater(cancel, before.rfind('kthread_cancel_delayed_work_sync(&s->progress_work);') - 400,
                                   name + ': poll_work cancel is not part of the teardown sequence')
        self.assertGreaterEqual(seen, 4, 'expected every teardown path')

    def test_stop_leaves_poll_work_queued(self):
        self.assertNotIn('poll_work', body(self.text, 'xdev_ext_mech_stop_work'))
        self.assertNotIn('poll_work', body(self.text, 'xdev_ext_mech_session_stop'))

    def test_accepted_submit_to_polled_stage_starts_polling(self):
        run = body(self.text, 'xdev_ext_mech_batch_run')
        accepted = run[run.index('err = xdev_ext_mech_submit(s, st, b);'):]
        branch = accepted[accepted.index('} else'):]
        self.assertRegex(branch, r'if \(st->poll\)\s*xdev_ext_mech_poll_kick\(s\);')
        self.assertNotIn('poll_kick', accepted[:accepted.index('} else')],
                         'a refused submit must not start polling')

    def test_create_starts_receive_source_after_activation(self):
        legacy = body(self.text, 'xdev_ext_mech_create')
        self.assertIn('return xdev_ext_mech_create_common(ctx, &c, uarg, NULL, NULL);', legacy)
        create = body(self.text, 'xdev_ext_mech_create_common')
        # Preserve the original activation-before-receive-poll contract on the
        # actual shared implementation reached by both CREATE entrypoints.
        self.assertRegex(create, r'if \(s->poll_rx\)\s*xdev_ext_mech_poll_kick\(s\);')
        self.assertLess(create.index('xdev_ext_mech_sess_activate'), create.index('xdev_ext_mech_poll_kick'))
        self.assertLess(create.index('s->create_pending_publish = !!r;'),
                        create.index('xdev_ext_mech_session_bind(s, c);'))
        publish = create.index('smp_store_release(&s->create_pending_publish, false);')
        self.assertLess(create.index('copy_to_user(uarg, envelope, sizeof(*envelope))'), publish)
        self.assertLess(create.index('list_add_tail(&s->live_node, &xdev_ext_mech_live);'), publish)
        guard = create.index('if (!xdev_ext_mech_session_admits(s))')
        self.assertLess(publish, guard)
        self.assertLess(guard, create.index('xdev_ext_mech_poll_kick'))
        self.assertRegex(create,
                         r'if \(!xdev_ext_mech_session_admits\(s\)\)\s*'
                         r'xdev_ext_mech_session_stop\(s, -ECANCELED\);\s*'
                         r'else if \(s->poll_rx\)\s*xdev_ext_mech_poll_kick\(s\);')


if __name__ == '__main__':
    unittest.main(verbosity=2)
