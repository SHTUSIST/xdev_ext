#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NVMe uring_cmd stage lookup visits only the issuing ring's sessions.

xdev_ext_mech_stage_get_cmd() runs for every F_XDEV_EXT_BUILD command, possibly
from io-wq without uring_lock.  It must not take a lock shared by every ring
nor walk sessions of other rings, and must keep its admission semantics:
an admitted stage takes a batch and a cmd reference; a stopping session
answers -ESHUTDOWN; no matching stage answers -EOPNOTSUPP.

The production get and put bodies are compiled unchanged against list,
lock and RCU shims that count what they touch.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def function(text, name):
    match = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}', text, re.M | re.S)
    if not match:
        raise RuntimeError('missing production function: ' + name)
    return match[0]


FIXTURE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_core.h"
typedef __u32 u32;
typedef __u64 u64;
#define EXPORT_SYMBOL_GPL(x)
#define WARN_ON_ONCE(x) (!!(x))
#define READ_ONCE(x) (x)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
struct list_head { struct list_head *next, *prev; };
static unsigned global_locks, visited, rcu_depth, max_rcu_depth, session_locks;
static int global_lock_word;
#define xdev_ext_mech_all_lock global_lock_word
static void spin_lock(int *l) { if (l == &global_lock_word) global_locks++; }
static void spin_unlock(int *l) { (void)l; }
#define spin_lock_irqsave(l,f) do { (void)(l); (f) = 0; session_locks++; } while (0)
#define spin_unlock_irqrestore(l,f) do { (void)(l); (void)(f); } while (0)
static void rcu_read_lock(void) { if (++rcu_depth > max_rcu_depth) max_rcu_depth = rcu_depth; }
static void rcu_read_unlock(void) { assert(rcu_depth); rcu_depth--; }
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) \
 for ((p) = list_entry((h)->next, typeof(*(p)), m); &(p)->m != (h); \
      (p) = list_entry((p)->m.next, typeof(*(p)), m), visited++)
#define list_for_each_entry_rcu(p,h,m) \
 for (assert(rcu_depth), (p) = list_entry((h)->next, typeof(*(p)), m); &(p)->m != (h); \
      (p) = list_entry((p)->m.next, typeof(*(p)), m), visited++)
static void list_init(struct list_head *h) { h->next = h->prev = h; }
static void list_add(struct list_head *n, struct list_head *h) {
 n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n;
}
struct file { int unused; };
struct io_ring_ctx { struct list_head xdev_ext_mech_sessions; };
struct io_uring_cmd { struct file *file; struct io_ring_ctx *ctx; };
static void *io_uring_cmd_ctx_handle(struct io_uring_cmd *c) { return c->ctx; }
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; u32 class_id; struct file *file; };
struct xdev_ext_mech_session {
 struct list_head ring_node, all_node; struct io_ring_ctx *ctx; int lock;
 struct xdev_ext_mech_sess ss; u32 cmd_refs, nr_stages, reaped;
 struct xdev_ext_mech_stage st[XDEV_EXT_MECH_MAX_STAGES];
 int reap_work;
};
static struct list_head xdev_ext_mech_all;
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s) { return xdev_ext_mech_sess_admits(&s->ss); }
static bool xdev_ext_mech_leave_locked(struct xdev_ext_mech_session *s, bool seq) {
 return xdev_ext_mech_sess_batch_end(&s->ss, seq);
}
static int system_unbound_wq;
static void queue_work(int q, int *w) { (void)q; container_of(w, struct xdev_ext_mech_session, reap_work)->reaped++; }
/* PRODUCTION */
#define OTHERS 1000
static struct io_ring_ctx mine, theirs;
static struct xdev_ext_mech_session other[OTHERS], s;
static struct file nvme, other_file;
static int failures;
#define EXPECT(c,msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } } while (0)
static void join(struct xdev_ext_mech_session *x, struct io_ring_ctx *ctx, struct file *f) {
 memset(x, 0, sizeof(*x)); x->ctx = ctx; x->nr_stages = 2; xdev_ext_mech_sess_init(&x->ss);
 x->st[0] = (struct xdev_ext_mech_stage){ .s = x, .class_id = XDEV_EXT_MECH_CLASS_AFXDP, .file = f };
 x->st[1] = (struct xdev_ext_mech_stage){ .s = x, .class_id = XDEV_EXT_MECH_CLASS_NVME, .file = f };
 list_add(&x->ring_node, &ctx->xdev_ext_mech_sessions); list_add(&x->all_node, &xdev_ext_mech_all);
}
int main(void) {
 list_init(&xdev_ext_mech_all); list_init(&mine.xdev_ext_mech_sessions); list_init(&theirs.xdev_ext_mech_sessions);
 for (unsigned i = 0; i < OTHERS; i++) join(&other[i], &theirs, &nvme);
 join(&s, &mine, &nvme);
 struct io_uring_cmd cmd = { .file = &nvme, .ctx = &mine };
 global_locks = visited = 0;
 struct xdev_ext_mech_stage *st = xdev_ext_mech_stage_get_cmd(&cmd, XDEV_EXT_MECH_CLASS_NVME);
 EXPECT(st == &s.st[1], "issuing ring's NVMe stage not found");
 EXPECT(global_locks == 0, "per-command lookup takes the all-rings lock");
 EXPECT(visited <= 1, "per-command lookup walks sessions of other rings");
 EXPECT(!rcu_depth, "lookup leaves an RCU read section open");
 EXPECT(s.cmd_refs == 1 && s.ss.inflight == 1, "admitted stage took no batch and cmd reference");
 xdev_ext_mech_stage_put(st);
 EXPECT(!s.cmd_refs && !s.ss.inflight && !s.reaped, "put did not return the references");
 cmd.file = &other_file;
 st = xdev_ext_mech_stage_get_cmd(&cmd, XDEV_EXT_MECH_CLASS_NVME);
 EXPECT(IS_ERR(st) && PTR_ERR(st) == -EOPNOTSUPP, "foreign file matched a stage");
 cmd.file = &nvme;
 xdev_ext_mech_sess_stop(&s.ss);
 st = xdev_ext_mech_stage_get_cmd(&cmd, XDEV_EXT_MECH_CLASS_NVME);
 EXPECT(IS_ERR(st) && PTR_ERR(st) == -ESHUTDOWN, "stopping session admitted a command");
 EXPECT(!s.cmd_refs && !s.ss.inflight, "refused command took a reference");
 cmd.ctx = &theirs;
 st = xdev_ext_mech_stage_get_cmd(&cmd, XDEV_EXT_MECH_CLASS_NVME);
 EXPECT(!IS_ERR(st) && st->s->ctx == &theirs, "other ring cannot find its own session");
 if (!failures) puts("PASS stage lookup is per ring");
 return failures != 0;
}
'''


class StageGetCmd(unittest.TestCase):
    def test_lookup_is_per_ring_without_global_lock(self):
        core = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
        code = FIXTURE.replace('/* PRODUCTION */', function(core, 'xdev_ext_mech_stage_get_cmd') + '\n' +
                               function(core, 'xdev_ext_mech_stage_put'))
        with tempfile.TemporaryDirectory(prefix='xdev_ext-get-cmd-') as tmp:
            source = Path(tmp) / 'get.c'
            source.write_text(code)
            binary = Path(tmp) / 'get'
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-Wno-unused-function', '-fsanitize=undefined',
                                    '-fno-sanitize-recover=undefined', '-I' + str(ROOT), str(source),
                                    '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
