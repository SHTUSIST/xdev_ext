#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contracts of the AF_XDP mechanism class that a fake driver cannot
exercise: where the allocator splices the recycle llist, where the fill ring
refuses session frames, the XDP_SHARED_UMEM refusal and the pool admission."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : pos]
    raise AssertionError(f"unterminated function: {signature}")


def statements(body: str) -> list:
    """Top-level statements of a function body, declarations dropped."""
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith(("/*", "*", "//")):
            continue
        out.append(line)
    return out


DECL = re.compile(r"^(const\s+)?(struct\s+\w+|u\d+|u64|bool|int|void)\s+[\w\s,*=\[\]0-9]+;$")


class PoolProviderSourceTest(unittest.TestCase):
    def setUp(self):
        self.pool = read("net/xdp/xsk_buff_pool.c")
        self.xsk = read("net/xdp/xsk.c")
        self.mech = read("net/xdp/xsk_xdev_ext_mech.c")
        self.mech_h = read("net/xdp/xsk_xdev_ext_mech.h")

    def first_statement(self, signature: str) -> str:
        body = function_body(self.pool, signature)
        stmts = [s for s in statements(body) if not DECL.match(s)]
        return stmts[0]

    def test_allocator_entries_splice_the_recycle_llist_first(self):
        for sig in (
            "static struct xdp_buff *xp_alloc_locked(struct xsk_buff_pool *pool)",
            "static u32 xp_alloc_batch_locked(struct xsk_buff_pool *pool,",
            "static bool xp_can_alloc_locked(struct xsk_buff_pool *pool, u32 count)",
        ):
            with self.subTest(sig=sig):
                self.assertEqual(self.first_statement(sig),
                                 "xp_xdev_ext_mech_splice(pool);")
        # Nothing else moves recycled frames back to free_list.
        self.assertEqual(self.pool.count("xp_xdev_ext_mech_splice(pool);"), 3)
        splice = function_body(self.mech_h, "xp_xdev_ext_mech_splice(struct xsk_buff_pool *pool)")
        self.assertIn("llist_del_all(&pool->xdev_ext_mech_recycle)", splice)
        self.assertIn("list_add(&xskb->list_node, &pool->free_list)", splice)
        self.assertNotIn("xp_free(xskb)", splice) # no recursion into allocator lock

    def test_fill_ring_entries_refuse_session_frames(self):
        for sig in (
            "static struct xdp_buff_xsk *__xp_alloc(struct xsk_buff_pool *pool)",
            "static u32 xp_alloc_new_from_fq(struct xsk_buff_pool *pool,",
        ):
            with self.subTest(sig=sig):
                body = function_body(self.pool, sig)
                check = body.index("xp_xdev_ext_mech_fq_ok(pool, state, addr)")
                self.assertLess(body.index("xp_check_aligned(pool, &addr)"), check)
                self.assertLess(check, body.index("pool->fq->invalid_descs++"))
                self.assertLess(check, body.index("xp_get_xskb(pool, addr)"))
                self.assertIn("state = xp_xdev_ext_mech_state(pool)", body)
        self.assertEqual(self.pool.count("xp_xdev_ext_mech_fq_ok(pool, state, addr)"), 2)

    def test_shared_umem_bind_onto_a_session_socket_is_busy(self):
        body = function_body(self.xsk, "static int xsk_bind(struct socket *sock,")
        shared = body[body.index("if (flags & XDP_SHARED_UMEM) {"):
                      body.index("} else if (!xs->umem || !xsk_validate_queues(xs)) {")]
        begin = shared.index("err = xsk_xdev_ext_mech_share_begin(umem_xs);")
        self.assertLess(shared.index("if (!xsk_is_bound(umem_xs)) {"), begin)
        for share in ("xp_create_and_assign_umem(xs,", "xp_get_pool(umem_xs->pool);",
                      "xdp_get_umem(umem_xs->umem);"):
            self.assertLess(begin, shared.index(share))
        # Every exit after begin ends the share before dropping the socket.
        after = shared[begin:]
        self.assertEqual(after.count("xsk_xdev_ext_mech_share_end(umem_xs);"),
                         after.count("sockfd_put(sock);") - 1)
        self.assertLess(after.index("xdp_get_umem(umem_xs->umem);"),
                        after.rindex("xsk_xdev_ext_mech_share_end(umem_xs);"))
        begin_body = function_body(self.mech, "int xsk_xdev_ext_mech_share_begin(struct xdp_sock *umem_xs)")
        self.assertIn("mutex_lock_nested(&umem_xs->mutex, SINGLE_DEPTH_NESTING)", begin_body)
        self.assertIn("xsk_xdev_ext_mech_share_check(", begin_body)

    def test_pool_bind_admits_under_the_socket_mutex(self):
        body = function_body(self.mech, "int xsk_xdev_ext_mech_pool_bind(struct xdev_ext_mech_pool *pool,")
        lock = body.index("mutex_lock(&xs->mutex);")
        admit = body.index("xsk_xdev_ext_mech_pool_admit(&facts, l)")
        publish = body.index("smp_store_release(&xs->umem->xdev_ext_mech_state, state);")
        self.assertLess(lock, admit)
        self.assertLess(admit, publish)
        self.assertLess(publish, body.index("mutex_unlock(&xs->mutex);", publish))
        self.assertIn("kvzalloc(", body)  # zero words: every chunk starts USER
        facts = function_body(self.mech, "static void xsk_xdev_ext_mech_sock_facts(")
        for field in ("f->zero_copy = xs->zc;", "f->unaligned = xs->pool->unaligned;",
                      "refcount_read(&xs->pool->users)", "refcount_read(&xs->umem->users)",
                      "xskq_cons_present_entries(fq)"):
            self.assertIn(field, facts)

    def test_recycle_and_release_never_take_rx_lock(self):
        recycle = function_body(self.mech, "static void xsk_xdev_ext_mech_pool_recycle(")
        self.assertIn("llist_add(", recycle)
        for forbidden in ("spin_lock", "xp_free", "free_list", "mutex"):
            self.assertNotIn(forbidden, recycle)
        release = function_body(self.mech, "static void xsk_xdev_ext_mech_pool_release(")
        retract = release.index("WRITE_ONCE(xs->umem->xdev_ext_mech_state, NULL);")
        self.assertLess(retract, release.index("synchronize_net();"))
        self.assertLess(release.index("synchronize_net();"), release.index("kvfree("))
        self.assertLess(release.index("kvfree("), release.index("fput(p->file);"))

    def test_class_kfuncs_are_filtered_per_member(self):
        self.assertIn("BTF_ID_FLAGS(func, bpf_xdev_ext_afxdp_hdr, KF_TRUSTED_ARGS | KF_RET_NULL)", self.mech)
        self.assertIn("BTF_ID_FLAGS(func, bpf_xdev_ext_afxdp_hold, KF_TRUSTED_ARGS)", self.mech)
        build = self.mech[self.mech.index("BTF_SET_START(xsk_xdev_ext_mech_build_kfuncs)"):]
        build = build[:build.index("BTF_SET_END")]
        complete = self.mech[self.mech.index("BTF_SET_START(xsk_xdev_ext_mech_complete_kfuncs)"):]
        complete = complete[:complete.index("BTF_SET_END")]
        self.assertIn("bpf_xdev_ext_afxdp_hdr", build)
        self.assertNotIn("bpf_xdev_ext_afxdp_hold", build)
        self.assertIn("bpf_xdev_ext_afxdp_hold", complete)
        self.assertNotIn("bpf_xdev_ext_afxdp_hdr", complete)
        flt = function_body(self.mech, "static int xsk_xdev_ext_mech_kfunc_filter(")
        self.assertIn("xdev_ext_mech_class_kfunc_filter(XDEV_EXT_MECH_CLASS_AFXDP", flt)
        hold = function_body(self.mech, "__bpf_kfunc int bpf_xdev_ext_afxdp_hold(")
        self.assertIn("c->hold = ", hold)
        # Five scalar arguments (a kfunc takes at most five); the count is
        # the session layout's frames per batch, from the envelope.
        self.assertIn(".count = c->batch_frames,", hold)
        header = read("include/linux/xdev_ext_mech.h")
        decl = re.search(r"^int bpf_xdev_ext_afxdp_hold\(([^;]*)\);", header, re.M)
        defn = re.search(r"__bpf_kfunc int bpf_xdev_ext_afxdp_hold\(([^)]*)\)", self.mech)
        norm = lambda a: [" ".join(x.split()) for x in a.split(",")]
        self.assertEqual(norm(defn.group(1)), norm(decl.group(1)))
        for forbidden in ("hold_commit", "llist", "xdev_ext_mech_frame_", "xp_"):
            self.assertNotIn(forbidden, hold)  # records the intent only

    def test_built_with_the_mechanism_layer(self):
        self.assertIn("obj-$(CONFIG_XDEV_EXT_MECH) += xsk_xdev_ext_mech.o", read("net/xdp/Makefile"))
        self.assertIn("xdev_ext_mech_class_register(&xsk_xdev_ext_mech_class_ops)", self.mech)


class RxHookSourceTest(unittest.TestCase):
    def setUp(self):
        self.xsk = read("net/xdp/xsk.c")
        self.mech = read("net/xdp/xsk_xdev_ext_mech.c")
        self.rcv = function_body(self.xsk, "static int __xsk_rcv(struct xdp_sock *xs,")

    def test_rcv_takes_the_callsite(self):
        sig = self.xsk[self.xsk.index("static int __xsk_rcv(struct xdp_sock *xs,"):]
        sig = sig[:sig.index("{")]
        self.assertIn("u32 callsite", sig)
        generic = function_body(self.xsk, "int xsk_generic_rcv(struct xdp_sock *xs,")
        locked = generic[generic.index("spin_lock_bh(&xs->pool->rx_lock);"):
                         generic.index("spin_unlock_bh(&xs->pool->rx_lock);")]
        self.assertIn("XDEV_EXT_MECH_SITE_RX_GENERIC)", locked)
        self.assertNotIn("XDEV_EXT_MECH_SITE_RX_NATIVE", generic)
        native = function_body(self.xsk, "static int xsk_rcv(struct xdp_sock *xs,")
        self.assertRegex(native, r"__xsk_rcv\(xs, xdp, len, tracked_cookie,\s+XDEV_EXT_MECH_SITE_RX_NATIVE\)")
        self.assertNotIn("XDEV_EXT_MECH_SITE_RX_GENERIC", native)

    def test_hook_runs_after_the_copy_and_before_the_reservation(self):
        single = self.rcv[:self.rcv.index("num_desc = ")]
        copy = single.index("memcpy(xsk_xdp->data - meta_len, copy_from, rem);")
        hook = single.index("xsk_xdev_ext_mech_rx(xs, xskb, len, callsite) != XDEV_EXT_MECH_PUBLISH")
        reserve = single.index("err = __xsk_rcv_zc_reserve(xs, xskb, len, 0);")
        self.assertLess(copy, hook)
        self.assertLess(hook, reserve)
        # A held or recycled frame leaves before any reservation or release.
        held = single[hook:reserve]
        self.assertIn("return 0;", held)
        self.assertNotIn("xp_release", held)
        self.assertNotIn("xsk_buff_free", held)
        self.assertNotIn("xsk_xdev_ext_mech_rx(", self.rcv[self.rcv.index("num_desc = "):])

    def test_frames_settle_on_every_exit_of_the_rx_path(self):
        rcv = self.rcv
        frees = [m.start() for m in re.finditer(r"xsk_buff_free\(xsk_xdp\);|xp_free\(pos\);", rcv)]
        self.assertEqual(len(frees), 3)
        for pos in frees:
            before = rcv[:pos].rstrip().splitlines()[-1].strip()
            self.assertRegex(before, r"^xsk_xdev_ext_mech_rx_settle\(xs, (xskb|pos), false\);$")
        releases = [m.start() for m in re.finditer(r"xp_release\((xskb|pos)\);", rcv)]
        self.assertEqual(len(releases), 2)
        for pos in releases:
            before = rcv[:pos].rstrip().splitlines()[-1].strip()
            self.assertRegex(before, r"^xsk_xdev_ext_mech_rx_settle\(xs, (xskb|pos), true\);$")

    def test_session_socket_skips_the_rx_policy_hooks(self):
        for sig in ("int xsk_generic_rcv(struct xdp_sock *xs,",
                    "static int xsk_rcv(struct xdp_sock *xs,"):
            with self.subTest(sig=sig):
                body = function_body(self.xsk, sig)
                self.assertNotIn("xsk_xdev_ext_rx_dispatch(", body)
                self.assertIn("xsk_rx_dispatch(xs, xdp, len,", body)
                for m in re.finditer(r"xsk_xdev_ext_rx_publish\(", body):
                    guard = "".join(body[:m.start()].splitlines()[-2:])
                    self.assertIn("disposition == XSK_XDEV_EXT_RX_TRACKED", guard)
        disp = function_body(self.xsk, "xsk_rx_dispatch(struct xdp_sock *xs,")
        session = disp.index("if (xsk_xdev_ext_mech_rx_session(xs)) {")
        fallback = disp.index("return XSK_XDEV_EXT_RX_C_FALLBACK;", session)
        self.assertLess(fallback, disp.index("xsk_xdev_ext_rx_dispatch("))
        self.assertEqual(self.xsk.count("xsk_xdev_ext_rx_dispatch("), 1)

    def test_rx_complete_decides_in_c_after_the_callback(self):
        body = function_body(self.mech, "int xsk_xdev_ext_mech_rx(struct xdp_sock *xs,")
        runs = body.index("xsk_xdev_ext_mech_rx_runs(callsite,")
        call = body.index("xsk_xdev_ext_mech_rx_call(st, xst, &f, callsite, &ret, &hold, NULL)")
        verdict = body.index("xsk_xdev_ext_mech_rx_verdict(callsite, ran, err, ret, &hold,")
        commit = body.index("xdev_ext_mech_hold_commit(st, &hold, &f)")
        self.assertLess(runs, call)
        self.assertLess(call, verdict)
        self.assertLess(verdict, commit)
        self.assertIn("xdev_ext_mech_frame_recycle(st->s, &f);", body)
        for forbidden in ("spin_lock", "xp_free", "xp_release", "free_list"):
            self.assertNotIn(forbidden, body)
        helper = function_body(self.mech, "static int xsk_xdev_ext_mech_rx_call(")
        self.assertIn("xdev_ext_mech_call(st, &a, ret, hold)", helper)
        self.assertIn(".member = XDEV_EXT_MECH_MEMBER_COMPLETE", helper)


SLEEPLESS = ("spin_lock", "rcu_read_lock", "local_bh_disable", "preempt_disable",
             "local_irq_disable", "rx_lock")


class TxStageSourceTest(unittest.TestCase):
    def setUp(self):
        self.mech = read("net/xdp/xsk_xdev_ext_mech.c")

    def test_validate_runs_the_pure_rules_and_stages_for_submit(self):
        body = function_body(self.mech, "static int xsk_xdev_ext_mech_validate(")
        # a refused batch never leaves an earlier one staged
        self.assertLess(body.index("xst->tx_staged = NULL;"), body.index("return"))
        self.assertIn("if (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE)", body)
        check = body.index("xsk_xdev_ext_mech_tx_validate(scratch, n,")
        self.assertLess(body.index("xdev_ext_mech_session_peer(st->s)"), check)
        self.assertLess(body.index("xdev_ext_mech_batch_frame(b, i, &f)"), check)
        # only an accepted batch is staged
        refused = body.index("if (err)\n\t\treturn err;", check)
        self.assertLess(refused, body.index("xst->tx_staged = b;"))
        self.assertEqual(body.count("xst->tx_staged = b;"), 1)

    def test_submit_sends_frame_by_frame_and_completes_in_the_worker(self):
        body = function_body(self.mech, "static int xsk_xdev_ext_mech_submit(")
        staged = body.index("xst->tx_staged != b")
        run = body.index("status = xsk_xdev_ext_mech_tx_run(xdev_ext_mech_batch_id(b), xst->tx_n,")
        ticket = body.index("u64 ticket = xdev_ext_mech_batch_ticket(b);")
        done = body.index("xdev_ext_mech_batch_complete(b, ticket, status);")
        self.assertLess(ticket, staged)
        self.assertLess(body.index("tb->ticket = ticket;"), run)
        self.assertLess(staged, run)
        self.assertLess(run, done)
        self.assertEqual(body.count("xdev_ext_mech_batch_complete("), 1)
        self.assertTrue(body.rstrip().endswith("return 0;"))
        step = function_body(self.mech, "static int xsk_xdev_ext_mech_tx_xmit(void *arg, u32 slot)")
        dead = step.index("if (READ_ONCE(xst->dead))")
        finish = step.index("xsk_xdev_ext_mech_tx_finish(xst->tx_pkt[slot]);")
        xmit = step.index("err = xsk_kernel_xmit(xst->sock, d->addr, d->len, d->options);")
        self.assertLess(dead, finish)
        self.assertLess(finish, xmit)
        # xsk_kernel_xmit() returns the sent length on success: only a
        # negative value is a failure, and the step itself reports 0.
        refused = step.index("if (err < 0)\n\t\treturn err;", xmit)
        self.assertLess(refused, step.index("xdev_ext_mech_count(st->s, xdev_ext_mech_nic_ops_counter(xst->xs->zc), 1);"))
        self.assertTrue(step.rstrip().endswith("return 0;"))
        self.assertNotIn("if (err)\n", step)
        # xsk_kernel_xmit() takes xs->mutex: worker context, no atomic section
        for text in (body, step):
            for forbidden in SLEEPLESS:
                self.assertNotIn(forbidden, text)
        self.assertEqual(len(re.findall(r"\bxsk_kernel_xmit\((?!\))", self.mech)), 1)
        self.assertEqual(self.mech.count("xsk_xdev_ext_mech_tx_xmit,"), 1)

    def test_fill_cqe_reports_each_frame(self):
        body = function_body(self.mech, "static void xsk_xdev_ext_mech_fill_cqe(")
        self.assertIn("struct xdev_ext_afxdp_tx_cqe *c = cqe;", body)
        self.assertIn("c[i].err = tb->err[i];", body)

    def test_class_ops_carry_the_tx_members(self):
        ops = self.mech[self.mech.index("static const struct xdev_ext_mech_class_ops xsk_xdev_ext_mech_class_ops = {"):]
        ops = ops[:ops.index("};")]
        for member in (".validate = xsk_xdev_ext_mech_validate,",
                       ".submit = xsk_xdev_ext_mech_submit,",
                       ".fill_cqe = xsk_xdev_ext_mech_fill_cqe,",
                       ".batch_priv_size = sizeof(struct xsk_xdev_ext_mech_tx_batch),"):
            self.assertIn(member, ops)

    def test_bind_admits_a_tx_stage_on_the_pool_socket(self):
        body = function_body(self.mech, "static int xsk_xdev_ext_mech_bind(struct xdev_ext_mech_stage *st,")
        self.assertNotIn("return -EOPNOTSUPP;", body)
        lock = body.index("mutex_lock(&xs->mutex);")
        check = body.index("xsk_xdev_ext_mech_stage_check(st->direction, st->index,")
        self.assertLess(lock, check)
        # Publication is a release store: the stage is complete (priv, rx_info)
        # before the data path can observe it.
        publish = body.index("smp_store_release(&xs->xdev_ext_mech_tx, st);")
        self.assertEqual(body.count("smp_store_release(&xs->xdev_ext_mech_tx, st);"), 1)
        self.assertNotIn("WRITE_ONCE(xs->xdev_ext_mech_tx, st);", body)
        self.assertLess(check, publish)
        self.assertLess(body.index("st->priv = xst;"), publish)
        self.assertLess(publish, body.index("mutex_unlock(&xs->mutex);"))
        self.assertIn("kvcalloc(pool->nr_frames, sizeof(*xst->tx_sent)", body)
        self.assertIn("if (p->xs != xs)", body)
        unbind = function_body(self.mech, "static void xsk_xdev_ext_mech_unbind(struct xdev_ext_mech_stage *st)")
        self.assertIn("WRITE_ONCE(xs->xdev_ext_mech_tx, NULL);", unbind)
        self.assertLess(unbind.index("synchronize_net();"), unbind.index("kvfree(xst->tx_sent);"))
        self.assertIn("struct xdev_ext_mech_stage *xdev_ext_mech_tx;", read("include/net/xdp_sock.h"))


# Calls that may sleep or wait for other contexts.
SLEEPING = re.compile(
    r"^(mutex_lock\w*|down|down_(read|write|interruptible|killable|timeout)\w*|"
    r"wait_event\w*|wait_for_completion\w*|synchronize_\w+|flush_\w+|"
    r"kthread_flush\w*|kthread_stop\w*|kthread_destroy_worker|msleep\w*|"
    r"usleep_range\w*|ssleep|schedule\w*|cond_resched\w*|might_sleep\w*|"
    r"rcu_barrier\w*|cancel_\w+_sync|del_timer_sync|timer_delete_sync|"
    r"timer_shutdown_sync|lock_sock|vfree|kvfree|fput|kmalloc|kzalloc|kvzalloc|"
    r"kvcalloc|xp_del_xsk|xsk_xdev_ext_mech_pool_release|io_xdev_ext_mech_ring_exit)$")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def callees(body: str) -> set:
    body = strip_comments(body)
    names = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", body))
    return names - {"if", "for", "while", "switch", "return", "sizeof"}


def sleepers(source: str, signature: str, depth: int = 4) -> list:
    """Sleeping calls reachable from a function through static functions of
    the same file (indirect calls are checked by their own tests)."""
    statics = set(re.findall(r"^static\s[^;{]*?\b(\w+)\(", source, flags=re.M))
    found, seen, todo = [], set(), [(signature, depth)]
    while todo:
        sig, left = todo.pop()
        body = function_body(source, sig)
        if "GFP_KERNEL" in strip_comments(body):
            found.append(f"{sig}: GFP_KERNEL")
        for name in sorted(callees(body)):
            if SLEEPING.match(name):
                found.append(f"{sig}: {name}")
            elif name in statics and name not in seen and left:
                seen.add(name)
                m = re.search(r"^static\s[^;{]*?\b" + name + r"\(", source, flags=re.M)
                todo.append((m.group(0), left - 1))
    return found


class ZeroCopySourceTest(unittest.TestCase):
    def setUp(self):
        self.xsk = read("net/xdp/xsk.c")
        self.mech = read("net/xdp/xsk_xdev_ext_mech.c")
        self.pool = read("net/xdp/xsk_buff_pool.c")

    def test_kernel_source_precedes_the_user_source_for_all_tx_hooks(self):
        for sig, mechanism, legacy in (
            ("void xsk_tx_completed(", "xsk_xdev_ext_mech_tx_complete", "xsk_xdev_ext_zc_tx_completed"),
            ("void xsk_tx_cancel_tail(", "xsk_xdev_ext_mech_tx_complete", "xsk_xdev_ext_zc_tx_cancel_tail"),
            ("void xsk_tx_set_tail_result(", "xsk_xdev_ext_mech_tx_complete", "xsk_xdev_ext_zc_tx_set_tail_result"),
            ("bool xsk_tx_peek_desc(", "xsk_xdev_ext_mech_tx_peek", "xsk_xdev_ext_zc_tx_peek_desc"),
            ("u32 xsk_tx_peek_release_desc_batch(", "xsk_xdev_ext_mech_tx_batch", "xsk_xdev_ext_zc_tx_peek_release_desc_batch"),
        ):
            body = function_body(self.xsk, sig)
            self.assertLess(body.index(mechanism), body.index(legacy))

    def test_zc_submit_never_copies_payload_or_produces_shared_rings(self):
        submit = function_body(self.mech, "static int xsk_xdev_ext_mech_zc_submit(")
        for forbidden in ("memcpy", "skb_", "xsk_kernel_xmit", "xskq_",
                          "batch_complete(b, status)",
                          "batch_complete(b, ticket, status)"):
            self.assertNotIn(forbidden, submit)
        self.assertIn("xp_dma_sync_for_device", submit)
        self.assertIn("ndo_xsk_wakeup", submit)
        complete = function_body(self.mech, "int xsk_xdev_ext_mech_tx_complete(")
        self.assertNotIn("pool->cq", complete)
        self.assertNotIn("xskq_", complete)
        self.assertIn("xsk_mech_zc_retire", complete)

    def test_native_hold_precedes_rx_publication(self):
        rx = function_body(self.xsk, "static int xsk_rcv_zc(")
        hook = rx.index("xsk_xdev_ext_mech_rx(xs,")
        self.assertLess(rx.index("spin_lock_bh(&xs->pool->rx_lock)"), hook)
        self.assertLess(hook, rx.index("__xsk_rcv_zc_reserve("))
        self.assertIn("disposition != XDEV_EXT_MECH_PUBLISH", rx)
        self.assertIn("return 0; /* HOLD/RECYCLE", rx)

    def test_zero_copy_certifies_all_actual_nic_page_mappings(self):
        certify = function_body(self.mech, "static bool xsk_xdev_ext_mech_dma_unbounced(")
        self.assertIn("dma_single_page_is_unbounced", certify)
        self.assertIn("i < xp->dma_pages_cnt", certify)
        self.assertIn("xp->umem->pgs[i]", certify)
        self.assertIn("~XSK_NEXT_PG_CONTIG_MASK", certify)
        bind = function_body(self.mech, "int xsk_xdev_ext_mech_pool_bind(")
        self.assertLess(bind.index("xsk_xdev_ext_mech_dma_unbounced(xs->pool)"),
                        bind.index("smp_store_release(&xs->umem->xdev_ext_mech_state"))

    def test_dma_unmap_stops_source_before_releasing_mapping(self):
        unmap = function_body(self.pool, "void xp_dma_unmap(")
        self.assertLess(unmap.index("xsk_xdev_ext_mech_pool_dead(pool)"),
                        unmap.index("__xp_dma_unmap("))
        sync = function_body(self.mech, "static void xsk_xdev_ext_mech_sync_for_cpu_batch(")
        self.assertIn("!p->stopped", sync)
        self.assertIn("spin_lock_irqsave(&p->tx_lock", sync)
        self.assertIn("dma_sync_single_for_cpu", sync)
        stop = function_body(self.mech, "static void xsk_mech_zc_stop(")
        self.assertIn("XSK_MECH_ZC_NATIVE", stop)
        self.assertIn("tb->completion.uncertain = true", stop)
        done = function_body(self.mech, "static void xsk_mech_zc_done(")
        # Native retirement retains the immutable submission ticket by value;
        # a late callback must never fetch the current batch generation.
        self.assertIn("u64 ticket = tb->ticket;", done)
        self.assertNotIn("xdev_ext_mech_batch_ticket(", done)
        self.assertIn("xdev_ext_mech_batch_sequester(b, ticket, status ?: -ENXIO);", done)
        self.assertIn("xdev_ext_mech_batch_complete(b, ticket, status);", done)


class UnbindSourceTest(unittest.TestCase):
    """T-UNBIND: the netdev unregister path holds xs->mutex, which the
    session worker's xsk_kernel_xmit() takes too, so unbinding only marks the
    session stages dead and never waits for the session."""

    def setUp(self):
        self.xsk = read("net/xdp/xsk.c")
        self.mech = read("net/xdp/xsk_xdev_ext_mech.c")

    def test_unbind_dev_marks_the_stages_dead_first(self):
        body = function_body(self.xsk, "static void xsk_unbind_dev(struct xdp_sock *xs)")
        unbound = body.index("WRITE_ONCE(xs->state, XSK_UNBOUND);")
        hook = body.index("xsk_xdev_ext_mech_unbind_dev(xs);")
        self.assertLess(unbound, hook)
        self.assertLess(hook, body.index("xp_del_xsk(xs->pool, xs);"))
        self.assertEqual(self.xsk.count("xsk_xdev_ext_mech_unbind_dev("), 1)
        # the driver-side RCU wait it always had, and nothing that waits
        # for a session
        self.assertEqual(callees(body), {"WRITE_ONCE", "xsk_xdev_ext_mech_unbind_dev",
                                         "xp_del_xsk", "synchronize_net",
                                         "xsk_xdev_ext_del_tx_socket", "dev_put"})
        # both callers hold xs->mutex around it
        for sig in ("static int xsk_release(struct socket *sock)",
                    "static int xsk_notifier(struct notifier_block *this,"):
            with self.subTest(sig=sig):
                caller = function_body(self.xsk, sig)
                call = caller.index("xsk_unbind_dev(xs);")
                self.assertLess(caller.rindex("mutex_lock(&xs->mutex);", 0, call), call)
                self.assertLess(call, caller.index("mutex_unlock(&xs->mutex);", call))

    def test_hook_only_marks_both_stages_dead(self):
        body = function_body(self.mech, "void xsk_xdev_ext_mech_unbind_dev(struct xdp_sock *xs)")
        self.assertIn("lockdep_assert_held(&xs->mutex);", body)
        self.assertIn("xdev_ext_mech_stage_dead(xs->xdev_ext_mech_rx, -ENXIO);", body)
        self.assertIn("xdev_ext_mech_stage_dead(xs->xdev_ext_mech_tx, -ENXIO);", body)
        self.assertEqual(callees(body), {"lockdep_assert_held", "xdev_ext_mech_stage_dead"})
        self.assertEqual(sleepers(self.mech, "void xsk_xdev_ext_mech_unbind_dev(struct xdp_sock *xs)"), [])
        stub = read("net/xdp/xsk_xdev_ext_mech.h")
        self.assertIn("static inline void xsk_xdev_ext_mech_unbind_dev(struct xdp_sock *xs)", stub)

    def test_mark_dead_takes_no_sleeping_lock(self):
        sig = "static void xsk_xdev_ext_mech_mark_dead(struct xdev_ext_mech_stage *st)"
        self.assertEqual(sleepers(self.mech, sig), [])
        self.assertIn("xsk_mech_zc_stop", callees(function_body(self.mech, sig)))
        stop = function_body(self.mech, "static void xsk_mech_zc_stop(")
        self.assertIn("tb->completion.uncertain = true", stop)
        self.assertIn("xsk_mech_zc_done(&done)", stop)

    def test_core_stage_dead_never_sleeps(self):
        core = ROOT / "io_uring/xdev_ext_mech.c"
        if not core.exists():
            self.skipTest("io_uring/xdev_ext_mech.c (core) is not in this tree")
        source = core.read_text(encoding="utf-8")
        sig = "void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st, int err)"
        self.assertEqual(sleepers(source, sig), [])
        self.assertIn("mark_dead(st)", function_body(source, sig))


if __name__ == "__main__":
    unittest.main()
