#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
BPF_SELFTESTS = ROOT / "tools/testing/selftests/bpf"

# Mechanism-layer verifier negatives: progs/xdev_ext_mech_fail_<name>.c and the
# verifier text each one must produce.
MECH_NEGATIVES = {
    "write_ctx": "XDEV_EXT callback context is read-only at off",
    "desc_complete": "calling kernel function bpf_xdev_ext_desc is not allowed",
    "dma_desc_complete": "calling kernel function bpf_xdev_ext_desc is not allowed",
    "dma_wrong_class_hold": "calling kernel function bpf_xdev_ext_afxdp_hold is not allowed",
    "sleepable_build":
        "attach to unsupported member build of struct xdev_ext_nvme_mech_ops",
    "view_size": "R2 is not a const",
    "binding_calls_mech": "calling kernel function bpf_xdev_ext_info is not allowed",
    "wrong_class_hold":
        "calling kernel function bpf_xdev_ext_afxdp_hold is not allowed",
    "forged_ctx": "R1 must be referenced or trusted",
    "frame_write": "cannot write into rdonly_mem",
}

# Which mechanism kfuncs each member may call (plan section 2.3.4), plus the
# two AF_XDP class kfuncs.  Positive programs must use exactly these.
MECH_KFUNCS = {
    "bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_cqe", "bpf_xdev_ext_frame",
    "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c", "bpf_xdev_ext_afxdp_hdr",
    "bpf_xdev_ext_afxdp_hold", "bpf_xdev_ext_afxdp_state",
}
MECH_MEMBER_KFUNCS = {
    "prepare": {"bpf_xdev_ext_info", "bpf_xdev_ext_crc32c"},
    "build": {"bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_frame",
              "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c"},
    "complete": {"bpf_xdev_ext_info", "bpf_xdev_ext_cqe", "bpf_xdev_ext_frame",
                 "bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c"},
}
MECH_CLASS_KFUNCS = {
    ("afxdp", "build"): {"bpf_xdev_ext_afxdp_hdr"},
    ("afxdp", "complete"): {"bpf_xdev_ext_afxdp_hold", "bpf_xdev_ext_afxdp_state"},
}


def function_body(path: Path, signature: str) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(signature)
    opening = text.index("{", start)
    depth = 0
    for offset, character in enumerate(text[opening:], opening):
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : offset + 1]
    raise AssertionError(f"unterminated function {signature} in {path}")


def mech_callbacks(path: Path):
    """{member: [(sleepable, name, kfuncs reached)]} of a mechanism program.

    Kfuncs called from static __always_inline helpers of the file or of
    progs/xdev_ext_mech_common.h count for the callback that calls the helper.
    """
    common = BPF_SELFTESTS / "progs/xdev_ext_mech_common.h"
    helpers = {}
    for source in (path, common):
        text = source.read_text(encoding="utf-8")
        for match in re.finditer(r"^static __always_inline [^;{(]*?\b(\w+)\(",
                                 text, re.M):
            helpers[match.group(1)] = function_body(source, match.group(0))

    def reached(body, seen):
        found = set(re.findall(r"\b(bpf_xdev_ext_\w+)\(", body)) & MECH_KFUNCS
        for name in re.findall(r"\b(\w+)\(", body):
            if name in helpers and name not in seen:
                seen.add(name)
                found |= reached(helpers[name], seen)
        return found

    callbacks = {}
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r'^SEC\("struct_ops(\.s)?/(\w+)"\)\n'
                             r'(?:__\w+[^\n]*\n)*__s32 BPF_PROG\((\w+),',
                             text, re.M):
        body = function_body(path, f"BPF_PROG({match.group(3)},")
        callbacks.setdefault(match.group(2), []).append(
            (bool(match.group(1)), match.group(3), reached(body, set())))
    return callbacks


class UbrHardeningSourceTest(unittest.TestCase):
    def test_default_pipeline_excludes_unmediated_gpu_demo(self):
        # The unmediated nvme_gpu_nic_chain.c demonstrator (cuMemHostRegister
        # on the shared frames, no XDEV_EXT GPU entry) is not distributed.  The
        # NVMe->GPU->NIC chain is built only from the mediated pipeline
        # sources, and never as a default target.
        path = ROOT / "Makefile.pipeline"
        text = path.read_text(encoding="utf-8")

        targets = next(
            line for line in text.splitlines() if line.startswith("TARGETS =")
        )
        userspace = next(
            line for line in text.splitlines() if line.startswith("userspace:")
        )

        self.assertFalse((ROOT / "nvme_gpu_nic_chain.c").exists())
        self.assertNotIn("nvme_gpu_nic_chain.c", text)
        self.assertNotIn("legacy-demo", text)
        for line in (targets, userspace):
            self.assertNotIn("gpu", line)
        self.assertIn("gpu-chain: nvme_gpu_nic_pipeline\n", text)
        self.assertIn("gpu-chain-host: nvme_gpu_nic_pipeline_host\n", text)
        for binary in ("nvme_gpu_nic_pipeline", "nvme_gpu_nic_pipeline_host"):
            rule = re.search(rf"^{binary}: (.*?)\n\n", text, re.M | re.S)
            self.assertIsNotNone(rule, binary)
            self.assertIn("-DXDEV_EXT_NVME_GPU_NIC_CHAIN", rule.group(1))
            self.assertIn("nvme_xdp_pipeline.c tools/nvme_gpu_nic_runtime.c",
                          rule.group(1))
        self.assertIn(
            "synchronously traverse the NVIDIA CE before sink publish",
            " ".join(text.replace("#", " ").split()),
        )

    def test_gpu_artifact_labels_match_current_roles(self):
        orchestrator = (ROOT / "tools/gpu_nvme_orchestrator.c").read_text(
            encoding="utf-8"
        )
        samples = " ".join((ROOT / "drivers/gpu/nvidia-p2p/README.md")
                           .read_text(encoding="utf-8").split())

        self.assertNotIn("setup-only", orchestrator)
        self.assertIn("NVMe <-> GPU staged host-UMEM pipeline", orchestrator)
        self.assertNotIn("demonstrates the full zero-copy pipeline", orchestrator)
        # The sample README labels the directory as userspace frontends over
        # the canonical gpu/kernel-open driver, not as a driver snapshot, and
        # states that the CE path still performs host<->VRAM DMA.
        self.assertIn("use the canonical NVIDIA implementation in "
                      "`gpu/kernel-open`", samples)
        self.assertIn("This directory contains no NVIDIA kernel driver "
                      "overlay.", samples)
        self.assertIn("includes host↔VRAM DMA", samples)
        self.assertIn("does not implement direct NIC-to-VRAM peer DMA",
                      samples)
        self.assertNotIn("Historical reference snapshot", samples)
        self.assertNotIn("openpgu-p2p-v3", samples)

    def test_nvme_child_timeout_uses_pidfd_and_never_blocks_reaping(self):
        path = ROOT / "tools/testing/selftests/bpf/prog_tests/xdev_ext_binding.c"
        body = function_body(path, "static int xdev_ext_wait_child_bounded")

        self.assertIn("syscall(__NR_pidfd_open, child, 0)", body)
        self.assertIn("__NR_pidfd_send_signal", body)
        self.assertIn("XDEV_EXT_TEST_NVME_KILL_REAP_TIMEOUT_MS", body)
        self.assertNotRegex(body, r"\bkill\s*\(\s*child\b")
        self.assertNotRegex(
            body,
            r"waitpid\s*\(\s*child\s*,\s*status\s*,\s*0\s*\)",
        )
        self.assertGreaterEqual(body.count("WNOHANG"), 2)

    def test_xsk_advisory_probe_reads_all_mutable_state_once(self):
        path = ROOT / "net/xdp/xsk.c"
        bound = function_body(path, "static bool xsk_is_bound")
        probe = function_body(path, "bool xsk_kernel_tx_capable")
        xmit = function_body(path, "int xsk_kernel_xmit")

        self.assertIn("READ_ONCE(xs->state)", bound)
        self.assertIn("xsk_is_bound(xs)", probe)
        self.assertRegex(probe, r"\btx\s*=\s*READ_ONCE\(xs->tx\)")
        self.assertRegex(probe, r"\bpool\s*=\s*READ_ONCE\(xs->pool\)")
        self.assertLess(probe.index("xsk_is_bound(xs)"),
                probe.index("READ_ONCE(xs->tx)"))
        self.assertLess(probe.index("READ_ONCE(xs->tx)"),
                probe.index("READ_ONCE(xs->pool)"))
        self.assertIn("return tx && pool;", probe)
        self.assertLess(xmit.index("mutex_lock(&xs->mutex)"),
                xmit.index("xsk_check_common(xs)"))
        self.assertLess(xmit.index("xsk_check_common(xs)"),
                xmit.index("if (!xs->tx)"))
        self.assertLess(xmit.index("if (!xs->tx)"),
                xmit.index("xp_validate_desc(xs->pool"))

    def test_generic_xsk_tx_uses_exact_xdev_ext_record_around_native_xmit(self):
        path = ROOT / "net/xdp/xsk.c"
        xmit = function_body(path, "static int __xsk_generic_xmit")
        destructor = function_body(path, "static void xsk_xdev_ext_destruct_skb")
        peek = function_body(path, "static bool xsk_copy_peek_desc")
        has_descs = function_body(path, "static bool xsk_copy_has_descs")

        self.assertIn("xsk_xdev_ext_copy_enter", xmit)
        self.assertIn("xsk_copy_peek_desc", xmit)
        self.assertIn("xsk_xdev_ext_copy_dispatch", xmit)
        self.assertIn("xsk_xdev_ext_copy_set_result", xmit)
        self.assertIn("xsk_xdev_ext_copy_cancel_busy", xmit)
        self.assertLess(xmit.index("xsk_xdev_ext_copy_dispatch"),
                        xmit.index("__dev_direct_xmit"))
        self.assertLess(xmit.index("__dev_direct_xmit"),
                        xmit.index("xsk_xdev_ext_copy_set_result"))
        self.assertIn("xsk_xdev_ext_copy_retired", destructor)
        self.assertLess(destructor.index("xsk_xdev_ext_copy_retired"),
                        destructor.index("sock_wfree"))
        self.assertIn("__xskq_cons_peek", has_descs)
        self.assertNotIn("__xskq_cons_release", peek)
        self.assertNotIn("__xskq_cons_release", has_descs)

    def test_generic_copy_overflow_discards_tail_without_redispatch(self):
        source = (ROOT / "include/net/xdp_sock.h").read_text(
            encoding="utf-8"
        )
        path = ROOT / "net/xdp/xsk.c"
        build = function_body(
            path, "static struct sk_buff *xsk_build_skb(struct"
        )
        peek = function_body(path, "static bool xsk_copy_peek_desc")
        discard = function_body(path, "static void xsk_copy_discard_desc")
        xmit = function_body(path, "static int __xsk_generic_xmit")

        self.assertIn("bool tx_copy_discard_until_eop;", source)
        self.assertIn(
            "tx_copy_discard_until_eop = xp_mb_desc(desc)", build
        )
        self.assertIn("tx_copy_discard_until_eop", peek)
        self.assertIn("ring->desc", peek)
        self.assertIn("tx_copy_discard_until_eop = false", discard)
        self.assertIn("__xskq_cons_release", discard)
        self.assertLess(
            xmit.index("xsk_copy_discard_desc"),
            xmit.index("xsk_cq_reserve_addr_locked"),
        )
        self.assertLess(
            xmit.index("max_batch--"),
            xmit.index("xsk_copy_discard_desc"),
        )
        self.assertRegex(
            xmit,
            r"err\s*!=\s*-EOVERFLOW[\s\S]*?"
            r"__xskq_cons_release\(xs->tx\)",
        )

    def test_generic_copy_invalid_contd_enters_bounded_discard(self):
        path = ROOT / "net/xdp/xsk.c"
        peek = function_body(path, "static bool xsk_copy_peek_desc")
        xmit = function_body(path, "static int __xsk_generic_xmit")

        self.assertIn("bool *valid", peek)
        self.assertIn("xskq_cons_read_desc", peek)
        self.assertLess(
            xmit.index("while (max_batch)"),
            xmit.index("xsk_copy_peek_desc"),
        )
        self.assertLess(
            xmit.index("xsk_copy_peek_desc"),
            xmit.index("max_batch--"),
        )
        self.assertIn("if (!valid_desc)", xmit)
        self.assertIn(
            "tx_copy_discard_until_eop = xp_mb_desc(&desc)", xmit
        )
        invalid = xmit.index("if (!valid_desc)")
        reserve = xmit.index("xsk_cq_reserve_addr_locked")
        dispatch = xmit.index("xsk_xdev_ext_copy_dispatch")
        self.assertLess(invalid, reserve)
        self.assertLess(invalid, dispatch)
        self.assertIn("__xskq_cons_release(xs->tx)", xmit[invalid:reserve])

    def test_generic_zerocopy_overflow_never_dereferences_null_skb(self):
        path = ROOT / "net/xdp/xsk.c"
        build = function_body(
            path, "static struct sk_buff *xsk_build_skb(struct"
        )

        self.assertNotIn("xsk_set_destructor_arg(xs->skb)", build)
        self.assertRegex(
            build,
            r"drop_skb\s*=\s*xs->skb\s*\?:\s*skb[\s\S]*?"
            r"if\s*\(drop_skb\)[\s\S]*?"
            r"xsk_set_destructor_arg\(drop_skb\)",
        )

    def test_zc_dispatch_uses_validated_kernel_snapshot_after_callback(self):
        path = ROOT / "net/xdp/xsk_xdev_ext.c"
        dispatch = function_body(path, "static int xsk_xdev_ext_dispatch_packet")
        after_callback = dispatch.split("xdev_ext_binding_dispatch", 1)[1]

        self.assertIn("snapshot", dispatch)
        self.assertNotIn("ring->desc", after_callback)
        self.assertNotIn("xsk_xdev_ext_scan_packet", after_callback)

    def test_zc_overlimit_and_batch_work_are_bounded(self):
        path = ROOT / "net/xdp/xsk_xdev_ext.c"
        scan = function_body(path, "static void xsk_xdev_ext_scan_packet")
        batch = function_body(
            path, "int xsk_xdev_ext_zc_tx_peek_release_desc_batch"
        )

        self.assertIn("packet->nr_descs >= pool->xdp_zc_max_segs", scan)
        self.assertRegex(
            scan,
            r"packet->nr_descs\s*>=\s*pool->xdp_zc_max_segs[\s\S]*?"
            r"packet->complete\s*=\s*true",
        )
        self.assertIn("work_descs", batch)
        self.assertIn("tx_budget_spent", batch)
        self.assertRegex(batch, r"work_descs\s*\+=\s*packet\.nr_descs")

    def test_zc_overlimit_tail_stays_bound_to_its_tx_socket(self):
        source = (ROOT / "include/net/xdp_sock.h").read_text(
            encoding="utf-8"
        )
        path = ROOT / "net/xdp/xsk_xdev_ext.c"
        scan = function_body(path, "static void xsk_xdev_ext_scan_packet")
        drop = function_body(path, "static u32 xsk_xdev_ext_drop_invalid_packet")
        discard = function_body(
            path,
            "static u32 xsk_xdev_ext_discard_packet_tail("
            "struct xdp_sock *xs, u32 max_descs)\n{",
        )
        single = function_body(path, "int xsk_xdev_ext_zc_tx_peek_desc")
        batch = function_body(
            path, "int xsk_xdev_ext_zc_tx_peek_release_desc_batch"
        )

        self.assertIn("bool tx_xdev_ext_discard_until_eop;", source)
        self.assertIn("packet->discard_until_eop = true", scan)
        self.assertIn(
            "tx_xdev_ext_discard_until_eop = true",
            drop,
        )
        self.assertIn("xsk_xdev_ext_discard_packet_tail", drop)
        self.assertIn("tx_xdev_ext_discard_until_eop", discard)
        self.assertIn("xskq_cons_nb_entries", discard)
        self.assertIn("xskq_cons_release_n", discard)
        self.assertRegex(
            discard,
            r"!xp_mb_desc\(&desc\)[\s\S]*?"
            r"tx_xdev_ext_discard_until_eop\s*=\s*false",
        )
        self.assertIn("xsk_xdev_ext_discard_packet_tail", single)
        self.assertIn("xsk_xdev_ext_discard_packet_tail", batch)
        self.assertRegex(
            batch,
            r"work_descs\s*\+=\s*discarded[\s\S]*?"
            r"tx_budget_spent\s*\+=\s*discarded",
        )

    def test_xsk_tx_socket_count_drops_only_for_tx_after_rcu_grace(self):
        path = ROOT / "net/xdp/xsk.c"
        unbind = function_body(path, "static void xsk_unbind_dev")

        self.assertIn("if (xs->tx)", unbind)
        self.assertLess(unbind.index("synchronize_net()"),
                        unbind.index("xsk_xdev_ext_del_tx_socket"))

    def test_gated_veth_fixture_drives_production_afxdp_rx_hook(self):
        path = ROOT / "tools/testing/selftests/bpf/prog_tests/xdev_ext_binding.c"
        signature = "static void test_runtime_afxdp_native_rx_copy"
        text = path.read_text(encoding="utf-8")

        self.assertIn(signature, text)
        body = function_body(path, signature)

        self.assertIn("XDEV_EXT_RUN_AFXDP_VETH", body)
        self.assertIn("xdev_ext_xsk_fill_rx", body)
        self.assertIn("xdev_ext_xsk_peer_inject", body)
        self.assertIn("xdev_ext_xsk_receive_bounded", body)
        self.assertIn("XDEV_EXT_SUCCESS_FALLBACK", body)
        self.assertIn("XDEV_EXT_SUCCESS_TERMINAL", body)
        self.assertIn("native_rx_terminal_no_descriptor", body)
        self.assertIn("XDEV_EXT_BINDING_STAGE_AFXDP_RX", body)
        self.assertIn("XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE", body)

    def test_native_rx_fixture_redirects_into_its_own_xskmap(self):
        # The AF_XDP RX hook runs only for frames an XDP program redirects into
        # an XSKMAP entry; without one every injected frame stays on the stack
        # path and the RX wait can only time out.
        path = ROOT / "tools/testing/selftests/bpf/prog_tests/xdev_ext_binding.c"
        text = path.read_text(encoding="utf-8")
        init = function_body(path, "static int xdev_ext_xsk_fixture_init_mode")
        cleanup = function_body(path, "static void xdev_ext_xsk_fixture_cleanup")
        program = (ROOT / "tools/testing/selftests/bpf/progs/"
                   "xdev_ext_binding_xsk_rx.c").read_text(encoding="utf-8")

        self.assertIn('#include "xdev_ext_binding_xsk_rx.skel.h"', text)
        self.assertIn("xsk_update_xskmap", init)
        self.assertIn("bpf_xdp_attach", init)
        self.assertLess(init.index("xsk_socket__create"),
                        init.index("xsk_update_xskmap"))
        self.assertLess(init.index("xsk_update_xskmap"),
                        init.index("bpf_xdp_attach"))
        # Detach before the socket goes away so no frame is redirected into a
        # map entry whose socket is being destroyed.
        self.assertIn("bpf_xdp_detach", cleanup)
        self.assertLess(cleanup.index("bpf_xdp_detach"),
                        cleanup.index("xsk_socket__delete"))

        self.assertIn("BPF_MAP_TYPE_XSKMAP", program)
        self.assertIn("bpf_redirect_map", program)
        # Link-local traffic a veth emits after link-up keeps the stack path
        # and cannot take the test's single fill-ring frame.
        self.assertIn("XDP_PASS", program)

        # An aligned-mode RX descriptor addresses the packet data inside its
        # chunk (base + XDP_PACKET_HEADROOM in copy mode).  The fill ring takes
        # the chunk base, so the receive helper must mask the offset away.
        receive = function_body(path, "static int xdev_ext_xsk_receive_bounded")
        self.assertRegex(
            receive,
            r"original\s*=\s*desc->addr\s*&\s*"
            r"~\(\(__u64\)XDEV_EXT_TEST_XSK_FRAME_SIZE\s*-\s*1\)")

        # xsk_xdev_ext_rx_publish() makes the descriptor visible before it runs the
        # complete callback, and native veth XDP may run on another CPU, so
        # the test waits for the completion count before reading it.
        rx_test = function_body(
            path, "static void test_runtime_afxdp_native_rx_copy")
        for wait_target, assertion in (
                ("complete_before + 1", '"native_rx_fallback_complete"'),
                ("terminal_complete_before + 1",
                 '"native_rx_recovery_complete"')):
            wait = re.search(
                r"xdev_ext_wait_count_at_least\(\s*&skel->bss->complete_count"
                r"\[XDEV_EXT_BINDING_BACKEND_AFXDP\],\s*" + re.escape(wait_target),
                rx_test)
            self.assertIsNotNone(wait, wait_target)
            self.assertLess(wait.start(), rx_test.index(assertion))

        # Generic XDP reaches xsk_generic_rcv(); native veth XDP reaches the
        # copy branch of xsk_rcv().  Both carry the XDEV_EXT RX dispatch.
        self.assertRegex(
            text,
            r'test__start_subtest\("runtime_afxdp_native_rx_copy"\)\)\s*'
            r"test_runtime_afxdp_native_rx_copy\(XDP_FLAGS_SKB_MODE\);")
        self.assertRegex(
            text,
            r'test__start_subtest\("runtime_afxdp_native_rx_copy_drv"\)\)\s*'
            r"test_runtime_afxdp_native_rx_copy\(XDP_FLAGS_DRV_MODE\);")

    def test_xsk_pool_defers_missing_cq_to_shared_queue_validation(self):
        path = ROOT / "net/xdp/xsk_buff_pool.c"
        create = function_body(path, "struct xsk_buff_pool *xp_create_and_assign_umem")
        assign_shared = function_body(path, "int xp_assign_dev_shared")

        guarded_init = re.compile(
            r"if\s*\(pool->cq\)\s*\{[\s\S]*?"
            r"xp_alloc_tx_descs\(pool, xs\)[\s\S]*?"
            r"xsk_xdev_ext_pool_init\(pool, pool->cq->nentries\)[\s\S]*?\}",
        )
        self.assertRegex(create, guarded_init)
        self.assertRegex(
            assign_shared,
            r"if\s*\(!pool->fq\s*\|\|\s*!pool->cq\)\s*"
            r"return\s+-EINVAL",
        )

    def test_zc_driver_rejects_use_tail_cancel_not_fifo_completion(self):
        virtio = function_body(
            ROOT / "drivers/net/virtio_net.c",
            "static int virtnet_xsk_xmit_batch",
        )
        stmmac = function_body(
            ROOT / "drivers/net/ethernet/stmicro/stmmac/stmmac_main.c",
            "static bool stmmac_xdp_xmit_zc",
        )
        dpaa2 = function_body(
            ROOT / "drivers/net/ethernet/freescale/dpaa2/dpaa2-xsk.c",
            "bool dpaa2_xsk_tx",
        )

        self.assertIn("xsk_tx_cancel_tail", virtio)
        self.assertNotIn("xsk_tx_completed(sq->xsk_pool, nb_pkts - i)",
                         virtio)
        self.assertIn("xsk_tx_cancel_tail(pool, 1, -EMSGSIZE)", stmmac)
        self.assertGreaterEqual(dpaa2.count("xsk_tx_cancel_tail"), 2)

        mlx5 = function_body(
            ROOT / "drivers/net/ethernet/mellanox/mlx5/core/en/xsk/tx.c",
            "bool mlx5e_xsk_tx",
        )
        self.assertIn("xsk_tx_set_tail_result", mlx5)

    def test_gve_xsk_preflight_covers_largest_frame_and_wrap_padding(self):
        text = (ROOT / "drivers/net/ethernet/google/gve/gve_tx.c").read_text(
            encoding="utf-8"
        )
        xmit = function_body(
            ROOT / "drivers/net/ethernet/google/gve/gve_tx.c",
            "static int gve_xsk_tx",
        )

        collapsed = text.replace("\\\n", " ")
        self.assertRegex(
            collapsed,
            r"#define\s+GVE_XSK_TX_START_THRESH\s+\(PAGE_SIZE\s*\+\s*"
            r"GVE_GQ_TX_MIN_PKT_DESC_BYTES\s*-\s*1\)",
        )
        self.assertIn("GVE_XSK_TX_START_THRESH", xmit)

    def test_nfp_reset_counts_only_af_xdp_tx_ring_descriptors(self):
        reset = function_body(
            ROOT / "drivers/net/ethernet/netronome/nfp/nfd3/rings.c",
            "static void nfp_nfd3_xsk_tx_bufs_free",
        )

        self.assertRegex(
            reset,
            r"if\s*\(txbuf->is_xsk_tx\)[\s\S]*?else\s*"
            r"xsk_tx_completed\(tx_ring->r_vec->xsk_pool, 1\)",
        )

    def test_xsk_fixture_ip_binary_is_configurable_and_validated(self):
        # BusyBox shells run their own "ip" applet ahead of PATH, and that
        # applet ignores "peer name" when it creates a veth pair, so the
        # fixture must be able to name the iproute2 binary explicitly.
        body = function_body(
            ROOT / "tools/testing/selftests/bpf/prog_tests/xdev_ext_binding.c",
            "static int xdev_ext_run_ip(",
        )
        self.assertIn('getenv("XDEV_EXT_IP_BIN")', body)
        self.assertIn("xdev_ext_ip_bin_valid(", body)
        validator = function_body(
            ROOT / "tools/testing/selftests/bpf/prog_tests/xdev_ext_binding.c",
            "static bool xdev_ext_ip_bin_valid(",
        )
        self.assertIn("isalnum(", validator)

    def test_shared_headers_do_not_depend_on_directory_local_macros(self):
        # A macro defined only through one directory's ccflags must not change
        # a header that other directories also include.  Otherwise the same
        # struct has different layouts in different compilation units, and
        # the vmlinux BTF keeps one copy per layout: struct io_ring_ctx, and
        # every type that reaches it such as struct file, appeared seven times.
        local = set()
        for makefile in ("io_uring/Makefile", "net/xdp/Makefile",
                         "drivers/nvme/host/Makefile"):
            text = (ROOT / makefile).read_text(encoding="utf-8")
            local.update(re.findall(
                r"^ccflags-\S*\s*\+?=.*?-D([A-Z0-9_]+)", text, re.M))
        self.assertIn("XDEV_EXT_UMEM_ZEROCOPY", local)

        offenders = []
        for header in sorted((ROOT / "include").rglob("*.h")):
            text = header.read_text(encoding="utf-8", errors="replace")
            for macro in sorted(local):
                if re.search(rf"^\s*#\s*(if|ifdef|ifndef|elif)\b.*\b{macro}\b",
                             text, re.M):
                    offenders.append(f"{header.relative_to(ROOT)}: {macro}")
        self.assertEqual(offenders, [])

    def test_binding_uses_shared_struct_ops_core(self):
        # The policy layer and the mechanism layer share one copy of the
        # struct_ops plumbing; xdev_ext_binding.c keeps only its own ABI v2 rules.
        core_h = (ROOT / "io_uring/xdev_ext_ops_core.h").read_text(encoding="utf-8")
        core_c = ROOT / "io_uring/xdev_ext_ops_core.c"
        binding = ROOT / "io_uring/xdev_ext_binding.c"
        text = binding.read_text(encoding="utf-8")
        makefile = (ROOT / "io_uring/Makefile").read_text(encoding="utf-8")

        self.assertRegex(
            makefile,
            r"obj-\$\(CONFIG_IO_URING_XDEV_EXT_BPF_POLICY\)\s*\+=\s*"
            r"xdev_ext_ops_core\.o\s+xdev_ext_binding\.o")
        self.assertIn('#include "xdev_ext_ops_core.h"', text)
        for name in ("DEFINE_XDEV_EXT_OPS_REGISTRY", "XDEV_EXT_OPS_CFI_STUB",
                     "xdev_ext_ops_call_seal", "xdev_ext_ops_call_sealed",
                     "xdev_ext_ops_call_take", "xdev_ext_ops_call_clean"):
            self.assertIn(name, core_h)
            self.assertIn(name, text)

        # Registry: RCU publish, static key, grace period on retract.
        publish = function_body(core_c, "int xdev_ext_ops_publish(")
        retract = function_body(core_c, "bool xdev_ext_ops_retract(")
        pin = function_body(core_c, "const void *xdev_ext_ops_pin(")
        self.assertIn("-EOPNOTSUPP", publish)
        self.assertIn("-EBUSY", publish)
        self.assertIn("rcu_assign_pointer", publish)
        self.assertIn("static_branch_enable", publish)
        self.assertIn("static_branch_disable", retract)
        self.assertLess(retract.index("mutex_unlock"),
                        retract.index("synchronize_rcu()"))
        self.assertIn("bpf_struct_ops_get", pin)
        self.assertIn("rcu_read_lock()", pin)

        # The filter must not hide kfuncs it does not own (btf.c calls every
        # filter on the hook), and no member asks for a private stack.
        kfilter = function_body(core_c, "int xdev_ext_ops_kfunc_filter(")
        self.assertRegex(
            kfilter,
            r"if\s*\(!btf_id_set8_contains\(rule->ids,\s*kfunc_id\)\)\s*"
            r"return 0;")
        self.assertIn("attach_st_ops_member_off", kfilter)
        self.assertNotIn("priv_stack", core_c.read_text(encoding="utf-8"))
        deny = function_body(core_c, "int xdev_ext_ops_deny_btf_write(")
        self.assertIn("XDEV_EXT callback context is read-only at off", deny)
        self.assertIn("XDEV_EXT callback kernel BTF objects are read-only at off",
                      deny)

        for signature, helper in (
                ("static int xdev_ext_binding_ops_reg(", "xdev_ext_ops_publish("),
                ("static void xdev_ext_binding_ops_unreg(", "xdev_ext_ops_retract("),
                ("int xdev_ext_binding_dispatch(", "xdev_ext_ops_pin("),
                ("void xdev_ext_binding_token_put(", "xdev_ext_ops_unpin("),
                ("int xdev_ext_binding_complete(", "xdev_ext_ops_unpin("),
                ("static int xdev_ext_binding_kfunc_filter(",
                 "xdev_ext_ops_kfunc_filter("),
                ("static int xdev_ext_binding_ops_init_member(",
                 "xdev_ext_ops_init_member("),
                ("static int xdev_ext_binding_ops_check_member(",
                 "xdev_ext_ops_check_member("),
                ("static int xdev_ext_binding_ops_validate(", "xdev_ext_ops_validate("),
                ("xdev_ext_binding_ops_btf_struct_access(",
                 "xdev_ext_ops_deny_btf_write("),
        ):
            self.assertIn(helper, function_body(binding, signature), signature)
        self.assertIn('"xdev_ext_binding_ctx_v2"',
                      function_body(binding,
                                    "xdev_ext_binding_ops_btf_struct_access("))
        for private in ("rcu_assign_pointer", "static_branch_enable",
                        "synchronize_rcu", "bpf_struct_ops_get",
                        "bpf_struct_ops_put", "btf_id_set8_contains",
                        "bpf_log(", "bpf_tracing_btf_ctx_access",
                        "__btf_member_bit_offset"):
            self.assertNotIn(private, text, private)
        self.assertIn(".init = xdev_ext_ops_init,", text)
        self.assertIn(".is_valid_access = xdev_ext_ops_is_valid_access,", text)

    def test_reference_policy_wrapper_compiles_the_shipped_object(self):
        # test_progs must load the same five struct_ops maps and callbacks the
        # guest loader attaches, so the wrapper adds nothing of its own.
        wrapper = (ROOT / "tools/testing/selftests/bpf/progs/"
                   "xdev_ext_reference_policy_wrap.c")
        shipped = ROOT / "tools/xdev_ext_reference_policy.bpf.c"
        self.assertTrue(wrapper.is_file(), f"missing {wrapper}")
        code = re.sub(r"/\*.*?\*/", "",
                      wrapper.read_text(encoding="utf-8"), flags=re.S)
        code = re.sub(r"//[^\n]*", "", code).strip()

        self.assertEqual(code, '#include "../../../../xdev_ext_reference_policy.bpf.c"')
        self.assertEqual((wrapper.parent / "../../../../xdev_ext_reference_policy.bpf.c")
                         .resolve(), shipped.resolve())

    def test_reference_policy_subtest_covers_each_stage_and_rx_gate(self):
        path = ROOT / "tools/testing/selftests/bpf/prog_tests/xdev_ext_binding.c"
        text = path.read_text(encoding="utf-8")
        self.assertTrue('#include "xdev_ext_reference_policy_wrap.skel.h"' in text,
                        "xdev_ext_binding.c does not use the shipped-policy skeleton")
        entry = function_body(path, "void serial_test_xdev_ext_binding(void)")
        registration = re.search(
            r'test__start_subtest\("reference_policy_per_backend"\)\)\s*\{(.*?)\}',
            entry, re.S)
        self.assertIsNotNone(registration)
        self.assertEqual(re.findall(r"(test_\w+)\(\);", registration.group(1)),
                         ["test_reference_policy_per_backend",
                          "test_reference_policy_rx_opt_in_cleared"])

        cases = re.search(r"xdev_ext_reference_policy_cases\[\]\s*=\s*\{(.*?)\n\};",
                          text, re.S)
        self.assertIsNotNone(cases)
        rows = re.findall(
            r"XDEV_EXT_BINDING_BACKEND_(\w+),\s*(\w+),\s*XDEV_EXT_BINDING_STAGE_(\w+)",
            cases.group(1))
        self.assertEqual(rows, [
            ("SOCKET", "0", "SEND"),
            ("AFXDP", "0", "AFXDP_TX"),
            ("AFXDP", "BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX", "AFXDP_RX"),
            ("NVME", "0", "NVME_READ"),
            ("IAA", "0", "IAA_COMPRESS"),
            ("GPU", "0", "GPU_COPY"),
        ])

        driver = function_body(path, "static void xdev_ext_reference_dispatch_complete(")
        self.assertLess(driver.index("BPF_TESTMOD_XDEV_EXT_DISPATCH"),
                        driver.index("BPF_TESTMOD_XDEV_EXT_COMPLETE"))
        each = function_body(path, "static void test_reference_policy_per_backend(")
        self.assertIn("xdev_ext_reference_policy_wrap__open_and_load()", each)
        self.assertIn("xdev_ext_reference_dispatch_complete(test_case->backend", each)

        gate = function_body(path, "static void test_reference_policy_rx_opt_in_cleared(")
        clear = gate.index("skel->struct_ops.afxdp_policy->flags = 0;")
        self.assertLess(clear, gate.index("xdev_ext_reference_policy_wrap__load(skel)"))
        self.assertIn("BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX", gate)
        self.assertIn("xdev_ext_reference_policy_wrap__open()", gate)

    def test_mech_kfunc_prototypes_fit_bpf_calls(self):
        # A kfunc takes at most MAX_BPF_FUNC_REG_ARGS (5) arguments: the
        # verifier refuses more (kernel/bpf/verifier.c, "Function %s has %d
        # > %d args") and clang's BPF backend will not emit the call.  The
        # programs' extern declarations must match the kernel prototypes.
        def params(text):
            return [p.strip() for p in text.split(",")] if text.strip() else []

        header = (ROOT / "include/linux/xdev_ext_mech.h").read_text(
            encoding="utf-8")
        kernel = {m.group(1): params(m.group(2)) for m in re.finditer(
            r"^(?:__u8 \*|__u32 |int )(bpf_xdev_ext_\w+)\(([^;]*)\);", header,
            re.M)}
        self.assertEqual(set(kernel), MECH_KFUNCS)
        common = (BPF_SELFTESTS / "progs/xdev_ext_mech_common.h").read_text(
            encoding="utf-8")
        progs = {m.group(1): params(m.group(2)) for m in re.finditer(
            r"^extern [^;(]*?\b(bpf_xdev_ext_\w+)\(([^;]*)\) __ksym;", common,
            re.M)}
        self.assertEqual(set(progs), MECH_KFUNCS)
        for name, args in kernel.items():
            self.assertLessEqual(len(args), 5, name)
            self.assertEqual(len(progs[name]), len(args), name)
            for kernel_arg, prog_arg in zip(args, progs[name]):
                last = kernel_arg.split()[-1].lstrip("*")
                if last.endswith("_buf_size") or last.endswith("__sz"):
                    self.assertEqual(prog_arg.split()[-1], last, name)
        # The hold count is not a program argument: bpf_testmod hands
        # xdev_ext_mech_call_active() the frames per batch a layout would give.
        testmod = (BPF_SELFTESTS / "test_kmods/bpf_testmod.c").read_text(
            encoding="utf-8")
        self.assertIn(".batch_frames = io->batch_frames,", testmod)
        shared = (BPF_SELFTESTS / "xdev_ext_mech_test.h").read_text(
            encoding="utf-8")
        self.assertRegex(shared, r"__u32 batch_frames;")

    def test_mech_verifier_negatives_are_wired(self):
        # Each negative is one rejected program in its own object, run by
        # RUN_TESTS behind the BTF gate, so a kernel without the mechanism
        # layer skips instead of reporting a different verifier text.
        progs = BPF_SELFTESTS / "progs"
        test = BPF_SELFTESTS / "prog_tests/xdev_ext_mech.c"
        entry = function_body(test, "void serial_test_xdev_ext_mech(void)")
        gate = entry.index("xdev_ext_mech_btf_available()")

        for name, message in MECH_NEGATIVES.items():
            path = progs / f"xdev_ext_mech_fail_{name}.c"
            self.assertTrue(path.is_file(), f"missing {path}")
            text = path.read_text(encoding="utf-8")
            self.assertEqual(text.count("__failure"), 1, name)
            self.assertEqual(len(re.findall(r'^SEC\("struct_ops', text, re.M)),
                             1, name)
            self.assertIn(f'__msg("{message}")', text, name)
            call = f"RUN_TESTS(xdev_ext_mech_fail_{name});"
            self.assertIn(call, entry, name)
            self.assertLess(gate, entry.index(call), name)
        self.assertEqual(
            sorted(path.stem for path in progs.glob("xdev_ext_mech_fail_*.c")),
            sorted(f"xdev_ext_mech_fail_{name}" for name in MECH_NEGATIVES))

        def prog(name):
            return (progs / f"xdev_ext_mech_fail_{name}.c").read_text(
                encoding="utf-8")

        self.assertIn('SEC("struct_ops.s/build")', prog("sleepable_build"))
        self.assertIn("struct xdev_ext_nvme_mech_ops", prog("sleepable_build"))
        self.assertIn("bpf_core_cast(", prog("forged_ctx"))
        self.assertRegex(prog("view_size"),
                         r"bpf_xdev_ext_info\(\w+,\s*\w+->\w+\)")
        self.assertIn("struct xdev_ext_binding_ops", prog("binding_calls_mech"))
        self.assertIn('SEC("struct_ops/complete")', prog("desc_complete"))
        self.assertIn('SEC("struct_ops/complete")', prog("wrong_class_hold"))
        self.assertIn("struct xdev_ext_nvme_mech_ops", prog("wrong_class_hold"))
        self.assertRegex(prog("frame_write"),
                         r"bpf_xdev_ext_frame\([^;]*\);[\s\S]*\[\d+\]\s*=")

        # Mechanism filters return 0 for kfuncs outside their set, so a
        # policy program next to them still loads.
        loads = (progs / "xdev_ext_mech_binding_loads.c").read_text(
            encoding="utf-8")
        self.assertIn("__success", loads)
        self.assertIn("struct xdev_ext_binding_ops", loads)
        self.assertIn("bpf_xdev_ext_dispatch_action(", loads)
        self.assertNotIn("bpf_xdev_ext_info", loads)
        self.assertIn("RUN_TESTS(xdev_ext_mech_binding_loads);", entry)

    def test_mech_positive_programs_use_each_member_kfunc_set(self):
        # No clang here: the kfunc filter table is checked on the source.
        # Each class has one positive program calling every kfunc its members
        # may call and nothing else; only prepare is sleepable.
        progs = BPF_SELFTESTS / "progs"
        for cls in ("nvme", "afxdp", "ce"):
            path = progs / f"xdev_ext_mech_{cls}.c"
            text = path.read_text(encoding="utf-8")
            callbacks = mech_callbacks(path)
            self.assertEqual(sorted(callbacks), ["build", "complete", "prepare"],
                             cls)
            self.assertIn(f"struct xdev_ext_{cls}_mech_ops ", text)
            for member, entries in callbacks.items():
                self.assertEqual(len(entries), 1, f"{cls}.{member}")
                sleepable, name, kfuncs = entries[0]
                self.assertEqual(sleepable, member == "prepare",
                                 f"{cls}.{member}")
                expected = (MECH_MEMBER_KFUNCS[member] |
                            MECH_CLASS_KFUNCS.get((cls, member), set()))
                self.assertEqual(kfuncs, expected, f"{cls}.{member}")
                self.assertRegex(text,
                                 rf"\.{member}\s*=\s*\(void \*\){name},")
            self.assertIn("bpf_xdev_ext_crc32c(", text)

        # Every other mechanism program stays inside the table.
        for path in sorted(progs.glob("xdev_ext_mech_*.c")):
            if path.stem.startswith("xdev_ext_mech_fail_"):
                continue
            cls = re.search(r"struct xdev_ext_(\w+)_mech_ops ",
                            path.read_text(encoding="utf-8"))
            if not cls:
                continue
            for member, entries in mech_callbacks(path).items():
                for _, name, kfuncs in entries:
                    allowed = (MECH_MEMBER_KFUNCS[member] |
                               MECH_CLASS_KFUNCS.get((cls.group(1), member),
                                                     set()))
                    self.assertLessEqual(kfuncs, allowed,
                                         f"{path.name}:{name}")

    def test_mech_nxp_rx_cases_are_wired(self):
        # The diagnostic seam has no RX session owner. Packet-shaped inputs
        # assert explicit rejection; real RX protocol coverage belongs to the
        # private guest integration with a valid session and serialized pool.
        path = BPF_SELFTESTS / "progs/xdev_ext_mech_nxp.c"
        text = path.read_text(encoding="utf-8")
        self.assertIn("struct xdev_ext_afxdp_mech_ops nxp_afxdp_ops", text)
        complete = mech_callbacks(path)["complete"]
        self.assertEqual(len(complete), 1)
        self.assertIn("bpf_xdev_ext_afxdp_hold", complete[0][2])
        body = function_body(path, f"BPF_PROG({complete[0][1]},")
        # Only the locked generic call site may hold or advance the group.
        self.assertLess(body.index("XDEV_EXT_MECH_SITE_RX_GENERIC"),
                        body.index("bpf_xdev_ext_afxdp_hold("))

        test = BPF_SELFTESTS / "prog_tests/xdev_ext_mech.c"
        entry = function_body(test, "void serial_test_xdev_ext_mech(void)")
        self.assertIn('test__start_subtest("nxp_rx_requires_owner")', entry)
        call = function_body(test, "static void xdev_ext_mech_nxp_rx(")
        self.assertIn("-EOPNOTSUPP", call)
        self.assertIn("xdev_ext_mech_check_hold(&io, 0, 0, 0, 0, 0", call)
        cases = function_body(test, "static void test_nxp_rx_cases(void)")
        for case in ("correct", "out_of_order", "duplicate", "bad_crc",
                     "wrong_session", "not_nxp", "rx_native"):
            self.assertIn(f'"{case}', cases, case)
        packet = function_body(test, "static __u32 xdev_ext_mech_nxp_packet(")
        self.assertIn("nxp_wire_header_encode(", packet)

    def test_mech_mk3_times_build_and_validate(self):
        # Plan section 6.2 MK3: 10^6 x (build + the NVMe class validate) in
        # the kernel, timed around the loop only; the C arm runs reference
        # ops through the same xdev_ext_mech_call_active() path.
        path = BPF_SELFTESTS / "test_kmods/bpf_testmod.c"
        text = path.read_text(encoding="utf-8")
        mk3 = function_body(path, "static int bpf_testmod_xdev_ext_mech_mk3(")
        start = mk3.index("ktime_get_ns()")
        stop = mk3.index("ktime_get_ns()", start + 1)
        loop = mk3[start:stop]
        for step in ("memset(io->scratch", "xdev_ext_mech_call_active(",
                     "xdev_ext_mech_slots_used(", "nvme_xdev_ext_mech_validate("):
            self.assertIn(step, loop, step)
        self.assertLess(loop.index("memset(io->scratch"),
                        loop.index("xdev_ext_mech_call_active("))
        self.assertLess(loop.index("xdev_ext_mech_call_active("),
                        loop.index("nvme_xdev_ext_mech_validate("))
        self.assertIn("xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME, NULL)", mk3)
        self.assertIn("bpf_testmod_xdev_ext_mech_c_calls", mk3)
        self.assertLess(mk3.index("xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME,"),
                        start)
        run = function_body(path, "static int bpf_testmod_xdev_ext_mech_run(")
        self.assertIn("bpf_testmod_xdev_ext_mech_mk3(io)", run)

        # The C reference build exists only in measurement builds and
        # mirrors the program's build.
        guard = text.index("#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE")
        cbuild = text.index("static __s32 bpf_testmod_xdev_ext_mech_c_build(")
        self.assertLess(guard, cbuild)
        program = (BPF_SELFTESTS / "progs/xdev_ext_mech_mk3.c").read_text(
            encoding="utf-8")
        self.assertIn("struct xdev_ext_nvme_mech_ops mk3_nvme_ops", program)
        build = mech_callbacks(BPF_SELFTESTS / "progs/xdev_ext_mech_mk3.c")
        self.assertEqual(build["build"][0][2], {"bpf_xdev_ext_info", "bpf_xdev_ext_desc"})

        test = BPF_SELFTESTS / "prog_tests/xdev_ext_mech.c"
        entry = function_body(test, "void serial_test_xdev_ext_mech(void)")
        self.assertIn('test__start_subtest("mk3")', entry)
        self.assertIn('"XDEV_EXT_MECH_MK3 arm=%s ns_per_iter=%.1f\\n"',
                      test.read_text(encoding="utf-8"))
        self.assertIn("XDEV_EXT_MECH_MK3_ITERS\t\t1000000ULL",
                      test.read_text(encoding="utf-8"))

    def test_mech_testmod_drives_call_active(self):
        # bpf_testmod is a module: it may call only the exported mechanism
        # entry points; everything else it uses is a static inline rule.
        path = BPF_SELFTESTS / "test_kmods/bpf_testmod.c"
        text = path.read_text(encoding="utf-8")
        header = (ROOT / "include/linux/xdev_ext_mech.h").read_text(
            encoding="utf-8")
        out_of_line = set(re.findall(r"^(?!static)(?=\w)(?:int|void|u\d+|bool|"
                                     r"[\w ]+\*)\s*(xdev_ext_mech_\w+)\(",
                                     header, re.M))
        used = set(re.findall(r"\b(xdev_ext_mech_\w+)\(", text))
        self.assertLessEqual(used & out_of_line,
                             {"xdev_ext_mech_call_active", "xdev_ext_mech_set_c_ops"})
        self.assertIn('#include "../xdev_ext_mech_test.h"', text)
        self.assertIn('#include "../../../../../io_uring/xdev_ext_mech_core.h"',
                      text)

        # The mechanism code exists only with CONFIG_XDEV_EXT_MECH.
        start = text.index("#ifdef CONFIG_XDEV_EXT_MECH\n")
        end = text.index("#endif /* CONFIG_XDEV_EXT_MECH */")
        code = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text,
                      flags=re.S)
        calls = [m.start() for m in re.finditer(r"xdev_ext_mech_call_active\(",
                                                code)]
        self.assertTrue(calls)
        for offset in calls:
            self.assertTrue(start < offset < end, offset)

        call = function_body(path, "static void bpf_testmod_xdev_ext_mech_call(")
        self.assertLess(call.index("memset(io->scratch"),
                        call.index("xdev_ext_mech_call_active("))
        for rule in ("xdev_ext_mech_slots_used(", "xdev_ext_mech_rx_resolve(",
                     "xdev_ext_mech_ret_resolve(", "xdev_ext_mech_hold_check(",
                     "bpf_testmod_xdev_ext_mech_nvme_validate("):
            self.assertIn(rule, call)
        self.assertIn("nvme_xdev_ext_mech_validate(", text)

        write = function_body(path, "bpf_testmod_xdev_ext_mech_write(")
        self.assertIn("mutex_lock(&bpf_testmod_xdev_ext_mech_mutex)", write)
        self.assertIn("bpf_testmod_xdev_ext_mech_run(io)", write)
        run = function_body(path, "static int bpf_testmod_xdev_ext_mech_run(")
        self.assertLess(run.index("bpf_testmod_xdev_ext_mech_check(io)"),
                        run.index("switch (io->command)"))
        init = function_body(path, "static int bpf_testmod_init(void)")
        exit_ = function_body(path, "static void bpf_testmod_exit(void)")
        self.assertIn("register_bpf_testmod_xdev_ext_mech()", init)
        self.assertIn("unregister_bpf_testmod_xdev_ext_mech()", exit_)

        test = BPF_SELFTESTS / "prog_tests/xdev_ext_mech.c"
        entry = function_body(test, "void serial_test_xdev_ext_mech(void)")
        for subtest in ("no_program", "nvme_members", "afxdp_members",
                        "ce_members"):
            self.assertIn(f'test__start_subtest("{subtest}")', entry)
        self.assertIn('#include "../xdev_ext_mech_test.h"',
                      test.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
