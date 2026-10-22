#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Integration contracts for the strict mechanism DMA path.

Runtime ring ownership is exercised by the C selftests; these checks ensure
that the real device entry points use those rules and cannot select bounce.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def read(path):
    return (ROOT / path).read_text()


def body(path, name):
    text = read(path)
    start = text.index("{", text.index(name))
    level = 1
    end = start + 1
    while level:
        level += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


class StrictDmaTest(unittest.TestCase):
    def test_bpf_observes_the_native_zero_copy_path(self):
        b = body("io_uring/xdev_ext_mech.c", "static struct xdev_ext_binding_ctx_v2 xdev_ext_mech_base(")
        self.assertIn("st->s->pool.capabilities", b)
        self.assertIn("xdev_ext_binding_make_afxdp_native_tx_ctx", b)
        rx = body("net/xdp/xsk_xdev_ext_mech.c", "static int xsk_xdev_ext_mech_rx_call(")
        self.assertIn("XDEV_EXT_BINDING_CAP_ZERO_COPY", rx)

    def test_mechanism_only_sgl_marker(self):
        self.assertIn("NVME_REQ_XDEV_EXT_ZC", read("drivers/nvme/host/nvme.h"))
        b = body("drivers/nvme/host/xdev_ext_mech_nvme.c", "static int nvme_xdev_ext_class_submit(")
        self.assertIn("nvme_req(req)->flags |= NVME_REQ_XDEV_EXT_ZC;", b)
        self.assertLess(b.index("NVME_REQ_XDEV_EXT_ZC"), b.index("nvme_xdev_ext_class_map("))

    def test_strict_map_bypasses_prp_optimization(self):
        b = body("drivers/nvme/host/pci.c", "static blk_status_t nvme_map_data(")
        self.assertLess(b.index("NVME_REQ_XDEV_EXT_ZC"), b.index("nvme_setup_prp_simple("))
        self.assertIn("!strict_sgl && blk_rq_nr_phys_segments(req) == 1", b)
        self.assertIn("strict_sgl || nvme_pci_use_sgls", b)
        self.assertLess(b.index("dma_sgtable_is_unbounced"), b.index("nvme_pci_setup_sgls"))

    def test_bounce_only_in_compatibility_build(self):
        text = read("drivers/nvme/host/xdev_ext_mech_nvme.c")
        start = text.index("#ifndef CONFIG_XDEV_EXT_MECH_ZEROCOPY")
        bounce = text.index("static void nvme_xdev_ext_class_bounce_copy(")
        end = text.index("#endif /* !CONFIG_XDEV_EXT_MECH_ZEROCOPY */", start)
        self.assertLess(start, bounce)
        self.assertLess(bounce, end)
        kconfig = read("io_uring/Kconfig")
        self.assertIn("config XDEV_EXT_MECH_ZEROCOPY", kconfig)
        self.assertIn("depends on XDEV_EXT_MECH && !XDEV_EXT_MECH_ZEROCOPY", kconfig)

    def test_ambiguous_completion_has_no_payload_views(self):
        b = body("io_uring/xdev_ext_mech.c", "static void xdev_ext_mech_batch_landed(")
        self.assertIn("if (seq) {", b)
        self.assertIn("a.frames = NULL;", b)
        self.assertIn("a.nr_frames = 0;", b)

    def test_failed_generation_stops_later_ordered_sends(self):
        b = body("io_uring/xdev_ext_mech.c", "static void xdev_ext_mech_abort(")
        self.assertIn("XDEV_EXT_MECH_CLASS_F_ORDERED", b)
        self.assertLess(b.index("xdev_ext_mech_session_stop("),
                        b.index("XDEV_EXT_MECH_EV_ABORT"))

    def test_sync_before_cpu_build_and_complete(self):
        for name, operation in (("static int xdev_ext_mech_build(", "xdev_ext_mech_call("),
                                ("static void xdev_ext_mech_batch_landed(", "xdev_ext_mech_call(")):
            b = body("io_uring/xdev_ext_mech.c", name)
            self.assertLess(b.index("xdev_ext_mech_sync_for_cpu("), b.index(operation))
        sync = body("io_uring/xdev_ext_mech.c", "static void xdev_ext_mech_sync_for_cpu(")
        self.assertIn("s->pool.ops->sync_for_cpu", sync)


if __name__ == "__main__":
    unittest.main()
