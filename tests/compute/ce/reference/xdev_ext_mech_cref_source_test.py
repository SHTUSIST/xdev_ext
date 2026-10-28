#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of the C reference module (measurement arm C).

xdev_ext_mech_cref_test.c shows on host inputs that the reference callbacks and
tools/xdev_ext_mech/nxp_mech.bpf.c produce the same bytes.  These checks hold
what that test cannot see: the module's copies of the two AF_XDP kfuncs say
what net/xdp/xsk_xdev_ext_mech.c says, the module calls only kfuncs the kernel
exports, uses the same pure helpers as the program, and installs and
removes both classes.
"""

import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
HEADER = HERE / "xdev_ext_mech_cref.h"
MODULE = HERE / "xdev_ext_mech_cref.c"
PROGRAM = ROOT / "tools/xdev_ext_mech/nxp_mech.bpf.c"
AFXDP_KFUNCS = ROOT / "net/xdp/xsk_xdev_ext_mech.c"
SHARED_KFUNCS = ROOT / "io_uring/xdev_ext_mech_ops.c"


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def body(text: str, name: str) -> str:
    """The braces-balanced body of the function definition @name."""
    match = re.search(rf"\b{name}\([^;{{]*\)\s*\{{", text)
    if not match:
        raise AssertionError(f"no definition of {name}")
    depth, pos = 1, match.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(text[pos], 0)
        pos += 1
    return text[match.end():pos - 1]


def statements(code: str):
    """Whitespace-normalized statements of a body."""
    flat = " ".join(strip_comments(code).split())
    return [s.strip() for s in re.split(r"(?<=[;{}])", flat) if s.strip()]


class CrefSourceTest(unittest.TestCase):
    def setUp(self):
        self.header = strip_comments(HEADER.read_text())
        self.module = strip_comments(MODULE.read_text())
        self.program = strip_comments(PROGRAM.read_text())

    def kfunc_copy(self, kfunc: str, copy: str):
        kernel = statements(body(AFXDP_KFUNCS.read_text(), kfunc))
        mine = statements(body(HEADER.read_text(), copy))
        self.assertEqual(kernel[0],
                         "struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);")
        self.assertEqual(
            mine[0],
            "__typeof__(XDEV_EXT_MECH_CREF_CALL_OF(ctx)) c = "
            "XDEV_EXT_MECH_CREF_CALL_OF(ctx);")
        self.assertEqual(kernel[1:], mine[1:], f"{copy} differs from {kfunc}")

    def test_hold_copy_matches_the_kfunc(self):
        self.kfunc_copy("bpf_xdev_ext_afxdp_hold", "xdev_ext_mech_cref_afxdp_hold")

    def test_hdr_copy_matches_the_kfunc(self):
        self.kfunc_copy("bpf_xdev_ext_afxdp_hdr", "xdev_ext_mech_cref_afxdp_hdr")

    def test_module_envelope_is_the_kernel_envelope(self):
        self.assertIn("#define XDEV_EXT_MECH_CREF_CALL_OF(ctx)\tubr_mech_call_of(ctx)",
                      MODULE.read_text())
        # bpf_ktime_get_ns() reads the fast monotonic clock.
        self.assertIn("return ktime_get_mono_fast_ns();", self.module)

    def test_only_exported_kfuncs(self):
        exported = set(re.findall(r"EXPORT_SYMBOL_GPL\((bpf_xdev_ext_\w+)\)",
                                  SHARED_KFUNCS.read_text() + AFXDP_KFUNCS.read_text()))
        used = set(re.findall(r"\b(bpf_xdev_ext_\w+)\(", self.header + self.module))
        self.assertTrue(used, "the reference calls no kfunc")
        self.assertLessEqual(used, exported)
        self.assertEqual({name for name in used if name.startswith("bpf_xdev_ext_afxdp_")},
                         {"bpf_xdev_ext_afxdp_state"})

    def test_same_pure_helpers_as_the_program(self):
        helpers = lambda text: set(re.findall(r"\b(xdev_ext_mp_\w+)\(", text))
        program = helpers(self.program)
        self.assertTrue(program)
        self.assertEqual(program, helpers(self.header))

    def test_every_program_has_a_reference(self):
        pairs = {
            "nxp_rx_complete": "xdev_ext_mech_cref_rx_complete",
            "nxp_tx_complete": "xdev_ext_mech_cref_tx_complete",
            "nxp_afxdp_complete": "xdev_ext_mech_cref_afxdp_complete",
            "nxp_afxdp_build": "xdev_ext_mech_cref_afxdp_build",
            "nxp_nvme_build": "xdev_ext_mech_cref_nvme_build",
            "nxp_nvme_complete": "xdev_ext_mech_cref_nvme_complete",
        }
        for prog, ref in pairs.items():
            self.assertRegex(self.program, rf"\b{prog}\b")
            self.assertIn(f"/* {prog}() */", HEADER.read_text())
            self.assertRegex(self.header, rf"\b{ref}\(")
        for global_name in ("nxp_session", "key_base", "nvme_mode"):
            self.assertRegex(self.program, rf"\b{global_name}\b")
            self.assertRegex(self.header, rf"g->{global_name}\b")
            if global_name != "rx_order":
                self.assertIn(f"module_param_named({global_name}, "
                              f"xdev_ext_mech_cref.{global_name}", self.module)

    def test_both_classes_installed_and_removed(self):
        init = statements(body(self.module, "xdev_ext_mech_cref_init"))
        exit_ = statements(body(self.module, "xdev_ext_mech_cref_exit"))
        self.assertIn("err = xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_AFXDP, "
                      "&xdev_ext_mech_cref_afxdp_ops);", init)
        self.assertIn("err = xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME, "
                      "&xdev_ext_mech_cref_nvme_ops);", init)
        self.assertIn("if (err) xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_AFXDP, NULL);",
                      init)
        self.assertEqual(
            ["xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME, NULL);",
             "xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_AFXDP, NULL);"], exit_)
        for ops in ("xdev_ext_mech_cref_afxdp_ops", "xdev_ext_mech_cref_nvme_ops"):
            table = re.search(
                rf"struct xdev_ext_mech_c_ops {ops} = \{{(.*?)\}};",
                self.module, re.S).group(1)
            self.assertIn(".build =", table)
            self.assertIn(".complete =", table)
            self.assertNotIn(".prepare", table)

    def test_kbuild_takes_helpers_from_the_kernel_tree(self):
        kbuild = (HERE / "Kbuild").read_text()
        self.assertIn("obj-m := xdev_ext_mech_cref.o", kbuild)
        self.assertIn("ccflags-y += -I$(srctree)", kbuild)
        self.assertIn('#include "net/xdp/xsk_xdev_ext_mech_core.h"', self.module)
        self.assertIn('#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"', self.module)


if __name__ == "__main__":
    unittest.main()
