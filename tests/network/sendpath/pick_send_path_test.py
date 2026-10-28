#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the SEND path selector truth table on the production bodies.

Extracts enum xdev_ext_send_path and xdev_ext_pick_send_path() from
io_uring/unified_ops.c and xsk_kernel_tx_capable() from net/xdp/xsk.c,
pastes them into pick_send_path_fixture.c and runs the 16-row table there.
Pins that the SEND dispatch decides with xsk_kernel_tx_capable() under the
feature guard, and shows the table fails when either body drops one of its
conditions.  Run directly with python3.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[3]
UNIFIED = KERNEL / "io_uring" / "unified_ops.c"
XSK = KERNEL / "net" / "xdp" / "xsk.c"
FEATURE_GUARD = "#if defined(XDEV_EXT_AFXDP_SEND) && IS_ENABLED(CONFIG_XDP_SOCKETS)"


def braced(text, start):
    """text[start:] up to the brace that closes the first one after start."""
    depth = 0
    for pos in range(text.index("{", start), len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise RuntimeError("unbalanced braces")


def selector_source(text):
    enum = re.search(r"^enum xdev_ext_send_path \{.*?^\};", text, re.M | re.S)
    func = re.search(r"^static inline enum xdev_ext_send_path\s*\n"
                     r"xdev_ext_pick_send_path\(", text, re.M)
    if not enum or not func:
        raise RuntimeError("selector enum or function missing in unified_ops.c")
    return enum.group(0) + "\n\n" + braced(text, func.start())


def tx_capable_source(text):
    func = re.search(r"^bool xsk_kernel_tx_capable\(struct socket \*sock\)\s*\{",
                     text, re.M)
    if not func:
        raise RuntimeError("xsk_kernel_tx_capable missing in net/xdp/xsk.c")
    return braced(text, func.start())


class PickSendPath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which(os.environ.get("CC", "cc"))
        if not cls.cc:
            raise unittest.SkipTest("C compiler unavailable")
        cls.unified = UNIFIED.read_text()
        cls.selector = selector_source(cls.unified)
        cls.tx_capable = tx_capable_source(XSK.read_text())
        cls.fixture = (HERE / "pick_send_path_fixture.c").read_text()
        cls.temp = tempfile.TemporaryDirectory(prefix="xdev_ext-pick-send-path-")
        cls.addClassCleanup(cls.temp.cleanup)

    def run_table(self, name, selector, tx_capable, strict=True):
        source = (self.fixture
                  .replace("/* PRODUCTION_SELECTOR */", selector)
                  .replace("/* PRODUCTION_TX_CAPABLE */", tx_capable))
        path = Path(self.temp.name)
        (path / f"{name}.c").write_text(source)
        # A mutant leaves a parameter or helper unused: warn, do not fail.
        flags = ["-Wall", "-Wextra", "-Werror"] if strict else ["-w"]
        build = subprocess.run([self.cc, "-std=gnu11", "-O2", *flags,
                                str(path / f"{name}.c"), "-o", str(path / name)],
                               text=True, capture_output=True)
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        return subprocess.run([str(path / name)], text=True, capture_output=True,
                              timeout=10)

    def test_truth_table_holds_for_selector_and_dispatch_probe(self):
        run = self.run_table("production", self.selector, self.tx_capable)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("RESULT: PASS", run.stdout)
        self.assertNotIn("FAIL", run.stdout)
        self.assertEqual(len(re.findall(r"^\s*\d+ \|", run.stdout, re.M)), 16,
                         run.stdout)

    def test_dispatch_decides_with_tx_capable_under_feature_guard(self):
        send = re.search(r"case IO_UNIFIED_OP_SEND: \{.*?\n\t\tbreak;", self.unified,
                         re.S)
        self.assertIsNotNone(send, "SEND dispatch case missing")
        body = send.group(0)
        probe = re.findall(re.escape(FEATURE_GUARD) +
                           r"\n\t\tafxdp = xsk_kernel_tx_capable\(send_sock\);\n#endif",
                           body)
        self.assertEqual(len(probe), 1, "afxdp must come from the probe, guarded")
        self.assertEqual(len(re.findall(r"^\t\tbool afxdp = false;$", body, re.M)), 1,
                         "afxdp starts false")
        self.assertEqual(len(re.findall(r"\bafxdp\s*=[^=]", body)), 2,
                         "afxdp is set only by its declaration and the probe")
        self.assertRegex(body, re.escape(FEATURE_GUARD) +
                         r"\n\t\tif \(afxdp\) \{\n\t\t\tret = io_unified_do_send_xdp\(")

    def test_mutation_selector_without_bound_check_fails(self):
        mutated = self.selector.replace("xsk_bound && ", "", 1)
        self.assertNotEqual(mutated, self.selector)
        run = self.run_table("selector_no_bound", mutated, self.tx_capable,
                             strict=False)
        self.assertEqual(run.returncode, 1, run.stdout)
        self.assertIn("selector disagrees with the contract", run.stdout)

    def test_mutation_selector_ignoring_compiled_fails(self):
        mutated = self.selector.replace("if (!afxdp_compiled)", "if (0)", 1)
        self.assertNotEqual(mutated, self.selector)
        run = self.run_table("selector_no_compiled", mutated, self.tx_capable,
                             strict=False)
        self.assertEqual(run.returncode, 1, run.stdout)
        self.assertIn("not compiled in must force SOCK", run.stdout)

    def test_mutation_probe_without_bound_check_fails(self):
        mutated = re.sub(r"\tif \(!xsk_is_bound\(xs\)\)\n\t\treturn false;\n", "",
                         self.tx_capable, count=1)
        self.assertNotEqual(mutated, self.tx_capable)
        run = self.run_table("probe_no_bound", self.selector, mutated,
                             strict=False)
        self.assertEqual(run.returncode, 1, run.stdout)
        self.assertIn("dispatch probe disagrees with the contract", run.stdout)

    def test_mutation_probe_without_tx_ring_fails(self):
        mutated = self.tx_capable.replace("return tx && pool;", "return pool;", 1)
        self.assertNotEqual(mutated, self.tx_capable)
        run = self.run_table("probe_no_tx", self.selector, mutated,
                             strict=False)
        self.assertEqual(run.returncode, 1, run.stdout)
        self.assertIn("dispatch probe disagrees with the contract", run.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
