#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real NVMe submit body under deterministic native API shims.

Run directly with python3. Sparse checkouts read the same HEAD via local git;
XDEV_EXT_NVME_TEST_SOURCE may explicitly select a working tree source file.
"""

import errno
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RELATIVE_SOURCE = "drivers/nvme/host/xdev_ext_mech_nvme.c"


class NvmeNowait(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        source_path = Path(os.environ.get("XDEV_EXT_NVME_TEST_SOURCE",
                                          str(ROOT / RELATIVE_SOURCE)))
        if source_path.is_file():
            source = source_path.read_text()
        else:
            source = subprocess.run(["git", "show", "HEAD:./" + RELATIVE_SOURCE],
                                    cwd=ROOT, check=True, text=True,
                                    capture_output=True).stdout
        # Retain every statement in the real function; only dependencies are faked.
        function = re.search(r"^static int nvme_xdev_ext_class_submit\([^)]*\)\s*"
                             r"\{.*?^\}", source, re.MULTILINE | re.DOTALL)
        if function is None:
            raise RuntimeError("production nvme_xdev_ext_class_submit function missing")
        cls.temp = tempfile.TemporaryDirectory(prefix="xdev_ext-nvme-nowait-")
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        fixture = (HERE / "xdev_ext_mech_nvme_nowait_fixture.c").read_text()
        # The stage-polling helpers the submit calls, verbatim, before it.
        helpers = [re.search(r"^static [^;{}]*\b" + name + r"\([^)]*\)\s*\{.*?^\}",
                             source, re.MULTILINE | re.DOTALL)
                   for name in ("nvme_xdev_ext_poll_opf", "nvme_xdev_ext_poll_check",
                                "nvme_xdev_ext_poll_arm")]
        if not all(helpers):
            raise RuntimeError("production stage-polling helpers missing")
        production = "\n".join(h[0] for h in helpers) + "\n" + function[0]
        generated = path / "submit.c"
        generated.write_text(fixture.replace("/* PRODUCTION_SUBMIT */", production))
        cls.probe = path / "probe"
        build = subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                "-DCONFIG_XDEV_EXT_MECH_ZEROCOPY", str(generated),
                                "-o", str(cls.probe)], text=True, capture_output=True)
        if build.returncode:
            raise RuntimeError("host shim compile failed:\n" + build.stdout + build.stderr)

    def run_submit(self, mode):
        p = subprocess.run([str(self.probe), mode], text=True, capture_output=True,
                           timeout=3, check=True)
        return {key: int(value) for key, value in
                (field.split("=", 1) for field in p.stdout.split())}

    def assert_no_native_work(self, result):
        for key in ("done_allocs", "maps", "handoffs", "completions"):
            self.assertEqual(result[key], 0, result)

    def test_full_tags_return_retry_without_wait_or_native_work(self):
        result = self.run_submit("full")
        self.assertEqual(result["rc"], -errno.EAGAIN, result)
        self.assertEqual(result["blocked"], 0, result)
        self.assertTrue(result["flags"] & 1, result)
        self.assertEqual(result["tag_calls"], 1, result)
        self.assert_no_native_work(result)

    def test_real_allocator_error_is_preserved_without_native_work(self):
        result = self.run_submit("nodev")
        self.assertEqual(result["rc"], -errno.ENODEV, result)
        self.assertEqual(result["tag_calls"], 1, result)
        self.assert_no_native_work(result)

    def test_success_hands_off_exactly_once(self):
        result = self.run_submit("success")
        self.assertEqual(result["rc"], 0, result)
        self.assertEqual(result["blocked"], 0, result)
        self.assertEqual(result["done_allocs"], 0, result)
        for key in ("tag_calls", "maps", "handoffs", "completions"):
            self.assertEqual(result[key], 1, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
