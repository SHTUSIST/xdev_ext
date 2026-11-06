#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""NV_ESC_XDEV_EXT_CE_ATTACH_MEMORY: one CUDA export per CE stage fd.

Compiles the actual nv_xdev_ext_ce_memory_attach() / _release() bodies
(nv.c) and the ioctl struct (nv-ioctl.h) into a host program with stubs for
the export fd lookup and allocation.  A stage fd keeps a reference on the
CUDA POSIX-FD export (a control fd) from attach until close, refuses bad
arguments before touching the fd, refuses non-control fds and a second
attach, and releases exactly once.  Host C only; no GPU.
"""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

NV_C = "kernel-open/nvidia/nv.c"
NV_IOCTL_H = "kernel-open/common/inc/nv-ioctl.h"
FIXTURE = ex.HERE / "nv_xdev_ext_ce_memory_attach_harness.c"
CASES = ("attach", "bad-args", "not-control-fd", "alloc-fail", "attach-twice")
FUNCTIONS = ("nv_xdev_ext_ce_memory_attach", "nv_xdev_ext_ce_memory_release")


class CeMemoryAttach(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".ce-memory-attach-")
        nv, ioctl_h = ex.read(NV_C), ex.read(NV_IOCTL_H)
        cls.missing = [name for name in FUNCTIONS if not ex.has_function(nv, name)]
        if "nv_ioctl_xdev_ext_ce_attach_memory" not in ioctl_h:
            cls.missing.append("nv_ioctl_xdev_ext_ce_attach_memory_t")
        cls.binary = cls.error = None
        if cls.missing:
            return
        cls.build.write("nv_xdev_ext_ce_memory_attach_types.h",
                        ex.typedef_struct(ioctl_h, "nv_ioctl_xdev_ext_ce_attach_memory_t") + "\n")
        cls.build.write("nv_xdev_ext_ce_memory_attach_actual.inc", "\n\n".join(
            ex.function(nv, name) for name in FUNCTIONS) + "\n")
        print(f"actual sha256 nv.c={ex.sha(nv)} nv-ioctl.h={ex.sha(ioctl_h)}")
        result, command = cls.build.compile(FIXTURE, "ce-memory-attach")
        if result.returncode:
            cls.error = " ".join(command) + "\n" + result.stderr[:3000]
        else:
            cls.binary = "ce-memory-attach"

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_attach_holds_one_export_per_stage_fd(self):
        self.assertEqual(self.missing, [], "feature missing: " + ", ".join(self.missing))
        self.assertIsNone(self.error, f"fixture did not compile:\n{self.error}")
        for case in CASES:
            with self.subTest(case=case):
                result = self.build.run(self.binary, case)
                self.assertEqual(result.returncode, 0, f"{case}\n{result.stdout}\n{result.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
