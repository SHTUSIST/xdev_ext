#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RM lock contract of the CE host entry points (osapi.c).

CeUtils, which the CE host bind constructs and the other entry points use,
runs under the API lock and every GPU lock in NVIDIA's own CeUtils API
(NV_CE_UTILS: RS_FLAGS_ACQUIRE_GPUS_LOCK; memcopy/check-progress controls
without NO_GPUS_LOCK), and its channel setup releases and reacquires all GPU
locks (mem_utils_gm107.c).  Called with the API lock only, the bind came back
owning every GPU lock; on the RTX 5090 the next CE stage bind of the same
CREATE then found "GPU lock already acquired by this thread" and its API lock
refused with NV_ERR_INVALID_LOCK_STATE (0x2f), and RM wedged.

Compiles the actual rm_p2p_umem_ce_host_bind / _unbind / _async_submit /
_progress bodies (and any static helper they use) against stubs that follow
RM's lock rules.  Host C only; no GPU.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

OSAPI = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
FIXTURE = ex.HERE / "nv_xdev_ext_ce_rm_locks_harness.c"
ENTRIES = ("rm_p2p_umem_ce_host_bind", "rm_p2p_umem_ce_host_unbind",
           "rm_p2p_umem_ce_async_submit", "rm_p2p_umem_ce_progress")
HELPERS = ("_rmP2PUmemCeLocksAcquire", "_rmP2PUmemCeLocksRelease")
CASES = ("bind", "controls", "lock-failures")


class CeRmLocks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".ce-rm-locks-")
        osapi = ex.read(OSAPI)
        parts = [ex.license_header(osapi)]
        parts += [ex.function(osapi, name) for name in HELPERS if ex.has_function(osapi, name)]
        parts += [ex.function(osapi, name) for name in ENTRIES]
        cls.build.write("nv_xdev_ext_ce_rm_locks_actual.inc", "\n\n".join(parts) + "\n")
        print(f"actual sha256 osapi.c={ex.sha(osapi)}")
        result, command = cls.build.compile(FIXTURE, "ce-rm-locks")
        cls.error = None if result.returncode == 0 else " ".join(command) + "\n" + result.stderr[:3000]

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_ce_entry_points_hold_the_api_and_gpu_locks_and_leave_none(self):
        self.assertIsNone(self.error, f"fixture did not compile:\n{self.error}")
        for case in CASES:
            with self.subTest(case=case):
                result = self.build.run("ce-rm-locks", case)
                self.assertEqual(result.returncode, 0, f"{case}\n{result.stdout}\n{result.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
