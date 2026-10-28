#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RM side of CE completion by event (G1) and active async controls (G11).

Copies the p2p_umem.c CE host group (P2P_UMEM_CE_HOST typedef through
RmP2PUmemCeHostUnbind, including any helper placed between them) and the real
CeUtils callback-list functions from ce_utils.c unchanged, then drives them
from nv_xdev_ext_ce_rm_event_harness.c.  Host C only; no GPU.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

P2P_UMEM = "src/nvidia/src/kernel/mem_mgr/p2p_umem.c"
P2P_H = "src/nvidia/inc/kernel/mem_mgr/p2p.h"
CE_UTILS = "src/nvidia/src/kernel/gpu/mem_mgr/ce_utils.c"
CE_NVOC = "src/nvidia/generated/g_ce_utils_nvoc.h"
VIDMEM_H = ex.GPU / "src/nvidia/inc/kernel/mem_mgr/p2p_umem_vidmem.h"
FIXTURE = ex.HERE / "nv_xdev_ext_ce_rm_event_harness.c"
CASES_G1 = ("bind-flags", "one-callback-per-plan", "event-forward", "event-poisoned",
            "event-unbind-pending")
CASES_G11 = ("invalidate", "progress-watermark", "resolve-before-push", "plan-before-push")


def ce_host_group(text):
    start = text.index("typedef struct P2P_UMEM_CE_HOST")
    end = ex.find_function(text, "RmP2PUmemCeHostUnbind")
    if end is None:
        raise AssertionError("actual RmP2PUmemCeHostUnbind missing")
    return text[start:end[1]] + "\n"


def event_api(p2p_h):
    return 1 if re.search(r"\bP2P_UMEM_CE_EVENT\b", p2p_h) else 0


def types(p2p_h, nvoc):
    parts = [ex.typedef_struct(nvoc, "CeUtilsCallback"),
             ex.typedef_struct(nvoc, "CEUTILS_MEMCOPY_PARAMS"),
             ex.typedef_struct(p2p_h, "P2P_UMEM_VIDMEM_BINDING"),
             ex.typedef_struct(p2p_h, "P2P_UMEM_XFER"),
             "#define P2P_UMEM_MAX_XFERS " +
             re.search(r"#define\s+P2P_UMEM_MAX_XFERS\s+(\d+)", p2p_h).group(1)]
    event = re.search(r"typedef[^;]*\bP2P_UMEM_CE_EVENT\b[^;]*;", p2p_h)
    if event:
        parts.append(event.group())
    parts.append('#include "%s"' % VIDMEM_H)
    return "\n".join(parts) + "\n"


class RmEventHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".ce-rm-event-")
        p2p = ex.read(P2P_UMEM)
        p2p_h = ex.read(P2P_H)
        ce = ex.read(CE_UTILS)
        nvoc = ex.read(CE_NVOC)
        cls.build.write("nv_xdev_ext_ce_rm_event_types.h", types(p2p_h, nvoc))
        cls.build.write("nv_xdev_ext_ce_rm_event_ceutils.inc", "\n\n".join([
            ex.function(ce, "ceutilsUpdateProgress_IMPL"),
            "#define ceutilsUpdateProgress ceutilsUpdateProgress_IMPL",
            ex.function(ce, "_ceutilsProcessCompletionCallbacks"),
            ex.function(ce, "_ceutilsInsertCallback"),
            ex.function(ce, "_ceutilsSemaphoreEventCallback")]) + "\n")
        cls.build.write("nv_xdev_ext_ce_rm_event_actual.inc",
                        ex.license_header(p2p) + ce_host_group(p2p))
        cls.api = event_api(p2p_h)
        print(f"actual {P2P_UMEM} sha256={ex.sha(p2p)} {CE_UTILS} sha256={ex.sha(ce)} "
              f"event_api={cls.api}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            name = "rm-event-" + Path(cc).name
            result, command = cls.build.compile(
                FIXTURE, name, defines=(f"HARNESS_RM_EVENT_API={cls.api}",), compiler=cc)
            if result.returncode:
                cls.errors[cc] = " ".join(command) + "\n" + result.stderr[:3000]
            else:
                cls.binaries[cc] = name

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_cases(self, cases):
        for cc in ex.compilers():
            with self.subTest(compiler=cc):
                if cc in self.errors:
                    self.fail("fixture did not compile:\n" + self.errors[cc])
                for case in cases:
                    with self.subTest(case=case):
                        result = self.build.run(self.binaries[cc], case)
                        self.assertEqual(result.returncode, 0,
                                         f"{case}\n{result.stdout}\n{result.stderr}")

    def test_g1_rm_ce_host_completion_by_semaphore_event(self):
        self.run_cases(CASES_G1)

    def test_g11_active_async_controls(self):
        self.run_cases(CASES_G11)


if __name__ == "__main__":
    unittest.main(verbosity=2)
