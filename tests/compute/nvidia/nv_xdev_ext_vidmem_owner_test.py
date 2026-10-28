#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Vidmem window ownership on unbind failure (G12-G14) with G07 controls.

Compiles the actual RmP2PUmemVidmemResolve/RmP2PUmemVidmemUnbind (p2p.c),
rm_p2p_umem_vidmem_bind/_unbind (osapi.c) and nv_p2p_vidmem_bind/_unbind
(nv-p2p.c) into one host program with lock, handle, Free and device-reference
stubs.  The cases record what is released, in which order, and on which
failure.  Host C only; no GPU.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

P2P_C = "src/nvidia/src/kernel/gpu/bus/p2p.c"
P2P_H = "src/nvidia/inc/kernel/mem_mgr/p2p.h"
OSAPI = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
NV_P2P = "kernel-open/nvidia/nv-p2p.c"
FIXTURE = ex.HERE / "nv_xdev_ext_vidmem_owner_harness.c"
CONTROLS = ("resolve", "bind-uuid-mismatch", "bind-wrong-gpu-before-dup", "bridge-lock-fail", "unbind-success-order",
            "unbind-stack-fail")
G12 = ("unbind-lock-fail", "bind-cleanup-free-fail")
G13 = ("rm-free-fail", "outer-rm-free-fail", "bridge-uuid-null-free-fail")


class VidmemOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".vidmem-owner-")
        p2p, p2p_h, osapi, nvp2p = (ex.read(P2P_C), ex.read(P2P_H), ex.read(OSAPI),
                                    ex.read(NV_P2P))
        rm_unbind = ex.function(p2p, "RmP2PUmemVidmemUnbind")
        nv_unbind = ex.function(nvp2p, "nv_p2p_vidmem_unbind")
        cls.rm_status = int(bool(re.match(r"\s*NV_STATUS\b", rm_unbind)))
        cls.nv_status = int(bool(re.match(r"\s*NV_STATUS\b", nv_unbind)))
        cls.build.write("nv_xdev_ext_vidmem_owner_types.h",
                        ex.typedef_struct(p2p_h, "P2P_UMEM_VIDMEM_BINDING") + "\n")
        cls.build.write("nv_xdev_ext_vidmem_owner_actual.inc", "\n\n".join([
            ex.license_header(p2p),
            ex.function(p2p, "RmP2PUmemVidmemBind"),
            ex.function(p2p, "RmP2PUmemVidmemResolve"), rm_unbind,
            ex.function(osapi, "rm_p2p_umem_vidmem_bind"),
            ex.function(osapi, "rm_p2p_umem_vidmem_unbind"),
            ex.struct(nvp2p, "nv_p2p_vidmem_binding"),
            ex.function(nvp2p, "nv_p2p_vidmem_bind"), nv_unbind]) + "\n")
        print(f"actual sha256 p2p.c={ex.sha(p2p)} osapi.c={ex.sha(osapi)} "
              f"nv-p2p.c={ex.sha(nvp2p)} rm_unbind_status={cls.rm_status} "
              f"nv_unbind_status={cls.nv_status}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            out = "vidmem-owner-" + Path(cc).name
            result, command = cls.build.compile(
                FIXTURE, out, compiler=cc,
                defines=(f"HARNESS_RM_UNBIND_STATUS={cls.rm_status}",
                         f"HARNESS_NV_UNBIND_STATUS={cls.nv_status}"))
            if result.returncode:
                cls.errors[cc] = " ".join(command) + "\n" + result.stderr[:3000]
            else:
                cls.binaries[cc] = out

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

    def test_g07_g14_controls(self):
        self.run_cases(CONTROLS)

    def test_g08_actual_bind_rejects_invalid_va_and_window(self):
        self.run_cases(("bind-range",))

    def test_g12_lock_failure_retains_window_owner(self):
        self.run_cases(G12)

    def test_g13_free_failure_is_propagated_and_retains_binding(self):
        self.run_cases(G13)


if __name__ == "__main__":
    unittest.main(verbosity=2)
