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
NV_H = "kernel-open/common/inc/nv.h"
FIXTURE = ex.HERE / "nv_xdev_ext_vidmem_owner_harness.c"
CONTROLS = ("resolve", "bind-uuid-mismatch", "bind-wrong-gpu-before-dup", "bridge-lock-fail", "unbind-success-order",
            "unbind-stack-fail")
G12 = ("unbind-lock-fail", "bind-cleanup-free-fail")
G13 = ("rm-free-fail", "outer-rm-free-fail", "bridge-uuid-null-free-fail")
# A window named by a CUDA POSIX-FD export (cuMemExportToShareableHandle):
# RM imports the fd's single export handle instead of resolving a GPU VA in
# third-party P2P registrations, then applies the same checks and binding.
EXPORT_RM = ("export-rm-bind", "export-rm-parent-retry", "export-rm-import-fail",
             "export-rm-reject", "export-rm-args")
EXPORT_BRIDGE = ("export-bridge", "export-bridge-handles", "export-bridge-device",
                 "export-bridge-lock-fail", "export-bridge-uuid-null-free-fail")
EXPORT_NV = ("export-nv-bind", "export-nv-uuid-mismatch", "export-nv-args")
# Shared static helpers come first: the actual bodies call them.
P2P_HELPERS = ("_rmP2PUmemVidmemBindDup",)
OSAPI_HELPERS = ("_rmP2PUmemVidmemBound", "_rmP2PUmemExportHandle")
NV_P2P_HELPERS = ("nv_p2p_vidmem_bind_window",)
EXPORT_FUNCTIONS = ((P2P_C, "RmP2PUmemVidmemBindExport"),
                    (OSAPI, "rm_p2p_umem_vidmem_bind_export"),
                    (NV_P2P, "nv_p2p_vidmem_bind_export"))


class VidmemOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".vidmem-owner-")
        p2p, p2p_h, osapi, nvp2p = (ex.read(P2P_C), ex.read(P2P_H), ex.read(OSAPI),
                                    ex.read(NV_P2P))
        texts = {P2P_C: p2p, OSAPI: osapi, NV_P2P: nvp2p}
        cls.missing = [name for path, name in EXPORT_FUNCTIONS
                       if not ex.has_function(texts[path], name)]
        export = int(not cls.missing)

        def helpers(text, names):
            return [ex.function(text, name) for name in names if ex.has_function(text, name)]
        rm_unbind = ex.function(p2p, "RmP2PUmemVidmemUnbind")
        nv_unbind = ex.function(nvp2p, "nv_p2p_vidmem_unbind")
        cls.rm_status = int(bool(re.match(r"\s*NV_STATUS\b", rm_unbind)))
        cls.nv_status = int(bool(re.match(r"\s*NV_STATUS\b", nv_unbind)))
        cls.build.write("nv_xdev_ext_vidmem_owner_types.h", "\n".join([
            ex.typedef_struct(p2p_h, "P2P_UMEM_VIDMEM_BINDING"),
            "typedef struct nv_file_private_t nv_file_private_t;",
            ex.struct(ex.read(NV_H), "nv_file_private_t")]) + "\n")
        cls.build.write("nv_xdev_ext_vidmem_owner_actual.inc", "\n\n".join([
            ex.license_header(p2p), *helpers(p2p, P2P_HELPERS),
            ex.function(p2p, "RmP2PUmemVidmemBind"),
            *helpers(p2p, ("RmP2PUmemVidmemBindExport",)),
            ex.function(p2p, "RmP2PUmemVidmemResolve"), rm_unbind,
            *helpers(osapi, OSAPI_HELPERS),
            ex.function(osapi, "rm_p2p_umem_vidmem_bind"),
            *helpers(osapi, ("rm_p2p_umem_vidmem_bind_export",)),
            ex.function(osapi, "rm_p2p_umem_vidmem_unbind"),
            ex.struct(nvp2p, "nv_p2p_vidmem_binding"),
            *helpers(nvp2p, NV_P2P_HELPERS),
            ex.function(nvp2p, "nv_p2p_vidmem_bind"),
            *helpers(nvp2p, ("nv_p2p_vidmem_bind_export",)), nv_unbind]) + "\n")
        print(f"actual sha256 p2p.c={ex.sha(p2p)} osapi.c={ex.sha(osapi)} "
              f"nv-p2p.c={ex.sha(nvp2p)} rm_unbind_status={cls.rm_status} "
              f"nv_unbind_status={cls.nv_status}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            out = "vidmem-owner-" + Path(cc).name
            result, command = cls.build.compile(
                FIXTURE, out, compiler=cc,
                defines=(f"HARNESS_RM_UNBIND_STATUS={cls.rm_status}",
                         f"HARNESS_NV_UNBIND_STATUS={cls.nv_status}",
                         f"HARNESS_EXPORT={export}"))
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

    def test_third_party_window_still_dups_the_registered_handle(self):
        self.run_cases(("bind-third-party-dup",))

    def require_export(self):
        self.assertEqual(self.missing, [], "feature missing: " + ", ".join(self.missing))

    def test_export_rm_imports_the_exported_allocation_and_checks_it(self):
        self.require_export()
        self.run_cases(EXPORT_RM)

    def test_export_bridge_takes_the_single_export_of_the_opened_gpu(self):
        self.require_export()
        self.run_cases(EXPORT_BRIDGE)

    def test_export_outer_bind_keeps_the_device_reference_order(self):
        self.require_export()
        self.run_cases(EXPORT_NV)


if __name__ == "__main__":
    unittest.main(verbosity=2)
