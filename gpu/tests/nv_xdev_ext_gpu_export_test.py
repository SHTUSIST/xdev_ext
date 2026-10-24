#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve the independent G01-G06 oracles and regenerate actual bodies.

The fixture is byte-identical to the earlier independent export-red-v1
fixture (sha256 4485573f4aa0fadcb148e4850098e54924c217972cdbca07a8e501f74eeb6788).
Only dependency boundaries are stubbed; current registration, query and DMA
bodies and handle layouts are extracted without rewriting them.
"""
from pathlib import Path
import re
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex

FIXTURE = ex.HERE / "nv_xdev_ext_gpu_export_harness.c"
LOWER = "kernel-open/nvidia/nv-p2p.c"
RM = "src/nvidia/src/kernel/mem_mgr/p2p_umem.c"
FUNCTIONS = ("_p2pCanUseHugePages", "_p2pCreateMemDesc", "RmP2PRegisterUmemBuffer",
             "RmP2PUnregisterUmemBuffer", "RmP2PGetUmemPages", "RmP2PUmemDmaRequest")
CASES = ("fixture-selfcheck", "G01-lower", "G01-rm", "G02-to", "G02-from", "G03-pages",
         "G04-wrap", "G04-zero-frame", "G04-nonpower", "G04-nonmultiple", "G04-count",
         "G05-repeat", "G05-old-cleanup", "G05-quota", "G05-lower-alloc", "G05-rm-alloc",
         "G05-inner-alloc", "G06-xsk", "G06-host", "G06-host-pin-fail", "G06-host-get-fail",
         "G06-cxl", "G06-cxl-pin-fail", "G06-cxl-get-fail")


class GpuExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".gpu-export-")
        # A sparse overlay may use an already prepared NVIDIA tree read-only.
        sdk = Path(os.environ.get("XDEV_EXT_NVIDIA_SDK", str(ex.GPU))) / "kernel-open/common/inc"
        if not (sdk / "nvtypes.h").is_file():
            raise AssertionError("prepared NVIDIA SDK headers required; set XDEV_EXT_NVIDIA_SDK")
        lower, rm = ex.read(LOWER), ex.read(RM)
        enum = re.search(r"typedef enum\s*\{[^}]*\}\s*nv_p2p_buffer_type_t;", lower, re.S)
        if not enum:
            raise AssertionError("production buffer enum missing")
        parts = [ex.license_header(lower), enum.group(),
                 ex.typedef_struct(lower, "nv_p2p_umem_buffer_t"),
                 ex.typedef_struct(rm, "P2P_UMEM_BUFFER_HANDLE")]
        parts += [ex.function(lower, n) for n in ("nv_register_gpu_umem", "nv_unregister_gpu_umem")]
        parts += [ex.function(rm, n) for n in FUNCTIONS]
        cls.build.write("independent_export_actual.inc", "\n\n".join(parts) + "\n")
        print(f"actual sha256 nv-p2p.c={ex.sha(lower)} p2p_umem.c={ex.sha(rm)}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            for strict in (0, 1):
                key = (cc, strict)
                out = f"export-{Path(cc).name}-strict{strict}"
                result, command = cls.build.compile(FIXTURE, out, compiler=cc,
                    defines=("NVTYPES_USE_STDINT=1", f"NV_P2P_UMEM_STRICT_SECURITY_CHECKS={strict}"),
                    extra=("-I", str(sdk)))
                if result.returncode:
                    cls.errors[key] = " ".join(command) + "\n" + result.stderr
                else:
                    cls.binaries[key] = out

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def test_g01_g06(self):
        for cc in ex.compilers():
            for strict in (0, 1):
                key = (cc, strict)
                with self.subTest(compiler=cc, strict=strict):
                    if key in self.errors:
                        self.fail("fixture did not compile:\n" + self.errors[key])
                    for case in CASES:
                        with self.subTest(case=case):
                            result = self.build.run(self.binaries[key], case)
                            self.assertEqual(result.returncode, 0,
                                             f"{case}\n{result.stdout}\n{result.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
