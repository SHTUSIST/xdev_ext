#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Caller-bound Direct CE controls (G08-G10) and dormant CXL first-page offset (G18).

Compiles the actual RmP2PUmemDmaRequestDirect, _p2pCreateMemDesc, the dormant
RmP2PRegisterUmemBuffer / RmP2PUmemDmaRequest / RmP2PUnregisterUmemBuffer group
(p2p_umem.c) and the rm_p2p_umem_dma_request bridge (osapi.c) with the real
chunk/window helper headers.  G08-G10 are positive controls expected to hold
on the current tree; G18 records whether the dormant registration preserves
an unaligned range's first byte (or refuses the range).  Host C only.
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
OSAPI = "src/nvidia/arch/nvalloc/unix/src/osapi.c"
CHUNK_H = ex.GPU / "src/nvidia/inc/kernel/mem_mgr/p2p_umem_chunk.h"
VIDMEM_H = ex.GPU / "src/nvidia/inc/kernel/mem_mgr/p2p_umem_vidmem.h"
FIXTURE = ex.HERE / "nv_xdev_ext_direct_dma_harness.c"
FUNCTIONS = ("_p2pCanUseHugePages", "_p2pCreateMemDesc", "RmP2PRegisterUmemBuffer",
             "RmP2PUnregisterUmemBuffer", "RmP2PUmemDmaRequest", "RmP2PUmemDmaRequestDirect")
CONTROLS = ("refuse-before-push", "offsets-and-segments", "refusal-vs-entered-copy",
            "bridge-poison", "cxl-aligned")
G18 = ("cxl-unaligned",)


def p2p_umem_pieces(text):
    enum = re.search(r"typedef enum\s*\{[^}]*\}\s*NV_P2P_BUFFER_TYPE;", text, re.S)
    defines = re.findall(r"(?m)^#define\s+P2P_(?:DMA_FLAG|PAGE_SIZE|DEFAULT_PAGE|MAX)\w*[^\n]*$",
                         text)
    statics = re.findall(r"(?m)^static Nv(?:U32|U64) g_p2p\w+ = 0;$", text)
    if not enum or not defines or len(statics) != 2:
        raise AssertionError("actual p2p_umem.c registration state missing")
    parts = [enum.group()] + defines + [ex.typedef_struct(text, "P2P_UMEM_BUFFER_HANDLE")]
    parts += statics
    names = list(FUNCTIONS)
    # Helpers added for the offset representation stay with their callers.
    bodies = "".join(ex.function(text, n) for n in names)
    for helper in sorted(set(re.findall(r"\b(_p2p\w+)\s*\(", bodies))):
        if helper not in names and ex.has_function(text, helper):
            names.insert(0, helper)
    parts += [ex.function(text, n) for n in names]
    return "\n\n".join(parts) + "\n"


class DirectDma(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".direct-dma-")
        p2p, p2p_h, osapi = ex.read(P2P_UMEM), ex.read(P2P_H), ex.read(OSAPI)
        cls.build.write("nv_xdev_ext_direct_dma_types.h", "\n".join([
            ex.typedef_struct(p2p_h, "P2P_UMEM_VIDMEM_BINDING"),
            ex.typedef_struct(p2p_h, "P2P_UMEM_XFER"),
            "#define P2P_UMEM_MAX_XFERS " +
            re.search(r"#define\s+P2P_UMEM_MAX_XFERS\s+(\d+)", p2p_h).group(1),
            '#include "%s"' % CHUNK_H, '#include "%s"' % VIDMEM_H]) + "\n")
        cls.build.write("nv_xdev_ext_direct_dma_actual.inc",
                        ex.license_header(p2p) + p2p_umem_pieces(p2p) + "\n" +
                        ex.function(osapi, "rm_p2p_umem_dma_request") + "\n")
        print(f"actual sha256 p2p_umem.c={ex.sha(p2p)} osapi.c={ex.sha(osapi)}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            out = "direct-dma-" + Path(cc).name
            result, command = cls.build.compile(FIXTURE, out, compiler=cc)
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

    def test_g08_g09_g10_direct_controls(self):
        self.run_cases(CONTROLS)

    def test_g18_dormant_cxl_unaligned_first_byte(self):
        self.run_cases(G18)


if __name__ == "__main__":
    unittest.main(verbosity=2)
