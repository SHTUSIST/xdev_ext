#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""G2 on the ioctl path: registered host pages reach the CE as DMA-API IOVAs.

Compiles the actual nv_pin_host_region(), nv_unpin_host_region() and, once it
exists, nv_host_region_dma_map() from nv-p2p.c with host stubs, in the default
(IOVA) build and the NV_XDEV_EXT_CE_PHYS_ADDR build.  Host C only.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

NV_P2P = "kernel-open/nvidia/nv-p2p.c"
FIXTURE = ex.HERE / "nv_xdev_ext_host_region_dma_harness.c"
FUNCTIONS = ("nv_pin_host_region", "nv_unpin_host_region",
             "nv_get_host_region_pages", "nv_get_cxl_buffer_pages", "nv_get_cxl_buffer_hugepages")
OPTIONAL = ("nv_host_region_dma_map",)
IOVA_CASES = ("pin-no-phys", "map-iova", "map-twice", "map-fail", "unpin-order", "unmapped-getters")
PHYS_CASES = ("phys-pin", "phys-map", "unmapped-getters")


def actual(text):
    enum = re.search(r"typedef enum\s*\{[^}]*\}\s*nv_p2p_buffer_type_t;", text, re.S)
    if not enum:
        raise AssertionError("actual buffer type enum missing")
    parts = [ex.license_header(text), enum.group(),
             ex.typedef_struct(text, "nv_p2p_umem_buffer_t"),
             "typedef nv_p2p_umem_buffer_t cxl_pinned_buffer_t;"]
    have_map = ex.has_function(text, "nv_host_region_dma_map")
    names = FUNCTIONS + (OPTIONAL if have_map else ())
    # Static nv_host_region_* helpers called by these bodies stay with them.
    bodies = "".join(ex.function(text, name) for name in names)
    for helper in sorted(set(re.findall(r"\b(nv_host_region_\w+)\s*\(", bodies))):
        if helper not in names and ex.has_function(text, helper):
            names = (helper,) + names
    parts += [ex.function(text, name) for name in names]
    return "\n\n".join(parts) + "\n", have_map


class HostRegionDma(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".host-region-dma-")
        text = ex.read(NV_P2P)
        generated, cls.have_map = actual(text)
        cls.build.write("nv_xdev_ext_host_region_actual.inc", generated)
        print(f"actual {NV_P2P} sha256={ex.sha(text)} nv_host_region_dma_map="
              f"{int(cls.have_map)}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            for strict in (0, 1):
                for variant, defines in (("iova", ()), ("phys", ("NV_XDEV_EXT_CE_PHYS_ADDR",))):
                    out = f"host-region-{Path(cc).name}-{variant}-strict{strict}"
                    result, command = cls.build.compile(
                        FIXTURE, out, defines=(f"HAVE_DMA_MAP={int(cls.have_map)}",
                            f"NV_P2P_UMEM_STRICT_SECURITY_CHECKS={strict}") + defines,
                        compiler=cc)
                    key = (cc, variant, strict)
                    if result.returncode:
                        cls.errors[key] = " ".join(command) + "\n" + result.stderr[:3000]
                    else:
                        cls.binaries[key] = out

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_cases(self, variant, cases):
        for cc in ex.compilers():
            for strict in (0, 1):
                key = (cc, variant, strict)
                with self.subTest(compiler=cc, variant=variant, strict=strict):
                    if key in self.errors:
                        self.fail("fixture did not compile:\n" + self.errors[key])
                    for case in cases:
                        with self.subTest(case=case):
                            result = self.build.run(self.binaries[key], case)
                            self.assertEqual(result.returncode, 0,
                                             f"{case}\n{result.stdout}\n{result.stderr}")

    def test_g2_iova_build_maps_host_region_for_gpu_device(self):
        self.run_cases("iova", IOVA_CASES)

    def test_g2_phys_build_keeps_identity_only_addresses(self):
        self.run_cases("phys", PHYS_CASES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
