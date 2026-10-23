#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native peer cleanup status and reference conservation (G15-G17).

Compiles the actual NVIDIA persistent put / DMA unmap bodies from nv-p2p.c
together with the owned provider adapter from nv-xdev_ext-peer.c and checks
that a failed native cleanup keeps its owner (device reference, page table,
mapping record) and reports failure.  Host C only; no GPU or peer device.
"""
from pathlib import Path
import re
import os
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

NV_P2P = "kernel-open/nvidia/nv-p2p.c"
NV_P2P_H = "kernel-open/nvidia/nv-p2p.h"
PEER = "kernel-open/nvidia/nv-xdev_ext-peer.c"
FIXTURE = ex.HERE / "nv_xdev_ext_native_peer_cleanup_harness.c"
P2P_FUNCTIONS = ("nvidia_p2p_map_status", "nv_p2p_insert_dma_mapping",
                 "nv_p2p_remove_dma_mapping", "nv_p2p_free_dma_mapping",
                 "nv_p2p_free_page_table", "nv_p2p_put_pages",
                 "nvidia_p2p_put_pages_persistent", "nvidia_p2p_dma_map_pages",
                 "nvidia_p2p_dma_unmap_pages")
PEER_FUNCTIONS = ("nv_xdev_ext_peer_pin", "nv_xdev_ext_peer_unpin", "nv_xdev_ext_peer_unmap")
CONTROLS = ("put-success", "unmap-success", "peer-pin-mismatch-put-ok")
G15 = ("put-fail-keeps-ref", "peer-unpin-fail")
G16 = ("unmap-alloc-fail", "unmap-os-fail", "peer-unmap-propagates", "table-cleanup-failure", "map-owner-preallocated")
G17 = ("peer-pin-mismatch-put-fail",)


def public_header(text):
    start = text.index("#define NVIDIA_P2P_MAJOR_VERSION_MASK")
    end = text.index("} nvidia_p2p_dma_mapping_t;") + len("} nvidia_p2p_dma_mapping_t;")
    return "#define ENOTSUPP 524\n" + text[start:end] + "\n"


def p2p_bodies(text):
    enum = re.search(r"typedef enum nv_p2p_page_table_type\s*\{[^}]*\}\s*"
                     r"nv_p2p_page_table_type_t;", text)
    table = re.search(r"static struct nvidia_status_mapping\s*\{.*?\};\s*\n", text, re.S)
    table_macro = re.search(r"#define NVIDIA_STATUS_MAPPINGS[^\n]*\\\n[^\n]*\n", text)
    sizes = re.search(r"static NvU32 nvidia_p2p_page_size_mappings\[[^;]*;", text, re.S)
    if not (enum and table and table_macro and sizes):
        raise AssertionError("actual nv-p2p.c helper definitions missing")
    parts = [ex.license_header(text), enum.group(),
             ex.typedef_struct(text, "nv_p2p_dma_mapping_t"),
             ex.typedef_struct(text, "nv_p2p_mem_info_t"),
             table.group(), table_macro.group(), sizes.group()]
    names = list(P2P_FUNCTIONS)
    # New status-preserving helpers called by these bodies stay with them.
    bodies = "".join(ex.function(text, n) for n in names)
    for helper in sorted(set(re.findall(r"\b(nv_p2p_\w+)\s*\(", bodies))):
        if helper not in names and ex.has_function(text, helper) and \
                helper.startswith(("nv_p2p_free_", "nv_p2p_unmap_", "nv_p2p_dma_")):
            names.insert(0, helper)
    parts += [ex.function(text, n) for n in names]
    return "\n\n".join(parts) + "\n"


def peer_bodies(text):
    parts = [ex.struct(text, "nv_xdev_ext_peer_allocation")]
    if ex.has_function(text, "nv_xdev_ext_peer_quarantine"):
        parts += re.findall(r"(?m)^static (?:LIST_HEAD|DEFINE_MUTEX)\([^\n]*\);$", text)
        parts.append(ex.function(text, "nv_xdev_ext_peer_quarantine"))
    return "\n\n".join(parts + [ex.function(text, n) for n in PEER_FUNCTIONS]) + "\n"


class NativePeerCleanup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = ex.Build(".native-peer-")
        p2p, header, peer = ex.read(NV_P2P), ex.read(NV_P2P_H), ex.read(PEER)
        revision = os.environ.get("XDEV_EXT_PEER_RED_REVISION")
        if revision:
            p2p = subprocess.check_output(["git", "-C", str(ex.REPO), "show",
                revision + ":gpu/" + NV_P2P], text=True)
        preallocated = int("*node" in ex.function(p2p, "nv_p2p_insert_dma_mapping").split("{")[0])
        cls.build.write("nv_xdev_ext_native_peer_public.h", public_header(header))
        cls.build.write("nv_xdev_ext_native_peer_p2p.inc", p2p_bodies(p2p))
        cls.build.write("nv_xdev_ext_native_peer_provider.inc", peer_bodies(peer))
        print(f"actual sha256 nv-p2p.c={ex.sha(p2p)} nv-p2p.h={ex.sha(header)} "
              f"nv-xdev_ext-peer.c={ex.sha(peer)}")
        cls.binaries, cls.errors = {}, {}
        for cc in ex.compilers():
            out = "native-peer-" + Path(cc).name
            result, command = cls.build.compile(FIXTURE, out, compiler=cc,
                                                defines=(f"HARNESS_PREALLOC_API={preallocated}",),
                                                extra=("-Wno-type-limits",))
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

    def test_controls_normal_success(self):
        self.run_cases(CONTROLS)

    def test_g15_failed_persistent_put_keeps_device_reference(self):
        self.run_cases(G15)

    def test_g16_failed_native_unmap_reports_and_keeps_mapping(self):
        self.run_cases(G16)

    def test_g17_pin_mismatch_with_failed_put_keeps_gpu_lifetime(self):
        self.run_cases(G17)


if __name__ == "__main__":
    unittest.main(verbosity=2)
