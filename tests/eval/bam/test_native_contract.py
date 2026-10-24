#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent BaM software contract. No hardware, CUDA substitute, or timings.

BAM_TARGET is the sole implementation-location override. Expected failures on
the current compatibility-patch-only product establish the missing behavior.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TARGET = Path(os.environ.get("BAM_TARGET", Path(__file__).resolve().parent))
REV = "315fadfc5c5c018a64596157bfac94ecbb7d87a2"
SUBREV = "6360203797a3601fa61f3580dc97b2535b2c232d"


def receipt():
    return dict(schema_version=1, upstream_revision=REV,
                backend="bam-native", gpu_initiated=True,
                controller="/dev/libnvm9", namespace_id=7,
                namespace_blocks=1048576, lba_size=512, page_size=4096,
                region_start_lba=128, region_blocks=64,
                direction="read", allow_write=False,
                approved=True, exclusive=True, gpu_uuid="GPU-contract-only",
                execution="physical", iommu="disabled", acs="disabled",
                above_4g=True, cuda_capability=80)


class NativeContract(unittest.TestCase):
    def contract(self):
        path = TARGET / "native_contract.py"
        self.assertTrue(path.is_file(), "missing native BaM qualification/geometry/oracle controller")
        spec = importlib.util.spec_from_file_location("bam_native_contract_under_test", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def test_pinned_real_upstream_and_submodule(self):
        path = TARGET / "native.lock.json"
        self.assertTrue(path.is_file(), "missing verified native BaM revision lock")
        lock = json.loads(path.read_text())
        self.assertEqual(lock["url"], "https://github.com/ZaidQureshi/bam.git")
        self.assertEqual(lock["revision"], REV)
        self.assertEqual(lock["submodule"]["revision"], SUBREV)
        self.assertEqual(lock["submodule"]["path"], "include/freestanding")
        self.assertNotEqual(lock["revision"], "unrecorded")

    def test_last_partial_page_is_bounded_in_lbas(self):
        p = self.contract().plan_io(4608, 4096, 512, 128, 9)
        self.assertEqual(p, [dict(offset=0, bytes=4096, lba=128, blocks=8),
                             dict(offset=4096, bytes=512, lba=136, blocks=1)])

    def test_exact_window_never_reads_an_extra_page(self):
        p = self.contract().plan_io(8192, 4096, 512, 128, 16)
        self.assertEqual(sum(x["bytes"] for x in p), 8192)
        self.assertEqual(len(p), 2)
        self.assertLessEqual(max(x["lba"] + x["blocks"] for x in p), 144)

    def test_geometry_rejects_unaligned_or_overlarge_transfer(self):
        m = self.contract()
        for args in [(4097,4096,512,128,9), (8192,4096,512,128,15),
                     (0,4096,512,128,16), (512,1000,512,128,16),
                     (512,4096,0,128,16), (512,4096,512,-1,16),
                     (512,4096,512,2**64-1,16)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.plan_io(*args)

    def test_full_image_oracle_detects_last_byte(self):
        m = self.contract()
        expected = bytes((i * 29 + i // 251 + 7) % 256 for i in range(4608))
        self.assertTrue(m.verify_image(expected, expected, b"\xa5"*32, b"\xa5"*32))
        for pos in [0, 7, 255, 4095, 4096, 4607]:
            actual = bytearray(expected)
            actual[pos] ^= 1
            with self.subTest(pos=pos):
                self.assertFalse(m.verify_image(expected, bytes(actual), b"\xa5"*32, b"\xa5"*32))

    def test_oracle_refuses_truncation_extra_bytes_and_guards(self):
        m = self.contract()
        for actual, prefix, suffix in [(b"abc",b"\xa5"*32,b"\xa5"*32),
            (b"abcdx",b"\xa5"*32,b"\xa5"*32),
            (b"abcd",b"\xa5"*31+b"\x00",b"\xa5"*32),
            (b"abcd",b"\xa5"*32,b"\x00"+b"\xa5"*31)]:
            self.assertFalse(m.verify_image(b"abcd", actual, prefix, suffix))

    def test_unknown_keeps_ownership_and_never_resubmits(self):
        self.assertEqual(self.contract().completion_policy("unknown"),
                         dict(reclaim=False,resubmit=False,success=False))

    def test_accepted_keeps_ownership_and_never_resubmits(self):
        self.assertEqual(self.contract().completion_policy("accepted"),
                         dict(reclaim=False,resubmit=False,success=False))

    def test_terminal_error_cannot_be_success(self):
        self.assertEqual(self.contract().completion_policy("error"),
                         dict(reclaim=True,resubmit=False,success=False))
        self.assertEqual(self.contract().completion_policy("success"),
                         dict(reclaim=True,resubmit=False,success=True))

    def test_qualification_accepts_explicit_read_region(self):
        q = self.contract().qualify(receipt())
        self.assertEqual(q["region_start_lba"], 128)
        self.assertEqual(q["namespace_id"], 7)

    def test_qualification_rejects_wrong_owner_revision_or_topology(self):
        m = self.contract()
        changes = [dict(upstream_revision="unrecorded"),dict(exclusive=False),
                   dict(approved=False),dict(execution="host-only"),dict(gpu_initiated=False),
                   dict(controller="/dev/nvme0n1"),dict(iommu="enabled"),
                   dict(acs="enabled"),dict(above_4g=False),dict(cuda_capability=60),
                   dict(namespace_id=0),dict(region_start_lba=1048570,region_blocks=64)]
        for change in changes:
            r=receipt();r.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.qualify(r)

    def test_write_needs_separate_explicit_region_authorization(self):
        m=self.contract();r=receipt();r["direction"]="write"
        with self.assertRaises(ValueError):m.qualify(r)
        r["allow_write"]=True
        self.assertEqual(m.qualify(r)["direction"], "write")

    def test_missing_qualification_is_skip_without_success_stdout(self):
        script=TARGET/"run_native.py"
        self.assertTrue(script.is_file(), "missing native runner with a capability gate")
        with tempfile.TemporaryDirectory() as td:
            p=subprocess.run([sys.executable,str(script),"--qualify",str(Path(td)/"absent.json"),
                              "--mode","correctness"],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,4,p.stderr)
        self.assertEqual(p.stdout,"")

    def test_absent_official_cuda_is_skip_and_does_not_create_output(self):
        script=TARGET/"build_native.py"
        self.assertTrue(script.is_file(), "missing official-SDK native build entry")
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"output"
            p=subprocess.run([sys.executable,str(script),"--upstream",td,
                              "--cuda-root",str(Path(td)/"missing-cuda"),"--output",str(out)],
                             capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,4,p.stderr)
            self.assertFalse(any(out.rglob("*")) if out.exists() else False)
        self.assertEqual(p.stdout,"")

    def test_native_queue_source_cannot_be_a_cpu_or_cufile_standin(self):
        source=TARGET/"bench_native.cu"
        self.assertTrue(source.is_file(), "missing real GPU-initiated native queue source")
        text=source.read_text()
        for token in ["__global__", "sq_enqueue", "cq_poll", "NVM_IO_READ", "NVM_IO_WRITE"]:
            self.assertIn(token,text)
        for token in ["cuFileRead", "cuFileWrite", "memcpy_standin", "fake_sdk"]:
            self.assertNotIn(token,text)


if __name__=="__main__":
    unittest.main(verbosity=2)
