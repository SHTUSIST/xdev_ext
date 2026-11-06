#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the production CUDA helper against a temporary Driver ABI library.

Run: python3 tools/testing/selftests/xdev_ext_mech_tools/xdev_ext_mech_cuda_lifecycle_test.py
No CUDA SDK, CUDA driver, or GPU is needed. The helper itself is not mocked.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
TOOLS = HERE.parents[2]
HEADER = Path(os.environ.get("XDEV_EXT_CUDA_TEST_HEADER",
                             str(TOOLS / "xdev_ext_mech" / "xdev_ext_mech_cuda.h")))


class CudaLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="xdev_ext-cuda-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.build = Path(cls.temp.name)
        cls.cc = shutil.which(os.environ.get("CC", "cc"))
        if not cls.cc:
            raise unittest.SkipTest("C compiler unavailable")
        cls.fake_dir = cls.build / "driver"
        cls.fake_dir.mkdir()
        # Compile the ABI fixture even on RED, to catch fixture syntax errors.
        cls.compile_fake(cls.fake_dir)
        cls.probe = cls.build / "probe"
        if HEADER.is_file():
            cls.compile([
                "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-I", str(HEADER.parent), str(HERE / "xdev_ext_mech_cuda_probe.c"),
                "-Wl,--wrap=dlopen", "-ldl", "-o", str(cls.probe),
            ])

    @classmethod
    def compile(cls, args):
        p = subprocess.run([cls.cc, *args], text=True, capture_output=True)
        if p.returncode:
            raise RuntimeError(f"fixture/probe compilation failed:\n{p.stdout}{p.stderr}")

    @classmethod
    def compile_fake(cls, directory, omit=None):
        args = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC"]
        if omit:
            args.append("-DOMIT_" + omit)
        cls.compile([*args, str(HERE / "xdev_ext_mech_cuda_fake.c"),
                     "-o", str(directory / "libcuda.so.1")])

    def run_helper(self, *, fail="", bdf="0000:65:00.0", bytes_=8192,
                   driver=None, no_library=False, vmm=False, retry_close=False,
                   granularity=None):
        self.assertTrue(HEADER.is_file(),
                        "feature missing: tools/xdev_ext_mech/xdev_ext_mech_cuda.h")
        trace = self.build / "trace"
        trace.unlink(missing_ok=True)
        env = os.environ.copy()
        env.pop("CUDA_TEST_NO_LIBRARY", None)
        env.update(LD_LIBRARY_PATH=str(driver or self.fake_dir),
                   CUDA_TEST_TRACE=str(trace), CUDA_TEST_FAIL=fail)
        if no_library:
            env["CUDA_TEST_NO_LIBRARY"] = "1"
        for key in ("CUDA_TEST_VMM", "CUDA_TEST_RETRY_CLOSE", "CUDA_TEST_GRANULARITY"):
            env.pop(key, None)
        if vmm:
            env["CUDA_TEST_VMM"] = "1"
        if retry_close:
            env["CUDA_TEST_RETRY_CLOSE"] = "1"
        if granularity is not None:
            env["CUDA_TEST_GRANULARITY"] = str(granularity)
        p = subprocess.run([str(self.probe), bdf, str(bytes_)], env=env,
                           text=True, capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        values = dict(line.split("=", 1) for line in p.stdout.splitlines())
        values = {key: int(value) for key, value in values.items()}
        events = trace.read_text().splitlines()
        self.assertEqual(values["zero_close"], 0)
        self.assertEqual(values["again_close"], 0)
        self.assertEqual(values["va_after_close"], 0)
        self.assertEqual(values["loaded_after_close"], 0, events)
        return values, events

    def assert_failed_cleanly(self, values, events, *, loaded=True):
        self.assertNotEqual(values["open"], 0, events)
        self.assertEqual(values["va"], 0, events)
        self.assertEqual(values["close"], 0, events)
        self.assertEqual(values["loaded_after_open"], 0, events)
        if loaded:
            unloads = [e for e in events if e.startswith("unload ")]
            self.assertEqual(unloads, ["unload retained=0 live=0 current=111"], events)

    def test_unique_exact_bdf_full_lifecycle_and_context_restoration(self):
        values, events = self.run_helper()
        self.assertEqual(values["open"], 0, events)
        self.assertEqual(values["va"], 0x123456789ABC)
        self.assertEqual(values["current_after_open"], 0x111, events)
        self.assertEqual(values["loaded_after_open"], 1)
        self.assertEqual(values["close"], 0)
        self.assertEqual(events.count("retain 11"), 1, events)
        self.assertEqual(events.count("release 11"), 1, events)
        self.assertEqual(events.count("alloc 8192 current=222"), 1, events)
        self.assertEqual(events.count("free 123456789abc current=222"), 1, events)
        for bdf in ("bdf 10", "bdf 11", "bdf 12"):
            self.assertLess(events.index(bdf), events.index("retain 11"), events)
        self.assertLess(events.index("alloc 8192 current=222"), events.index("after_open"))
        self.assertLess(events.index("before_close"), events.index("free 123456789abc current=222"))
        self.assertLess(events.index("free 123456789abc current=222"), events.index("release 11"))
        self.assertIn("unload retained=0 live=0 current=333", events)
        self.assertLess(events.index("release 11"), events.index("unload retained=0 live=0 current=333"))
        self.assertLess(events.index("unload retained=0 live=0 current=333"), events.index("after_close"))

    def test_bdf_must_match_exactly(self):
        for bdf in ("0000:65:00.1", "65:00.0", "0000:65:00.0suffix"):
            with self.subTest(bdf=bdf):
                values, events = self.run_helper(bdf=bdf)
                # Invalid syntax may be rejected before loading the driver.
                self.assert_failed_cleanly(values, events,
                                           loaded=any(e.startswith("unload") for e in events))
                self.assertFalse(any(e.startswith("retain") for e in events), events)

    def test_close_retry_restores_this_callers_current_context(self):
        values, events = self.run_helper(fail="close_restore")
        self.assertEqual(values["open"], 0, events)
        self.assertNotEqual(values["close"], 0, events)
        self.assertEqual(values["retry_close"], 0, events)
        self.assertEqual(values["current_after_retry"], 0x444, events)
        self.assertIn("unload retained=0 live=0 current=444", events)

    def test_duplicate_bdf_is_rejected_before_retaining(self):
        values, events = self.run_helper(fail="duplicate")
        self.assert_failed_cleanly(values, events)
        self.assertFalse(any(e.startswith("retain") for e in events), events)

    def test_zero_devices_is_explicit_failure(self):
        values, events = self.run_helper(fail="zero_devices")
        self.assert_failed_cleanly(values, events)

    def test_driver_errors_release_every_acquired_resource(self):
        for fail in ("init", "count", "device", "bdf", "retain", "get", "set", "alloc", "restore"):
            with self.subTest(fail=fail):
                values, events = self.run_helper(fail=fail)
                self.assert_failed_cleanly(values, events)

    def test_invalid_arguments_are_explicit_failures(self):
        for bdf, bytes_ in (("NULL", 8192), ("", 8192), ("0000:65:00.0", 0),
                            ("0000:65:00.0", (1 << 64) - 1)):
            with self.subTest(bdf=bdf, bytes=bytes_):
                values, events = self.run_helper(bdf=bdf, bytes_=bytes_)
                self.assert_failed_cleanly(values, events,
                                           loaded=any(e.startswith("unload") for e in events))

    def test_missing_driver_is_explicit_failure(self):
        values, events = self.run_helper(no_library=True)
        self.assert_failed_cleanly(values, events, loaded=False)
        self.assertFalse(any(e.startswith("init") for e in events), events)

    # --- CUDA VMM: an allocation a GPU without GPUDirect RDMA can still name
    # to a CE window, through its POSIX file descriptor export.
    VMM_SYMBOLS = ("GRANULARITY", "CREATE", "EXPORT", "RESERVE", "MAP", "ACCESS",
                   "UNMAP", "ADDRESS_FREE", "RELEASE_MEM")

    def assert_vmm_released(self, values, events):
        self.assertIn("export_open=0", events, events)
        self.assertNotIn("export_open=1", events, events)
        unloads = [e for e in events if e.startswith("unload ")]
        self.assertEqual(len(unloads), 1, events)
        self.assertIn(" live=0 ", unloads[0], events)

    def test_vmm_full_lifecycle_exports_and_maps_on_the_retained_context(self):
        values, events = self.run_helper(vmm=True)
        self.assertEqual(values["open"], 0, events)
        self.assertEqual(values["va"], 0x7a4879200000, events)
        self.assertEqual(values["vmm_bytes"], 2 << 20, events)
        self.assertGreaterEqual(values["export_fd"], 0, events)
        self.assertEqual(values["current_after_open"], 0x111, events)
        self.assertEqual(values["close"], 0, events)
        opened = ["granularity type=1 handles=1 loc=1:11 option=0",
                  "create 2097152 flags=0 current=222",
                  "export abc0 type=1 flags=0",
                  "reserve 2097152 align=0 addr=0 flags=0",
                  "map 7a4879200000 2097152 offset=0 handle=abc0 current=222",
                  "access 7a4879200000 2097152 loc=1:11 flags=3 count=1 current=222"]
        positions = [events.index(e) for e in opened]
        self.assertEqual(positions, sorted(positions), events)
        self.assertLess(events.index("retain 11"), positions[0], events)
        self.assertLess(positions[-1], events.index("after_open"), events)
        self.assertFalse(any(e.startswith("alloc ") for e in events), events)
        closed = ["unmap 7a4879200000 2097152 current=222",
                  "address_free 7a4879200000 2097152", "release_mem abc0", "release 11"]
        positions = [events.index(e) for e in closed]
        self.assertEqual(positions, sorted(positions), events)
        self.assertLess(events.index("before_close"), positions[0], events)
        self.assertFalse(any(e.startswith("free ") for e in events), events)
        self.assertIn("unload retained=0 live=0 current=333", events)
        self.assert_vmm_released(values, events)

    def test_vmm_rounds_the_window_up_to_the_allocation_granularity(self):
        values, events = self.run_helper(vmm=True, bytes_=3 << 20)
        self.assertEqual(values["open"], 0, events)
        self.assertEqual(values["vmm_bytes"], 4 << 20, events)
        self.assertIn("create 4194304 flags=0 current=222", events)
        values, events = self.run_helper(vmm=True, bytes_=8192, granularity=0)
        self.assertNotEqual(values["open"], 0, events)
        self.assertFalse(any(e.startswith("create ") for e in events), events)

    def test_vmm_driver_errors_release_every_acquired_resource(self):
        for fail in ("granularity", "create", "export", "reserve", "map", "access",
                     "retain", "set", "restore"):
            with self.subTest(fail=fail):
                values, events = self.run_helper(vmm=True, fail=fail)
                self.assert_failed_cleanly(values, events)
                self.assert_vmm_released(values, events)

    def test_vmm_unmap_failure_keeps_ownership_until_retry(self):
        values, events = self.run_helper(vmm=True, fail="unmap_once", retry_close=True)
        self.assertEqual(values["open"], 0, events)
        self.assertNotEqual(values["close"], 0, events)
        self.assertEqual(values["retry_close"], 0, events)
        first = events.index("before_close")
        retry = events.index("before_retry_close")
        self.assertFalse([e for e in events[first:retry]
                          if e.startswith(("address_free", "release_mem", "release "))],
                         "an allocation still mapped was released: " + repr(events))
        self.assertIn("release_mem abc0", events[retry:], events)
        self.assert_vmm_released(values, events)

    def test_vmm_symbols_are_required_only_for_vmm(self):
        for symbol in self.VMM_SYMBOLS:
            with self.subTest(symbol=symbol):
                directory = self.build / ("vmm-" + symbol)
                directory.mkdir(exist_ok=True)
                self.compile_fake(directory, symbol)
                values, events = self.run_helper(driver=directory, vmm=True)
                self.assert_failed_cleanly(values, events)
                values, events = self.run_helper(driver=directory)
                self.assertEqual(values["open"], 0, events)
                self.assertEqual(values["close"], 0, events)

    def test_missing_required_symbols_close_library(self):
        self.assertTrue(HEADER.is_file(),
                        "feature missing: tools/xdev_ext_mech/xdev_ext_mech_cuda.h")
        for symbol in ("INIT", "COUNT", "DEVICE", "BDF", "RETAIN", "RELEASE",
                       "GET", "SET", "ALLOC", "FREE"):
            with self.subTest(symbol=symbol):
                directory = self.build / symbol
                directory.mkdir(exist_ok=True)
                self.compile_fake(directory, symbol)
                values, events = self.run_helper(driver=directory)
                self.assert_failed_cleanly(values, events)


if __name__ == "__main__":
    unittest.main(verbosity=2)
