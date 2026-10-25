#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute guest export functions with real files, without booting a guest.

The shell interface uses fanout_trace plus XDEV_FANOUT_PORT_SYSFS and
XDEV_FANOUT_DEV_ROOT to substitute tracefs/sysfs/dev roots. Only rmdir is
substituted: tracefs removes populated instances, unlike an ordinary directory.
Set XDEV_FANOUT_GUEST_SCRIPT to exercise an older guest script for a RED run.
"""
import os
import importlib
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
GUEST = Path(os.environ.get(
    "XDEV_FANOUT_GUEST_SCRIPT",
    str(HERE.parents[1] / "xdev_ext_integration" /
        "xdev_ext_mech_lifecycle_guest.sh"),
))
STATS = (
    "entries: 12000\noverrun: 0\ncommit overrun: 0\nbytes: 2097152\n"
    "oldest event ts: 1.000000\nnow ts: 2.000000\n"
    "dropped events: 0\nread events: 0\n"
)


class FanoutExportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.trace = self.root / "tracefs"
        self.sysfs = self.root / "ports"
        self.dev = self.root / "dev"
        self.dev.mkdir()
        self.sysfs.mkdir()
        (self.trace / "events/xdev_ext/native_event").mkdir(parents=True)
        (self.trace / "events/xdev_ext/native_event/enable").write_text("1\n")
        (self.trace / "tracing_on").write_text("1\n")
        for cpu in (0, 3):
            statdir = self.trace / f"per_cpu/cpu{cpu}"
            statdir.mkdir(parents=True)
            (statdir / "stats").write_text(STATS)
        # Several MiB exposes accidental console export and partial copies.
        self.payload = "".join(
            f"worker-{i:06d} [003] .... 1.000001: native_event: "
            f"cookie={i} " + "x" * 140 + "\n" for i in range(18000)
        )
        (self.trace / "trace").write_text(self.payload)

    def port(self, number, name):
        entry = self.sysfs / number
        entry.mkdir()
        (entry / "name").write_text(name + "\n")
        device = self.dev / number
        device.touch()
        return device

    def export(self):
        # Execute production function bodies; do not reproduce export logic.
        functions = re.findall(
            r"^[A-Za-z_][A-Za-z_0-9]*\(\)\s*\{\n.*?^\}",
            GUEST.read_text(), re.MULTILINE | re.DOTALL,
        )
        self.assertTrue(functions, "guest shell function extraction failed")
        script = "set -eu\n" + "\n".join(functions)
        script += "\nrmdir() { :; }\n"
        script += "fanout_trace=" + shlex.quote(str(self.trace)) + "\n"
        script += "dump_fanout_trace\n"
        env = dict(os.environ, XDEV_FANOUT_PORT_SYSFS=str(self.sysfs),
                   XDEV_FANOUT_DEV_ROOT=str(self.dev))
        return subprocess.run(["/bin/sh", "-c", script], env=env,
                              capture_output=True, timeout=15)

    def test_complete_native_evidence_uses_named_port_without_console_payload(self):
        other = self.port("vport0p0", "unrelated-diagnostics")
        target = self.port("vport7p2", "xdev-fanout-native")
        result = self.export()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertFalse(b"native_event:" in result.stdout,
                         "native payload must not share the printk console")
        self.assertFalse(b"XDEV_EXT_FANOUT_TRACE_BEGIN" in result.stdout)
        expected = "XDEV_EXT_FANOUT_TRACE_CLOCK=mono\n"
        for cpu in (0, 3):
            expected += f"XDEV_EXT_FANOUT_TRACE_CPU_BEGIN cpu{cpu}\n"
            expected += STATS
            expected += f"XDEV_EXT_FANOUT_TRACE_CPU_END cpu{cpu}\n"
        expected += "XDEV_EXT_FANOUT_TRACE_BEGIN\n"
        expected += self.payload + "XDEV_EXT_FANOUT_TRACE_END\n"
        self.assertTrue(target.read_bytes() == expected.encode(),
                        "native stream lost or changed trace/statistics bytes")
        self.assertEqual(other.read_bytes(), b"")
        self.assertEqual((self.trace / "tracing_on").read_text(), "0\n")
        self.assertEqual((self.trace / "events/xdev_ext/native_event/enable")
                         .read_text(), "0\n")

    def test_missing_named_port_fails_without_console_fallback(self):
        other = self.port("vport0p0", "unrelated-diagnostics")
        result = self.export()
        self.assertNotEqual(result.returncode, 0,
                            "missing native transport must fail closed")
        self.assertFalse(b"native_event:" in result.stdout)
        self.assertFalse(b"XDEV_EXT_FANOUT_TRACE_BEGIN" in result.stdout)
        self.assertEqual(other.read_bytes(), b"")

    def test_disconnected_device_fails_without_console_fallback(self):
        target = self.port("vport7p2", "xdev-fanout-native")
        target.unlink()
        result = self.export()
        self.assertNotEqual(result.returncode, 0,
                            "sysfs entry without a device must not create one")
        self.assertFalse(target.exists())
        self.assertFalse(b"native_event:" in result.stdout)


class FanoutMergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.console = self.root / "guest.raw.log"
        self.native = self.root / "fanout-native.raw.log"
        self.output = self.root / "guest.log"
        self.console_bytes = (
            b"Linux boot\r\nWARNING: real-driver-warning\r\n"
            b"XDEV_EXT_FANOUT_VERIFY_BEGIN\r\nverified bytes=8192\r\n"
            b"XDEV_EXT_FANOUT_VERIFY_END\r\n"
        )
        self.native_bytes = (
            b"XDEV_EXT_FANOUT_TRACE_CLOCK=mono\r\n"
            b"XDEV_EXT_FANOUT_TRACE_CPU_BEGIN cpu0\r\n"
            + STATS.replace("\n", "\r\n").encode()
            + b"XDEV_EXT_FANOUT_TRACE_CPU_END cpu0\r\n"
            b"XDEV_EXT_FANOUT_TRACE_BEGIN\r\n"
            b"worker [000] .... 1.000000: native_event: cookie=17\r\n"
            b"XDEV_EXT_FANOUT_TRACE_END\r\n"
        )
        self.console.write_bytes(self.console_bytes)
        self.native.write_bytes(self.native_bytes)

    def merge(self):
        sys.path.insert(0, str(HERE))
        try:
            module = importlib.import_module("fanout_trace")
        finally:
            sys.path.pop(0)
        function = getattr(module, "merge_fanout_logs", None)
        self.assertTrue(callable(function), "host merge_fanout_logs API missing")
        return function(self.console, self.native, self.output)

    def test_merge_retains_warning_trace_stats_data_and_both_originals(self):
        self.merge()
        actual = self.output.read_bytes()
        self.assertTrue(actual.startswith(self.console_bytes.replace(b"\r", b"")))
        self.assertIn(self.native_bytes.replace(b"\r", b""), actual)
        self.assertNotIn(b"\r", actual)
        self.assertEqual(actual.count(b"WARNING: real-driver-warning"), 1)
        self.assertEqual(actual.count(b"XDEV_EXT_FANOUT_TRACE_BEGIN\n"), 1)
        self.assertEqual(self.console.read_bytes(), self.console_bytes)
        self.assertEqual(self.native.read_bytes(), self.native_bytes)

    def test_merge_rejects_missing_or_incomplete_native_stream(self):
        for invalid in (b"", b"XDEV_EXT_FANOUT_TRACE_BEGIN\npartial\n",
                        b"partial\nXDEV_EXT_FANOUT_TRACE_END\n"):
            with self.subTest(native=invalid):
                self.native.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    self.merge()
                self.assertEqual(self.console.read_bytes(), self.console_bytes)
                self.assertEqual(self.native.read_bytes(), invalid)

    def test_merge_rejects_native_evidence_already_in_console(self):
        contaminated = self.console_bytes + self.native_bytes
        self.console.write_bytes(contaminated)
        with self.assertRaises(ValueError):
            self.merge()
        self.assertEqual(self.console.read_bytes(), contaminated)
        self.assertEqual(self.native.read_bytes(), self.native_bytes)


if __name__ == "__main__":
    unittest.main()
