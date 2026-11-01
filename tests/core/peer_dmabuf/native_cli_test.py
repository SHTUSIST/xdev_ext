#!/usr/bin/env python3
"""CLI/setup checks only: deliberately never target an existing device."""
import pathlib
import subprocess
import sys
import tempfile
import unittest


class NativeCLI(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([str(BINARY), *args], text=True, capture_output=True,
                              timeout=10)

    def test_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Usage:", result.stdout)
        self.assertIn("--expect-disabled", result.stdout)
        self.assertIn("REGISTER returns EOPNOTSUPP", result.stdout)
        self.assertIn("kernel configuration requires external evidence", result.stdout)
        self.assertNotIn("PASS", result.stdout)

    def test_bad_arguments(self):
        for args in [("--unknown",), ("--heap",), ("--control",),
                     ("--heap", ""), ("--control", ""), ("--expect-disabled=x",)]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("SETUP_ERROR", result.stderr)
                self.assertNotIn("PASS", result.stdout)

    def test_unavailable_control_is_never_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            for extra in [[], ["--expect-disabled"]]:
                result = self.run_cli("--control", str(pathlib.Path(tmp) / "absent"),
                                      "--heap", str(pathlib.Path(tmp) / "no-heap"), *extra)
                self.assertEqual(result.returncode, 2)
                self.assertIn("SETUP_ERROR", result.stderr)
                self.assertNotIn("PASS", result.stdout)

    def test_nonheap_character_device_is_never_pass(self):
        # /dev/null is harmless; its ALLOC ioctl must fail, never an importer test.
        for extra in [[], ["--expect-disabled"]]:
            result = self.run_cli("--control", "/dev/null", "--heap", "/dev/null", *extra)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("SETUP_ERROR", result.stderr)
            self.assertNotIn("PASS", result.stdout)

    def test_regular_file_is_not_control_device(self):
        with tempfile.NamedTemporaryFile() as regular:
            result = self.run_cli("--control", regular.name)
            self.assertEqual(result.returncode, 2)
            self.assertIn("SETUP_ERROR", result.stderr)
            self.assertNotIn("PASS", result.stdout)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: native_cli_test.py /absolute/path/to/native_import")
    BINARY = pathlib.Path(sys.argv.pop()).resolve()
    unittest.main()
