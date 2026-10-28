#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual parent build-only dispatch, recording only child invocation.

No SDK compiler, workload, device or network operation is executed. SDK refusal
and compiler failure are distinct recorded child outcomes, not missing-SDK skips.
"""
import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


class DelegateBuild(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("actual_delegate_runner", HERE / "run.py")
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)
        temporary = tempfile.TemporaryDirectory(prefix="gds-build-boundary-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.args = argparse.Namespace(arms=["gds-direct"], build_only=True, dry_run=False,
            build_dir=self.directory / "build", directory=self.directory,
            cuda_root=self.directory / "official-sdk-boundary")
        self.calls = []

    def execute(self, rc, timeout=False):
        def recorder(argv, **kwargs):
            self.calls.append((list(map(str, argv)), kwargs))
            if timeout:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return subprocess.CompletedProcess(argv, rc, stdout="compiler progress\n",
                stderr="delegate built\n" if rc == 0 else
                       "SDK capability refusal\n" if rc == 4 else "delegate compile failed\n")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.runner, "arguments", return_value=self.args), \
             mock.patch.object(self.runner.subprocess, "run", side_effect=recorder), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self.runner.main([])
        return result, out.getvalue(), err.getvalue()

    def assert_delegate(self, directory=None):
        self.assertEqual(len(self.calls), 1, "build-only must invoke its real builder once")
        argv, kwargs = self.calls[0]
        self.assertEqual(argv[:2], [sys.executable, str(HERE.parent / "gds/run.py")])
        self.assertIn("--build-only", argv, "a build request cannot execute a workload")
        for flag, expected in (("--mode", "cufile-direct"), ("--workload", "llm-load"),
                               ("--bytes", "4096"), ("--chunk", "4096"),
                               ("--iterations", "1"), ("--cuda-root", str(self.args.cuda_root)),
                               ("--directory", str((directory or self.directory).resolve()))):
            self.assertEqual(argv[argv.index(flag) + 1], expected)
        self.assertGreater(kwargs["timeout"], 0)
        self.assertTrue(kwargs["capture_output"])

    def test_success_invokes_delegate_and_keeps_stdout_empty(self):
        rc, out, err = self.execute(0)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertIn("compiler progress\n", err)
        self.assertIn("delegate built\n", err)
        self.assertIn("Built gds-direct:", err)
        self.assert_delegate()

    def test_unavailable_sdk_is_not_reported_built(self):
        rc, out, err = self.execute(4)
        self.assertEqual((rc, out), (4, ""))
        self.assertNotIn("Built gds-direct:", err)
        self.assertIn("SDK capability refusal", err)
        self.assert_delegate()

    def test_fatal_build_failure_is_not_reported_built(self):
        rc, out, err = self.execute(1)
        self.assertEqual((rc, out), (1, ""))
        self.assertNotIn("Built gds-direct:", err)
        self.assertIn("delegate compile failed", err)
        self.assert_delegate()

    def test_delegate_timeout_is_fatal(self):
        rc, out, err = self.execute(0, timeout=True)
        self.assertEqual((rc, out), (1, ""))
        self.assertNotIn("Built gds-direct:", err)
        self.assert_delegate()

    def test_build_only_without_campaign_directory_uses_build_directory(self):
        self.args.directory = None
        rc, out, _ = self.execute(0)
        self.assertEqual((rc, out), (0, ""))
        self.assertTrue(self.args.build_dir.is_dir())
        self.assert_delegate(directory=self.args.build_dir)


if __name__ == "__main__":
    unittest.main()
