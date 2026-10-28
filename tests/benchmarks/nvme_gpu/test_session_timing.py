#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual session timing/drain order at deterministic host control boundaries.

No baseline scheduler contract, SDK ABI or device/performance result is tested.
"""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("NVME_GPU_SOURCE_ROOT", str(HERE.parents[2]))).resolve()


def function(text, name):
    match = re.search(r"^([^\n;#{}]*\b" + re.escape(name) +
                      r"\s*\([^;]*?\))\s*\{", text, re.M)
    if not match:
        raise AssertionError("missing actual " + name)
    brace, depth = text.index("{", match.start()), 0
    for i in range(brace, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if not depth:
            return text[match.start():i + 1]
    raise AssertionError("unbalanced " + name)


class SessionTiming(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix="nvme-gpu-timer-")
        cls.addClassCleanup(temp.cleanup)
        cls.out = Path(temp.name)
        timer = (HERE / "timer_fixture.c.in").read_text()
        session = (ROOT / "tests/eval/nvme_gpu/session_nvme_ce.c").read_text()
        for name, token in (("sn_opts", "SN_OPTS"), ("sn_pass", "SN_PASS")):
            start = session.index("struct " + name + " {")
            timer = timer.replace("@" + token + "@",
                                  session[start:session.index("\n};", start) + 3])
        timer = timer.replace("@SN_SESSION@", function(session, "sn_session"))
        path = cls.out / "timer.c"
        path.write_text(timer)
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
            "-I", str(ROOT), "-I", str(ROOT / "tests/eval/nvme_gpu"),
            str(path), "-o", str(cls.out / "timer")]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError("actual session fixture compile failed:\n" + result.stderr)

    def run_case(self, save, fail):
        result = subprocess.run([str(self.out / "timer"), str(int(save)), str(int(fail))],
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def test_session_timer_includes_successful_drain(self):
        for save in (False, True):
            with self.subTest(save=save):
                record = self.run_case(save, False)
                self.assertEqual((record["rc"], record["settled"], record["closed"]), (0, 1, 1))
                self.assertEqual((record["io_ns"], record["cpu_us"], record["host_busy_us"]),
                                 (130, 130, 130), "terminal wake alone is not the measured drain")

    def test_session_drain_error_cannot_report_success(self):
        for save in (False, True):
            with self.subTest(save=save):
                record = self.run_case(save, True)
                self.assertEqual((record["rc"], record["io_ns"], record["settled"], record["closed"]),
                                 (1, 0, 1, 1))


if __name__ == "__main__":
    unittest.main()
