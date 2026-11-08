#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production C control flow with device/control boundaries, no hardware or timing claims."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class RuntimeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = HERE / 'build'
        build.mkdir(exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdomain-contract-', dir=build)
        cls.bin = Path(cls.tmp.name) / 'contract'
        command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-ffunction-sections', '-fdata-sections', str(HERE / 'test_xdomain_runtime.c'),
                   '-Wl,--gc-sections', '-Wl,--wrap=dlsym', '-ldl', '-o', str(cls.bin)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.bin), name], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]

    def test_stale_stream_image_at_next_size_is_rejected(self):
        rows = self.scenario('stale-stream')
        self.assertTrue(rows[0]['verified'])
        self.assertFalse(rows[1]['verified'])
        self.assertEqual(rows[1]['verified_bytes'], 0)

    def test_missing_pingpong_prefix_at_next_size_is_rejected(self):
        rows = self.scenario('stale-pingpong')
        self.assertTrue(rows[0]['verified'])
        self.assertFalse(rows[1]['verified'])

    def test_verification_counts_only_retained_window(self):
        row = self.scenario('count')[0]
        self.assertEqual(row['messages'], 100)
        self.assertEqual(row['verified_bytes'], 128)
        self.assertEqual(row['transferred_bytes'], 6400)
        self.assertEqual(row['verification_scope'], 'final-window')

    def test_poison_failure_prevents_start(self):
        self.assertEqual(self.scenario('poison-failure'), [])


if __name__ == '__main__':
    unittest.main()
