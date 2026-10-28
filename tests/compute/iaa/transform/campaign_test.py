#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independently validate the exact byte oracle and adversarial mutations."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class CampaignOracle(unittest.TestCase):
    def test_whole_image_pool_guards_mutations_and_real_deflate_entropy(self):
        with tempfile.TemporaryDirectory(prefix='iaa-oracle-') as tmp:
            binary = Path(tmp) / 'oracle'
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2',
                                    '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                                    '-fno-sanitize-recover=undefined', '-I' + str(HERE),
                                    str(HERE / 'campaign_fixture.c'), '-lz', '-o', str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('mutations=7', run.stdout)
            self.assertIn('raw_deflate_groups=257', run.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
