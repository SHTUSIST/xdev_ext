#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host policy correctness; no device emulation or performance measurement."""
from pathlib import Path
import sys
import unittest
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'xdev_ext_mech/reliable/bpf_glue'))
import glue_common as G

class Policy(unittest.TestCase):
    def test_policy_bounds_defaults_and_enforcement(self):
        self.assertTrue(G.POLICY_H.is_file(), 'ABSENCE: production policy module missing')
        _, run = G.build_and_run(self, (HERE / 'policy_test.c').read_text(), name='policy')
        self.assertIn(' 0 failures', run.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)
