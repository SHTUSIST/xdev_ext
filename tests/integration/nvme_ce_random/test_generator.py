#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Request input generation only; never starts devices or consumes BPF output."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


class RequestGeneration(unittest.TestCase):
    def test_random_disjoint_multibatch_and_terminal_repeat_inputs(self):
        spec=importlib.util.spec_from_file_location('random_native_input',Path(__file__).with_name('run.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for direction in ('load','save'):
            args=SimpleNamespace(depth=2,batches=8,phases=2,gpu_bytes=16777216,disk_bytes=16777216,
                                 lba_bytes=512,seed=42,direction=direction)
            rows=module.requests(args)
            self.assertEqual(len(rows),16)
            self.assertEqual([r['key'] for r in rows],list(range(100,116)))
            self.assertEqual(rows[0]['gpu_offset'],1)
            self.assertEqual(rows[8]['gpu_offset'],1)
            self.assertNotEqual(rows[8]['nvme_offset'],rows[0]['nvme_offset'])
            self.assertEqual(rows[9]['nvme_offset'],rows[0]['nvme_offset'])
            self.assertEqual(rows[9]['gpu_offset'],15728640)
            self.assertTrue(all(r['bytes']==1048576 for r in rows))
            self.assertTrue(any(r['gpu_offset']%32768 for r in rows))
            for phase in (rows[:8],rows[8:]):
                for i,left in enumerate(phase):
                    self.assertEqual(left['nvme_offset']%512,0)
                    self.assertLessEqual(left['gpu_offset']+1048576,16777216)
                    for right in phase[i+1:]:
                        self.assertTrue(left['gpu_offset']+1048576<=right['gpu_offset'] or right['gpu_offset']+1048576<=left['gpu_offset'])
                        if direction=='save':
                            self.assertTrue(left['nvme_offset']+1048576<=right['nvme_offset'] or right['nvme_offset']+1048576<=left['nvme_offset'])
            args.depth=1
            with self.assertRaises(ValueError):module.requests(args)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RequestGeneration))
    raise SystemExit(2 if result.errors else 0 if result.wasSuccessful() else 1)
