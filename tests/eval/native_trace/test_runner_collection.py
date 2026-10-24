#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise the actual native_views CLI and its tracing refusal receipt."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

EVAL = Path(__file__).resolve().parent.parent


class RunnerCollection(unittest.TestCase):
    def test_execute_keeps_trace_unavailable_and_never_runs_fixture_workload(self):
        entry = EVAL / 'native_views/run.py'
        fixture = EVAL / 'native_views/fixtures/builders.py'
        self.assertTrue(entry.is_file(), 'actual native_views runner is not implemented')
        self.assertTrue(fixture.is_file(), 'frozen native_views fixtures must be integrated')
        spec = importlib.util.spec_from_file_location('native_trace_runner_fixture', fixture)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='native-trace-runner-') as directory:
            directory = Path(directory)
            marker = directory / 'started'
            manifest = module.run_fixture()
            manifest['commands'] = [[sys.executable, '-c',
                                      'open(__import__("sys").argv[1],"w").close()', str(marker)]]
            path = directory / 'manifest.json'
            path.write_text(json.dumps(manifest))
            result = subprocess.run([sys.executable, str(entry), '--manifest', str(path),
                                     '--output', str(directory / 'out'), '--execute'],
                                    capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists(), 'fixture workload must never start')
            receipt = json.loads(result.stdout)
            self.assertIs(receipt['performance_eligible'], False)
            self.assertIn('trace_collection', receipt,
                          'actual runner must retain its trace preflight/collection receipt')
            trace = receipt['trace_collection']
            self.assertEqual(trace['status'], 'unavailable')
            self.assertTrue(trace['reasons'])
            self.assertNotIn('raw_trace', trace['artifacts'])


if __name__ == '__main__':
    unittest.main()
