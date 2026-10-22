#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host application/validator checks; these do not certify a custom-kernel VM."""
from pathlib import Path
import importlib.util
import os
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE/'xdev_ext_preload_mech_workload.c'
spec = importlib.util.spec_from_file_location('mech_validate', HERE/'xdev_ext_preload_mech_validate.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ConcurrentApplication(unittest.TestCase):
    def compile_run(self, source, threads=4, processes=1, rounds=65):
        with tempfile.TemporaryDirectory(prefix='xdev-concurrency-') as directory:
            path = Path(directory)
            (path/'app.c').write_text(source)
            subprocess.run(shlex.split(os.environ.get('CC', 'cc')) + ['-std=gnu11', '-O2', '-Wall', '-Wextra',
                            '-Werror', '-pthread', str(path/'app.c'), '-o', str(path/'app')],
                           check=True, capture_output=True, text=True)
            env = {k: v for k, v in os.environ.items() if not k.startswith('XDEV_EXT_PRELOAD_')}
            env.pop('LD_PRELOAD', None)
            return subprocess.run([str(path/'app'), 'concurrency', str(threads),
                                   str(processes), str(rounds)], env=env,
                                  text=True, capture_output=True, timeout=45)

    def test_real_threads_and_independent_processes(self):
        for threads, processes in ((4, 1), (2, 4)):
            with self.subTest(threads=threads, processes=processes):
                result = self.compile_run(SOURCE.read_text(), threads, processes)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn('XDEV_EXT_MECH_CONCURRENCY=PASS', result.stdout)
                self.assertEqual(result.stdout.count('XDEV_EXT_MECH_ACTOR=PASS '), threads*processes)
                self.assertEqual(result.stdout.count('XDEV_EXT_MECH_FDS=PASS '), processes)

    def test_corrupted_payload_and_serial_schedule_rejected(self):
        source = SOURCE.read_text()
        mutations = (
            source.replace('/* concurrency receive fault point */', 'received.data[0] ^= 1;'),
            source.replace('/* concurrency call lock fault point */', 'pthread_mutex_lock(&s->lock);')
                  .replace('/* concurrency call unlock fault point */', 'pthread_mutex_unlock(&s->lock);'))
        for mutated in mutations:
            with self.subTest(fault='byte corruption' if 'received.data[0] ^= 1;' in mutated else 'serialized sends'):
                self.assertNotEqual(mutated, source)
                result = self.compile_run(mutated)
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertNotIn('XDEV_EXT_MECH_CONCURRENCY=PASS', result.stdout)

    def test_per_actor_runtime_validator_rejects_fallback_and_missing_evidence(self):
        result = self.compile_run(SOURCE.read_text(), 2, 4)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        # App behavior is real libc/UDP above. Counter records below are strict
        # validator fixtures only; never evidence of kernel execution.
        actors = validator.records(result.stdout, 'XDEV_EXT_MECH_ACTOR=PASS')
        reports = []
        for actor in actors:
            reports.append('XDEV_EXT_PRELOAD_MECH_REPORT '+
                ' '.join(f'{k}={actor[k]}' for k in ('pid','tid','calls','bytes'))+
                ' creates=1 errors=0 stops=1 stop_errors=0 '+
                ' '.join(f'{kind}{stage}=65' for kind in ('submitted','completed') for stage in range(3)))
        good = result.stdout+'\n'.join(reports)+'\n'
        validator.validate_concurrency(good, 3, 2, 4)
        for bad in (good.replace(reports[0], ''), good+reports[0]+'\n',
                    good.replace('calls=65', 'calls=64', 1),
                    good.replace(reports[0], reports[0].replace('calls=65', 'calls=64')),
                    good.replace(reports[0], reports[0].replace('creates=1', 'creates=65')),
                    good.replace('errors=0', 'errors=1', 1),
                    good.replace('stop_errors=0', 'stop_errors=1', 1),
                    good.replace('completed2=65', 'completed2=64', 1),
                    good.replace('full_compare=1', 'full_compare=0', 1),
                    good.replace('fd_leaks=0', 'fd_leaks=1', 1)):
            with self.subTest(mutation=bad[-200:]), self.assertRaises(AssertionError):
                validator.validate_concurrency(bad, 3, 2, 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
