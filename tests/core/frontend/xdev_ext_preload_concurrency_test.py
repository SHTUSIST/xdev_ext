#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host application/validator checks; these do not certify a custom-kernel VM."""
from pathlib import Path
import importlib.util
import os
import re
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
    def fixture(self, threads=2, processes=4, rounds=65):
        """Synthetic validator input only; never records of kernel execution."""
        actors, reports, fds = [], [], []
        total_bytes = sum((31, 257, 1023)[i % 3] for i in range(rounds))
        for actor in range(threads*processes):
            identity = f'pid={1000+actor//threads} tid={2000+actor}'
            actors.append(f'XDEV_EXT_MECH_ACTOR=PASS actor={actor} {identity} '+
                f'calls={rounds} bytes={total_bytes} ready={rounds} entered={rounds} exited={rounds} '+
                'full_compare=1 guards=1 extra_datagrams=0')
            reports.append(f'XDEV_EXT_PRELOAD_MECH_REPORT {identity} calls={rounds} bytes={total_bytes} '+
                'creates=1 errors=0 stops=1 stop_errors=0 '+
                ' '.join(f'{kind}{stage}={rounds}' for kind in ('submitted', 'completed') for stage in range(3)))
        for process in range(processes):
            fds.append(f'XDEV_EXT_MECH_FDS=PASS process={process} pid={1000+process} before=4 after=4')
        final = (f'XDEV_EXT_MECH_CONCURRENCY=PASS processes={processes} threads={threads} '+
            f'actors={threads*processes} rounds={rounds} overlap_pairs=1 '+
            f'cross_process_overlap_pairs={int(processes > 1)} per_round_gate=1 fd_leaks=0')
        return '\n'.join(fds+actors+[final])+'\n', reports

    def test_host_profile_accepts_only_complete_overlap_not_observed(self):
        text, _ = self.fixture()
        actors = '\n'.join(line for line in text.splitlines() if not line.startswith('XDEV_EXT_MECH_CONCURRENCY='))+'\n'
        diagnostic = 'XDEV_EXT_MECH_CONCURRENCY_FAILURE overlap_pairs=0 cross_process_overlap_pairs=0\n'
        result = subprocess.CompletedProcess([], 1, actors, diagnostic)
        self.assertEqual(self.check_host_campaign(result, 2, 4), 'not_observed')
        for bad in (
                subprocess.CompletedProcess([], 2, actors, diagnostic),
                subprocess.CompletedProcess([], 1, actors, diagnostic+'another failure\n'),
                subprocess.CompletedProcess([], 1, actors, diagnostic.replace('=0', '=1')),
                subprocess.CompletedProcess([], 1, actors.replace('calls=65', 'calls=64', 1), diagnostic),
                subprocess.CompletedProcess([], 1, actors.replace('guards=1', 'guards=0', 1), diagnostic),
                subprocess.CompletedProcess([], 1, actors.replace('after=4', 'after=5', 1), diagnostic),
                subprocess.CompletedProcess([], 1, actors+actors.splitlines()[0]+'\n', diagnostic),
                subprocess.CompletedProcess([], 1, '\n'.join(actors.splitlines()[:-1]), diagnostic)):
            with self.subTest(result=bad), self.assertRaises(AssertionError):
                self.check_host_campaign(bad, 2, 4)

    def check_host_campaign(self, result, threads, processes, rounds=65):
        """Check real host UDP behavior without promising scheduler overlap.

        Only the exact overlap-only failure can accompany complete actor/data
        evidence. The unchanged guest workload and VM validator still require
        positive measured overlap before their concurrency verdict can pass.
        """
        text = result.stdout
        actors = validator.records(text, 'XDEV_EXT_MECH_ACTOR=PASS')
        fds = validator.records(text, 'XDEV_EXT_MECH_FDS=PASS')
        finals = validator.records(text, 'XDEV_EXT_MECH_CONCURRENCY=PASS')
        self.assertTrue(all(line.startswith(('XDEV_EXT_MECH_ACTOR=PASS ',
            'XDEV_EXT_MECH_FDS=PASS ', 'XDEV_EXT_MECH_CONCURRENCY=PASS ')) for line in text.splitlines()), text)
        count = threads*processes
        self.assertEqual(len(actors), count, text+result.stderr)
        self.assertEqual({int(a['actor']) for a in actors}, set(range(count)))
        self.assertEqual(len({(a['pid'], a['tid']) for a in actors}), count)
        pids = {a['pid'] for a in actors}
        self.assertEqual(len(pids), processes)
        self.assertTrue(all(sum(a['pid'] == pid for a in actors) == threads for pid in pids))
        total_bytes = sum((31, 257, 1023)[i % 3] for i in range(rounds))
        for actor in actors:
            self.assertGreater(int(actor['pid']), 0)
            self.assertGreater(int(actor['tid']), 0)
            for key, value in dict(calls=rounds, bytes=total_bytes, ready=rounds,
                    entered=rounds, exited=rounds, full_compare=1, guards=1, extra_datagrams=0).items():
                self.assertEqual(int(actor[key]), value, actor)
        self.assertEqual(len(fds), processes, text)
        self.assertEqual({int(f['process']) for f in fds}, set(range(processes)))
        self.assertEqual({f['pid'] for f in fds}, pids)
        for record in fds:
            self.assertGreater(int(record['before']), 0)
            self.assertEqual(record['before'], record['after'])
        if result.returncode == 0:
            self.assertEqual(result.stderr, '')
            self.assertEqual(len(finals), 1)
            final = finals[0]
            for key, value in dict(processes=processes, threads=threads, actors=count,
                    rounds=rounds, per_round_gate=1, fd_leaks=0).items():
                self.assertEqual(int(final[key]), value)
            overlap, cross = int(final['overlap_pairs']), int(final['cross_process_overlap_pairs'])
            self.assertGreater(overlap, 0)
            self.assertTrue(0 <= cross <= overlap)
            self.assertTrue(cross > 0 if processes > 1 else cross == 0)
            return 'observed'
        self.assertEqual(result.returncode, 1, text+result.stderr)
        self.assertEqual(finals, [])
        diagnostic = re.fullmatch(r'XDEV_EXT_MECH_CONCURRENCY_FAILURE overlap_pairs=(\d+) '
                                  r'cross_process_overlap_pairs=(\d+)\n', result.stderr)
        self.assertIsNotNone(diagnostic, text+result.stderr)
        overlap, cross = map(int, diagnostic.groups())
        self.assertTrue(0 <= cross <= overlap)
        self.assertTrue(overlap == 0 or (processes > 1 and cross == 0), result.stderr)
        self.assertTrue(processes > 1 or cross == 0)
        return 'not_observed'
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
                scheduling = self.check_host_campaign(result, threads, processes)
                print(f'XDEV_EXT_HOST_UDP_PROFILE processes={processes} threads={threads} '
                      f'host_scheduling={scheduling} data=checked scope=ordinary-libc-host', flush=True)

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
                if 'received.data[0] ^= 1;' in mutated:
                    with self.assertRaises(AssertionError):
                        self.check_host_campaign(result, 4, 1)
                else:
                    self.assertEqual(result.stderr, 'XDEV_EXT_MECH_CONCURRENCY_FAILURE '
                        'overlap_pairs=0 cross_process_overlap_pairs=0\n')

    def test_per_actor_runtime_validator_rejects_fallback_and_missing_evidence(self):
        text, reports = self.fixture()
        good = text+'\n'.join(reports)+'\n'
        validator.validate_concurrency(good, 3, 2, 4)
        for bad in (good.replace(reports[0], ''), good+reports[0]+'\n',
                    good.replace('calls=65', 'calls=64', 1),
                    good.replace(reports[0], reports[0].replace('calls=65', 'calls=64')),
                    good.replace(reports[0], reports[0].replace('creates=1', 'creates=65')),
                    good.replace('errors=0', 'errors=1', 1),
                    good.replace('stop_errors=0', 'stop_errors=1', 1),
                    good.replace('completed2=65', 'completed2=64', 1),
                    good.replace('full_compare=1', 'full_compare=0', 1),
                    good.replace('fd_leaks=0', 'fd_leaks=1', 1),
                    good.replace('overlap_pairs=1', 'overlap_pairs=0'),
                    good.replace('cross_process_overlap_pairs=1', 'cross_process_overlap_pairs=0')):
            with self.subTest(mutation=bad[-200:]), self.assertRaises(AssertionError):
                validator.validate_concurrency(bad, 3, 2, 4)


if __name__ == '__main__':
    unittest.main(verbosity=2)
