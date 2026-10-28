"""Software-only CPU sampler and hand-derived counter-bound contracts."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load():
    path = HERE / 'cpu_sampling.py'
    if not path.exists():
        raise AssertionError('periodic CPU sampler is missing')
    spec = importlib.util.spec_from_file_location('cpu_sampling_tested', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stat(n):
    return 'cpu %d 0 0 100 0 0 0 0 0 0\ncpu0 %d 0 0 100 0 0 0 0 0 0\n' % (n, n)


def inputs():
    m = dict(run_id='software', clock='CLOCK_MONOTONIC', clock_domain='host',
             records=[dict(session_id=1, record_id=1, generation=1, measured=True),
                      dict(session_id=1, record_id=0, generation=1, measured=False)])
    events = [dict(run_id='software', session_id=1, record_id=r, generation=1,
                   event=phase, frame_id=-1, stage='record', accepted=True, status=0,
                   clock='CLOCK_MONOTONIC', clock_domain='host', ts_ns=stamp)
              for r, phase, stamp in [(0, 'record_admit', 1), (0, 'record_terminal', 8),
                                      (1, 'record_admit', 20), (1, 'record_terminal', 80)]]
    samples = [dict(before_ns=a, after_ns=b, stat=stat(n))
               for a, b, n in [(5, 10, 1), (19, 21, 3), (25, 30, 4),
                                (60, 70, 7), (79, 81, 10), (90, 95, 11)]]
    return m, events, samples


class Bounds(unittest.TestCase):
    def test_enclosing_and_interior_reads_are_bounds_not_points(self):
        result = load().cpu_bounds(*inputs(), 100)
        self.assertEqual(result['lower'], 30_000_000)
        self.assertEqual(result['upper'], 100_000_000)
        self.assertEqual(result['interval_ns'], [20, 80])
        self.assertEqual(result['outer_samples'], [0, 5])
        self.assertEqual(result['inner_samples'], [2, 3])
        self.assertEqual(result.get('read_width_ns'), dict(min=2, max=10))
        self.assertEqual(result.get('endpoint_slack_ns'), dict(before=10, after=10))

    def test_no_inner_pair_is_zero_lower_bound(self):
        m, e, s = inputs()
        result = load().cpu_bounds(m, e, [s[0], s[-1]], 100)
        self.assertEqual((result['lower'], result['upper']), (0, 100_000_000))
        self.assertIsNone(result['inner_samples'])

    def test_invalid_samples_and_endpoints_are_unavailable(self):
        mutations = []
        m, e, s = inputs()
        mutations += [(m, e, s[1:]), (m, e, s[:-1]), (m, e, s + [s[-1]])]
        for change in ('clock', 'clock_domain', 'status', 'accepted', 'generation', 'frame_id', 'ts_ns'):
            bad = copy.deepcopy(e)
            bad[-1][change] = {'status': -5, 'accepted': False, 'generation': 2,
                              'frame_id': 0, 'ts_ns': True}.get(change, 'wrong')
            mutations.append((m, bad, s))
        mutations += [(m, e + [e[-1]], s), (m, e[:-1], s)]
        for text in (stat(0), 'cpu 1 2\ncpu0 1 2\n', stat(11) + 'cpu0 1 2\n',
                     stat(11) + 'cpu1 1 0 0 100 0 0 0 0\n'):
            bad = copy.deepcopy(s)
            bad[-1]['stat'] = text
            mutations.append((m, e, bad))
        bad = copy.deepcopy(e)
        bad[-1]['ts_ns'] = 20
        mutations.append((m, bad, s))
        bad_m = copy.deepcopy(m)
        bad_m['records'][0]['measured'] = False
        mutations.append((bad_m, e, s))
        for args in mutations:
            with self.subTest(args=args), self.assertRaises(ValueError):
                load().cpu_bounds(*args, 100)


class ActualSampler(unittest.TestCase):
    def test_periodic_actual_proc_reads_surround_software_child_and_join(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'samples.jsonl'
            with load().CpuSampler(path, period_seconds=0.005) as sampler:
                begin = time.monotonic_ns()
                subprocess.run([sys.executable, '-c', 'import time; time.sleep(.06)'], check=True)
                end = time.monotonic_ns()
            self.assertIsNone(sampler.error)
            self.assertFalse(sampler.thread.is_alive())
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertGreater(len(rows), 2)
            self.assertLessEqual(rows[0]['after_ns'], begin)
            self.assertGreaterEqual(rows[-1]['before_ns'], end)
            self.assertTrue(all('cpu0 ' in row['stat'] for row in rows))
            self.assertTrue(all(line.split()[0].startswith('cpu')
                                for row in rows for line in row['stat'].splitlines()))

    def test_unreadable_snapshot_records_error_and_closes_worker(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'samples.jsonl'
            sampler = module.CpuSampler(path)
            with patch.object(module, 'Path', side_effect=lambda _: Path(tmp) / 'missing-proc-stat'):
                with sampler:
                    pass
            self.assertIsNotNone(sampler.error)
            self.assertFalse(sampler.thread.is_alive())
            self.assertEqual(path.read_bytes(), b'')

    def test_size_limit_records_failure_and_stops_even_on_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'samples.jsonl'
            sampler = load().CpuSampler(path, period_seconds=.001, max_bytes=1)
            with self.assertRaisesRegex(RuntimeError, 'child failure'):
                with sampler:
                    raise RuntimeError('child failure')
            self.assertFalse(sampler.thread.is_alive())
            self.assertIn('limit', sampler.error)
            self.assertLessEqual(path.stat().st_size, 1)


class CollectorCapture(unittest.TestCase):
    def test_actual_sampler_retained_and_joined_after_command_timeout(self):
        spec = importlib.util.spec_from_file_location('cpu_capture_collector', HERE / 'collector.py')
        collector = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = collector
        spec.loader.exec_module(collector)
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / 'trace-instance'
            trace_path.mkdir()
            (trace_path / 'trace').write_text('')

            class SoftwareTrace:
                def __init__(self, *args, **kwargs):
                    self.path = trace_path
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
                def configuration(self):
                    return {}
                def stats(self):
                    return {'cpu0': 'overrun: 0\ndropped events: 0\ncommit overrun: 0\n'}
                def start(self):
                    pass
                def stop(self):
                    pass
                def mark(self, text):
                    with (self.path / 'trace').open('a') as stream:
                        stream.write(text + '\n')

            m, _, _ = inputs()
            m.update(arm='K-BPF', trace=dict(timeout_seconds=.05), stages=[])
            with patch.object(collector, 'PrivateTrace', SoftwareTrace), patch.object(
                    collector, '_native_preflight', return_value=dict(physical=False, evidence_kind='fixture')):
                receipt = collector._capture(m, [sys.executable, '-c', 'import time; time.sleep(10)'],
                                              Path(tmp) / 'capture', trace_path, False)
            self.assertNotEqual(receipt['returncode'], 0)
            self.assertIn('cpu_samples', receipt['artifacts'])
            sample_path = Path(receipt['artifacts']['cpu_samples']['path'])
            self.assertGreater(len(sample_path.read_text().splitlines()), 2)
            metadata = json.loads(Path(receipt['artifacts']['trace_metadata']['path']).read_text())
            self.assertEqual(metadata['cpu_interval_scope'], 'native_interval_counter_bounds')
            self.assertIsNone(metadata['cpu_sampler_error'])
            import threading
            self.assertFalse(any(t.name == 'native-cpu-sampler' for t in threading.enumerate()))


if __name__ == '__main__':
    unittest.main()
