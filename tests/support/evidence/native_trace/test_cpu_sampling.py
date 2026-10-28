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


BOOT_ID = '01234567-89ab-4cde-8f01-23456789abcd'


class ActualSamplerIdentity(unittest.TestCase):
    """Exercise the real sampler through redirected procfs/sysfs file reads."""
    def os_fixture(self, root):
        root = Path(root)
        files = {'stat': root / 'proc/stat',
                 'boot': root / 'proc/sys/kernel/random/boot_id',
                 'online': root / 'sys/devices/system/cpu/online',
                 'possible': root / 'sys/devices/system/cpu/possible'}
        values = {'stat': stat(1), 'boot': BOOT_ID + '\n', 'online': '0\n', 'possible': '0-1\n'}
        for key, path in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(values[key])
        return files

    def redirected_path(self, root):
        def resolve(value, *args, **kwargs):
            value = str(value)
            if value == '/proc' or value.startswith('/proc/') or value == '/sys' or value.startswith('/sys/'):
                return Path(root) / value.lstrip('/')
            return Path(value, *args, **kwargs)
        return resolve

    def test_default_diagnostic_sampler_retains_actual_identity_without_claimed_domain(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            self.os_fixture(tmp)
            path = Path(tmp) / 'samples.jsonl'
            sampler = module.CpuSampler(path, period_seconds=60)
            with patch.object(module, 'Path', side_effect=self.redirected_path(tmp)):
                with sampler:
                    pass
            self.assertIsNone(sampler.error)
            self.assertFalse(sampler.thread.is_alive())
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            for row in rows:
                self.assertEqual(row.get('boot_id'), BOOT_ID)
                self.assertEqual(row.get('online_cpus'), [0])
                self.assertEqual(row.get('possible_cpus'), [0, 1])
                self.assertEqual(row.get('clock'), 'CLOCK_MONOTONIC')
                self.assertIn('clock_domain', row)
                self.assertIsNone(row['clock_domain'])
                self.assertEqual(row['stat'], stat(1))
                self.assertIs(type(row['before_ns']), int)
                self.assertIs(type(row['after_ns']), int)
                self.assertLessEqual(row['before_ns'], row['after_ns'])

    def test_explicit_existing_run_clock_domain_is_written_to_every_sample(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            self.os_fixture(tmp)
            path = Path(tmp) / 'samples.jsonl'
            try:
                sampler = module.CpuSampler(path, period_seconds=60, clock_domain='measurement-host')
            except TypeError as error:
                self.fail('sampler cannot retain the selected run clock domain: ' + str(error))
            with patch.object(module, 'Path', side_effect=self.redirected_path(tmp)):
                with sampler:
                    pass
            self.assertIsNone(sampler.error)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual([row.get('clock_domain') for row in rows],
                             ['measurement-host', 'measurement-host'])

    def test_identity_change_between_samples_stops_without_appending_changed_row(self):
        for changed in ('boot', 'online', 'possible'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                module = load()
                files = self.os_fixture(tmp)
                path = Path(tmp) / 'samples.jsonl'
                sampler = module.CpuSampler(path, period_seconds=60)
                with patch.object(module, 'Path', side_effect=self.redirected_path(tmp)):
                    with sampler:
                        files[changed].write_text({'boot': 'fedcba98-7654-4321-8abc-0123456789ab\n',
                                                   'online': '0-1\n', 'possible': '0-2\n'}[changed])
                        if changed == 'online':
                            files['stat'].write_text(stat(1) + 'cpu1 0 0 0 100 0 0 0 0 0 0\n')
                self.assertIsNotNone(sampler.error, 'changed OS identity was silently accepted')
                self.assertFalse(sampler.thread.is_alive())
                self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_boot_change_during_stat_read_refuses_the_entire_snapshot(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            files = self.os_fixture(tmp)
            path = Path(tmp) / 'samples.jsonl'
            sampler = module.CpuSampler(path, period_seconds=60)
            real_open = Path.open
            changed = []

            def open_with_reboot(target, *args, **kwargs):
                if target == files['stat'] and not changed:
                    changed.append(True)
                    files['boot'].write_text('fedcba98-7654-4321-8abc-0123456789ab\n')
                return real_open(target, *args, **kwargs)

            with patch.object(module, 'Path', side_effect=self.redirected_path(tmp)), patch.object(
                    Path, 'open', autospec=True, side_effect=open_with_reboot):
                with sampler:
                    pass
            self.assertTrue(changed, 'fixture never reached the real stat read')
            self.assertIsNotNone(sampler.error, 'boot changed during the read but sample was accepted')
            self.assertFalse(sampler.thread.is_alive())
            self.assertEqual(path.read_bytes(), b'')

    def test_unreadable_boot_identity_cannot_emit_valid_samples(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            files = self.os_fixture(tmp)
            files['boot'].unlink()
            path = Path(tmp) / 'samples.jsonl'
            sampler = module.CpuSampler(path, period_seconds=60)
            with patch.object(module, 'Path', side_effect=self.redirected_path(tmp)):
                with sampler:
                    pass
            self.assertIsNotNone(sampler.error, 'missing boot identity silently became valid samples')
            self.assertFalse(sampler.thread.is_alive())
            self.assertEqual(path.read_bytes(), b'')


def selected_inputs():
    """Selected CPUs have 9 inner / 30 outer ticks; aggregate is unrelated."""
    manifest, events, samples = inputs()
    for row, n in zip(samples, (1, 3, 4, 7, 10, 11)):
        row.update(boot_id=BOOT_ID, online_cpus=[0, 1, 3], possible_cpus=[0, 1, 2, 3],
                   clock='CLOCK_MONOTONIC', clock_domain='host')
        row['stat'] = ''.join('cpu%s %d 0 0 100 0 0 0 0 0 0\n' % (cpu, user)
                              for cpu, user in (('', 900 * n), ('0', 100 * n),
                                                ('1', n), ('3', 2 * n)))
    return manifest, events, samples


class SelectedCpuParsing(unittest.TestCase):
    """A measurement set must be explicit, bounded and available, never intersected."""
    def parser(self):
        parse = getattr(load(), 'parse_cpu_set', None)
        self.assertTrue(callable(parse), 'selected CPU-set parser is not implemented')
        return parse

    def test_default_resolves_all_online_and_ranges_normalize(self):
        parse = self.parser()
        self.assertEqual(parse(None, possible=(0, 1, 2, 3), online=(0, 1, 3)), (0, 1, 3))
        self.assertEqual(parse('3,0-1', possible=(0, 1, 2, 3), online=(0, 1, 3)), (0, 1, 3))
        self.assertEqual(parse('3', possible=(0, 1, 2, 3), online=(0, 1, 3)), (3,))

    def test_duplicate_offline_unknown_or_non_ascii_selections_reject(self):
        parse = self.parser()
        for text in ('', '0,0', '0-1,1', '2', '4', '3-1', '0,,1', '-1', '+1',
                     '1.0', '\u0661', '0-18446744073709551615', '0,' * 600000):
            with self.subTest(text=text[:100]), self.assertRaises(ValueError):
                parse(text, possible=(0, 1, 2, 3), online=(0, 1, 3))

    def test_invalid_possible_or_online_universe_rejects_before_selection(self):
        parse = self.parser()
        for possible, online in (((), ()), ((0, 0), (0,)), ((1, 0), (0,)),
                                 ((False, 1), (1,)), ((-1, 0), (0,)),
                                 ((0, 1), ()), ((0, 1), (1, 0)),
                                 ((0, 1), (0, 0)), ((0, 1), (True,)),
                                 ((0, 1), (2,)), ((0, 1.0), (0,))):
            with self.subTest(possible=possible, online=online), self.assertRaises(ValueError):
                parse(None, possible=possible, online=online)


class StrictCpuCounters(unittest.TestCase):
    def test_unsigned64_boundary_is_exact_and_overflow_rejects(self):
        module = load()
        maximum = str(2**64 - 1)
        text = stat(0).replace(' 0 0 100', ' ' + maximum + ' 0 100')
        self.assertEqual(module.parse_stat(text)['cpu0'][1], 18446744073709551615)
        with self.assertRaises(ValueError):
            module.parse_stat(text.replace(maximum, '18446744073709551616'))

    def test_oversized_numeric_token_cannot_hide_behind_leading_zeroes(self):
        with self.assertRaises(ValueError):
            load().parse_stat(stat(0).replace(' 0 0 100', ' ' + '0' * 1000 + ' 0 100'))

    def test_malformed_rows_are_unavailable_instead_of_zero_fill(self):
        for text in ('cpu 1 0 0 100 0 0 0 0\n', 'cpu0 1 0 0 100 0 0 0 0\n',
                     stat(1) + stat(1), 'cpu 1 0\ncpu0 1 0\n',
                     stat(1).replace(' 100 ', ' -1 '),
                     stat(1).replace(' 100 ', ' +1 '),
                     stat(1).replace(' 100 ', ' 1.0 ')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                load().parse_stat(text)


class SelectedBusyArithmetic(unittest.TestCase):
    def busy(self, before, after, cpus=(1, 3)):
        function = getattr(load(), 'busy_ticks', None)
        self.assertTrue(callable(function), 'selected CPU arithmetic is not implemented')
        return function(before, after, cpus)

    def test_only_selected_rows_count_once_aggregate_and_other_cpu_do_not(self):
        before = load().parse_stat('cpu 0 0 0 0 0 0 0 0\ncpu0 0 0 0 0 0 0 0 0\n'
                                   'cpu1 0 0 0 0 0 0 0 0\ncpu3 0 0 0 0 0 0 0 0\n')
        after = copy.deepcopy(before)
        after['cpu'][0], after['cpu0'][0], after['cpu1'][0], after['cpu3'][0] = 900, 777, 7, 11
        self.assertEqual(self.busy(before, after), 18)

    def test_user_guest_and_irq_are_not_summed_twice_and_steal_is_excluded(self):
        before = {'cpu': [0] * 10, 'cpu1': [0] * 10, 'cpu3': [0] * 10}
        after = copy.deepcopy(before)
        after['cpu1'] = [5, 2, 3, 100, 30, 7, 11, 40, 5, 2]
        self.assertEqual(self.busy(before, after), 28)

    def test_python_sum_can_exceed_unsigned64_without_float_rounding(self):
        before = {'cpu': [0] * 10, 'cpu1': [0] * 10, 'cpu3': [0] * 10}
        after = copy.deepcopy(before)
        after['cpu1'][0] = after['cpu3'][0] = 18446744073709551615
        result = self.busy(before, after)
        self.assertIs(type(result), int)
        self.assertEqual(result, 36893488147419103230)

    def test_invalid_selected_sets_missing_rows_resets_and_width_changes_reject(self):
        before = {'cpu': [10] * 10, 'cpu1': [10] * 10, 'cpu3': [10] * 10}
        for cpus in ((), (3, 1), (1, 1), (True,), (2,), [1, 3]):
            with self.subTest(cpus=cpus), self.assertRaises(ValueError):
                self.busy(before, copy.deepcopy(before), cpus)
        for variant in ('missing', 'reset', 'width'):
            after = copy.deepcopy(before)
            if variant == 'missing':
                del after['cpu1']
            elif variant == 'reset':
                after['cpu1'][5] = 9
            else:
                after['cpu1'].append(10)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                self.busy(before, after)

    def test_isolated_iowait_decrease_does_not_create_busy_or_reset(self):
        before = {'cpu': [0] * 10, 'cpu1': [0] * 10, 'cpu3': [0] * 10}
        before['cpu1'][4] = 10
        after = copy.deepcopy(before)
        after['cpu1'][4] = 9
        self.assertEqual(self.busy(before, after), 0)


class SelectedCounterBounds(unittest.TestCase):
    def bounds(self, manifest, events, samples, hz=7, cpus=(1, 3)):
        try:
            return load().cpu_bounds(manifest, events, samples, hz, cpu_set=cpus)
        except TypeError as error:
            self.fail('existing CPU replay does not accept selected-set measurement: ' + str(error))

    def test_selected_integer_bounds_round_outward_using_existing_endpoints(self):
        result = self.bounds(*selected_inputs())
        self.assertEqual((result['lower'], result['upper']), (1285714285, 4285714286))
        self.assertIs(type(result['lower']), int)
        self.assertIs(type(result['upper']), int)
        self.assertEqual(result['interval_ns'], [20, 80])
        self.assertEqual(result['outer_samples'], [0, 5])
        self.assertEqual(result['inner_samples'], [2, 3])
        self.assertEqual(result['endpoint_slack_ns'], dict(before=10, after=10))

    def test_interval_adapter_unions_overlapping_records_into_one_envelope(self):
        function = getattr(load(), 'interval_bounds', None)
        self.assertTrue(callable(function), 'shared interval replay is not implemented')
        _, _, samples = selected_inputs()
        result = function([(20, 60), (30, 80), (25, 70)], samples, 7, cpu_set=(1, 3))
        self.assertEqual((result['lower'], result['upper']), (1285714285, 4285714286))
        self.assertEqual(result['interval_ns'], [20, 80])

    def test_selected_samples_require_stable_actual_identity_and_complete_online_rows(self):
        mutations = [('boot_id', 'fedcba98-7654-4321-8abc-0123456789ab'),
                     ('boot_id', ''), ('online_cpus', [0, 1]), ('online_cpus', [0, 1, 1, 3]),
                     ('online_cpus', [False, 1, 3]), ('possible_cpus', [0, 1, 3]),
                     ('clock', 'CLOCK_REALTIME'), ('clock_domain', 'other-host')]
        for field, value in mutations:
            manifest, events, samples = selected_inputs()
            samples[2][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.bounds(manifest, events, samples)
        for field in ('boot_id', 'online_cpus', 'possible_cpus', 'clock', 'clock_domain'):
            manifest, events, samples = selected_inputs()
            for sample in samples:
                del sample[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.bounds(manifest, events, samples)

    def test_boolean_tick_rate_and_busy_resets_cannot_produce_bounds(self):
        for hz in (True, 0, -1, 1.0):
            with self.subTest(hz=hz), self.assertRaises(ValueError):
                self.bounds(*selected_inputs(), hz=hz)
        manifest, events, samples = selected_inputs()
        samples[-1]['stat'] = samples[-1]['stat'].replace('cpu1 11 ', 'cpu1 1 ')
        with self.assertRaises(ValueError):
            self.bounds(manifest, events, samples)

    def test_overlap_without_two_inner_reads_has_zero_lower_bound(self):
        manifest, events, samples = selected_inputs()
        result = self.bounds(manifest, events, [samples[0], samples[-1]])
        self.assertEqual((result['lower'], result['upper']), (0, 4285714286))
        self.assertIsNone(result['inner_samples'])

    def test_iowait_regression_is_not_busy_counter_reset(self):
        manifest, events, samples = selected_inputs()
        for index, sample in enumerate(samples):
            sample['stat'] = sample['stat'].replace(' 100 0 0 0 ', ' 100 %d 0 0 ' % (10 - index))
        result = self.bounds(manifest, events, samples)
        self.assertEqual((result['lower'], result['upper']), (1285714285, 4285714286))

    def test_process_worker_irq_diagnostics_do_not_change_primary_counter_bounds(self):
        manifest, events, samples = selected_inputs()
        expected = self.bounds(manifest, events, samples)
        for sample in samples:
            sample.update(process_cpu_ns=999999999999, worker_cpu_ns=888888888888,
                          irq_cpu_ns=777777777777, poller_budget=6)
        actual = self.bounds(manifest, events, samples)
        self.assertEqual((actual['lower'], actual['upper']), (expected['lower'], expected['upper']))


if __name__ == '__main__':
    unittest.main()
