"""Software-only timer replay; literal clocks/durations and actual owner lifecycle."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
BOOT = '01234567-89ab-4cde-8f01-23456789abcd'
IDENTITY = dict(token='token', run_id='run', pid=123, process_start_ticks=456,
                returncode=0, complete=True)
OMITTED = object()
OWNER_KEYS = ('XDEV_EXT_EVAL_CPU_OWNER', 'XDEV_EXT_EVAL_CPU_JOURNAL_DIR',
              'XDEV_EXT_EVAL_CPU_TOKEN', 'XDEV_EXT_EVAL_CPU_RUN_ID',
              'XDEV_EXT_EVAL_CPU_CLOCK_DOMAIN')


def load():
    path = HERE / 'timer_scope.py'
    if not path.is_file():
        raise AssertionError('single-owner timer CPU replay is not implemented')
    spec = importlib.util.spec_from_file_location('tested_timer_scope', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def scope(clock='CLOCK_MONOTONIC', selected=None):
    selected = [0] if selected is None else selected
    held = selected != [0]
    return dict(schema=1, selected_cpus=selected, online_cpus=[0], possible_cpus=[0, 1],
                boot_id=BOOT, clock=clock, clock_domain='host',
                selection='subset' if held else 'all-online',
                status='hold' if held else 'qualified', hold_reasons=['subset'] if held else [])


def samples(clock='CLOCK_MONOTONIC', extra=False):
    # MONO and RAW deliberately have unrelated origins. No offset may be guessed.
    result = []
    for i, stamp in enumerate((0, 10, 20, 30, 40, 50, 60)):
        row = dict(before_ns=stamp, after_ns=stamp,
                   stat='cpu %d 0 0 100 0 0 0 0 0 0\ncpu0 %d 0 0 100 0 0 0 0 0 0\n' % (i, i),
                   boot_id=BOOT, online_cpus=[0], possible_cpus=[0, 1],
                   clock=clock, clock_domain='host')
        if extra:
            row['clock_brackets'] = {'CLOCK_MONOTONIC_RAW': dict(before_ns=1000+stamp, after_ns=1000+stamp)}
        result.append(row)
    return result


def journal(clock='CLOCK_MONOTONIC', shift=0):
    return [dict(kind='cpu-timer-metadata', schema=1, token='token', run_id='run',
                 pid=123, process_start_ticks=456, clock=clock, clock_domain='host',
                 rows=2, complete=True),
            dict(kind='cpu-timer-span', metric='io_ns', key=7, start_ns=10+shift, end_ns=30+shift),
            dict(kind='cpu-timer-span', metric='io_ns', key=9, start_ns=40+shift, end_ns=50+shift)]


class TimerReplay(unittest.TestCase):
    def replay(self, rows=None, raw=None, cpu_scope=None, keys=(7, 9), duration=30,
               expected_identity=IDENTITY):
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'closed.jsonl'
            if isinstance(rows, str):
                path.write_text(rows)
            else:
                path.write_text(''.join(json.dumps(row) + '\n' for row in (journal() if rows is None else rows)))
            binding = {} if expected_identity is OMITTED else dict(expected_identity=expected_identity)
            return module.timer_bounds(path, samples() if raw is None else raw, 3,
                                       cpu_scope=scope() if cpu_scope is None else cpu_scope,
                                       metric='io_ns', keys=keys, expected_duration_ns=duration,
                                       interval_mode='union', **binding)

    def test_exact_original_keys_and_duration_replay_union_without_oracle_gap(self):
        result = self.replay()
        self.assertEqual((result['lower'], result['upper']), (1000000000, 1000000000))
        self.assertEqual(result['measured_ns'], 30)
        self.assertEqual(result['intervals_ns'], [[10, 30], [40, 50]])
        self.assertEqual(result['outer_sample_ranges'], [[1, 3], [4, 5]])

    def test_closed_success_receipt_identity_must_match_all_four_journal_fields(self):
        for field, value in [('token', 'other-token'), ('run_id', 'other-run'),
                             ('pid', 124), ('process_start_ticks', 457), ('pid', True)]:
            expected = dict(IDENTITY, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.replay(expected_identity=expected)
        for field in IDENTITY:
            expected = dict(IDENTITY)
            del expected[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                self.replay(expected_identity=expected)
        with self.assertRaises((TypeError, ValueError)):
            self.replay(expected_identity=OMITTED)

    def test_failed_or_incomplete_observed_child_cannot_yield_primary_bounds(self):
        for changes in (dict(returncode=17), dict(returncode=-9), dict(returncode=False),
                        dict(complete=False), dict(complete=1)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.replay(expected_identity=dict(IDENTITY, **changes))

    def test_raw_top_level_and_actual_extra_brackets_replay_same_ticks(self):
        raw = self.replay(journal('CLOCK_MONOTONIC_RAW'), samples('CLOCK_MONOTONIC_RAW'),
                          scope('CLOCK_MONOTONIC_RAW'))
        dual = self.replay(journal('CLOCK_MONOTONIC_RAW', 1000), samples(extra=True))
        self.assertEqual((raw['lower'], raw['upper']), (1000000000, 1000000000))
        self.assertEqual((dual['lower'], dual['upper']), (1000000000, 1000000000))
        self.assertEqual(dual['intervals_ns'], [[1010, 1030], [1040, 1050]])

    def test_foreign_clock_missing_or_regressing_extra_brackets_cannot_fallback(self):
        variants = [samples()]
        for mutation in ('missing', 'reverse', 'regress'):
            rows = samples(extra=True)
            if mutation == 'missing':
                del rows[3]['clock_brackets']
            elif mutation == 'reverse':
                rows[3]['clock_brackets']['CLOCK_MONOTONIC_RAW']['after_ns'] = 1029
            else:
                rows[3]['clock_brackets']['CLOCK_MONOTONIC_RAW'] = dict(before_ns=1010, after_ns=1010)
            variants.append(rows)
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.replay(journal('CLOCK_MONOTONIC_RAW', 1000), raw)

    def test_reported_duration_must_be_exact_before_union(self):
        for value in (29, 31, 0, -1, True, 30.0):
            with self.subTest(duration=value), self.assertRaises(ValueError):
                self.replay(duration=value)
        # Overlapping actors report original 20+20; their union is only 30.
        rows = journal()
        rows[2].update(start_ns=20, end_ns=40)
        result = self.replay(rows, duration=40)
        self.assertEqual(result['measured_ns'], 30)
        with self.assertRaises(ValueError):
            self.replay(rows, duration=30)

    def test_requested_keys_cannot_omit_duplicate_or_invent_measured_rows(self):
        for keys in ((), (7,), (7, 7, 9), (7, 9, 11), (True, 9)):
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                self.replay(keys=keys)

    def test_duplicate_partial_foreign_or_nonpositive_journal_is_rejected(self):
        variants = []
        for field, value in [('complete', False), ('rows', 1), ('rows', True),
                             ('clock', 'CLOCK_REALTIME'), ('clock_domain', 'foreign'),
                             ('pid', True), ('process_start_ticks', 0), ('token', '')]:
            rows = journal()
            rows[0][field] = value
            variants.append(rows)
        variants.extend([journal()[:-1], journal()+[journal()[1]],
                         '{"kind":"cpu-timer-metadata"}\n{"kind":'])
        for field, value in [('end_ns', 10), ('start_ns', True), ('key', 7)]:
            rows = journal()
            rows[2][field] = value
            variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                self.replay(rows)

    def test_scope_hold_and_changed_raw_identity_do_not_produce_primary(self):
        with self.assertRaises(ValueError):
            self.replay(cpu_scope=scope(selected=[1]))
        for field, value in [('boot_id', 'fedcba98-7654-4321-8abc-0123456789ab'),
                             ('online_cpus', [0, 1]), ('possible_cpus', [0, 1, 2]),
                             ('clock_domain', 'foreign')]:
            rows = samples()
            rows[3][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.replay(raw=rows)


class TimerOwner(unittest.TestCase):
    def clean_environment(self):
        return {k: v for k, v in os.environ.items() if k not in OWNER_KEYS}

    def test_three_attached_contexts_keep_one_sampler_and_do_not_stop_owner(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp) / 'owner') as owner:
                env = owner.environment(dict(os.environ))
                config = json.loads(Path(env['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                self.assertEqual(config['schema'], 1)
                self.assertEqual(config['measurement_cpu_count'],
                                 len(config['cpu_scope']['selected_cpus']))
                self.assertEqual(config['cpu_scope']['selected_cpus'], config['cpu_scope']['online_cpus'])
                self.assertTrue(config['cpu_scope']['selected_cpus'])
                self.assertEqual(config['cpu_scope']['selection'], 'all-online')
                sampler_threads = [t for t in threading.enumerate() if t.name == 'native-cpu-sampler']
                self.assertEqual(len(sampler_threads), 1)
                stream = Path(config['samples_path'])
                self.assertTrue(stream.is_absolute())
                self.assertTrue(Path(config['journal_dir']).is_dir())
                self.assertTrue(Path(config['receipts_dir']).is_absolute())
                self.assertEqual(stat.S_IMODE(Path(config['receipts_dir']).stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(Path(env['XDEV_EXT_EVAL_CPU_OWNER']).parent.stat().st_mode), 0o700)
                with patch.dict(os.environ, env, clear=True):
                    for _ in range(3):
                        with module.TimerCpuRun(None) as attached:
                            self.assertEqual(attached.environment({})['XDEV_EXT_EVAL_CPU_OWNER'],
                                             env['XDEV_EXT_EVAL_CPU_OWNER'])
                            self.assertEqual([t for t in threading.enumerate()
                                              if t.name == 'native-cpu-sampler'], sampler_threads)
                        self.assertTrue(sampler_threads[0].is_alive())
                time.sleep(.025)
            self.assertFalse(sampler_threads[0].is_alive())
            self.assertGreaterEqual(len(stream.read_text().splitlines()), 2)

    @staticmethod
    def process_identity(pid):
        # Linux proc_pid_stat field 22, with comm allowed to contain spaces/paren.
        tail = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()
        return int(tail[19]), int(tail[1])

    def closed_receipts(self, config):
        rows = []
        for path in Path(config['receipts_dir']).rglob('*'):
            if path.is_file():
                text = path.read_text()
                try:
                    value = json.loads(text)
                    rows.extend(value if isinstance(value, list) else [value])
                except json.JSONDecodeError:
                    rows.extend(json.loads(line) for line in text.splitlines())
        return [row for row in rows if isinstance(row, dict) and 'pid' in row]

    def test_watch_existing_popen_records_actual_child_and_observer_identity(self):
        module = load()
        command = [sys.executable, '-c', "import time; time.sleep(.2); print('child-output')"]
        observer_start, _ = self.process_identity(os.getpid())
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as child:
                    start_ticks, ppid = self.process_identity(child.pid)
                    watch = getattr(owner, 'watch_child', None)
                    self.assertTrue(callable(watch), 'owner cannot observe existing Popen child identity')
                    watch(child, command)
                    output, _ = child.communicate(timeout=3)
                    self.assertEqual(output, 'child-output\n')
                    pid = child.pid
            matching = [row for row in self.closed_receipts(config) if row['pid'] == pid]
            self.assertEqual(len(matching), 1)
            receipt = matching[0]
            for key, value in dict(token=config['token'], run_id=config['run_id'], pid=pid,
                                   process_start_ticks=start_ticks, observed_ppid=ppid,
                                   observer_pid=os.getpid(), observer_start_ticks=observer_start,
                                   argv=command, returncode=0, complete=True).items():
                self.assertEqual(receipt[key], value, key)

    def test_run_preserves_explicit_environment_and_binds_successful_child(self):
        module = load()
        command = [sys.executable, '-c',
                   "import json,os; print(json.dumps([os.environ.get(k) for k in "
                   "['ONLY_MARKER','XDEV_EXT_EVAL_CPU_TOKEN','XDEV_EXT_EVAL_CPU_RUN_ID']]))"]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                run = getattr(owner, 'run', None)
                self.assertTrue(callable(run), 'owner lacks observed subprocess.run wrapper')
                done = run(command, env={'ONLY_MARKER': 'kept'}, capture_output=True,
                           text=True, check=True, timeout=3)
                self.assertIsInstance(done, subprocess.CompletedProcess)
                self.assertEqual(done.returncode, 0)
                self.assertEqual(json.loads(done.stdout), ['kept', config['token'], config['run_id']])
            receipts = [row for row in self.closed_receipts(config) if row['argv'] == command]
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]['returncode'], 0)
            self.assertIs(receipts[0]['complete'], True)

    def test_run_preserves_completedprocess_output_and_records_failed_child(self):
        module = load()
        command = [sys.executable, '-c', "import sys; print('failed-output'); sys.exit(17)"]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                run = getattr(owner, 'run', None)
                self.assertTrue(callable(run), 'owner lacks narrow subprocess.run-compatible observation')
                done = run(command, capture_output=True, text=True, check=False, timeout=3)
                self.assertIsInstance(done, subprocess.CompletedProcess)
                self.assertEqual((done.returncode, done.stdout, done.stderr), (17, 'failed-output\n', ''))
                self.assertEqual(done.args, command)
            receipts = [row for row in self.closed_receipts(config) if row['argv'] == command]
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]['returncode'], 17)
            self.assertIs(receipts[0]['complete'], True)
            self.assertIs(type(receipts[0]['pid']), int)
            self.assertGreater(receipts[0]['process_start_ticks'], 0)

    def test_run_preserves_check_exception_and_closes_failed_receipt(self):
        module = load()
        command = [sys.executable, '-c', "import sys; print('checked-failure'); sys.exit(17)"]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                run = getattr(owner, 'run', None)
                self.assertTrue(callable(run), 'owner lacks subprocess.run check semantics')
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    run(command, capture_output=True, text=True, check=True, timeout=3)
                self.assertEqual((raised.exception.returncode, raised.exception.stdout),
                                 (17, 'checked-failure\n'))
            receipts = [row for row in self.closed_receipts(config) if row['argv'] == command]
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]['returncode'], 17)
            self.assertIs(receipts[0]['complete'], True)

    def test_owner_exception_joins_and_retains_closed_samples(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with self.assertRaisesRegex(RuntimeError, 'child timeout'):
                with module.TimerCpuRun(Path(tmp) / 'owner') as owner:
                    config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                    raise RuntimeError('child timeout')
            self.assertFalse(any(t.name == 'native-cpu-sampler' for t in threading.enumerate()))
            self.assertGreaterEqual(len(Path(config['samples_path']).read_text().splitlines()), 2)

    def test_attached_scope_or_output_conflict_is_rejected_without_stopping_owner(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp) / 'owner') as owner:
                env = owner.environment({})
                with patch.dict(os.environ, env):
                    for kwargs in (dict(output=Path(tmp)/'foreign'), dict(output=None, cpu_set='999999999')):
                        with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                            with module.TimerCpuRun(**kwargs):
                                pass
                self.assertEqual(len([t for t in threading.enumerate() if t.name == 'native-cpu-sampler']), 1)

    def test_malformed_inherited_owner_never_silently_starts_new_capture(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            path = Path(tmp)/'owner.json'
            path.write_text('{"schema":1}')
            with patch.dict(os.environ, {'XDEV_EXT_EVAL_CPU_OWNER': str(path)}):
                with self.assertRaises(ValueError):
                    with module.TimerCpuRun(None):
                        pass
            self.assertFalse(any(t.name == 'native-cpu-sampler' for t in threading.enumerate()))



class ObservedChildQualification(unittest.TestCase):
    """Copied owner-shaped files cannot replace actual child observations."""
    clean_environment = TimerOwner.clean_environment

    def test_nonexistent_child_receipt_and_matching_journal_cannot_qualify(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                begin = time.monotonic_ns()
                time.sleep(.025)
                end = time.monotonic_ns()
                fake_pid = 2000000000
                self.assertFalse(Path('/proc/%d' % fake_pid).exists())
                receipt = dict(schema=1, token=config['token'], run_id=config['run_id'],
                               pid=fake_pid, process_start_ticks=123,
                               observer_pid=config['owner_pid'],
                               observer_start_ticks=config['owner_start_ticks'],
                               observed_ppid=config['owner_pid'], ppid=config['owner_pid'],
                               argv=['/never-executed'], command=['/never-executed'],
                               returncode=0, complete=True)
                (Path(config['receipts_dir'])/'forged.json').write_text(json.dumps(receipt)+'\n')
                metadata = dict(kind='cpu-timer-metadata', schema=1, token=config['token'],
                                run_id=config['run_id'], pid=fake_pid, process_start_ticks=123,
                                clock='CLOCK_MONOTONIC', clock_domain=config['cpu_scope']['clock_domain'],
                                rows=1, complete=True)
                row = dict(kind='cpu-timer-span', metric='io_ns', key=0, start_ns=begin, end_ns=end)
                (Path(config['journal_dir'])/'forged.jsonl').write_text(
                    json.dumps(metadata)+'\n'+json.dumps(row)+'\n')
            result = owner.measurement([dict(arm='uring-cuda', identity={'test': 'forged'},
                                      metric='io_ns', keys=[0], expected_duration_ns=end-begin,
                                      endpoint_semantics='retired-pass', clock='CLOCK_MONOTONIC')])
            self.assertNotEqual(result['status'], 'qualified',
                                'unobserved nonexistent child was promoted by copied owner identity')
            self.assertTrue(all(view.get('bounds') is None for view in result.get('views', [])))

    def test_actual_observed_software_child_journal_can_qualify(self):
        module = load()
        child_source = """import json,os,time
from pathlib import Path
config=json.loads(Path(os.environ['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
start_ticks=int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19])
t0=time.monotonic_ns()
time.sleep(.025)
t1=time.monotonic_ns()
metadata=dict(kind='cpu-timer-metadata',schema=1,token=config['token'],run_id=config['run_id'],
              pid=os.getpid(),process_start_ticks=start_ticks,clock='CLOCK_MONOTONIC',
              clock_domain=config['cpu_scope']['clock_domain'],rows=1,complete=True)
row=dict(kind='cpu-timer-span',metric='io_ns',key=0,start_ns=t0,end_ns=t1)
(Path(config['journal_dir'])/'actual-child.jsonl').write_text(json.dumps(metadata)+'\\n'+json.dumps(row)+'\\n')
print(json.dumps(dict(duration=t1-t0,pid=os.getpid(),start_ticks=start_ticks)))
"""
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                done = owner.run([sys.executable, '-c', child_source],
                                 capture_output=True, text=True, check=True, timeout=3)
                actual = json.loads(done.stdout)
            result = owner.measurement([dict(arm='uring-cuda', identity={'test': 'actual-child'},
                                      metric='io_ns', keys=[0], expected_duration_ns=actual['duration'],
                                      endpoint_semantics='retired-pass', clock='CLOCK_MONOTONIC')])
            self.assertEqual(result['status'], 'qualified', result)
            self.assertEqual(len(result['views']), 1)
            self.assertIsNotNone(result['views'][0]['bounds'])
            self.assertEqual(result['views'][0]['measured_ns'], actual['duration'])


class ObservationFailurePreservesWorkload(unittest.TestCase):
    """Measurement sidecar refusal cannot replace a workload's own outcome."""
    clean_environment = TimerOwner.clean_environment

    def refuse_receipts(self, owner):
        config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
        Path(config['receipts_dir']).rmdir()

    def assert_cpu_held(self, owner):
        result = owner.measurement([])
        self.assertNotEqual(result['status'], 'qualified')
        self.assertTrue(all(view.get('bounds') is None for view in result.get('views', [])))

    def test_receipt_write_failure_preserves_success_and_nonzero_completedprocess(self):
        module = load()
        for code in (0, 17):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp, patch.dict(
                    os.environ, self.clean_environment(), clear=True):
                with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                    self.refuse_receipts(owner)
                    command = [sys.executable, '-c',
                               "import sys; print('original-output'); sys.exit(%d)" % code]
                    try:
                        done = owner.run(command, capture_output=True, text=True, check=False)
                    except OSError as error:
                        self.fail('CPU receipt failure replaced workload returncode %d: %s' % (code, error))
                    self.assertIsInstance(done, subprocess.CompletedProcess)
                    self.assertEqual((done.returncode, done.stdout, done.stderr),
                                     (code, 'original-output\n', ''))
                self.assert_cpu_held(owner)

    def test_receipt_write_failure_preserves_check_exception_and_original_output(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                self.refuse_receipts(owner)
                try:
                    with self.assertRaises(subprocess.CalledProcessError) as raised:
                        owner.run([sys.executable, '-c',
                                   "import sys; print('checked-original'); sys.exit(17)"],
                                  capture_output=True, text=True, check=True)
                except OSError as error:
                    self.fail('CPU receipt failure replaced original CalledProcessError: '+str(error))
                self.assertEqual((raised.exception.returncode, raised.exception.stdout),
                                 (17, 'checked-original\n'))
            self.assert_cpu_held(owner)

    def test_receipt_write_failure_does_not_swallow_original_workload_timeout(self):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner') as owner:
                self.refuse_receipts(owner)
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        owner.run([sys.executable, '-c', 'import time; time.sleep(5)'],
                                  capture_output=True, text=True, timeout=.05)
                except OSError as error:
                    self.fail('CPU receipt failure replaced original TimeoutExpired: '+str(error))
            self.assert_cpu_held(owner)


class ActualNestedProcessOwnership(unittest.TestCase):
    """Real process ancestry qualifies only when the root observed each child."""
    clean_environment = TimerOwner.clean_environment

    def nested_program(self, observe, child_exit, mutate_receipt=False):
        child = """import json,os,time,sys
from pathlib import Path
config=json.loads(Path(os.environ['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
start_ticks=int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19])
t0=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
time.sleep(CHILD_SLEEP)
t1=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
metadata=dict(kind='cpu-timer-metadata',schema=1,token=config['token'],run_id=config['run_id'],
              pid=os.getpid(),process_start_ticks=start_ticks,clock='CLOCK_MONOTONIC_RAW',
              clock_domain=config['cpu_scope']['clock_domain'],rows=1,complete=True)
row=dict(kind='cpu-timer-span',metric='window_ns',key=0,start_ns=t0,end_ns=t1)
(Path(config['journal_dir'])/'actual-nested-child.jsonl').write_text(json.dumps(metadata)+'\\n'+json.dumps(row)+'\\n')
print(json.dumps(dict(duration=t1-t0,pid=os.getpid(),ppid=os.getppid(),start_ticks=start_ticks)))
sys.exit(CHILD_EXIT)
""".replace('CHILD_EXIT', str(child_exit)).replace('CHILD_SLEEP', repr(.12 if observe else 0))
        parent = """import importlib.util,json,subprocess,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('actual_nested_timer', TIMER_PATH)
timer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(timer)
with timer.TimerCpuRun(None,clock='CLOCK_MONOTONIC_RAW') as attached:
    command=[sys.executable,'-c',CHILD_SOURCE]
    done=RUN_CHILD(command,capture_output=True,text=True,check=False)
    actual=json.loads(done.stdout)
result=attached.measurement([dict(arm='userspace-shared',identity={'fixture':'nested-software'},
    metric='window_ns',keys=[0],expected_duration_ns=actual['duration'],
    endpoint_semantics='original-closed-window',clock='CLOCK_MONOTONIC_RAW')])
print(json.dumps(dict(child=actual,child_returncode=done.returncode,pending=result)))
"""
        if mutate_receipt:
            mutation = """import os
config=json.loads(Path(os.environ['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
matches=[]
for path in Path(config['receipts_dir']).glob('*.json'):
    receipt=json.loads(path.read_text())
    if receipt.get('pid')==actual['pid'] and receipt.get('process_start_ticks')==actual['start_ticks']:
        matches.append((path,receipt))
assert len(matches)==1
path,receipt=matches[0]
assert receipt['returncode']==EXPECTED_CODE
MUTATION
path.write_text(json.dumps(receipt)+'\\n')
"""
            mutation=mutation.replace('EXPECTED_CODE',str(child_exit)).replace('MUTATION',
                "receipt['observer_pid']=config['owner_pid']; receipt['observer_start_ticks']=config['owner_start_ticks']"
                if mutate_receipt=='ancestor' else "receipt['returncode']=0")
            parent=parent.replace('print(json.dumps(dict(child=actual,', mutation+'\nprint(json.dumps(dict(child=actual,')
        return parent.replace('TIMER_PATH', repr(str(HERE/'timer_scope.py'))).replace(
            'CHILD_SOURCE', repr(child)).replace('RUN_CHILD', 'attached.run' if observe else 'subprocess.run')

    def nested(self, observe, child_exit=0, mutate_receipt=False):
        module = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with module.TimerCpuRun(Path(tmp)/'owner', extra_clocks=('CLOCK_MONOTONIC_RAW',)) as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                sampler_threads = [t for t in threading.enumerate() if t.name == 'native-cpu-sampler']
                self.assertEqual(len(sampler_threads), 1)
                done = owner.run([sys.executable, '-c', self.nested_program(observe, child_exit, mutate_receipt)],
                                 capture_output=True, text=True, check=True, timeout=5)
                observed = json.loads(done.stdout)
                self.assertEqual(done.returncode, 0)
                self.assertEqual(observed['child_returncode'], child_exit)
                self.assertTrue(observed['pending'] is None or
                                observed['pending'].get('status') != 'qualified')
                self.assertEqual([t for t in threading.enumerate() if t.name == 'native-cpu-sampler'],
                                 sampler_threads)
            result = owner.measurement([])
            self.assertFalse(sampler_threads[0].is_alive())
            rows = [json.loads(line) for line in Path(config['samples_path']).read_text().splitlines()]
            self.assertGreaterEqual(len(rows), 2)
            self.assertTrue(all(row['clock'] == 'CLOCK_MONOTONIC' for row in rows))
            self.assertTrue(all('CLOCK_MONOTONIC_RAW' in row['clock_brackets'] for row in rows))
            receipts = TimerOwner.closed_receipts(self, config)
            return result, observed, receipts

    def test_actual_observed_parent_and_live_nested_child_qualify_one_raw_view(self):
        result, actual, receipts = self.nested(True)
        child_receipts = [row for row in receipts if row['pid'] == actual['child']['pid']]
        self.assertEqual(len(child_receipts), 1)
        child_receipt = child_receipts[0]
        self.assertEqual(child_receipt['process_start_ticks'], actual['child']['start_ticks'])
        self.assertEqual(child_receipt['observer_pid'], actual['child']['ppid'])
        self.assertTrue(any(row['pid'] == child_receipt['observer_pid'] for row in receipts))
        self.assertEqual(result['status'], 'qualified', result)
        self.assertEqual(len(result['views']), 1)
        self.assertEqual(result['views'][0]['clock'], 'CLOCK_MONOTONIC_RAW')
        self.assertEqual(result['views'][0]['measured_ns'], actual['child']['duration'])
        self.assertIsNotNone(result['views'][0]['bounds'])

    def test_successful_nested_child_with_mismatched_observer_ancestor_stays_held(self):
        result, actual, _ = self.nested(True, child_exit=0, mutate_receipt='ancestor')
        self.assertEqual(actual['child_returncode'], 0)
        self.assertNotEqual(result['status'], 'qualified', result)
        self.assertTrue(all(view.get('bounds') is None for view in result.get('views', [])))

    def test_failed_observed_nested_child_cannot_qualify_after_receipt_file_status_edit(self):
        result, actual, _ = self.nested(True, child_exit=17, mutate_receipt=True)
        self.assertEqual(actual['child_returncode'], 17)
        self.assertNotEqual(result['status'], 'qualified', result)
        self.assertTrue(all(view.get('bounds') is None for view in result.get('views', [])))

    def test_unobserved_nested_child_keeps_original_nonzero_returncode_and_hold(self):
        result, actual, _ = self.nested(False, child_exit=17)
        self.assertEqual(actual['child_returncode'], 17)
        self.assertNotEqual(result['status'], 'qualified', result)
        self.assertTrue(all(view.get('bounds') is None for view in result.get('views', [])))


class DeferredNativeOwnerFinalization(unittest.TestCase):
    """Synthetic native ABI artifacts replay only after the real owner stops."""
    clean_environment = TimerOwner.clean_environment

    def test_fixture_native_capture_is_held_then_automatically_sealed_and_reimported(self):
        import hashlib
        native_dir = HERE.parent/'native_views'
        spec = importlib.util.spec_from_file_location('deferred_native_fixture', native_dir/'test_runtime_import.py')
        fixtures = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(native_dir))
        try:
            spec.loader.exec_module(fixtures)
        finally:
            sys.path.remove(str(native_dir))
        fixture = fixtures.RuntimeImport('test_unknown_native_ids_bind_without_changing_expected_work')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        timer = load()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.clean_environment(), clear=True):
            with timer.TimerCpuRun(Path(tmp)/'owner', clock_domain=fixture.manifest['clock_domain'],
                                   extra_clocks=('CLOCK_MONOTONIC_RAW',)) as owner:
                config = json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
                selected = dict(cpu_scope=config['cpu_scope'],
                                measurement_cpu_count=config['measurement_cpu_count'],
                                cpu_accounting='cpu_set_total', cpu_budget=1)
                fixture.manifest.update(selected)
                fixture.metadata.update(selected)
                fixture.metadata.update(cpu_interval_scope='native_interval_counter_bounds',
                    cpu_sampler_error='outer owner capture pending; native replay requires finalized owner artifacts')
                # Existing ABI fixture is synthetic; only its counter-clock
                # endpoints are created inside the real owner sample envelope.
                text = ''
                for native, pid, process_start in ((99,47,123), (100,48,124)):
                    text += fixture.abi.raw('session_bind', '1.0', ts_ns=time.monotonic_ns(),
                        session_id=native, origin_tgid=pid, process_start_ticks=process_start, aux=2)
                for phase, generation in [('record_admit',0), ('native_submit',11),
                                          ('native_complete',11), ('record_terminal',11)]:
                    text += fixture.abi.raw(phase, '1.0', ts_ns=time.monotonic_ns(), session_id=99,
                        origin_tgid=47, process_start_ticks=123, generation=generation,
                        frame_id=501, frame_ordinal=0, frame_offset=0, frame_length=4096,
                        batch_key=1, cookie=500, aux=2)
                    time.sleep(.005)
                fixture.artifact('raw_trace', text)
                events = fixture.collector.decode_trace(fixture.manifest, text, fixture.metadata)
                fixture.artifact('events', ''.join(json.dumps(row)+'\n' for row in events))
                mapped = fixture.collector.derive_mapped_manifest(fixture.manifest, text, fixture.metadata)
                fixture.artifact('mapped_manifest', json.dumps(mapped))
                fixture.artifact('trace_metadata', json.dumps(fixture.metadata))
                fixture.receipt['cpu_owner_pending'] = True
                manifest_path = fixture.directory/'pending-manifest.json'
                receipt_path = fixture.directory/'pending-collection.json'
                manifest_path.write_text(json.dumps(fixture.manifest))
                receipt_path.write_text(json.dumps(fixture.receipt))
                immediate = fixture.import_run()
                self.assertIsNone(immediate['manifest'].get('total_cpu_ns_bounds'))
                self.assertFalse(immediate['performance_eligible'])
                self.assertTrue(any('system_cpu' in error for error in immediate['errors']))
                with patch.dict(os.environ, owner.environment(dict(os.environ)), clear=True):
                    with timer.TimerCpuRun(None) as attached_collector:
                        defer = getattr(attached_collector, 'defer_native', None)
                        self.assertTrue(callable(defer), 'outer owner cannot finalize attached native artifacts')
                        defer(manifest_path, receipt_path)
                # Neither immediate import nor deferral may stop the outer stream.
                self.assertEqual(len([t for t in threading.enumerate() if t.name=='native-cpu-sampler']),1)
            finalizations = owner.config['native_finalizations']
            final_metadata = json.loads((Path(config['samples_path']).parent/'final.json').read_text())
            self.assertEqual(len(finalizations), 1, final_metadata.get('evidence_errors'))
            finalized = finalizations[0]
            imported = json.loads(Path(finalized['imported_run_path']).read_text())
            collection = json.loads(Path(finalized['collection_path']).read_text())
            self.assertIs(collection['cpu_owner_pending'], False)
            sample_ref = collection['artifacts']['cpu_samples']
            self.assertEqual(Path(sample_ref['path']), Path(config['samples_path']))
            self.assertEqual(sample_ref['sha256'], hashlib.sha256(Path(sample_ref['path']).read_bytes()).hexdigest())
            metadata_ref = collection['artifacts']['trace_metadata']
            self.assertEqual(metadata_ref['sha256'], hashlib.sha256(Path(metadata_ref['path']).read_bytes()).hexdigest())
            metadata = json.loads(Path(metadata_ref['path']).read_text())
            self.assertIsNone(metadata['cpu_sampler_error'])
            self.assertEqual(metadata['cpu_scope'], config['cpu_scope'])
            self.assertIsNotNone(imported['manifest'].get('total_cpu_ns_bounds'), imported['errors'])
            self.assertFalse(imported['performance_eligible'])
            self.assertIs(imported['manifest']['physical'], False)
            self.assertEqual(imported['manifest']['evidence_kind'], 'fixture')
            self.assertFalse(any(t.name=='native-cpu-sampler' for t in threading.enumerate()))


class NonregularObservationRequest(unittest.TestCase):
    """A nonregular request cannot stall the existing sampler callback/join."""
    clean_environment = TimerOwner.clean_environment

    def test_fifo_request_exits_bounded_with_cpu_hold_and_explicit_exit_marker(self):
        # Outer timeout detects a shutdown hang; it is not a semantic-mutant score.
        program = """import importlib.util,json,os,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('fifo_request_timer',sys.argv[1])
timer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(timer)
with timer.TimerCpuRun(Path(sys.argv[2])) as owner:
    config=json.loads(Path(owner.environment({})['XDEV_EXT_EVAL_CPU_OWNER']).read_text())
    os.mkfifo(Path(config['receipts_dir'])/'blocking.request')
    time.sleep(.08)
result=owner.measurement([])
final=json.loads((Path(config['samples_path']).parent/'final.json').read_text())
print(json.dumps(dict(exited=True,result=result,evidence_errors=final.get('evidence_errors'))))
"""
        with tempfile.TemporaryDirectory() as tmp:
            try:
                done = subprocess.run([sys.executable, '-c', program, str(HERE/'timer_scope.py'),
                                       str(Path(tmp)/'owner')], capture_output=True, text=True,
                                      timeout=3, env=self.clean_environment())
            except subprocess.TimeoutExpired:
                self.fail('FIFO request blocked owner exit beyond the bounded 3s shutdown harness')
            self.assertEqual(done.returncode, 0, done.stderr)
            report = json.loads(done.stdout)
            self.assertIs(report['exited'], True)
            self.assertNotEqual(report['result']['status'], 'qualified')
            self.assertTrue(report['evidence_errors'], 'nonregular request was silently ignored')
            self.assertTrue(all(view.get('bounds') is None for view in report['result'].get('views', [])))

if __name__ == '__main__':
    unittest.main()
