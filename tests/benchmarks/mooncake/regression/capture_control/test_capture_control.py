"""Independent operation-order and cleanup tests for actual production Capture.

Expectations come from ROOT-CONTRACT.md. Only OS boundaries are instrumented;
actual Capture, selector, pipe reads, signals, waits and receipts execute unchanged.
"""
import importlib.util
import json
import os
from pathlib import Path
import queue
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
DEFAULT_EXECUTOR = HERE.parents[1] / 'executor.py'
EXECUTOR = Path(os.environ.get('CAPTURE_EXECUTOR', str(DEFAULT_EXECUTOR)))


def _new_artifact_directory():
    explicit = os.environ.get('CAPTURE_ARTIFACTS')
    if explicit is not None:
        if not explicit:
            raise ValueError('CAPTURE_ARTIFACTS must name an absent absolute directory')
        selected = Path(explicit).expanduser()
        if not selected.is_absolute():
            raise ValueError('CAPTURE_ARTIFACTS must name an absent absolute directory')
        selected.mkdir(mode=0o700, parents=True, exist_ok=False)
        return selected
    parent = HERE.parents[4] / 'build' / 'mooncake-capture-tests' / HERE.name
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='run-', dir=parent))


TRACE_DIR = _new_artifact_directory()
print('capture artifacts: ' + str(TRACE_DIR), file=sys.stderr)
spec = importlib.util.spec_from_file_location('actual_capture_executor', EXECUTOR)
ex = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ex
spec.loader.exec_module(ex)


def until(predicate, label, seconds=6):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError('synchronization timeout: ' + label)
        time.sleep(.002)


class Timeline:
    def __init__(self):
        self.items = []
        self.lock = threading.Lock()

    def add(self, event, **details):
        with self.lock:
            self.items.append(dict(index=len(self.items), event=event,
                                   thread=threading.current_thread().name, **details))

    def save(self, name):
        (TRACE_DIR / (name + '.json')).write_text(json.dumps(self.items, indent=2) + '\n')


class AcquireBoundary:
    """Transparent underlying RLock; pause one nominated caller before acquire.

    The post-detection collector gate merely prevents further unobserved barging
    while releasing the test; it is armed only AFTER the decisive second select.
    """
    def __init__(self, real, timeline):
        self.real = real
        self.timeline = timeline
        self.foreground = None
        self.collector = None
        self.entered = threading.Event()
        self.release_foreground = threading.Event()
        self.foreground_returned = threading.Event()
        self.detected_second = threading.Event()
        self.once = False
        self.pause_at = 1
        self.foreground_acquires = 0
        self.raise_once = False

    def acquire(self, *args, **kwargs):
        current = threading.current_thread()
        if current is self.foreground:
            self.foreground_acquires += 1
        if current is self.foreground and not self.once and self.foreground_acquires == self.pause_at:
            self.once = True
            self.timeline.add('foreground_before_real_acquire')
            self.entered.set()
            if not self.release_foreground.wait(6):
                raise RuntimeError('foreground acquisition gate not released')
            if self.raise_once:
                self.timeline.add('foreground_acquire_exception')
                raise OSError('independent real-lock boundary failure')
        if (current is self.collector and self.detected_second.is_set()
                and not self.foreground_returned.is_set()):
            if not self.foreground_returned.wait(6):
                raise RuntimeError('post-observation collector release not reached')
        result = self.real.acquire(*args, **kwargs)
        if current is self.foreground:
            self.timeline.add('foreground_real_acquire', acquisition_number=self.foreground_acquires)
        return result

    def release(self):
        return self.real.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *unused):
        self.release()

    def _is_owned(self):
        return self.real._is_owned()

    def _release_save(self):
        return self.real._release_save()

    def _acquire_restore(self, state):
        return self.real._acquire_restore(state)


class SelectBoundary:
    """Delegate every real select; first admitted collector pump is held."""
    def __init__(self, real, boundary, timeline, observations):
        self.real = real
        self.boundary = boundary
        self.timeline = timeline
        self.observations = observations
        self.entered = threading.Event()
        self.release_first = threading.Event()
        self.collector_calls = 0

    def select(self, timeout=None):
        if threading.current_thread() is self.boundary.collector:
            self.collector_calls += 1
            number = self.collector_calls
            self.timeline.add('collector_select', number=number)
            if number == 1:
                self.entered.set()
                if not self.release_first.wait(6):
                    raise RuntimeError('first admitted selector not released')
            elif number == 2 and not self.boundary.foreground_returned.is_set():
                self.boundary.detected_second.set()
                self.observations.put('second_select')
                if not self.boundary.release_foreground.wait(6):
                    raise RuntimeError('second selector release not reached')
        result = self.real.select(timeout)
        self.timeline.add('actual_select_return', ready=len(result))
        return result

    def close(self):
        self.timeline.add('actual_selector_close')
        return self.real.close()

    def __getattr__(self, name):
        return getattr(self.real, name)


class CaptureTests(unittest.TestCase):
    """Every check below is on production state, raw bytes, ordering or receipts."""
    assertion_count = 0

    def check(self, condition, message):
        type(self).assertion_count += 1
        self.assertTrue(condition, message)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='owned-', dir=TRACE_DIR)
        self.directory = Path(self.temp.name)
        self.captures = []

    def tearDown(self):
        # Independent emergency cleanup never substitutes for asserted cleanup.
        for capture in self.captures:
            child = capture.process
            if child is not None and child.poll() is None:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            if child is not None:
                child.wait(timeout=3)
            collector = capture._collector
            if collector is not None:
                collector.join(3)
            if not capture.closed and (collector is None or not collector.is_alive()):
                capture._close()
        self.temp.cleanup()

    def capture(self, mode='idle'):
        cap = ex.Capture([sys.executable, '-u', str(HERE / 'child.py'), mode],
                         {'PATH': '/usr/bin:/bin'}, self.directory, 30)
        self.captures.append(cap)
        until(lambda: (self.directory / 'child-ready').exists(), 'child signal handlers ready')
        return cap

    def assert_cleanup(self, cap, outcome, require_flag=True):
        if require_flag:
            self.check(outcome.cleanup_complete, 'actual cleanup must complete')
        self.check(cap.closed, 'selector/raw closure must be reached')
        self.check(cap.process.poll() is not None, 'owned direct child must be reaped')
        self.check(cap._collector is None or not cap._collector.is_alive(), 'collector must stop')
        self.check(all(stream.closed for stream in cap.files.values()), 'raw descriptors must close')
        self.check(cap.process.stdout.closed and cap.process.stderr.closed, 'pipe descriptors must close')

    def ordering(self, mode, inject_exception=False):
        cap = self.capture(mode)
        if mode == 'idle':
            cap.pump(0)  # Consume the banner before testing idle-pipe admission.
        timeline = Timeline()
        observations = queue.Queue()
        boundary = AcquireBoundary(cap._io_lock, timeline)
        boundary.raise_once = inject_exception
        cap._io_lock = boundary
        selector = SelectBoundary(cap.selector, boundary, timeline, observations)
        cap.selector = selector
        result = {}
        old_profile = threading.getprofile()
        real_killpg = os.killpg
        wait_code = threading.Condition.wait.__code__
        wait_for_code = threading.Condition.wait_for.__code__

        def profile(frame, event, arg):
            caller = frame.f_back
            if caller is not None and caller.f_code is wait_for_code:
                caller = caller.f_back
            production_wait = caller is not None and caller.f_code.co_filename == str(EXECUTOR)
            if (event == 'call' and frame.f_code is wait_code and production_wait
                    and threading.current_thread() is boundary.collector
                    and boundary.entered.is_set()
                    and not boundary.foreground_returned.is_set()):
                timeline.add('collector_condition_wait')
                observations.put('condition_wait')
            if old_profile is not None:
                old_profile(frame, event, arg)

        def killpg(pid, number):
            if pid == cap.process.pid and number == signal.SIGTERM:
                timeline.add('actual_TERM_attempt')
            return real_killpg(pid, number)

        def control():
            try:
                cap.terminate('target_stop')
                result['returned'] = True
            except BaseException as error:
                result['error'] = error
            finally:
                timeline.add('foreground_returned')
                boundary.foreground_returned.set()

        threading.setprofile(profile)
        try:
            # start_background starts the thread while holding RLock. Install
            # identity before its first selector using the production thread name.
            original_select = selector.select
            def identify_select(timeout=None):
                boundary.collector = cap._collector
                return original_select(timeout)
            selector.select = identify_select
            with patch.object(ex.os, 'killpg', killpg):
                cap.start_background()
                boundary.collector = cap._collector
                self.check(selector.entered.wait(6), 'first actual collector select must be admitted')
                thread = threading.Thread(target=control, name='independent-foreground')
                boundary.foreground = thread
                thread.start()
                self.check(boundary.entered.wait(6), 'foreground must reach actual RLock acquisition boundary')
                selector.release_first.set()
                observation = observations.get(timeout=6)
                timeline.add('harness_observation', observed=observation)
                boundary.release_foreground.set()
                thread.join(6)
                self.check(not thread.is_alive(), 'foreground must leave actual control path')
            if inject_exception:
                self.check(isinstance(result.get('error'), OSError), 'real boundary failure must propagate')
                before = cap.counts['stdout'] + cap.counts['stderr']
                (self.directory / 'drain-now').touch()
                until(lambda: cap.counts['stdout'] + cap.counts['stderr'] > before,
                      'collector resumes actual pipe drain after foreground exception')
                self.check(cap.counts['stdout'] + cap.counts['stderr'] > before,
                           'exception publication release must permit actual stream progress')
            else:
                self.check(result.get('returned') is True, 'actual terminate must return')
                terms = [e['index'] for e in timeline.items if e['event'] == 'actual_TERM_attempt']
                seconds = [e['index'] for e in timeline.items if e['event'] == 'collector_select' and e['number'] == 2]
                self.check(bool(terms), 'actual owned-group TERM transition must execute')
                self.check(not seconds or terms[0] < seconds[0],
                           'published foreground control must perform TERM before second collector pump')
        finally:
            boundary.release_foreground.set()
            selector.release_first.set()
            boundary.foreground_returned.set()
            threading.setprofile(old_profile)
            timeline.save(self._testMethodName)
            # Bound teardown after recording the decisive observation, even on RED.
            if cap.process.poll() is None:
                os.killpg(cap.process.pid, signal.SIGTERM)
            cap.process.wait(timeout=3)
            cap._collector.join(3)
        outcome = cap.finish('target_stop')
        self.assert_cleanup(cap, outcome)

    def test_idle_foreground_precedes_second_pump(self):
        self.ordering('idle')

    def test_readable_foreground_precedes_second_pump(self):
        self.ordering('busy')

    def test_exception_releases_handoff_and_real_drain_resumes(self):
        self.ordering('idle', inject_exception=True)

    def test_abort_fallback_close_precedes_second_pump(self):
        cap = self.capture('termwait')
        cap.pump(0)
        timeline = Timeline()
        observations = queue.Queue()
        boundary = AcquireBoundary(cap._io_lock, timeline)
        boundary.pause_at = 2  # terminate first; then actual fallback close.
        cap._io_lock = boundary
        selector = SelectBoundary(cap.selector, boundary, timeline, observations)
        cap.selector = selector
        result = {}
        old_profile = threading.getprofile()
        wait_code = threading.Condition.wait.__code__
        wait_for_code = threading.Condition.wait_for.__code__
        def profile(frame, event, arg):
            caller = frame.f_back
            if caller is not None and caller.f_code is wait_for_code:
                caller = caller.f_back
            if (event == 'call' and frame.f_code is wait_code
                    and caller is not None and caller.f_code.co_filename == str(EXECUTOR)
                    and threading.current_thread() is boundary.collector
                    and boundary.entered.is_set() and not boundary.foreground_returned.is_set()):
                timeline.add('collector_condition_wait')
                observations.put('condition_wait')
            if old_profile is not None: old_profile(frame, event, arg)
        def abort():
            try:
                cap._abort_owned('target_stop')
                result['returned'] = True
            except BaseException as error: result['error'] = error
            finally:
                timeline.add('foreground_returned')
                boundary.foreground_returned.set()
        thread = threading.Thread(target=abort, name='independent-fallback-close')
        boundary.foreground = thread
        threading.setprofile(profile)
        try:
            thread.start()
            until(lambda: (self.directory / 'term-entered').exists(), 'actual TERM handler entered')
            original_select = selector.select
            def identify_select(timeout=None):
                boundary.collector = cap._collector
                return original_select(timeout)
            selector.select = identify_select
            cap.start_background()
            boundary.collector = cap._collector
            self.check(selector.entered.wait(6), 'first actual fallback collector pump must be admitted')
            (self.directory / 'exit-now').touch()
            self.check(boundary.entered.wait(6), 'fallback close must reach actual RLock acquisition boundary')
            selector.release_first.set()
            observation = observations.get(timeout=6)
            timeline.add('harness_observation', observed=observation)
            boundary.release_foreground.set()
            thread.join(6)
            self.check(not thread.is_alive(), 'actual fallback close must return')
            if 'error' in result: raise result['error']
            self.check(result.get('returned') is True, 'actual abort cleanup must execute')
            closes = [e['index'] for e in timeline.items if e['event'] == 'actual_selector_close']
            seconds = [e['index'] for e in timeline.items if e['event'] == 'collector_select' and e['number'] == 2]
            self.check(bool(closes), 'actual selector closure must execute')
            close_acquires = [e['index'] for e in timeline.items if e['event'] == 'foreground_real_acquire' and e['acquisition_number'] == 2]
            self.check(bool(close_acquires), 'actual foreground fallback lock must be acquired')
            self.check(not seconds or close_acquires[0] < seconds[0],
                       'published fallback close must acquire I/O before second collector pump')
        finally:
            (self.directory / 'exit-now').touch()
            boundary.release_foreground.set(); selector.release_first.set()
            boundary.foreground_returned.set()
            thread.join(6)
            threading.setprofile(old_profile)
            timeline.save(self._testMethodName)
        cap._collector.join(3)
        self.assert_cleanup(cap, cap.finish())

    def target(self, mode='idle'):
        cell = dict(campaign_id='independent-control', cell_id='owned-target', profile='owned-profile',
                    experiment='e7', arm='tcp', block_bytes=4096, batch_requests=1,
                    source_host_id='owned-source', destination_host_id='owned-destination',
                    shape=dict(block_bytes=[4096], batch_requests=[1], worker_threads=1,
                               duration_seconds=1, buffer_bytes=4096, gpu_ordinal=0))
        context = ex.ExecutionContext('contract-fixture', 'owned-profile', {'route_qualified': True}, 'destination')
        handle = ex.start_target({'argv': [sys.executable, '-u', str(HERE / 'child.py'), mode]},
                                 cell, context, self.directory)
        self.captures.append(handle.capture)
        return handle

    def completion(self, handle):
        return dict(schema_version=1, campaign_id='independent-control', cell_id='owned-target',
                    profile='owned-profile', destination_host_id='owned-destination',
                    source_host_id='owned-source', launch_id=handle.ready_receipt['launch_id'],
                    segment_name='owned-control', endpoint='source', execution='contract-fixture',
                    status='source_completed', source_returncode=0, source_cleanup_complete=True,
                    source_receipt='owned-source-evidence.json')

    def stop_with_collector_gate(self, handle, completion, fail_select=False):
        """Use real selector boundary to synchronize stop and optional OS failure."""
        cap = handle.capture
        real_select = cap.selector.select
        entered = threading.Event()
        release = threading.Event()
        one = threading.Event()
        def select(timeout=None):
            if threading.current_thread() is cap._collector and not one.is_set():
                one.set(); entered.set()
                if not release.wait(6): raise RuntimeError('stop selector gate not released')
                if fail_select: raise OSError('independent selector I/O failure')
            return real_select(timeout)
        cap.selector.select = select
        self.check(entered.wait(6), 'collector must reach real selector boundary')
        # Stop publication occurs before unlocking the collector. A transparent
        # RLock gate avoids relying on scheduler luck for this setup too.
        timeline = Timeline()
        lock = AcquireBoundary(cap._io_lock, timeline)
        cap._io_lock = lock
        result = {}
        def stop():
            try: result['receipt'] = ex.stop_target(handle, completion)
            except BaseException as error: result['error'] = error
            finally: lock.foreground_returned.set()
        thread = threading.Thread(target=stop, name='independent-stop-target')
        lock.foreground = thread
        thread.start()
        try:
            self.check(lock.entered.wait(6), 'stop_target must enter actual foreground lock path')
            # Let foreground proceed to real acquire, then release collector.
            lock.release_foreground.set()
            release.set()
            thread.join(18)
            self.check(not thread.is_alive(), 'actual stop_target must return after existing cleanup stages')
            if 'error' in result: raise result['error']
            receipt = result['receipt']
            (TRACE_DIR / (self._testMethodName + '-receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')
            return receipt
        finally:
            release.set(); lock.release_foreground.set(); lock.foreground_returned.set()
            thread.join(2)

    def test_after_ready_dual_pipe_drain_and_clean_TERM(self):
        handle = self.target()
        cap = handle.capture
        before_out = cap.counts['stdout']
        (self.directory / 'drain-now').touch()
        until(lambda: (self.directory / 'drain-written').exists(), 'child wrote both after-ready streams')
        until(lambda: cap.counts['stdout'] >= before_out + 131072 and cap.counts['stderr'] >= 131072,
              'background drain after readiness')
        receipt = self.stop_with_collector_gate(handle, self.completion(handle))
        self.check(receipt['exit_code'] == 0, 'matched source and clean TERM must qualify')
        self.check(receipt['process']['returncode'] == 0, 'normal TERM handler must exit0')
        self.check(receipt['process']['signals'] == ('SIGTERM',) or receipt['process']['signals'] == ['SIGTERM'],
                   'normal TERM must avoid KILL escalation')
        self.check((self.directory / 'stdout.raw').read_bytes().count(b'D') == 131072,
                   'actual stdout after-ready bytes must remain exact')
        self.check((self.directory / 'stderr.raw').read_bytes() == b'E' * 131072 + b'TERM-stderr\n',
                   'actual stderr after-ready bytes and TERM tail must remain exact')
        self.assert_cleanup(cap, cap.finish())

    def test_forced_KILL_stops_child_and_never_qualifies(self):
        handle = self.target('ignore')
        receipt = self.stop_with_collector_gate(handle, self.completion(handle))
        self.check(receipt['exit_code'] != 0, 'KILL escalation must remain unqualified')
        self.check(receipt['process']['returncode'] == -signal.SIGKILL, 'ignoring child must actually die by KILL')
        self.check('SIGKILL' in receipt['process']['signals'], 'real KILL signal must be recorded')
        self.assert_cleanup(handle.capture, handle.capture.finish())

    def test_mismatched_source_receipt_still_cleans_owned_target(self):
        handle = self.target()
        completion = self.completion(handle)
        completion['launch_id'] = 'wrong-owned-launch'
        receipt = self.stop_with_collector_gate(handle, completion)
        self.check(receipt['exit_code'] != 0, 'mismatched source must remain unqualified')
        self.check(any('launch_id' in error for error in receipt['errors']), 'mismatch must stay explicit')
        self.assert_cleanup(handle.capture, handle.capture.finish())

    def test_missing_source_receipt_still_cleans_owned_target(self):
        handle = self.target()
        receipt = self.stop_with_collector_gate(handle, None)
        self.check(receipt['exit_code'] != 0, 'missing source must remain unqualified')
        self.check('missing source completion' in receipt['errors'], 'missing source must stay explicit')
        self.assert_cleanup(handle.capture, handle.capture.finish())

    def test_collector_error_after_target_stop_cannot_qualify_exit0(self):
        handle = self.target()
        cap = handle.capture
        real_select = cap.selector.select
        failed = threading.Event()
        def fail_after_term(timeout=None):
            if (threading.current_thread() is cap._collector
                    and cap.term_at is not None and not failed.is_set()):
                # Error is emitted only after production TERM publication and
                # actual child exit0; no outcome/error/success method is stubbed.
                code = cap.process.wait(timeout=3)
                if code != 0:
                    raise RuntimeError('owned TERM handler did not exit0')
                failed.set()
                raise OSError('independent selector I/O failure after target stop')
            return real_select(timeout)
        cap.selector.select = fail_after_term
        receipt = self.stop_with_collector_gate(handle, self.completion(handle))
        self.check(failed.is_set(), 'actual collector selector failure must execute after TERM')
        self.check(receipt['process']['termination'] == 'target_stop', 'first reason must stay target_stop')
        self.check(receipt['process']['returncode'] == 0, 'child must really exit0 before collector failure')
        self.check(bool(receipt['process']['error']), 'actual collector failure must stay explicit')
        self.check(receipt['exit_code'] != 0, 'collector error plus first target_stop and child0 must remain unqualified')
        self.assert_cleanup(cap, cap.finish(), require_flag=False)


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CaptureTests)
    if len(sys.argv) > 1:
        suite = unittest.defaultTestLoader.loadTestsFromNames(sys.argv[1:], module=sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                         assertions=CaptureTests.assertion_count, executor=str(EXECUTOR))))
    raise SystemExit(0 if result.wasSuccessful() else 1)
