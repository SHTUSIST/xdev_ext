"""Independent real-Condition publication-release interruption regression.

The negative-fixture pending reset is allowed solely after failure capture so a
known broken candidate's owned collector/child can be disposed. It is never a
production repair and never contributes to a successful test verdict.
"""
from dataclasses import asdict
import hashlib
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
SOURCE = Path(os.environ.get('CAPTURE_EXECUTOR', str(HERE.parents[1] / 'executor.py'))).resolve()


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


ARTIFACTS = _new_artifact_directory()
print('capture artifacts: ' + str(ARTIFACTS), file=sys.stderr)
spec = importlib.util.spec_from_file_location('actual_publication_capture', SOURCE)
actual = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = actual
spec.loader.exec_module(actual)


def until(predicate, label, seconds=4):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise RuntimeError('synchronization timeout: ' + label)
        time.sleep(.002)


class PublicationInterruption(unittest.TestCase):
    checks = 0

    def check(self, condition, message):
        type(self).checks += 1
        self.assertTrue(condition, message)

    def test_release_exception_does_not_strand_collector(self):
        events = []
        event_lock = threading.Lock()
        def record(event, **details):
            with event_lock:
                events.append(dict(index=len(events), event=event,
                                   thread=threading.current_thread().name, **details))
        temporary = tempfile.TemporaryDirectory(prefix='owned-publication-', dir=ARTIFACTS)
        directory = Path(temporary.name)
        cap = None
        foreground = None
        release_select = threading.Event()
        first_select = threading.Event()
        foreground_returned = threading.Event()
        boundaries = queue.Queue()
        injected = threading.Event()
        progress = threading.Event()
        outcome = None
        failure = None
        disposal = {'used': False, 'counts_as_success': False}
        result = {}
        try:
            cap = actual.Capture([sys.executable, '-u', str(HERE / 'child.py')],
                                 {'PATH': '/usr/bin:/bin'}, directory, 30)
            until(lambda: (directory / 'child-ready').exists(), 'owned child ready')
            cap.pump(0)
            self.check((directory / 'stdout.raw').read_bytes() == b'publication-ready\n',
                       'initial real child output must be drained before interruption')
            # Find the Capture-owned direct Condition without depending on the
            # future name or representation of its publication accounting field.
            conditions = [value for value in vars(cap).values()
                          if isinstance(value, threading.Condition)]
            self.check(len(conditions) == 1, 'Capture must expose one direct arbitration Condition to instrument')
            condition = conditions[0]
            real_select = cap.selector.select
            real_exit = threading.Condition.__exit__
            real_wait = threading.Condition.wait
            real_read = os.read
            collector_calls = [0]

            def select(timeout=None):
                if threading.current_thread() is cap._collector:
                    collector_calls[0] += 1
                    record('actual_collector_select', number=collector_calls[0])
                    if collector_calls[0] == 1:
                        first_select.set()
                        if not release_select.wait(5):
                            raise RuntimeError('first actual selector gate not released')
                    else:
                        boundaries.put('collector_selected_again')
                return real_select(timeout)

            def condition_exit(subject, *args):
                returned = real_exit(subject, *args)
                if (subject is condition and threading.current_thread() is foreground
                        and not injected.is_set()):
                    record('real_publication_condition_exit_returned')
                    injected.set()
                    record('single_KeyboardInterrupt_injected_after_real_condition_release')
                    raise KeyboardInterrupt('independent publication release interruption')
                return returned

            def condition_wait(subject, *args, **kwargs):
                if subject is condition and threading.current_thread() is cap._collector:
                    record('actual_collector_condition_wait_entered')
                    boundaries.put('collector_waited_for_publication')
                value = real_wait(subject, *args, **kwargs)
                if subject is condition and threading.current_thread() is cap._collector:
                    record('actual_collector_condition_wait_returned')
                return value

            def read(fd, count):
                payload = real_read(fd, count)
                if (threading.current_thread() is cap._collector
                        and b'publication-after-interrupt-' in payload):
                    record('actual_after_interrupt_pipe_read', bytes=len(payload))
                    progress.set()
                return payload

            def control():
                try:
                    cap.terminate('target_stop')
                    result['returned'] = True
                except BaseException as error:
                    result['error'] = type(error).__name__
                    record('foreground_exception_propagated', exception=type(error).__name__)
                finally:
                    foreground_returned.set()

            cap.selector.select = select
            cap.start_background()
            self.check(first_select.wait(5), 'one real collector pump must be admitted')
            foreground = threading.Thread(target=control, name='publication-interrupted-foreground')
            with patch.object(threading.Condition, '__exit__', condition_exit), \
                 patch.object(threading.Condition, 'wait', condition_wait), \
                 patch.object(actual.os, 'read', read):
                foreground.start()
                self.check(foreground_returned.wait(4), 'publication interruption must return to its caller')
                foreground.join(1)
                self.check(injected.is_set(), 'single interrupt must occur after actual publication Condition release')
                self.check(result.get('error') == 'KeyboardInterrupt', 'actual KeyboardInterrupt must propagate')
                self.check(not cap.signals and cap.process.poll() is None,
                           'publication exception must occur before actual TERM control transition')
                record('foreground_finished_before_first_pump_release')
                release_select.set()
                boundary = boundaries.get(timeout=4)
                record('observed_actual_collector_boundary', boundary=boundary)
                (directory / 'write-now').touch()
                until(lambda: (directory / 'child-wrote').exists(), 'actual small stdout/stderr writes complete')
                record('actual_child_completed_both_pipe_writes')
                recovered = progress.wait(2)
                record('post_interrupt_drain_verdict', recovered=recovered,
                       stdout_bytes=cap.counts['stdout'], stderr_bytes=cap.counts['stderr'],
                       child_alive=cap.process.poll() is None, collector_alive=cap._collector.is_alive())
                self.check(recovered,
                           'collector must resume actual pipe drain after KeyboardInterrupt at publication release')
                until(lambda: cap.counts['stderr'] >= len(b'publication-after-interrupt-stderr\n'),
                      'both actual streams drain after interruption')
            # This is actual production control/cleanup; no success/outcome stub.
            cap.terminate('target_stop')
            outcome = cap.finish()
            self.check(outcome.returncode == 0, 'later real TERM must permit actual child exit0')
            self.check(outcome.cleanup_complete, 'later production finish must report cleanup complete')
            self.check(cap.closed and not cap._collector.is_alive(), 'actual collector must stop and descriptors close')
            self.check(all(stream.closed for stream in cap.files.values()), 'actual raw streams must close')
            self.check(cap.process.stdout.closed and cap.process.stderr.closed, 'actual pipe streams must close')
            self.check((directory / 'stdout.raw').read_bytes() ==
                       b'publication-ready\npublication-after-interrupt-stdout\npublication-TERM-stdout\n',
                       'stdout must contain exact real post-interruption bytes and TERM tail')
            self.check((directory / 'stderr.raw').read_bytes() ==
                       b'publication-after-interrupt-stderr\npublication-TERM-stderr\n',
                       'stderr must contain exact real post-interruption bytes and TERM tail')
        except BaseException as error:
            failure = dict(type=type(error).__name__, message=str(error))
            record('TEST_FAILURE_CAPTURED_BEFORE_DISPOSAL', **failure)
            raise
        finally:
            release_select.set()
            if foreground is not None:
                foreground.join(1)
            if cap is not None:
                if failure is not None:
                    disposal['used'] = True
                    record('NEGATIVE_FIXTURE_DISPOSAL_START_NOT_A_PRODUCTION_RELEASE')
                    # Frozen-candidate-specific disposal, expressly authorized by
                    # root. Behavioral failure has already been captured above.
                    known_condition = getattr(cap, '_control_condition', None)
                    known_pending = getattr(cap, '_control_pending', None)
                    disposal['known_pending_before'] = known_pending
                    if known_condition is not None and type(known_pending) is int:
                        with known_condition:
                            cap._control_pending = 0
                            known_condition.notify_all()
                        disposal['numeric_pending_reset_for_disposal_only'] = True
                        record('TEST_ONLY_PENDING_RESET_AND_NOTIFY_AFTER_CAPTURED_FAILURE')
                    # The collector can now run real production termination,
                    # drain, reap and closure. It does not erase the test failure.
                    try:
                        disposed = cap.finish('target_stop')
                        disposal['actual_cleanup_outcome'] = asdict(disposed)
                    except BaseException as disposal_error:
                        disposal['cleanup_error'] = type(disposal_error).__name__ + ': ' + str(disposal_error)
                if cap.process is not None and cap.process.poll() is None:
                    try: os.killpg(cap.process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    cap.process.wait(timeout=2)
                if cap._collector is not None:
                    cap._collector.join(2)
                disposal['owned_child_reaped'] = cap.process is not None and cap.process.poll() is not None
                disposal['collector_stopped'] = cap._collector is None or not cap._collector.is_alive()
                disposal['descriptors_closed'] = cap.closed and all(stream.closed for stream in cap.files.values())
                # Hard failure remains visible if even negative-fixture disposal
                # fails; root's external 30-second watchdog owns final fallback.
                record('owned_resources_after_test', **disposal)
            raw = dict(executor=str(SOURCE), executor_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                       events=events, behavioral_failure=failure,
                       outcome=asdict(outcome) if outcome is not None else None,
                       disposal=disposal, executed_assertions=type(self).checks)
            (ARTIFACTS / 'publication-interrupt-observation.json').write_text(json.dumps(raw, indent=2) + '\n')
            temporary.cleanup()


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PublicationInterruption)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                         assertions=PublicationInterruption.checks, executor=str(SOURCE))))
    raise SystemExit(0 if result.wasSuccessful() else 1)
