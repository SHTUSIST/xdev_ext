#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real connector/RPC lifecycle; CUDA scheduling boundary substituted on CPU.

TorchDevice.scatter_async/wait_host/drain are real methods. The CUDA boundary
holds previously submitted work pending, or raises at launch/event/synchronize.
No CUDA execution or native worker DMA is claimed.
"""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import gc
import sys
import tempfile
import threading
import time
import unittest
import weakref

import _paths  # noqa: F401
from xdev_kv_vllm import core
from xdev_kv_vllm.layout import StagingLayout
from xdev_kv_vllm.restore import RestoreConfig, RestoreService
from xdev_kv_vllm.scatter import TorchDevice

S = StagingLayout(4, 2, 2, 2, 1, 'uint8')
GROUP, POOL = 32, 512


class Tensor:
    def __getitem__(self, key):
        return self

    def view(self, dtype):
        return self


class Stage:
    def __init__(self, ready, pid):
        self.tensor, self.released = Tensor(), False

    def release(self):
        self.released = True


class Device(TorchDevice):
    def __init__(self, fail='layer'):
        # Keep the production orchestration, tensor/stream/event boundaries only.
        self.fail = fail
        self.pending = False
        self.queued = threading.Event()
        self.draining = threading.Event()
        self.complete = threading.Event()
        self.waiting = threading.Event()
        self.second = threading.Event()
        self.drained_devices = []
        self.stream = SimpleNamespace(wait_event=lambda e: None)
        self.device, self.dtype = 7, 'uint8'
        self.layers, self.targets, self.staging = [Tensor(), Tensor()], [None, None], S
        self._blocks = {}
        self.fn = self.launch
        owner = self

        class Event:
            def record(self, stream):
                if 'record' in owner.fail.split('+'):
                    raise RuntimeError('CUDA event record failed')

            def synchronize(self):
                owner.waiting.set()
                if 'wait' in owner.fail.split('+'):
                    raise RuntimeError('CUDA event synchronize failed')
                if not owner.complete.wait(5):
                    raise RuntimeError('test event deadline')
                owner.pending = False

        self.torch = SimpleNamespace(
            cuda=SimpleNamespace(set_device=lambda d: None, stream=lambda s: nullcontext(),
                                 Event=Event, current_stream=lambda d: self.stream,
                                 synchronize=self.synchronize),
            tensor=lambda *a, **k: Tensor(), int32='i32')

    def fence(self):
        return SimpleNamespace(synchronize=lambda: None)

    def launch(self, src, dst, blocks, spec, staging, target, layer):
        self.pending = True
        self.queued.set()
        if 'layer' in self.fail.split('+') and layer == 1 and spec.req_id == 'a':
            raise RuntimeError('layer1 failed after layer0 GPU work queued')
        if spec.req_id == 'b':
            self.second.set()

    def synchronize(self, device):
        self.drained_devices.append(device)
        self.draining.set()
        if 'drain' in self.fail.split('+'):
            raise RuntimeError('CUDA completion unknown')
        if not self.complete.wait(5):
            raise RuntimeError('test drain deadline')
        self.pending = False


def spec(req, slba):
    return core.LoadSpec(req, (0,), 0, 4, 0, slba, GROUP, 0)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-lifetime-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def worker(self, fail='layer', mode='async'):
        run = Path(tempfile.mkdtemp(dir=self.root))
        source, self.stage_file, self.log = (run / n for n in ('source', 'stage', 'rpc.log'))
        source.write_bytes(b'A' * GROUP + b'B' * GROUP + bytes(POOL - 2 * GROUP))
        self.stage_file.write_bytes(bytes(POOL))
        argv = [sys.executable, '-B', str(Path(__file__).with_name('fake_restore_worker.py')),
                '--mode', 'local-verify' if mode == 'async' else 'ok',
                '--source', str(source), '--stage', str(self.stage_file), '--log', str(self.log),
                '--lba-bytes', '8', '--frame-bytes', '8', '--group-bytes', str(GROUP),
                '--pool-bytes', str(POOL)]
        svc = RestoreService(RestoreConfig(argv, GROUP, POOL, ready_timeout=2, go_timeout=2,
                                          quit_timeout=2), Stage)
        svc.start()
        dev = Device(fail)
        cfg = core.ConnectorConfig('unused', 'tiny', POOL, group_bytes=GROUP, lba_bytes=8,
                                   load_mode=mode)
        worker = core.WorkerSide(cfg, svc, dev, {'l0': 0, 'l1': 1}, S)

        def cleanup():
            dev.fail = ''
            dev.complete.set()
            worker.shutdown(timeout=3)
            # Original c59 may already have closed; upgraded unknown paths are
            # permitted to retire only after the boundary now proves completion.
            if svc.worker is not None:
                svc.close()
        self.addCleanup(cleanup)
        return worker, svc, dev

    def go_count(self):
        return sum(line.startswith('GO ') for line in self.log.read_text().splitlines())

    def finish(self, worker):
        deadline = time.monotonic() + 3
        done, failed = set(), set()
        while done != {'a', 'b'} and time.monotonic() < deadline:
            a, b = worker.transfer_results(set())
            done |= a
            failed |= b
            time.sleep(.005)
        self.assertEqual(done, {'a', 'b'})
        self.assertEqual(failed, {'a'})

    def test_partial_launch_error_drains_before_next_go_or_fallback(self):
        worker, svc, dev = self.worker()
        worker.start_loads([spec('a', 0), spec('b', 4)])
        self.assertTrue(dev.queued.wait(2))
        self.assertTrue(dev.draining.wait(.5), 'partial scatter never waited for GPU completion')
        self.assertEqual(self.go_count(), 1)
        self.assertEqual(self.stage_file.read_bytes()[:GROUP], b'A' * GROUP)
        self.assertEqual(worker.transfer_results(set()), (set(), set()))
        self.assertFalse(svc.staging.released)
        dev.complete.set()
        self.finish(worker)
        self.assertEqual(self.go_count(), 2)
        self.assertEqual(dev.drained_devices, [7])

    def test_event_record_error_drains_previously_queued_work(self):
        worker, _, dev = self.worker('record')
        worker.start_loads([spec('a', 0)])
        self.assertTrue(dev.draining.wait(.5), 'event record failure skipped GPU drain')
        self.assertEqual(worker.transfer_results(set()), (set(), set()))
        dev.complete.set()

    def test_wait_host_error_drains_before_reusing_staging(self):
        worker, _, dev = self.worker('wait')
        worker.start_loads([spec('a', 0), spec('b', 4)])
        self.assertTrue(dev.draining.wait(.5), 'event synchronize error skipped GPU drain')
        self.assertEqual(self.go_count(), 1)
        self.assertEqual(worker.transfer_results(set()), (set(), set()))
        dev.fail = ''
        dev.complete.set()
        self.finish(worker)

    def test_shutdown_timeout_preserves_live_thread_service_and_staging(self):
        worker, svc, dev = self.worker('')
        stage = svc.staging
        worker.start_loads([spec('a', 0)])
        self.assertTrue(dev.waiting.wait(2))
        start = time.monotonic()
        self.assertIs(worker.shutdown(timeout=.01), False)
        self.assertLess(time.monotonic() - start, .5, 'shutdown ignored its join deadline')
        self.assertTrue(worker._thread.is_alive())
        self.assertIs(svc.staging, stage)
        self.assertIsNotNone(svc.worker)
        self.assertFalse(stage.released)
        dev.complete.set()
        self.assertIs(worker.shutdown(timeout=3), True)
        self.assertFalse(worker._thread.is_alive())
        self.assertTrue(stage.released)

    def test_failed_gpu_drain_stops_go_fallback_and_resource_release(self):
        for failure in ('layer+drain', 'wait+drain', 'record+drain'):
            with self.subTest(failure=failure):
                worker, svc, dev = self.worker(failure)
                stage = svc.staging
                worker.start_loads([spec('a', 0), spec('b', 4)])
                deadline = time.monotonic() + .7
                while not svc.disabled and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue(svc.disabled, 'unknown GPU completion still allows restores')
                self.assertEqual(self.go_count(), 1)
                with self.assertRaisesRegex(RuntimeError, 'GPU|completion'):
                    worker.transfer_results(set())
                with self.assertRaisesRegex(RuntimeError, 'GPU|completion'):
                    worker.start_loads([spec('c', 0)])
                self.assertIs(worker.shutdown(timeout=2), False)
                self.assertIs(svc.staging, stage)
                self.assertFalse(stage.released)
                # A later successful device drain is a valid retirement proof.
                dev.fail = ''
                dev.complete.set()
                self.assertIs(worker.shutdown(timeout=2), True)

    def test_sync_partial_scatter_drains_before_reporting_recompute_blocks(self):
        worker, _, dev = self.worker('layer', mode='sync')
        worker.start_loads([spec('a', 0)])
        worker.wait_layer('l0')
        error = []

        def wait_layer():
            try:
                worker.wait_layer('l1')
            except Exception as exc:
                error.append(exc)
        thread = threading.Thread(target=wait_layer)
        thread.start()
        try:
            self.assertTrue(dev.draining.wait(.5), 'sync scatter error skipped drain')
            self.assertTrue(thread.is_alive(), 'fallback published before GPU completion')
        finally:
            dev.complete.set()
            thread.join(2)
        self.assertEqual(error, [])
        self.assertEqual(worker.load_error_blocks(), {0})

    def test_failed_fence_record_preserves_resources_and_stops_go(self):
        worker, svc, dev = self.worker('record+drain')
        stage = svc.staging
        # Production fence may raise after earlier stream work was submitted.
        dev.fence = lambda: TorchDevice.fence(dev)
        with self.assertRaisesRegex(RuntimeError, 'GPU|record'):
            worker.start_loads([spec('a', 0)])
        self.assertTrue(svc.disabled)
        with self.assertRaisesRegex(RuntimeError, 'GPU|completion'):
            worker.start_loads([spec('b', 4)])
        self.assertIs(worker.shutdown(timeout=2), False)
        self.assertFalse(stage.released)
        self.assertIsNotNone(svc.worker)

    def test_sync_failed_drain_prevents_recompute_and_next_go(self):
        worker, svc, dev = self.worker('layer+drain', mode='sync')
        worker.start_loads([spec('a', 0)])
        worker.wait_layer('l0')
        with self.assertRaisesRegex(RuntimeError, 'GPU completion unknown'):
            worker.wait_layer('l1')
        with self.assertRaisesRegex(RuntimeError, 'GPU completion unknown'):
            worker.load_error_blocks()
        with self.assertRaisesRegex(RuntimeError, 'GPU completion unknown'):
            worker.start_loads([spec('b', 4)])
        self.assertEqual(self.go_count(), 1)
        self.assertFalse(svc.staging.released)

    def test_sync_fence_wait_failure_never_releases_or_restores(self):
        worker, svc, dev = self.worker('drain', mode='sync')

        class BadFence:
            def synchronize(self):
                raise RuntimeError('sync fence wait failed')
        dev.fence = BadFence
        worker.start_loads([spec('a', 0)])
        self.assertTrue(dev.draining.wait(.5))
        with self.assertRaisesRegex(RuntimeError, 'GPU completion unknown'):
            worker.wait_layer('l0')
        self.assertEqual(svc.stats['restores'], 0)
        self.assertFalse(svc.staging.released)

    def test_sync_shutdown_drains_work_that_outlives_scatter_now(self):
        worker, svc, dev = self.worker('', mode='sync')
        stage = svc.staging
        worker.start_loads([spec('a', 0)])
        worker.wait_layer('l0')
        worker.wait_layer('l1')
        self.assertTrue(dev.pending)
        retired = []
        thread = threading.Thread(target=lambda: retired.append(worker.shutdown(timeout=2)))
        thread.start()
        try:
            self.assertTrue(dev.draining.wait(.5))
            self.assertTrue(thread.is_alive())
            self.assertFalse(stage.released)
            self.assertIsNotNone(svc.worker)
        finally:
            dev.complete.set()
            thread.join(2)
        self.assertEqual(retired, [True])
        self.assertTrue(stage.released)

    def test_unknown_completion_keeps_owners_after_caller_drops_worker(self):
        worker, svc, dev = self.worker('wait+drain')
        worker.start_loads([spec('a', 0)])
        self.assertTrue(dev.draining.wait(.5))
        self.assertIs(worker.shutdown(timeout=2), False)
        self.assertFalse(worker._thread.is_alive())
        # Drop the fixture cleanup's strong reference along with the caller's.
        self._cleanups.pop()
        ref = weakref.ref(worker)
        del worker

        def cleanup():
            dev.fail = ''
            dev.complete.set()
            owner = ref()
            if owner is not None:
                owner.shutdown(timeout=2)
            if svc.worker is not None:
                svc.close()
        self.addCleanup(cleanup)
        gc.collect()
        self.assertIsNotNone(ref(), 'GPU owners were garbage-collected without a drain proof')
        self.assertFalse(svc.staging.released)


if __name__ == '__main__':
    unittest.main()
