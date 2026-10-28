# SPDX-License-Identifier: GPL-2.0
"""Fixed vLLM shutdown/reference ownership tests; CUDA boundaries are mocked."""
from contextlib import nullcontext
import importlib.util
from pathlib import Path
import sys
import types
import unittest
import weakref
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT/'src/compute/torch'), str(ROOT/'src/compute/vllm')]


class WorkerShutdownTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        events = self.events
        self.torch = types.SimpleNamespace(
            inference_mode=lambda: (lambda f: f),
            cuda=types.SimpleNamespace(device=lambda d: nullcontext(),
                synchronize=lambda device: events.append('cuda_sync')),
            distributed=types.SimpleNamespace(destroy_process_group=lambda group: events.append('pg_'+group)))
        self.patch = patch.dict(sys.modules, {'torch': self.torch}); self.patch.start()
        self.module = self.load('vllm_worker')
        group_module = self.load('vllm_group')
        import xdev_tp_vllm
        xdev_tp_vllm._install_coordinator(group_module.GroupCoordinator, group_module.GraphCaptureContext)
        self.native_refs = []
        def close():
            events.append('native_close')
            if any(ref() is not None for ref in self.native_refs):
                raise RuntimeError('future graph use retained')
        self.backend = types.SimpleNamespace(backend='xdev_tp', mode=2, config={'device_index': 0},
            synchronize=lambda: events.append('native_wait'), close=close,
            stats=lambda: dict(backend='xdev_tp', rank=0, world_size=2,
                native=dict(submitted=1, completed=1, failed=0, error=0, retained=0,
                    fallback_calls=0, logical_inflight=0, tx_done=1, rx_delivered=1, last_use_released=1)))
        comm = types.SimpleNamespace(rank_in_group=0, _xdev_tp_backend=self.backend,
            _xdev_tp_selection=dict(backend='xdev_tp', group='tp:0', rank=0, world_size=2),
            destroy=lambda: events.append('comm_destroy'))
        self.group = group_module.GroupCoordinator()
        self.group.device_communicator = comm
        self.group.device_group, self.group.cpu_group = 'device', 'cpu'
        self.group.mq_broadcaster = None
        self.module.destroy_model_parallel = self.group.destroy
        self.module.destroy_distributed_environment = lambda: events.append('distributed_destroy')
        self.module.CUDAGraphMode = types.SimpleNamespace(NONE=object())
        self.mode = object()
        self.module.get_forward_context = lambda: types.SimpleNamespace(
            batch_descriptor='batch', cudagraph_runtime_mode=self.mode)
        class Output: pass
        self.module.ModelRunnerOutput = Output
        self.module.AsyncModelRunnerOutput = type('AsyncOutput', (), {})
        self.output = Output()
        self.wrapper = self.make_wrapper()
        self.worker = self.module.Worker()
        self.worker.model_runner = types.SimpleNamespace(model=self.wrapper,
            ensure_kv_transfer_shutdown=lambda: events.append('kv_shutdown'),
            execute_model=lambda scheduler, intermediate: self.wrapper())
        base = self.module.WorkerWrapperBase(); base.worker = self.worker
        self.proc = self.module.WorkerProc(); self.proc.worker = base
        self.proc.rpc_broadcast_mq, self.proc.worker_response_mq = object(), object()
        self.scheduler = types.SimpleNamespace(total_num_scheduled_tokens=0)

    def load(self, name):
        filename = Path(__file__).parent/'fixtures'/f'{name}.py'
        spec = importlib.util.spec_from_file_location('shutdown_fixture_'+name, filename)
        module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def make_wrapper(self):
        events = self.events
        class Graph:
            def replay(self): events.append('replay')
            def __del__(self): events.append('graph_ref_released')
        graph = Graph(); self.native_refs.append(weakref.ref(graph))
        wrapper = self.module.CUDAGraphWrapper()
        wrapper.runtime_mode = self.mode
        wrapper.is_debugging_mode = False
        wrapper.concrete_cudagraph_entries = {'batch': types.SimpleNamespace(cudagraph=graph, output=self.output)}
        return wrapper

    def install(self):
        spec = importlib.util.find_spec('xdev_tp_vllm.shutdown')
        self.assertIsNotNone(spec, 'fixed V1 worker-owned graph cleanup missing')
        from xdev_tp_vllm.shutdown import install_worker_shutdown
        install_worker_shutdown(self.module.Worker, self.module.CUDAGraphWrapper, lambda: self.group)

    def tearDown(self): self.patch.stop()

    def test_actual_workerproc_chain_releases_owned_graph_before_process_groups(self):
        self.install(); self.worker.execute_model(self.scheduler)
        self.proc.shutdown()
        self.assertIsNone(self.native_refs[0]())
        self.assertLess(self.events.index('kv_shutdown'), self.events.index('cuda_sync'))
        self.assertLess(self.events.index('cuda_sync'), self.events.index('graph_ref_released'))
        self.assertLess(self.events.index('graph_ref_released'), self.events.index('native_wait'))
        self.assertLess(self.events.index('graph_ref_released'), self.events.index('native_close'))
        self.assertLess(self.events.index('native_close'), self.events.index('pg_device'))
        self.assertLess(self.events.index('native_close'), self.events.index('pg_cpu'))
        self.assertEqual(self.worker.model_runner.model.concrete_cudagraph_entries, {})

    def test_external_graph_reference_keeps_native_guard_and_process_groups(self):
        self.install(); self.worker.execute_model(self.scheduler)
        external = self.native_refs[0]()
        with self.assertRaisesRegex(RuntimeError, 'future graph use retained'): self.proc.shutdown()
        self.assertIs(external, self.native_refs[0]())
        self.assertEqual(self.group.device_group, 'device')
        self.assertNotIn('pg_device', self.events)
        self.assertEqual(self.wrapper.concrete_cudagraph_entries, {})

    def test_cuda_synchronization_failure_preserves_graph_cache(self):
        self.install(); self.worker.execute_model(self.scheduler)
        def fail(device): raise RuntimeError('CUDA completion unknown')
        self.torch.cuda.synchronize = fail
        with self.assertRaises(RuntimeError): self.proc.shutdown()
        self.assertIn('batch', self.wrapper.concrete_cudagraph_entries)
        self.assertNotIn('native_close', self.events)
        self.assertNotIn('pg_device', self.events)

    def test_dispatch_and_direct_wrapper_replay_reject_after_shutdown(self):
        self.install(); self.worker.execute_model(self.scheduler); self.proc.shutdown()
        before = self.events.count('replay')
        with self.assertRaises(RuntimeError): self.worker.execute_model(self.scheduler)
        with self.assertRaises(RuntimeError): self.wrapper()
        self.assertEqual(self.events.count('replay'), before)

    def test_every_executed_same_class_wrapper_releases_own_cache(self):
        self.install(); extra = self.make_wrapper()
        self.worker.execute_model(self.scheduler); extra()
        self.proc.shutdown()
        self.assertTrue(all(ref() is None for ref in self.native_refs))
        self.assertEqual(extra.concrete_cudagraph_entries, {})

    def test_actual_capture_without_replay_releases_own_cache_at_shutdown(self):
        self.install()
        self.wrapper.concrete_cudagraph_entries.clear()
        events, refs = self.events, self.native_refs
        class Graph:
            def __init__(self): refs.append(weakref.ref(self))
            def replay(self): events.append('replay')
            def __del__(self): events.append('graph_ref_released')
        self.torch.cuda.CUDAGraph = Graph
        self.torch.cuda.graph = lambda graph, pool: nullcontext()
        self.module.ExitStack = __import__('contextlib').ExitStack
        self.module.validate_cudagraph_capturing_enabled = lambda: events.append('capture')
        self.module.weak_ref_tensors = lambda x: x
        self.module.compilation_counter = types.SimpleNamespace(num_cudagraph_captured=0)
        self.wrapper.graph_pool = None
        self.wrapper.cudagraph_options = types.SimpleNamespace(debug_log_enable=False,
            gc_disable=False, weak_ref_output=False)
        self.wrapper.runnable = lambda: self.output
        self.worker.execute_model(self.scheduler)
        self.assertIn('capture', self.events)
        self.assertNotIn('replay', self.events)
        def zero_stats():
            return dict(backend='xdev_tp', rank=0, world_size=2,
                native=dict(submitted=0, completed=0, failed=0, error=0, retained=0,
                    fallback_calls=0, logical_inflight=0, tx_done=0, rx_delivered=0, last_use_released=0))
        self.backend.stats = zero_stats
        self.proc.shutdown()
        self.assertTrue(all(ref() is None for ref in self.native_refs))
        self.assertIn('pg_device', self.events)
        self.assertEqual(self.module.compilation_counter.num_cudagraph_captured, 1)

    def test_shutdown_waits_for_inflight_cpu_dispatch_before_closing_gate(self):
        import threading
        self.install()
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        errors = []
        graph = self.native_refs[0]()
        def replay():
            started.set()
            if not release.wait(5): raise RuntimeError('test release timeout')
            self.events.append('dispatch_finished')
        graph.replay = replay
        del graph
        def dispatch():
            try: self.worker.execute_model(self.scheduler)
            except Exception as error: errors.append(error)
        def stop():
            try: self.proc.shutdown()
            except Exception as error: errors.append(error)
            finally: finished.set()
        first = threading.Thread(target=dispatch, daemon=True)
        second = threading.Thread(target=stop, daemon=True)
        first.start()
        try:
            self.assertTrue(started.wait(5))
            second.start()
            self.assertFalse(finished.wait(0.02))
            self.assertNotIn('kv_shutdown', self.events)
        finally:
            release.set(); first.join(5)
            if second.ident is not None: second.join(5)
        self.assertEqual(errors, [])
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertLess(self.events.index('dispatch_finished'), self.events.index('kv_shutdown'))

    def test_shutdown_hook_rejects_changed_upstream_signature(self):
        from xdev_tp_vllm.shutdown import install_worker_shutdown
        class Changed:
            def execute_model(self, scheduler_output=None): pass
            def shutdown(self): pass
        with self.assertRaises(RuntimeError):
            install_worker_shutdown(Changed, self.module.CUDAGraphWrapper, lambda: self.group)

if __name__ == '__main__': unittest.main(verbosity=2)
