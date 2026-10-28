# SPDX-License-Identifier: GPL-2.0
"""Execute fixed upstream methods with mocked stream/ProcessGroup boundaries."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT/'src/compute/torch'), str(ROOT/'src/compute/vllm')]


class UpstreamLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        calls = self.calls
        class Stream:
            def __init__(self, handle): self.cuda_stream = handle
            def wait_stream(self, other): calls.append(('wait', self.cuda_stream, other.cuda_stream))
        self.original_stream = Stream(33)
        self.communication_stream = Stream(44)
        current = [self.original_stream]
        self.current = current
        class StreamContext:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): self.old = current[0]; current[0] = self.stream
            def __exit__(self, *args): current[0] = self.old
        fake_torch = types.SimpleNamespace(cuda=types.SimpleNamespace(
            Stream=lambda *args, **kwargs: Stream(55), stream=lambda s: StreamContext(s),
            current_stream=lambda: current[0], is_current_stream_capturing=lambda: False),
            distributed=types.SimpleNamespace(destroy_process_group=lambda g: calls.append(('destroy_group', g))))
        class Cuda:
            ca_comm = None
            def destroy(self): calls.append(('cuda_destroy',))
        self.comm = Cuda()
        self.comm.unique_name = 'tp:0'
        self.comm.rank_in_group = 0
        self.backend = types.SimpleNamespace(backend='xdev_tp', rank=0, world_size=2,
            execution_stream=self.communication_stream,
            synchronize=lambda: calls.append(('native_wait',)),
            close=lambda: calls.append(('native_close',)),
            stats=lambda: dict(backend='xdev_tp', rank=0, world_size=2,
                native=dict(submitted=2, completed=2, failed=0, error=0, retained=0,
                    fallback_calls=0, logical_inflight=0, tx_done=2,
                    rx_delivered=2, last_use_released=2)))
        self.comm._xdev_tp_backend = self.backend
        self.comm._xdev_tp_selection = dict(backend='xdev_tp', group='tp:0', rank=0, world_size=2)
        modules = {'torch': fake_torch,
            'vllm.distributed.device_communicators.cuda_communicator': types.SimpleNamespace(CudaCommunicator=Cuda)}
        self.patch = patch.dict(sys.modules, modules); self.patch.start()
        filename = Path(__file__).parent/'fixtures/vllm_group.py'
        spec = importlib.util.spec_from_file_location('fixed_vllm_group', filename)
        module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.module = module
        self.group = module.GroupCoordinator()
        self.group.device_communicator = self.comm
        self.group.device_group, self.group.cpu_group = 'device', 'cpu'
        self.group.mq_broadcaster = None

    def tearDown(self): self.patch.stop()

    def install(self):
        import xdev_tp_vllm
        install = getattr(xdev_tp_vllm, '_install_coordinator', None)
        self.assertTrue(callable(install), 'fixed upstream lifecycle hook missing')
        install(self.module.GroupCoordinator, self.module.GraphCaptureContext)

    def test_actual_upstream_none_context_uses_same_communication_stream(self):
        self.install()
        with self.group.graph_capture() as context:
            self.assertIs(context.stream, self.communication_stream)
            self.assertIs(self.current[0], self.communication_stream)
        self.assertIs(self.current[0], self.original_stream)

    def test_shared_context_is_updated_for_following_pipeline_group(self):
        self.install()
        context = self.module.GraphCaptureContext(self.original_stream)
        with self.group.graph_capture(context) as actual:
            self.assertIs(actual, context)
            self.assertIs(context.stream, self.communication_stream)
            self.assertIn(('wait', 44, 33), self.calls)
        self.assertIs(context.stream, self.communication_stream)

    def test_actual_upstream_global_capture_shares_context_with_tp_and_pp(self):
        self.install()
        pp = self.module.GroupCoordinator()
        pp.device_communicator = type(self.comm)()
        pp.device_communicator.unique_name = 'pp:0'
        self.module.get_tp_group = lambda: self.group
        self.module.get_pp_group = lambda: pp
        with self.module.graph_capture(device=1) as context:
            self.assertIs(context.stream, self.communication_stream)
            self.assertIs(self.current[0], self.communication_stream)
        self.assertIs(self.current[0], self.original_stream)

    def test_actual_upstream_destroy_waits_and_closes_before_process_groups(self):
        self.install(); self.group.destroy()
        self.assertEqual(self.calls[:2], [('native_wait',), ('native_close',)])
        self.assertEqual(self.calls[2:], [('destroy_group', 'device'), ('destroy_group', 'cpu'), ('cuda_destroy',)])

    def test_failed_native_close_preserves_actual_upstream_process_groups(self):
        def fail(): raise RuntimeError('unknown graph/native users')
        self.backend.close = fail
        self.install()
        with self.assertRaises(RuntimeError): self.group.destroy()
        self.assertEqual(self.group.device_group, 'device')
        self.assertEqual(self.group.cpu_group, 'cpu')
        self.assertFalse(any(c[0] == 'destroy_group' for c in self.calls))

    def test_non_tp_upstream_behavior_remains_original(self):
        self.comm.unique_name = 'pp:0'; del self.comm._xdev_tp_backend
        self.install()
        with self.group.graph_capture() as context:
            self.assertEqual(context.stream.cuda_stream, 55)
        self.group.destroy()
        self.assertNotIn(('native_close',), self.calls)

if __name__ == '__main__': unittest.main(verbosity=2)
