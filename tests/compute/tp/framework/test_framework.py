# SPDX-License-Identifier: GPL-2.0
"""Framework boundary unit tests. No CUDA/vLLM runtime evidence is implied."""
import importlib
import inspect
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT / 'src/compute/torch'), str(ROOT / 'src/compute/vllm')]


class PolicyTests(unittest.TestCase):
    def policy(self, shape=(2, 3, 4), **kw):
        from xdev_tp_torch.policy import qualify
        args = dict(dtype='float32', device_type='cuda', contiguous=True,
                    world_size=2, rank=0, operation='all_reduce', dim=-1,
                    dst=0, max_payload_bytes=4096)
        args.update(kw)
        return qualify(shape, **args)

    def test_allreduce_preserves_every_dimension(self):
        p = self.policy()
        self.assertEqual(p.output_shape, (2, 3, 4))
        self.assertEqual((p.rows, p.width), (1, 24))

    def test_gather_doubles_inside_each_row(self):
        p = self.policy(operation='all_gather')
        self.assertEqual(p.output_shape, (2, 3, 8))
        self.assertEqual((p.rows, p.width), (6, 4))

    def test_non_destination_has_no_output(self):
        self.assertIsNone(self.policy(operation='gather', rank=1).output_shape)
        self.assertEqual(self.policy(operation='gather', rank=1, dst=1).output_shape,
                         (2, 3, 8))

    def test_empty_keeps_control_exchange_shape(self):
        p = self.policy(shape=(2, 0, 4), operation='all_gather')
        self.assertEqual((p.rows, p.width, p.output_shape), (0, 4, (2, 0, 8)))

    def test_rejects_before_submission(self):
        cases = [dict(dtype='int32'), dict(world_size=4), dict(contiguous=False),
                 dict(device_type='cpu'), dict(rank=2), dict(dst=2),
                 dict(operation='all_gather', dim=0), dict(operation='product'),
                 dict(shape=(-1, 2)), dict(shape=(2**62, 8)),
                 dict(max_payload_bytes=4)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises((ValueError, OverflowError)):
                self.policy(**case)

    def test_wire_payload_uint32_is_enforced_before_native(self):
        with self.assertRaises(OverflowError):
            self.policy(shape=(2**30,), max_payload_bytes=2**40)


class Tensor:
    def __init__(self, shape=(2, 2), *, dtype='float32', device='cuda', contiguous=True):
        self.shape, self.dtype = shape, dtype
        self.device = types.SimpleNamespace(type=device, index=1)
        self.is_meta = device == 'meta'
        self.contiguous = contiguous
    def is_contiguous(self):
        return self.contiguous
    def new_empty(self, shape):
        return Tensor(tuple(shape), dtype=self.dtype, device=self.device.type)


class TorchBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        calls = self.calls
        class Native:
            def __init__(self, config, owner): self.config = config
            def all_reduce(self, tensor, stream):
                calls.append(('sum', tensor, stream)); return tensor.new_empty(tensor.shape)
            def gather(self, tensor, stream, dst, all_gather):
                calls.append(('gather', tensor, stream, dst, all_gather))
                return (tensor.new_empty((*tensor.shape[:-1], tensor.shape[-1]*2))
                        if all_gather or dst == self.config['rank'] else None)
            @classmethod
            def from_options(cls, config, stream, owner):
                calls.append(("bootstrap", stream)); return cls(config, owner)
            def stats(self):
                n = sum(c[0] in ('sum', 'gather') for c in calls)
                return dict(submitted=n, completed=n, failed=0)
            def close(self): calls.append(('close',))
            def wait(self, timeout_ns): calls.append(('wait', timeout_ns))
        self.native = types.SimpleNamespace(Communicator=Native)
        class DeviceContext:
            def __enter__(self): calls.append(('device_enter',))
            def __exit__(self, *a): calls.append(('device_exit',))
        class Stream:
            def __init__(self, handle): self.cuda_stream = handle
            def wait_stream(self, other): calls.append(('wait_stream', self.cuda_stream, other.cuda_stream))
        self.caller = Stream(98765)
        self.dedicated = Stream(444)
        current = [self.caller]
        self.current_stream = current
        class StreamContext:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): self.previous = current[0]; current[0] = self.stream
            def __exit__(self, *args): current[0] = self.previous
        self.torch = types.SimpleNamespace(
            __version__='2.8.0+cu128', float16='float16', bfloat16='bfloat16', float32='float32',
            cuda=types.SimpleNamespace(device=lambda d: DeviceContext(),
                current_stream=lambda d=None: current[0],
                current_device=lambda: 1, Stream=lambda device: self.dedicated,
                stream=lambda stream: StreamContext(stream),
                is_current_stream_capturing=lambda: False))
        from xdev_tp_torch import TorchCommunicator
        self.patches = [patch.dict(sys.modules, {'torch': self.torch,
                        'xdev_tp_torch._native': self.native})]
        self.patches[0].start()
        self.comm = TorchCommunicator(dict(rank=1, world_size=2, mode=1,
                                          device_index=1, max_payload_bytes=4096), object())
        self.setup_calls = list(self.calls)
        self.calls.clear()
    def tearDown(self): self.patches[0].stop()

    def test_real_current_stream_is_explicit_boundary_argument(self):
        x = Tensor()
        y = self.comm.all_reduce(x)
        self.assertIsNot(x, y)
        self.assertEqual(y.shape, x.shape)
        self.assertIn(('sum', x, 98765), self.calls)

    def test_gather_calls_native_on_non_destination(self):
        x = Tensor()
        self.assertIsNone(self.comm.gather(x, dst=0))
        self.assertIn(('gather', x, 98765, 0, False), self.calls)

    def test_fake_and_meta_shape_only(self):
        y = self.comm.all_gather(Tensor((3, 4), device='meta'))
        self.assertEqual(y.shape, (3, 8))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.comm.stats()['native']['submitted'], 0)
        self.assertIn('framework', self.comm.stats(), 'framework preflight accounting absent')
        self.assertEqual(self.comm.stats()['framework']['api_attempts'], 0)

    def test_rejection_does_not_call_native(self):
        for x in [Tensor(dtype='int32'), Tensor(contiguous=False), Tensor(device='cpu')]:
            with self.assertRaises(ValueError): self.comm.all_reduce(x)
        self.assertEqual(self.calls, [])
        self.assertIn('framework', self.comm.stats(), 'framework preflight accounting absent')
        self.assertEqual(self.comm.stats()['framework']['api_attempts'], 3)
        self.assertEqual(self.comm.stats()['framework']['preflight_rejected'], 3)

    def test_d1_capture_is_rejected_without_submit(self):
        self.torch.cuda.is_current_stream_capturing = lambda: True
        with self.assertRaises(RuntimeError): self.comm.all_reduce(Tensor())
        self.assertFalse(any(c[0] == 'sum' for c in self.calls))

    def test_wrong_device_rejected_before_native(self):
        x = Tensor(); x.device.index = 0
        with self.assertRaises(ValueError): self.comm.all_reduce(x)
        self.assertEqual(self.calls, [])

    def test_explicit_wait_exposes_native_completion_without_resubmit(self):
        self.assertTrue(callable(getattr(self.comm, "synchronize", None)), "native completion wait missing")
        self.comm.synchronize(timeout_ns=1000)
        self.assertIn(('wait', 1000), self.calls)
        self.assertFalse(any(c[0] in ('sum', 'gather') for c in self.calls))

    def test_construct_stats_and_close_scope_actual_device(self):
        self.assertIn(('device_enter',), self.setup_calls)
        self.comm.stats()
        self.comm.close()
        self.assertEqual(self.calls[-3:], [('device_enter',), ('close',), ('device_exit',)])

    def test_owned_stream_scopes_dependencies_without_global_stream_change(self):
        self.comm._comm_stream = self.dedicated
        x = Tensor(); self.comm.all_reduce(x)
        self.assertIn(('sum', x, 444), self.calls)
        self.assertIn(('wait_stream', 444, 98765), self.calls)
        self.assertIn(('wait_stream', 98765, 444), self.calls)
        self.assertIs(self.current_stream[0], self.caller)

    def test_capturing_on_unknown_stream_is_rejected_before_native(self):
        self.comm.mode = 2
        self.comm._comm_stream = self.dedicated
        self.torch.cuda.is_current_stream_capturing = lambda: True
        with self.assertRaises(RuntimeError): self.comm.all_reduce(Tensor())
        self.assertFalse(any(c[0] == 'sum' for c in self.calls))

    def test_shipped_bootstrap_passes_actual_owned_stream_not_pointer_config(self):
        from xdev_tp_torch import TorchCommunicator
        self.assertTrue(callable(getattr(TorchCommunicator, 'from_options', None)),
                        'shipped real endpoint bootstrap missing')
        options = dict(version=1, rank=1, world_size=2, device_index=1, mode=1,
            nvidia_node='/dev/nvidia0', bpf_object=__file__, user_bpf_object=__file__, ptx_path=__file__,
            link_token=7, allocation_bytes=65536, group_bytes=4096, depth=1,
            nr_batches=10, first_sequence=1, timeout_ns=10**9,
            communicator_id=11, epoch=2, max_payload_bytes=4000)
        comm = TorchCommunicator.from_options(options)
        self.assertIs(comm.execution_stream, self.dedicated)
        self.assertIn(('bootstrap', 444), self.calls)
        self.assertIs(self.current_stream[0], self.caller)


class PluginTests(unittest.TestCase):
    def setUp(self):
        import xdev_tp_vllm as plugin
        self.plugin = plugin
        self.original_calls = []
        calls = self.original_calls
        class Base:
            def all_gather(self, input_, dim=-1): calls.append('original_all_gather'); return input_
            def gather(self, input_, dst=0, dim=-1): calls.append('original_gather'); return input_
        class Cuda(Base):
            def __init__(self, cpu_group, device=None, device_group=None, unique_name=''):
                self.unique_name, self.world_size, self.rank_in_group = unique_name, cpu_group[0], cpu_group[1]
                self.ca_comm = object(); calls.append('original_init')
            def all_reduce(self, input_): calls.append('original_sum'); return input_
            def destroy(self): calls.append('original_destroy')
        self.cls = Cuda
        self.backend = types.SimpleNamespace(
            backend='xdev_tp', rank=0, world_size=2,
            all_reduce=lambda x: ('native_sum', x),
            all_gather=lambda x, dim=-1: ('native_all_gather', x, dim),
            gather=lambda x, dst=0, dim=-1: ('native_gather', x, dst, dim),
            close=lambda: calls.append('native_close'),
            stats=lambda: dict(backend='xdev_tp', rank=0, world_size=2,
                               native=dict(submitted=2, completed=2, failed=0,
                                           fallback_calls=0, error=0, retained=0, logical_inflight=0,
                                           tx_done=2, rx_delivered=2, last_use_released=2)))

    def install(self, **kwargs):
        return self.plugin._install_on_class(self.cls, version='0.10.2',
                    factory=lambda c: self.backend, **kwargs)

    def test_original_instance_resources_and_inherited_gather_preserved(self):
        self.install(); c = self.cls((2, 0), unique_name='tp:0')
        self.assertIsInstance(c, self.cls); self.assertIsNotNone(c.ca_comm)
        self.assertEqual(c.all_reduce('x'), ('native_sum', 'x'))
        self.assertEqual(c.all_gather('x'), ('native_all_gather', 'x', -1))
        self.assertEqual(c.gather('x', dst=1), ('native_gather', 'x', 1, -1))
        c.destroy()
        self.assertEqual(self.original_calls, ['original_init', 'native_close', 'original_destroy'])

    def test_only_actual_two_rank_tp_names_select_backend(self):
        self.install()
        for name in ['pp:0', 'dp:0', 'ep:0', 'dcp:0', 'not_tp:0', 'tp:0:ep', 'tp']:
            c = self.cls((2, 0), unique_name=name); c.all_reduce('x')
            self.assertFalse(hasattr(c, '_xdev_tp_backend'))
        c = self.cls((4, 0), unique_name='tp:0')
        with self.assertRaises(RuntimeError): c.all_reduce('x')

    def test_idempotence_and_exact_version_signature_gate(self):
        self.install(); first = self.cls.all_reduce; self.install()
        self.assertIs(first, self.cls.all_reduce)
        with self.assertRaises(RuntimeError):
            self.plugin._install_on_class(type('Bad', (), {}), version='0.10.3', factory=lambda c: None)
        class Wrong(self.cls):
            def all_reduce(self, input_, unexpected=None): pass
        with self.assertRaises(RuntimeError):
            self.plugin._install_on_class(Wrong, version='0.10.2', factory=lambda c: None)

    def test_failure_after_native_dispatch_never_falls_back(self):
        def fail(x): raise RuntimeError('accepted native failure')
        self.backend.all_reduce = fail
        self.install(); c = self.cls((2, 0), unique_name='tp:0')
        with self.assertRaisesRegex(RuntimeError, 'accepted native failure'): c.all_reduce('x')
        self.assertNotIn('original_sum', self.original_calls)

    def test_destroy_failure_preserves_original_resources(self):
        def fail(): raise RuntimeError('retained work')
        self.backend.close = fail
        self.install(); c = self.cls((2, 0), unique_name='tp:0')
        with self.assertRaises(RuntimeError): c.destroy()
        self.assertNotIn('original_destroy', self.original_calls)
        self.assertIsNotNone(c.ca_comm)

    def test_selection_and_final_stats_require_native_activity(self):
        self.install(); c = self.cls((2, 0), unique_name='tp:0')
        self.plugin.assert_backend_selected(c)
        evidence = self.plugin.collect_backend_evidence([c], expected_ranks={0}, require_completed=True)
        self.assertEqual(evidence[0]['native']['completed'], 2)
        with self.assertRaises(RuntimeError):
            self.plugin.collect_backend_evidence([c], expected_ranks={0, 1}, require_completed=True)
        self.backend.stats = lambda: dict(backend='xdev_tp', rank=0, world_size=2,
            native=dict(submitted=0, completed=0, failed=0, fallback_calls=0, error=0, retained=0, logical_inflight=0,
                                           tx_done=0, rx_delivered=0, last_use_released=0))
        with self.assertRaises(RuntimeError):
            self.plugin.collect_backend_evidence([c], expected_ranks={0}, require_completed=True)

    def test_evidence_requires_coverage_within_each_group(self):
        self.install(); first = self.cls((2, 0), unique_name='tp:0')
        first_backend = self.backend
        second_backend = types.SimpleNamespace(**vars(first_backend))
        second_backend.rank = 1
        second_backend.stats = lambda: dict(backend='xdev_tp', rank=1, world_size=2,
             native=dict(submitted=2, completed=2, failed=0, fallback_calls=0, error=0, retained=0, logical_inflight=0,
                                           tx_done=2, rx_delivered=2, last_use_released=2))
        self.backend = second_backend
        second = self.cls((2, 1), unique_name='tp:1')
        with self.assertRaises(RuntimeError):
            self.plugin.collect_backend_evidence([first, second], expected_ranks={0, 1})

    def test_incomplete_native_statistics_cannot_certify_strict_run(self):
        self.install(); comm = self.cls((2, 0), unique_name='tp:0')
        self.backend.stats = lambda: dict(backend='xdev_tp', rank=0, world_size=2,
                                         native=dict(submitted=1, completed=1))
        with self.assertRaises(RuntimeError):
            self.plugin.collect_backend_evidence([comm], expected_ranks={0})


if __name__ == '__main__': unittest.main(verbosity=2)
