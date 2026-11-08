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
                 # Gather/all-gather remain one native message (no splitting).
                 dict(operation='all_gather', max_payload_bytes=4),
                 dict(operation='gather', max_payload_bytes=4),
                 # A segment smaller than one element is truly illegal.
                 dict(max_payload_bytes=2), dict(max_payload_bytes=0)]
        for case in cases:
            with self.subTest(case=case), self.assertRaises((ValueError, OverflowError)):
                self.policy(**case)

    def test_wire_payload_uint32_is_enforced_before_native(self):
        # One wire message never carries more than UINT32_MAX payload bytes.
        with self.assertRaises(OverflowError):
            self.policy(shape=(2**30,), operation='all_gather', max_payload_bytes=2**40)
        q = self.policy(shape=(2**30,), max_payload_bytes=2**40)
        self.assertLessEqual(q.segment_elements * 4, (1 << 32) - 1)
        self.assertEqual(q.segments, 2)

    def test_single_message_allreduce_keeps_one_segment(self):
        q = self.policy(shape=(2, 3, 4), max_payload_bytes=96)
        self.assertEqual((q.segments, q.segment_elements), (1, 24))
        empty = self.policy(shape=(0, 4), max_payload_bytes=96)
        self.assertEqual((empty.segments, empty.output_shape), (1, (0, 4)))

    def test_large_allreduce_splits_into_legal_segments(self):
        # 10000 F32 elements = 40000 bytes with a 4096-byte admitted payload.
        q = self.policy(shape=(100, 100), max_payload_bytes=4096)
        self.assertEqual(q.output_shape, (100, 100))
        self.assertEqual((q.segment_elements, q.segments), (1024, 10))
        q16 = self.policy(shape=(5000,), dtype='bfloat16', max_payload_bytes=4095)
        self.assertEqual((q16.segment_elements, q16.segments), (2047, 3))

    def test_llama_prefill_allreduce_geometry_is_legal(self):
        # 2048-token prefill x 8192 hidden x BF16 = 32 MiB, largest legal group.
        q = self.policy(shape=(2048, 8192), dtype='bfloat16',
                        max_payload_bytes=32 * 4096 - 64)
        self.assertEqual(q.segment_elements, (32 * 4096 - 64) // 2)
        self.assertEqual(q.segments, 257)
        self.assertLessEqual(q.segment_elements * 2, 32 * 4096 - 64)


class CaptureTemplateBudgetTests(unittest.TestCase):
    """TODO.54 G0-f: templates a vLLM capture keeps alive at once.

    vLLM 0.10.2 (commit 01efc7ef) defaults, read from its source: on a GPU
    below 70 GiB max_num_seqs=256 (engine/arg_utils.py), cuda_graph_sizes=
    [min(2*256, 512)] (config/scheduler.py), capture list [1, 2, 4] + 8..512
    step 8 = 67 sizes (config/__init__.py), PIECEWISE graphs kept for every
    size (config/__init__.py, v1/worker/gpu_model_runner.py capture_model).
    Per forward: one all-reduce after VocabParallelEmbedding, one after each
    o_proj RowParallelLinear, one after each MLP down_proj (dense) or FusedMoE
    reduce_results (MoE); logits gather runs outside the graph.
    Qwen3-32B: 64 layers, hidden 5120; Qwen3-30B-A3B: 48 layers, hidden 2048,
    every layer sparse (Hugging Face config.json).
    """
    SIZES = [1, 2, 4] + list(range(8, 513, 8))

    def budget(self, **kw):
        from xdev_tp_torch.policy import capture_template_budget
        return capture_template_budget(**kw)

    def test_single_message_steps_hold_one_template_per_all_reduce(self):
        self.assertEqual(self.budget(capture_sizes=[1], hidden_size=5120, all_reduces_per_step=129,
                                     dtype='bfloat16', max_payload_bytes=131008), 129)
        self.assertEqual(self.budget(capture_sizes=[1], hidden_size=2048, all_reduces_per_step=97,
                                     dtype='bfloat16', max_payload_bytes=131008), 97)

    def test_batch_16_dense_step_already_exceeds_the_old_256(self):
        # 16 x 5120 x 2 B = 163,840 B > 131,008 B: two legal segments each.
        self.assertEqual(self.budget(capture_sizes=[16], hidden_size=5120, all_reduces_per_step=129,
                                     dtype='bfloat16', max_payload_bytes=131008), 258)

    def test_default_vllm_capture_of_planned_models(self):
        self.assertEqual(len(self.SIZES), 67)
        self.assertEqual(self.budget(capture_sizes=self.SIZES, hidden_size=5120, all_reduces_per_step=129,
                                     dtype='bfloat16', max_payload_bytes=131008), 172731)
        self.assertEqual(self.budget(capture_sizes=self.SIZES, hidden_size=2048, all_reduces_per_step=97,
                                     dtype='bfloat16', max_payload_bytes=131008), 54611)

    def test_segments_follow_the_runtime_split_policy(self):
        from xdev_tp_torch.policy import qualify
        for size in self.SIZES:
            q = qualify((size, 5120), dtype='bfloat16', device_type='meta', contiguous=True,
                        world_size=2, rank=0, operation='all_reduce', max_payload_bytes=131008)
            self.assertEqual(self.budget(capture_sizes=[size], hidden_size=5120, all_reduces_per_step=1,
                                         dtype='bfloat16', max_payload_bytes=131008), q.segments)

    def test_rejects_invalid_geometry(self):
        for kw in (dict(capture_sizes=[0]), dict(capture_sizes=[]), dict(hidden_size=0),
                   dict(all_reduces_per_step=-1), dict(dtype='int8'), dict(max_payload_bytes=1)):
            args = dict(capture_sizes=[1], hidden_size=5120, all_reduces_per_step=1,
                        dtype='bfloat16', max_payload_bytes=131008)
            args.update(kw)
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.budget(**args)


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

    def test_bootstrap_forwards_early_cts_request_to_native_owner(self):
        from xdev_tp_torch import TorchCommunicator
        options = dict(version=1, rank=1, world_size=2, device_index=1, mode=1,
            nvidia_node='/dev/nvidia0', bpf_object=__file__, user_bpf_object=__file__, ptx_path=__file__,
            link_token=7, allocation_bytes=65536, group_bytes=4096, depth=1,
            nr_batches=10, first_sequence=1, timeout_ns=10**9,
            communicator_id=11, epoch=2, max_payload_bytes=4000)
        self.assertEqual(TorchCommunicator.from_options(options)._native.config.get('early_cts', 0), 0)
        options['early_cts'] = 1
        self.assertEqual(TorchCommunicator.from_options(options)._native.config['early_cts'], 1)


class FlatTensor:
    """Contiguous fake CUDA tensor whose flat views remember their offset."""
    def __init__(self, shape, *, dtype='float32', device='cuda', base=None, start=0):
        self.shape, self.dtype = tuple(shape), dtype
        self.device = types.SimpleNamespace(type=device, index=1)
        self.is_meta = device == 'meta'
        self.base = self if base is None else base
        self.start = start
        count = 1
        for size in self.shape: count *= size
        self.count = count
    def is_contiguous(self): return True
    def numel(self): return self.count
    def new_empty(self, shape): return FlatTensor(shape, dtype=self.dtype, device=self.device.type)
    def view(self, *shape):
        assert shape == (-1,), shape
        return FlatTensor((self.count,), dtype=self.dtype, base=self.base, start=self.start)
    def __getitem__(self, item):
        assert isinstance(item, slice) and item.step is None and len(self.shape) == 1
        assert 0 <= item.start < item.stop <= self.count
        return FlatTensor((item.stop - item.start,), dtype=self.dtype, base=self.base,
                          start=self.start + item.start)


class SegmentedAllReduceTests(unittest.TestCase):
    """T6b: one all-reduce larger than max_payload_bytes becomes legal messages."""
    def setUp(self):
        self.calls = []
        calls = self.calls
        state = self.state = dict(capacity=256, held=0)
        class Native:
            def __init__(self, config, owner): self.config = config
            def all_reduce(self, tensor, stream):
                calls.append(('sum', tensor, stream)); return tensor.new_empty(tensor.shape)
            def all_reduce_into(self, inputs, outputs, stream):
                calls.append(('into', [(t.base, t.start, t.count) for t in inputs],
                              [(t.base, t.start, t.count) for t in outputs], stream))
                state['held'] += len(inputs)
            def template_available(self):
                calls.append(('available',)); return state['capacity'] - state['held']
            def reserve_templates(self, count, timeout_ns):
                calls.append(('reserve', count, timeout_ns)); state['held'] = 0
            def stats(self): return dict(submitted=0, completed=0, failed=0)
            def close(self): calls.append(('close',))
        class Null:
            def __enter__(self): return self
            def __exit__(self, *a): return False
        class Stream:
            def __init__(self, handle): self.cuda_stream = handle
            def wait_stream(self, other): pass
        self.caller = Stream(98765)
        self.torch = types.SimpleNamespace(
            __version__='2.8.0', float16='float16', bfloat16='bfloat16', float32='float32',
            empty_like=lambda t: FlatTensor(t.shape, dtype=t.dtype),
            cuda=types.SimpleNamespace(device=lambda d: Null(),
                current_stream=lambda d=None: self.caller, current_device=lambda: 1,
                stream=lambda stream: Null(), is_current_stream_capturing=lambda: False))
        self.patch = patch.dict(sys.modules, {'torch': self.torch,
                                'xdev_tp_torch._native': types.SimpleNamespace(Communicator=Native)})
        self.patch.start()
    def tearDown(self): self.patch.stop()

    def comm(self, mode, depth, max_payload=4096):
        from xdev_tp_torch import TorchCommunicator
        return TorchCommunicator(dict(rank=0, world_size=2, mode=mode, device_index=1,
                                      logical_depth=depth, max_payload_bytes=max_payload,
                                      timeout_ns=5000), object())

    def submissions(self):
        return [c for c in self.calls if c[0] in ('into', 'sum')]

    def assert_covers(self, x, y, expected_windows):
        windows = self.submissions()
        self.assertFalse(any(c[0] == 'sum' for c in windows),
                         'oversize all-reduce was submitted as one native message')
        self.assertEqual([len(c[1]) for c in windows], expected_windows)
        inputs = [seg for c in windows for seg in c[1]]
        outputs = [seg for c in windows for seg in c[2]]
        self.assertTrue(all(seg[0] is x for seg in inputs))
        self.assertTrue(all(seg[0] is y for seg in outputs))
        # Consecutive, disjoint, complete and each one legal message.
        self.assertEqual([(s, n) for _, s, n in inputs], [(s, n) for _, s, n in outputs])
        cursor = 0
        for _, start, count in inputs:
            self.assertEqual(start, cursor)
            self.assertTrue(0 < count <= 1024)
            cursor += count
        self.assertEqual(cursor, x.count)

    def test_d1_submits_each_legal_segment_into_one_output(self):
        c = self.comm(mode=1, depth=1)
        x = FlatTensor((3, 1000))
        y = c.all_reduce(x)
        self.assertEqual(y.shape, (3, 1000))
        self.assert_covers(x, y, [1, 1, 1])
        self.assertFalse(any(k[0] == 'sum' for k in self.calls))
        reserves = [k for k in self.calls if k[0] == 'reserve']
        self.assertEqual(reserves, [('reserve', 1, 5000)] * 3)
        framework = c.stats()['framework']
        self.assertEqual((framework['segmented_calls'], framework['segments_submitted']), (1, 3))

    def test_d2_eager_pipelines_windows_of_logical_depth(self):
        c = self.comm(mode=2, depth=4)
        x = FlatTensor((10000,))
        y = c.all_reduce(x)
        self.assert_covers(x, y, [4, 4, 2])
        order = [k[0] if k[0] != 'reserve' else ('reserve', k[1]) for k in self.calls
                 if k[0] in ('into', 'reserve')]
        self.assertEqual(order, [('reserve', 4), 'into', ('reserve', 4), 'into',
                                 ('reserve', 2), 'into'])
        self.assertTrue(all(k[3] == 98765 for k in self.submissions()))

    def test_capture_rejects_before_any_native_call_without_templates(self):
        self.torch.cuda.is_current_stream_capturing = lambda: True
        self.state['capacity'] = 9
        c = self.comm(mode=2, depth=4)
        with self.assertRaisesRegex(RuntimeError, 'template'):
            c.all_reduce(FlatTensor((10000,)))
        self.assertEqual(self.submissions(), [])
        self.assertFalse(any(k[0] == 'reserve' for k in self.calls))
        self.assertEqual(c.stats()['framework']['preflight_rejected'], 1)

    def test_capture_records_all_windows_without_blocking_reservation(self):
        self.torch.cuda.is_current_stream_capturing = lambda: True
        self.state['capacity'] = 10
        c = self.comm(mode=2, depth=4)
        x = FlatTensor((10000,))
        y = c.all_reduce(x)
        self.assert_covers(x, y, [4, 4, 2])
        self.assertFalse(any(k[0] == 'reserve' for k in self.calls))

    def test_single_message_path_is_unchanged(self):
        c = self.comm(mode=2, depth=4)
        x = FlatTensor((1024,))
        c.all_reduce(x)
        self.assertEqual([k[0] for k in self.submissions()], ['sum'])

    def test_shape_only_large_allreduce_submits_nothing(self):
        c = self.comm(mode=2, depth=4)
        y = c.all_reduce(FlatTensor((10000,), device='meta'))
        self.assertEqual(y.shape, (10000,))
        self.assertEqual(self.calls, [])

    def test_vllm_plugin_large_allreduce_never_uses_original_nccl(self):
        import xdev_tp_vllm as plugin
        original = []
        class Cuda:
            def __init__(self, cpu_group, device=None, device_group=None, unique_name=''):
                self.unique_name, self.world_size, self.rank_in_group = unique_name, 2, 0
            def all_reduce(self, input_): original.append('nccl'); return input_
            def all_gather(self, input_, dim=-1): return input_
            def gather(self, input_, dst=0, dim=-1): return input_
            def destroy(self): pass
        backend = self.comm(mode=2, depth=4)
        plugin._install_on_class(Cuda, version='0.10.2', factory=lambda c: backend)
        group = Cuda(None, unique_name='tp:0')
        x = FlatTensor((2048, 8))
        y = group.all_reduce(x)
        self.assertEqual(original, [])
        self.assertEqual(y.shape, (2048, 8))
        self.assertFalse(any(k[0] == 'sum' for k in self.submissions()))
        self.assertEqual(sum(len(k[1]) for k in self.submissions()), 16)


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
