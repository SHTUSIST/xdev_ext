#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""XdevExtConnector against vLLM 0.33.0's KVConnectorBase_V1 interface (host test).

Without vLLM installed the test uses vllm_stub.py, which reproduces the
interface of base.py at the v0.33.0 tag. Checked: every abstract method is
implemented with vLLM's parameter names; the connector refuses configurations
in which a failed load could not be recomputed or the staged layout cannot be
the vLLM cache's (kv_load_failure_policy other than "recompute", tensor or
pipeline parallelism, more than one KV cache group, a non full-attention spec,
a layer cache of another shape); the scheduler and worker hooks drive the
rules of core.py; a failed restore is reported as a failed receive.
"""
import inspect
from pathlib import Path
import tempfile
import time
import types
import unittest

import _paths  # noqa: F401
try:
    import vllm  # noqa: F401
    HAVE_VLLM = True
except ImportError:
    import vllm_stub
    vllm_stub.install()
    HAVE_VLLM = False

import test_core as tc
from xdev_kv_vllm import connector as kc
from xdev_kv_vllm import index as ki
from xdev_kv_vllm.restore import RestoreError
from vllm.distributed.kv_transfer.kv_connector.v1.base import (KVConnectorBase_V1,
                                                                KVConnectorRole)

NAMES = [f'model.layers.{i}.self_attn.attn' for i in range(tc.S.layers)]


class FakeDtype:
    def __init__(self, name='uint8', itemsize=1):
        self.name, self.itemsize = name, itemsize

    def __str__(self):
        return 'torch.' + self.name


class FullAttentionSpec:
    def __init__(self, **kw):
        self.block_size, self.num_kv_heads, self.head_size, self.head_size_v = 4, 2, 1, 1
        self.dtype = FakeDtype()
        self.state_content_bytes = None
        self.__dict__.update(kw)

    @property
    def num_heads(self):
        return self.num_kv_heads

    @property
    def state_content_size_bytes(self):
        return (self.head_size + self.head_size_v) * self.dtype.itemsize


class FakeTensor:
    def __init__(self, shape=(tc.BLOCKS, 2, 4, 2), strides=tc.STRIDES, dtype=None):
        self.shape, self._strides = shape, strides
        self.dtype = dtype if dtype is not None else FakeDtype()
        self.device = types.SimpleNamespace(index=0, type='cuda')

    def dim(self):
        return len(self.shape)

    def stride(self):
        return self._strides


class Base(unittest.TestCase):
    def setUp(self):
        self.fx = tc.Fixture('setUp')
        self.fx.setUp()
        self.addCleanup(self.fx.tearDown)
        self.extra = {'xdev_ext.index': str(self.fx.dir / 'kv.index'), 'xdev_ext.model_key': tc.MODEL,
                      'xdev_ext.pool_bytes': tc.POOL, 'xdev_ext.group_bytes': tc.GROUP,
                      'xdev_ext.lba_bytes': tc.LBA, 'xdev_ext.worker_argv': ['kv_restore', 'restore']}
        self.made = {}
        self.log = []
        orig = (kc.make_device, kc.make_service)
        self.addCleanup(lambda: (setattr(kc, 'make_device', orig[0]),
                                 setattr(kc, 'make_service', orig[1])))

        def make_device(views, staging, device_index, scatter):
            self.made['views'] = views
            self.made['device'] = tc.FakeDevice(self.log)
            return self.made['device']

        def make_service(restore_cfg, staging_factory):
            svc = tc.FakeService(self.fx.disk, self.made.get('outcomes'), log=self.log)
            if self.made.get('start_fails'):
                def start():
                    raise RestoreError('KV_READY refused: dst peer')
            else:
                def start():
                    pass
            svc.start = start
            self.made['service'] = svc
            return svc
        kc.make_device, kc.make_service = make_device, make_service

    def config(self, **kw):
        ktc = types.SimpleNamespace(kv_connector_extra_config=dict(self.extra, **kw.pop('extra', {})),
                                    kv_load_failure_policy=kw.pop('policy', 'recompute'),
                                    kv_role='kv_consumer')
        vc = types.SimpleNamespace(
            kv_transfer_config=ktc,
            parallel_config=types.SimpleNamespace(tensor_parallel_size=kw.pop('tp', 1),
                                                  pipeline_parallel_size=kw.pop('pp', 1)),
            cache_config=types.SimpleNamespace(block_size=4, cache_dtype=kw.pop('cache_dtype', 'auto')),
            model_config=types.SimpleNamespace(model='tiny-model', dtype=kw.pop('model_dtype', 'uint8')))
        groups = kw.pop('groups', None) or [types.SimpleNamespace(
            layer_names=list(reversed(NAMES)), kv_cache_spec=kw.pop('spec', FullAttentionSpec()))]
        return vc, types.SimpleNamespace(kv_cache_groups=groups, num_blocks=tc.BLOCKS)

    def connector(self, role, **kw):
        vc, kcc = self.config(**kw)
        c = kc.XdevExtConnector(vc, role, kcc)
        if role == KVConnectorRole.WORKER:
            self.addCleanup(c.shutdown)
        return c

    def request(self, req_id, prompt):
        return types.SimpleNamespace(request_id=req_id, prompt_token_ids=prompt,
                                     status=types.SimpleNamespace(name='WAITING'))


class Interface(Base):
    def test_spec_dtype_must_match_resolved_and_explicit_dtype(self):
        spec = FullAttentionSpec(dtype=FakeDtype('bfloat16', 2))
        for kw in ({'spec': spec, 'model_dtype': 'float16'},
                   {'spec': spec, 'model_dtype': 'bfloat16',
                    'extra': {'xdev_ext.kv_dtype': 'float16'}},
                   {'model_dtype': None},
                   {'spec': FullAttentionSpec(dtype=FakeDtype('unknown', 1))}):
            with self.subTest(kw=kw), self.assertRaisesRegex(ValueError, 'dtype'):
                self.connector(KVConnectorRole.WORKER, **kw)
        # Explicit cache dtype can differ from the model's default, but the
        # actual spec and caller's optional expectation must agree with it.
        self.connector(KVConnectorRole.WORKER, spec=spec, model_dtype='float16',
                       cache_dtype='bfloat16', extra={'xdev_ext.kv_dtype': 'bf16'})

    def test_tensor_dtype_is_checked_before_restore_service_start(self):
        c = self.connector(KVConnectorRole.WORKER,
                           spec=FullAttentionSpec(dtype=FakeDtype('bfloat16', 2)),
                           model_dtype='bfloat16')
        for dtype in (FakeDtype('float16', 2), FakeDtype('mystery', 2)):
            with self.subTest(dtype=str(dtype)), self.assertRaisesRegex(ValueError, 'dtype'):
                c.register_kv_caches({name: FakeTensor(dtype=dtype) for name in NAMES})
        self.assertNotIn('service', self.made)
    def test_every_abstract_method_with_vllm_names(self):
        self.assertEqual(kc.XdevExtConnector.__abstractmethods__, frozenset())
        for name, base in inspect.getmembers(KVConnectorBase_V1, inspect.isfunction):
            mine = kc.XdevExtConnector.__dict__.get(name)
            if mine is None or isinstance(mine, (classmethod, staticmethod)):
                continue
            with self.subTest(method=name):
                self.assertEqual(list(inspect.signature(mine).parameters),
                                 list(inspect.signature(base).parameters))
        self.assertTrue(issubclass(kc.XdevExtConnector, KVConnectorBase_V1))
        self.assertEqual(kc.XdevExtConnector._cache_hit_source.value, 'disk')

    def test_cudagraph_mode(self):
        self.assertFalse(kc.XdevExtConnector.requires_piecewise_for_cudagraph({}))
        self.assertTrue(kc.XdevExtConnector.requires_piecewise_for_cudagraph(
            {'xdev_ext.load_mode': 'sync'}))

    def test_refusals(self):
        two = [types.SimpleNamespace(layer_names=NAMES, kv_cache_spec=FullAttentionSpec())] * 2

        class MLAAttentionSpec(FullAttentionSpec):
            pass
        for kw in ({'policy': 'fail'}, {'tp': 2}, {'pp': 2}, {'groups': two},
                   {'spec': MLAAttentionSpec()}, {'spec': FullAttentionSpec(state_content_bytes=8)},
                   {'extra': {'xdev_ext.colour': 'red'}}):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.connector(KVConnectorRole.SCHEDULER, **kw)


class Scheduler(Base):
    def test_offer_plan_and_finish(self):
        c = self.connector(KVConnectorRole.SCHEDULER)
        req = self.request('a', self.fx.prompt_a)
        self.assertEqual(c.get_num_new_matched_tokens(req, 0), (40, True))
        blocks = types.SimpleNamespace(get_block_ids=lambda: (list(range(3, 15)),))
        c.update_state_after_alloc(req, blocks, 40)
        meta = c.build_connector_meta(types.SimpleNamespace())
        self.assertIsInstance(meta, kc.XdevExtConnectorMetadata)
        (spec,) = meta.loads
        self.assertEqual((spec.req_id, spec.block_ids, spec.end_token), ('a', tuple(range(3, 13)), 40))
        self.assertEqual(c.request_finished(req, []), (False, None))
        self.assertEqual(c.request_finished_all_groups(req, ([],)), (False, None))
        miss = self.request('m', list(range(7000, 7041)))
        self.assertEqual(c.get_num_new_matched_tokens(miss, 0), (0, False))
        preempted = self.request('a', self.fx.prompt_a)
        preempted.status = types.SimpleNamespace(name='PREEMPTED')
        self.assertEqual(c.get_num_new_matched_tokens(preempted, 0), (0, False))


class Worker(Base):
    def loads(self, mode='async'):
        s = tc.core.SchedulerSide(tc.cfg(load_mode=mode), self.fx.index, tc.S, block_size=4)
        n, _ = s.lookup('a', self.fx.prompt_a, 0)
        s.after_alloc('a', list(range(10)), n)
        return kc.XdevExtConnectorMetadata(s.build())

    def register(self, c, **tensor):
        c.register_kv_caches({name: FakeTensor(**tensor) for name in reversed(NAMES)})

    def poll(self, c, want):
        deadline = time.monotonic() + 10
        got = None
        while time.monotonic() < deadline:
            got = c.get_transfer_results(set())
            if got.finished_recving:
                return got
            time.sleep(0.01)
        return got

    def test_async_load(self):
        c = self.connector(KVConnectorRole.WORKER)
        self.register(c)
        self.assertEqual(len(self.made['views']), tc.S.layers)
        c.bind_connector_metadata(self.loads())
        c.start_load_kv(types.SimpleNamespace())
        for name in NAMES:
            c.wait_for_layer_load(name)
        c.save_kv_layer(NAMES[0], None, None)
        c.wait_for_save()
        got = self.poll(c, {'a'})
        self.assertEqual((got.finished_recving, got.failed_recving), ({'a'}, set()))
        self.assertEqual(c.get_block_ids_with_load_errors(), set())
        self.fx.check_loaded(self.made['device'], c._get_connector_metadata().loads[0], self.fx.slba_a)

    def test_layers_in_model_order(self):
        names = [f'model.layers.{i}.attn' for i in (10, 2, 1, 0, 3, 4, 5, 6, 7, 8, 9)]
        self.assertEqual(kc.layer_order(names), sorted(names, key=lambda n: int(n.split('.')[2])))
        self.assertEqual(kc.layer_order(['b', 'a']), ['b', 'a'], 'unnumbered names keep vLLM order')

    def test_failed_restore_is_a_failed_receive(self):
        self.made['outcomes'] = ['fail']
        c = self.connector(KVConnectorRole.WORKER)
        self.register(c)
        c.bind_connector_metadata(self.loads())
        c.start_load_kv(types.SimpleNamespace())
        got = self.poll(c, {'a'})
        self.assertEqual((got.finished_recving, got.failed_recving), ({'a'}, {'a'}))

    def test_worker_that_cannot_start_fails_every_load(self):
        self.made['start_fails'] = True
        c = self.connector(KVConnectorRole.WORKER)
        self.register(c)
        c.bind_connector_metadata(self.loads())
        c.start_load_kv(types.SimpleNamespace())
        got = self.poll(c, {'a'})
        self.assertEqual(got.failed_recving, {'a'})

    def test_sync_load(self):
        c = self.connector(KVConnectorRole.WORKER, extra={'xdev_ext.load_mode': 'sync'})
        self.register(c)
        c.bind_connector_metadata(self.loads('sync'))
        c.start_load_kv(types.SimpleNamespace())
        for name in NAMES:
            c.wait_for_layer_load(name)
        self.assertEqual(c.get_block_ids_with_load_errors(), set())
        self.fx.check_loaded(self.made['device'], c._get_connector_metadata().loads[0], self.fx.slba_a)

    def test_cache_of_another_shape_is_refused(self):
        c = self.connector(KVConnectorRole.WORKER)
        with self.assertRaises(ValueError):
            self.register(c, shape=(tc.BLOCKS, 2, 4, 3))


if __name__ == '__main__':
    unittest.main()
