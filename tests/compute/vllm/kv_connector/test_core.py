#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Scheduling, loading and fallback rules of the connector, without vLLM or a GPU.

Scheduler side: a prompt whose longest stored prefix (index) is longer than
vLLM's own computed tokens is offered as P - computed external tokens; the
plan restores whole groups from a group-aligned token into the staging pool.
Worker side, async mode (default, like LMCacheMPConnector): the restore and the
scatter run off the forward path; the request is reported finished receiving,
and also failed when anything went wrong, so vLLM (kv_load_failure_policy
"recompute") recomputes it. Sync mode: the restore starts in start_load_kv and
wait_for_layer_load scatters each layer before its attention; a failed restore,
or a layer that was never scattered, makes the blocks invalid so vLLM discards
the step's output for that request and recomputes. No wrong KV is ever left
looking loaded.
"""
import json
from pathlib import Path
import os
import random
import sys
import tempfile
import threading
import time
import unittest

import _paths
from xdev_kv_vllm import core
from xdev_kv_vllm import index as ki
from xdev_kv_vllm import layout as kl
from xdev_kv_vllm.restore import RestoreOutcome

S = kl.StagingLayout(block_size=4, layers=2, heads=2, state_elems=2, elem_bytes=1)  # 8 B/token
LBA, GROUP, POOL = 8, 32, 512
MODEL = 'tiny'
BLOCKS = 32
# One layer's [B, H, N, C] view in vLLM's default LBNHC layout: physical [B, N, H, C].
STRIDES = (S.block_size * S.heads * S.state_elems, S.state_elems, S.heads * S.state_elems, 1)
TARGET = kl.PagedTarget(4, 4, S.heads, S.state_elems, STRIDES)
LAYER_ELEMS = BLOCKS * S.block_size * S.heads * S.state_elems


def cfg(**kw):
    base = dict(index_path='unused', model_key=MODEL, load_mode='async', group_bytes=GROUP,
                pool_bytes=POOL, lba_bytes=LBA, restore=None)
    base.update(kw)
    return core.ConnectorConfig(**base)


class Disk:
    def __init__(self, nbytes=1 << 14):
        rnd = random.Random(7)
        self.data = bytearray(rnd.randrange(256) for _ in range(nbytes))

    def kv(self, slba, token, layer, head, elem):
        return self.data[slba * LBA + S.src_index(token, layer, head, elem)]


class FakeService:
    """RestoreService's interface: restore into a staging buffer, replaceable staging."""

    def __init__(self, disk, outcomes=None, log=None):
        self.disk, self.outcomes, self.log = disk, list(outcomes or []), log if log is not None else []
        self.staging = bytearray(POOL)
        self.frame_bytes = 8
        self.disabled = False
        self.released = []
        self.release = self.released.append
        self.calls = []

    def restore(self, object_slba, nbytes, staging_offset):
        self.log.append(('restore', object_slba))
        self.calls.append((object_slba, nbytes, staging_offset))
        how = self.outcomes.pop(0) if self.outcomes else 'ok'
        if how == 'fail':
            return RestoreOutcome(False, -5, 'KV_RESULT not ok', 0, None)
        if how == 'replace':   # fails and the worker (and its staging) is replaced
            self.release(self.staging)
            self.staging = bytearray(POOL)
            return RestoreOutcome(False, -5, 'replaced', 0, None)
        a = object_slba * LBA
        self.staging[staging_offset:staging_offset + nbytes] = self.disk.data[a:a + nbytes]
        return RestoreOutcome(True, 0, '', 1000, {})

    def close(self):
        return []


class FakeDevice:
    """GPU operations of the worker side over Python lists (one per layer)."""

    def __init__(self, log=None, fail_scatter=False):
        self.mem = [[-1] * LAYER_ELEMS for _ in range(S.layers)]
        self.log = log if log is not None else []
        self.fail_scatter = fail_scatter
        self.fences = 0

    def fence(self):
        self.fences += 1
        self.log.append(('fence', self.fences))
        return self.fences

    def wait_host(self, token):
        self.log.append(('wait', token))

    def _scatter(self, staging, spec, layer):
        if self.fail_scatter:
            raise RuntimeError('scatter failed')
        rng = kl.ScatterRange(spec.first_token, spec.end_token, spec.stage_token)
        for src, dst in kl.scatter_pairs(S, TARGET, spec.block_ids, rng, layer):
            self.mem[layer][dst] = staging[spec.staging_offset + src]

    def scatter_async(self, staging, spec, after):
        self.log.append(('scatter_async', spec.req_id, after))
        for layer in range(S.layers):
            self._scatter(staging, spec, layer)
        return ('done', spec.req_id)

    def scatter_now(self, staging, spec, layer):
        self.log.append(('scatter', spec.req_id, layer))
        self._scatter(staging, spec, layer)


def write_index(path, entries):
    path.write_text('xdev-kv-index 1\n' + ''.join(
        f'prefix {h} object=o slba={slba} offset={off} bytes={tok * S.bytes_per_token} '
        f'tokens={tok}\n' for h, slba, off, tok in entries))


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kvconn-core-')
        self.dir = Path(self.tmp.name)
        self.prompt_a = list(range(100, 100 + 41))      # 41 tokens: 40 hashable for a hit
        self.prompt_b = list(range(500, 500 + 21))
        ha = dict(ki.prefix_hashes(MODEL, S, self.prompt_a))
        hb = dict(ki.prefix_hashes(MODEL, S, self.prompt_b))
        self.slba_a, self.slba_b = 64, 512
        write_index(self.dir / 'kv.index', [(ha[16], self.slba_a, 0, 16), (ha[40], self.slba_a, 0, 40),
                                             (hb[20], self.slba_b, 0, 20)])
        self.index = ki.PrefixIndex.load(self.dir / 'kv.index', MODEL, S, LBA)
        self.disk = Disk()

    def tearDown(self):
        self.tmp.cleanup()

    def scheduler(self, mode='async', **kw):
        return core.SchedulerSide(cfg(load_mode=mode, **kw), self.index, S, block_size=4)

    def worker(self, mode='async', service=None, device=None, stats_file=None):
        self.log = []
        service = service or FakeService(self.disk, log=self.log)
        device = device or FakeDevice(self.log)
        w = core.WorkerSide(cfg(load_mode=mode, stats_file=stats_file), service, device,
                            {f'model.layers.{i}.self_attn.attn': i for i in range(S.layers)}, S)
        self.addCleanup(w.shutdown)
        return w, service, device

    def check_loaded(self, device, spec, slba):
        for token in range(spec.first_token, spec.end_token):
            for layer in range(S.layers):
                for head in range(S.heads):
                    for e in range(S.state_elems):
                        got = device.mem[layer][TARGET.dst_index(spec.block_ids, token, head, e)]
                        # The object stores token 0 at slba; token t sits at src_index(t).
                        self.assertEqual(got, self.disk.kv(slba, token, layer, head, e))

    def written(self, device):
        return sum(1 for layer in device.mem for v in layer if v != -1)


class Scheduler(Fixture):
    def test_hit_and_plan(self):
        s = self.scheduler()
        self.assertEqual(s.lookup('a', self.prompt_a, 0), (40, True))
        self.assertEqual(s.lookup('a', self.prompt_a, 0), (40, True), 'side-effect free')
        self.assertEqual(s.lookup('x', list(range(9000, 9041)), 0), (0, False))
        blocks = [9, 3, 7, 1, 0, 2, 4, 5, 6, 8, 10, 11]
        s.after_alloc('a', blocks, 40)
        (spec,) = s.build()
        self.assertEqual(spec, core.LoadSpec('a', tuple(blocks[:10]), 0, 40, 0, self.slba_a,
                                             40 * 8, 0, ''))
        self.assertEqual(s.build(), [], 'build resets')

    def test_at_most_prompt_minus_one(self):
        s = self.scheduler()
        self.assertEqual(s.lookup('a', self.prompt_a[:40], 0), (16, True))

    def test_after_a_local_prefix_hit(self):
        s = self.scheduler()
        self.assertEqual(s.lookup('a', self.prompt_a, 8), (32, True))
        s.after_alloc('a', list(range(10)), 32)
        (spec,) = s.build()
        # 32-byte groups are 4 tokens: staging starts at the first computed-out token.
        self.assertEqual((spec.first_token, spec.stage_token, spec.end_token), (8, 8, 40))
        self.assertEqual((spec.object_slba, spec.nbytes), (self.slba_a + 8 * 8 // LBA, 32 * 8))

    def test_local_hit_covers_the_stored_prefix(self):
        self.assertEqual(self.scheduler().lookup('a', self.prompt_a, 40), (0, False))

    def test_restore_larger_than_the_pool_is_a_miss(self):
        s = self.scheduler(pool_bytes=256)
        self.assertEqual(s.lookup('a', self.prompt_a, 0), (16, True), 'the 16-token prefix fits')

    def test_sync_packs_a_step_into_the_pool(self):
        s = self.scheduler('sync', pool_bytes=512)
        self.assertEqual(s.lookup('a', self.prompt_a, 0), (40, False))
        s.after_alloc('a', list(range(10)), 40)
        # 320 bytes used; prompt_b needs 160 at offset 320 -> fits (480 <= 512).
        self.assertEqual(s.lookup('b', self.prompt_b, 0), (20, False))
        s.after_alloc('b', list(range(10, 15)), 20)
        self.assertEqual(s.lookup('c', self.prompt_a, 0), (0, False), 'pool full this step')
        a, b = s.build()
        self.assertEqual((a.staging_offset, b.staging_offset), (0, 320))
        self.assertEqual(s.lookup('c', self.prompt_a, 0), (40, False), 'next step starts empty')

    def test_too_few_blocks_marks_the_load_failed(self):
        s = self.scheduler()
        s.lookup('a', self.prompt_a, 0)
        s.after_alloc('a', [1, 2], 40)
        (spec,) = s.build()
        self.assertTrue(spec.invalid)

    def test_no_external_tokens_no_load(self):
        s = self.scheduler()
        s.lookup('a', self.prompt_a, 0)
        s.after_alloc('a', list(range(10)), 0)
        self.assertEqual(s.build(), [])


def wait_results(w, want, timeout=10):
    finished, failed = set(), set()
    deadline = time.monotonic() + timeout
    while finished != want and time.monotonic() < deadline:
        f, x = w.transfer_results(set())
        finished |= f
        failed |= x
        time.sleep(0.01)
    return finished, failed


class AsyncWorker(Fixture):
    def plan(self, req, prompt, computed=0):
        s = self.scheduler()
        n, _ = s.lookup(req, prompt, computed)
        s.after_alloc(req, [5, 2, 9, 0, 1, 3, 4, 6, 7, 8, 10], n)
        return s.build()[0]

    def test_loads_and_reports(self):
        w, svc, dev = self.worker(stats_file=str(self.dir / 'stats.jsonl'))
        spec = self.plan('a', self.prompt_a)
        w.start_loads([spec])
        finished, failed = wait_results(w, {'a'})
        self.assertEqual((finished, failed), ({'a'}, set()))
        self.check_loaded(dev, spec, self.slba_a)
        self.assertEqual(self.written(dev), 40 * S.layers * S.heads * S.state_elems)
        fence = [e for e in self.log if e[0] == 'fence'][0][1]
        self.assertIn(('scatter_async', 'a', fence), self.log, 'scatter waits for the fence')
        row = json.loads((self.dir / 'stats.jsonl').read_text().splitlines()[0])
        self.assertEqual((row['req_id'], row['ok'], row['tokens'], row['mode']), ('a', True, 40, 'async'))

    def test_local_hit_scatters_only_new_tokens(self):
        w, svc, dev = self.worker()
        spec = self.plan('a', self.prompt_a, computed=8)
        w.start_loads([spec])
        wait_results(w, {'a'})
        self.check_loaded(dev, spec, self.slba_a)
        self.assertEqual(self.written(dev), 32 * S.layers * S.heads * S.state_elems)

    def test_restore_failure_is_reported_and_nothing_scattered(self):
        svc = FakeService(self.disk, ['fail'])
        w, _, dev = self.worker(service=svc)
        w.start_loads([self.plan('a', self.prompt_a)])
        self.assertEqual(wait_results(w, {'a'}), ({'a'}, {'a'}))
        self.assertEqual(self.written(dev), 0)

    def test_scatter_failure_is_a_load_failure(self):
        w, _, dev = self.worker(device=FakeDevice(fail_scatter=True))
        w.start_loads([self.plan('a', self.prompt_a)])
        self.assertEqual(wait_results(w, {'a'}), ({'a'}, {'a'}))

    def test_invalid_plan_fails_without_a_restore(self):
        w, svc, _ = self.worker()
        spec = self.plan('a', self.prompt_a)._replace(invalid='too few blocks')
        w.start_loads([spec])
        self.assertEqual(wait_results(w, {'a'}), ({'a'}, {'a'}))
        self.assertEqual(svc.calls, [])

    def test_fifo_and_no_sync_errors(self):
        w, svc, dev = self.worker()
        a, b = self.plan('a', self.prompt_a), self.plan('b', self.prompt_b)
        w.start_loads([a, b])
        self.assertEqual(wait_results(w, {'a', 'b'})[1], set())
        self.assertEqual([c[0] for c in svc.calls], [self.slba_a, self.slba_b])
        self.assertEqual(w.load_error_blocks(), set())


class SyncWorker(Fixture):
    def plans(self, *reqs):
        s = self.scheduler('sync')
        out = []
        for req, prompt, blocks in reqs:
            n, is_async = s.lookup(req, prompt, 0)
            self.assertFalse(is_async)
            s.after_alloc(req, blocks, n)
        return s.build()

    def layers(self, w, which=None):
        for i in (range(S.layers) if which is None else which):
            w.wait_layer(f'model.layers.{i}.self_attn.attn')

    def test_layer_by_layer(self):
        w, svc, dev = self.worker('sync')
        (spec,) = self.plans(('a', self.prompt_a, list(range(20, 30))))
        w.start_loads([spec])
        self.layers(w)
        w.wait_layer('model.unrelated')
        self.assertEqual(w.load_error_blocks(), set())
        self.assertEqual([e for e in self.log if e[0] == 'scatter'],
                         [('scatter', 'a', 0), ('scatter', 'a', 1)])
        self.check_loaded(dev, spec, self.slba_a)
        self.assertEqual(w.transfer_results(set()), (set(), set()))

    def test_failed_restore_invalidates_the_blocks(self):
        svc = FakeService(self.disk, ['ok', 'fail'])
        w, _, dev = self.worker('sync', service=svc)
        a, b = self.plans(('a', self.prompt_a, list(range(20, 30))),
                          ('b', self.prompt_b, [3, 4, 5, 6, 7, 8]))
        w.start_loads([a, b])
        self.layers(w)
        self.assertEqual(w.load_error_blocks(), {3, 4, 5, 6, 7})
        self.check_loaded(dev, a, self.slba_a)
        self.assertNotIn(('scatter', 'b', 0), self.log)

    def test_unscattered_layer_invalidates_the_blocks(self):
        w, _, _ = self.worker('sync')
        (spec,) = self.plans(('a', self.prompt_a, list(range(20, 30))))
        w.start_loads([spec])
        self.layers(w, [0])
        self.assertEqual(w.load_error_blocks(), set(range(20, 30)))
        self.assertEqual(w.load_error_blocks(), set(), 'reported once')

    def test_next_step_waits_for_the_previous_scatters(self):
        w, svc, dev = self.worker('sync')
        (a,) = self.plans(('a', self.prompt_a, list(range(20, 30))))
        w.start_loads([a])
        self.layers(w)
        w.load_error_blocks()
        (b,) = self.plans(('b', self.prompt_b, [3, 4, 5, 6, 7, 8]))
        w.start_loads([b])
        self.layers(w)
        second = [e for e in self.log if e[0] == 'fence'][1][1]
        self.assertLess(self.log.index(('wait', second)), self.log.index(('restore', self.slba_b)))

    def test_replaced_staging_outlives_the_step(self):
        svc = FakeService(self.disk, ['ok', 'replace'])
        w, _, dev = self.worker('sync', service=svc)
        a, b = self.plans(('a', self.prompt_a, list(range(20, 30))),
                          ('b', self.prompt_b, [3, 4, 5, 6, 7, 8]))
        first = svc.staging
        w.start_loads([a, b])
        self.layers(w)
        self.check_loaded(dev, a, self.slba_a)
        self.assertEqual(svc.released, [], 'released only after the step')
        self.assertEqual(w.load_error_blocks(), {3, 4, 5, 6, 7})
        w.start_loads([])
        deadline = time.monotonic() + 5
        while not svc.released and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIs(svc.released[0], first)

    def test_disabled_service_fails_every_load(self):
        svc = FakeService(self.disk)
        svc.disabled = True
        w, _, _ = self.worker('sync', service=svc)
        (spec,) = self.plans(('a', self.prompt_a, list(range(20, 30))))
        w.start_loads([spec])
        self.layers(w)
        self.assertEqual(w.load_error_blocks(), set(range(20, 30)))
        self.assertEqual(svc.calls, [])


class EndToEnd(Fixture):
    """The real RestoreService against the fake worker process; staging is its stage file."""

    def test_async_restore_through_the_worker_process(self):
        from xdev_kv_vllm import restore as kr
        disk, stage = self.dir / 'disk', self.dir / 'stage'
        disk.write_bytes(bytes(self.disk.data))
        stage.write_bytes(b'\0' * POOL)

        class FileStaging:
            def __init__(self, ready, pid):
                self.ready = ready

            def __getitem__(self, i):
                return stage.read_bytes()[i]

            def release(self):
                pass
        fake = Path(__file__).resolve().parent / 'fake_restore_worker.py'
        rc = kr.RestoreConfig(argv=[sys.executable, '-B', str(fake), '--source', str(disk),
                                    '--stage', str(stage), '--lba-bytes', str(LBA),
                                    '--frame-bytes', '8', '--group-bytes', str(GROUP),
                                    '--pool-bytes', str(POOL)],
                              group_bytes=GROUP, pool_bytes=POOL, ready_timeout=20, go_timeout=20)
        svc = kr.RestoreService(rc, FileStaging)
        svc.start()
        w, _, dev = self.worker(service=svc)
        s = self.scheduler()
        n, _ = s.lookup('b', self.prompt_b, 0)
        s.after_alloc('b', [7, 1, 4, 2, 0], n)
        (spec,) = s.build()
        w.start_loads([spec])
        self.assertEqual(wait_results(w, {'b'}), ({'b'}, set()))
        self.check_loaded(dev, spec, self.slba_b)


class Config(unittest.TestCase):
    BASE = {'xdev_ext.index': '/k/kv.index', 'xdev_ext.model_key': 'qwen3-8b-bf16',
            'xdev_ext.pool_bytes': 1 << 30, 'lmcache.other': 1}

    def test_defaults_and_worker(self):
        c = core.ConnectorConfig.from_extra(dict(self.BASE))
        self.assertEqual((c.load_mode, c.group_bytes, c.lba_bytes, c.scatter, c.restore),
                         ('async', 131072, 512, 'triton', None))
        w = core.ConnectorConfig.from_extra(dict(self.BASE, **{
            'xdev_ext.worker_argv': ['kv_restore', 'restore'], 'xdev_ext.go_timeout_s': 30,
            'xdev_ext.ordinal_file': '/k/o.json', 'xdev_ext.load_mode': 'sync'}), worker=True)
        self.assertEqual((w.load_mode, w.restore.argv, w.restore.go_timeout, w.restore.pool_bytes,
                          w.restore.ordinal_file), ('sync', ['kv_restore', 'restore'], 30.0, 1 << 30,
                                                    '/k/o.json'))

    def test_refusals(self):
        for extra, worker in (({'xdev_ext.colour': 1}, False), ({'xdev_ext.load_mode': 'eager'}, False),
                              ({}, True), ({'xdev_ext.worker_argv': 'kv_restore restore'}, True),
                              ({'xdev_ext.pool_bytes': 1000}, False),
                              ({'xdev_ext.scatter': 'cpu'}, False)):
            with self.subTest(extra=extra), self.assertRaises(core.ConfigError):
                core.ConnectorConfig.from_extra(dict(self.BASE, **extra), worker=worker)
        for need in ('xdev_ext.index', 'xdev_ext.model_key', 'xdev_ext.pool_bytes'):
            extra = dict(self.BASE)
            del extra[need]
            with self.subTest(missing=need), self.assertRaises(core.ConfigError):
                core.ConnectorConfig.from_extra(extra)


if __name__ == '__main__':
    unittest.main()
