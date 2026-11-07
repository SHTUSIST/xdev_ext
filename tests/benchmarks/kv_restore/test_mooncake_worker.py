#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mooncake baseline worker logic against a recording stand-in of mooncake.store.

Requirements: host 1 loads every KV chunk and ends with each one on its SSD
only (a put that finds DRAM full is retried, the last chunks are pushed out
with fillers that are then removed); host 2 contributes no DRAM, restores a
prefix with one batch_get_into() into its registered buffer, synchronizes
before the clock stops, and refuses a run whose chunks are not SSD-only.
The stand-in proves nothing about Mooncake itself, TCP or a GPU.
"""
import contextlib
import ctypes
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('mooncake_worker', HERE / 'mooncake_worker.py')
mw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mw)
kl, kp = mw.kl, mw.kp
MIB = 1 << 20


class Desc:
    def __init__(self, memory):
        self.status = 'ReplicaStatus.COMPLETE'
        self.memory = memory

    def is_memory_replica(self):
        return self.memory

    def is_disk_replica(self):
        return False

    def is_local_disk_replica(self):
        return not self.memory


class FakeStore:
    """DRAM holds `capacity` objects; a put into a full DRAM fails once and
    offloads the oldest object to the SSD, as an eviction would."""
    instances = []

    def __init__(self, capacity=2, promote=False, corrupt=False):
        self.capacity, self.promote, self.corrupt = capacity, promote, corrupt
        self.memory, self.disk, self.removed, self.calls = {}, {}, [], []
        self.registered = {}
        FakeStore.instances.append(self)

    def setup(self, config):
        self.config = config
        return 0

    def put(self, key, data):
        self.calls.append(('put', key))
        if len(self.memory) >= self.capacity:
            old = next(iter(self.memory))
            self.disk[old] = self.memory.pop(old)
            return -200
        self.memory[key] = bytes(data)
        return 0

    def batch_get_replica_desc(self, keys):
        out = {}
        for k in keys:
            out[k] = ([Desc(True)] if k in self.memory else []) + ([Desc(False)] if k in self.disk else [])
        return out

    def remove(self, key):
        self.removed.append(key)
        self.memory.pop(key, None)
        self.disk.pop(key, None)
        return 0

    def register_buffer(self, ptr, size):
        self.registered[ptr] = size
        return 0

    def unregister_buffer(self, ptr):
        self.registered.pop(ptr)
        return 0

    def batch_get_into(self, keys, ptrs, sizes):
        self.calls.append(('batch_get_into', len(keys)))
        got = []
        for k, p, s in zip(keys, ptrs, sizes):
            data = self.disk.get(k) or self.memory.get(k)
            if data is None or len(data) > s:
                got.append(-704)
                continue
            if self.corrupt:
                data = b'\0' + data[1:]
            ctypes.memmove(p, data, len(data))
            got.append(len(data))
            if self.promote:
                self.memory[k] = data
        return got

    def close(self):
        return 0


def fake_module(**kwargs):
    m = types.ModuleType('mooncake.store')
    m.MooncakeDistributedStore = lambda: FakeStore(**kwargs)
    return m


MANIFEST = {'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
            'window': {'slba': 0, 'nlb': 64 * MIB // 512},
            'objects': [{'name': 'q14', 'model': 'qwen3-14b', 'tokens': 64, 'seed': 5,
                         'slba': 0, 'nlb': 64 * 163840 // 512}]}


class Logic(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-mooncake-')
        self.manifest = Path(self.tmp.name) / 'manifest.json'
        self.manifest.write_text(json.dumps(MANIFEST))
        FakeStore.instances.clear()

    def tearDown(self):
        self.tmp.cleanup()

    def test_chunks_cover_the_prefix_exactly(self):
        chunks = mw.object_keys('kv', 'q14', 10 * MIB + 5, 4 * MIB)
        self.assertEqual([c[0] for c in chunks], ['kv/q14/0', 'kv/q14/1', 'kv/q14/2'])
        self.assertEqual([c[1] for c in chunks], [0, 4 * MIB, 8 * MIB])
        self.assertEqual([c[2] for c in chunks], [4 * MIB, 4 * MIB, 2 * MIB + 5])

    def test_load_leaves_every_chunk_on_ssd_only(self):
        store = FakeStore(capacity=2)
        keys, fillers, g = mw.load(store, kl.load_manifest(self.manifest), 'kv', MIB, 5, 5, 8)
        self.assertEqual(len(keys), 64 * 163840 // MIB)
        self.assertTrue(g['ok'], g)
        self.assertTrue(all(k in store.disk and k not in store.memory for k in keys))
        self.assertTrue(fillers and set(fillers) <= set(store.removed), 'fillers removed')
        self.assertIn(('put', keys[2]), store.calls[3:6], 'a put into full DRAM was retried')
        self.assertEqual(store.disk[keys[1]], kl.pattern_bytes(5, MIB, MIB))

    def run_main(self, role, stdin, *extra, **store):
        out = io.StringIO()
        argv = [role, '--manifest', str(self.manifest), '--local-hostname', '10.0.0.2',
                '--master', '10.0.0.1:50051', '--object-bytes', str(MIB)] + list(extra)
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out):
                rc = mw.main(argv, store_module=fake_module(**store))
        finally:
            sys.stdin = old_stdin
        return rc, [kp.parse_line(l) for l in out.getvalue().splitlines()]

    def preload(self, store):
        mw.load(store, kl.load_manifest(self.manifest), 'kv', MIB, 5, 5, 8)

    def test_host1_config_is_factory_default_plus_offload(self):
        rc, lines = self.run_main('host1-load', 'QUIT\n', '--ssd-offload-path', '/ssd/mc')
        self.assertEqual(rc, 0)
        self.assertEqual([k for k, _ in lines], ['KV_READY', 'KV_BYE'])
        cfg = FakeStore.instances[0].config
        self.assertEqual(cfg['protocol'], 'tcp')
        self.assertTrue(cfg['enable_ssd_offload'])
        self.assertNotIn('global_segment_size', cfg, 'host 1 keeps the factory segment size')

    def restore_lines(self, stdin, **store):
        def module(**kwargs):
            m = fake_module(**kwargs)
            make = m.MooncakeDistributedStore

            def preloaded():
                s = make()
                self.preload(s)
                return s
            m.MooncakeDistributedStore = preloaded
            return m
        out = io.StringIO()
        argv = ['host2-restore', '--manifest', str(self.manifest), '--local-hostname', '10.0.0.2',
                '--master', '10.0.0.1:50051', '--object-bytes', str(MIB), '--pool-bytes',
                str(16 * MIB), '--test-host-destination']
        old = sys.stdin
        sys.stdin = io.StringIO(stdin)
        try:
            with contextlib.redirect_stdout(out):
                rc = mw.main(argv, store_module=module(**store))
        finally:
            sys.stdin = old
        return rc, [kp.parse_line(l) for l in out.getvalue().splitlines()]

    def test_host2_restores_into_its_buffer(self):
        size = 64 * 163840
        rc, lines = self.restore_lines(kp.go_line('m1', 1, 0, size, 2, 5, True) + 'QUIT\n')
        self.assertEqual(rc, 0)
        self.assertEqual([k for k, _ in lines], ['KV_READY', 'KV_RESULT', 'KV_BYE'])
        ready, result = lines[0][1], lines[1][1]
        self.assertEqual(ready['config']['global_segment_size'], 0, 'host 2 adds no DRAM')
        kp.check_result(result, 'm1')
        self.assertTrue(result['ok'] and result['verified'], result)
        self.assertEqual(result['objects'], 10)
        self.assertTrue(result['residency_before']['ok'])
        store = FakeStore.instances[-1]
        self.assertIn(('batch_get_into', 10), store.calls, 'one batch call for the prefix')
        self.assertEqual(store.registered, {}, 'buffer unregistered at QUIT')

    def test_promotion_makes_the_next_run_refused(self):
        size = 64 * 163840
        rc, lines = self.restore_lines(kp.go_line('p1', 1, 0, size, 0, 5) +
                                       kp.go_line('p2', 2, 0, size, 0, 5) + 'QUIT\n', promote=True)
        first, second = lines[1][1], lines[2][1]
        self.assertTrue(first['ok'])
        self.assertFalse(first['residency_after']['ok'], 'promotion is recorded')
        self.assertFalse(second['ok'])
        self.assertEqual(second['error'], -5)
        self.assertFalse(second['started'], 'refused before any transfer')

    def test_clock_stops_after_the_device_synchronized(self):
        events = []

        class Gpu:
            ptr = 1 << 20

            def sync(self):
                events.append('sync')

            def read(self, offset, size):
                return b''

        class Store(FakeStore):
            def batch_get_into(self, keys, ptrs, sizes):
                events.append('get')
                return list(sizes)
        store = Store()
        self.preload(store)
        args = types.SimpleNamespace(frame_bytes=131072, pool_bytes=16 * MIB, namespace='kv',
                                     object_bytes=MIB)
        obj = kl.load_manifest(self.manifest).objects[0]
        clock = mw.time.monotonic_ns
        mw.time.monotonic_ns = lambda: events.append('clock') or clock()
        try:
            r = mw.restore(store, Gpu(), {0: obj}, dict(run='s', ordinal=1, object_slba=0,
                                                         bytes=obj.bytes, dst_frame0=0, seed=5,
                                                         verify=False), args)
        finally:
            mw.time.monotonic_ns = clock
        self.assertTrue(r['ok'])
        self.assertEqual(events, ['clock', 'get', 'sync', 'clock'])

    def test_refusals_and_corruption(self):
        size = 64 * 163840
        rc, lines = self.restore_lines(kp.go_line('u', 1, 512, size, 0) +
                                       kp.go_line('o', 2, 0, size, 100, 5) + 'QUIT\n')
        self.assertEqual(lines[1][1]['error'], -22, 'no object at that LBA')
        self.assertEqual(lines[2][1]['error'], -28, 'destination beyond the buffer')
        rc, lines = self.restore_lines(kp.go_line('c', 1, 0, size, 0, 5, True) + 'QUIT\n',
                                       corrupt=True)
        self.assertFalse(lines[1][1]['ok'])
        self.assertIs(lines[1][1]['verified'], False)


if __name__ == '__main__':
    unittest.main()
