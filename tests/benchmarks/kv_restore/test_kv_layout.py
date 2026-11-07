#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""KV layout, LBA mapping and restore plan of the K-KV experiment.

Expectations come from the experiment design (bytes per token, prefixes,
one contiguous KV object per extent) and from the kernel rules the plan
must satisfy (window, frames per batch, NHI elements, START frame lists);
nothing here opens a device or measures time.
"""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_layout', HERE / 'kv_layout.py')
kl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kl)

KIB, MIB, GIB = 1 << 10, 1 << 20, 1 << 30


def manifest(**over):
    m = {
        'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
        'window': {'slba': 2048, 'nlb': 40 * GIB // 512},
        'objects': [
            {'name': 'q14-a', 'model': 'qwen3-14b', 'tokens': 32768, 'seed': 7,
             'slba': 2048, 'nlb': 5 * GIB // 512},
            {'name': 'q8-a', 'model': 'qwen3-8b-bf16', 'tokens': 32768, 'seed': 9,
             'slba': 2048 + 6 * GIB // 512, 'nlb': 9 * GIB // 2 // 512},
        ],
    }
    m.update(over)
    return m


def geometry(**over):
    g = dict(group_bytes=256 * KIB, frame_bytes=128 * KIB, depth=32, window=32, early=True)
    g.update(over)
    return kl.Geometry(**g)


class Models(unittest.TestCase):
    def test_bytes_per_token_from_the_design(self):
        self.assertEqual(kl.MODELS['qwen3-14b'], 163840)
        self.assertEqual(kl.MODELS['qwen3-8b-bf16'], 147456)
        self.assertEqual(kl.PREFIX_TOKENS, (4096, 16384, 32768))

    def test_prefix_bytes_span_the_planned_range(self):
        self.assertEqual(kl.kv_bytes('qwen3-8b-bf16', 4096), 603979776)  # 0.5625 GiB
        self.assertEqual(kl.kv_bytes('qwen3-14b', 32768), 5 * GIB)
        self.assertEqual(kl.kv_bytes('qwen3-14b', 4096), 671088640)

    def test_unknown_model_or_bad_tokens_refused(self):
        with self.assertRaises(kl.LayoutError):
            kl.kv_bytes('qwen3-32b', 4096)
        for bad in (0, -1, True, 1.5):
            with self.assertRaises(kl.LayoutError):
                kl.kv_bytes('qwen3-14b', bad)


class Manifest(unittest.TestCase):
    def test_valid_manifest_parses(self):
        m = kl.parse_manifest(manifest())
        self.assertEqual(m.lba_bytes, 512)
        self.assertEqual([o.name for o in m.objects], ['q14-a', 'q8-a'])
        self.assertEqual(m.object('q8-a').bytes_per_token, 147456)

    def test_refusals(self):
        cases = {
            'lba not power of two': manifest(lba_bytes=520),
            'lba too small': manifest(lba_bytes=256),
            'unknown key': dict(manifest(), extra=1),
            'bool as int': manifest(lba_bytes=True),
            'duplicate names': manifest(objects=[manifest()['objects'][0]] * 2),
            'outside window': manifest(objects=[dict(manifest()['objects'][0], slba=1024)]),
            'past window end': manifest(window={'slba': 2048, 'nlb': 4 * GIB // 512}),
            'extent smaller than tokens': manifest(objects=[dict(manifest()['objects'][0],
                                                                 nlb=GIB // 512)]),
            'unknown model': manifest(objects=[dict(manifest()['objects'][0], model='x')]),
            'seed too large': manifest(objects=[dict(manifest()['objects'][0], seed=1 << 64)]),
            'overlapping objects': manifest(objects=[
                manifest()['objects'][0],
                dict(manifest()['objects'][1], slba=2048 + 4 * GIB // 512)]),
        }
        for why, value in cases.items():
            with self.subTest(why=why), self.assertRaises(kl.LayoutError):
                kl.parse_manifest(value)


class Plan(unittest.TestCase):
    def setUp(self):
        self.m = kl.parse_manifest(manifest())

    def test_every_key_reads_its_own_object_lba(self):
        g = geometry()
        for ordinal in (1, 2, 7):
            p = kl.plan_restore(self.m, 'q8-a', 16384, g, ordinal=ordinal)
            obj = self.m.object('q8-a')
            blocks = g.group_bytes // 512
            self.assertEqual(p.groups, 16384 * 147456 // g.group_bytes)
            self.assertEqual(p.slots, self.m.window_nlb // blocks)
            self.assertEqual(p.slot0, (obj.slba - self.m.window_slba) // blocks)
            self.assertEqual(p.first_seq, ordinal * p.slots + p.slot0)
            for i in (0, 1, p.groups // 2, p.groups - 1):
                key = p.first_seq + i
                # The NVMe program reads slot (key mod slots) of the window.
                slot = key % p.slots
                self.assertEqual(self.m.window_slba + slot * blocks, obj.slba + i * blocks)
                self.assertEqual(p.group_slba(i), obj.slba + i * blocks)

    def test_ordinals_give_disjoint_increasing_keys(self):
        g = geometry()
        a = kl.plan_restore(self.m, 'q14-a', 32768, g, ordinal=1)
        b = kl.plan_restore(self.m, 'q14-a', 4096, g, ordinal=2)
        self.assertLess(a.first_seq + a.groups - 1, b.first_seq)

    def test_host2_destination_is_contiguous_frames(self):
        g = geometry()
        p = kl.plan_restore(self.m, 'q14-a', 4096, g, ordinal=1, dst_frame0=3)
        fpg = g.group_bytes // g.frame_bytes
        self.assertEqual(p.frames_per_group, fpg)
        self.assertEqual(p.host2_indices, list(range(3, 3 + p.groups * fpg)))
        self.assertEqual(p.host2_pool_frames, 3 + p.groups * fpg)
        with self.assertRaises(kl.LayoutError):
            kl.plan_restore(self.m, 'q14-a', 4096, g, ordinal=1, dst_frame0=3,
                            pool_frames=p.groups * fpg)

    def test_host1_staging_ring(self):
        g = geometry(depth=8, window=4)
        p = kl.plan_restore(self.m, 'q14-a', 4096, g, ordinal=1)
        self.assertEqual(p.host1_pool_frames, 8 * 2)
        self.assertEqual(p.host1_indices, list(range(16)))
        # Eight tokens of Qwen3-14B are five 256 KiB groups: fewer groups than depth.
        small = kl.plan_restore(self.m, 'q14-a', 8, geometry(depth=64, window=32), ordinal=1)
        self.assertEqual(small.groups, 5)
        self.assertEqual(small.host1_indices, list(range(5 * 2)))

    def test_32k_tokens_need_frames_of_128k(self):
        # The library lends at most 65536 frame indices per START.
        with self.assertRaises(kl.LayoutError):
            kl.plan_restore(self.m, 'q14-a', 32768, geometry(frame_bytes=64 * KIB), ordinal=1)
        p = kl.plan_restore(self.m, 'q14-a', 32768, geometry(), ordinal=1)
        self.assertEqual(len(p.host2_indices), 5 * GIB // (128 * KIB))

    def test_geometry_refusals(self):
        bad = {
            'group not a multiple of frame': dict(group_bytes=192 * KIB),
            'frame not power of two': dict(frame_bytes=96 * KIB, group_bytes=192 * KIB),
            'frame below 4 KiB': dict(frame_bytes=2 * KIB, group_bytes=8 * KIB),
            'frame above 2 MiB': dict(frame_bytes=4 * MIB, group_bytes=4 * MIB),
            'more than 64 NHI elements': dict(group_bytes=512 * KIB),
            'more than 32 frames per batch': dict(frame_bytes=4 * KIB, group_bytes=132 * KIB),
            'window above 32': dict(window=33, depth=64),
            'window above depth': dict(window=16, depth=8),
            'window zero': dict(window=0),
            'depth above 64': dict(depth=65),
            'early not bool': dict(early=1),
        }
        for why, over in bad.items():
            with self.subTest(why=why), self.assertRaises(kl.LayoutError):
                kl.plan_restore(self.m, 'q14-a', 4096, geometry(**over), ordinal=1)

    def test_request_refusals(self):
        g = geometry()
        for why, kwargs in {
            'prefix beyond object': dict(name='q14-a', tokens=65536),
            'unknown object': dict(name='nope', tokens=4096),
            'ordinal zero': dict(name='q14-a', tokens=4096, ordinal=0),
            'prefix not whole groups': dict(name='q14-a', tokens=4095),
        }.items():
            with self.subTest(why=why), self.assertRaises(kl.LayoutError):
                kl.plan_restore(self.m, kwargs['name'], kwargs['tokens'], g,
                                ordinal=kwargs.get('ordinal', 1))

    def test_object_must_start_on_a_group_slot(self):
        m = kl.parse_manifest(manifest(objects=[dict(manifest()['objects'][0], slba=2049)]))
        with self.assertRaises(kl.LayoutError):
            kl.plan_restore(m, 'q14-a', 4096, geometry(), ordinal=1)

    def test_plan_json_has_the_driver_parameters(self):
        p = kl.plan_restore(self.m, 'q14-a', 4096, geometry(), ordinal=3, dst_frame0=1)
        j = json.loads(json.dumps(p.to_json()))
        for key in ('object', 'model', 'prefix_tokens', 'bytes', 'groups', 'group_bytes',
                    'frame_bytes', 'frames_per_group', 'lba_bytes', 'window_slba', 'window_nlb',
                    'slots', 'slot0', 'first_seq', 'ordinal', 'depth', 'window', 'early',
                    'host1_pool_frames', 'host1_recycle_frames', 'host2_dst_frame0',
                    'host2_frames', 'host2_pool_frames', 'object_slba', 'seed'):
            self.assertIn(key, j)
        self.assertEqual(j['host2_frames'], p.groups * p.frames_per_group)


class Pattern(unittest.TestCase):
    def test_splitmix64_reference_value(self):
        # First output of the reference SplitMix64 generator with state 0.
        self.assertEqual(kl.mix64(0), 0xE220A8397B1DCDAF)

    def test_blocks_are_deterministic_and_distinct(self):
        a = kl.pattern_block(7, 0)
        self.assertEqual(len(a), 4096)
        self.assertEqual(a, kl.pattern_block(7, 0))
        seen = {kl.pattern_block(7, b) for b in range(2048)}
        self.assertEqual(len(seen), 2048)
        self.assertNotEqual(kl.pattern_block(8, 0), a)
        # Within one block the 64-bit words are not one repeated value.
        words = {a[i:i + 8] for i in range(0, 4096, 8)}
        self.assertGreater(len(words), 500)

    def test_byte_ranges_cross_block_boundaries(self):
        whole = b''.join(kl.pattern_block(3, b) for b in range(4))
        self.assertEqual(kl.pattern_bytes(3, 0, 16384), whole)
        self.assertEqual(kl.pattern_bytes(3, 4000, 200), whole[4000:4200])
        self.assertEqual(kl.pattern_bytes(3, 8192, 1), whole[8192:8193])
        with self.assertRaises(kl.LayoutError):
            kl.pattern_bytes(3, -1, 4)


if __name__ == '__main__':
    unittest.main()
