#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The driver's C plan (kv_plan.h) and kv_layout.py agree on every case.

Two independent implementations of the same restore arithmetic and payload
pattern: a case grid must give the same accepted plans field by field and
the same refusals, and the C pattern must hash like the Python one. Run in
the source view (the C side includes ../../../kernel UAPI headers).
"""
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_layout', HERE / 'kv_layout.py')
kl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kl)
CC = shutil.which(os.environ.get('CC', 'cc'))
UAPI = HERE.parents[2] / 'kernel/include/uapi/linux/xdev_ext_mech.h'
KIB, GIB = 1 << 10, 1 << 30
FIELDS = ('groups', 'slots', 'slot0', 'first_seq', 'frames_per_group', 'host1_pool_frames',
          'host1_recycle_frames', 'host2_dst_frame0', 'host2_frames', 'host2_pool_frames',
          'host2_ring', 'host2_start_frames')


def fnv1a(data):
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & ((1 << 64) - 1)
    return h


@unittest.skipUnless(CC and UAPI.is_file(), 'needs a C compiler and the source view')
class CrossCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='kv-plan-')
        cls.cli = Path(cls.tmp.name) / 'kv_plan_cli'
        subprocess.run([CC, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(HERE / 'kv_plan_cli.c'), '-o', str(cls.cli)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def c_plan(self, m, obj, prefix, g, ordinal, dst0, pool, ring=False):
        args = [str(self.cli), 'plan', '--window-slba', m.window_slba, '--window-nlb',
                m.window_nlb, '--lba-bytes', m.lba_bytes, '--object-slba', obj.slba,
                '--bytes', kl.kv_bytes(obj.model, prefix), '--group-bytes', g.group_bytes,
                '--frame-bytes', g.frame_bytes, '--depth', g.depth, '--window', g.window,
                '--ordinal', ordinal, '--dst-frame0', dst0]
        if pool is not None:
            args += ['--pool-frames', pool]
        if g.early:
            args.append('--early')
        if ring:
            args.append('--host2-ring')
        r = subprocess.run([str(a) for a in args], capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 1), r.stderr)
        return r.returncode, json.loads(r.stdout)

    def test_plans_agree(self):
        manifests = [
            kl.parse_manifest({'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
                               'window': {'slba': 2048, 'nlb': 40 * GIB // 512},
                               'objects': [
                                   {'name': 'a', 'model': 'qwen3-14b', 'tokens': 32768, 'seed': 1,
                                    'slba': 2048, 'nlb': 5 * GIB // 512},
                                   {'name': 'b', 'model': 'qwen3-8b-bf16', 'tokens': 32768,
                                    'seed': 2, 'slba': 2048 + 6 * GIB // 512,
                                    'nlb': 9 * GIB // 2 // 512}]}),
            kl.parse_manifest({'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 4096,
                               'window': {'slba': 0, 'nlb': 16 * GIB // 4096},
                               'objects': [
                                   {'name': 'a', 'model': 'qwen3-8b-bf16', 'tokens': 32768,
                                    'seed': 3, 'slba': 5 * GIB // 4096 + 64,
                                    'nlb': 9 * GIB // 2 // 4096},
                                   {'name': 'b', 'model': 'qwen3-14b', 'tokens': 16384, 'seed': 4,
                                    'slba': 10 * GIB // 4096 + 1, 'nlb': 5 * GIB // 2 // 4096}]}),
        ]
        geometries = [kl.Geometry(256 * KIB, 128 * KIB, 32, 32, True),
                      kl.Geometry(256 * KIB, 256 * KIB, 64, 32, False),
                      kl.Geometry(128 * KIB, 128 * KIB, 16, 8, True),
                      kl.Geometry(64 * KIB, 64 * KIB, 8, 8, False),
                      kl.Geometry(256 * KIB, 64 * KIB, 4, 4, True),
                      kl.Geometry(512 * KIB, 128 * KIB, 4, 4, True),
                      kl.Geometry(128 * KIB, 4 * KIB, 32, 32, True)]
        accepted = refused = ring_only = 0
        for m, g, name, prefix, ordinal, dst0, pool, ring in itertools.product(
                manifests, geometries, ('a', 'b'), (8, 4096, 16384, 32768), (1, 5), (0, 7),
                (None, 30000, 2000000), (False, True)):
            obj = m.object(name)
            if prefix > obj.tokens:
                continue
            with self.subTest(lba=m.lba_bytes, g=g, obj=name, prefix=prefix, ordinal=ordinal,
                              dst0=dst0, pool=pool, ring=ring):
                try:
                    p = kl.plan_restore(m, name, prefix, g, ordinal, dst0, pool,
                                        host2_ring=ring).to_json()
                except kl.LayoutError:
                    p = None
                rc, c = self.c_plan(m, obj, prefix, g, ordinal, dst0, pool, ring)
                if p is None:
                    self.assertEqual(rc, 1, f'Python refused, C accepted {c}')
                    refused += 1
                    continue
                self.assertEqual(rc, 0, f'Python accepted, C refused {c}')
                for f in FIELDS:
                    self.assertEqual(c[f], p[f], f)
                self.assertEqual(c['first_group_slba'], obj.slba)
                self.assertEqual(c['last_group_slba'],
                                 obj.slba + (p['groups'] - 1) * g.group_bytes // m.lba_bytes)
                self.assertEqual(c['xdomain_arg1'], g.window << 32)
                self.assertEqual(p['host2_start_frames'],
                                 min(p['groups'], g.depth) * p['frames_per_group'] if ring
                                 else p['host2_frames'])
                if ring and p['host2_frames'] > kl.LIB_MAX_START_FRAMES:
                    ring_only += 1
                accepted += 1
        self.assertGreater(accepted, 100)
        self.assertGreater(refused, 20)
        self.assertGreater(ring_only, 10)

    def test_pattern_agrees(self):
        for seed, offset, length in ((7, 0, 4096), (7, 4096, 4096), (9, 100, 9000),
                                     ((1 << 64) - 1, 3 * 4096 - 5, 10), (0, 1 << 30, 4096)):
            with self.subTest(seed=seed, offset=offset):
                r = subprocess.run([str(self.cli), 'pattern', str(seed), str(offset), str(length)],
                                   capture_output=True, text=True, check=True)
                want = fnv1a(kl.pattern_bytes(seed, offset, length))
                self.assertEqual(int(json.loads(r.stdout)['fnv1a'], 16), want)

    def test_block_pages_agree(self):
        layouts = [kl.BlockLayout(16, 36, 8, 512), kl.BlockLayout(64, 36, 8, 512),
                   kl.BlockLayout(16, 40, 8, 512), kl.BlockLayout(16, 36, 5, 512),
                   kl.BlockLayout(16, 3, 1, 512), kl.BlockLayout(32, 2, 2, 1024)]
        for b, group in itertools.product(layouts, (64 * KIB, 128 * KIB, 256 * KIB)):
            try:
                b.validate(group)
                ok = True
            except kl.LayoutError:
                ok = False
            for gi in (0, 1, 17, 18, 37):
                with self.subTest(b=b, group=group, gi=gi):
                    r = subprocess.run([str(self.cli), 'pages', str(b.block_size), str(b.layers),
                                        str(b.heads), str(b.state_bytes), str(group), str(gi)],
                                       capture_output=True, text=True)
                    self.assertEqual(r.returncode, 0 if ok else 1, r.stdout + r.stderr)
                    if ok:
                        got = [tuple(x) for x in json.loads(r.stdout)['pieces']]
                        self.assertEqual(got, b.group_pages(gi, group))

    def test_index_parsers_agree(self):
        good = [kl.IndexEntry('ab' * 32, 'conv-a', 2048, 0, 4096 * 147456, 4096, 0x1234),
                kl.IndexEntry('cd' * 32, 'conv-b', 7, 2359296, 147456 * 16, 16, None)]
        cases = {
            'good': (good, True),
            'typed BF16': ('xdev-kv-index 2 dtype=bfloat16\n' + good[0].line() + '\n', True),
            'typed FP16': ('xdev-kv-index 2 dtype=float16\n' + good[0].line() + '\n', True),
            'unknown dtype': ('xdev-kv-index 2 dtype=mystery\n' + good[0].line() + '\n', False),
            'untyped v2': ('xdev-kv-index 2\n' + good[0].line() + '\n', False),
            'leading zeros and hex': ('xdev-kv-index 1\nprefix ' + 'ef' * 32 +
                                      ' object=x slba=007 offset=0x10 bytes=1 tokens=1\n', True),
            'repeat': (good + good[:1], False),
            'bad number': ('xdev-kv-index 1\nprefix ' + 'ef' * 32 +
                           ' object=x slba=1e3 offset=0 bytes=1 tokens=1\n', False),
            'missing tokens': ('xdev-kv-index 1\nprefix ' + 'ef' * 32 +
                               ' object=x slba=1 offset=0 bytes=1\n', False),
            'no header': ('prefix ' + 'ef' * 32 + ' object=x slba=1 offset=0 bytes=1 tokens=1\n',
                          False),
        }
        for name, (content, ok) in cases.items():
            with self.subTest(name):
                path = Path(self.tmp.name) / 'kv.index'
                if isinstance(content, str):
                    path.write_text(content)
                else:
                    path.write_text('\n'.join([kl.INDEX_HEADER] + [e.line() for e in content])
                                    + '\n')
                try:
                    py = kl.parse_index_text(path.read_text())
                except kl.LayoutError:
                    py = None
                self.assertEqual(py is not None, ok, name)
                r = subprocess.run([str(self.cli), 'index', str(path)], capture_output=True,
                                   text=True)
                self.assertEqual(r.returncode, 0 if ok else 1, r.stdout + r.stderr)
                if ok:
                    c = [kl.IndexEntry(e['hash'], e['object'], e['slba'], e['offset'], e['bytes'],
                                       e['tokens'], int(e['fnv1a'], 16) if e['fnv1a'] else None)
                         for e in json.loads(r.stdout)['entries']]
                    self.assertEqual(c, py)
    def test_prefix_digest_tool_agrees(self):
        spec = importlib.util.spec_from_file_location('kv_dump', HERE / 'kv_dump.py')
        kd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(kd)
        path = Path(self.tmp.name) / 'obj'
        data = bytes((i * 31 + 7) & 255 for i in range(300000))
        path.write_bytes(data)
        lengths = [1, 4096, 131072, 299999, 300000]
        self.assertEqual(kd.prefix_fnv1a(path, lengths, self.cli), kd.prefix_fnv1a(path, lengths))
        r = subprocess.run([str(self.cli), 'fnv', str(path), '300001'], capture_output=True,
                           text=True)
        self.assertEqual(r.returncode, 1, 'past the end of the file')


if __name__ == '__main__':
    unittest.main()
