#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Prefix index: prefix hash -> (object, offset, length, tokens).

The hash chains SHA-256 over whole vLLM blocks of token ids, so the hashes of
a P-token prefix are the first P / block_size hashes of any longer prompt
that starts with it, and the connector finds the longest stored prefix of a
prompt by hashing it once. The index file is line-based text so the C worker
reads the same file (kv_index.h); test_plan_crosscheck.py compares the two
parsers. No device, no timing.
"""
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_layout', HERE / 'kv_layout.py')
kl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kl)

KIB, MIB, GIB = 1 << 10, 1 << 20, 1 << 30
LAYOUT = kl.BlockLayout(16, 36, 8, 512)


def spec_hashes(model, layout, tokens):
    """The chain as kv_layout.prefix_hashes documents it, written out independently."""
    h = hashlib.sha256(b'xdev-kv-prefix\x001\x00' + model.encode() + b'\x00' +
                       struct.pack('<4I', layout.block_size, layout.layers, layout.heads,
                                   layout.state_bytes)).digest()
    out = []
    for i in range(len(tokens) // layout.block_size):
        block = tokens[i * layout.block_size:(i + 1) * layout.block_size]
        h = hashlib.sha256(h + struct.pack(f'<{layout.block_size}I', *block)).digest()
        out.append(((i + 1) * layout.block_size, h.hex()))
    return out


def manifest():
    kv = dict(order='block-layer', block_size=16, layers=36, heads=8, state_bytes=512)
    return kl.parse_manifest({
        'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
        'window': {'slba': 2048, 'nlb': 40 * GIB // 512},
        'objects': [
            {'name': 'conv-a', 'model': 'qwen3-8b-bf16', 'tokens': 8192, 'seed': 0,
             'slba': 2048, 'nlb': 8192 * 147456 // 512, 'kv': kv},
            {'name': 'conv-b', 'model': 'qwen3-8b-bf16', 'tokens': 4096, 'seed': 0,
             'slba': 2048 + 2 * GIB // 512, 'nlb': 4096 * 147456 // 512, 'kv': kv},
        ]})


class Hashes(unittest.TestCase):
    def test_chain_matches_the_definition(self):
        tokens = list(range(1000, 1000 + 50))
        got = kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, tokens)
        self.assertEqual(got, spec_hashes('qwen3-8b-bf16', LAYOUT, tokens))
        self.assertEqual([t for t, _ in got], [16, 32, 48], 'a partial block has no hash')

    def test_prefix_property_and_domain(self):
        long = list(range(64))
        short = long[:32]
        self.assertEqual(kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, long)[:2],
                         kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, short))
        a = kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, short)
        self.assertNotEqual(a, kl.prefix_hashes('qwen3-14b', kl.BlockLayout(16, 40, 8, 512), short))
        self.assertNotEqual(a[1], kl.prefix_hashes('qwen3-8b-bf16', kl.BlockLayout(32, 36, 8, 512),
                                                   long)[0])
        other = list(short)
        other[17] += 1
        b = kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, other)
        self.assertEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])

    def test_token_ids_must_be_u32(self):
        for bad in ([-1] * 16, [1 << 32] * 16, [1.0] * 16, [True] * 16):
            with self.subTest(bad=bad[0]), self.assertRaises(kl.LayoutError):
                kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, bad)


class Index(unittest.TestCase):
    def setUp(self):
        self.m = manifest()
        self.tok_a = [7] * 16 + list(range(8192 - 16))
        self.tok_b = list(range(5, 5 + 4096))
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-index-')

    def tearDown(self):
        self.tmp.cleanup()

    def entries(self):
        ha = dict(kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, self.tok_a))
        hb = dict(kl.prefix_hashes('qwen3-8b-bf16', LAYOUT, self.tok_b))
        return [kl.IndexEntry(ha[4096], 'conv-a', 2048, 0, 4096 * 147456, 4096, 0x1234),
                kl.IndexEntry(ha[8192], 'conv-a', 2048, 0, 8192 * 147456, 8192, None),
                kl.IndexEntry(hb[4096], 'conv-b', 2048 + 2 * GIB // 512, 0, 4096 * 147456, 4096,
                              None)]

    def test_round_trip_and_text_form(self):
        path = Path(self.tmp.name) / 'kv.index'
        kl.write_index(path, self.entries())
        text = path.read_text().splitlines()
        self.assertEqual(text[0], 'xdev-kv-index 1')
        e = self.entries()[0]
        self.assertEqual(text[1], f'prefix {e.hash} object=conv-a slba=2048 offset=0 '
                                  f'bytes={4096 * 147456} tokens=4096 fnv1a=0x0000000000001234')
        self.assertNotIn('fnv1a', text[2])
        idx = kl.load_index(path, self.m)
        self.assertEqual(list(idx.entries), self.entries())

    def test_longest_match(self):
        idx = kl.PrefixIndex(self.entries(), self.m)
        hit = idx.longest_match('qwen3-8b-bf16', LAYOUT, self.tok_a + [1, 2, 3])
        self.assertEqual((hit.object, hit.tokens), ('conv-a', 8192))
        hit = idx.longest_match('qwen3-8b-bf16', LAYOUT, self.tok_a[:6000])
        self.assertEqual((hit.object, hit.tokens), ('conv-a', 4096))
        hit = idx.longest_match('qwen3-8b-bf16', LAYOUT, self.tok_a, max_tokens=8191)
        self.assertEqual(hit.tokens, 4096, 'at most max_tokens')
        self.assertIsNone(idx.longest_match('qwen3-8b-bf16', LAYOUT, self.tok_a[:4095]))
        self.assertIsNone(idx.longest_match('qwen3-14b', kl.BlockLayout(16, 40, 8, 512),
                                            self.tok_a))
        self.assertEqual(idx.get(self.entries()[2].hash).object, 'conv-b')
        self.assertIsNone(idx.get('00' * 32))

    def test_entries_checked_against_the_manifest(self):
        good = self.entries()[0]
        bad = {
            'unknown object': good._replace(object='nope'),
            'object moved': good._replace(slba=4096),
            'past the object': good._replace(bytes=9008 * 147456, tokens=9008),
            'tokens disagree with bytes': good._replace(tokens=4080),
            'partial block': good._replace(bytes=4100 * 147456, tokens=4100),
            'offset not on a block': good._replace(offset=512),
            'bad hash': good._replace(hash='xyz'),
            'zero tokens': good._replace(bytes=0, tokens=0),
        }
        for name, e in bad.items():
            with self.subTest(name), self.assertRaises(kl.LayoutError):
                kl.PrefixIndex([e], self.m)
        with self.assertRaises(kl.LayoutError):
            kl.PrefixIndex([good, good._replace(object='conv-b', slba=2048 + 2 * GIB // 512)],
                           self.m)

    def test_file_refusals(self):
        path = Path(self.tmp.name) / 'kv.index'
        line = (f'prefix {"ab" * 32} object=conv-a slba=2048 offset=0 '
                f'bytes={4096 * 147456} tokens=4096')
        for name, text in {
            'no header': line + '\n',
            'wrong version': 'xdev-kv-index 2\n' + line + '\n',
            'unknown key': 'xdev-kv-index 1\n' + line + ' color=red\n',
            'missing key': 'xdev-kv-index 1\n' + line.replace(' offset=0', '') + '\n',
            'not a number': 'xdev-kv-index 1\n' + line.replace('slba=2048', 'slba=x') + '\n',
            'unknown record': 'xdev-kv-index 1\nsuffix ' + line[7:] + '\n',
            'repeated key': 'xdev-kv-index 1\n' + line + ' tokens=4096\n',
        }.items():
            path.write_text(text)
            with self.subTest(name), self.assertRaises(kl.LayoutError):
                kl.load_index(path, self.m)
        path.write_text('xdev-kv-index 1\n# comment\n\n' + line + '\n')
        self.assertEqual(len(kl.load_index(path, self.m).entries), 1)

    def test_resolve_gives_the_restore_request(self):
        e = self.entries()[1]
        self.assertEqual(kl.resolve(e, self.m.lba_bytes), (2048, 8192 * 147456))
        shifted = kl.IndexEntry(e.hash, 'conv-a', 2048, LAYOUT.block_bytes, 4096 * 147456, 4096,
                                None)
        self.assertEqual(kl.resolve(shifted, self.m.lba_bytes),
                         (2048 + LAYOUT.block_bytes // 512, 4096 * 147456))


if __name__ == '__main__':
    unittest.main()
