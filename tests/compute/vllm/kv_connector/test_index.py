#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Prefix index the connector's scheduler side reads: prefix hash -> stored KV extent.

The format is the K-KV benchmark's (kv_layout.py prefix_hashes / write_index):
SHA-256 chained over whole blocks of u32 token ids after a domain block that
names the model key and the staging layout, so a layout or model mismatch can
never hit; a text file "xdev-kv-index 1" with one "prefix HASH object=NAME
slba=N offset=N bytes=N tokens=N [fnv1a=0x...]" line per stored prefix.
"""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

import _paths
from xdev_kv_vllm import index as ki
from xdev_kv_vllm.layout import StagingLayout

Q8 = StagingLayout(16, 36, 8, 256, 2)
BPT = Q8.bytes_per_token


def spec_hashes(model, s, tokens):
    h = hashlib.sha256(b'xdev-kv-prefix\x001\x00' + model.encode() + b'\x00' +
                       struct.pack('<4I', s.block_size, s.layers, s.heads, s.state_bytes)).digest()
    out = []
    for i in range(len(tokens) // s.block_size):
        block = tokens[i * s.block_size:(i + 1) * s.block_size]
        h = hashlib.sha256(h + struct.pack(f'<{s.block_size}I', *block)).digest()
        out.append(((i + 1) * s.block_size, h.hex()))
    return out


class Hashes(unittest.TestCase):
    def test_chain(self):
        tokens = list(range(1000, 1050))
        self.assertEqual(ki.prefix_hashes('qwen3-8b-bf16', Q8, tokens),
                         spec_hashes('qwen3-8b-bf16', Q8, tokens))
        self.assertEqual([t for t, _ in ki.prefix_hashes('qwen3-8b-bf16', Q8, tokens)], [16, 32, 48])

    def test_domain_and_prefix(self):
        long = list(range(64))
        a = ki.prefix_hashes('qwen3-8b-bf16', Q8, long[:32])
        self.assertEqual(ki.prefix_hashes('qwen3-8b-bf16', Q8, long)[:2], a)
        self.assertNotEqual(a, ki.prefix_hashes('qwen3-14b', Q8, long[:32]))
        self.assertNotEqual(a, ki.prefix_hashes('qwen3-8b-bf16', StagingLayout(16, 36, 8, 256, 4),
                                                long[:32]))
        self.assertNotEqual(a[1], ki.prefix_hashes('qwen3-8b-bf16', StagingLayout(32, 36, 8, 256, 2),
                                                   long)[0])

    def test_token_ids_are_u32(self):
        for bad in ([-1] * 16, [1 << 32] * 16, [1.0] * 16, [True] * 16):
            with self.subTest(bad=bad[0]), self.assertRaises(ki.PrefixIndexError):
                ki.prefix_hashes('m', Q8, bad)

    def test_limit(self):
        tokens = list(range(100))
        self.assertEqual(len(ki.prefix_hashes('m', Q8, tokens, max_tokens=47)), 2)


class File(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kvconn-index-')
        self.path = Path(self.tmp.name) / 'kv.index'
        self.tok_a = [7] * 16 + list(range(8192 - 16))
        self.tok_b = list(range(5, 5 + 4096))
        ha = dict(ki.prefix_hashes('qwen3-8b-bf16', Q8, self.tok_a))
        hb = dict(ki.prefix_hashes('qwen3-8b-bf16', Q8, self.tok_b))
        self.lines = [
            f'prefix {ha[4096]} object=conv-a slba=2048 offset=0 bytes={4096 * BPT} tokens=4096 '
            'fnv1a=0x0000000000001234',
            f'prefix {ha[8192]} object=conv-a slba=2048 offset=0 bytes={8192 * BPT} tokens=8192',
            f'prefix {hb[4096]} object=conv-b slba=4196352 offset=0 bytes={4096 * BPT} tokens=4096',
        ]

    def tearDown(self):
        self.tmp.cleanup()

    def load(self, text):
        self.path.write_text(text)
        return ki.PrefixIndex.load(self.path, 'qwen3-8b-bf16', Q8, lba_bytes=512)

    def test_longest_match(self):
        idx = self.load('xdev-kv-index 1\n# stored prefixes\n\n' + '\n'.join(self.lines) + '\n')
        self.assertEqual(len(idx), 3)
        hit = idx.longest_match(self.tok_a + [1, 2, 3])
        self.assertEqual((hit.object, hit.tokens, hit.fnv1a), ('conv-a', 8192, None))
        hit = idx.longest_match(self.tok_a[:6000])
        self.assertEqual((hit.object, hit.tokens, hit.fnv1a), ('conv-a', 4096, 0x1234))
        self.assertEqual(idx.longest_match(self.tok_a, max_tokens=8191).tokens, 4096)
        self.assertIsNone(idx.longest_match(self.tok_a[:4095]))
        self.assertEqual(idx.longest_match(self.tok_b).object, 'conv-b')
        other = list(self.tok_a)
        other[100] += 1
        self.assertIsNone(idx.longest_match(other))

    def test_resolve(self):
        e = self.load('xdev-kv-index 1\n' + self.lines[1] + '\n').longest_match(self.tok_a)
        self.assertEqual(ki.resolve(e, 512), (2048, 8192 * BPT))
        shifted = e._replace(offset=Q8.block_bytes)
        self.assertEqual(ki.resolve(shifted, 512), (2048 + Q8.block_bytes // 512, 8192 * BPT))

    def test_refusals(self):
        line = self.lines[1]
        cases = {
            'no header': line + '\n',
            'wrong version': 'xdev-kv-index 2\n' + line + '\n',
            'unknown key': 'xdev-kv-index 1\n' + line + ' color=red\n',
            'missing key': 'xdev-kv-index 1\n' + line.replace(' offset=0', '') + '\n',
            'not a number': 'xdev-kv-index 1\n' + line.replace('slba=2048', 'slba=x') + '\n',
            'unknown record': 'xdev-kv-index 1\nsuffix ' + line[7:] + '\n',
            'repeated key': 'xdev-kv-index 1\n' + line + ' tokens=8192\n',
            'bad hash': 'xdev-kv-index 1\n' + line.replace(line.split()[1], 'xyz') + '\n',
            'duplicate hash': 'xdev-kv-index 1\n' + line + '\n' + line + '\n',
            'bytes disagree': 'xdev-kv-index 1\n' + line.replace(f'bytes={8192 * BPT}',
                                                                 f'bytes={8191 * BPT}') + '\n',
            'partial block': 'xdev-kv-index 1\n' + line.replace('tokens=8192', 'tokens=8200')
            .replace(f'bytes={8192 * BPT}', f'bytes={8200 * BPT}') + '\n',
            'offset off block': 'xdev-kv-index 1\n' + line.replace('offset=0', 'offset=512') + '\n',
            'zero tokens': 'xdev-kv-index 1\n' + line.replace('tokens=8192', 'tokens=0')
            .replace(f'bytes={8192 * BPT}', 'bytes=0') + '\n',
            'bad digest': 'xdev-kv-index 1\n' + line + ' fnv1a=12\n',
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(ki.PrefixIndexError):
                self.load(text)


@unittest.skipUnless(_paths.load_benchmark_module('kv_layout') is not None and
                     hasattr(_paths.load_benchmark_module('kv_layout'), 'prefix_hashes'),
                     'the K-KV benchmark has no prefix index yet')
class SameFormatAsTheBenchmark(unittest.TestCase):
    """The writer of the stored prefixes is the benchmark's kv_layout.py."""

    def test_hashes_and_file(self):
        kl = _paths.load_benchmark_module('kv_layout')
        bl = kl.BlockLayout(16, 36, 8, 512)
        tokens = list(range(9, 9 + 4096))
        theirs = kl.prefix_hashes('qwen3-8b-bf16', bl, tokens)
        self.assertEqual(ki.prefix_hashes('qwen3-8b-bf16', Q8, tokens), theirs)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'kv.index'
            h = dict(theirs)[4096]
            kl.write_index(path, [kl.IndexEntry(h, 'obj', 2048, 0, 4096 * BPT, 4096, 0xabc)])
            hit = ki.PrefixIndex.load(path, 'qwen3-8b-bf16', Q8, 512).longest_match(tokens + [1])
            self.assertEqual((hit.object, hit.slba, hit.tokens, hit.fnv1a), ('obj', 2048, 4096, 0xabc))


if __name__ == '__main__':
    unittest.main()
