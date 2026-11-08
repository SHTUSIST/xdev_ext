#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The staging -> paged scatter as torch and Triton run it, checked against layout.py.

Needs torch (CPU is enough for the reference); the Triton kernel runs on a CUDA
device, or on the CPU under TRITON_INTERPRET=1. vLLM's per-layer caches are
built the way vLLM 0.33.0 builds them: one strided 5-D view [L, B, H, N, C] of
a flat buffer per KVCacheLayout permutation (create_kv_cache_views), one layer
at a time.
"""
import itertools
import os
import unittest

import _paths  # noqa: F401
from xdev_kv_vllm import layout as kl
from xdev_kv_vllm.core import LoadSpec

try:
    import torch
except ImportError:
    torch = None
try:
    import triton  # noqa: F401
except ImportError:
    triton = None

LAYOUTS = {'LBNHC': (0, 1, 3, 2, 4), 'LBHNC': (0, 1, 2, 3, 4), 'BLNHC': (1, 0, 3, 2, 4),
           'BHLNC': (1, 2, 0, 3, 4)}
CUDA = torch is not None and torch.cuda.is_available()
INTERPRET = os.environ.get('TRITON_INTERPRET') == '1'


def strides5(order, shape):
    strides, current = [0] * 5, 1
    for dim in reversed(order):
        strides[dim] = current
        current *= shape[dim]
    return strides, current


@unittest.skipIf(torch is None, 'needs torch')
class Case(unittest.TestCase):
    L, H, C, BLOCKS = 3, 2, 8, 12
    device = 'cpu'
    dtype = None

    def caches(self, order, block_size, kbs):
        ratio = block_size // kbs
        shape = (self.L, self.BLOCKS * ratio, self.H, kbs, self.C)
        st, size = strides5(order, shape)
        raw = torch.full((size,), -1, dtype=self.dtype or torch.float32, device=self.device)
        view = raw.as_strided(shape, st)
        return raw, [view[layer] for layer in range(self.L)]

    def staged(self, s, spec):
        n = kl.staged_elems(s, kl.ScatterRange(spec.first_token, spec.end_token, spec.stage_token))
        g = torch.Generator().manual_seed(spec.end_token)
        src = torch.randn(spec.staging_offset // 4 + n, generator=g)
        return src.to(self.dtype or torch.float32).to(self.device)

    def expect(self, s, spec, src, layer, token, head, e):
        return src[spec.staging_offset // 4 +
                   s.src_index(token - spec.stage_token, layer, head, e)].item()

    def run_scatter(self, fn, order, block_size, kbs, first, end, stage, block_ids):
        from xdev_kv_vllm import scatter as ks
        s = kl.StagingLayout(block_size, self.L, self.H, self.C, 4)
        raw, layers = self.caches(order, block_size, kbs)
        spec = LoadSpec('r', tuple(block_ids), first, end, stage, 0, 0, 64 * 4)
        src = self.staged(s, spec)
        blocks = torch.tensor(block_ids, dtype=torch.int32, device=self.device)
        for layer, view in enumerate(layers):
            target = ks.layer_target(view, s)
            fn(src[spec.staging_offset // 4:], view, blocks, spec, s, target, layer)
        written = int((raw != -1).sum())
        self.assertEqual(written, (end - first) * self.L * self.H * self.C)
        for layer, view in enumerate(layers):
            for token, head, e in itertools.product(range(first, end), range(self.H), range(self.C)):
                kb = block_ids[token // block_size] * (block_size // kbs) + (token % block_size) // kbs
                self.assertEqual(view[kb, head, token % kbs, e].item(),
                                 self.expect(s, spec, src, layer, token, head, e),
                                 (layer, token, head, e))

    def cases(self):
        return (('LBNHC', 4, 4, 0, 12, 0, [7, 1, 3]), ('LBHNC', 4, 4, 4, 16, 4, [9, 2, 0, 5]),
                ('BLNHC', 4, 2, 8, 16, 4, [2, 6, 0, 1]), ('BHLNC', 8, 4, 8, 24, 0, [3, 11, 4]))


class TorchReference(Case):
    def test_matches_the_layout_mapping(self):
        from xdev_kv_vllm import scatter as ks
        for name, bs, kbs, first, end, stage, blocks in self.cases():
            with self.subTest(layout=name, kbs=kbs):
                self.run_scatter(ks.scatter_layer_torch, LAYOUTS[name], bs, kbs, first, end, stage,
                                 blocks)

    def test_layer_target_reads_vllm_strides(self):
        from xdev_kv_vllm import scatter as ks
        _, layers = self.caches(LAYOUTS['LBNHC'], 16, 8)
        s = kl.StagingLayout(16, self.L, self.H, self.C, 4)
        t = ks.layer_target(layers[1], s)
        self.assertEqual((t.block_size, t.kernel_block_size, t.heads, t.state_elems, t.ratio),
                         (16, 8, self.H, self.C, 2))
        self.assertEqual(t.strides, tuple(layers[1].stride()))
        for bad in (layers[1][:, :, :, :4], layers[1][:, :1], layers[1].reshape(-1)):
            with self.assertRaises(kl.LayoutError):
                ks.layer_target(bad, s)
        with self.assertRaises(kl.LayoutError):
            ks.layer_target(layers[1], kl.StagingLayout(12, self.L, self.H, self.C, 4))

    def test_gather_is_the_inverse(self):
        from xdev_kv_vllm import scatter as ks
        s = kl.StagingLayout(4, self.L, self.H, self.C, 4)
        _, layers = self.caches(LAYOUTS['LBNHC'], 4, 4)
        for view in layers:
            view.copy_(torch.randn(view.shape))
        spec = LoadSpec('r', (5, 0, 8), 0, 12, 0, 0, 0, 0)
        blocks = torch.tensor(spec.block_ids, dtype=torch.int32)
        staged = torch.zeros(kl.staged_elems(s, kl.ScatterRange(0, 12, 0)))
        for layer, view in enumerate(layers):
            ks.gather_layer_torch(staged, view, blocks, spec, s, ks.layer_target(view, s), layer)
        _, fresh = self.caches(LAYOUTS['LBNHC'], 4, 4)
        for layer, view in enumerate(fresh):
            ks.scatter_layer_torch(staged, view, blocks, spec, s, ks.layer_target(view, s), layer)
            for b in spec.block_ids:
                self.assertTrue(torch.equal(view[b], layers[layer][b]))


@unittest.skipUnless(torch is not None and triton is not None and (CUDA or INTERPRET),
                     'needs torch, triton and CUDA (or TRITON_INTERPRET=1)')
class TritonKernel(Case):
    device = 'cuda' if CUDA and not INTERPRET else 'cpu'

    def test_matches_the_layout_mapping(self):
        from xdev_kv_vllm import scatter as ks
        for dtype in (torch.float32, torch.bfloat16):
            self.dtype = dtype
            for name, bs, kbs, first, end, stage, blocks in self.cases():
                with self.subTest(layout=name, kbs=kbs, dtype=dtype):
                    self.run_scatter(ks.scatter_layer_triton, LAYOUTS[name], bs, kbs, first, end,
                                     stage, blocks)


if __name__ == '__main__':
    unittest.main()
