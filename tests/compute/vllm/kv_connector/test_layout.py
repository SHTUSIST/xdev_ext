#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Index mapping of the staging -> paged scatter, without a GPU or torch.

The restored prefix is staged in the K-KV object order "block-layer": block b
of the prefix (block_size tokens), then layer l, then the layer's [H, N, C]
page of that block (KV head, token in the block, content element; content is
K then V, head_size + head_size_v elements). vLLM 0.33.0 views each layer's
cache as [B, H, N, C] with strides set by one of six KVCacheLayout stride
permutations of [L, B, H, N, C] (vllm/v1/kv_cache_layout.py,
compute_layout_strides in vllm/v1/kv_cache_interface.py), and may split a
manager block into kernel blocks (group_kernel_blocks). Every staged cell of
a token in [first_token, end_token) must land at its own logical cell and no
other cell may be written.
"""
import itertools
import math
import unittest

import _paths  # noqa: F401
from xdev_kv_vllm import layout as kl

# vllm/v1/kv_cache_layout.py KVCacheLayout values (physical order of [L, B, H, N, C]).
VLLM_LAYOUTS = {
    'LBHNC': (0, 1, 2, 3, 4), 'LBNHC': (0, 1, 3, 2, 4), 'LHBNC': (0, 2, 1, 3, 4),
    'BLHNC': (1, 0, 2, 3, 4), 'BLNHC': (1, 0, 3, 2, 4), 'BHLNC': (1, 2, 0, 3, 4),
}


def layer_view_strides(order, shape5):
    """Element strides of one layer's [B, H, N, C] view (compute_layout_strides, no padding)."""
    strides, current = [0] * 5, 1
    for dim in reversed(order):
        strides[dim] = current
        current *= shape5[dim]
    return tuple(strides[1:]), current


def decode(position, order, shape5):
    """Logical [L, B, H, N, C] coordinates of a physical position (mixed radix, outermost first)."""
    coords = [0] * 5
    for dim in reversed(order):
        position, coords[dim] = divmod(position, shape5[dim])
    return coords


class Staging(unittest.TestCase):
    def test_block_layer_order(self):
        s = kl.StagingLayout(block_size=4, layers=3, heads=2, state_elems=5, elem_bytes=2)
        # The order written out by nested loops, outermost first.
        cells = [(blk * 4 + n, layer, head, e)
                 for blk in range(3) for layer in range(3) for head in range(2)
                 for n in range(4) for e in range(5)]
        for i, (t, layer, head, e) in enumerate(cells):
            self.assertEqual(s.src_index(t, layer, head, e), i, (t, layer, head, e))

    def test_model_sizes(self):
        # Qwen3-8B: 36 layers, 8 KV heads, head_dim 128, BF16; Qwen3-14B: 40 layers.
        q8 = kl.StagingLayout(16, 36, 8, 256, 2)
        self.assertEqual((q8.bytes_per_token, q8.page_bytes, q8.block_bytes),
                         (147456, 65536, 36 * 65536))
        self.assertEqual(kl.StagingLayout(16, 40, 8, 256, 2).bytes_per_token, 163840)

    def test_refuses_bad_geometry(self):
        for bad in ((0, 1, 1, 1, 2), (1, 1, 1, 1, 0), (1, -1, 1, 1, 2), (1, 1, 1, 1, 2.0)):
            with self.subTest(bad=bad), self.assertRaises(kl.LayoutError):
                kl.StagingLayout(*bad)


class Paged(unittest.TestCase):
    def test_every_vllm_layout_and_kernel_split(self):
        H, C, B = 2, 3, 5
        for name, order in VLLM_LAYOUTS.items():
            for block_size, kbs in ((4, 4), (4, 2), (4, 1)):
                ratio = block_size // kbs
                shape5 = (3, B * ratio, H, kbs, C)
                strides, size = layer_view_strides(order, shape5)
                layer = 1
                base = layer * _five(order, shape5)[0]
                t = kl.PagedTarget(block_size, kbs, H, C, strides)
                block_ids = [3, 0, 4]
                seen = set()
                for token in range(len(block_ids) * block_size):
                    for head in range(H):
                        for e in range(C):
                            pos = base + t.dst_index(block_ids, token, head, e)
                            self.assertNotIn(pos, seen)
                            seen.add(pos)
                            want_kb = block_ids[token // block_size] * ratio + \
                                (token % block_size) // kbs
                            self.assertEqual(decode(pos, order, shape5),
                                             [layer, want_kb, head, token % kbs, e],
                                             (name, block_size, kbs, token, head, e))
                self.assertLess(max(seen), size)

    def test_refuses_kernel_block_that_does_not_divide(self):
        with self.assertRaises(kl.LayoutError):
            kl.PagedTarget(16, 6, 8, 256, (1, 1, 1, 1))

    def test_block_list_must_cover_the_token(self):
        t = kl.PagedTarget(4, 4, 1, 1, (4, 4, 1, 1))
        with self.assertRaises(kl.LayoutError):
            t.dst_index([7], 4, 0, 0)


def _five(order, shape5):
    strides, current = [0] * 5, 1
    for dim in reversed(order):
        strides[dim] = current
        current *= shape5[dim]
    return strides


class Scatter(unittest.TestCase):
    def check(self, block_size, kbs, order, block_ids, first, end, stage):
        L, H, C = 3, 2, 4
        s = kl.StagingLayout(block_size, L, H, C, 2)
        ratio = block_size // kbs
        shape5 = (L, (max(block_ids) + 1) * ratio, H, kbs, C)
        strides5 = _five(order, shape5)
        size = math.prod(shape5)
        t = kl.PagedTarget(block_size, kbs, H, C, tuple(strides5[1:]))
        r = kl.ScatterRange(first, end, stage)

        def value(token, layer, head, e):
            return ((token * L + layer) * H + head) * C + e + 1
        staged = [0] * kl.staged_elems(s, r)
        for token in range(stage, ((end - stage + block_size - 1) // block_size) * block_size + stage):
            for layer, head, e in itertools.product(range(L), range(H), range(C)):
                staged[s.src_index(token - stage, layer, head, e)] = value(token, layer, head, e)
        memory = [-1] * size
        for layer in range(L):
            for src, dst in kl.scatter_pairs(s, t, block_ids, r, layer):
                memory[layer * strides5[0] + dst] = staged[src]
        written = sum(1 for v in memory if v != -1)
        self.assertEqual(written, (end - first) * L * H * C, 'only the loaded tokens')
        for token in range(first, end):
            for layer, head, e in itertools.product(range(L), range(H), range(C)):
                pos = layer * strides5[0] + t.dst_index(block_ids, token, head, e)
                self.assertEqual(memory[pos], value(token, layer, head, e))

    def test_whole_prefix(self):
        self.check(4, 4, VLLM_LAYOUTS['LBNHC'], [5, 1, 3], 0, 12, 0)

    def test_after_a_local_hit(self):
        # Tokens 0..3 are vLLM's own prefix-cache hit; staging starts at token 4.
        self.check(4, 4, VLLM_LAYOUTS['LBHNC'], [5, 1, 3, 0], 4, 16, 4)

    def test_stage_before_first_token_and_kernel_split(self):
        self.check(4, 2, VLLM_LAYOUTS['BLNHC'], [2, 6, 0, 1], 8, 16, 4)

    def test_range_rules(self):
        for bad in ((4, 4, 0), (4, 2, 0), (2, 8, 3), (-4, 8, -4), (4, 8, 8), (4, 8, 2)):
            with self.subTest(bad=bad), self.assertRaises(kl.LayoutError):
                kl.ScatterRange(*bad).check(kl.StagingLayout(4, 1, 1, 1, 2))

    def test_scatter_needs_blocks_for_every_token(self):
        s = kl.StagingLayout(4, 1, 1, 1, 2)
        t = kl.PagedTarget(4, 4, 1, 1, (4, 4, 1, 1))
        with self.assertRaises(kl.LayoutError):
            list(kl.scatter_pairs(s, t, [0], kl.ScatterRange(0, 8, 0), 0))


class StageStart(unittest.TestCase):
    def test_largest_aligned_start(self):
        # Qwen3-8B, 16-token blocks, 128 KiB groups: every block start is a group start.
        self.assertEqual(kl.stage_start(4096, 147456, 16, 131072), 4096)
        # 12 KiB per token: a group start every 32 tokens.
        self.assertEqual(kl.stage_start(48, 12288, 16, 131072), 32)
        self.assertEqual(kl.stage_start(15, 12288, 16, 131072), 0)
        for computed in range(0, 200, 16):
            s0 = kl.stage_start(computed, 12288, 16, 131072)
            self.assertTrue(s0 <= computed and s0 % 16 == 0 and s0 * 12288 % 131072 == 0)
            self.assertFalse(any(x % 16 == 0 and x * 12288 % 131072 == 0
                                 for x in range(s0 + 1, computed + 1)))

    def test_round_up(self):
        self.assertEqual(kl.round_up(1, 4096), 4096)
        self.assertEqual(kl.round_up(8192, 4096), 8192)
        self.assertEqual(kl.round_up(0, 4096), 0)


if __name__ == '__main__':
    unittest.main()
