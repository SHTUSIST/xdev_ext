# SPDX-License-Identifier: GPL-2.0
"""Staging -> paged KV scatter on the GPU, and the torch reference it is checked against.

scatter_layer_triton launches one Triton program per (16 tokens, KV head):
each row reads the cell of token t, head h from the staging range in
block-layer order and writes it to (kernel block, head, slot) of vLLM's layer
view through the view's own strides, so every KVCacheLayout works. It reads
only staging and the layer's blocks of [first_token, end_token); offsets are
64-bit. scatter_layer_torch does the same with torch indexing and
gather_layer_torch is its inverse (paged -> staging). layout.py defines both
index functions; tests compare all three element by element.

TorchDevice gives core.WorkerSide its GPU operations: an event on the current
stream (fence), a host wait, all layers on a side stream after a fence
(async mode) and one layer on the current stream (sync mode).
"""
from .layout import LayoutError, PagedTarget, ScatterRange, staged_blocks

TOKENS_PER_PROGRAM = 16


def layer_target(view, staging):
    """PagedTarget of one layer's [B, H, N, C] view, which must hold the staged cells."""
    if view.dim() != 4:
        raise LayoutError(f'a layer cache must be [B, H, N, C], got shape {tuple(view.shape)}')
    _, heads, kbs, cell = view.shape
    if heads != staging.heads or cell != staging.state_elems:
        raise LayoutError(f'layer cache [*, {heads}, *, {cell}] does not hold '
                          f'{staging.heads} heads of {staging.state_elems} elements')
    return PagedTarget(staging.block_size, kbs, heads, cell, tuple(view.stride()))


def _rows(spec, staging, target, block_ids):
    import torch
    t = torch.arange(spec.first_token, spec.end_token, device=block_ids.device, dtype=torch.int64)
    i = torch.div(t, target.block_size, rounding_mode='floor')
    n = t - i * target.block_size
    kb = block_ids.to(torch.int64)[i] * target.ratio + \
        torch.div(n, target.kernel_block_size, rounding_mode='floor')
    rel = t - spec.stage_token
    sblk = torch.div(rel, staging.block_size, rounding_mode='floor')
    return kb, n % target.kernel_block_size, sblk, rel - sblk * staging.block_size


def _staged_layer(src, spec, staging, layer):
    nblk = staged_blocks(staging, ScatterRange(spec.first_token, spec.end_token, spec.stage_token))
    need = nblk * staging.block_elems
    if src.numel() < need:
        raise LayoutError(f'staging holds {src.numel()} of {need} elements')
    return src[:need].view(nblk, staging.layers, staging.heads, staging.block_size,
                           staging.state_elems)[:, layer]


def scatter_layer_torch(src, dst, block_ids, spec, staging, target, layer):
    kb, slot, sblk, sn = _rows(spec, staging, target, block_ids)
    dst[kb, :, slot, :] = _staged_layer(src, spec, staging, layer)[sblk, :, sn, :]


def gather_layer_torch(src, dst, block_ids, spec, staging, target, layer):
    kb, slot, sblk, sn = _rows(spec, staging, target, block_ids)
    _staged_layer(src, spec, staging, layer)[sblk, :, sn, :] = dst[kb, :, slot, :]


_KERNEL = None


def _kernel():
    global _KERNEL
    if _KERNEL is None:
        import triton
        import triton.language as tl

        @triton.jit
        def scatter_kernel(src, dst, blocks, first_token, n_tokens, stage_token, stage_bs,
                           src_block, src_layer, src_head, cell, block_size, kbs, ratio,
                           s_b, s_h, s_n, s_c, TOK: tl.constexpr, BLOCK_C: tl.constexpr):
            rows = tl.program_id(0) * TOK + tl.arange(0, TOK)
            head = tl.program_id(1).to(tl.int64)
            rmask = rows < n_tokens
            t = rows.to(tl.int64) + first_token
            rel = t - stage_token
            sblk = rel // stage_bs
            src_row = sblk * src_block + src_layer + head * src_head + (rel - sblk * stage_bs) * cell
            i = t // block_size
            n = t - i * block_size
            b = tl.load(blocks + i, mask=rmask, other=0).to(tl.int64)
            kq = n // kbs
            dst_row = (b * ratio + kq) * s_b + head * s_h + (n - kq * kbs) * s_n
            e = tl.arange(0, BLOCK_C)
            mask = rmask[:, None] & (e < cell)[None, :]
            values = tl.load(src + src_row[:, None] + e[None, :], mask=mask)
            tl.store(dst + dst_row[:, None] + e[None, :].to(tl.int64) * s_c, values, mask=mask)

        _KERNEL = (triton, scatter_kernel)
    return _KERNEL


def scatter_layer_triton(src, dst, block_ids, spec, staging, target, layer):
    if src.dtype != dst.dtype:
        raise LayoutError(f'staging dtype {src.dtype} != cache dtype {dst.dtype}')
    _staged_layer(src, spec, staging, layer)       # bounds check of the staged range
    triton, kernel = _kernel()
    n = spec.end_token - spec.first_token
    sb, sh, sn, sc = target.strides
    grid = (triton.cdiv(n, TOKENS_PER_PROGRAM), staging.heads)
    kernel[grid](src, dst, block_ids, spec.first_token, n, spec.stage_token, staging.block_size,
                 staging.block_elems, layer * staging.page_elems,
                 staging.block_size * staging.state_elems, staging.state_elems,
                 target.block_size, target.kernel_block_size, target.ratio, sb, sh, sn, sc,
                 TOK=TOKENS_PER_PROGRAM, BLOCK_C=triton.next_power_of_2(staging.state_elems))


class TorchDevice:
    """GPU side of core.WorkerSide over vLLM's layer caches (index = staged layer)."""

    def __init__(self, layers, staging, device, scatter='triton'):
        import torch
        self.torch = torch
        self.layers = list(layers)
        self.staging = staging
        self.device = device
        self.targets = [layer_target(v, staging) for v in self.layers]
        self.dtype = self.layers[0].dtype
        self.stream = torch.cuda.Stream(device=device)
        self.fn = scatter_layer_triton if scatter == 'triton' else scatter_layer_torch
        self._blocks = {}

    def fence(self):
        event = self.torch.cuda.Event()
        event.record(self.torch.cuda.current_stream(self.device))
        self._blocks.clear()
        return event

    def wait_host(self, event):
        event.synchronize()

    def drain(self):
        """Prove all device work complete, including a partially failed launch.

        A completion event may not have been recorded, and sync-mode scatters
        use the caller's stream. A successful device synchronization covers both.
        Failure is not a proof of completion; the caller must retain ownership.
        """
        self.torch.cuda.set_device(self.device)
        self.torch.cuda.synchronize(self.device)

    def _inputs(self, buffer, spec):
        src = buffer.tensor[spec.staging_offset:spec.staging_offset + spec.nbytes].view(self.dtype)
        key = (spec.req_id, spec.block_ids)
        blocks = self._blocks.get(key)
        if blocks is None:
            blocks = self.torch.tensor(spec.block_ids, dtype=self.torch.int32, device=self.device)
            self._blocks[key] = blocks
        return src, blocks

    def scatter_async(self, buffer, spec, after):
        torch = self.torch
        torch.cuda.set_device(self.device)
        with torch.cuda.stream(self.stream):
            self.stream.wait_event(after)
            src = buffer.tensor[spec.staging_offset:spec.staging_offset + spec.nbytes] \
                .view(self.dtype)
            blocks = torch.tensor(spec.block_ids, dtype=torch.int32, device=self.device)
            for layer, (view, target) in enumerate(zip(self.layers, self.targets)):
                self.fn(src, view, blocks, spec, self.staging, target, layer)
            done = torch.cuda.Event()
            done.record(self.stream)
        return done

    def scatter_now(self, buffer, spec, layer):
        src, blocks = self._inputs(buffer, spec)
        self.fn(src, self.layers[layer], blocks, spec, self.staging, self.targets[layer], layer)
