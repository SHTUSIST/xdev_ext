# SPDX-License-Identifier: GPL-2.0
"""Where each KV element of a restored prefix is staged and where it goes in vLLM.

Staging ("block-layer", the K-KV object order): block b of the prefix
(block_size tokens), then attention layer l, then that layer's [H, N, C] page
of the block: KV head h, token n of the block, content element e. Content is
K then V (head_size + head_size_v elements), the cell vLLM 0.33.0 stores per
(head, token) (AttentionSpec.state_content_size_bytes). A P-token prefix with
P a multiple of block_size is the first P * bytes_per_token bytes.

Destination: one layer's cache as vLLM 0.33.0 views it, [B, H, N, C] with any
element strides (the six KVCacheLayout permutations give different ones). N is
the kernel block size; when it is smaller than the manager block size, manager
block b, token n is kernel block b * ratio + n // N, slot n % N
(group_kernel_blocks in vllm/v1/kv_cache_interface.py).

The Triton kernel and the torch reference in scatter.py implement exactly the
two index functions below; tests compare them element by element.
"""
from dataclasses import dataclass
import math


class LayoutError(ValueError):
    pass


DTYPE_BYTES = {'bfloat16': 2, 'float16': 2, 'float32': 4, 'uint8': 1}


def canonical_dtype(value):
    name = str(value).removeprefix('torch.')
    name = {'bf16': 'bfloat16', 'half': 'float16', 'fp16': 'float16',
            'float': 'float32', 'fp32': 'float32'}.get(name, name)
    if name not in DTYPE_BYTES:
        raise LayoutError(f'unknown KV dtype {value!r}')
    return name


def resolved_dtype(config, requested=None):
    cache = getattr(config.cache_config, 'cache_dtype', 'auto')
    value = getattr(config.model_config, 'dtype', None) if cache == 'auto' else cache
    dtype = canonical_dtype(value)
    if requested is not None and canonical_dtype(requested) != dtype:
        raise LayoutError(f'configured KV dtype {requested!r} disagrees with resolved {dtype}')
    return dtype


def _positive(value, what):
    if type(value) is not int or value < 1:
        raise LayoutError(f'{what} must be a positive integer: {value!r}')
    return value


def round_up(value, multiple):
    return -(-value // multiple) * multiple


@dataclass(frozen=True)
class StagingLayout:
    block_size: int     # tokens per staged block
    layers: int
    heads: int          # H: KV head slots of a page
    state_elems: int    # C: elements per (head, token) cell, K then V
    elem_bytes: int
    dtype: str = None

    def __post_init__(self):
        for what in ('block_size', 'layers', 'heads', 'state_elems', 'elem_bytes'):
            _positive(getattr(self, what), what)
        if self.dtype is not None:
            dtype = canonical_dtype(self.dtype)
            if DTYPE_BYTES[dtype] != self.elem_bytes:
                raise LayoutError('KV dtype size disagrees with element bytes')
            object.__setattr__(self, 'dtype', dtype)

    @property
    def state_bytes(self):
        return self.state_elems * self.elem_bytes

    @property
    def page_elems(self):
        return self.heads * self.block_size * self.state_elems

    @property
    def block_elems(self):
        return self.layers * self.page_elems

    @property
    def page_bytes(self):
        return self.page_elems * self.elem_bytes

    @property
    def block_bytes(self):
        return self.block_elems * self.elem_bytes

    @property
    def bytes_per_token(self):
        return self.layers * self.heads * self.state_bytes

    def src_index(self, token, layer, head, elem):
        """Element index of a cell; token counts from the first staged token."""
        block, n = divmod(token, self.block_size)
        return (((block * self.layers + layer) * self.heads + head) * self.block_size + n) * \
            self.state_elems + elem


@dataclass(frozen=True)
class PagedTarget:
    block_size: int          # tokens of one manager block id
    kernel_block_size: int   # N of the per-layer view
    heads: int
    state_elems: int
    strides: tuple           # element strides of the per-layer [B, H, N, C] view

    def __post_init__(self):
        _positive(self.block_size, 'block_size')
        _positive(self.kernel_block_size, 'kernel_block_size')
        _positive(self.heads, 'heads')
        _positive(self.state_elems, 'state_elems')
        if self.block_size % self.kernel_block_size:
            raise LayoutError(f'kernel block size {self.kernel_block_size} does not divide '
                              f'block size {self.block_size}')
        if len(self.strides) != 4 or any(type(s) is not int or s < 0 for s in self.strides):
            raise LayoutError(f'four nonnegative element strides required: {self.strides!r}')

    @property
    def ratio(self):
        return self.block_size // self.kernel_block_size

    def dst_index(self, block_ids, token, head, elem):
        """Element offset in the layer view; token counts from the request's first token."""
        i, n = divmod(token, self.block_size)
        if not 0 <= i < len(block_ids):
            raise LayoutError(f'no block for token {token}')
        kb = block_ids[i] * self.ratio + n // self.kernel_block_size
        sb, sh, sn, sc = self.strides
        return kb * sb + head * sh + (n % self.kernel_block_size) * sn + elem * sc


@dataclass(frozen=True)
class ScatterRange:
    first_token: int    # first token written (vLLM's computed tokens before the load)
    end_token: int      # one past the last token written (the restored prefix length)
    stage_token: int    # token at the start of the staged bytes

    def check(self, staging):
        if not all(type(v) is int for v in (self.first_token, self.end_token, self.stage_token)):
            raise LayoutError('token positions must be integers')
        if not 0 <= self.stage_token <= self.first_token < self.end_token:
            raise LayoutError(f'need 0 <= stage {self.stage_token} <= first {self.first_token} '
                              f'< end {self.end_token}')
        if self.stage_token % staging.block_size:
            raise LayoutError(f'staging starts mid-block at token {self.stage_token}')
        return self

    @property
    def tokens(self):
        return self.end_token - self.first_token


def staged_blocks(staging, rng):
    rng.check(staging)
    return -(-(rng.end_token - rng.stage_token) // staging.block_size)


def staged_elems(staging, rng):
    return staged_blocks(staging, rng) * staging.block_elems


def staged_bytes(staging, rng):
    return staged_elems(staging, rng) * staging.elem_bytes


def scatter_pairs(staging, target, block_ids, rng, layer):
    """(staging element, layer-view element) of every element the scatter writes."""
    rng.check(staging)
    if -(-rng.end_token // target.block_size) > len(block_ids):
        raise LayoutError(f'{len(block_ids)} blocks do not hold {rng.end_token} tokens')
    for token in range(rng.first_token, rng.end_token):
        for head in range(staging.heads):
            for elem in range(staging.state_elems):
                yield (staging.src_index(token - rng.stage_token, layer, head, elem),
                       target.dst_index(block_ids, token, head, elem))


def stage_start(computed, bytes_per_token, block_size, group_bytes):
    """Largest token s <= computed on a block boundary whose byte offset is a whole group.

    The restore reads whole groups from a group-aligned object start, so the
    staged range can only begin at such a token.
    """
    unit = math.lcm(block_size, group_bytes // math.gcd(bytes_per_token, group_bytes))
    return computed // unit * unit
