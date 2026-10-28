# SPDX-License-Identifier: GPL-2.0
"""Pre-submit shape policy shared by runtime dispatch and shape propagation."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Qualified:
    output_shape: tuple | None
    rows: int
    width: int


def qualify(shape, *, dtype, device_type, contiguous, world_size, rank,
            operation, dim=-1, dst=0, max_payload_bytes):
    if world_size != 2 or rank not in (0, 1):
        raise ValueError('xdev TP requires world_size=2 and rank 0 or 1')
    if dtype not in ('float16', 'bfloat16', 'float32'):
        raise ValueError('xdev TP supports float16, bfloat16, float32 only')
    if device_type not in ('cuda', 'meta') or not contiguous:
        raise ValueError('xdev TP requires contiguous CUDA tensors')
    if operation not in ('all_reduce', 'gather', 'all_gather') or dst not in (0, 1):
        raise ValueError('unsupported collective or destination')
    shape = tuple(shape)
    limit = (1 << 63) - 1
    numel = 1
    for size in shape:
        if not isinstance(size, int) or size < 0:
            raise ValueError('shape must have concrete nonnegative dimensions')
        if size and numel > limit // size:
            raise OverflowError('tensor element count overflows int64')
        numel *= size
    itemsize = 4 if dtype == 'float32' else 2
    if numel > limit // itemsize or numel * itemsize > min(max_payload_bytes, (1 << 32) - 1):
        raise OverflowError('tensor payload exceeds admitted capacity')
    if operation == 'all_reduce':
        return Qualified(shape, 1, numel)
    if not shape or dim not in (-1, len(shape) - 1):
        raise ValueError('xdev TP gather supports the last dimension only')
    rows = 1
    for size in shape[:-1]:
        if size and rows > limit // size:
            raise OverflowError('gather row count overflows int64')
        rows *= size
    if shape[-1] > limit // 2 or numel > limit // (2 * itemsize):
        raise OverflowError('gather output size overflows int64')
    output = (*shape[:-1], shape[-1] * 2)
    return Qualified(output if operation == 'all_gather' or rank == dst else None,
                     rows, shape[-1])
