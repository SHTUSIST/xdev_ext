/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: MIT
 */

#ifndef P2P_UMEM_CHUNK_H
#define P2P_UMEM_CHUNK_H

/*
 * Limit one synchronous CE request to one physical segment on each side.
 * ceutilsMemcopy() emits one completion payload only for the final segment in
 * a request.  Keeping each request within both page boundaries means an error
 * cannot leave successful earlier segments from that request outstanding.
 */
static NV_INLINE NvU32
nvP2PUmemCeChunkSize
(
    NvU64 umemOffset,
    NvU32 umemPageSize,
    NvU64 gpuOffset,
    NvU32 gpuPageSize,
    NvU64 remaining
)
{
    NvU64 umemPageRemaining;
    NvU64 gpuPageRemaining;
    NvU64 chunk;

    if (umemPageSize == 0 || gpuPageSize == 0 || remaining == 0)
        return 0;

    umemPageRemaining = umemPageSize - (umemOffset % umemPageSize);
    gpuPageRemaining = gpuPageSize - (gpuOffset % gpuPageSize);
    chunk = remaining;
    if (chunk > umemPageRemaining)
        chunk = umemPageRemaining;
    if (chunk > gpuPageRemaining)
        chunk = gpuPageRemaining;
    if (chunk > (NvU64)(NvU32)~0U)
        chunk = (NvU64)(NvU32)~0U;

    return (NvU32)chunk;
}

#endif /* P2P_UMEM_CHUNK_H */
