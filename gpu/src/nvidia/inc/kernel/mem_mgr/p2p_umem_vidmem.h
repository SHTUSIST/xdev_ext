/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: MIT
 */

#ifndef P2P_UMEM_VIDMEM_H
#define P2P_UMEM_VIDMEM_H

/*
 * GPU side of a UBR CE transfer: a window [windowOffset, windowOffset +
 * windowLength) of one vidmem allocation's memdesc, bound once from the
 * caller's GPU VA range.  Transfers name window-relative offsets; the CE
 * surface is (memdesc, windowOffset + gpuOffset).  Every bound is checked
 * in subtraction form so no sum of untrusted values is ever formed.
 */

/* A non-empty GPU VA range that does not wrap. */
static NV_INLINE NvBool
nvP2PVidmemRangeValid
(
    NvU64 address,
    NvU64 length
)
{
    return length != 0 && address <= ~(NvU64)0 - (length - 1);
}

/* The window lies inside an allocation of memdescSize bytes. */
static NV_INLINE NvBool
nvP2PVidmemWindowValid
(
    NvU64 memdescSize,
    NvU64 windowOffset,
    NvU64 windowLength
)
{
    return windowLength != 0 && windowOffset <= memdescSize &&
           windowLength <= memdescSize - windowOffset;
}

/* Memdesc offset of a transfer of size bytes at window offset gpuOffset. */
static NV_INLINE NvBool
nvP2PVidmemXferOffset
(
    NvU64  windowOffset,
    NvU64  windowLength,
    NvU64  gpuOffset,
    NvU64  size,
    NvU64 *pMemdescOffset
)
{
    if (size == 0 || gpuOffset > windowLength ||
        size > windowLength - gpuOffset ||
        gpuOffset > ~(NvU64)0 - windowOffset)
        return NV_FALSE;

    *pMemdescOffset = windowOffset + gpuOffset;
    return NV_TRUE;
}

/*
 * Device-contiguous segment of the window, in window offsets: 0 when the
 * allocation is physically contiguous, else the GPU page size reduced to
 * the largest power of two that divides windowStart, the window's byte
 * position relative to a GPU page boundary.  Segment k is then [k * seg,
 * (k + 1) * seg) and never crosses a GPU page.
 */
static NV_INLINE NvBool
nvP2PVidmemSegSize
(
    NvU64   windowStart,
    NvU64   pageSize,
    NvBool  bContiguous,
    NvU32  *pSegSize
)
{
    NvU64 misalign;

    if (bContiguous)
    {
        *pSegSize = 0;
        return NV_TRUE;
    }

    if (pageSize == 0 || (pageSize & (pageSize - 1)) != 0 ||
        pageSize > NV_U32_MAX)
        return NV_FALSE;

    misalign = windowStart & (pageSize - 1);
    *pSegSize = (NvU32)(misalign != 0 ? (misalign & (~misalign + 1)) :
                                        pageSize);
    return NV_TRUE;
}

#endif /* P2P_UMEM_VIDMEM_H */
