/*
 * SPDX-FileCopyrightText: Copyright (c) 2015-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _P2P_H_
#define _P2P_H_

#include "core/core.h"
#include "gpu/gpu_uuid.h"

struct MEMORY_DESCRIPTOR;

//
// UBR CE: the GPU side of a transfer is a window of one vidmem allocation,
// bound from the calling process's GPU VA range by RmP2PUmemVidmemBind().
// hMemory dups that allocation into the GPU's RM-internal client, which keeps
// its FB pages allocated until RmP2PUmemVidmemUnbind().
//
typedef struct P2P_UMEM_VIDMEM_BINDING
{
    OBJGPU                   *pGpu;
    NvHandle                  hClient;
    NvHandle                  hMemory;
    struct MEMORY_DESCRIPTOR *pMemDesc;
    NvU64                     offset;    // window start in pMemDesc
    NvU64                     length;    // window bytes
    NvU32                     segSize;   // device-contiguous segment, 0: whole window
    NvU8                      gpuUuid[RM_SHA1_GID_SIZE];
} P2P_UMEM_VIDMEM_BINDING;

// One transfer; the layout matches nv_p2p_umem_xfer_t in kernel-open nv.h.
typedef struct P2P_UMEM_XFER
{
    NvU64 umemOffset;
    NvU64 gpuOffset;    // in the bound window
    NvU64 size;
} P2P_UMEM_XFER;

#define P2P_UMEM_MAX_XFERS 64

NV_STATUS  RmP2PGetPages            (NvU64, NvU32, NvU64, NvU64, NvU64 *, NvU32 *, NvU32 *, NvU32 *, OBJGPU **, void *, void (*)(void *), void *);
NV_STATUS  RmP2PGetPagesWithoutCallbackRegistration (NvU64, NvU32, NvU64, NvU64, NvU64 *, NvU32 *, NvU32 *, NvU32 *, NvBool *, OBJGPU **, void *);
NV_STATUS  RmP2PGetPagesPersistent  (NvU64, NvU64, void **, NvU64 *, NvU32 *, NvBool *, NvBool, void *, void *, void **);
NV_STATUS  RmP2PRegisterCallback    (NvU64, NvU64, NvU64, void *, void (*)(void *), void *);
NV_STATUS  RmP2PPutPages            (NvU64, NvU32, NvU64, void *);
NV_STATUS  RmP2PGetGpuByAddress     (NvU64, NvU64, OBJGPU **);
NV_STATUS  RmP2PPutPagesPersistent  (void *, void *, void *);
NV_STATUS  RmP2PUmemVidmemBind      (NvU64, NvU64, OBJGPU *, P2P_UMEM_VIDMEM_BINDING **, P2P_UMEM_VIDMEM_BINDING **);
NV_STATUS  RmP2PUmemVidmemResolve   (P2P_UMEM_VIDMEM_BINDING *, OBJGPU *, struct MEMORY_DESCRIPTOR **);
NV_STATUS  RmP2PUmemVidmemUnbind    (P2P_UMEM_VIDMEM_BINDING *);
NV_STATUS RmP2PUmemDmaRequestDirect(OBJGPU *, NvU64 *, NvU32, NvU32, NvU64, struct MEMORY_DESCRIPTOR *, NvU64, NvU64, const P2P_UMEM_XFER *, NvU32, NvU32, NvBool *, NvU64 *);

typedef void (*P2P_UMEM_CE_EVENT)(void *arg, NvU64 watermark);
NV_STATUS RmP2PUmemCeHostBind(P2P_UMEM_VIDMEM_BINDING *, NvU64 *, NvU32, NvU32, NvU64, P2P_UMEM_CE_EVENT, void *, void **);
NV_STATUS RmP2PUmemCeHostUnbind(void *);
NV_STATUS RmP2PUmemCeAsyncSubmit(void *, const P2P_UMEM_XFER *, NvU32, NvU32, NvBool *, NvU64 *);
NV_STATUS RmP2PUmemCeProgress(void *, NvU64 *);
void RmP2PUmemCeInvalidate(OBJGPU *);

#endif
