/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/*
 * Generic P2P UMEM Support
 *
 * Provides unified DMA support for:
 * - CXL memory expanders
 * - AF_XDP UMEM (zero-copy networking)
 * - Generic user memory regions
 *
 * Supports both directions:
 * - GPU DMA to/from external memory (CXL, UMEM)
 * - GPU memory exported as UMEM backing store
 */

#include "core/core.h"
#include "gpu/gpu.h"
#include "mem_mgr/p2p.h"
#include "mem_mgr/p2p_umem_chunk.h"
#include "mem_mgr/p2p_umem_vidmem.h"
#include "os/os.h"
#include "nvport/nvport.h"
#include "gpu/mem_mgr/mem_mgr.h"
#include "gpu/mem_mgr/mem_desc.h"
#include "gpu/mem_mgr/ce_utils.h"
#include "gpu/bus/kern_bus.h"

// Buffer type enumeration (must match nv-p2p.c)
typedef enum {
    NV_P2P_BUFFER_TYPE_GENERIC = 0,
    NV_P2P_BUFFER_TYPE_CXL,
    NV_P2P_BUFFER_TYPE_HOST_REGION,
    NV_P2P_BUFFER_TYPE_GPU_EXPORT,
    /* Established only by the kernel-open ioctl registry, never raw RM ABI. */
    NV_P2P_BUFFER_TYPE_VERIFIED_XSK,
} NV_P2P_BUFFER_TYPE;

// DMA direction flags
#define P2P_DMA_FLAG_TO_GPU      0x1
#define P2P_DMA_FLAG_FROM_GPU    0x0
#define P2P_DMA_FLAG_ASYNC       0x2

// Page size constants
#define P2P_PAGE_SIZE_4K         (4ULL * 1024)
#define P2P_PAGE_SIZE_2M         (2ULL * 1024 * 1024)
#define P2P_DEFAULT_PAGE_SIZE    P2P_PAGE_SIZE_2M

// Forward declarations for kernel pinning interface (generic)
extern NV_STATUS nv_pin_cxl_buffer(NvU64, NvU64, void **);
extern NV_STATUS nv_unpin_cxl_buffer(void *);
extern NV_STATUS nv_get_cxl_buffer_pages(void *, NvU64 **, NvU32 *);
extern NV_STATUS nv_pin_cxl_buffer_hugepages(NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_get_cxl_buffer_hugepages(void *, NvU64 **, NvU32 *, NvU32 *);

// Explicit host-region interface (legacy type value 2)
extern NV_STATUS nv_pin_host_region(NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_unpin_host_region(void *);
extern NV_STATUS nv_get_host_region_pages(void *, NvU64, NvU64, NvU64 **, NvU32 *, NvU32 *);
extern NV_STATUS nv_register_gpu_umem(void *, NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_unregister_gpu_umem(void *);
extern NV_STATUS nv_get_umem_buffer_info(void *, NvU32 *, NvU64 *, NvU32 *, NvU32 *, NvBool *);

// CXL device enumeration
typedef struct {
    NvU32   numDevices;
    NvU32   numMemoryDevices;
    NvBool  bLinkUp;
    NvU32   cxlVersion;
} P2P_SYSTEM_INFO;

extern NV_STATUS nv_enumerate_cxl_devices(P2P_SYSTEM_INFO *pInfo);

//
// Unified P2P Buffer Handle
//
typedef struct P2P_UMEM_BUFFER_HANDLE
{
    void               *pKernelHandle;     // Kernel pinning handle
    NvU64               baseAddress;       // Base virtual address
    NvU64               size;              // Size in bytes
    NvU32               bufferType;        // NV_P2P_BUFFER_TYPE
    NvU64              *pPageArray;        // Physical page addresses
    NvU32               pageCount;         // Number of pages
    NvU32               pageSize;          // Page size (4K or 2M)
    NvU32               frameSize;         // XDP frame size (for UMEM)
    NvBool              bRegistered;       // Registration state
    NvBool              bHugePages;        // Using huge pages
    NvBool              bGpuBacked;        // GPU memory backing
    // GPU state
    void               *gpuMemHandle;      // GPU memory handle (for export)
    NvU64               gpuOffset;         // GPU memory offset
    MEMORY_DESCRIPTOR  *pMemDesc;          // Persistent memory descriptor
} P2P_UMEM_BUFFER_HANDLE;

// Global tracking
#define P2P_MAX_BUFFER_SIZE         (1ULL << 40)  // 1TB
#define P2P_MAX_REGISTERED_BUFFERS  256

#ifndef NV_P2P_UMEM_STRICT_SECURITY_CHECKS
#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1
#endif

static NvU32 g_p2pRegisteredBufferCount = 0;
static NvU64 g_p2pTotalRegisteredSize = 0;

//
// Helper: Check if address range is 2MB aligned
//
static NvBool
_p2pCanUseHugePages
(
    NvU64 baseAddress,
    NvU64 size
)
{
    return ((baseAddress & (P2P_PAGE_SIZE_2M - 1)) == 0) &&
           ((size & (P2P_PAGE_SIZE_2M - 1)) == 0) &&
           (size >= P2P_PAGE_SIZE_2M);
}

//
// Helper: Create memory descriptor for external memory
//
static NV_STATUS
_p2pCreateMemDesc
(
    OBJGPU *pGpu,
    P2P_UMEM_BUFFER_HANDLE *pHandle
)
{
    NV_STATUS status;
    MEMORY_DESCRIPTOR *pMemDesc = NULL;
    RmPhysAddr *pPteArray = NULL;
    NvU32 i;

    if (pHandle->pPageArray == NULL || pHandle->pageCount == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P UMEM: No page array available\n");
        return NV_ERR_INVALID_STATE;
    }

    status = memdescCreate(&pMemDesc, pGpu, pHandle->size, 0, NV_FALSE, ADDR_SYSMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P UMEM: Failed to create memdesc: 0x%x\n", status);
        return status;
    }

    pPteArray = portMemAllocNonPaged(pHandle->pageCount * sizeof(RmPhysAddr));
    if (pPteArray == NULL)
    {
        memdescDestroy(pMemDesc);
        return NV_ERR_NO_MEMORY;
    }

    for (i = 0; i < pHandle->pageCount; i++)
    {
        pPteArray[i] = (RmPhysAddr)pHandle->pPageArray[i];
    }

    memdescFillPages(pMemDesc, 0, pPteArray, pHandle->pageCount, pHandle->pageSize);
    memdescSetPageSize(pMemDesc, AT_GPU, pHandle->pageSize);

    pHandle->pMemDesc = pMemDesc;
    portMemFree(pPteArray);

    NV_PRINTF(LEVEL_INFO, "P2P UMEM: Created memdesc - %u pages of %u bytes (type=%u)\n",
              pHandle->pageCount, pHandle->pageSize, pHandle->bufferType);

    return NV_OK;
}

//
// RmP2PGetSystemInfo
//
// Gets P2P system capabilities (CXL devices, etc.)
//
NV_STATUS
RmP2PGetSystemInfo
(
    NvU32  *pNumDevices,
    NvU32  *pNumMemDevices,
    NvBool *pbLinkUp,
    NvU32  *pVersion
)
{
    P2P_SYSTEM_INFO info;
    NV_STATUS status;

    portMemSet(&info, 0, sizeof(info));

    status = nv_enumerate_cxl_devices(&info);
    if (status != NV_OK)
    {
        info.numDevices = 0;
        info.numMemoryDevices = 0;
        info.bLinkUp = NV_FALSE;
        info.cxlVersion = 2;
    }

    if (pNumDevices)    *pNumDevices = info.numDevices;
    if (pNumMemDevices) *pNumMemDevices = info.numMemoryDevices;
    if (pbLinkUp)       *pbLinkUp = info.bLinkUp;
    if (pVersion)       *pVersion = info.cxlVersion;

    return NV_OK;
}

// Backward compatibility alias
NV_STATUS RmP2PGetCxlSystemInfo(NvU32 *a, NvU32 *b, NvBool *c, NvU32 *d)
{
    return RmP2PGetSystemInfo(a, b, c, d);
}

//
// RmP2PRegisterUmemBuffer
//
// Unified registration for all buffer types.
//
NV_STATUS
RmP2PRegisterUmemBuffer
(
    NvU32   bufferType,
    NvU64   baseAddress,
    NvU64   size,
    NvU32   frameSize,
    void   *gpuMemHandle,
    NvU64   gpuOffset,
    void  **ppBufferHandle
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = NULL;
    NV_STATUS status;
    void *pKernelHandle = NULL;
    NvU64 *pPhysAddrs = NULL;
    NvU32 pageCount = 0;
    NvU32 actualPageSize = P2P_PAGE_SIZE_4K;
    NvBool bUseHugePages;

    if (size == 0 || ppBufferHandle == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P Register: invalid args\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size > P2P_MAX_BUFFER_SIZE)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P Register: buffer too large\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (g_p2pRegisteredBufferCount >= P2P_MAX_REGISTERED_BUFFERS)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P Register: max buffers reached\n");
        return NV_ERR_INSUFFICIENT_RESOURCES;
    }

    pHandle = portMemAllocNonPaged(sizeof(P2P_UMEM_BUFFER_HANDLE));
    if (pHandle == NULL)
        return NV_ERR_NO_MEMORY;

    portMemSet(pHandle, 0, sizeof(P2P_UMEM_BUFFER_HANDLE));
    pHandle->bufferType = bufferType;
    pHandle->frameSize = frameSize ? frameSize : P2P_PAGE_SIZE_4K;

    switch (bufferType)
    {
        case NV_P2P_BUFFER_TYPE_CXL:
        case NV_P2P_BUFFER_TYPE_GENERIC:
            // Try huge pages for CXL/generic
            bUseHugePages = _p2pCanUseHugePages(baseAddress, size);
            if (bUseHugePages)
            {
                status = nv_pin_cxl_buffer_hugepages(baseAddress, size,
                                                     P2P_PAGE_SIZE_2M, &pKernelHandle);
                if (status == NV_OK)
                {
                    status = nv_get_cxl_buffer_hugepages(pKernelHandle, &pPhysAddrs,
                                                         &pageCount, &actualPageSize);
                    if (status == NV_OK && pageCount > 0)
                    {
                        pHandle->bHugePages = NV_TRUE;
                    }
                    else
                    {
                        nv_unpin_cxl_buffer(pKernelHandle);
                        pKernelHandle = NULL;
                        bUseHugePages = NV_FALSE;
                    }
                }
                else
                {
                    bUseHugePages = NV_FALSE;
                }
            }
            // Fall back to 4K
            if (!bUseHugePages)
            {
                status = nv_pin_cxl_buffer(baseAddress, size, &pKernelHandle);
                if (status != NV_OK)
                {
                    portMemFree(pHandle);
                    return status;
                }
                status = nv_get_cxl_buffer_pages(pKernelHandle, &pPhysAddrs, &pageCount);
                if (status != NV_OK || pageCount == 0)
                {
                    nv_unpin_cxl_buffer(pKernelHandle);
                    portMemFree(pHandle);
                    return (status != NV_OK) ? status : NV_ERR_INVALID_STATE;
                }
                actualPageSize = P2P_PAGE_SIZE_4K;
            }
            break;

        case NV_P2P_BUFFER_TYPE_HOST_REGION:
            // Explicit host-region registration
            status = nv_pin_host_region(baseAddress, size, pHandle->frameSize, &pKernelHandle);
            if (status != NV_OK)
            {
                NV_PRINTF(LEVEL_ERROR, "P2P Register: host-region pin failed: 0x%x\n", status);
                portMemFree(pHandle);
                return status;
            }
            status = nv_get_host_region_pages(pKernelHandle, 0, size,
                                           &pPhysAddrs, &pageCount, NULL);
            if (status != NV_OK || pageCount == 0)
            {
                nv_unpin_host_region(pKernelHandle);
                portMemFree(pHandle);
                return (status != NV_OK) ? status : NV_ERR_INVALID_STATE;
            }
            actualPageSize = P2P_PAGE_SIZE_4K;
            break;

        case NV_P2P_BUFFER_TYPE_GPU_EXPORT:
            // GPU memory exported as UMEM
            if (gpuMemHandle == NULL)
            {
                NV_PRINTF(LEVEL_ERROR, "P2P Register: GPU export requires gpu handle\n");
                portMemFree(pHandle);
                return NV_ERR_INVALID_ARGUMENT;
            }
            status = nv_register_gpu_umem(gpuMemHandle, gpuOffset, size,
                                          pHandle->frameSize, &pKernelHandle);
            if (status != NV_OK)
            {
                portMemFree(pHandle);
                return status;
            }
            pHandle->gpuMemHandle = gpuMemHandle;
            pHandle->gpuOffset = gpuOffset;
            pHandle->bGpuBacked = NV_TRUE;
            pageCount = (NvU32)(size / pHandle->frameSize);
            actualPageSize = pHandle->frameSize;
            break;

        case NV_P2P_BUFFER_TYPE_VERIFIED_XSK:
            /* RM has no socket identity; only nv_pin_xsk_umem() may claim it. */
            portMemFree(pHandle);
            return NV_ERR_INSUFFICIENT_PERMISSIONS;

        default:
            NV_PRINTF(LEVEL_ERROR, "P2P Register: unknown buffer type %u\n", bufferType);
            portMemFree(pHandle);
            return NV_ERR_INVALID_ARGUMENT;
    }

    pHandle->pKernelHandle = pKernelHandle;
    pHandle->baseAddress = baseAddress;
    pHandle->size = size;
    pHandle->pPageArray = pPhysAddrs;
    pHandle->pageCount = pageCount;
    pHandle->pageSize = actualPageSize;
    pHandle->bRegistered = NV_TRUE;
    pHandle->pMemDesc = NULL;

    g_p2pRegisteredBufferCount++;
    g_p2pTotalRegisteredSize += size;

    *ppBufferHandle = pHandle;

    NV_PRINTF(LEVEL_INFO, "P2P Register: type=%u, size=0x%llx, pages=%u, pageSize=%u\n",
              bufferType, size, pageCount, actualPageSize);

    return NV_OK;
}

// Backward compatibility wrapper
NV_STATUS RmP2PRegisterCxlBuffer(void *dev, NvU64 addr, NvU64 size, NvU32 ver, void **h)
{
    (void)ver;  // Version unused in generic path
    return RmP2PRegisterUmemBuffer(NV_P2P_BUFFER_TYPE_CXL, addr, size, 0, NULL, 0, h);
}

//
// RmP2PUnregisterUmemBuffer
//
NV_STATUS
RmP2PUnregisterUmemBuffer
(
    void *pBufferHandle
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;
    NvU64 savedSize;

    if (pHandle == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (!pHandle->bRegistered)
        return NV_ERR_INVALID_STATE;

    savedSize = pHandle->size;
    pHandle->bRegistered = NV_FALSE;

    // Clean up memory descriptor
    if (pHandle->pMemDesc != NULL)
    {
        memdescDestroy(pHandle->pMemDesc);
        pHandle->pMemDesc = NULL;
    }

    // Unpin based on type
    if (pHandle->pKernelHandle != NULL)
    {
        switch (pHandle->bufferType)
        {
            case NV_P2P_BUFFER_TYPE_CXL:
            case NV_P2P_BUFFER_TYPE_GENERIC:
                nv_unpin_cxl_buffer(pHandle->pKernelHandle);
                break;
            case NV_P2P_BUFFER_TYPE_HOST_REGION:
            case NV_P2P_BUFFER_TYPE_VERIFIED_XSK:
                nv_unpin_host_region(pHandle->pKernelHandle);
                break;
            case NV_P2P_BUFFER_TYPE_GPU_EXPORT:
                nv_unregister_gpu_umem(pHandle->pKernelHandle);
                break;
        }
    }

    portMemFree(pHandle);

    if (g_p2pRegisteredBufferCount > 0)
        g_p2pRegisteredBufferCount--;
    if (g_p2pTotalRegisteredSize >= savedSize)
        g_p2pTotalRegisteredSize -= savedSize;

    return NV_OK;
}

// Backward compatibility
NV_STATUS RmP2PUnregisterCxlBuffer(void *h)
{
    return RmP2PUnregisterUmemBuffer(h);
}

//
// RmP2PGetUmemPages
//
NV_STATUS
RmP2PGetUmemPages
(
    void   *pBufferHandle,
    NvU64   offset,
    NvU64   size,
    NvU64  *pPhysAddrs,
    NvU32  *pPageCount,
    NvU32  *pPageSize
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;
    NvU64 endOffset;
    NvU64 endPage;
    NvU32 startPage, numPages, i;

    if (pHandle == NULL || pPhysAddrs == NULL || pPageCount == NULL || pPageSize == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (!pHandle->bRegistered)
        return NV_ERR_INVALID_STATE;

    if (size == 0 || offset > pHandle->size ||
        size > pHandle->size - offset)
        return NV_ERR_INVALID_ARGUMENT;

    if (pHandle->bGpuBacked)
    {
        NvU64 frameCount;

        if (pHandle->frameSize == 0)
            return NV_ERR_INVALID_STATE;

        frameCount = size / pHandle->frameSize;
        if (frameCount > NV_U32_MAX)
            return NV_ERR_INVALID_ARGUMENT;

        // GPU-backed doesn't have page array, return frame info
        *pPageCount = (NvU32)frameCount;
        *pPageSize = pHandle->frameSize;
        return NV_OK;
    }

    if (pHandle->pageSize == 0)
        return NV_ERR_INVALID_STATE;

    endOffset = offset + size;
    startPage = (NvU32)(offset / pHandle->pageSize);
    endPage = (endOffset == 0) ? 0 :
              ((endOffset - 1) / pHandle->pageSize) + 1;
    if (endPage < startPage || endPage - startPage > NV_U32_MAX)
        return NV_ERR_INVALID_ARGUMENT;

    numPages = (NvU32)(endPage - startPage);

    if (startPage > pHandle->pageCount ||
        numPages > pHandle->pageCount - startPage)
        return NV_ERR_INVALID_ARGUMENT;

    for (i = 0; i < numPages; i++)
    {
        pPhysAddrs[i] = pHandle->pPageArray[startPage + i];
    }

    *pPageCount = numPages;
    *pPageSize = pHandle->pageSize;

    return NV_OK;
}

// Backward compatibility
NV_STATUS RmP2PGetCxlPages(void *h, NvU64 o, NvU64 s, NvU64 *p, NvU32 *c, NvU32 *z)
{
    return RmP2PGetUmemPages(h, o, s, p, c, z);
}

NV_STATUS RmP2PPutCxlPages(void *h, NvU64 o, NvU64 s)
{
    (void)h; (void)o; (void)s;
    return NV_OK;  // No-op for now
}

//
// RmP2PUmemDmaRequest
//
// Unified DMA request for all buffer types.
// Supports GPU <-> external memory transfers.
//
NV_STATUS
RmP2PUmemDmaRequest
(
    OBJGPU *pGpu,
    void   *pBufferHandle,
    NvU64   gpuOffset,
    NvU64   umemOffset,
    NvU64   size,
    NvU32   flags
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;
    NV_STATUS status = NV_OK;
    MemoryManager *pMemoryManager;
    KernelBus *pKernelBus;
    NvBool bToGpu = (flags & P2P_DMA_FLAG_TO_GPU) != 0;
    MEMORY_DESCRIPTOR *pGpuMemDesc = NULL;
    TRANSFER_SURFACE srcSurf = {0};
    TRANSFER_SURFACE dstSurf = {0};
    NvU64 transferSize;

    if (pGpu == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: NULL GPU\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pHandle == NULL || !pHandle->bRegistered)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: Invalid buffer handle\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: Zero size\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (umemOffset > pHandle->size || size > pHandle->size - umemOffset)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: OOB access\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    pMemoryManager = GPU_GET_MEMORY_MANAGER(pGpu);
    pKernelBus = GPU_GET_KERNEL_BUS(pGpu);

    if (pMemoryManager == NULL || pKernelBus == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: NULL managers\n");
        return NV_ERR_INVALID_STATE;
    }

    // Create memory descriptor on first use (for non-GPU-backed buffers)
    if (pHandle->pMemDesc == NULL && !pHandle->bGpuBacked)
    {
        status = _p2pCreateMemDesc(pGpu, pHandle);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "P2P DMA: Failed to create memdesc: 0x%x\n", status);
            return status;
        }
    }

    // Validate GPU
    if (pGpu->bIsSOC || pGpu->getProperty(pGpu, PDB_PROP_GPU_IS_LOST))
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: GPU not available\n");
        return NV_ERR_GPU_IS_LOST;
    }

    // Create GPU memory descriptor
    status = memdescCreate(&pGpuMemDesc, pGpu, size, 0, NV_TRUE, ADDR_FBMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: Failed to create GPU memdesc: 0x%x\n", status);
        return status;
    }

    memdescDescribe(pGpuMemDesc, ADDR_FBMEM, gpuOffset, size);

    transferSize = size;
    if (transferSize > (NvU64)NV_U32_MAX)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: transfer size 0x%llx exceeds NvU32 max\n", transferSize);
        memdescDestroy(pGpuMemDesc);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Set up transfer based on direction
    if (bToGpu)
    {
        // External -> GPU
        srcSurf.pMemDesc = pHandle->pMemDesc;
        srcSurf.offset = umemOffset;
        dstSurf.pMemDesc = pGpuMemDesc;
        dstSurf.offset = 0;

        NV_PRINTF(LEVEL_INFO, "P2P DMA: %s->GPU, size=0x%llx, type=%u\n",
                  pHandle->bufferType == NV_P2P_BUFFER_TYPE_HOST_REGION ? "UMEM" : "EXT",
                  transferSize, pHandle->bufferType);
    }
    else
    {
        // GPU -> External
        srcSurf.pMemDesc = pGpuMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pHandle->pMemDesc;
        dstSurf.offset = umemOffset;

        NV_PRINTF(LEVEL_INFO, "P2P DMA: GPU->%s, size=0x%llx, type=%u\n",
                  pHandle->bufferType == NV_P2P_BUFFER_TYPE_HOST_REGION ? "UMEM" : "EXT",
                  transferSize, pHandle->bufferType);
    }

    // Execute DMA via Copy Engine
    status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, (NvU32)transferSize,
                           TRANSFER_FLAGS_PREFER_CE | TRANSFER_FLAGS_REQUIRE_CE);

    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA: CE copy failed: 0x%x\n", status);
    }

    memdescDestroy(pGpuMemDesc);

    return status;
}

// Backward compatibility
NV_STATUS RmP2PCxlDmaRequest(OBJGPU *g, void *h, NvU64 go, NvU64 co, NvU64 s, NvU32 f)
{
    return RmP2PUmemDmaRequest(g, h, go, co, s, f);
}

/* A bind owns its channel for its entire lifetime; it is never recreated. */
typedef struct P2P_UMEM_CE_HOST {
    P2P_UMEM_VIDMEM_BINDING *pBinding;
    MEMORY_DESCRIPTOR *pHostMemDesc;
    CeUtils *pCeUtils;
    NvU64 bytes;
    NvBool poisoned;
    struct P2P_UMEM_CE_HOST *pNext;
} P2P_UMEM_CE_HOST;

/* Accessed only under the RM API lock. Mapping changes invalidate every bind. */
static P2P_UMEM_CE_HOST *g_pXdevExtCeHosts;
void RmP2PUmemCeInvalidate(OBJGPU *pGpu)
{
    P2P_UMEM_CE_HOST *h;
    for (h = g_pXdevExtCeHosts; h != NULL; h = h->pNext)
        if (h->pBinding->pGpu == pGpu)
            h->poisoned = NV_TRUE;
}

NV_STATUS RmP2PUmemCeHostBind(P2P_UMEM_VIDMEM_BINDING *b,
    NvU64 *phys, NvU32 count, NvU32 pageSize, NvU64 bytes, void **out)
{
    P2P_UMEM_CE_HOST *h;
    NV0050_ALLOCATION_PARAMETERS params = {0};
    MemoryManager *mm;
    NV_STATUS status;
    OBJGPU *g;
    if (b == NULL || phys == NULL || out == NULL || count == 0 ||
        pageSize == 0 || bytes == 0 || bytes > (NvU64)count * pageSize)
        return NV_ERR_INVALID_ARGUMENT;
    *out = NULL;
    g = b->pGpu;
    mm = GPU_GET_MEMORY_MANAGER(g);
    /* Physical-mode copies only. Virtual/MIG/CC require a separate mapping API. */
    if (mm == NULL || IS_VIRTUAL(g) || IS_MIG_IN_USE(g) ||
        mm->bCePhysicalVidmemAccessNotSupported || g->bIsSOC ||
        g->getProperty(g, PDB_PROP_GPU_IS_LOST))
        return NV_ERR_NOT_SUPPORTED;
    h = portMemAllocNonPaged(sizeof(*h));
    if (h == NULL) return NV_ERR_NO_MEMORY;
    portMemSet(h, 0, sizeof(*h));
    h->pBinding = b; h->bytes = bytes;
    /* UMEM is ordinary cached CPU RAM. CE cache operations use this attribute. */
    status = memdescCreate(&h->pHostMemDesc, g, bytes, 0, NV_FALSE,
                          ADDR_SYSMEM, NV_MEMORY_CACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK) goto fail;
    memdescFillPages(h->pHostMemDesc, 0, (RmPhysAddr *)phys, count, pageSize);
    memdescSetPageSize(h->pHostMemDesc, AT_GPU, pageSize);
    if (IsTURINGorBetter(g))
        params.flags |= DRF_DEF(0050_CEUTILS, _FLAGS, _NO_BAR1_USE, _TRUE);
    status = objCreate(&h->pCeUtils, mm, CeUtils, g, NULL, &params);
    if (status != NV_OK) goto fail;
    /* The shadow-transfer fallback can allocate (and issue synchronous copies)
     * for each semaphore read. Require the constructor's persistent CPU maps.
     */
    if (h->pCeUtils->pChannel->pbCpuVA == NULL ||
        h->pCeUtils->pChannel->pControlGPFifo == NULL ||
        (h->pCeUtils->pChannel->bUseDoorbellRegister &&
         h->pCeUtils->pChannel->pTokenFromNotifier == NULL)) {
        status = NV_ERR_NOT_SUPPORTED;
        goto fail;
    }
    h->pNext = g_pXdevExtCeHosts; g_pXdevExtCeHosts = h;
    *out = h;
    return NV_OK;
fail:
    if (h->pCeUtils != NULL) objDelete(h->pCeUtils);
    if (h->pHostMemDesc != NULL) memdescDestroy(h->pHostMemDesc);
    portMemFree(h);
    return status;
}

static NV_STATUS _p2pXdevExtCeValid(P2P_UMEM_CE_HOST *h)
{
    OBJGPU *g = h->pBinding->pGpu;
    if (h->poisoned || g->getProperty(g, PDB_PROP_GPU_IS_LOST) ||
        g->getProperty(g, PDB_PROP_GPU_IN_FULLCHIP_RESET) ||
        g->getProperty(g, PDB_PROP_GPU_IN_SECONDARY_BUS_RESET) ||
        g->getProperty(g, PDB_PROP_GPU_IN_GC6_RESET) ||
        ceutilsIsSubmissionPaused(h->pCeUtils) ||
        kbusIsBarAccessBlocked(GPU_GET_KERNEL_BUS(g)) ||
        h->pCeUtils->pChannel->pbCpuVA == NULL ||
        h->pCeUtils->pChannel->pControlGPFifo == NULL) {
        h->poisoned = NV_TRUE;
        return NV_ERR_INVALID_STATE;
    }
    return NV_OK;
}

NV_STATUS RmP2PUmemCeAsyncSubmit(void *host, const P2P_UMEM_XFER *x,
    NvU32 n, NvU32 direction, NvBool *issued, NvU64 *token)
{
    P2P_UMEM_CE_HOST *h = host;
    MEMORY_DESCRIPTOR *gpuMd = NULL;
    NV_STATUS status;
    NvU32 i;
    *issued = NV_FALSE; *token = 0;
    if (h == NULL || x == NULL || n == 0 || n > P2P_UMEM_MAX_XFERS || direction > 1)
        return NV_ERR_INVALID_ARGUMENT;
    status = _p2pXdevExtCeValid(h);
    if (status != NV_OK) return status;
    status = RmP2PUmemVidmemResolve(h->pBinding, h->pBinding->pGpu, &gpuMd);
    if (status != NV_OK) return status;
    /* Validate the entire plan, including token budget, before the first push. */
    if (h->pCeUtils->lastSubmittedPayload > NV_U64_MAX - n)
        return NV_ERR_INVALID_STATE;
    /* HW has only 32 bits. Keep unobserved work below half a semaphore lap (modulo wait ordering). */
    if (h->pCeUtils->lastSubmittedPayload - h->pCeUtils->lastCompletedPayload >
        (NvU64)NV_S32_MAX - n)
        return NV_ERR_BUSY_RETRY;
    for (i = 0; i < n; i++) {
        NvU64 offset;
        if (x[i].size == 0 || x[i].size > NV_U32_MAX ||
            x[i].umemOffset > h->bytes || x[i].size > h->bytes - x[i].umemOffset ||
            !nvP2PVidmemXferOffset(h->pBinding->offset, h->pBinding->length,
                                 x[i].gpuOffset, x[i].size, &offset))
            return NV_ERR_INVALID_ARGUMENT;
    }
    for (i = 0; i < n; i++) {
        CEUTILS_MEMCOPY_PARAMS p = {0};
        p.pSrcMemDesc = direction ? h->pHostMemDesc : gpuMd;
        p.pDstMemDesc = direction ? gpuMd : h->pHostMemDesc;
        p.srcOffset = direction ? x[i].umemOffset : h->pBinding->offset + x[i].gpuOffset;
        p.dstOffset = direction ? h->pBinding->offset + x[i].gpuOffset : x[i].umemOffset;
        p.length = x[i].size;
        p.flags = NV0050_CTRL_MEMCOPY_FLAGS_ASYNC;
        /* No completion wait here. A full GPFIFO may still wait for space. */
        *issued = NV_TRUE;
        status = ceutilsMemcopy(h->pCeUtils, &p);
        if (status != NV_OK || p.submittedWorkId == 0) {
            h->poisoned = NV_TRUE;
            return status != NV_OK ? status : NV_ERR_INVALID_STATE;
        }
        *token = p.submittedWorkId;
    }
    return NV_OK;
}

NV_STATUS RmP2PUmemCeProgress(void *host, NvU64 *watermark)
{
    P2P_UMEM_CE_HOST *h = host;
    NV_STATUS status;
    if (h == NULL || watermark == NULL) return NV_ERR_INVALID_ARGUMENT;
    status = _p2pXdevExtCeValid(h);
    if (status != NV_OK) return status;
    *watermark = ceutilsUpdateProgress(h->pCeUtils);
    if (*watermark > h->pCeUtils->lastSubmittedPayload) {
        h->poisoned = NV_TRUE;
        return NV_ERR_INVALID_STATE;
    }
    return NV_OK;
}

NV_STATUS RmP2PUmemCeHostUnbind(void *host)
{
    P2P_UMEM_CE_HOST *h = host, **link;
    NvU64 watermark;
    NV_STATUS status = RmP2PUmemCeProgress(h, &watermark);
    if (status != NV_OK) return status;
    if (watermark != h->pCeUtils->lastSubmittedPayload) return NV_ERR_BUSY_RETRY;
    for (link = &g_pXdevExtCeHosts; *link != NULL; link = &(*link)->pNext)
        if (*link == h) { *link = h->pNext; break; }
    /* Already drained: the CeUtils destructor's legacy wait observes completion. */
    objDelete(h->pCeUtils);
    memdescDestroy(h->pHostMemDesc);
    portMemFree(h);
    return NV_OK;
}

//
// RmP2PUmemDmaRequestDirect
//
// CE transfers between a pinned host region and a bound vidmem window.  This
// is the entry point for the kernel-open UBR CE paths (NV_ESC_P2P_DMA_XFER and
// the copy-engine mechanism backend), which already hold pinned host pages but
// no RM-level registration.  The host side is an ADDR_SYSMEM memdesc built
// from pPhysAddrs; the GPU side is pGpuMemDesc, the caller's own vidmem
// allocation, at windowOffset + each transfer's window-relative gpuOffset.
// Every transfer is checked before the first copy.
//
// *pHwSubmitted reports whether the step that ended the request had entered
// memmgrMemCopy(): NV_FALSE on any failure before that point (nothing was
// pushed to a channel), NV_TRUE on success and on any failure inside the
// copy, which the caller must treat as ambiguous.  *pBytesDone counts the
// bytes of the copies that completed.
//
NV_STATUS
RmP2PUmemDmaRequestDirect
(
    OBJGPU              *pGpu,
    NvU64               *pPhysAddrs,
    NvU32                pageCount,
    NvU32                pageSize,
    NvU64                bufferSize,
    MEMORY_DESCRIPTOR   *pGpuMemDesc,
    NvU64                windowOffset,
    NvU64                windowLength,
    const P2P_UMEM_XFER *pXfers,
    NvU32                xferCount,
    NvU32                flags,
    NvBool              *pHwSubmitted,
    NvU64               *pBytesDone
)
{
    P2P_UMEM_BUFFER_HANDLE tempHandle;
    NV_STATUS status;
    MemoryManager *pMemoryManager;
    TRANSFER_SURFACE srcSurf = {0};
    TRANSFER_SURFACE dstSurf = {0};
    NvBool bToGpu = (flags & 0x1) != 0;
    NvU64 umemBytes;
    NvU64 gpuPageSize;
    NvU64 gpuPteAdjust;
    NvU64 currentUmemOffset;
    NvU64 currentGpuOffset;
    NvU64 remaining;
    NvU32 i;
    const NvU32 transferFlags =
        TRANSFER_FLAGS_PREFER_CE | TRANSFER_FLAGS_REQUIRE_CE;

    if (pHwSubmitted != NULL)
        *pHwSubmitted = NV_FALSE;
    if (pBytesDone != NULL)
        *pBytesDone = 0;

    if (pGpu == NULL || pPhysAddrs == NULL || pGpuMemDesc == NULL ||
        pXfers == NULL || pHwSubmitted == NULL || pBytesDone == NULL ||
        pageCount == 0 || pageSize == 0 || bufferSize == 0 ||
        xferCount == 0 || xferCount > P2P_UMEM_MAX_XFERS)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: invalid args\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    umemBytes = (NvU64)pageCount * pageSize;
    if (bufferSize > umemBytes)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: UMEM pages do not cover buffer\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (memdescGetAddressSpace(pGpuMemDesc) != ADDR_FBMEM ||
        !nvP2PVidmemWindowValid(memdescGetSize(pGpuMemDesc), windowOffset,
                                windowLength))
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: GPU window outside allocation\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    gpuPageSize = memdescGetPageSize(pGpuMemDesc, AT_GPU);
    gpuPteAdjust = memdescGetPteAdjust(pGpuMemDesc);
    if (gpuPageSize == 0 || gpuPageSize > NV_U32_MAX)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: invalid GPU page size\n");
        return NV_ERR_INVALID_STATE;
    }

    for (i = 0; i < xferCount; i++)
    {
        NvU64 gpuMemdescOffset;

        if (pXfers[i].size == 0 || pXfers[i].size > (NvU64)NV_U32_MAX ||
            pXfers[i].umemOffset > bufferSize ||
            pXfers[i].size > bufferSize - pXfers[i].umemOffset)
        {
            NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: UMEM OOB access\n");
            return NV_ERR_INVALID_ARGUMENT;
        }

        if (!nvP2PVidmemXferOffset(windowOffset, windowLength,
                                   pXfers[i].gpuOffset, pXfers[i].size,
                                   &gpuMemdescOffset))
        {
            NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: GPU window OOB access\n");
            return NV_ERR_INVALID_ARGUMENT;
        }
    }

    pMemoryManager = GPU_GET_MEMORY_MANAGER(pGpu);
    if (pMemoryManager == NULL)
        return NV_ERR_INVALID_STATE;

    /* Build UMEM side memdesc */
    portMemSet(&tempHandle, 0, sizeof(tempHandle));
    tempHandle.pPageArray   = pPhysAddrs;
    tempHandle.pageCount    = pageCount;
    tempHandle.pageSize     = pageSize;
    tempHandle.size         = bufferSize;
    tempHandle.bufferType   = NV_P2P_BUFFER_TYPE_HOST_REGION;
    tempHandle.bRegistered  = NV_TRUE;
    tempHandle.bGpuBacked   = NV_FALSE;
    tempHandle.pMemDesc     = NULL;

    status = _p2pCreateMemDesc(pGpu, &tempHandle);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: UMEM memdesc failed: 0x%x\n", status);
        return status;
    }

    /* Set up the two surfaces; offsets are assigned for each CE chunk. */
    if (bToGpu)
    {
        srcSurf.pMemDesc = tempHandle.pMemDesc;
        dstSurf.pMemDesc = pGpuMemDesc;
    }
    else
    {
        srcSurf.pMemDesc = pGpuMemDesc;
        dstSurf.pMemDesc = tempHandle.pMemDesc;
    }

    status = NV_OK;
    for (i = 0; i < xferCount && status == NV_OK; i++)
    {
        currentUmemOffset = pXfers[i].umemOffset;
        currentGpuOffset = windowOffset + pXfers[i].gpuOffset;
        remaining = pXfers[i].size;
        while (remaining != 0)
        {
            NvU32 chunkSize;

            /* Earlier chunks completed; this one has not reached a channel. */
            *pHwSubmitted = NV_FALSE;
            chunkSize = nvP2PUmemCeChunkSize(currentUmemOffset, pageSize,
                                             gpuPteAdjust + currentGpuOffset,
                                             (NvU32)gpuPageSize, remaining);
            if (chunkSize == 0)
            {
                status = NV_ERR_INVALID_STATE;
                break;
            }

            if (bToGpu)
            {
                srcSurf.offset = currentUmemOffset;
                dstSurf.offset = currentGpuOffset;
            }
            else
            {
                srcSurf.offset = currentGpuOffset;
                dstSurf.offset = currentUmemOffset;
            }

            /*
             * The copy below refuses a REQUIRE_CE request it cannot place on
             * CeUtils (absent, paused, or a surface pair CE cannot take)
             * before any GPFIFO entry is written.  Check that first, under
             * the API lock held by the caller, so such a refusal ends the
             * request as a pre-submit failure instead of an ambiguous one.
             */
            if (!memmgrMemCopyUsesCe(pMemoryManager, &dstSurf, &srcSurf,
                                     transferFlags))
            {
                status = NV_ERR_NOT_SUPPORTED;
                break;
            }

            /*
             * One call covers one physical segment on each side, so CeUtils
             * emits and waits for that segment's completion payload before
             * the next segment can be submitted.  A later submit failure
             * therefore cannot leave an earlier segment outstanding.
             */
            /*
             * Once the synchronous CE call is entered, an error cannot prove
             * the GPFIFO/doorbell was not observed by hardware.  Keep the
             * UMEM memdesc until reset unless the completion payload is
             * observed successfully; the caller keeps the GPU window bound.
             */
            *pHwSubmitted = NV_TRUE;
            status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf,
                                   chunkSize, transferFlags);
            if (status != NV_OK)
                goto quarantine;

            currentUmemOffset += chunkSize;
            currentGpuOffset += chunkSize;
            remaining -= chunkSize;
            *pBytesDone += chunkSize;
        }
    }

    if (status != NV_OK)
        NV_PRINTF(LEVEL_ERROR, "P2P DMA Direct: CE copy failed: 0x%x\n", status);

    memdescDestroy(tempHandle.pMemDesc);
    return status;

quarantine:
    NV_PRINTF(LEVEL_ERROR,
              "P2P DMA Direct: CE completion ambiguous; retaining memdescs until reset\n");
    return status;
}

//
// RmP2PGetBufferInfo
//
// Returns information about a registered buffer.
//
NV_STATUS
RmP2PGetBufferInfo
(
    void   *pBufferHandle,
    NvU32  *pBufferType,
    NvU64  *pSize,
    NvU32  *pPageSize,
    NvU32  *pFrameSize,
    NvBool *pIsGpuBacked
)
{
    P2P_UMEM_BUFFER_HANDLE *pHandle = (P2P_UMEM_BUFFER_HANDLE *)pBufferHandle;

    if (pHandle == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBufferType)  *pBufferType = pHandle->bufferType;
    if (pSize)        *pSize = pHandle->size;
    if (pPageSize)    *pPageSize = pHandle->pageSize;
    if (pFrameSize)   *pFrameSize = pHandle->frameSize;
    if (pIsGpuBacked) *pIsGpuBacked = pHandle->bGpuBacked;

    return NV_OK;
}
