/*
 * SPDX-FileCopyrightText: Copyright (c) 2011-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#define  __NO_VERSION__

#include "os-interface.h"
#include "nv-linux.h"
#include "nv-rsync.h"

#include "nv-p2p.h"
#include "nv-p2p-gpu-identity.h"
#include "nv-xdev_ext-ce-classify.h"
#include "nv-xdev_ext-gpu.h"
#include "nv-xdev_ext-umem-quota.h"
#include "rmp2pdefines.h"

#include "nvmisc.h"

#include <linux/atomic.h>
#include <linux/iommu.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
#include <linux/vmalloc.h>

typedef enum nv_p2p_page_table_type {
    NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT = 0,
    NV_P2P_PAGE_TABLE_TYPE_PERSISTENT,
} nv_p2p_page_table_type_t;

typedef struct nv_p2p_dma_mapping {
    struct list_head list_node;
    struct nvidia_p2p_dma_mapping *dma_mapping;
} nv_p2p_dma_mapping_t;

typedef struct nv_p2p_mem_info {
    void (*free_callback)(void *data);
    void *data;
    struct nvidia_p2p_page_table page_table;
    struct {
        struct list_head list_head;
        struct semaphore lock;
    } dma_mapping_list;
    void *private;
    void *mig_info;
    NvBool force_pcie;
} nv_p2p_mem_info_t;

// declared and created in nv.c
extern void *nvidia_p2p_page_t_cache;

static struct nvidia_status_mapping {
    NV_STATUS status;
    int error;
} nvidia_status_mappings[] = {
    { NV_ERR_GENERIC,                -EIO      },
    { NV_ERR_INSUFFICIENT_RESOURCES, -ENOMEM   },
    { NV_ERR_NO_MEMORY,              -ENOMEM   },
    { NV_ERR_INVALID_ARGUMENT,       -EINVAL   },
    { NV_ERR_INVALID_OBJECT_HANDLE,  -EINVAL   },
    { NV_ERR_INVALID_STATE,          -EIO      },
    { NV_ERR_NOT_SUPPORTED,          -ENOTSUPP },
    { NV_ERR_OBJECT_NOT_FOUND,       -EINVAL   },
    { NV_ERR_STATE_IN_USE,           -EBUSY    },
    { NV_ERR_GPU_UUID_NOT_FOUND,     -ENODEV   },
    { NV_OK,                          0        },
};

#define NVIDIA_STATUS_MAPPINGS \
    NV_ARRAY_ELEMENTS(nvidia_status_mappings)

static int nvidia_p2p_map_status(NV_STATUS status)
{
    int error = -EIO;
    uint8_t i;

    for (i = 0; i < NVIDIA_STATUS_MAPPINGS; i++)
    {
        if (nvidia_status_mappings[i].status == status)
        {
            error = nvidia_status_mappings[i].error;
            break;
        }
    }
    return error;
}

/*
 * The RM binding dups the caller's vidmem allocation, so its FB pages stay
 * allocated while bound, and the device reference keeps the GPU open, as a
 * persistent P2P page table did.
 */
struct nv_p2p_vidmem_binding {
    void *rm;
    NvU8 gpu_uuid[NVIDIA_P2P_GPU_UUID_LEN];
};

struct nv_xdev_ext_gpu_rm_call {
    struct nv_xdev_ext_gpu_binding binding;
    nvidia_stack_t *sp;
    nv_p2p_vidmem_binding_t *vidmem;
    NvU64 *umem_phys_pages;
    NvU32 umem_page_count;
    NvU32 umem_page_size;
    NvU64 umem_size;
    nv_p2p_umem_xfer_t xfer;
    NvU32 direction;
    NvBool hwSubmitted;
    NvU64 bytesDone;
};

static int nv_xdev_ext_gpu_policy_dispatch(
    void *private,
    const struct nv_xdev_ext_gpu_request *request,
    struct nv_xdev_ext_gpu_plan *plan
)
{
    struct nv_xdev_ext_gpu_rm_call *call = private;

    return nv_xdev_ext_gpu_binding_dispatch(&call->binding, request, plan);
}

static nv_xdev_ext_gpu_u32 nv_xdev_ext_gpu_rm_submit(
    void *private,
    const struct nv_xdev_ext_gpu_request *request
)
{
    struct nv_xdev_ext_gpu_rm_call *call = private;

    (void)request;
    return rm_p2p_umem_dma_request(call->sp,
                                   call->umem_phys_pages,
                                   call->umem_page_count,
                                   call->umem_page_size,
                                   call->umem_size,
                                   call->vidmem->rm,
                                   &call->xfer, 1,
                                   call->direction,
                                   &call->hwSubmitted,
                                   &call->bytesDone);
}

static int nv_xdev_ext_gpu_policy_complete(
    void *private,
    const struct nv_xdev_ext_gpu_request *request,
    const struct nv_xdev_ext_gpu_result *result,
    struct nv_xdev_ext_gpu_plan *plan
)
{
    struct nv_xdev_ext_gpu_rm_call *call = private;

    return nv_xdev_ext_gpu_binding_complete(&call->binding, request, result, plan);
}

static void nv_xdev_ext_gpu_policy_put(void *private)
{
    struct nv_xdev_ext_gpu_rm_call *call = private;

    nv_xdev_ext_gpu_binding_put(&call->binding);
}

static nv_xdev_ext_gpu_s32 nv_xdev_ext_gpu_policy_normalize(
    void *private,
    nv_xdev_ext_gpu_u32 status
)
{
    (void)private;
    return nvidia_p2p_map_status((NV_STATUS)status);
}

static const struct nv_xdev_ext_gpu_ops nv_xdev_ext_gpu_policy_ops = {
    .dispatch = nv_xdev_ext_gpu_policy_dispatch,
    .submit = nv_xdev_ext_gpu_rm_submit,
    .complete = nv_xdev_ext_gpu_policy_complete,
    .token_put = nv_xdev_ext_gpu_policy_put,
    .normalize_status = nv_xdev_ext_gpu_policy_normalize,
};

static atomic_t nv_xdev_ext_gpu_dispatch_error_reported = ATOMIC_INIT(0);
static atomic_t nv_xdev_ext_gpu_completion_error_reported = ATOMIC_INIT(0);

static void nv_xdev_ext_gpu_report_policy_errors(
    const struct nv_xdev_ext_gpu_outcome *outcome
)
{
    if (outcome == NULL)
        return;

    if (outcome->dispatch_error != 0 &&
        atomic_cmpxchg(&nv_xdev_ext_gpu_dispatch_error_reported, 0, 1) == 0)
    {
        nv_printf(NV_DBG_WARNINGS,
                  "NVRM: XDP DMA xfer: XDEV_EXT dispatch policy error %d; further errors suppressed\n",
                  outcome->dispatch_error);
    }

    if (outcome->completion_error != 0 &&
        atomic_cmpxchg(&nv_xdev_ext_gpu_completion_error_reported, 0, 1) == 0)
    {
        nv_printf(NV_DBG_WARNINGS,
                  "NVRM: XDP DMA xfer: XDEV_EXT completion policy error %d; further errors suppressed\n",
                  outcome->completion_error);
    }
}

static NvU32 nvidia_p2p_page_size_mappings[NVIDIA_P2P_PAGE_SIZE_COUNT] = {
    NVRM_P2P_PAGESIZE_SMALL_4K, NVRM_P2P_PAGESIZE_BIG_64K, NVRM_P2P_PAGESIZE_BIG_128K
};

static NV_STATUS nvidia_p2p_map_page_size(NvU32 page_size, NvU32 *page_size_index)
{
    NvU32 i;

    for (i = 0; i < NVIDIA_P2P_PAGE_SIZE_COUNT; i++)
    {
        if (nvidia_p2p_page_size_mappings[i] == page_size)
        {
            *page_size_index = i;
            break;
        }
    }

    if (i == NVIDIA_P2P_PAGE_SIZE_COUNT)
        return NV_ERR_GENERIC;

    return NV_OK;
}

static NV_STATUS nv_p2p_insert_dma_mapping(
    struct nv_p2p_mem_info *mem_info,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    NV_STATUS status;
    struct nv_p2p_dma_mapping *node;

    status = os_alloc_mem((void**)&node, sizeof(*node));
    if (status != NV_OK)
    {
        return status;
    }

    down(&mem_info->dma_mapping_list.lock);

    node->dma_mapping = dma_mapping;
    list_add_tail(&node->list_node, &mem_info->dma_mapping_list.list_head);

    up(&mem_info->dma_mapping_list.lock);

    return NV_OK;
}

static struct nvidia_p2p_dma_mapping* nv_p2p_remove_dma_mapping(
    struct nv_p2p_mem_info *mem_info,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    struct nv_p2p_dma_mapping *cur;
    struct nvidia_p2p_dma_mapping *ret_dma_mapping = NULL;

    down(&mem_info->dma_mapping_list.lock);

    list_for_each_entry(cur, &mem_info->dma_mapping_list.list_head, list_node)
    {
        if (dma_mapping == NULL || dma_mapping == cur->dma_mapping)
        {
            ret_dma_mapping = cur->dma_mapping;
            list_del(&cur->list_node);
            os_free_mem(cur);
            break;
        }
    }

    up(&mem_info->dma_mapping_list.lock);

    return ret_dma_mapping;
}

static void nv_p2p_free_dma_mapping(
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    nv_dma_device_t peer_dma_dev = {{ 0 }};
    NvU32 page_size;
    NV_STATUS status;

    peer_dma_dev.dev = &dma_mapping->pci_dev->dev;
    peer_dma_dev.addressable_range.limit = dma_mapping->pci_dev->dma_mask;

    page_size = nvidia_p2p_page_size_mappings[dma_mapping->page_size_type];

    if (dma_mapping->private != NULL)
    {
        /*
         * If OS page size is smaller than P2P page size,
         * page inflation logic applies for DMA unmapping too.
         * Bigger P2P page needs to be split in smaller OS pages.
         */
        if (page_size > PAGE_SIZE)
        {
            NvU64 *os_dma_addresses = NULL;
            NvU32 os_pages_per_p2p_page = page_size;
            NvU32 os_page_count;
            NvU32 index, i, j;

            do_div(os_pages_per_p2p_page, PAGE_SIZE);

            os_page_count = os_pages_per_p2p_page * dma_mapping->entries;

            status = os_alloc_mem((void **)&os_dma_addresses,
                        (os_page_count * sizeof(NvU64)));
            if(WARN_ON(status != NV_OK))
            {
                goto failed;
            }

            index = 0;
            for (i = 0; i < dma_mapping->entries; i++)
            {
                os_dma_addresses[index] = dma_mapping->dma_addresses[i];
                index++;

                for (j = 1; j < os_pages_per_p2p_page; j++)
                {
                    os_dma_addresses[index] = os_dma_addresses[index - 1] + PAGE_SIZE;
                    index++;
                }
            }

            status = nv_dma_unmap_alloc(&peer_dma_dev,
                                        os_page_count,
                                        os_dma_addresses,
                                        &dma_mapping->private);
            WARN_ON(status != NV_OK);

            os_free_mem(os_dma_addresses);
        }
        else
        {
            WARN_ON(page_size != PAGE_SIZE);

            status = nv_dma_unmap_alloc(&peer_dma_dev,
                                        dma_mapping->entries,
                                        dma_mapping->dma_addresses,
                                        &dma_mapping->private);
            WARN_ON(status != NV_OK);
        }
    }
    else
    {
        NvU32 i;
        for (i = 0; i < dma_mapping->entries; i++)
        {
            nv_dma_unmap_peer(&peer_dma_dev, page_size / PAGE_SIZE,
                              dma_mapping->dma_addresses[i]);
        }
    }

failed:
    os_free_mem(dma_mapping->dma_addresses);

    os_free_mem(dma_mapping);
}

static void nv_p2p_free_page_table(
    struct nvidia_p2p_page_table *page_table
)
{
    NvU32 i;
    struct nvidia_p2p_dma_mapping *dma_mapping;
    struct nv_p2p_mem_info *mem_info = NULL;

    mem_info = container_of(page_table, nv_p2p_mem_info_t, page_table);

    dma_mapping = nv_p2p_remove_dma_mapping(mem_info, NULL);
    while (dma_mapping != NULL)
    {
        nv_p2p_free_dma_mapping(dma_mapping);

        dma_mapping = nv_p2p_remove_dma_mapping(mem_info, NULL);
    }

    for (i = 0; i < page_table->entries; i++)
    {
        NV_KMEM_CACHE_FREE(page_table->pages[i], nvidia_p2p_page_t_cache);
    }

    if (page_table->gpu_uuid != NULL)
    {
        os_free_mem(page_table->gpu_uuid);
    }

    if (page_table->pages != NULL)
    {
        os_free_mem(page_table->pages);
    }

    os_free_mem(mem_info);
}

static NV_STATUS nv_p2p_put_pages(
    nv_p2p_page_table_type_t pt_type,
    nvidia_stack_t * sp,
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    struct nvidia_p2p_page_table **page_table
)
{
    NV_STATUS status;

    /*
     * rm_p2p_put_pages returns NV_OK if the page_table was found and
     * got unlinked from the RM's tracker (atomically). This ensures that
     * RM's tear-down path does not race with this path.
     *
     * rm_p2p_put_pages returns NV_ERR_OBJECT_NOT_FOUND if the page_table
     * was already unlinked.
     */
    if (pt_type == NV_P2P_PAGE_TABLE_TYPE_PERSISTENT)
    {
        struct nv_p2p_mem_info *mem_info = NULL;

        /*
         * It is safe to access persistent page_table as there is no async
         * callback which can free it unlike non-persistent page_table.
         */
        mem_info = container_of(*page_table, nv_p2p_mem_info_t, page_table);
        status = rm_p2p_put_pages_persistent(sp, mem_info->private, *page_table, mem_info->mig_info);
    }
    else
    {
        status = rm_p2p_put_pages(sp, p2p_token, va_space,
                                  virtual_address, *page_table);
    }

    if (status == NV_OK)
    {
        nv_p2p_free_page_table(*page_table);
        *page_table = NULL;
    }
    else if ((pt_type == NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT) &&
             (status == NV_ERR_OBJECT_NOT_FOUND))
    {
        status = NV_OK;
        *page_table = NULL;
    }
    else
    {
        WARN_ON(status != NV_OK);
    }

    return status;
}

void NV_API_CALL nv_p2p_free_platform_data(
    void *data
)
{
    if (data == NULL)
    {
        WARN_ON(data == NULL);
        return;
    }

    nv_p2p_free_page_table((struct nvidia_p2p_page_table*)data);
}

int nvidia_p2p_init_mapping(
    uint64_t p2p_token,
    struct nvidia_p2p_params *params,
    void (*destroy_callback)(void *data),
    void *data
)
{
    return -ENOTSUPP;
}

NV_EXPORT_SYMBOL(nvidia_p2p_init_mapping);

int nvidia_p2p_destroy_mapping(uint64_t p2p_token)
{
    return -ENOTSUPP;
}

NV_EXPORT_SYMBOL(nvidia_p2p_destroy_mapping);

static void nv_p2p_mem_info_free_callback(void *data)
{
    nv_p2p_mem_info_t *mem_info = (nv_p2p_mem_info_t*) data;

    mem_info->free_callback(mem_info->data);

    nv_p2p_free_platform_data(&mem_info->page_table);
}

static int nv_p2p_get_pages(
    nv_p2p_page_table_type_t pt_type,
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    uint64_t length,
    uint8_t  flags,
    struct nvidia_p2p_page_table **page_table,
    void (*free_callback)(void * data),
    void *data
)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    struct nvidia_p2p_page *page;
    struct nv_p2p_mem_info *mem_info = NULL;
    NvU32 entries;
    NvU32 *wreqmb_h = NULL;
    NvU32 *rreqmb_h = NULL;
    NvU64 *physical_addresses = NULL;
    NvU32 page_count;
    NvU32 i = 0;
    NvBool bGetPages = NV_FALSE;
    NvBool bGetUuid = NV_FALSE;
    NvU32 page_size = NVRM_P2P_PAGESIZE_BIG_64K;
    NvU32 page_size_index;
    NvU64 temp_length;
    NvU8 *gpu_uuid = NULL;
    NvU8 uuid[NVIDIA_P2P_GPU_UUID_LEN] = {0};
    NvBool force_pcie = !!(flags & NVIDIA_P2P_FLAGS_FORCE_BAR1_MAPPING);
    NvBool cpu_cacheable;
    int rc;

    if (!NV_IS_ALIGNED64(virtual_address, NVRM_P2P_PAGESIZE_BIG_64K) ||
        !NV_IS_ALIGNED64(length, NVRM_P2P_PAGESIZE_BIG_64K))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: Invalid argument in nv_p2p_get_pages,"
                  "address or length are not aligned "
                  "address=0x%llx, length=0x%llx\n",
                  virtual_address, length);
        return -EINVAL;
    }

    // Forced PCIe mappings are not supported for non-persistent APIs
    if ((free_callback != NULL) && force_pcie)
    {
        return -ENOTSUPP;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    *page_table = NULL;
    status = os_alloc_mem((void **)&mem_info, sizeof(*mem_info));
    if (status != NV_OK)
    {
        goto failed;
    }

    memset(mem_info, 0, sizeof(*mem_info));

    INIT_LIST_HEAD(&mem_info->dma_mapping_list.list_head);
    NV_INIT_MUTEX(&mem_info->dma_mapping_list.lock);

    mem_info->force_pcie = force_pcie;

    *page_table = &(mem_info->page_table);

    /*
     * assign length to temporary variable since do_div macro does in-place
     * division
     */
    temp_length = length;
    do_div(temp_length, page_size);
    page_count = temp_length;

    if (length & (page_size - 1))
    {
        page_count++;
    }

    status = os_alloc_mem((void **)&physical_addresses,
            (page_count * sizeof(NvU64)));
    if (status != NV_OK)
    {
        goto failed;
    }
    status = os_alloc_mem((void **)&wreqmb_h, (page_count * sizeof(NvU32)));
    if (status != NV_OK)
    {
        goto failed;
    }
    status = os_alloc_mem((void **)&rreqmb_h, (page_count * sizeof(NvU32)));
    if (status != NV_OK)
    {
        goto failed;
    }

    if (pt_type == NV_P2P_PAGE_TABLE_TYPE_PERSISTENT)
    {
        void *gpu_info = NULL;

        if ((p2p_token != 0) || (va_space != 0))
        {
            status = -ENOTSUPP;
            goto failed;
        }

        status = rm_p2p_get_gpu_info(sp, virtual_address, length,
                                     &gpu_uuid, &gpu_info);
        if (status != NV_OK)
        {
            goto failed;
        }

        (*page_table)->gpu_uuid = gpu_uuid;

        rc = nvidia_dev_get_uuid(gpu_uuid, sp);
        if (rc != 0)
        {
            status = NV_ERR_GPU_UUID_NOT_FOUND;
            goto failed;
        }

        os_mem_copy(uuid, gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN);

        bGetUuid = NV_TRUE;

        status = rm_p2p_get_pages_persistent(sp, virtual_address, length,
                                             &mem_info->private,
                                             physical_addresses, &entries,
                                             force_pcie, *page_table, gpu_info,
                                             &mem_info->mig_info, &cpu_cacheable);
        if (status != NV_OK)
        {
            goto failed;
        }
    }
    else
    {
        // Get regular old-style, non-persistent mappings
        status = rm_p2p_get_pages(sp, p2p_token, va_space,
                virtual_address, length, physical_addresses, wreqmb_h,
                rreqmb_h, &entries, &gpu_uuid, *page_table, &cpu_cacheable);
        if (status != NV_OK)
        {
            goto failed;
        }

        (*page_table)->gpu_uuid = gpu_uuid;
    }

    bGetPages = NV_TRUE;

    status = os_alloc_mem((void *)&(*page_table)->pages,
             (entries * sizeof(page)));
    if (status != NV_OK)
    {
        goto failed;
    }

    (*page_table)->version = NVIDIA_P2P_PAGE_TABLE_VERSION;

    for (i = 0; i < entries; i++)
    {
        page = NV_KMEM_CACHE_ALLOC(nvidia_p2p_page_t_cache);
        if (page == NULL)
        {
            status = NV_ERR_NO_MEMORY;
            goto failed;
        }

        memset(page, 0, sizeof(*page));

        page->physical_address = physical_addresses[i];
        page->registers.fermi.wreqmb_h = wreqmb_h[i];
        page->registers.fermi.rreqmb_h = rreqmb_h[i];

        (*page_table)->pages[i] = page;
        (*page_table)->entries++;
    }

    status = nvidia_p2p_map_page_size(page_size, &page_size_index);
    if (status != NV_OK)
    {
        goto failed;
    }

    (*page_table)->page_size = page_size_index;

    if (cpu_cacheable)
    {
        (*page_table)->flags |= NVIDIA_P2P_PAGE_TABLE_FLAGS_CPU_CACHEABLE;
    }

    os_free_mem(physical_addresses);
    physical_addresses = NULL;

    os_free_mem(wreqmb_h);
    wreqmb_h = NULL;

    os_free_mem(rreqmb_h);
    rreqmb_h = NULL;

    if (free_callback != NULL)
    {
        mem_info->free_callback = free_callback;
        mem_info->data          = data;

        status = rm_p2p_register_callback(sp, p2p_token, virtual_address, length,
                                          *page_table, nv_p2p_mem_info_free_callback, mem_info);
        if (status != NV_OK)
        {
            goto failed;
        }
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);

failed:
    if (physical_addresses != NULL)
    {
        os_free_mem(physical_addresses);
    }

    if (wreqmb_h != NULL)
    {
        os_free_mem(wreqmb_h);
    }

    if (rreqmb_h != NULL)
    {
        os_free_mem(rreqmb_h);
    }

    if (bGetPages)
    {
        (void)nv_p2p_put_pages(pt_type, sp, p2p_token, va_space,
                               virtual_address, page_table);
    }

    if (bGetUuid)
    {
        nvidia_dev_put_uuid(uuid, sp);
    }

    if (*page_table != NULL)
    {
        nv_p2p_free_page_table(*page_table);
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

int nvidia_p2p_get_pages(
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    uint64_t length,
    struct nvidia_p2p_page_table **page_table,
    void (*free_callback)(void * data),
    void *data
)
{
    if (free_callback == NULL)
    {
        return -EINVAL;
    }

    return nv_p2p_get_pages(NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT,
                            p2p_token, va_space, virtual_address,
                            length, NVIDIA_P2P_FLAGS_DEFAULT,
                            page_table, free_callback, data);
}
NV_EXPORT_SYMBOL(nvidia_p2p_get_pages);

int nvidia_p2p_get_pages_persistent(
    uint64_t virtual_address,
    uint64_t length,
    struct nvidia_p2p_page_table **page_table,
    uint32_t flags
)
{
    return nv_p2p_get_pages(NV_P2P_PAGE_TABLE_TYPE_PERSISTENT, 0, 0,
                            virtual_address, length, flags, page_table,
                            NULL, NULL);
}
NV_EXPORT_SYMBOL(nvidia_p2p_get_pages_persistent);

/*
 * This function is a no-op, but is left in place (for now), in order to allow
 * third-party callers to build and run without errors or warnings. This is OK,
 * because the missing functionality is provided by nv_p2p_free_platform_data,
 * which is being called as part of the RM's cleanup path.
 */
int nvidia_p2p_free_page_table(struct nvidia_p2p_page_table *page_table)
{
    return 0;
}

NV_EXPORT_SYMBOL(nvidia_p2p_free_page_table);

int nvidia_p2p_put_pages(
    uint64_t p2p_token,
    uint32_t va_space,
    uint64_t virtual_address,
    struct nvidia_p2p_page_table *page_table
)
{
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    int rc = 0;

    if (page_table == NULL)
    {
        return 0;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return -ENOMEM;
    }

    status = nv_p2p_put_pages(NV_P2P_PAGE_TABLE_TYPE_NON_PERSISTENT,
                              sp, p2p_token, va_space,
                              virtual_address, &page_table);
    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}
NV_EXPORT_SYMBOL(nvidia_p2p_put_pages);

int nvidia_p2p_put_pages_persistent(
    uint64_t virtual_address,
    struct nvidia_p2p_page_table *page_table,
    uint32_t flags
)
{
    NvU8 uuid[NVIDIA_P2P_GPU_UUID_LEN] = {0};
    NV_STATUS status;
    nvidia_stack_t *sp = NULL;
    int rc = 0;

    if (flags != 0)
    {
        return -EINVAL;
    }

    if (page_table == NULL)
    {
        return 0;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return -ENOMEM;
    }

    os_mem_copy(uuid, page_table->gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN);

    status = nv_p2p_put_pages(NV_P2P_PAGE_TABLE_TYPE_PERSISTENT,
                              sp, 0, 0, virtual_address, &page_table);

    nvidia_dev_put_uuid(uuid, sp);

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}
NV_EXPORT_SYMBOL(nvidia_p2p_put_pages_persistent);

int nvidia_p2p_dma_map_pages(
    struct pci_dev *peer,
    struct nvidia_p2p_page_table *page_table,
    struct nvidia_p2p_dma_mapping **dma_mapping
)
{
    NV_STATUS status;
    nv_dma_device_t peer_dma_dev = {{ 0 }};
    nvidia_stack_t *sp = NULL;
    NvU64 *dma_addresses = NULL;
    NvU32 page_count;
    NvU32 page_size;
    enum nvidia_p2p_page_size_type page_size_type;
    struct nv_p2p_mem_info *mem_info = NULL;
    NvU32 i;
    void *priv;
    int rc;

    if (peer == NULL || page_table == NULL || dma_mapping == NULL ||
        page_table->gpu_uuid == NULL)
    {
        return -EINVAL;
    }

    mem_info = container_of(page_table, nv_p2p_mem_info_t, page_table);

    //
    // Only CPU mappings are supported for forced PCIe config through
    // nv-p2p APIs. IO mappings will not be supported.
    //
    if (mem_info->force_pcie)
    {
        return -ENOTSUPP;
    }

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
    {
        return rc;
    }

    *dma_mapping = NULL;
    status = os_alloc_mem((void **)dma_mapping, sizeof(**dma_mapping));
    if (status != NV_OK)
    {
        goto failed;
    }
    memset(*dma_mapping, 0, sizeof(**dma_mapping));

    page_count = page_table->entries;

    status = os_alloc_mem((void **)&dma_addresses,
            (page_count * sizeof(NvU64)));
    if (status != NV_OK)
    {
        goto failed;
    }

    page_size_type = page_table->page_size;

    BUG_ON((page_size_type <= NVIDIA_P2P_PAGE_SIZE_4KB) ||
           (page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT));

    peer_dma_dev.dev = &peer->dev;
    peer_dma_dev.addressable_range.limit = peer->dma_mask;

    page_size = nvidia_p2p_page_size_mappings[page_size_type];

    for (i = 0; i < page_count; i++)
    {
        dma_addresses[i] = page_table->pages[i]->physical_address;
    }

    status = rm_p2p_dma_map_pages(sp, &peer_dma_dev,
            page_table->gpu_uuid, page_size, page_count, dma_addresses, &priv);
    if (status != NV_OK)
    {
        goto failed;
    }

    (*dma_mapping)->version = NVIDIA_P2P_DMA_MAPPING_VERSION;
    (*dma_mapping)->page_size_type = page_size_type;
    (*dma_mapping)->entries = page_count;
    (*dma_mapping)->dma_addresses = dma_addresses;
    (*dma_mapping)->private = priv;
    (*dma_mapping)->pci_dev = peer;

    /*
     * All success, it is safe to insert dma_mapping now.
     */
    status = nv_p2p_insert_dma_mapping(mem_info, *dma_mapping);
    if (status != NV_OK)
    {
        goto failed_insert;
    }

    nv_kmem_cache_free_stack(sp);

    return 0;

failed_insert:
    nv_p2p_free_dma_mapping(*dma_mapping);
    dma_addresses = NULL;
    *dma_mapping = NULL;

failed:
    if (dma_addresses != NULL)
    {
        os_free_mem(dma_addresses);
    }

    if (*dma_mapping != NULL)
    {
        os_free_mem(*dma_mapping);
        *dma_mapping = NULL;
    }

    nv_kmem_cache_free_stack(sp);

    return nvidia_p2p_map_status(status);
}

NV_EXPORT_SYMBOL(nvidia_p2p_dma_map_pages);

int nvidia_p2p_dma_unmap_pages(
    struct pci_dev *peer,
    struct nvidia_p2p_page_table *page_table,
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    struct nv_p2p_mem_info *mem_info = NULL;

    if (peer == NULL || dma_mapping == NULL || page_table == NULL)
    {
        return -EINVAL;
    }

    mem_info = container_of(page_table, nv_p2p_mem_info_t, page_table);

    /*
     * nv_p2p_remove_dma_mapping returns dma_mapping if the dma_mapping was
     * found and got unlinked from the mem_info->dma_mapping_list (atomically).
     * This ensures that the RM's tear-down path does not race with this path.
     *
     * nv_p2p_remove_dma_mappings returns NULL if the dma_mapping was already
     * unlinked.
     */
    if (nv_p2p_remove_dma_mapping(mem_info, dma_mapping) == NULL)
    {
        return 0;
    }

    WARN_ON(peer != dma_mapping->pci_dev);

    BUG_ON((dma_mapping->page_size_type <= NVIDIA_P2P_PAGE_SIZE_4KB) ||
           (dma_mapping->page_size_type >= NVIDIA_P2P_PAGE_SIZE_COUNT));

    nv_p2p_free_dma_mapping(dma_mapping);

    return 0;
}

NV_EXPORT_SYMBOL(nvidia_p2p_dma_unmap_pages);

/*
 * This function is a no-op, but is left in place (for now), in order to allow
 * third-party callers to build and run without errors or warnings. This is OK,
 * because the missing functionality is provided by nv_p2p_free_platform_data,
 * which is being called as part of the RM's cleanup path.
 */
int nvidia_p2p_free_dma_mapping(
    struct nvidia_p2p_dma_mapping *dma_mapping
)
{
    return 0;
}

NV_EXPORT_SYMBOL(nvidia_p2p_free_dma_mapping);

int nvidia_p2p_register_rsync_driver(
    nvidia_p2p_rsync_driver_t *driver,
    void *data
)
{
    if (driver == NULL)
    {
        return -EINVAL;
    }

    if (!NVIDIA_P2P_RSYNC_DRIVER_VERSION_COMPATIBLE(driver))
    {
        return -EINVAL;
    }

    if (driver->get_relaxed_ordering_mode == NULL ||
        driver->put_relaxed_ordering_mode == NULL ||
        driver->wait_for_rsync == NULL)
    {
        return -EINVAL;
    }

    return nv_register_rsync_driver(driver->get_relaxed_ordering_mode,
                                    driver->put_relaxed_ordering_mode,
                                    driver->wait_for_rsync, data);
}

NV_EXPORT_SYMBOL(nvidia_p2p_register_rsync_driver);

void nvidia_p2p_unregister_rsync_driver(
    nvidia_p2p_rsync_driver_t *driver,
    void *data
)
{
    if (driver == NULL)
    {
        WARN_ON(1);
        return;
    }

    if (!NVIDIA_P2P_RSYNC_DRIVER_VERSION_COMPATIBLE(driver))
    {
        WARN_ON(1);
        return;
    }

    if (driver->get_relaxed_ordering_mode == NULL ||
        driver->put_relaxed_ordering_mode == NULL ||
        driver->wait_for_rsync == NULL)
    {
        WARN_ON(1);
        return;
    }

    nv_unregister_rsync_driver(driver->get_relaxed_ordering_mode,
                               driver->put_relaxed_ordering_mode,
                               driver->wait_for_rsync, data);
}

NV_EXPORT_SYMBOL(nvidia_p2p_unregister_rsync_driver);

int nvidia_p2p_get_rsync_registers(
    nvidia_p2p_rsync_reg_info_t **reg_info
)
{
    // TODO: Remove this interface.
    return -ENODEV;
}

NV_EXPORT_SYMBOL(nvidia_p2p_get_rsync_registers);

void nvidia_p2p_put_rsync_registers(
    nvidia_p2p_rsync_reg_info_t *reg_info
)
{
    // TODO: Remove this interface.  There is nothing to do because
    // nvidia_p2p_get_rsync_registers always fails.
}

NV_EXPORT_SYMBOL(nvidia_p2p_put_rsync_registers);

/*
 * Generic P2P UMEM Buffer Support
 *
 * Provides unified page pinning and DMA support for:
 * - CXL memory expanders
 * - AF_XDP UMEM (zero-copy networking)
 * - Generic user memory regions for GPU DMA
 *
 * Supports both directions:
 * - GPU DMA to/from UMEM (Copy Engine transfers)
 * - GPU memory registered as UMEM backing store
 */

#include <linux/sched/signal.h>
#include <linux/net.h>
#include <linux/netdevice.h>

// Try to include AF_XDP headers if available
#if defined(CONFIG_XDP_SOCKETS) || defined(CONFIG_XDP_SOCKETS_MODULE)
#include <net/xdp_sock_drv.h>
#define NV_XDP_UMEM_SUPPORT 1
#else
#define NV_XDP_UMEM_SUPPORT 0
#endif

// Buffer type enumeration
typedef enum {
    NV_P2P_BUFFER_TYPE_GENERIC = 0,    // Generic user memory
    NV_P2P_BUFFER_TYPE_CXL,            // CXL memory expander
    NV_P2P_BUFFER_TYPE_HOST_REGION,    // Explicitly registered host pages
    NV_P2P_BUFFER_TYPE_GPU_EXPORT,     // GPU memory exported as UMEM
    NV_P2P_BUFFER_TYPE_VERIFIED_XSK,   // Page-identical live AF_XDP UMEM
} nv_p2p_buffer_type_t;

// Global tracking for pinned buffers (generic)
typedef struct {
    spinlock_t      lock;
    NvU64           totalPinnedBytes;      // Total bytes currently pinned
    NvU64           totalPinnedPages;      // Total pages currently pinned
    NvU32           numBuffers;            // Number of active buffers
    NvU64           maxPinnedBytes;        // Maximum allowed pinned bytes (0 = no limit)
    NvU32           maxBuffers;            // Maximum number of buffers (0 = no limit)
    NvBool          bInitialized;
} nv_p2p_umem_tracker_t;

static nv_p2p_umem_tracker_t g_p2pUmemTracker = {
    .totalPinnedBytes = 0,
    .totalPinnedPages = 0,
    .numBuffers = 0,
    .maxPinnedBytes = 0,           // Will be set based on system memory
    .maxBuffers = 256,             // Default max buffers
    .bInitialized = NV_FALSE
};

static DEFINE_MUTEX(g_p2pUmemTrackerInitLock);

// Per-buffer structure (generic for all buffer types)
typedef struct {
    NvU64                   userVirtAddr;
    NvU64                   size;
    NvU32                   pageCount;
    NvU32                   pageSize;       // Track actual page size (4K or 2M)
    NvU32                   frameSize;      // XDP frame size (for UMEM)
    NvU64                  *physAddrs;
    struct page           **pages;
    NvBool                  bHugePages;     // Whether huge pages are used
    NvU32                   refCount;       // Reference count for buffer reuse
    nv_p2p_buffer_type_t    bufferType;     // Type of buffer
    struct list_head        listNode;       // For tracking in global list
    void                   *gpuMemHandle;   // GPU memory handle (for GPU export)
    NvU64                   gpuOffset;      // GPU memory offset
    NvBool                  bGpuBacked;     // Whether backed by GPU memory
    struct mm_struct       *pinMm;          // Host region: mm charged in locked_vm
} nv_p2p_umem_buffer_t;

// Backwards compatibility typedef
typedef nv_p2p_umem_buffer_t cxl_pinned_buffer_t;

// Initialize the global tracker (called on first use)
static void nv_p2p_umem_init_tracker(void)
{
    struct sysinfo si;

    if (smp_load_acquire(&g_p2pUmemTracker.bInitialized))
        return;

    mutex_lock(&g_p2pUmemTrackerInitLock);
    if (smp_load_acquire(&g_p2pUmemTracker.bInitialized))
    {
        mutex_unlock(&g_p2pUmemTrackerInitLock);
        return;
    }

    spin_lock_init(&g_p2pUmemTracker.lock);

    // Get system memory info to set reasonable limits
    si_meminfo(&si);

    // Default: allow pinning up to 90% of total system RAM for P2P workloads
    g_p2pUmemTracker.maxPinnedBytes = (NvU64)si.totalram * si.mem_unit * 9 / 10;
    smp_store_release(&g_p2pUmemTracker.bInitialized, NV_TRUE);
    mutex_unlock(&g_p2pUmemTrackerInitLock);
}

/* Reserve all tracker counters in one lock hold. */
static inline NV_STATUS nv_p2p_umem_reserve_quota(NvU64 size, NvU32 pageCount)
{
    struct nv_xdev_ext_umem_quota quota;
    unsigned long flags;
    int ret;

    nv_p2p_umem_init_tracker();

    spin_lock_irqsave(&g_p2pUmemTracker.lock, flags);
    quota.bytes = g_p2pUmemTracker.totalPinnedBytes;
    quota.pages = g_p2pUmemTracker.totalPinnedPages;
    quota.buffers = g_p2pUmemTracker.numBuffers;
    quota.max_bytes = g_p2pUmemTracker.maxPinnedBytes;
    quota.max_buffers = g_p2pUmemTracker.maxBuffers;
    ret = nv_xdev_ext_umem_quota_reserve(&quota, size, pageCount);
    if (ret == 0)
    {
        g_p2pUmemTracker.totalPinnedBytes = quota.bytes;
        g_p2pUmemTracker.totalPinnedPages = quota.pages;
        g_p2pUmemTracker.numBuffers = quota.buffers;
    }
    spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);

    if (ret == -ENOSPC)
        return NV_ERR_INSUFFICIENT_RESOURCES;
    if (ret != 0)
        return NV_ERR_INVALID_ARGUMENT;
    return NV_OK;
}

/* Release the exact reservation or leave every counter untouched. */
static inline NV_STATUS nv_p2p_umem_release_quota(NvU64 size, NvU32 pageCount)
{
    struct nv_xdev_ext_umem_quota quota;
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&g_p2pUmemTracker.lock, flags);
    quota.bytes = g_p2pUmemTracker.totalPinnedBytes;
    quota.pages = g_p2pUmemTracker.totalPinnedPages;
    quota.buffers = g_p2pUmemTracker.numBuffers;
    quota.max_bytes = g_p2pUmemTracker.maxPinnedBytes;
    quota.max_buffers = g_p2pUmemTracker.maxBuffers;
    ret = nv_xdev_ext_umem_quota_release(&quota, size, pageCount);
    if (ret == 0)
    {
        g_p2pUmemTracker.totalPinnedBytes = quota.bytes;
        g_p2pUmemTracker.totalPinnedPages = quota.pages;
        g_p2pUmemTracker.numBuffers = quota.buffers;
    }
    spin_unlock_irqrestore(&g_p2pUmemTracker.lock, flags);

    if (WARN_ON_ONCE(ret != 0))
        return NV_ERR_INVALID_STATE;
    return NV_OK;
}

static nv_xdev_ext_quota_u32 nv_p2p_umem_pin_reserve(void *mm, NvU64 bytes,
                                                NvU32 pages)
{
    (void)mm;
    return nv_p2p_umem_reserve_quota(bytes, pages);
}

static nv_xdev_ext_quota_u32 nv_p2p_umem_pin_release(void *mm, NvU64 bytes,
                                                NvU32 pages)
{
    (void)mm;
    return nv_p2p_umem_release_quota(bytes, pages);
}

/* Long-term pins count in the pinning mm's locked_vm (RLIMIT_MEMLOCK). */
static nv_xdev_ext_quota_u32 nv_p2p_umem_pin_lock(void *mm, NvU32 pages)
{
    if (account_locked_vm(mm, pages, true) != 0)
        return NV_ERR_INSUFFICIENT_RESOURCES;
    return NV_OK;
}

static void nv_p2p_umem_pin_unlock(void *mm, NvU32 pages)
{
    account_locked_vm(mm, pages, false);
}

static const struct nv_xdev_ext_pin_charge_ops nv_p2p_umem_pin_charge_ops = {
    .reserve = nv_p2p_umem_pin_reserve,
    .release = nv_p2p_umem_pin_release,
    .lock = nv_p2p_umem_pin_lock,
    .unlock = nv_p2p_umem_pin_unlock,
};

// Backward compatibility aliases
#define cxl_init_tracker        nv_p2p_umem_init_tracker
#define cxl_reserve_quota       nv_p2p_umem_reserve_quota
#define cxl_release_quota       nv_p2p_umem_release_quota

NV_STATUS NV_API_CALL nv_pin_cxl_buffer(
    NvU64   userVirtAddr,
    NvU64   size,
    void  **ppHandle
)
{
    cxl_pinned_buffer_t *pBuffer = NULL;
    unsigned long startAddr;
    NvU32 pageCount;
    int ret;
    NvU32 i;
    NV_STATUS status;
    NvBool bLargeAlloc;
    NvBool bReserved = NV_FALSE;

    if (unlikely(size == 0 || ppHandle == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: invalid argument (size=%llu, ppHandle=%p)\n",
                  (unsigned long long)size, ppHandle);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check for overflow
    if (unlikely(userVirtAddr > ULONG_MAX - size))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: address overflow (addr=0x%llx, size=0x%llx)\n",
                  (unsigned long long)userVirtAddr, (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    startAddr = userVirtAddr & PAGE_MASK;
    pageCount = ((userVirtAddr + size - 1) >> PAGE_SHIFT) - (startAddr >> PAGE_SHIFT) + 1;

    // Sanity check (max ~1TB)
    if (unlikely(pageCount == 0 || pageCount > (1UL << 28)))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: invalid page count %u (size=0x%llx)\n",
                  pageCount, (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check limits before allocating
    status = cxl_reserve_quota(size, pageCount);
    if (unlikely(status != NV_OK))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: resource limit exceeded (size=0x%llx, pages=%u)\n",
                  (unsigned long long)size, pageCount);
        return status;
    }
    bReserved = NV_TRUE;

    pBuffer = kzalloc(sizeof(*pBuffer), GFP_KERNEL);
    if (unlikely(pBuffer == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: failed to allocate buffer struct\n");
        if (bReserved)
            cxl_release_quota(size, pageCount);
        return NV_ERR_NO_MEMORY;
    }

    // Use vmalloc for large arrays (>512 entries)
    bLargeAlloc = (pageCount > 512);

    if (bLargeAlloc)
    {
        pBuffer->pages = vmalloc(pageCount * sizeof(struct page *));
        pBuffer->physAddrs = vmalloc(pageCount * sizeof(NvU64));
    }
    else
    {
        pBuffer->pages = kmalloc(pageCount * sizeof(struct page *), GFP_KERNEL);
        pBuffer->physAddrs = kmalloc(pageCount * sizeof(NvU64), GFP_KERNEL);
    }

    if (unlikely(pBuffer->pages == NULL || pBuffer->physAddrs == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: failed to allocate page arrays (%u pages)\n", pageCount);
        goto fail_alloc;
    }

    // Pin user pages
    nv_mmap_read_lock(current->mm);
    ret = NV_PIN_USER_PAGES(startAddr, pageCount, FOLL_WRITE, pBuffer->pages);
    nv_mmap_read_unlock(current->mm);

    if (unlikely(ret != pageCount))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: page pinning failed - got %d, expected %u (addr=0x%lx)\n",
                  ret, pageCount, startAddr);
        if (ret > 0)
        {
            for (i = 0; i < ret; i++)
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }
        goto fail_alloc;
    }

    // Convert to physical addresses with validation
    for (i = 0; i < pageCount; i++)
    {
        if (unlikely(pBuffer->pages[i] == NULL))
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: NULL page at index %u\n", i);
            // Unpin pages we've processed so far
            for (; i > 0; i--)
                NV_UNPIN_USER_PAGE(pBuffer->pages[i - 1]);
            goto fail_alloc;
        }
        pBuffer->physAddrs[i] = page_to_phys(pBuffer->pages[i]);

        // Sanity check physical address
        if (unlikely(pBuffer->physAddrs[i] == 0))
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL pin: zero physical address at page %u\n", i);
        }
    }

    pBuffer->userVirtAddr = userVirtAddr;
    pBuffer->size = size;
    pBuffer->pageCount = pageCount;
    pBuffer->pageSize = PAGE_SIZE;
    pBuffer->refCount = 1;
    pBuffer->bHugePages = NV_FALSE;

    *ppHandle = pBuffer;
    return NV_OK;

fail_alloc:
    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }
    if (pBuffer->pages)
    {
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }
    kfree(pBuffer);
    if (bReserved)
        cxl_release_quota(size, pageCount);
    return NV_ERR_NO_MEMORY;
}

NV_STATUS NV_API_CALL nv_unpin_cxl_buffer(void *pHandle)
{
    cxl_pinned_buffer_t *pBuffer = (cxl_pinned_buffer_t *)pHandle;
    NvU32 i;
    NvU64 savedSize;
    NvU32 savedPageCount;
    NvBool bLargeAlloc;
    NV_STATUS status;

    if (unlikely(pBuffer == NULL))
        return NV_ERR_INVALID_ARGUMENT;

    savedSize = pBuffer->size;
    savedPageCount = pBuffer->pageCount;
    bLargeAlloc = (savedPageCount > 512);

    // Unpin pages
    if (pBuffer->pages)
    {
        for (i = 0; i < savedPageCount; i++)
        {
            if (pBuffer->pages[i])
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }

        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }

    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }

    kfree(pBuffer);
    status = cxl_release_quota(savedSize, savedPageCount);

    return status;
}

NV_STATUS NV_API_CALL nv_get_cxl_buffer_pages(
    void    *pHandle,
    NvU64  **ppPhysAddrs,
    NvU32   *pPageCount
)
{
    cxl_pinned_buffer_t *pBuffer = (cxl_pinned_buffer_t *)pHandle;

    if (unlikely(pBuffer == NULL || ppPhysAddrs == NULL || pPageCount == NULL))
        return NV_ERR_INVALID_ARGUMENT;

    if (unlikely(pBuffer->physAddrs == NULL || pBuffer->pageCount == 0))
        return NV_ERR_INVALID_STATE;

    *ppPhysAddrs = pBuffer->physAddrs;
    *pPageCount = pBuffer->pageCount;

    return NV_OK;
}

/*
 * CXL Buffer Huge Page Pinning (2MB pages)
 *
 * Pins user pages using huge pages (2MB) for CXL buffer DMA.
 * Huge pages significantly reduce page table overhead for large transfers.
 */
#define CXL_HUGEPAGE_SIZE       (2ULL * 1024 * 1024)  // 2MB
#define CXL_HUGEPAGE_SHIFT      21

NV_STATUS NV_API_CALL nv_pin_cxl_buffer_hugepages(
    NvU64   userVirtAddr,
    NvU64   size,
    NvU32   requestedPageSize,
    void  **ppHandle
)
{
    cxl_pinned_buffer_t *pBuffer = NULL;
    unsigned long startAddr;
    NvU32 pageCount;
    NvU32 actualPageSize;
    int ret;
    NvU32 i;
    NV_STATUS status;
    NvBool bLargeAlloc;
    NvBool bUseHugePages = NV_FALSE;
    NvBool bReserved = NV_FALSE;

    if (unlikely(size == 0 || ppHandle == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: invalid argument\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

#if NV_P2P_UMEM_STRICT_SECURITY_CHECKS
    if (unlikely(size > NV_P2P_UMEM_MAX_PIN_SIZE))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: CXL hugepage pin: size exceeds cap (size=0x%llx)\n",
                  (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }
#endif

    if (unlikely(userVirtAddr > ULONG_MAX - size))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: CXL hugepage pin: invalid range (addr=0x%llx, size=0x%llx)\n",
                  (unsigned long long)userVirtAddr, (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check if we can use huge pages (both address and size must be 2MB aligned)
    if (requestedPageSize == CXL_HUGEPAGE_SIZE &&
        (userVirtAddr & (CXL_HUGEPAGE_SIZE - 1)) == 0 &&
        (size & (CXL_HUGEPAGE_SIZE - 1)) == 0 &&
        size >= CXL_HUGEPAGE_SIZE)
    {
        bUseHugePages = NV_TRUE;
        actualPageSize = CXL_HUGEPAGE_SIZE;
        startAddr = userVirtAddr;
        pageCount = (NvU32)(size >> CXL_HUGEPAGE_SHIFT);
        nv_printf(NV_DBG_INFO, "NVRM: CXL hugepage pin: using 2MB pages (%u pages)\n", pageCount);
    }
    else
    {
        // Fall back to 4K pages
        actualPageSize = PAGE_SIZE;
        startAddr = userVirtAddr & PAGE_MASK;
        pageCount = ((userVirtAddr + size - 1) >> PAGE_SHIFT) - (startAddr >> PAGE_SHIFT) + 1;
        nv_printf(NV_DBG_INFO, "NVRM: CXL hugepage pin: falling back to 4K pages (%u pages)\n", pageCount);
    }

    if (unlikely(pageCount == 0 || pageCount > NV_P2P_UMEM_MAX_PIN_PAGES))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: invalid page count %u\n",
                  pageCount);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Check limits
    status = cxl_reserve_quota(size, pageCount);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: resource limit exceeded\n");
        return status;
    }
    bReserved = NV_TRUE;

    // Allocate buffer structure
    pBuffer = kzalloc(sizeof(cxl_pinned_buffer_t), GFP_KERNEL);
    if (pBuffer == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: failed to allocate buffer struct\n");
        if (bReserved)
            cxl_release_quota(size, pageCount);
        return NV_ERR_NO_MEMORY;
    }

    pBuffer->userVirtAddr = userVirtAddr;
    pBuffer->size = size;
    pBuffer->pageCount = pageCount;
    pBuffer->pageSize = actualPageSize;
    pBuffer->bHugePages = bUseHugePages;
    pBuffer->refCount = 1;

    bLargeAlloc = (pageCount > 512);

    // Allocate page tracking arrays
    if (bLargeAlloc)
    {
        pBuffer->physAddrs = vmalloc(pageCount * sizeof(NvU64));
        pBuffer->pages = vmalloc(pageCount * sizeof(struct page *));
    }
    else
    {
        pBuffer->physAddrs = kmalloc(pageCount * sizeof(NvU64), GFP_KERNEL);
        pBuffer->pages = kmalloc(pageCount * sizeof(struct page *), GFP_KERNEL);
    }

    if (pBuffer->physAddrs == NULL || pBuffer->pages == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: failed to allocate arrays\n");
        goto fail_alloc;
    }

    memset(pBuffer->pages, 0, pageCount * sizeof(struct page *));
    memset(pBuffer->physAddrs, 0, pageCount * sizeof(NvU64));

    // Pin pages using pin_user_pages
    // NV_PIN_USER_PAGES macro handles the vmas argument internally based on kernel version
    ret = NV_PIN_USER_PAGES(startAddr, pageCount, FOLL_LONGTERM | FOLL_WRITE,
                           pBuffer->pages);
    if (ret != pageCount)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: failed - got %d, expected %u\n",
                  ret, pageCount);
        // Unpin any pages that were pinned
        if (ret > 0)
        {
            for (i = 0; i < (NvU32)ret; i++)
            {
                if (pBuffer->pages[i])
                    NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
            }
        }
        goto fail_alloc;
    }

    // Convert page pointers to physical addresses
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i] == NULL)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: NULL page at index %u\n", i);
            goto fail_unpin;
        }
        pBuffer->physAddrs[i] = page_to_phys(pBuffer->pages[i]);
        if (pBuffer->physAddrs[i] == 0)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: CXL hugepage pin: zero phys addr at page %u\n", i);
            goto fail_unpin;
        }
    }

    *ppHandle = pBuffer;

    nv_printf(NV_DBG_INFO, "NVRM: CXL hugepage pin: success - %u %s pages, size=0x%llx\n",
              pageCount, bUseHugePages ? "2MB" : "4K", (unsigned long long)size);

    return NV_OK;

fail_unpin:
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i])
            NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
    }

fail_alloc:
    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }
    if (pBuffer->pages)
    {
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }
    kfree(pBuffer);
    if (bReserved)
        cxl_release_quota(size, pageCount);
    return NV_ERR_NO_MEMORY;
}

NV_STATUS NV_API_CALL nv_get_cxl_buffer_hugepages(
    void    *pHandle,
    NvU64  **ppPhysAddrs,
    NvU32   *pPageCount,
    NvU32   *pPageSize
)
{
    cxl_pinned_buffer_t *pBuffer = (cxl_pinned_buffer_t *)pHandle;

    if (unlikely(pBuffer == NULL || ppPhysAddrs == NULL ||
                 pPageCount == NULL || pPageSize == NULL))
        return NV_ERR_INVALID_ARGUMENT;

    if (unlikely(pBuffer->physAddrs == NULL || pBuffer->pageCount == 0))
        return NV_ERR_INVALID_STATE;

    *ppPhysAddrs = pBuffer->physAddrs;
    *pPageCount = pBuffer->pageCount;
    *pPageSize = pBuffer->pageSize;

    return NV_OK;
}

/*
 * ============================================================================
 * AF_XDP UMEM Support for GPU P2P DMA
 * ============================================================================
 *
 * Provides zero-copy networking support via AF_XDP sockets.
 * Enables direct GPU DMA to/from an explicitly registered host region.  The
 * raw host API makes no AF_XDP claim.  nv_pin_xsk_umem() adds that claim only
 * after comparing every pinned page with a live, bound XSK UMEM.
 */

// XDP frame size constants
#define NV_XDP_FRAME_SIZE_2K     2048
#define NV_XDP_FRAME_SIZE_4K     4096
#define NV_XDP_DEFAULT_HEADROOM  256

/*
 * nv_p2p_umem_iommu_untranslated
 *
 * Pinned host pages reach the copy engine as page_to_phys() addresses in
 * ADDR_SYSMEM PTEs; nothing maps them through the GPU's IOMMU domain.  They
 * are valid DMA addresses for the GPU only when dev has no IOMMU domain or
 * an identity (passthrough) one, so admission fails closed on any
 * translating domain.
 */
NvBool NV_API_CALL nv_p2p_umem_iommu_untranslated(struct device *dev)
{
    struct iommu_domain *domain;

    if (dev == NULL)
        return NV_FALSE;

    domain = iommu_get_domain_for_dev(dev);
    return domain == NULL || domain->type == IOMMU_DOMAIN_IDENTITY;
}

/*
 * nv_pin_host_region
 *
 * Pins an explicit host region for GPU DMA access.  Callers that need an
 * AF_XDP identity must use nv_pin_xsk_umem() instead.
 *
 * Parameters:
 *   umemAddr     [IN]  - User virtual address of UMEM region
 *   size         [IN]  - Size of UMEM in bytes
 *   frameSize    [IN]  - Size of each XDP frame (typically 2K or 4K)
 *   ppHandle     [OUT] - Returns handle for subsequent operations
 */
NV_STATUS NV_API_CALL nv_pin_host_region(
    NvU64   umemAddr,
    NvU64   size,
    NvU32   frameSize,
    void  **ppHandle
)
{
    nv_p2p_umem_buffer_t *pBuffer = NULL;
    unsigned long startAddr;
    NvU32 pageCount;
    int ret;
    NvU32 i;
    NV_STATUS status;
    NvBool bLargeAlloc;
    NvBool bReserved = NV_FALSE;

    if (unlikely(size == 0 || ppHandle == NULL))
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: invalid argument\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

#if NV_P2P_UMEM_STRICT_SECURITY_CHECKS
    if (unlikely(size > NV_P2P_UMEM_MAX_PIN_SIZE))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: host region pin: size exceeds cap (size=0x%llx)\n",
                  (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }
#endif

    if (unlikely(umemAddr > ULONG_MAX - size))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: host region pin: invalid range (addr=0x%llx, size=0x%llx)\n",
                  (unsigned long long)umemAddr, (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    /* always-on (audit #9): a non-page-aligned base loses its intra-page
     * offset when startAddr rounds down below, so a later DMA at umemOffset
     * would address the wrong location within the pinned region. */
    if (unlikely((umemAddr & (PAGE_SIZE - 1)) != 0))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: host region pin: base must be page aligned (addr=0x%llx)\n",
                  (unsigned long long)umemAddr);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Validate frame size (must be power of 2, typically 2K or 4K)
    if (frameSize == 0 || (frameSize & (frameSize - 1)) != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: invalid frame size %u\n", frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // UMEM size must be multiple of frame size
    if (size % frameSize != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: size 0x%llx not multiple of frame %u\n",
                  (unsigned long long)size, frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

    startAddr = umemAddr & PAGE_MASK;
    {
        /* audit (low): compute the page span in 64-bit and bound it BEFORE
         * narrowing to NvU32. The size cap above is STRICT-gated, so in the
         * default build a span > 2^32 would otherwise truncate and slip past
         * the cap. */
        NvU64 pages64 = ((umemAddr + size - 1) >> PAGE_SHIFT)
                        - (startAddr >> PAGE_SHIFT) + 1;
        if (unlikely(pages64 == 0 || pages64 > NV_P2P_UMEM_MAX_PIN_PAGES))
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: invalid page count %llu\n",
                      (unsigned long long)pages64);
            return NV_ERR_INVALID_ARGUMENT;
        }
        pageCount = (NvU32)pages64;
    }

    // Charge the global tracker and this mm's locked_vm before pinning.
    status = nv_xdev_ext_pin_charge(&nv_p2p_umem_pin_charge_ops, current->mm,
                               size, pageCount);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: resource limit exceeded\n");
        return status;
    }
    bReserved = NV_TRUE;

    pBuffer = kzalloc(sizeof(*pBuffer), GFP_KERNEL);
    if (pBuffer == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: failed to allocate buffer struct\n");
        if (bReserved)
            nv_xdev_ext_pin_uncharge(&nv_p2p_umem_pin_charge_ops, current->mm,
                                size, pageCount);
        return NV_ERR_NO_MEMORY;
    }

    pBuffer->bufferType = NV_P2P_BUFFER_TYPE_HOST_REGION;
    pBuffer->frameSize = frameSize;
    pBuffer->bGpuBacked = NV_FALSE;

    bLargeAlloc = (pageCount > 512);

    if (bLargeAlloc)
    {
        pBuffer->pages = vmalloc(pageCount * sizeof(struct page *));
        pBuffer->physAddrs = vmalloc(pageCount * sizeof(NvU64));
    }
    else
    {
        pBuffer->pages = kmalloc(pageCount * sizeof(struct page *), GFP_KERNEL);
        pBuffer->physAddrs = kmalloc(pageCount * sizeof(NvU64), GFP_KERNEL);
    }

    if (pBuffer->pages == NULL || pBuffer->physAddrs == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: failed to allocate arrays\n");
        goto fail_alloc;
    }

    // Pin UMEM pages with FOLL_LONGTERM for persistent DMA access.
    // pin_user_pages() walks the VMAs with locked=1: the caller holds
    // mmap_read_lock, and GUP asserts it.
    nv_mmap_read_lock(current->mm);
    ret = NV_PIN_USER_PAGES(startAddr, pageCount, FOLL_LONGTERM | FOLL_WRITE, pBuffer->pages);
    nv_mmap_read_unlock(current->mm);

    if (ret != pageCount)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: failed - got %d, expected %u\n",
                  ret, pageCount);
        if (ret > 0)
        {
            for (i = 0; i < (NvU32)ret; i++)
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
        }
        goto fail_alloc;
    }

    // Convert to physical addresses
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i] == NULL)
        {
            nv_printf(NV_DBG_ERRORS, "NVRM: host region pin: NULL page at index %u\n", i);
            goto fail_unpin;
        }
        pBuffer->physAddrs[i] = page_to_phys(pBuffer->pages[i]);
    }

    pBuffer->userVirtAddr = umemAddr;
    pBuffer->size = size;
    pBuffer->pageCount = pageCount;
    pBuffer->pageSize = PAGE_SIZE;
    pBuffer->refCount = 1;
    /* The unpin may run from another task's close; keep the charged mm. */
    pBuffer->pinMm = current->mm;
    mmgrab(current->mm);

    *ppHandle = pBuffer;

    nv_printf(NV_DBG_INFO, "NVRM: host region pin: success - %u pages, %llu frames of %u bytes\n",
              pageCount, (unsigned long long)(size / frameSize), frameSize);

    return NV_OK;

fail_unpin:
    for (i = 0; i < pageCount; i++)
    {
        if (pBuffer->pages[i])
            NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
    }

fail_alloc:
    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }
    if (pBuffer->pages)
    {
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }
    kfree(pBuffer);
    if (bReserved)
        nv_xdev_ext_pin_uncharge(&nv_p2p_umem_pin_charge_ops, current->mm,
                            size, pageCount);
    return NV_ERR_NO_MEMORY;
}

NV_STATUS NV_API_CALL nv_pin_xsk_umem(
    struct socket *xskSocket,
    NvU64          umemAddr,
    NvU64          size,
    NvU32          frameSize,
    void          **ppHandle
)
{
#if NV_XDP_UMEM_SUPPORT
    nv_p2p_umem_buffer_t *pBuffer;
    NV_STATUS status;

    if (xskSocket == NULL || xskSocket->sk == NULL || ppHandle == NULL ||
        xskSocket->sk->sk_family != PF_XDP)
        return NV_ERR_INVALID_ARGUMENT;

    status = nv_pin_host_region(umemAddr, size, frameSize, ppHandle);
    if (status != NV_OK)
        return status;

    pBuffer = (nv_p2p_umem_buffer_t *)*ppHandle;
    pBuffer->bufferType = NV_P2P_BUFFER_TYPE_VERIFIED_XSK;
    status = nv_validate_xsk_umem(xskSocket, pBuffer);
    if (status != NV_OK)
    {
        nv_unpin_host_region(pBuffer);
        *ppHandle = NULL;
    }
    return status;
#else
    (void)xskSocket;
    (void)umemAddr;
    (void)size;
    (void)frameSize;
    (void)ppHandle;
    return NV_ERR_NOT_SUPPORTED;
#endif
}

/*
 * Verify that a retained AF_XDP socket still owns the exact UMEM pages and
 * geometry represented by pHandle.  The ioctl registry holds the socket file
 * reference for the handle lifetime.  We intentionally retain no raw umem or
 * pool pointer here; both are read only while the socket control mutex is held.
 */
NV_STATUS NV_API_CALL nv_validate_xsk_umem(
    struct socket *xskSocket,
    void          *pHandle
)
{
#if NV_XDP_UMEM_SUPPORT
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    struct xdp_sock *xs;
    NV_STATUS status = NV_ERR_INVALID_STATE;
    NvU32 i;

    if (xskSocket == NULL || xskSocket->sk == NULL || pBuffer == NULL ||
        xskSocket->sk->sk_family != PF_XDP ||
        pBuffer->bufferType != NV_P2P_BUFFER_TYPE_VERIFIED_XSK)
        return NV_ERR_INVALID_ARGUMENT;

    xs = (struct xdp_sock *)xskSocket->sk;
    mutex_lock(&xs->mutex);
    if (xs->state != XSK_BOUND || xs->umem == NULL || xs->pool == NULL ||
        xs->pool->umem != xs->umem || xs->umem->pgs == NULL ||
        xs->umem->size != pBuffer->size ||
        xs->umem->chunk_size != pBuffer->frameSize ||
        xs->pool->chunk_size != pBuffer->frameSize ||
        xs->umem->npgs != pBuffer->pageCount)
        goto out_unlock;

    for (i = 0; i < pBuffer->pageCount; i++)
    {
        if (pBuffer->pages[i] != xs->umem->pgs[i])
            goto out_unlock;
    }

    status = NV_OK;

out_unlock:
    mutex_unlock(&xs->mutex);
    return status;
#else
    (void)xskSocket;
    (void)pHandle;
    return NV_ERR_NOT_SUPPORTED;
#endif
}

/*
 * nv_unpin_host_region
 *
 * Unpins a previously registered host region or verified XSK UMEM.
 */
NV_STATUS NV_API_CALL nv_unpin_host_region(void *pHandle)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    NvU32 i;
    NvU64 savedSize;
    NvU32 savedPageCount;
    struct mm_struct *pinMm;
    NvBool bLargeAlloc;
    NV_STATUS status;

    if (pBuffer == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBuffer->bufferType != NV_P2P_BUFFER_TYPE_HOST_REGION &&
        pBuffer->bufferType != NV_P2P_BUFFER_TYPE_VERIFIED_XSK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: host region unpin: wrong buffer type %d\n",
                  pBuffer->bufferType);
        return NV_ERR_INVALID_ARGUMENT;
    }

    savedSize = pBuffer->size;
    savedPageCount = pBuffer->pageCount;
    pinMm = pBuffer->pinMm;
    bLargeAlloc = (savedPageCount > 512);

    if (pBuffer->pages)
    {
        for (i = 0; i < savedPageCount; i++)
        {
            if (pBuffer->pages[i])
            {
                /* The region was pinned writable and may have been a CE dst. */
                set_page_dirty_lock(pBuffer->pages[i]);
                NV_UNPIN_USER_PAGE(pBuffer->pages[i]);
            }
        }
        if (bLargeAlloc)
            vfree(pBuffer->pages);
        else
            kfree(pBuffer->pages);
    }

    if (pBuffer->physAddrs)
    {
        if (bLargeAlloc)
            vfree(pBuffer->physAddrs);
        else
            kfree(pBuffer->physAddrs);
    }

    kfree(pBuffer);
    status = nv_xdev_ext_pin_uncharge(&nv_p2p_umem_pin_charge_ops, pinMm,
                                 savedSize, savedPageCount);
    mmdrop(pinMm);

    return status;
}

/*
 * nv_p2p_vidmem_bind
 *
 * Binds [gpuVA, gpuVA + length) of the calling process to its vidmem
 * allocation for XDEV_EXT CE transfers.  The GPU side of a CE copy is that
 * allocation's memdesc at an offset: P2P page table entries are BAR1 bus
 * addresses and never name it.  The device reference is taken first and the
 * RM binding must name the same GPU as pExpectedGpuUuid.
 */
NV_STATUS NV_API_CALL nv_p2p_vidmem_bind(
    const NvU8 *pExpectedGpuUuid,
    NvU64 gpuVA,
    NvU64 length,
    nv_p2p_vidmem_binding_t **ppBinding,
    NvU32 *pSegSize
)
{
    nv_p2p_vidmem_binding_t *pBinding;
    nvidia_stack_t *sp = NULL;
    NvU8 gpu_uuid[NVIDIA_P2P_GPU_UUID_LEN];
    NvU32 seg_size;
    NV_STATUS status;

    if (ppBinding == NULL || pExpectedGpuUuid == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *ppBinding = NULL;

    pBinding = kzalloc(sizeof(*pBinding), GFP_KERNEL);
    if (pBinding == NULL)
        return NV_ERR_NO_MEMORY;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        status = NV_ERR_NO_MEMORY;
        goto free_binding;
    }

    if (nvidia_dev_get_uuid(pExpectedGpuUuid, sp) != 0)
    {
        status = NV_ERR_GPU_UUID_NOT_FOUND;
        goto free_stack;
    }
    os_mem_copy(pBinding->gpu_uuid, pExpectedGpuUuid, NVIDIA_P2P_GPU_UUID_LEN);

    status = rm_p2p_umem_vidmem_bind(sp, gpuVA, length, gpu_uuid, &seg_size,
                                     &pBinding->rm);
    if (status != NV_OK)
        goto put_device;

    if (!nv_p2p_gpu_identity_matches(pExpectedGpuUuid, gpu_uuid))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: XDEV_EXT CE window: opened GPU does not own allocation\n");
        status = NV_ERR_INVALID_DEVICE;
        goto unbind;
    }

    nv_kmem_cache_free_stack(sp);
    if (pSegSize != NULL)
        *pSegSize = seg_size;
    *ppBinding = pBinding;
    return NV_OK;

unbind:
    WARN_ON(rm_p2p_umem_vidmem_unbind(sp, pBinding->rm) != NV_OK);
put_device:
    nvidia_dev_put_uuid(pBinding->gpu_uuid, sp);
free_stack:
    nv_kmem_cache_free_stack(sp);
free_binding:
    kfree(pBinding);
    return status;
}

/*
 * nv_p2p_vidmem_unbind
 *
 * Drops the RM dup, then the device reference.  Never called after an
 * ambiguous CE outcome on the window: both then stay held until reboot.
 */
void NV_API_CALL nv_p2p_vidmem_unbind(nv_p2p_vidmem_binding_t *pBinding)
{
    nvidia_stack_t *sp = NULL;

    if (pBinding == NULL)
        return;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: XDEV_EXT CE window: no stack to unbind, window kept\n");
        return;
    }

    WARN_ON(rm_p2p_umem_vidmem_unbind(sp, pBinding->rm) != NV_OK);
    nvidia_dev_put_uuid(pBinding->gpu_uuid, sp);
    nv_kmem_cache_free_stack(sp);
    kfree(pBinding);
}

/*
 * nv_p2p_vidmem_dma_request
 *
 * Runs xferCount CE transfers between pinned host pages and a bound vidmem
 * window as one RM request, under one RM API lock hold.  Each transfer's
 * gpuOffset is relative to the window.  *pHwSubmitted and *pBytesDone are
 * RM's: see RmP2PUmemDmaRequestDirect().  Process context, may sleep.
 */
NV_STATUS NV_API_CALL nv_p2p_vidmem_dma_request(
    nv_p2p_vidmem_binding_t *pBinding,
    NvU64 *pPhysAddrs,
    NvU32 pageCount,
    NvU32 pageSize,
    NvU64 bufferSize,
    const nv_p2p_umem_xfer_t *pXfers,
    NvU32 xferCount,
    NvU32 direction,
    NvBool *pHwSubmitted,
    NvU64 *pBytesDone
)
{
    nvidia_stack_t *sp = NULL;
    NV_STATUS status;

    if (pHwSubmitted == NULL || pBytesDone == NULL)
        return NV_ERR_INVALID_ARGUMENT;
    *pHwSubmitted = NV_FALSE;
    *pBytesDone = 0;
    if (pBinding == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
        return NV_ERR_NO_MEMORY;

    status = rm_p2p_umem_dma_request(sp, pPhysAddrs, pageCount, pageSize,
                                     bufferSize, pBinding->rm, pXfers,
                                     xferCount, direction, pHwSubmitted,
                                     pBytesDone);
    nv_kmem_cache_free_stack(sp);
    return status;
}

/* Bind-time stack allocation avoids a per-submit RM stack allocation. */
struct nv_p2p_ce_host {
    nvidia_stack_t *sp;
    void *rm;
};
NV_STATUS NV_API_CALL nv_p2p_ce_host_bind(nv_p2p_vidmem_binding_t *b,
    NvU64 *phys, NvU32 count, NvU32 pageSize, NvU64 bytes,
    nv_p2p_ce_host_t **out)
{
    nv_p2p_ce_host_t *h;
    NV_STATUS status;
    if (b == NULL || out == NULL) return NV_ERR_INVALID_ARGUMENT;
    *out = NULL;
    h = kzalloc(sizeof(*h), GFP_KERNEL);
    if (h == NULL) return NV_ERR_NO_MEMORY;
    if (nv_kmem_cache_alloc_stack(&h->sp) != 0) {
        kfree(h);
        return NV_ERR_NO_MEMORY;
    }
    status = rm_p2p_umem_ce_host_bind(h->sp, b->rm, phys, count, pageSize,
                                    bytes, &h->rm);
    if (status != NV_OK) {
        nv_kmem_cache_free_stack(h->sp);
        kfree(h);
        return status;
    }
    *out = h;
    return NV_OK;
}
NV_STATUS NV_API_CALL nv_p2p_ce_host_unbind(nv_p2p_ce_host_t *h)
{
    NV_STATUS status = rm_p2p_umem_ce_host_unbind(h->sp, h->rm);
    if (status == NV_OK) {
        nv_kmem_cache_free_stack(h->sp);
        kfree(h);
    }
    return status;
}
NV_STATUS NV_API_CALL nv_p2p_ce_async_submit(nv_p2p_ce_host_t *h,
    const nv_p2p_umem_xfer_t *x, NvU32 n, NvU32 direction,
    NvBool *issued, NvU64 *token)
{
    *issued = NV_FALSE;
    *token = 0;
    return rm_p2p_umem_ce_async_submit(h->sp, h->rm, x, n, direction,
                                      issued, token);
}
NV_STATUS NV_API_CALL nv_p2p_ce_progress(nv_p2p_ce_host_t *h, NvU64 *watermark)
{
    return rm_p2p_umem_ce_progress(h->sp, h->rm, watermark);
}

/* The errno an NV_STATUS of the P2P paths maps to (-EIO when unmapped). */
int NV_API_CALL nv_p2p_umem_errno(NV_STATUS status)
{
    return nvidia_p2p_map_status(status);
}

/*
 * nv_registered_region_dma_xfer
 *
 * Performs a GPU Copy Engine DMA transfer between a pinned XDP UMEM
 * region and GPU framebuffer memory.  This is the kernel-open entry
 * point for the NV_ESC_P2P_DMA_XFER ioctl.
 *
 * The gpuVA parameter identifies the GPU allocation range for the transfer;
 * nv_p2p_vidmem_bind() holds that allocation for the duration of this
 * synchronous RM CE request, and for good after an ambiguous outcome.
 *
 * Parameters:
 *   pHandle     [IN]  - Handle from nv_pin_host_region()
 *   gpuVA       [IN]  - GPU virtual address
 *   umemOffset  [IN]  - Byte offset in UMEM
 *   size        [IN]  - Transfer size in bytes
 *   direction   [IN]  - 0 = GPU->UMEM, 1 = UMEM->GPU
 */
NV_STATUS NV_API_CALL nv_registered_region_dma_xfer(
    void   *pHandle,
    NvU64   gpuVA,
    NvU64   umemOffset,
    NvU64   size,
    NvU32   direction,
    const NvU8 *pExpectedGpuUuid,
    const nv_p2p_xdev_ext_identity_t *pIdentity,
    NvBool *pCeAmbiguous
)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    nvidia_stack_t *sp = NULL;
    nv_p2p_vidmem_binding_t *vidmem = NULL;
    struct nv_xdev_ext_gpu_rm_call xdev_ext_call = { 0 };
    struct nv_xdev_ext_gpu_request xdev_ext_request = { 0 };
    struct nv_xdev_ext_gpu_outcome xdev_ext_outcome = { 0 };
    const NvU64 p2p_page_size = NVRM_P2P_PAGESIZE_BIG_64K;
    NV_STATUS status;
    NvU64 gpu_page_offset;
    NvBool ceAmbiguous = NV_FALSE;

    if (pCeAmbiguous != NULL)
        *pCeAmbiguous = NV_FALSE;
    if (pBuffer == NULL || pExpectedGpuUuid == NULL || pIdentity == NULL ||
        pCeAmbiguous == NULL)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: registered region DMA: invalid handle/identity\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pBuffer->bufferType != NV_P2P_BUFFER_TYPE_HOST_REGION &&
        pBuffer->bufferType != NV_P2P_BUFFER_TYPE_VERIFIED_XSK)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: wrong buffer type %u\n",
                  pBuffer->bufferType);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (direction != 0 && direction != 1)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: invalid direction %u\n",
                  direction);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size == 0 || !pIdentity->requestId || !pIdentity->chainId ||
        !pIdentity->endpointId || !pIdentity->hostBufferId ||
        !pIdentity->gpuBufferId)
        return NV_ERR_INVALID_ARGUMENT;

    if (size > (NvU64)~0U)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: size exceeds CE limit (sz=0x%llx)\n",
                  (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (umemOffset > pBuffer->size || size > pBuffer->size - umemOffset)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: OOB (off=0x%llx sz=0x%llx buf=0x%llx)\n",
                  (unsigned long long)umemOffset, (unsigned long long)size,
                  (unsigned long long)pBuffer->size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pBuffer->physAddrs == NULL || pBuffer->pageCount == 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: XDP DMA xfer: no pinned pages\n");
        return NV_ERR_INVALID_STATE;
    }

    status = nv_p2p_vidmem_bind(pExpectedGpuUuid, gpuVA, size, &vidmem, NULL);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: XDP DMA xfer: GPU window bind failed: 0x%x\n", status);
        return status;
    }

    if (nv_kmem_cache_alloc_stack(&sp) != 0)
    {
        status = NV_ERR_NO_MEMORY;
        goto unbind;
    }

    xdev_ext_call.sp = sp;
    xdev_ext_call.vidmem = vidmem;
    xdev_ext_call.umem_phys_pages = pBuffer->physAddrs;
    xdev_ext_call.umem_page_count = pBuffer->pageCount;
    xdev_ext_call.umem_page_size = pBuffer->pageSize;
    xdev_ext_call.umem_size = pBuffer->size;
    xdev_ext_call.xfer.umemOffset = umemOffset;
    xdev_ext_call.xfer.gpuOffset = 0;
    xdev_ext_call.xfer.size = size;
    xdev_ext_call.direction = direction;

    /* The policy sees the GPU VA range at P2P page granularity. */
    gpu_page_offset = gpuVA % p2p_page_size;

    xdev_ext_request.request_id = pIdentity->requestId;
    xdev_ext_request.chain_id = pIdentity->chainId;
    xdev_ext_request.endpoint_id = pIdentity->endpointId;
    xdev_ext_request.umem_buffer_id = pIdentity->hostBufferId;
    xdev_ext_request.gpu_buffer_id = pIdentity->gpuBufferId;
    xdev_ext_request.direction = direction;
    xdev_ext_request.umem_page_size = pBuffer->pageSize;
    xdev_ext_request.umem_page_count = pBuffer->pageCount;
    xdev_ext_request.gpu_page_size = p2p_page_size;
    xdev_ext_request.gpu_page_count =
        (NvU32)((gpu_page_offset + size + p2p_page_size - 1) / p2p_page_size);
    xdev_ext_request.umem_offset = umemOffset;
    xdev_ext_request.gpu_offset = gpu_page_offset;
    xdev_ext_request.length = size;
    xdev_ext_request.umem_capacity = pBuffer->size;

    status = (NV_STATUS)nv_xdev_ext_gpu_run(&xdev_ext_request,
                                       &nv_xdev_ext_gpu_policy_ops,
                                       &xdev_ext_call,
                                       NV_ERR_INVALID_STATE,
                                       NV_ERR_INSUFFICIENT_PERMISSIONS,
                                       &xdev_ext_outcome);
    ceAmbiguous = nv_xdev_ext_ce_classify(status, xdev_ext_call.hwSubmitted) ==
                  NV_XDEV_EXT_CE_AMBIGUOUS;
    *pCeAmbiguous = ceAmbiguous;
    nv_xdev_ext_gpu_report_policy_errors(&xdev_ext_outcome);
    nv_kmem_cache_free_stack(sp);

unbind:
    if (!ceAmbiguous)
        nv_p2p_vidmem_unbind(vidmem);
    return status;
}

/*
 * nv_get_host_region_pages
 *
 * Gets physical page addresses for a range within the UMEM.
 * Useful for setting up GPU DMA descriptors.
 */
NV_STATUS NV_API_CALL nv_get_host_region_pages(
    void    *pHandle,
    NvU64    offset,
    NvU64    size,
    NvU64  **ppPhysAddrs,
    NvU32   *pPageCount,
    NvU32   *pFrameSize
)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    NvU64 endOffset;
    NvU64 endPage64;
    NvU32 startPage, endPage;

    if (pBuffer == NULL || ppPhysAddrs == NULL || pPageCount == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if ((pBuffer->bufferType != NV_P2P_BUFFER_TYPE_HOST_REGION &&
         pBuffer->bufferType != NV_P2P_BUFFER_TYPE_VERIFIED_XSK) ||
        pBuffer->physAddrs == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (size == 0 || offset > pBuffer->size || size > pBuffer->size - offset)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBuffer->pageSize == 0)
        return NV_ERR_INVALID_STATE;

    endOffset = offset + size;
    startPage = (NvU32)(offset / pBuffer->pageSize);
    endPage64 = (endOffset == 0) ? 0 :
                ((endOffset - 1) / pBuffer->pageSize) + 1;
    if (endPage64 > (NvU64)~0U)
        return NV_ERR_INVALID_ARGUMENT;

    endPage = (NvU32)endPage64;

    if (endPage > pBuffer->pageCount)
        return NV_ERR_INVALID_ARGUMENT;

    *ppPhysAddrs = &pBuffer->physAddrs[startPage];
    *pPageCount = endPage - startPage;
    if (pFrameSize)
        *pFrameSize = pBuffer->frameSize;

    return NV_OK;
}

/*
 * nv_register_gpu_umem
 *
 * Registers GPU memory to be used as UMEM backing store.
 * This enables zero-copy TX where packets are composed directly in GPU memory.
 *
 * Parameters:
 *   gpuMemHandle  [IN]  - Handle to allocated GPU memory
 *   gpuOffset     [IN]  - Offset within GPU memory
 *   size          [IN]  - Size of region to expose
 *   frameSize     [IN]  - XDP frame size
 *   ppHandle      [OUT] - Returns handle for UMEM operations
 */
NV_STATUS NV_API_CALL nv_register_gpu_umem(
    void   *gpuMemHandle,
    NvU64   gpuOffset,
    NvU64   size,
    NvU32   frameSize,
    void  **ppHandle
)
{
    nv_p2p_umem_buffer_t *pBuffer = NULL;
    NV_STATUS status;
    NvU64 frameCount64;
    NvU32 frameCount;

    if (gpuMemHandle == NULL || ppHandle == NULL || size == 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: invalid argument\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (frameSize == 0 || (frameSize & (frameSize - 1)) != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: invalid frame size %u\n", frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

#if NV_P2P_UMEM_STRICT_SECURITY_CHECKS
    if (size > NV_P2P_UMEM_MAX_PIN_SIZE)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: size exceeds cap 0x%llx\n",
                  (unsigned long long)size);
        return NV_ERR_INVALID_ARGUMENT;
    }
#endif

    if (size % frameSize != 0)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: invalid size 0x%llx for frame %u\n",
                  (unsigned long long)size, frameSize);
        return NV_ERR_INVALID_ARGUMENT;
    }

    frameCount64 = size / frameSize;
    if (frameCount64 == 0 || frameCount64 > NV_P2P_UMEM_MAX_PIN_PAGES)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM register: invalid frame count %llu\n",
                  (unsigned long long)frameCount64);
        return NV_ERR_INVALID_ARGUMENT;
    }
    frameCount = (NvU32)frameCount64;

    status = nv_p2p_umem_reserve_quota(size, frameCount);
    if (status != NV_OK)
        return status;

    pBuffer = kzalloc(sizeof(*pBuffer), GFP_KERNEL);
    if (pBuffer == NULL)
    {
        nv_p2p_umem_release_quota(size, frameCount);
        return NV_ERR_NO_MEMORY;
    }

    pBuffer->bufferType = NV_P2P_BUFFER_TYPE_GPU_EXPORT;
    pBuffer->gpuMemHandle = gpuMemHandle;
    pBuffer->gpuOffset = gpuOffset;
    pBuffer->size = size;
    pBuffer->frameSize = frameSize;
    pBuffer->pageCount = frameCount;  // Using frames as "pages"
    pBuffer->pageSize = frameSize;
    pBuffer->bGpuBacked = NV_TRUE;
    pBuffer->refCount = 1;

    // Physical addresses will be resolved via GPU BAR1 mapping
    // The actual BAR1 offset calculation happens in the RM layer
    pBuffer->physAddrs = NULL;
    pBuffer->pages = NULL;

    *ppHandle = pBuffer;

    nv_printf(NV_DBG_INFO, "NVRM: GPU UMEM register: success - %u frames, gpuOffset=0x%llx\n",
              frameCount, (unsigned long long)gpuOffset);

    return NV_OK;
}

/*
 * nv_unregister_gpu_umem
 *
 * Unregisters GPU memory previously registered as UMEM backing.
 */
NV_STATUS NV_API_CALL nv_unregister_gpu_umem(void *pHandle)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;
    NvU64 savedSize;
    NvU32 savedPageCount;
    NV_STATUS status;

    if (pBuffer == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBuffer->bufferType != NV_P2P_BUFFER_TYPE_GPU_EXPORT)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: GPU UMEM unregister: wrong buffer type\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    savedSize = pBuffer->size;
    savedPageCount = pBuffer->pageCount;

    kfree(pBuffer);
    status = nv_p2p_umem_release_quota(savedSize, savedPageCount);

    return status;
}

/*
 * nv_get_umem_buffer_info
 *
 * Gets information about a registered UMEM buffer (generic).
 * Works for both user UMEM and GPU-backed UMEM.
 */
NV_STATUS NV_API_CALL nv_get_umem_buffer_info(
    void   *pHandle,
    NvU32  *pBufferType,
    NvU64  *pSize,
    NvU32  *pFrameSize,
    NvU32  *pFrameCount,
    NvBool *pIsGpuBacked
)
{
    nv_p2p_umem_buffer_t *pBuffer = (nv_p2p_umem_buffer_t *)pHandle;

    if (pBuffer == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (pBufferType)
        *pBufferType = pBuffer->bufferType;
    if (pSize)
        *pSize = pBuffer->size;
    if (pFrameSize)
        *pFrameSize = pBuffer->frameSize;
    if (pFrameCount)
        *pFrameCount = pBuffer->size / pBuffer->frameSize;
    if (pIsGpuBacked)
        *pIsGpuBacked = pBuffer->bGpuBacked;

    return NV_OK;
}

/*
 * CXL Device Enumeration
 *
 * Enumerates CXL devices in the system using the Linux PCI subsystem.
 * CXL memory devices have PCI class 0x0502 (Memory Controller / CXL)
 */

// CXL System Info structure (must match definition in p2p_cxl.c)
typedef struct {
    NvU32   numDevices;
    NvU32   numMemoryDevices;
    NvBool  bLinkUp;
    NvU32   cxlVersion;
} cxl_system_info_t;

// PCI class for CXL memory devices
#define PCI_CLASS_MEMORY_CXL  0x0502

NV_STATUS NV_API_CALL nv_enumerate_cxl_devices(void *pInfo)
{
    cxl_system_info_t *info = (cxl_system_info_t *)pInfo;
    struct pci_dev *pdev = NULL;
    NvU32 numDevices = 0;
    NvU32 numMemDevices = 0;
    NvBool bLinkUp = NV_FALSE;
    NvU32 cxlVersion = 2;
    u16 linkStatus;
    int ret;

    if (info == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    // Enumerate all PCI devices looking for CXL memory devices
    for_each_pci_dev(pdev)
    {
        // Check for CXL memory device class (0x0502xx)
        if ((pdev->class >> 8) == PCI_CLASS_MEMORY_CXL)
        {
            numDevices++;
            numMemDevices++;

            // Check if PCIe link is up by reading link status
            ret = pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &linkStatus);
            if (ret == 0)
            {
                // For endpoints, link is up if speed > 0 and width > 0
                u16 speed = linkStatus & PCI_EXP_LNKSTA_CLS;
                u16 width = (linkStatus & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

                if (speed > 0 && width > 0)
                {
                    bLinkUp = NV_TRUE;
                }

                // Check link speed for CXL version estimation
                // Gen5 (32 GT/s) typically means CXL 2.0+
                if (speed >= 5)  // Gen5 or higher
                    cxlVersion = 2;
                else if (speed >= 4)  // Gen4
                    cxlVersion = 1;
            }

        }
    }

    info->numDevices = numDevices;
    info->numMemoryDevices = numMemDevices;
    info->bLinkUp = bLinkUp;
    info->cxlVersion = cxlVersion;

    return NV_OK;
}
