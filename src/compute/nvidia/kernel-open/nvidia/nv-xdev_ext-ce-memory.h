/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */
#ifndef NV_XDEV_EXT_CE_MEMORY_H
#define NV_XDEV_EXT_CE_MEMORY_H

/*
 * One CUDA allocation a CE stage fd (/dev/nvidiaN) carries for its window,
 * attached once by NV_ESC_XDEV_EXT_CE_ATTACH_MEMORY.  The caller passes the
 * allocation's CUDA POSIX file descriptor shareable handle
 * (cuMemExportToShareableHandle(): a control fd holding one RM export
 * handle) and the GPU VA range it mapped the allocation at, gpu_va naming
 * allocation offset 0.  The VA range only names windows, as the address of a
 * third-party P2P registration does; holding the export is the authority
 * over the allocation.  The stage fd keeps a reference on the export fd
 * until it is closed.
 *
 * The CE class keys its window exclusion on these configured addresses
 * (xdev_ext_mech_ce.c): fds that attach one allocation at different VAs name
 * the same bytes under different keys and are not excluded from each other,
 * as two mappings of one allocation were not before.  Only holders of the
 * export can do that, and an ambiguous window still keeps its binding, so
 * the memory is never freed or reused by RM.
 */
struct nv_file_private_t;

typedef struct nv_xdev_ext_ce_memory
{
    struct nv_file_private_t *nvfp;   /* the export fd's RM file private */
    void                     *file;   /* our reference on the export fd */
    NvU64                     gpu_va; /* the caller's mapping of it */
    NvU64                     size;
} nv_xdev_ext_ce_memory_t;

/* A nonzero, non-wrapping range at a nonzero VA; no flags are defined. */
static inline NvBool nv_xdev_ext_ce_memory_args_ok(NvU64 gpu_va, NvU64 size,
                                                   NvU32 flags, NvU32 reserved)
{
    return flags == 0 && reserved == 0 && gpu_va != 0 && size != 0 &&
           gpu_va <= ~(NvU64)0 - (size - 1);
}

/*
 * The offset in the attached allocation of the window [start, start + len),
 * which must lie inside [gpu_va, gpu_va + size).  Subtraction form only.
 */
static inline NvBool nv_xdev_ext_ce_memory_window(NvU64 gpu_va, NvU64 size,
                                                  NvU64 start, NvU64 len,
                                                  NvU64 *pOffset)
{
    NvU64 offset;

    if (len == 0 || start < gpu_va)
        return NV_FALSE;
    offset = start - gpu_va;
    if (offset >= size || len > size - offset)
        return NV_FALSE;
    *pOffset = offset;
    return NV_TRUE;
}

#endif /* NV_XDEV_EXT_CE_MEMORY_H */
