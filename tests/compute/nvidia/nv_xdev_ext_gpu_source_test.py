#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow source contract for the NVIDIA CE-DMA XDEV_EXT call site."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
P2P = (ROOT / "kernel-open/nvidia/nv-p2p.c").read_text()
NV = (ROOT / "kernel-open/nvidia/nv.c").read_text()
OSAPI = (ROOT / "src/nvidia/arch/nvalloc/unix/src/osapi.c").read_text()
RM_UMEM = (ROOT / "src/nvidia/src/kernel/mem_mgr/p2p_umem.c").read_text()
MEM_UTILS = (ROOT / "src/nvidia/src/kernel/gpu/mem_mgr/mem_utils.c").read_text()
MEM_MGR = (ROOT / "src/nvidia/generated/g_mem_mgr_nvoc.h").read_text()
P2P_H = (ROOT / "kernel-open/nvidia/nv-p2p.h").read_text()
DMA_LIFETIME_H = (ROOT / "kernel-open/nvidia/nv-xdev_ext-dma-lifetime.h").read_text()
NV_KBUILD = (ROOT / "kernel-open/nvidia/nvidia.Kbuild").read_text()
NV_REG = (ROOT / "kernel-open/nvidia/nv-reg.h").read_text()
NV_LINUX = (ROOT / "kernel-open/common/inc/nv-linux.h").read_text()
NV_H = (ROOT / "kernel-open/common/inc/nv.h").read_text()
RM_P2P = (ROOT / "src/nvidia/src/kernel/gpu/bus/p2p.c").read_text()
RM_P2P_H = (ROOT / "src/nvidia/inc/kernel/mem_mgr/p2p.h").read_text()


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


def guarded(source: str, pos: int, macro: str) -> bool:
    """True when pos lies in the taken branch of an #if on defined(macro)."""
    stack = []
    for line in source[:pos].splitlines():
        m = re.match(r"\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", line)
        if not m:
            continue
        kind, cond = m.groups()
        if kind in ("if", "ifdef"):
            stack.append(re.search(rf"(?<!!)\bdefined\s*\(\s*{macro}\s*\)"
                                   if kind == "if" else rf"\b{macro}\b",
                                   cond) is not None)
        elif kind == "ifndef":
            stack.append(False)
        elif kind in ("elif", "else"):
            stack[-1] = False
        else:
            stack.pop()
    return any(stack)


assert '#include "nv-xdev_ext-gpu.h"' in P2P
assert "NV_P2P_BUFFER_TYPE_VERIFIED_XSK" in RM_UMEM
xfer = function_body(P2P, "NV_STATUS NV_API_CALL nv_registered_region_dma_xfer(")
assert "pExpectedGpuUuid" in xfer
assert "pCeAmbiguous" in xfer
assert "gpu_phys_offset" not in xfer
assert "cudaMalloc" not in xfer
assert "contiguous allocations" not in xfer
assert "FBMEM offset" not in xfer
assert "-> phys=" not in xfer
assert "VA=0x" not in xfer
# G1: P2P page table entries (physical_address) are BAR1 bus addresses, not
# FB offsets.  The GPU side of the CE copy is the caller's vidmem allocation,
# bound in RM for this request as (vidmem memdesc, offset).
for token in ("nvidia_p2p_get_pages_persistent(", "physical_address",
              "gpu_phys_pages", "gpu_page_table"):
    assert token not in xfer, f"G1: GPU surface still built from {token}"
bind = xfer.index("nv_p2p_vidmem_bind(pExpectedGpuUuid, gpuVA, size,")
run = xfer.index("nv_xdev_ext_gpu_run(")
report = xfer.index("nv_xdev_ext_gpu_report_policy_errors(&xdev_ext_outcome)")
unbind = xfer.index("nv_p2p_vidmem_unbind(vidmem)")
assert bind < run < report < unbind
# Unbind now reports failure and retains its residual instead of losing the owner.
assert "if (!ceAmbiguous)\n    {" in xfer
assert "releaseStatus = nv_p2p_vidmem_unbind(vidmem)" in xfer
assert "if (ceAmbiguous) pBuffer->vidmemResidual = vidmem;" in xfer
assert "rm_p2p_umem_dma_request(" not in xfer
run_args = xfer[run:report]
assert "NV_ERR_INVALID_STATE" in run_args
assert "NV_ERR_INSUFFICIENT_PERMISSIONS" in run_args
for field in ("request_id", "chain_id", "endpoint_id",
              "umem_buffer_id", "gpu_buffer_id"):
    assert f"xdev_ext_request.{field}" in xfer[:run]
assert "pIdentity->requestId" in xfer
assert "pIdentity->chainId" in xfer
assert "pIdentity->endpointId" in xfer
assert "pIdentity->hostBufferId" in xfer
assert "pIdentity->gpuBufferId" in xfer

assert '#include <linux/atomic.h>' in P2P
assert "static atomic_t nv_xdev_ext_gpu_dispatch_error_reported = ATOMIC_INIT(0);" in P2P
assert "static atomic_t nv_xdev_ext_gpu_completion_error_reported = ATOMIC_INIT(0);" in P2P
diagnostic = function_body(P2P, "static void nv_xdev_ext_gpu_report_policy_errors(")
assert diagnostic.count("atomic_cmpxchg(") == 2
assert "nv_xdev_ext_gpu_dispatch_error_reported" in diagnostic
assert "nv_xdev_ext_gpu_completion_error_reported" in diagnostic
assert "outcome->dispatch_error" in diagnostic
assert "outcome->completion_error" in diagnostic
assert diagnostic.count("nv_printf(NV_DBG_WARNINGS") == 2
assert diagnostic.count("%d") == 2
assert "%p" not in diagnostic
assert "%x" not in diagnostic
assert "%ll" not in diagnostic

submit = function_body(P2P, "static nv_xdev_ext_gpu_u32 nv_xdev_ext_gpu_rm_submit(")
assert submit.count("rm_p2p_umem_dma_request(") == 1
assert "call->vidmem->rm," in submit
assert "&call->xfer, 1," in submit
assert "&call->bytesDone" in submit

# The binding names the GPU that owns gpuVA; RM finds that GPU again by UUID
# for every request and checks the duped allocation is still the bound one.
# Never silently route a multi-GPU request through device index zero.
rm_submit = function_body(OSAPI, "NV_STATUS NV_API_CALL rm_p2p_umem_dma_request(")
assert "gpumgrGetGpuFromUuid(pBinding->gpuUuid" in rm_submit
assert "gpumgrGetGpu(gpuIndex)" not in rm_submit
assert "NV_ERR_GPU_UUID_NOT_FOUND" in rm_submit
resolve = rm_submit.index("RmP2PUmemVidmemResolve(pBinding, pGpu, &pGpuMemDesc)")
assert rm_submit.index("gpumgrGetGpuFromUuid(") < resolve < rm_submit.index(
    "RmP2PUmemDmaRequestDirect(")
assert "pGpuPhysPages" not in rm_submit
assert "*pBytesDone = bytesDone;" in rm_submit

# G1 in RM: the helper resolves the calling process's registered GPU VA range
# to its vidmem allocation and dups that allocation into the GPU's internal
# client.  The dup is the reference that keeps the FB pages allocated while
# bound (vidmemCopyConstruct() takes a heap/PMA block reference), as a
# persistent P2P mapping does.
rm_bind = function_body(RM_P2P, "RmP2PUmemVidmemBind\n(")
assert "rmapiLockIsOwner()" in rm_bind
range_check = rm_bind.index("nvP2PVidmemRangeValid(address, length)")
lookup = rm_bind.index("RmP2PGetInfoWithoutToken(address, length, NULL,")
vidmem_info = rm_bind.index(
    "CliGetThirdPartyP2PVidmemInfoFromAddress(pThirdPartyP2P, address,")
dup = rm_bind.index("DupObject(pRmApi, pMemoryManager->hClient,")
assert range_check < lookup < vidmem_info < dup
after_dup = rm_bind[dup:]
assert "ADDR_FBMEM" in after_dup
assert "nvP2PVidmemWindowValid(" in after_dup
assert "nvP2PVidmemSegSize(" in after_dup
assert "->Free(pRmApi, pMemoryManager->hClient, hMemory)" in after_dup
rm_unbind = function_body(RM_P2P, "RmP2PUmemVidmemUnbind\n(")
assert "->Free(pRmApi, pBinding->hClient, pBinding->hMemory)" in rm_unbind
rm_resolve = function_body(RM_P2P, "RmP2PUmemVidmemResolve\n(")
assert "memGetByHandle(pClient, pBinding->hMemory, &pMemory)" in rm_resolve
assert "pMemory->pMemDesc != pBinding->pMemDesc" in rm_resolve
osapi_bind = function_body(OSAPI, "NV_STATUS NV_API_CALL rm_p2p_umem_vidmem_bind(")
osapi_unbind = function_body(OSAPI, "NV_STATUS NV_API_CALL rm_p2p_umem_vidmem_unbind(")
for body, call in ((osapi_bind, "RmP2PUmemVidmemBind("),
                   (osapi_unbind, "RmP2PUmemVidmemUnbind(")):
    assert body.index("rmapiLockAcquire(") < body.index(call) < \
        body.index("rmapiLockRelease()")

# The old RmP2PUmemDmaRequest() treats an unchecked gpuOffset as an FB
# offset; no XDEV_EXT CE path references it.
legacy = re.compile(r"\bRmP2PUmemDmaRequest\b")
for name, body in (("rm_p2p_umem_dma_request", rm_submit),
                   ("rm_p2p_umem_vidmem_bind", osapi_bind),
                   ("RmP2PUmemVidmemBind", rm_bind),
                   ("RmP2PUmemVidmemResolve", rm_resolve),
                   ("nv-p2p.c", P2P)):
    assert not legacy.search(body), name

# One transfer crosses the kernel-open/RM boundary with the same layout.
def struct_fields(source: str, opener: str) -> list:
    start = source.index(opener)
    body = source[source.index("{", start) + 1:source.index("}", start)]
    return [tuple(line.split(";")[0].split()) for line in body.splitlines()
            if ";" in line]
assert struct_fields(NV_H, "typedef struct nv_p2p_umem_xfer") == \
    struct_fields(RM_P2P_H, "typedef struct P2P_UMEM_XFER") != []
assert "const nv_p2p_umem_xfer_t *" in NV_H[NV_H.index("rm_p2p_umem_dma_request"):]
# nv-kernel.o is linked with --gc-sections: an RM entry kernel-open calls
# exists only when exports_link_command.txt keeps it.
EXPORTS = (ROOT / "src/nvidia/exports_link_command.txt").read_text()
for entry in ("rm_p2p_umem_dma_request", "rm_p2p_umem_vidmem_bind",
              "rm_p2p_umem_vidmem_unbind"):
    assert f"--undefined={entry}\n" in EXPORTS, entry

# This ioctl is a CE passthrough.  PREFER_CE alone permits a silent CPU copy;
# REQUIRE_CE makes absence/pausing/incompatibility fail closed.
assert "TRANSFER_FLAGS_REQUIRE_CE" in MEM_MGR
memcopy = function_body(MEM_UTILS, "memmgrMemCopy_IMPL")
assert "TRANSFER_FLAGS_REQUIRE_CE" in memcopy
assert "transferType != TRANSFER_TYPE_CE" in memcopy
direct = function_body(RM_UMEM, "RmP2PUmemDmaRequestDirect")
assert "TRANSFER_FLAGS_PREFER_CE | TRANSFER_FLAGS_REQUIRE_CE" in direct
legacy_direct = function_body(RM_UMEM, "NV_STATUS\nRmP2PUmemDmaRequest\n(")
assert "TRANSFER_FLAGS_PREFER_CE | TRANSFER_FLAGS_REQUIRE_CE" in legacy_direct
assert '#include "mem_mgr/p2p_umem_chunk.h"' in RM_UMEM
assert "nvP2PUmemCeChunkSize(" in direct
assert "while (remaining != 0)" in direct
assert direct.index("nvP2PUmemCeChunkSize(") < direct.index("memmgrMemCopy(")
assert direct.count("memmgrMemCopy(") == 1
assert "remaining -= chunkSize" in direct

# Bounds and quota reservation must be enabled in normal builds.  In the old
# default, the check and the accounting update were separate lock sections,
# so concurrent pins could both pass the same quota.
assert "#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1" in P2P_H
assert "#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1" in OSAPI
assert "#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1" in RM_UMEM
reserve = function_body(P2P, "static inline NV_STATUS nv_p2p_umem_reserve_quota(")
release_quota = function_body(P2P, "static inline NV_STATUS nv_p2p_umem_release_quota(")
assert reserve.index("spin_lock_irqsave(") < reserve.index("nv_xdev_ext_umem_quota_reserve(")
assert reserve.index("nv_xdev_ext_umem_quota_reserve(") < reserve.index("spin_unlock_irqrestore(")
assert release_quota.index("spin_lock_irqsave(") < release_quota.index("nv_xdev_ext_umem_quota_release(")
assert "nv_p2p_umem_track_pin" not in P2P
assert "nv_p2p_umem_check_limits" not in P2P
tracker_init = function_body(P2P, "static void nv_p2p_umem_init_tracker(")
assert "smp_load_acquire(&g_p2pUmemTracker.bInitialized)" in tracker_init
assert "smp_store_release(&g_p2pUmemTracker.bInitialized, NV_TRUE)" in tracker_init

# The default ioctl mode proves that the exact pinned page array belongs to a
# live, bound AF_XDP socket.  Raw host memory is a separately named opt-in.
xsk_pin = function_body(P2P, "NV_STATUS NV_API_CALL nv_pin_xsk_umem(")
assert "xskSocket->sk->sk_family != PF_XDP" in xsk_pin
assert "nv_validate_xsk_umem(xskSocket, pBuffer)" in xsk_pin
assert "xdpUmem" not in P2P
assert "xskPool" not in P2P
xsk_validate = function_body(P2P, "NV_STATUS NV_API_CALL nv_validate_xsk_umem(")
assert "xs->state != XSK_BOUND" in xsk_validate
assert "xs->umem->size != pBuffer->size" in xsk_validate
assert "xs->umem->chunk_size != pBuffer->frameSize" in xsk_validate
assert "pBuffer->pages[i] != xs->umem->pgs[i]" in xsk_validate
assert xsk_validate.index("mutex_lock(&xs->mutex)") < xsk_validate.index("xs->umem")
assert xsk_validate.index("xs->umem->pgs[i]") < xsk_validate.index(
    "mutex_unlock(&xs->mutex)"
)
host_pin = function_body(P2P, "NV_STATUS NV_API_CALL nv_pin_host_region(")
assert "NV_P2P_BUFFER_TYPE_HOST_REGION" in host_pin
assert "XDP UMEM pin" not in host_pin
# pin_user_pages() runs GUP with locked=1, i.e. the caller holds mmap_lock;
# FOLL_LONGTERM does not change that contract (mm/gup.c pin_user_pages).
assert host_pin.count("NV_PIN_USER_PAGES(") == 1
pin_call = host_pin.index("NV_PIN_USER_PAGES(")
assert "nv_mmap_read_lock(current->mm);" in host_pin[:pin_call], \
    "G2: host region pin runs without mmap_read_lock"
pin_lock = host_pin.rindex("nv_mmap_read_lock(current->mm);", 0, pin_call)
pin_unlock = host_pin.index("nv_mmap_read_unlock(current->mm);", pin_call)
assert host_pin[pin_lock:pin_unlock].count(";") == 2
assert "if (ret != pageCount)" in host_pin[pin_unlock:]
assert "Do NOT hold mmap_read_lock" not in host_pin
host_unpin = function_body(P2P, "NV_STATUS NV_API_CALL nv_unpin_host_region(")
assert host_unpin.index("set_page_dirty_lock(pBuffer->pages[i])") < host_unpin.index(
    "NV_UNPIN_USER_PAGE(pBuffer->pages[i])"
)

ioctl = function_body(NV, "nvidia_ioctl(")
assert "rm_get_gpu_uuid_raw(sp, nv)" in ioctl
assert "nv_xdev_ext_dma_finish(" in ioctl
assert "&entry->dma_lifetime" in ioctl
assert "nv_p2p_umem_quarantine_backing(entry)" in ioctl
assert ioctl.count("if (ceAmbiguous)\n                    nv_p2p_umem_quarantine_backing(entry);\n                else\n                    nv_xdev_ext_dma_finish(") == 1
assert ioctl.count("if (ceAmbiguous)\n                            nv_p2p_umem_quarantine_backing(entry);\n                        else\n                            nv_xdev_ext_dma_finish(") == 1
assert "if (ceAmbiguous || item->status != NV_OK)" in ioctl
for command in ("NV_ESC_P2P_PIN_UMEM", "NV_ESC_P2P_UNPIN_UMEM",
                "NV_ESC_P2P_DMA_XFER", "NV_ESC_P2P_DMA_XFER_BATCH"):
    command_case = ioctl[ioctl.index(f"case {command}"):]
    command_case = command_case[:command_case.index("break;")]
    assert "NV_ACTUAL_DEVICE_ONLY(nv);" in command_case
assert "sockfd_lookup(params->xsk_fd" in ioctl
assert "NV_P2P_PIN_F_HOST_REGION" in ioctl
assert "nv_pin_xsk_umem(" in ioctl
assert "nv_pin_host_region(" in ioctl
get_ref = ioctl.index("nv_p2p_umem_ioctl_handle_get(")
xfer_lock = ioctl.index("mutex_lock(&entry->operation_lock)", get_ref)
xfer_live = ioctl.index("if (!entry->live ||", xfer_lock)
xsk_revalidate = ioctl.index("nv_validate_xsk_umem(", xfer_live)
xfer_call = ioctl.index("nv_registered_region_dma_xfer(", get_ref)
unlock = ioctl.index("mutex_unlock(&entry->operation_lock)", xfer_call)
put_ref = ioctl.index("nv_p2p_umem_ioctl_handle_put(entry)", xfer_call)
pm_lock = ioctl.index("nv_down_read_interruptible(&nv_system_pm_lock)")
pm_unlock = ioctl.index("up_read(&nv_system_pm_lock)", put_ref)
assert pm_lock < get_ref < xfer_lock < xfer_live < xsk_revalidate < xfer_call
assert xfer_call < unlock < put_ref < pm_unlock

assert "NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS" in DMA_LIFETIME_H
assert "lifetime->quarantined = 1" in DMA_LIFETIME_H

# N1: RM reports hw_submitted, set only once a chunk enters memmgrMemCopy().
# A REQUIRE_CE refusal that memmgrMemCopy() would make before touching a
# channel is checked first, under the API lock, and ends the request as a
# pre-submit failure; only a failure inside the copy is ambiguous.
direct = function_body(RM_UMEM, "RmP2PUmemDmaRequestDirect")
assert "pCeAmbiguous" not in direct, "N1: RM still pre-classifies ambiguity"
loop = direct.index("while (remaining != 0)")
copy = direct.index("memmgrMemCopy(", loop)
reset = direct.index("*pHwSubmitted = NV_FALSE;", loop)
precheck = direct.index(
    "memmgrMemCopyUsesCe(pMemoryManager, &dstSurf, &srcSurf,", loop)
assert "transferFlags" in direct[precheck:direct.index(")", precheck)]
submitted = direct.rindex("*pHwSubmitted = NV_TRUE;", 0, copy)
assert loop < reset < precheck < submitted < copy
assert "break;" in direct[precheck:submitted]
assert "goto quarantine;" in direct[copy:]
assert "*pHwSubmitted = NV_FALSE;" not in direct[copy:]
umem_destroy = direct.index("memdescDestroy(tempHandle.pMemDesc);")
assert umem_destroy < direct.index("quarantine:")
assert "memdescDestroy(" not in direct[direct.index("quarantine:"):]
uses_ce = function_body(MEM_UTILS, "memmgrMemCopyUsesCe_IMPL")
assert "memmgrGetMemTransferType(pMemoryManager, pDstInfo, pSrcInfo,\n" \
       "                                    flags) == TRANSFER_TYPE_CE" in uses_ce
assert "memmgrMemCopyUsesCe_IMPL(" in MEM_MGR

rm_submit = function_body(OSAPI, "NV_STATUS NV_API_CALL rm_p2p_umem_dma_request(")
assert "g_xdev_ext_ce_poisoned" in rm_submit
assert "if (g_xdev_ext_ce_poisoned)" in rm_submit
assert "g_xdev_ext_ce_poisoned = NV_TRUE" in rm_submit
assert "if (rmStatus != NV_OK && hwSubmitted)\n" \
       "                    g_xdev_ext_ce_poisoned = NV_TRUE;" in rm_submit
assert "*pHwSubmitted = hwSubmitted;" in rm_submit
assert rm_submit.index("if (g_xdev_ext_ce_poisoned)") < rm_submit.index(
    "RmP2PUmemDmaRequestDirect("
)

# kernel-open turns (status, hw_submitted) into OK / PRE_SUBMIT_FAILED /
# AMBIGUOUS with the pure classifier; only AMBIGUOUS quarantines.
assert '#include "nv-xdev_ext-ce-classify.h"' in P2P
assert "xdev_ext_call.hwSubmitted" in xfer
assert "nv_xdev_ext_ce_classify(status, xdev_ext_call.hwSubmitted) ==\n" \
       "                  NV_XDEV_EXT_CE_AMBIGUOUS" in xfer
assert "&call->hwSubmitted" in submit

# A vidmem binding is also the actual-device ref: bind takes the Linux usage
# ref and RM external-client ref before RM dups the allocation, and only
# unbind releases them after RM drops the dup.  The ambiguous branch skips
# unbind permanently.  The opened GPU must own the allocation.
vbind = function_body(P2P, "NV_STATUS NV_API_CALL nv_p2p_vidmem_bind(")
vunbind = function_body(P2P, "NV_STATUS NV_API_CALL nv_p2p_vidmem_unbind(")
dev_get = function_body(NV, "int nvidia_dev_get_uuid(")
dev_put = function_body(NV, "void nvidia_dev_put_uuid(")
dev_ref = vbind.index("nvidia_dev_get_uuid(pExpectedGpuUuid, sp)")
bound = vbind.index("rm_p2p_umem_vidmem_bind(sp, gpuVA, length,")
identity = vbind.index("nv_p2p_gpu_identity_matches(pExpectedGpuUuid, gpu_uuid)")
assert dev_ref < bound < identity
assert "rm_p2p_umem_vidmem_unbind(sp, pBinding->rm)" in vbind[identity:]
assert vunbind.index("rm_p2p_umem_vidmem_unbind(sp, pBinding->rm)") < \
    vunbind.index("nvidia_dev_put_uuid(pBinding->gpu_uuid, sp)")
assert "nv_open_device(nv, sp)" in dev_get
assert "rm_set_external_kernel_client_count" in dev_get
assert "nv_close_device(" in dev_put
assert "rm_set_external_kernel_client_count" in dev_put

quarantine = function_body(NV, "static void nv_p2p_umem_quarantine_backing(")
for token in ("list_add_tail", "entry->owner = NULL", "__module_get(THIS_MODULE)",
              "xa_erase(", "kref_get(&entry->refcount)",
              "nv_xdev_ext_dma_quarantine_needs_ref(",
              "NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS"):
    assert token in quarantine
assert "!nv_xdev_ext_dma_can_submit" not in quarantine
release = function_body(NV, "static void nv_p2p_umem_ioctl_handle_release(")
assert "nv_xdev_ext_dma_can_release(&entry->dma_lifetime)" in release

handle_get = function_body(NV, "static nv_p2p_umem_ioctl_handle_t *nv_p2p_umem_ioctl_handle_get(")
handle_remove = function_body(NV, "static NV_STATUS nv_p2p_umem_ioctl_handle_remove(")
handle_release = function_body(NV, "static void nv_p2p_umem_ioctl_handle_release(")
assert "entry->owner == owner" in handle_get
assert "entry->owner_mm == current->mm" in handle_get
assert "entry->owner_tgid == task_tgid(current)" in handle_get
assert "kref_get(&entry->refcount)" in handle_get
assert "entry->owner_mm == current->mm" in handle_remove
assert "entry->owner_tgid == task_tgid(current)" in handle_remove
assert handle_remove.index("xa_erase(") < handle_remove.index(
    "mutex_lock(&entry->operation_lock)"
)
assert handle_remove.index("mutex_lock(&entry->operation_lock)") < handle_remove.index(
    "entry->live = NV_FALSE"
)
assert handle_remove.index("entry->live = NV_FALSE") < handle_remove.index(
    "nv_unpin_host_region(entry->kernel_handle)"
)
assert handle_remove.index("nv_unpin_host_region(entry->kernel_handle)") < handle_remove.index(
    "nv_p2p_umem_ioctl_handle_put(entry)"
)
assert "nv_unpin_host_region(entry->kernel_handle)" in handle_release
assert "sockfd_put(entry->xsk_socket)" in handle_release
assert "mmdrop(entry->owner_mm)" in handle_release
assert "put_pid(entry->owner_tgid)" in handle_release

# User handles include a generation as well as the xarray slot.  A stale
# handle must not become valid again when xa_alloc() reuses the same slot.
handle_insert = function_body(NV, "static NV_STATUS nv_p2p_umem_ioctl_handle_insert(")
assert "entry->user_handle" in handle_insert
assert "entry->user_handle == userHandle" in handle_get
assert "entry->user_handle == userHandle" in handle_remove

# Both actual GPU files and /dev/nvidiactl can reach these ioctls, so both
# close paths must retire their owner-scoped handles before freeing nvlfp.
close_callback = function_body(NV, "nvidia_close_callback(")
ctl_close = function_body(NV, "static int\nnvidia_ctl_close(")
assert close_callback.index("nv_p2p_umem_ioctl_handle_release_owner(nvlfp)") < \
       close_callback.index("nv_free_file_private(nvlfp)")
assert ctl_close.index("nv_p2p_umem_ioctl_handle_release_owner(nvlfp)") < \
       ctl_close.index("nv_free_file_private(nvlfp)")

# G1: the GPU surface is the bound vidmem memdesc at a checked window
# offset; RM builds no FBMEM memdesc from page-table addresses.  Every
# transfer is checked before the first copy.
rm_direct = function_body(RM_UMEM, "RmP2PUmemDmaRequestDirect")
assert '#include "mem_mgr/p2p_umem_vidmem.h"' in RM_UMEM
for token in ("memdescCreate(", "pGpuPhysPages", "memdescFillPages(pGpuMemDesc"):
    assert token not in rm_direct, f"G1: {token}"
assert "memdescGetAddressSpace(pGpuMemDesc) != ADDR_FBMEM" in rm_direct
window = rm_direct.index("nvP2PVidmemXferOffset(windowOffset, windowLength,")
assert window < rm_direct.index("_p2pCreateMemDesc(") < \
    rm_direct.index("while (remaining != 0)")
assert "srcSurf.pMemDesc = pGpuMemDesc;" in rm_direct
assert "dstSurf.pMemDesc = pGpuMemDesc;" in rm_direct
assert "*pBytesDone += chunkSize;" in rm_direct

batch_case = ioctl[ioctl.index("case NV_ESC_P2P_DMA_XFER_BATCH:") :]
batch_case = batch_case[:batch_case.index("default:")]
assert "params->count == 0" in batch_case
assert "params->count > NV_P2P_DMA_MAX_BATCH" in batch_case
batch_lock = batch_case.index("mutex_lock(&entry->operation_lock)")
batch_loop = batch_case.index("for (i = 0; i < params->count; i++)", batch_lock)
batch_validate = batch_case.index("nv_validate_xsk_umem(", batch_loop)
batch_xfer = batch_case.index("nv_registered_region_dma_xfer(", batch_validate)
batch_complete = batch_case.index("params->completed++", batch_xfer)
batch_unlock = batch_case.index("mutex_unlock(&entry->operation_lock)", batch_complete)
assert batch_lock < batch_loop < batch_validate < batch_xfer
assert batch_xfer < batch_complete < batch_unlock
assert "params->failed_index = i" in batch_case[batch_loop:batch_unlock]
assert "NV_ERR_NOT_READY" in batch_case

# G3: the four CE passthrough ioctls exist only in builds made with
# XDEV_EXT_ENABLE_GPU_CE_DMA=1 and answer only when nvidia.ko is loaded with
# NVreg_EnableXdevExtCeDma=1; the CE mechanism backend registers under the same
# two gates.
GATE = "XDEV_EXT_ENABLE_GPU_CE_DMA"
assert "ifeq ($(XDEV_EXT_ENABLE_GPU_CE_DMA),1)\n" \
       " NVIDIA_CFLAGS += -DXDEV_EXT_ENABLE_GPU_CE_DMA=1\nendif" in NV_KBUILD, \
    "G3: no XDEV_EXT_ENABLE_GPU_CE_DMA build switch"
assert NV_KBUILD.index("-DXDEV_EXT_ENABLE_GPU_CE_DMA=1") < NV_KBUILD.index(
    "$(call ASSIGN_PER_OBJ_CFLAGS, $(NVIDIA_OBJECTS), $(NVIDIA_CFLAGS))")
assert "#define __NV_ENABLE_XDEV_EXT_CE_DMA EnableXdevExtCeDma" in NV_REG
reg_entry = NV_REG.index("NV_DEFINE_REG_ENTRY_GLOBAL(__NV_ENABLE_XDEV_EXT_CE_DMA, 0);")
assert guarded(NV_REG, reg_entry, GATE)
assert guarded(NV_LINUX, NV_LINUX.index("extern NvU32 NVreg_EnableXdevExtCeDma;"), GATE)
gate_macro = NV.index("#define NV_XDEV_EXT_CE_DMA_ONLY()")
assert guarded(NV, gate_macro, GATE)
gate_body = NV[gate_macro:NV.index("\n\n", gate_macro)]
assert "NVreg_EnableXdevExtCeDma == 0" in gate_body
assert "status = -EOPNOTSUPP;" in gate_body and "goto done;" in gate_body
for command in ("NV_ESC_P2P_PIN_UMEM", "NV_ESC_P2P_UNPIN_UMEM",
                "NV_ESC_P2P_DMA_XFER", "NV_ESC_P2P_DMA_XFER_BATCH"):
    case_pos = NV.index(f"case {command}:")
    assert guarded(NV, case_pos, GATE), f"G3: {command} built without {GATE}"
    command_case = NV[case_pos:NV.index("break;", case_pos)]
    runtime_gate = command_case.index("NV_XDEV_EXT_CE_DMA_ONLY();")
    assert runtime_gate < command_case.index("NV_ACTUAL_DEVICE_ONLY(nv);")
    assert "params->" not in command_case[:runtime_gate]
for symbol in ("typedef struct nv_p2p_umem_ioctl_handle",
               "static DEFINE_XARRAY_ALLOC(g_nv_p2p_umem_ioctl_handles);",
               "static void nv_p2p_umem_ioctl_handle_release_owner("):
    assert guarded(NV, NV.index(symbol), GATE), symbol
release_calls = [m.start() for m in re.finditer(
    re.escape("nv_p2p_umem_ioctl_handle_release_owner(nvlfp);"), NV)]
assert len(release_calls) == 2
assert all(guarded(NV, pos, GATE) for pos in release_calls)
for source_path in sorted((ROOT / "kernel-open/nvidia").glob("*.c")):
    source = source_path.read_text()
    for m in re.finditer(r"\bxdev_ext_ce_backend_register\(", source):
        assert guarded(source, m.start(), GATE), source_path.name
        fn_start = source.rindex("\n{\n", 0, m.start())
        assert "NVreg_EnableXdevExtCeDma" in source[fn_start:m.start()], \
            source_path.name

# G4(a): pinned host pages reach the CE as page_to_phys() addresses with no
# IOMMU mapping, so pin only for a GPU with no IOMMU domain or an identity
# one; any translating domain fails closed.
assert "#include <linux/iommu.h>" in P2P
untranslated = function_body(
    P2P, "NvBool NV_API_CALL nv_p2p_umem_iommu_untranslated(")
assert "iommu_get_domain_for_dev(dev)" in untranslated
assert "domain == NULL || domain->type == IOMMU_DOMAIN_IDENTITY" in untranslated
assert "NvBool NV_API_CALL nv_p2p_umem_iommu_untranslated(struct device *dev);" \
       in P2P_H
pin_case = NV[NV.index("case NV_ESC_P2P_PIN_UMEM:"):
              NV.index("case NV_ESC_P2P_UNPIN_UMEM:")]
iommu_check = pin_case.index("!nv_p2p_umem_iommu_untranslated(nvl->dev)")
assert iommu_check < pin_case.index("sockfd_lookup(")
assert iommu_check < pin_case.index("nv_pin_host_region(")
assert "params->status = NV_ERR_NOT_SUPPORTED;\n                break;" in \
       pin_case[iommu_check:pin_case.index("sockfd_lookup(")]

# G9: a host region pin is charged to the global tracker and to the pinning
# mm's locked_vm; every exit after a successful charge and every unpin undo
# both, and account_locked_vm() (mmap_write_lock) never nests in the pin's
# mmap_read_lock.
lock_op = function_body(P2P, "static nv_xdev_ext_quota_u32 nv_p2p_umem_pin_lock(")
assert "account_locked_vm(mm, pages, true)" in lock_op, \
    "G9: pin is not charged to locked_vm"
unlock_op = function_body(P2P, "static void nv_p2p_umem_pin_unlock(")
assert "account_locked_vm(mm, pages, false)" in unlock_op
host_pin = function_body(P2P, "NV_STATUS NV_API_CALL nv_pin_host_region(")
assert "nv_p2p_umem_reserve_quota(" not in host_pin
assert "nv_p2p_umem_release_quota(" not in host_pin
charge = host_pin.index(
    "status = nv_xdev_ext_pin_charge(&nv_p2p_umem_pin_charge_ops, current->mm,")
assert charge < host_pin.index("nv_mmap_read_lock(current->mm);")
charge_failed = host_pin.index("return status;", charge)
after_charge = host_pin[charge_failed + len("return status;"):]
uncharge = "nv_xdev_ext_pin_uncharge(&nv_p2p_umem_pin_charge_ops, current->mm,"
assert after_charge.count(uncharge) == 2
previous_exit = 0
for m in re.finditer(r"\breturn ([^;]+);", after_charge):
    if m.group(1) != "NV_OK":
        assert uncharge in after_charge[previous_exit:m.start()], m.group(0)
    previous_exit = m.end()
success = after_charge.index("return NV_OK;")
assert after_charge.index("pBuffer->pinMm = current->mm;") < success
assert after_charge.index("mmgrab(current->mm);") < success
host_unpin = function_body(P2P, "NV_STATUS NV_API_CALL nv_unpin_host_region(")
assert "nv_p2p_umem_release_quota(" not in host_unpin
unpin_pages = host_unpin.rindex("NV_UNPIN_USER_PAGE(")
unpin_uncharge = host_unpin.index(
    "status = nv_xdev_ext_pin_uncharge(&nv_p2p_umem_pin_charge_ops, pinMm,")
assert unpin_pages < unpin_uncharge < host_unpin.index("mmdrop(pinMm);")

# E3: the copy-engine backend of the XDEV_EXT mechanism layer.  The kernel CE class
# (io_uring/xdev_ext_mech_ce.c) validates the plan the program built and calls
# this backend; nvidia.ko registers no kfunc or struct_ops of its own.
BACKEND_C = ROOT / "kernel-open/nvidia/nv-xdev_ext-ce-backend.c"
assert BACKEND_C.exists(), "E3: no copy-engine mechanism backend"
BACKEND = BACKEND_C.read_text()
BACKEND_H = (ROOT / "kernel-open/nvidia/nv-xdev_ext-ce-backend.h").read_text()
BOTH = "#if defined(XDEV_EXT_ENABLE_GPU_CE_DMA) && defined(CONFIG_XDEV_EXT_MECH_CE)"

# Built only with the switch and against a XDEV_EXT kernel with the CE class.
assert "ifeq ($(XDEV_EXT_ENABLE_GPU_CE_DMA),1)\n ifeq ($(CONFIG_XDEV_EXT_MECH_CE),y)\n" \
       "  NVIDIA_SOURCES += nvidia/nv-xdev_ext-ce-backend.c\n endif\nendif" in NV_KBUILD
assert NV_KBUILD.index("NVIDIA_SOURCES += nvidia/nv-xdev_ext-ce-backend.c") < \
    NV_KBUILD.index("nvidia-y := $(NVIDIA_OBJECTS)")
assert BOTH in BACKEND and BOTH in BACKEND_H
assert guarded(BACKEND, BACKEND.index("xdev_ext_ce_backend_register("), GATE)
for symbol in ("void nv_xdev_ext_ce_backend_init(", "void nv_xdev_ext_ce_backend_exit("):
    assert guarded(BACKEND_H, BACKEND_H.index(symbol), GATE), symbol

# Registered once the char devices exist and only under NVreg_EnableXdevExtCeDma,
# with nvidia's own file_operations so a /dev/nvidiaN stage fd selects it;
# unregistered first at module exit.
init = function_body(NV, "static int __init nvidia_init_module(void)")
backend_init = init.index("nv_xdev_ext_ce_backend_init(&nvidia_fops);")
assert init.index('"nvidiactl", &nvidia_fops);') < backend_init < \
    init.index("__nv_init_sp = sp;")
module_exit = function_body(NV, "static void __exit nvidia_exit_module(void)")
assert module_exit.index("nv_xdev_ext_ce_backend_exit();") < \
    module_exit.index("nv_unregister_chrdev(")
binit = function_body(BACKEND, "void nv_xdev_ext_ce_backend_init(")
assert binit.index("NVreg_EnableXdevExtCeDma == 0") < \
    binit.index("nv_xdev_ext_ce_backend.fops = fops;") < \
    binit.index("xdev_ext_ce_backend_register(&nv_xdev_ext_ce_backend)")
bexit = function_body(BACKEND, "void nv_xdev_ext_ce_backend_exit(")
assert "xdev_ext_ce_backend_unregister(&nv_xdev_ext_ce_backend)" in bexit
assert re.search(r"\.owner\s*=\s*THIS_MODULE,", BACKEND)

# bind_region: an actual GPU fd; the window is the CREATE caller's vidmem
# allocation through the G1 binding, which holds it while bound.
bind_region = function_body(BACKEND, "static int nv_xdev_ext_ce_bind_region(")
assert "nv_is_control_device(" in bind_region
assert "nv_p2p_vidmem_bind(uuid, gpu_va, len, &region->vidmem," in bind_region
assert "out->len = len;" in bind_region
assert "out->seg_size = seg_size;" in bind_region

# bind_host keeps the identity-only variant; the default maps GPU-device IOVAs.
bind_host = function_body(BACKEND, "static int nv_xdev_ext_ce_bind_host(")
iommu = bind_host.index("!nv_p2p_umem_iommu_untranslated(region->dev)")
assert "return -EOPNOTSUPP;" in bind_host[iommu:iommu + 80]
assert iommu < bind_host.index("kvzalloc(")
assert "page_to_phys(pages[i])" in bind_host
assert "#ifdef NV_XDEV_EXT_CE_PHYS_ADDR" in bind_host
assert "dma_map_sgtable(region->dev" in bind_host
for pin in ("pin_user_pages", "NV_PIN_USER_PAGES", "get_page("):
    assert pin not in BACKEND, pin

# submit: validate before native async RM admission. Success is completed by
# progress, while an ambiguous submit completes once and parks the region.
submit_ce = function_body(BACKEND, "static int nv_xdev_ext_ce_submit(")
entry = submit_ce.index("nv_xdev_ext_ce_entry_ok(")
request = submit_ce.index("nv_p2p_ce_async_submit(")
park = submit_ce.index("outcome == NV_XDEV_EXT_CE_AMBIGUOUS")
complete = submit_ce.index("xdev_ext_ce_complete(ck,")
assert submit_ce.count("xdev_ext_ce_complete(") == 1
assert submit_ce.index("nv_xdev_ext_ce_rm_direction(") < entry < request < park < complete
assert "nv_xdev_ext_ce_async_submitted(&h->pool, slot, status, issued, token)" in submit_ce
assert "NV_TRUE, 0);" in submit_ce[complete:]
assert "queue_work(system_unbound_wq, &h->progress)" in submit_ce
progress_ce = function_body(BACKEND, "static void nv_xdev_ext_ce_progress(")
assert "nv_p2p_ce_progress(h->rm, &watermark)" in progress_ce
assert "nv_xdev_ext_ce_async_ready(" in progress_ce
assert "xdev_ext_ce_complete(c->cookie, c->ticket" in progress_ce
assert progress_ce.index("mutex_unlock(&h->lock)") < progress_ce.index("xdev_ext_ce_complete(")
unbind_region = function_body(BACKEND, "static int nv_xdev_ext_ce_unbind_region(")
assert unbind_region.index("READ_ONCE(region->ambiguous)") < \
    unbind_region.index("nv_p2p_vidmem_unbind(region->vidmem)")

vrequest = function_body(P2P, "NV_STATUS NV_API_CALL nv_p2p_vidmem_dma_request(")
assert vrequest.count("rm_p2p_umem_dma_request(sp,") == 1
assert "pBytesDone" in vrequest

# The backend is the mechanism path only: it never reaches the old RM path and
# does not reroute the ioctl policy path (that one still runs nv_xdev_ext_gpu_run).
assert not legacy.search(BACKEND)
assert "nv_xdev_ext_gpu_run(" not in BACKEND
assert "nv_xdev_ext_gpu_run(" in xfer

print("PASS: GPU XDEV_EXT source-order contract")
