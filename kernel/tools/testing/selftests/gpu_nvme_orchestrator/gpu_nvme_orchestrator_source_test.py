#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
SOURCE = (ROOT / "gpu_nvme_orchestrator.c").read_text()
CORE = (ROOT / "gpu_nvme_orchestrator_core.h").read_text()
MAKEFILE = (Path(__file__).resolve().parent / "Makefile").read_text()
PIPELINE_MAKEFILE = (ROOT.parent / "Makefile.pipeline").read_text()

checks = {
    "setup-only claim removed": "setup-only" not in SOURCE.lower(),
    "fixed vectored native command": all(
        token in SOURCE
        for token in (
            "NVME_URING_CMD_IO_VEC",
            "IORING_URING_CMD_FIXED",
            "NVME_URING_CMD_F_XDEV_EXT",
        )
    ),
    "host-region pin is explicit": all(
        token in SOURCE
        for token in ("XDEV_EXT_NV_P2P_PIN_F_HOST_REGION", ".xsk_fd = -1")
    ),
    "gpu transfers use bounded batch ioctl": all(
        token in SOURCE
        for token in (
            "XDEV_EXT_NV_P2P_MAX_BATCH",
            "xdev_ext_nv_p2p_dma_batch",
            "gpu_batch_syscalls",
        )
    ),
    "gpu stage is one bounded ioctl": (
        "#define GNO_MAX_BATCH XDEV_EXT_NV_P2P_MAX_BATCH" in CORE
        and "while (first < batch->count)" not in CORE
    ),
    "single gpu transfer fallback is absent": "xdev_ext_nv_p2p_dma_xfer(" not in SOURCE,
    "gpu completed prefix checks every native status": (
        "batch.entries[i].status != XDEV_EXT_NV_OK" in SOURCE
    ),
    "host registration is frame padded": all(
        token in CORE
        for token in ("GNO_HOST_FRAME_SIZE", "gno_required_registered_umem")
    ),
    "cuda ordinal uniquely matches opened gpu PCI identity": all(
        token in SOURCE
        for token in (
            "gpu_pci_bdf", "cuDeviceGetCount", "cuDeviceGetPCIBusId",
            "matches != 1", "matched_ordinal != runtime->cli.gpu_index",
        )
    ),
    "opened GPU identity uses shared strict resolver": all(
        token in SOURCE for token in
        ('include/xdev_ext_gpu_identity.h', 'xdev_ext_gpu_identity_from_opened(',
         'XDEV_EXT_GPU_IDENTITY_ANY_MINOR')
    ) and "static int verify_gpu_device(" not in SOURCE,
    "production builds link shared GPU identity implementation":
        "../../../xdev_ext_gpu_identity.c" in MAKEFILE,
    "cuda cleanup calls are checked": all(
        token in SOURCE
        for token in (
            "cuda_result(cuMemFree",
            "cuda_result(cuDevicePrimaryCtxRelease",
            "cleanup_attempted",
        )
    ),
    "write mode opens char device read-write": bool(
        re.search(r"writes\s*\?\s*O_RDWR", SOURCE)
    ),
    "write requires explicit gate": all(
        token in SOURCE for token in ("--allow-write", "!cli->allow_write")
    ),
    "window is local configuration": all(
        token in SOURCE
        for token in ("authorized_first_lba", "authorized_lbas", "request_index")
    ),
    "true iopoll is opt-in and proven": all(
        token in SOURCE
        for token in ("IORING_SETUP_IOPOLL", "prove_iopoll", "--iopoll")
    ),
    "accepted prefix is observed from sq head": all(
        token in SOURCE
        for token in ("head_start", "consumed = head_after - head_start", "accepted_out")
    ),
    "unsafe backing is retained": all(
        token in SOURCE
        for token in ("backing_retained", "DMA quiescence was not proven")
    ),
    "ambiguous dma keeps the process and backing alive": all(
        token in SOURCE for token in ("sequester_backing", "SIG_IGN", "pause()")
    ),
    "help explains sequester recovery": all(
        token in SOURCE
        for token in ("ambiguous DMA failure", "verify device quiescence", "SIGKILL")
    ),
    "cuda-less build fails closed": all(
        token in SOURCE
        for token in ("XDEV_EXT_GPU_NVME_WITH_CUDA", "has no CUDA support")
    ),
    "cuda production build has an explicit target": all(
        token in MAKEFILE for token in ("cuda:", "XDEV_EXT_GPU_NVME_WITH_CUDA", "-lcuda")
    ),
    "top-level production builds expose host and CUDA targets": all(
        token in PIPELINE_MAKEFILE
        for token in (
            "gpu-nvme: gpu_nvme_orchestrator",
            "gpu-nvme-host: gpu_nvme_orchestrator_host",
            "tools/gpu_nvme_orchestrator.c",
            "tools/xdev_ext_gpu_identity.c",
            "-DXDEV_EXT_GPU_NVME_WITH_CUDA",
            "$(CUDA_LDLIBS)",
        )
    ),
    "roundtrip checks returned bytes before write": bool(
        re.search(r"compare_umem.*gno_nvme_stage", CORE, re.S)
    ),
    "core never re-executes a batch": "if (batch->executed)" in CORE,
    "gpu path is named synchronous": "gpu_batch_sync" in CORE,
    "no cpu data-copy fallback in gpu backend": "memcpy(" not in SOURCE[
        SOURCE.index("static int backend_gpu_batch") :
        SOURCE.index("static int backend_compare_umem")
    ],
}

failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(f"{'ok' if ok else 'not ok'} - {name}")
print(f"gpu_nvme_orchestrator_source: {len(checks)} checks, {len(failed)} failures")
sys.exit(1 if failed else 0)
