#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[4]
pipeline = (ROOT / "nvme_xdp_pipeline.c").read_text()
runtime = (ROOT / "tools/nvme_gpu_nic_runtime.c").read_text()
makefile = (ROOT / "Makefile.pipeline").read_text()
readme = (ROOT / "tools/README_unified_ops.md").read_text()

runtime_init = pipeline.find("ngn_gpu_runtime_init(&ctx.gpu")
pipeline_run = pipeline.find("run_pipeline(&ctx")
runtime_cleanup = pipeline.find("ngn_gpu_runtime_cleanup(&ctx.gpu)")
xsk_delete = pipeline.find("xsk_socket__delete(ctx.xsk.xsk)")
redirect_detach = pipeline.find("ret = pipeline_detach_xsk_redirect(&ctx);")

checks = {
    "production chain target":
        "nvme_gpu_nic_pipeline:" in makefile,
    "no-CUDA build target is explicit":
        "nvme_gpu_nic_pipeline_host:" in makefile,
    "CUDA build selects the real runtime":
        "XDEV_EXT_NVME_GPU_NIC_WITH_CUDA" in makefile,
    "production initializes GPU after XSK and before pipeline":
        runtime_init >= 0 and pipeline_run >= 0 and runtime_init < pipeline_run,
    "GPU cleanup precedes XSK destruction":
        runtime_cleanup >= 0 and xsk_delete >= 0 and runtime_cleanup < xsk_delete,
    "redirect is detached before GPU and XSK cleanup":
        redirect_detach >= 0 and runtime_cleanup >= 0 and
        redirect_detach < runtime_cleanup < xsk_delete,
    "active redirect prevents backing destruction":
        "!xdev_ext_xsk_redirect_is_active(&ctx->xsk.redirect)" in pipeline,
    "pipeline embeds one journal per UMEM frame":
        re.search(r"ngn_frame_journal\s+chain_frames\s*\[\s*NUM_FRAMES\s*\]",
                  pipeline) is not None,
    "pipeline begins the frame journal":
        "ngn_journal_begin(" in pipeline,
    "source acceptance is explicit":
        "ngn_journal_source_accept(" in pipeline,
    "source completion is explicit":
        "ngn_journal_source_complete(" in pipeline,
    "GPU roundtrip is in the production path":
        "ngn_gpu_roundtrip_frames(" in pipeline,
    "sink acceptance is explicit":
        "ngn_journal_sink_accept(" in pipeline,
    "exact sink completion retires journal ownership":
        "ngn_journal_sink_complete(" in pipeline,
    "GPU pin is tied to the XSK fd":
        ".xsk_fd = xsk_fd" in runtime and ".flags = 0" in runtime,
    "runtime uses shared exact GPU identity": all(
        token in runtime for token in
        ('include/xdev_ext_gpu_identity.h', 'xdev_ext_gpu_identity_from_opened(',
         'XDEV_EXT_GPU_IDENTITY_ANY_MINOR')
    ) and "ngn_opened_gpu_bdf(" not in runtime,
    "runtime links shared GPU identity implementation":
        "tools/xdev_ext_gpu_identity.c" in makefile,
    "runtime uses bounded batch ioctl":
        "xdev_ext_nv_p2p_dma_batch(" in runtime,
    "runtime has no CUDA memcpy fallback":
        "cuMemcpy" not in runtime and "cudaMemcpy" not in runtime,
    "GPU ambiguity latches sequester":
        "runtime->sequestered = true" in runtime,
    "normal signals cannot release sequestered backing":
        all(sig in pipeline for sig in
            ("signal(SIGHUP, SIG_IGN)", "signal(SIGINT, SIG_IGN)",
             "signal(SIGQUIT, SIG_IGN)", "signal(SIGTERM, SIG_IGN)")),
    "operator documentation names both staged directions":
        all(text in readme for text in
            ("NVMe READ -> host XSK UMEM", "AF_XDP RX -> host XSK UMEM",
             "not NVMe-to-VRAM or NIC-to-VRAM", "gpu-chain-host")),
    "pipeline links the private redirect loader":
        "tools/xdev_ext_xsk_redirect.c" in makefile and "LIBBPF_LIBS" in makefile,
    "default build does not install the conflicting manual XDP object":
        re.search(r"^TARGETS\s*=\s*nvme_xdp_pipeline\s*$", makefile,
                  re.MULTILINE) is not None and "legacy-xdp:" in makefile,
}

failed = [name for name, ok in checks.items() if not ok]
if failed:
    for name in failed:
        print(f"FAIL: {name}")
    raise SystemExit(1)

print(f"PASS: {len(checks)} composite-chain source checks")
