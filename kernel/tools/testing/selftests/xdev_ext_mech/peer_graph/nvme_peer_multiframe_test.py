#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""One native NVMe command per multi-frame GPU batch, SGL or PRP (requirement P2).

Reuses the production extraction and native shims of nvme_peer_async_test.py
(software block queue, provider leases as bookkeeping, no GPU, controller or
DMA). A 1 MiB batch of sixteen 64 KiB frames must be exactly one command when
the transfer limit allows it, -E2BIG before acceptance when it does not, and on
a controller without SGL support the same batch is one command whose PRP1/PRP2
and PRP list name every 4 KiB page of the peer span in payload order.
"""
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "nvme_peer_async_test.py"))
KERNEL = BASE["KERNEL"]

EXTRA_SHIM = r'''
/* PRODUCTION_FUNCTIONS */'''

CASES = r'''
#define FRAMES 16
static void batch16(int i, u64 slba)
{
 batch_init(i, 0, 0, 65536, slba);
 bs[i].nr = FRAMES; bs[i].bytes = FRAMES * 65536;
 for (u32 k = 0; k < FRAMES; k++)
  bs[i].f[k] = (struct xdev_ext_mech_frame){ .umem_addr = (u64)k * 65536, .index = k, .data_len = 65536 };
}
static const void *coherent_host(u64 dma)
{ return dma >= coherent_base && dma < coherent_base + coherent_len ? (const u8 *)coherent_ptr + (dma - coherent_base) : NULL; }
static void case_sgl_one_command(void)
{
 provider_page = 65536; head.lba_shift = 9; ctrl_sgl = true; queue.max_hw_sectors = 4096;
 int e = executes;
 batch16(0, 64);
 CHECK(!SUBMIT(&st, &bs[0]), "1 MiB batch of sixteen 64 KiB GPU frames accepted");
 CHECK(executes == e + 1 && outstanding() == 1, "the whole 1 MiB batch is exactly one native command");
 struct request *r = nth_outstanding(0);
 struct nvme_command *c = r ? r->nr.cmd : NULL;
 CHECK(c && c->rw.slba == 64 && c->rw.length == 2047 && c->rw.opcode == 2, "command covers 2048 sectors from the batch SLBA");
 CHECK(c && c->rw.dptr.sgl.type == (NVME_SGL_FMT_LAST_SEG_DESC << 4) && c->rw.dptr.sgl.length == 3 * sizeof(struct nvme_sgl_desc),
       "frame 2 is remote: three SGL data blocks in one list");
 const struct nvme_sgl_desc *d = c ? coherent_host(c->rw.dptr.sgl.addr) : NULL;
 CHECK(d && d[0].addr == provider_dma(0) && d[0].length == 2 * 65536 && d[1].addr == provider_dma(2 * 65536) &&
       d[1].length == 65536 && d[2].addr == provider_dma(3 * 65536) && d[2].length == 13 * 65536,
       "SGL blocks follow the provider DMA addresses of the sixteen frames");
 CHECK(live_leases == FRAMES, "one provider lease per 64 KiB page while the command is outstanding");
 if (r) controller_complete(r, 0, 0, 0);
 worker_consume(0);
 CHECK(!live_leases && bs[0].publishes == 1 && !bs[0].status, "one completion, all leases released by the worker");
 puts("ok 1 - a 1 MiB multi-frame GPU batch is one NVMe command with an SGL over the peer addresses");
}
static void case_transfer_limit(void)
{
 queue.max_hw_sectors = 1024; /* 512 KiB */
 int e = executes, a = acquire_calls;
 batch16(1, 64);
 CHECK(SUBMIT(&st, &bs[1]) == -E2BIG && executes == e && acquire_calls == a && !live_leases && !allocated() && !bs[1].publishes,
       "a batch above the controller transfer limit is refused before any lease or request");
 queue.max_hw_sectors = 4096;
 puts("ok 2 - the transfer limit is checked before acceptance");
}
static void case_prp(void)
{
 ctrl_sgl = false;
 int e = executes;
 batch16(2, 128);
 int ret = SUBMIT(&st, &bs[2]);
 CHECK(!ret, "controller without SGL support accepts the 1 MiB GPU batch (PRP)");
 if (ret) { ctrl_sgl = true; return; }
 struct request *r = nth_outstanding(0);
 struct nvme_command *c = r->nr.cmd;
 CHECK(executes == e + 1 && outstanding() == 1, "PRP batch is one native command");
 CHECK(!(c->common.flags & NVME_CMD_SGL_ALL), "PRP command does not mark SGL data pointers");
 CHECK(c->rw.dptr.prp1 == provider_dma(0), "PRP1 is the first peer page");
 const u64 *list = coherent_host(c->rw.dptr.prp2);
 int bad = !list;
 for (u32 k = 1; list && k < 256; k++) if (list[k - 1] != provider_dma((u64)k * 4096)) { bad = 1; break; }
 CHECK(!bad, "PRP2 points at a list of the 255 following 4 KiB peer pages in payload order, remote frame included");
 controller_complete(r, 0, 0, 0); worker_consume(2);
 CHECK(!live_leases, "PRP leases released after the completion");
 ctrl_sgl = true;
 puts("ok 3 - without SGL support the same batch is one PRP command over the peer pages");
}

static void case_two_mib_prp(void)
{
 CHECK(nvme_xdev_ext_peer_resources_free(&priv), "drained resources can be resized for a 2 MiB peer frame");
 session.pool.frame_size = session.l.frame_size = session.l.seg_len = session.l.group_bytes = 2 * 1024 * 1024;
 CHECK(!nvme_xdev_ext_peer_resources_init(&st), "2 MiB PRP descriptor storage reserved at CREATE");
 provider_page = 4096; ctrl_sgl = false; queue.max_hw_sectors = 8192;
 batch_init(0, 0, 0, 2 * 1024 * 1024, 0);
 int ret = SUBMIT(&st, &bs[0]);
 CHECK(!ret, "2 MiB PRP command leases all 512 provider pages without a 256-SGL-entry lease cap");
 if (ret) return;
 struct request *r = nth_outstanding(0);
 const u64 *list = coherent_host(r->nr.cmd->rw.dptr.prp2);
 int bad = !list;
 for (u32 k = 1; list && k < 512; k++) if (list[k - 1] != provider_dma((u64)k * 4096)) bad = 1;
 CHECK(!bad && live_leases == 512, "2 MiB PRP contains 511 following pages, including provider discontinuity");
 controller_complete(r, 0, 0, 0); worker_consume(0);
 CHECK(!live_leases, "all 512 PRP leases released after completion");
 puts("ok 4 - PRP lease capacity is independent of the 256-entry SGL descriptor capacity");
}
int main(void)
{
 int rc;
 session.pool = (struct xdev_ext_mech_pool){ 3, 65536, 32 };
 session.l.frame_size = 65536; session.l.seg_len = 65536; session.l.group_bytes = FRAMES * 65536;
 session.depth = DEPTH;
 priv.ns = &ns; priv.identity.nsid = 7;
 INIT_RESOURCES;
 assert(!rc);
 case_sgl_one_command(); if (failures) return 1;
 case_transfer_limit(); if (failures) return 1;
 case_prp(); if (failures) return 1;
 case_two_mib_prp(); if (failures) return 1;
 return 0;
}
'''


def main():
    shim = BASE["SHIM"]
    for old, new in (
        ("#define MAX_TEST_FRAMES 4", "#define MAX_TEST_FRAMES 16"),
        ("{ (void)g; assert(d == &pci_device); coherent_live++; *dma = coherent_base; return calloc(1, n); }",
         "{ (void)g; assert(d == &pci_device); coherent_live++; *dma = coherent_base; coherent_len = n; return coherent_ptr = calloc(1, n); }"),
        ("/* PRODUCTION_FUNCTIONS */", EXTRA_SHIM),
    ):
        if old not in shim:
            raise SystemExit("not ok - harness anchor moved in nvme_peer_async_test.py: " + old)
        shim = shim.replace(old, new, 1)
    # The allocator records where the descriptor lists live.
    shim = shim.replace("static u64 coherent_base = 0x9000000ULL;",
                        "static u64 coherent_base = 0x9000000ULL;\nstatic void *coherent_ptr;\nstatic size_t coherent_len;", 1)
    prefix = BASE["MAIN"][:BASE["MAIN"].index("static void case_depth(void)")]
    text, code, fill, submit, have_res = BASE["extract"](BASE["production_source"]())
    BASE["build"].__globals__["SHIM"] = shim
    BASE["build"].__globals__["MAIN"] = prefix + CASES
    with tempfile.TemporaryDirectory(prefix="nvme-peer-multiframe-") as tmp:
        result = BASE["build"](text, code, fill, submit, have_res, Path(tmp), "actual")
        print(result.stdout, end="")
        if result.returncode:
            print(result.stderr, end="", file=sys.stderr)
            raise SystemExit("not ok - multi-frame GPU NVMe command contract violated")


if __name__ == "__main__":
    main()
