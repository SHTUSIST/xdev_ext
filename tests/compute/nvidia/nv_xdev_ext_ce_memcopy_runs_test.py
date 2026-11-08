#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual ceutilsMemcopy_IMPL chunking of a non-contiguous copy.

Requirement (TODO.63): the XDEV_EXT copy-engine path registers the host frame
pool as a non-contiguous memory descriptor at 4 KiB page granularity, and the
bound GPU allocation is non-contiguous as well, so CeUtils emitted one CE
command (pushbuffer block, GPFIFO entry, doorbell) per 4 KiB page.  When the
caller requests it (CEUTILS_MEMCOPY_PARAMS.bCoalescePhysRuns), one command
must cover each run of pages whose programmed (PTE) addresses are physically
adjacent on both sides, so a group that is contiguous on both sides becomes
one command; every byte is still copied exactly once from and to the same
addresses, and only the final command carries the finish payload.  Callers
that do not ask keep the page-granular chunking byte for byte.

Each command is min(source run, destination run, remaining bytes), and
finding it looks only at pages that command uses: when one side is one long
run and the other is fragmented, the long side is not walked to its end again
for every command (that walk made a fragmented copy quadratic in its length).

The function body and the parameter struct are taken unchanged from the
given sources; memory descriptors and the push are host stubs.  This is a
host command-sequence test; it does not run a GPU or prove DMA.

Usage: python3 nv_xdev_ext_ce_memcopy_runs_test.py --source .../ce_utils.c
         --params-header .../generated/g_ce_utils_nvoc.h [--cc gcc]
"""

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile

TOKENS = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)


def block_end(source, opening):
    depth = 0
    for token in TOKENS.finditer(source, opening):
        if token.group() == "{":
            depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return token.end()
    raise ValueError("unbalanced block")


def extract_function(source, name, required=True):
    # Definitions in ce_utils.c put the return type on the previous line.
    match = re.search(r"(?m)^(?:static\s+)?[A-Za-z_][\w \t\*]*\n%s\s*\n?\(" % re.escape(name), source)
    if match is None:
        if required:
            raise ValueError("actual %s definition missing" % name)
        return ""
    opening = source.index("{", match.end())
    return source[match.start():block_end(source, opening)]


def extract_params(header):
    match = re.search(r"typedef struct\s*\{(?:(?!typedef struct).)*?\}\s*CEUTILS_MEMCOPY_PARAMS;", header, re.S)
    if match is None:
        raise ValueError("actual CEUTILS_MEMCOPY_PARAMS missing")
    return match.group(0)


PRELUDE = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t NvU64; typedef uint32_t NvU32; typedef uint8_t NvBool;
typedef int NV_STATUS; typedef NvU64 RmPhysAddr;
#define NV_TRUE 1
#define NV_FALSE 0
#define NV_U64_MAX UINT64_MAX
#define NV_OK 0
#define NV_ERR_INVALID_ARGUMENT 0x1f
#define NV_ERR_BUSY_RETRY 0x3
#define NV_MIN(a, b) ((a) < (b) ? (a) : (b))
#define CE_MAX_BYTES_PER_LINE 0xffffffffULL
#define NV0050_CTRL_MEMCOPY_FLAGS_PIPELINED (1U << 0)
#define NV0050_CTRL_MEMCOPY_FLAGS_ASYNC (1U << 1)
#define NV0050_CTRL_MEMSET_FLAGS_ASYNC (1U << 1)
#define NV_PRINTF(level, ...) do { } while (0)
#define NV_ASSERT_OR_RETURN(c, r) do { if (!(c)) return (r); } while (0)
typedef void (*ChannelCompletionCallback)(void *);
typedef enum { AT_GPU = 1 } ADDRESS_TRANSLATION;
#define FORCE_VMMU_TRANSLATION(md, at) (at)
enum { ADDR_SYSMEM = 1, ADDR_FBMEM = 2, ADDR_VIRTUAL = 3 };
typedef struct { int unused; } OBJGPU;
typedef struct { OBJGPU *pGpu; } OBJCHANNEL;
typedef struct CeUtils { OBJCHANNEL *pChannel; NvU64 lastSubmittedPayload; } CeUtils;
#define MAX_PAGES 64
typedef struct MEMORY_DESCRIPTOR {
    OBJGPU *pGpu;
    NvU64 size, pageArrayGranularity;
    NvU32 addrSpace, _cpuCacheAttrib;
    NvBool contiguous;
    RmPhysAddr pte[MAX_PAGES];
} MEMORY_DESCRIPTOR;
static NvU64 memdescGetSize(MEMORY_DESCRIPTOR *m) { return m->size; }
static NvU32 memdescGetAddressSpace(MEMORY_DESCRIPTOR *m) { return m->addrSpace; }
static NvBool memdescGetContiguity(MEMORY_DESCRIPTOR *m, ADDRESS_TRANSLATION at)
{ (void)at; return m->contiguous; }
/* Every page-array lookup, directly or through memdescGetPtePhysAddr. */
static unsigned long lookups;
static RmPhysAddr memdescGetPhysAddr(MEMORY_DESCRIPTOR *m, ADDRESS_TRANSLATION at, NvU64 off)
{
    (void)at;
    lookups++;
    if (m->contiguous) return m->pte[0] + off;
    return m->pte[off / m->pageArrayGranularity] + off % m->pageArrayGranularity;
}
/* The CE is programmed with these; a fixed tag keeps them distinct from
 * memdescGetPhysAddr so a chunk programmed from the wrong one is caught. */
#define PTE_TAG 0x100000000000ULL
static RmPhysAddr memdescGetPtePhysAddr(MEMORY_DESCRIPTOR *m, ADDRESS_TRANSLATION at, NvU64 off)
{ return memdescGetPhysAddr(m, at, off) | PTE_TAG; }
static NvBool ceutilsIsSubmissionPaused(CeUtils *c) { (void)c; return NV_FALSE; }
typedef struct {
    NvBool bCeMemcopy; NvU32 payload;
    NvU32 srcAddressSpace, dstAddressSpace, srcCpuCacheAttrib, dstCpuCacheAttrib;
    ChannelCompletionCallback pCompletionCallback; void *pCompletionCallbackArg;
    NvBool bSecureCopy, bEncrypt; NvU64 authTagAddr, encryptIvAddr;
    NvU64 srcAddr, dstAddr; NvU32 size;
} CHANNEL_PB_INFO;
#define MAX_CHUNKS 256
static struct { NvU64 src, dst; NvU32 size; NvBool finish, pipelined; NvU32 srcSpace, dstSpace; } chunk[MAX_CHUNKS];
static unsigned nchunks;
static NV_STATUS _ceutilsSubmitPushBuffer(CeUtils *c, NvBool pipelined, NvBool finish,
                                          CHANNEL_PB_INFO *info)
{
    (void)c;
    if (nchunks == MAX_CHUNKS) return NV_ERR_INVALID_ARGUMENT;
    chunk[nchunks].srcSpace = info->srcAddressSpace; chunk[nchunks].dstSpace = info->dstAddressSpace;
    chunk[nchunks].src = info->srcAddr; chunk[nchunks].dst = info->dstAddr;
    chunk[nchunks].size = info->size; chunk[nchunks].finish = finish;
    chunk[nchunks].pipelined = pipelined; nchunks++;
    return NV_OK;
}
static NV_STATUS channelWaitForFinishPayload(OBJCHANNEL *ch, NvU64 p)
{ (void)ch; (void)p; return NV_OK; }
'''

MAIN = r'''
#define PAGE 4096ULL
static OBJGPU gpu;
static OBJCHANNEL channel = { &gpu };
static CeUtils ce = { &channel, 0 };
static unsigned failures, checks;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; \
    fprintf(stderr, "FAIL %s:%d: ", name, __LINE__); fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); } } while (0)

static void fill(MEMORY_DESCRIPTOR *m, NvU32 space, NvU64 base, unsigned pages,
                 const unsigned *breaks, NvU64 jump)
{
    unsigned i, b = 0;
    NvU64 addr = base;
    memset(m, 0, sizeof(*m));
    m->pGpu = &gpu; m->size = pages * PAGE; m->pageArrayGranularity = PAGE;
    m->addrSpace = space;
    for (i = 0; i < pages; i++) {
        if (breaks && breaks[b] && breaks[b] == i) { addr += jump; b++; }
        m->pte[i] = addr;
        addr += PAGE;
    }
}

/* Copies [src_off, +len) -> [dst_off, +len); checks coverage and finish. */
static void run(const char *name, MEMORY_DESCRIPTOR *src, NvU64 src_off,
                MEMORY_DESCRIPTOR *dst, NvU64 dst_off, NvU64 len, int coalesce,
                unsigned want_chunks, const NvU32 *want_sizes)
{
    CEUTILS_MEMCOPY_PARAMS p;
    NvU64 done = 0;
    unsigned long used;
    unsigned i;
    NV_STATUS st;

    memset(&p, 0, sizeof(p));
    p.pSrcMemDesc = src; p.pDstMemDesc = dst;
    p.srcOffset = src_off; p.dstOffset = dst_off; p.length = len;
    p.flags = NV0050_CTRL_MEMCOPY_FLAGS_ASYNC;
#ifdef HAVE_COALESCE
    p.bCoalescePhysRuns = coalesce ? NV_TRUE : NV_FALSE;
#else
    if (coalesce) {
        failures++;
        fprintf(stderr, "FAIL %s: CEUTILS_MEMCOPY_PARAMS has no bCoalescePhysRuns request\n", name);
    }
#endif
    nchunks = 0;
    lookups = 0;
    st = ceutilsMemcopy_IMPL(&ce, &p);
    used = lookups;
    CHECK(st == NV_OK, "status 0x%x", st);
    printf("%s coalesce=%d chunks=%u lookups=%lu:", name, coalesce, nchunks, used);
    for (i = 0; i < nchunks; i++)
        printf(" %u", chunk[i].size);
    printf("\n");
    CHECK(nchunks == want_chunks, "%u CE commands, expected %u", nchunks, want_chunks);
    for (i = 0; i < nchunks; i++) {
        if (want_sizes && i < want_chunks)
            CHECK(chunk[i].size == want_sizes[i], "command %u size %u, expected %u",
                  i, chunk[i].size, want_sizes[i]);
        CHECK(chunk[i].src == memdescGetPtePhysAddr(src, AT_GPU, src_off + done),
              "command %u source 0x%llx", i, (unsigned long long)chunk[i].src);
        CHECK(chunk[i].dst == memdescGetPtePhysAddr(dst, AT_GPU, dst_off + done),
              "command %u destination 0x%llx", i, (unsigned long long)chunk[i].dst);
        CHECK(chunk[i].finish == (i + 1 == nchunks),
              "finish payload on command %u of %u", i, nchunks);
        CHECK(chunk[i].pipelined == (i != 0), "pipelining of command %u", i);
        done += chunk[i].size;
    }
    CHECK(done == len, "commands cover %llu of %llu bytes",
          (unsigned long long)done, (unsigned long long)len);
    CHECK(p.submittedWorkId == ce.lastSubmittedPayload && p.submittedWorkId != 0,
          "async work id");
    if (coalesce) {
        /*
         * Per command: 4 lookups for the programmed and logged addresses, 2
         * per side for its first page, then one per page the command uses
         * on either side plus the page that ends it.  A walk that runs to
         * the end of the longer side's run for every command exceeds this.
         */
        unsigned long src_pages = (unsigned long)((src_off % PAGE + len + PAGE - 1) / PAGE);
        unsigned long dst_pages = (unsigned long)((dst_off % PAGE + len + PAGE - 1) / PAGE);
        unsigned long bound = 11UL * nchunks + src_pages + dst_pages;

        CHECK(used <= bound, "%lu page-array lookups for %u commands over %lu+%lu pages, "
              "at most %lu expected", used, nchunks, src_pages, dst_pages, bound);
    }
}

static void virtual_host(int reverse)
{
    const char *name = reverse ? "virtual-host-d2h" : "virtual-host-h2d";
    MEMORY_DESCRIPTOR host, vid;
    static const unsigned every[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0 };
    static const unsigned device_break[] = { 8,0 };
    NvU64 base = 0x8000000000ULL, done = 0;
    CEUTILS_MEMCOPY_PARAMS p = {0};
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, every, 0x10000ULL);
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, 16, device_break, 0x200000ULL);
    p.pSrcMemDesc = reverse ? &vid : &host; p.pDstMemDesc = reverse ? &host : &vid;
    p.srcOffset = reverse ? 300 : 100; p.dstOffset = reverse ? 100 : 300;
    p.length = 10 * PAGE; p.flags = NV0050_CTRL_MEMCOPY_FLAGS_ASYNC;
    p.bCoalescePhysRuns = NV_TRUE;
    if (reverse) p.dstGpuVA = base; else p.srcGpuVA = base;
    nchunks = 0;
    NV_STATUS status = ceutilsMemcopy_IMPL(&ce, &p);
    CHECK(status == NV_OK && nchunks == 2, "virtual host ignores its physical run boundaries; status=%d chunks=%u", status, nchunks);
    for (unsigned i = 0; i < nchunks; i++) {
        NvU64 physical = memdescGetPtePhysAddr(&vid, AT_GPU, 300 + done);
        CHECK((reverse ? chunk[i].dst : chunk[i].src) == base + 100 + done,
              "host address is mapped base plus logical offset");
        CHECK((reverse ? chunk[i].src : chunk[i].dst) == physical, "GPU operand remains physical");
        CHECK((reverse ? chunk[i].dstSpace : chunk[i].srcSpace) == ADDR_VIRTUAL,
              "host command requests virtual addressing");
        CHECK((reverse ? chunk[i].srcSpace : chunk[i].dstSpace) == ADDR_FBMEM,
              "GPU command retains FB physical aperture");
        CHECK(chunk[i].finish == (i + 1 == nchunks), "only final command carries completion");
        done += chunk[i].size;
    }
    CHECK(done == p.length, "exact copy coverage across host DMA runs");
    p.srcGpuVA = reverse ? base : 0; p.dstGpuVA = reverse ? 0 : base;
    nchunks = 0;
    CHECK(ceutilsMemcopy_IMPL(&ce, &p) == NV_ERR_INVALID_ARGUMENT && nchunks == 0,
          "virtual override on FB descriptor rejected before any push");
    p.srcGpuVA = reverse ? 0 : NV_U64_MAX - PAGE; p.dstGpuVA = reverse ? NV_U64_MAX - PAGE : 0;
    nchunks = 0;
    CHECK(ceutilsMemcopy_IMPL(&ce, &p) == NV_ERR_INVALID_ARGUMENT && nchunks == 0,
          "overflowing virtual base rejected before any push");
}

int main(void)
{
    MEMORY_DESCRIPTOR host, vid;
    static const unsigned host_break5[] = { 5, 0 };
    static const unsigned vid_runs8[] = { 8, 0 };
    static const unsigned every[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0 };
    static const unsigned host_breaks[] = { 3, 8, 12, 0 };
    static const unsigned vid_breaks[] = { 2, 6, 12, 14, 0 };
    unsigned every64[MAX_PAGES];
    NvU32 sizes[MAX_PAGES], unaligned[11];
    unsigned i;

    for (i = 0; i < MAX_PAGES; i++) sizes[i] = PAGE;
    for (i = 0; i + 1 < MAX_PAGES; i++) every64[i] = i + 1;
    every64[MAX_PAGES - 1] = 0;

    /* Both sides adjacent: one command when asked, page-granular otherwise. */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, NULL, 0);
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, 16, NULL, 0);
    run("adjacent", &host, 0, &vid, 0, 16 * PAGE, 1, 1, (const NvU32[]){ 16 * PAGE });
    run("adjacent", &host, 0, &vid, 0, 16 * PAGE, 0, 16, sizes);
    /* Device to host is the same rule. */
    run("adjacent-d2h", &vid, 0, &host, 0, 16 * PAGE, 1, 1, (const NvU32[]){ 16 * PAGE });

    /* Host run breaks after page 4: two commands, split exactly there. */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, host_break5, 0x100000ULL);
    run("host-break", &host, 0, &vid, 0, 16 * PAGE, 1, 2,
        (const NvU32[]){ 5 * PAGE, 11 * PAGE });
    /* Same break from an unaligned start: the first run is shorter by it. */
    run("host-break-unaligned", &host, 100, &vid, 100, 10 * PAGE, 1, 2,
        (const NvU32[]){ 5 * PAGE - 100, 5 * PAGE + 100 });

    /* Device side in runs of 8 pages, host adjacent: the shorter run wins. */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, NULL, 0);
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, 16, vid_runs8, 0x200000ULL);
    run("device-runs", &host, 0, &vid, 0, 16 * PAGE, 1, 2,
        (const NvU32[]){ 8 * PAGE, 8 * PAGE });

    /* Unaligned offsets: the first run ends at the first break, not a page. */
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, 16, NULL, 0);
    run("unaligned", &host, 100, &vid, 300, 3 * PAGE, 1, 1, (const NvU32[]){ 3 * PAGE });
    /* Page-granular: each command ends at the nearer of the two page ends. */
    run("unaligned", &host, 100, &vid, 300, 3 * PAGE, 0, 7,
        (const NvU32[]){ PAGE - 300, 200, PAGE - 200, 200, PAGE - 200, 200, 100 });

    /* No adjacent pages: asking changes nothing. */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, every, 0x10000ULL);
    run("scattered", &host, 0, &vid, 0, 16 * PAGE, 1, 16, sizes);

    /* A contiguous descriptor keeps its single command either way. */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, NULL, 0);
    host.contiguous = NV_TRUE;
    vid.contiguous = NV_TRUE;
    run("contiguous", &host, 0, &vid, 0, 16 * PAGE, 0, 1, (const NvU32[]){ 16 * PAGE });
    run("contiguous", &host, 0, &vid, 0, 16 * PAGE, 1, 1, (const NvU32[]){ 16 * PAGE });

    /*
     * One side one long run, the other broken at every page: one command
     * per page of the fragmented side, each starting where the previous
     * ended, in both directions.
     */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, MAX_PAGES, NULL, 0);
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, MAX_PAGES, every64, 0x10000ULL);
    run("host-long-device-fragmented", &host, 0, &vid, 0, MAX_PAGES * PAGE, 1,
        MAX_PAGES, sizes);
    run("device-fragmented-host-long-d2h", &vid, 0, &host, 0, MAX_PAGES * PAGE, 1,
        MAX_PAGES, sizes);
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, MAX_PAGES, every64, 0x10000ULL);
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, MAX_PAGES, NULL, 0);
    run("host-fragmented-device-long", &host, 0, &vid, 0, MAX_PAGES * PAGE, 1,
        MAX_PAGES, sizes);
    /* Unaligned: the fragmented side's page ends decide every split. */
    unaligned[0] = PAGE - 300;
    for (i = 1; i < 10; i++) unaligned[i] = PAGE;
    unaligned[10] = 300;
    run("device-long-host-fragmented-unaligned", &vid, 100, &host, 300, 10 * PAGE, 1,
        11, unaligned);

    /* Runs break at different pages on each side: split at every break. */
    fill(&host, ADDR_SYSMEM, 0x40000000ULL, 16, host_breaks, 0x100000ULL);
    fill(&vid, ADDR_FBMEM, 0x200000000ULL, 16, vid_breaks, 0x200000ULL);
    run("interleaved-breaks", &host, 0, &vid, 0, 16 * PAGE, 1, 7,
        (const NvU32[]){ 2 * PAGE, PAGE, 3 * PAGE, 2 * PAGE, 4 * PAGE, 2 * PAGE, 2 * PAGE });

    virtual_host(0); virtual_host(1);
    printf("checks=%u failures=%u\n", checks, failures);
    return failures ? 1 : 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--params-header", required=True, type=Path)
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    source = args.source.read_text()
    params = extract_params(args.params_header.read_text())
    helper = extract_function(source, "_ceutilsPhysRunLength", required=False)
    actual = extract_function(source, "ceutilsMemcopy_IMPL")
    defines = ["-DHAVE_COALESCE"] if re.search(r"\bbCoalescePhysRuns\b", params) else []
    with tempfile.TemporaryDirectory(prefix="xdev-ce-memcopy-") as temp:
        build = Path(temp)
        c_file = build / "actual_ce_memcopy.c"
        binary = build / "actual_ce_memcopy"
        c_file.write_text(PRELUDE + "\n" + params + "\n" + helper + "\n" + actual + "\n" + MAIN)
        command = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", *defines, str(c_file), "-o", str(binary)]
        subprocess.run(command, check=True)
        result = subprocess.run([str(binary)], check=False)
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
