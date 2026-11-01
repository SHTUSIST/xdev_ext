// SPDX-License-Identifier: GPL-2.0
/* Actual BPF callback + actual admission; map/kfunc transport is host-only. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef BLOCKTABLE_BASELINE
#define nvme_s0_build blocktable_build
#define nvme_s0_complete blocktable_complete
#include "nvme_s0.bpf.c"
#include "nvme_blocktable.h"
#else
#include "nvme_blocktable.bpf.c"
#endif
#include "include/linux/nvme_xdev_ext_passthru.h"
static struct xdev_ext_nvme_mech_info info;
static struct xdev_ext_nvme_mech_cqe cqe;
static unsigned char scratch[64];
static struct blocktable_value entries[3];
static int missing, no_info, no_desc, no_cqe;
void *bpf_map_lookup_elem(const void *map, const void *key)
{
    const struct blocktable_key *k = key;
    (void)map;
    if (missing || k->session_id != 42 || k->logical_key < 100 || k->logical_key > 102)
        return NULL;
    return &entries[k->logical_key - 100];
}
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, size_t n)
{ (void)ctx; return !no_info && n == sizeof(info) ? (void *)&info : NULL; }
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t n)
{ (void)ctx; return !no_desc && !slot && n == sizeof(scratch) ? scratch : NULL; }
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t n)
{ (void)ctx; return !no_cqe && !slot && n == sizeof(cqe) ? (void *)&cqe : NULL; }
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, msg); return 1; } } while (0)
static struct xdev_ext_mech_ctx context(void)
{
    struct xdev_ext_mech_ctx c = { .session_id = 42, .callsite = XDEV_EXT_MP_SITE_WORKER };
    c.base.direction = XDEV_EXT_MP_DIR_FROM_DEVICE;
    c.base.length = 4096;
    c.base.src_offset = 100;
    c.base.request_id = 7; /* deliberately unrelated to logical key */
    memset(&info, 0, sizeof(info));
    info.window_slba = 2048; info.window_nlb = 64; info.capacity_lbas = 4096;
    info.lba_shift = 9; info.l.group_bytes = 4096; info.max_nlb = 8;
    entries[0] = (struct blocktable_value){ 12288, 4096, 0 };
    return c;
}
static int mappings(void)
{
    /* Fixed map contents and fixed expected LBAs; no builder helper oracle. */
    static const unsigned offsets[2][3] = { {12288,0,24576}, {16384,20480,4096} };
    static const unsigned want[2][3] = { {2072,2048,2096}, {2080,2088,2056} };
    static const unsigned char markers[2][3] = { {3,0,6}, {4,5,1} };
    unsigned char disk[32768], got[12288], expected[12288];
    struct xdev_ext_mech_ctx ctx = context();
    struct nvme_xdev_ext_mech_bounds b = { .window_slba=2048, .window_nlb=64,
        .capacity_lbas=4096, .data_len=4096, .lba_shift=9 };
    struct nvme_xdev_ext_decoded d;
    unsigned m, i;
    for (i=0; i<8; i++) memset(disk + i*4096, i, 4096);
    for (m=0; m<2; m++) {
        for (i=0; i<3; i++) entries[i] = (struct blocktable_value){ offsets[m][i], 4096, 0 };
        for (i=0; i<3; i++) {
            unsigned char literal[64] = { [0]=2, [40]=want[m][i]&255, [41]=8, [48]=7 };
            ctx.base.src_offset = 100+i;
            memset(scratch, 0, sizeof(scratch));
            CHECK(blocktable_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT,"valid map SUBMIT");
            CHECK(!memcmp(scratch,literal,64),"fixed complete descriptor oracle");
            CHECK(!nvme_xdev_ext_mech_validate(scratch,&b,&d),"production admission");
            CHECK(d.slba==want[m][i] && d.nlb==8 && !d.write,"fixed decoded LBA/length");
            memcpy(got+i*4096,disk+(d.slba-2048)*512,4096);
            memset(expected+i*4096,markers[m][i],4096);
        }
        CHECK(!memcmp(got,expected,sizeof(got)),"full independent output bytes");
    }
    puts("PASS map-only remap: fixed descriptors and complete output bytes");
    return 0;
}
#define ABORT(msg) do { memset(scratch,0xa5,sizeof(scratch)); CHECK(blocktable_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT,msg); } while(0)
static int negatives(void)
{
    struct xdev_ext_mech_ctx ctx = context();
    missing=1; ABORT("missing entry"); missing=0;
    ctx.session_id=43; ABORT("other session"); ctx.session_id=42;
    ctx.base.src_offset=103; ABORT("unknown logical key"); ctx.base.src_offset=100;
    entries[0].byte_offset=1; ABORT("misaligned offset");
    entries[0].byte_offset=32768; ABORT("past window");
    entries[0].byte_offset=UINT64_MAX; ABORT("offset overflow");
    entries[0].byte_offset=UINT64_MAX-511; ABORT("aligned offset overflow");
    entries[0].byte_offset=29184; ABORT("length crosses window");
    ctx=context(); entries[0].byte_offset=28672;
    memset(scratch,0,sizeof(scratch));
    CHECK(blocktable_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT,"exact window end is legal");
    CHECK(scratch[40]==56 && scratch[41]==8,"literal last legal LBA 2104");
    ctx=context(); entries[0].byte_length=4095; ABORT("misaligned length");
    entries[0].byte_length=0; ABORT("zero length");
    entries[0].byte_length=8192; ABORT("map length differs from batch");
    ctx=context(); entries[0].reserved=1; ABORT("unknown map flags");
    ctx=context(); ctx.base.length=0x100001000ULL; ABORT("wide batch length");
    ctx=context(); ctx.base.length=4095; ABORT("unaligned batch");
    ctx=context(); info.l.group_bytes=8192; ABORT("group mismatch");
    ctx=context(); info.lba_shift=8; ABORT("shift below minimum");
    info.lba_shift=32; ABORT("shift above maximum");
    ctx=context(); info.window_nlb=0; ABORT("empty window");
    ctx=context(); info.window_slba=UINT64_MAX-3; ABORT("window wraparound");
    ctx=context(); info.window_nlb=UINT64_MAX; ABORT("oversized window");
    ctx=context(); info.capacity_lbas=2079; ABORT("request outside capacity");
    ctx=context(); info.max_nlb=7; ABORT("transfer limit");
    ctx=context();
    entries[0].byte_length=33554944; ctx.base.length=33554944;
    info.l.group_bytes=33554944; info.max_nlb=65537; info.window_nlb=65537;
    info.capacity_lbas=100000; entries[0].byte_offset=0;
    ABORT("NVMe encoded NLB limit");
    ctx=context(); ctx.base.direction=XDEV_EXT_MP_DIR_TO_DEVICE; ABORT("READ-only");
    ctx=context(); no_info=1; ABORT("missing info"); no_info=0;
    no_desc=1; ABORT("missing descriptor"); no_desc=0;
    ctx=context();
    CHECK(blocktable_complete(NULL,&ctx)==XDEV_EXT_MP_NEXT,"complete NEXT");
    ctx.callsite=XDEV_EXT_MP_SITE_URING_CMD;
    CHECK(blocktable_complete(NULL,&ctx)==XDEV_EXT_MP_DONE,"complete DONE");
    cqe.err=-EIO; CHECK(blocktable_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT,"error abort"); cqe.err=0;
    cqe.status=1; CHECK(blocktable_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT,"status abort"); cqe.status=0;
    no_cqe=1; CHECK(blocktable_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT,"missing completion");
    puts("PASS fail-closed boundaries and completion (host only)");
    return 0;
}
int main(void) { return mappings() || negatives(); }
