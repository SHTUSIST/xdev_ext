// SPDX-License-Identifier: GPL-2.0
/* Requirement-derived host semantic checks, not DMA or verifier proof.
 * The actual BPF program is included verbatim; only sized memory views and
 * libbpf calling/iteration syntax are replaced. No planner is copied here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xdev_ext_mech_kfunc.h"

static struct xdev_ext_mech_ctx call;
static struct xdev_ext_dma_mech_info info;
static struct xdev_ext_dma_copy_desc scratch[32];
static struct xdev_ext_dma_mech_cqe completion;
static int no_info, no_cqe, bad_access;

__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *m, size_t size)
{
 if (m != &call || size != sizeof(info)) { bad_access = 1; return NULL; }
 return no_info ? NULL : (__u8 *)&info;
}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *m, __u32 slot, size_t size)
{
 if (m != &call || size != sizeof(scratch[0])) { bad_access = 1; return NULL; }
 if (slot >= call.desc_cap || slot >= 32) return NULL;
 return (__u8 *)&scratch[slot];
}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *m, __u32 slot, size_t size)
{
 if (m != &call || slot || size != sizeof(completion)) { bad_access = 1; return NULL; }
 return no_cqe ? NULL : (__u8 *)&completion;
}

#ifndef DMA_REFERENCE_SOURCE
#define DMA_REFERENCE_SOURCE "../../../examples/compute/dma_plan.bpf.c"
#endif
#include DMA_REFERENCE_SOURCE

static unsigned int checks, failures;
static void check(int ok, const char *name)
{
 ++checks;
 if (!ok) { fprintf(stderr, "FAIL: %s\n", name); ++failures; }
}
static void reset(__u32 bytes)
{
 memset(&call, 0, sizeof(call)); memset(&info, 0, sizeof(info));
 memset(scratch, 0, sizeof(scratch)); memset(&completion, 0, sizeof(completion));
 no_info = no_cqe = bad_access = 0; key_base = 1;
 call.base.src_offset = 1; call.base.length = bytes;
 call.base.direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
 call.class_id = XDEV_EXT_MECH_CLASS_DMA;
 call.member = XDEV_EXT_MECH_MEMBER_BUILD;
 call.mech_abi_version = XDEV_EXT_MECH_ABI_VERSION;
 call.nr_frames = info.nr_frames = 1; call.desc_cap = 32;
 info.l.frame_size = 65536; info.l.hdr_room = 256;
 info.l.seg_len = bytes; info.l.group_bytes = bytes;
 info.window_len = (__u64)bytes * 2; info.max_entry_len = 65536;
 info.alignment = 256;
 info.directions = XDEV_EXT_DMA_DIR_KNOWN_MASK;
 info.f[0] = (struct xdev_ext_mech_frame_info){ .data_off = 256, .data_len = bytes };
}
static int build(void)
{
 int ret = dma_plan_build(NULL, &call);
 check(!bad_access, "only correctly sized callback views are requested");
 return ret;
}
static void aborts(const char *why)
{
 check(build() == XDEV_EXT_MECH_BUILD_ABORT, why);
}
static void descriptor(__u32 i, __u32 pos, __u32 off, __u64 dev, __u32 len, __u32 flags)
{
 const struct xdev_ext_dma_copy_desc *d = &scratch[i];
 check(d->frame_pos == pos && d->frame_off == off && d->device_off == dev &&
       d->len == len && d->flags == flags, "literal ordered descriptor and completion flag");
}
static void split_both_directions(void)
{
 /* A 1536-byte frame crosses 768-byte entries and 1024-byte segments.
  * The second frame starts halfway through a provider segment. */
 for (__u32 dir = 1; dir <= 2; ++dir) {
  reset(3072); call.base.direction = dir; call.base.src_offset = 2;
  call.nr_frames = info.nr_frames = 2;
  info.segment_size = 1024; info.max_entry_len = 768;
  info.f[0].data_len = 1536;
  info.f[1] = (struct xdev_ext_mech_frame_info){ .data_off = 768, .data_len = 1536 };
  check(build() == XDEV_EXT_MECH_BUILD_SUBMIT, "multi-frame split submits in either direction");
  descriptor(0, 0, 256, 3072, 768, 0);
  descriptor(1, 0, 1024, 3840, 256, 0);
  descriptor(2, 0, 1280, 4096, 512, 0);
  descriptor(3, 1, 768, 4608, 512, 0);
  descriptor(4, 1, 1280, 5120, 768, 0);
  descriptor(5, 1, 2048, 5888, 256, XDEV_EXT_DMA_F_COMPLETION_POINT);
  check(scratch[6].len == 0, "no extra trailing transfer");
 }
}
static void capacity_boundaries(void)
{
 reset(8192); info.max_entry_len = 256;
 check(build() == XDEV_EXT_MECH_BUILD_SUBMIT, "exactly 32 descriptors are legal");
 for (__u32 i = 0; i < 32; ++i)
  descriptor(i, 0, 256 + 256 * i, 256 * i, 256,
             i == 31 ? XDEV_EXT_DMA_F_COMPLETION_POINT : 0);
 reset(8448); info.max_entry_len = 256;
 aborts("33 descriptors must abort instead of silently truncating");
 reset(512); info.max_entry_len = 256; call.desc_cap = 1;
 aborts("insufficient C-owned scratch aborts");
}
static void invalid_inputs(void)
{
 reset(512); info.max_entry_len = 0; aborts("zero maximum entry cannot carry payload");
 reset(512); info.alignment = 0; aborts("zero alignment");
 reset(512); info.f[0].data_off = 1; aborts("misaligned frame start");
 reset(513); aborts("misaligned transfer length");
 reset(512); info.window_len = 511; aborts("window shorter than group");
 reset(512); call.base.src_offset = 3; aborts("key beyond final window slot");
 reset(512); call.base.src_offset = 0; aborts("key below key base");
 reset(512); call.base.src_offset = ULLONG_MAX; aborts("key-to-byte overflow");
 reset(512); info.l.group_bytes = 0; aborts("zero group");
 reset(512); call.nr_frames = info.nr_frames = 0; aborts("zero frames");
 reset(512); call.nr_frames = info.nr_frames = 33; aborts("frame count over 32");
 reset(512); info.f[0].data_len = 0; aborts("zero payload frame");
 reset(512); no_info = 1; aborts("missing info view");
}
static void active_payload_spans(void)
{
 /* group_bytes locates the batch slot. The current frame data_len, which
  * may change after an earlier stage, is the exact payload to cover. */
 reset(512); info.f[0].data_len = 256;
 check(build() == XDEV_EXT_MECH_BUILD_SUBMIT, "short current payload submits without extending to stride");
 descriptor(0, 0, 256, 0, 256, XDEV_EXT_DMA_F_COMPLETION_POINT);
 check(scratch[1].len == 0, "short payload does not fabricate stride padding");
 reset(512); info.f[0].data_len = 768;
 check(build() == XDEV_EXT_MECH_BUILD_SUBMIT, "current payload may exceed stride within frame and window");
 descriptor(0, 0, 256, 0, 768, XDEV_EXT_DMA_F_COMPLETION_POINT);
 check(scratch[1].len == 0, "larger payload is covered once without duplication");
}
static void final_window(void)
{
 reset(512); info.segment_size = 0; info.max_entry_len = 512;
 check(build() == XDEV_EXT_MECH_BUILD_SUBMIT, "zero segment size imposes no boundary");
 descriptor(0, 0, 256, 0, 512, XDEV_EXT_DMA_F_COMPLETION_POINT);
 reset(512); info.alignment = 1; info.segment_size = 1024; info.max_entry_len = 512;
 call.base.src_offset = 2;
 check(build() == XDEV_EXT_MECH_BUILD_SUBMIT, "last exactly fitting window slot submits");
 descriptor(0, 0, 256, 512, 512, XDEV_EXT_DMA_F_COMPLETION_POINT);
}
int main(void)
{
 split_both_directions(); capacity_boundaries(); invalid_inputs(); active_payload_spans(); final_window();
 if (failures) {
  fprintf(stderr, "FAIL: DMA reference host semantic checks (%u/%u assertions failed)\n", failures, checks);
  return 1;
 }
 printf("PASS: DMA reference host semantic checks (%u assertions)\n", checks);
 return 0;
}
