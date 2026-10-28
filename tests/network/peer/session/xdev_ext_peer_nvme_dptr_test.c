// SPDX-License-Identifier: GPL-2.0
/* One NVMe command over several GPU frames: SGL data blocks and PRP entries
 * built from the provider's peer DMA addresses (requirement P2). Pure rules;
 * no controller or GPU exists here.
 */
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include "../../../../drivers/nvme/host/xdev_ext_peer_nvme_core.h"
#ifndef XDEV_EXT_PEER_NVME_DPTR
int main(void)
{
 puts("not ok 1 - multi-frame peer NVMe data pointer (xdev_ext_peer_nvme_sgl_build/prp_build) missing");
 puts("not ok 2 - PRP fallback for controllers without SGL missing");
 return 1;
}
#else
static int failures;
#define CHECK(c, text) do { if (!(c)) { printf("not ok - %s (line %d)\n", text, __LINE__); failures++; } } while (0)
#define KIB 1024ULL
#define MIB (1024ULL * KIB)
static struct xdev_ext_peer_nvme_seg seg[300], out[300];
static uint64_t list[600];

static void sgl_cases(void)
{
 u32 n = 99, i;
 /* 16 x 64 KiB frames, provider maps them contiguously: one 1 MiB data block. */
 for (i = 0; i < 16; i++) seg[i] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL + i * 64 * KIB, 64 * KIB };
 CHECK(!xdev_ext_peer_nvme_sgl_build(seg, 16, out, 256, &n) && n == 1 &&
       out[0].addr == 0x40000000ULL && out[0].len == MIB, "contiguous 1 MiB over 16 frames is one inline SGL data block");
 /* Frame 5 lives elsewhere: three runs [0,5) [5] [6,16). */
 seg[5].addr = 0x90000000ULL;
 CHECK(!xdev_ext_peer_nvme_sgl_build(seg, 16, out, 256, &n) && n == 3 &&
       out[0].addr == 0x40000000ULL && out[0].len == 5 * 64 * KIB &&
       out[1].addr == 0x90000000ULL && out[1].len == 64 * KIB &&
       out[2].addr == 0x40000000ULL + 6 * 64 * KIB && out[2].len == 10 * 64 * KIB,
       "a remote frame splits the list into three data blocks in payload order");
 CHECK(xdev_ext_peer_nvme_sgl_build(seg, 16, out, 2, &n) == -EREMOTEIO && n == 0, "more blocks than list room: -EREMOTEIO");
 seg[5].addr = 0x40000000ULL + 5 * 64 * KIB;
 /* Merged length must fit the 32-bit SGL length field. */
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x100000000ULL, 0xfffff000U };
 seg[1] = (struct xdev_ext_peer_nvme_seg){ 0x100000000ULL + 0xfffff000ULL, 0x2000 };
 CHECK(!xdev_ext_peer_nvme_sgl_build(seg, 2, out, 4, &n) && n == 2 && out[0].len == 0xfffff000U &&
       out[1].len == 0x2000, "a run that would overflow the 32-bit length starts a new block");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000002ULL, 4096 };
 CHECK(xdev_ext_peer_nvme_sgl_build(seg, 1, out, 4, &n) == -EINVAL && n == 0, "non-dword address refused");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL, 4094 };
 CHECK(xdev_ext_peer_nvme_sgl_build(seg, 1, out, 4, &n) == -EINVAL, "non-dword length refused");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL, 0 };
 CHECK(xdev_ext_peer_nvme_sgl_build(seg, 1, out, 4, &n) == -EINVAL, "empty segment refused");
 CHECK(xdev_ext_peer_nvme_sgl_build(seg, 0, out, 4, &n) == -EINVAL, "no segment refused");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ UINT64_MAX - 4095, 8192 };
 CHECK(xdev_ext_peer_nvme_sgl_build(seg, 1, out, 4, &n) == -EOVERFLOW, "wrapping segment refused");
 if (!failures) puts("ok 1 - SGL data blocks merge DMA-contiguous peer pages across frames, bounded by list room");
}

static void prp_cases(void)
{
 u64 prp1 = 1, prp2 = 1;
 u32 n = 99, i;
 int before = failures;
 const u64 list_dma = 0x7000000ULL;
 /* 1 MiB in 16 contiguous 64 KiB frames with 4 KiB controller pages. */
 for (i = 0; i < 16; i++) seg[i] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL + i * 64 * KIB, 64 * KIB };
 CHECK(!xdev_ext_peer_nvme_prp_build(seg, 16, 12, list_dma, list, 512, &prp1, &prp2, &n) &&
       prp1 == 0x40000000ULL && prp2 == list_dma && n == 255, "1 MiB: PRP1 plus a 255-entry list");
 for (i = 0; i < 255 && n == 255; i++)
  if (list[i] != 0x40000000ULL + (i + 1) * 4 * KIB) { CHECK(0, "PRP list holds every following 4 KiB page in order"); break; }
 /* Non-contiguous frames: entries follow each frame's own addresses. */
 seg[1].addr = 0x90000000ULL;
 CHECK(!xdev_ext_peer_nvme_prp_build(seg, 2, 12, list_dma, list, 512, &prp1, &prp2, &n) && n == 31 &&
       list[14] == 0x40000000ULL + 15 * 4 * KIB && list[15] == 0x90000000ULL && list[30] == 0x90000000ULL + 15 * 4 * KIB,
       "a remote frame's pages continue the list at its own address");
 seg[1].addr = 0x40000000ULL + 64 * KIB;
 /* One page with an offset start: PRP1 only. Two pages: PRP2 is the second page. */
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000200ULL, 1024 };
 CHECK(!xdev_ext_peer_nvme_prp_build(seg, 1, 12, list_dma, list, 512, &prp1, &prp2, &n) &&
       prp1 == 0x40000200ULL && prp2 == 0 && n == 0, "a span inside one page uses PRP1 only");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000200ULL, 4096 };
 CHECK(!xdev_ext_peer_nvme_prp_build(seg, 1, 12, list_dma, list, 512, &prp1, &prp2, &n) &&
       prp1 == 0x40000200ULL && prp2 == 0x40001000ULL && n == 0, "a span over two pages puts the second page in PRP2");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL, 8192 };
 CHECK(!xdev_ext_peer_nvme_prp_build(seg, 1, 12, list_dma, list, 512, &prp1, &prp2, &n) &&
       prp2 == 0x40001000ULL && n == 0, "exactly two aligned pages need no list");
 /* Holes inside the payload are not PRP-describable. */
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL, 6144 };
 seg[1] = (struct xdev_ext_peer_nvme_seg){ 0x50000000ULL, 4096 };
 CHECK(xdev_ext_peer_nvme_prp_build(seg, 2, 12, list_dma, list, 512, &prp1, &prp2, &n) == -EINVAL && n == 0,
       "a middle segment ending off a page boundary refused");
 seg[0].len = 8192; seg[1].addr = 0x50000200ULL;
 CHECK(xdev_ext_peer_nvme_prp_build(seg, 2, 12, list_dma, list, 512, &prp1, &prp2, &n) == -EINVAL,
       "a later segment starting off a page boundary refused");
 seg[0] = (struct xdev_ext_peer_nvme_seg){ 0x40000002ULL, 4096 };
 CHECK(xdev_ext_peer_nvme_prp_build(seg, 1, 12, list_dma, list, 512, &prp1, &prp2, &n) == -EINVAL,
       "PRP1 must be dword aligned");
 for (i = 0; i < 16; i++) seg[i] = (struct xdev_ext_peer_nvme_seg){ 0x40000000ULL + i * 64 * KIB, 64 * KIB };
 CHECK(xdev_ext_peer_nvme_prp_build(seg, 16, 12, list_dma, list, 254, &prp1, &prp2, &n) == -EREMOTEIO && n == 0,
       "list longer than its room: -EREMOTEIO, no chaining");
 CHECK(xdev_ext_peer_nvme_prp_build(seg, 16, 11, list_dma, list, 512, &prp1, &prp2, &n) == -EINVAL,
       "controller page below 4 KiB refused");
 /* 64 KiB controller pages: 1 MiB is PRP1 + 15 entries. */
 CHECK(!xdev_ext_peer_nvme_prp_build(seg, 16, 16, list_dma, list, 512, &prp1, &prp2, &n) && n == 15 &&
       list[0] == 0x40000000ULL + 64 * KIB && list[14] == 0x40000000ULL + 15 * 64 * KIB, "page size follows page_shift");
 if (failures == before) puts("ok 2 - PRP entries cover every controller page of a multi-frame peer span");
}

int main(void)
{
 sgl_cases();
 prp_cases();
 return failures ? 1 : 0;
}
#endif
