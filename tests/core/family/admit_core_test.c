// SPDX-License-Identifier: GPL-2.0
/* A trusted requester may reach discrete BAR memory only after topology
 * judgment, or an explicit administrator override; hard refusals never waive.
 * Defaults report only what CREATE actually established. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_requester_core.h"
#ifndef XDEV_EXT_PEER_REFUSE_NO_P2P_PATH
int main(void) { puts("not ok 1 - no requester admission: a requester is mapped without a reachability decision"); return 1; }
#else
static unsigned checks, failures;
#define EQ(a, b) do { long long av = (long long)(a), bv = (long long)(b); checks++; \
 if (av != bv) { if (failures++ < 16) fprintf(stderr, "%s:%d got %lld expected %lld\n", __func__, __LINE__, av, bv); } } while (0)

static void admission_matrix(void)
{
 static const int distances[] = { -99, -1, 0, 3, INT32_MAX };
 unsigned backing, bits, owner, d;
 for (backing = 0; backing < 32; backing++)
 for (owner = 0; owner < 2; owner++)
 for (d = 0; d < sizeof(distances) / sizeof(distances[0]); d++)
 for (bits = 0; bits < 64; bits++) {
  struct xdev_ext_admit_facts f = {
   .backing = backing, .owner_known = owner, .distance = distances[d],
   .untrusted = !!(bits & 1), .swiotlb_force = !!(bits & 2),
   .dma_iommu = !!(bits & 4), .dma_ops = !!(bits & 8), .admin = !!(bits & 16),
  };
  struct xdev_ext_admission a;
  bool override = !!(bits & 32), no_path = distances[d] < 0;
  bool wrong_memory = !owner || !(backing & 1) || (backing & 6);
  bool raw_translated = (backing & 16) && (bits & 12);
  bool hard = wrong_memory || (bits & 3) || (backing & 8) || raw_translated;
  bool permitted = !hard && (!no_path || (override && f.admin));
  int reach = !no_path ? XDEV_EXT_CAP_TOPOLOGY_PASSED :
   override && f.admin ? XDEV_EXT_CAP_UNVERIFIED_FORCED : XDEV_EXT_CAP_TOPOLOGY_FAILED;
  memset(&a, 0xa5, sizeof(a));
  EQ(xdev_ext_admit_decide(&f, override ? XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED : 0, &a), permitted ? 0 : -EXDEV);
  EQ(a.reachability, reach);
  EQ(a.distance, distances[d]); EQ(a.backing, backing);
  EQ(!!(a.refused & XDEV_EXT_PEER_REFUSE_NO_P2P_PATH), no_path);
  EQ(!!(a.refused & XDEV_EXT_PEER_REFUSE_BACKING), wrong_memory);
  EQ(!!(a.refused & XDEV_EXT_PEER_REFUSE_UNTRUSTED), f.untrusted);
  EQ(!!(a.refused & XDEV_EXT_PEER_REFUSE_SWIOTLB_FORCE), f.swiotlb_force);
  EQ(!!(a.refused & XDEV_EXT_PEER_REFUSE_IOMMU_RAW_ADDR), raw_translated);
  EQ(!!(a.refused & XDEV_EXT_PEER_REFUSE_EXTERNAL_OWNER), !!(backing & 8));
  EQ(a.refused & ~63U, 0);
 }
}

static void capability_defaults(void)
{
 /* Fixed policy rows from F3: NET/NVMe have a PEER requester in both
  * directions; all other current classes use host-page paths here. */
 static const struct { unsigned id, family; bool peer; } cases[] = {
  { XDEV_EXT_MECH_CLASS_NET, XDEV_EXT_FAMILY_NETWORK, true },
  { XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_FAMILY_STORAGE, true },
  { XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_FAMILY_NETWORK, false },
  { XDEV_EXT_MECH_CLASS_SOCKET, XDEV_EXT_FAMILY_NETWORK, false },
  { XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_FAMILY_COMPUTE, false },
  { XDEV_EXT_MECH_CLASS_DMA, XDEV_EXT_FAMILY_COMPUTE, false },
  { XDEV_EXT_MECH_CLASS_IAA, XDEV_EXT_FAMILY_COMPUTE, false },
  { XDEV_EXT_MECH_CLASS_CPU, XDEV_EXT_FAMILY_COMPUTE, false },
  { XDEV_EXT_MECH_CLASS_USER, XDEV_EXT_FAMILY_COMPUTE, false },
 };
 unsigned i, pool, dir;
 EQ(sizeof(struct xdev_ext_mech_stage_caps), 64);
 EQ(XDEV_EXT_MECH_OP_STAGE_CAPS, 8);
 for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
 for (pool = 0; pool < 2; pool++)
 for (dir = XDEV_EXT_MECH_DIR_TO_DEVICE; dir <= XDEV_EXT_MECH_DIR_FROM_DEVICE; dir++) {
  struct xdev_ext_mech_stage_uapi u = { .class_id = cases[i].id, .direction = dir };
  struct xdev_ext_mech_stage_caps c;
  /* Keep frozen F3 rows; strict USER adds only PEER TO_DEVICE. FROM_DEVICE
   * and every other class retain the original capability expectations. */
  bool peer = pool && (cases[i].peer ||
   (cases[i].id == XDEV_EXT_MECH_CLASS_USER && dir == XDEV_EXT_MECH_DIR_TO_DEVICE));
  unsigned na = XDEV_EXT_CAP_NOT_APPLICABLE;
  memset(&c, 0xa5, sizeof(c));
  xdev_ext_mech_stage_caps_default(&u, pool ? XDEV_EXT_MECH_POOL_PEER : XDEV_EXT_MECH_POOL_IOU_UMEM, &c);
  EQ(c.size, 64); EQ(c.version, 1); EQ(c.session_id, 0); EQ(c.stage, 0);
  EQ(c.family, cases[i].family);
  EQ(c.export_authority, peer ? XDEV_EXT_CAP_ESTABLISHED : na);
  EQ(c.reachability, peer ? XDEV_EXT_CAP_UNKNOWN : na);
  EQ(c.requester_mapping, peer ? XDEV_EXT_CAP_UNKNOWN : na);
  EQ(c.native_queue, XDEV_EXT_CAP_UNKNOWN);
  EQ(c.producer_visibility, peer ? XDEV_EXT_CAP_NOT_WIRED : na);
  EQ(c.last_use_quiescence, peer ? XDEV_EXT_CAP_NOT_WIRED : na);
  EQ(c.invalidation, peer ? XDEV_EXT_CAP_NOT_WIRED : na);
  EQ(c.p2p_distance, -1); EQ(c.backing, 0); EQ(c.refused, 0);
 }
}

static void unknown_backing_bits(void)
{
 unsigned bit;
 for (bit = 5; bit < 32; bit++) {
  struct xdev_ext_admit_facts f = { .distance = 3, .owner_known = true,
   .backing = XDEV_EXT_PEER_BACKING_MMIO_BAR | (1U << bit), .admin = true };
  struct xdev_ext_admission a;
  /* Unknown provider facts cannot become a successful BAR admission merely
   * because all currently known hard-refusal flags happen to be clear. */
  EQ(xdev_ext_admit_decide(&f, XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED, &a), -EXDEV);
  EQ(a.refused, XDEV_EXT_PEER_REFUSE_BACKING);
  EQ(a.reachability, XDEV_EXT_CAP_TOPOLOGY_PASSED);
  EQ(a.backing, f.backing);
  /* An override waives only the missing topology path, never unknown bits
   * or any simultaneous trust, bounce, ownership or translation refusal. */
  f.distance = -1; f.untrusted = true; f.swiotlb_force = true; f.dma_ops = true;
  f.backing |= XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR | XDEV_EXT_PEER_BACKING_EXTERNAL;
  EQ(xdev_ext_admit_decide(&f, XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED, &a), -EXDEV);
  EQ(a.refused, 63);
  EQ(a.reachability, XDEV_EXT_CAP_UNVERIFIED_FORCED);
 }
 {
  struct xdev_ext_admit_facts f = { .distance = 0, .owner_known = true,
   .backing = 0xffffffe1U, .admin = true };
  struct xdev_ext_admission a;
  EQ(xdev_ext_admit_decide(&f, XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED, &a), -EXDEV);
  EQ(a.refused, XDEV_EXT_PEER_REFUSE_BACKING);
 }
}
int main(void)
{
 admission_matrix(); unknown_backing_bits(); capability_defaults();
 printf("%s 1 - requester admission hard refusals, administrator override and honest capability defaults (%u checks, %u failures)\n", failures ? "not ok" : "ok", checks, failures);
 return failures != 0;
}
#endif
