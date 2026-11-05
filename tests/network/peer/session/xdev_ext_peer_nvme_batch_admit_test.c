// SPDX-License-Identifier: GPL-2.0
/* Whole-batch admission of the synchronous peer NVMe batch (42-PEER-BATCH,
 * 42-RANDOM): every request of a batch is admitted before any device sees
 * the batch. Each request names its own device-memory offset and LBA; a
 * request may span several provider pages; destinations of one batch must
 * be disjoint (device memory for a read, LBAs for a write) because the
 * commands of one batch may be in flight together. Pure rules only.
 */
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include "../../../../drivers/nvme/host/xdev_ext_peer_nvme_core.h"
#ifndef XDEV_EXT_PEER_NVME_BATCH_ADMIT
int main(void)
{
 puts("not ok 1 - whole-batch peer NVMe admission (xdev_ext_peer_nvme_batch_admit) missing");
 return 1;
}
#else
static int failures, checks;
#define CHECK(c, text) do { checks++; if (!(c)) { printf("not ok %d - %s (line %d)\n", checks, text, __LINE__); \
	failures++; } else printf("ok %d - %s\n", checks, text); } while (0)
#define KIB 1024U
#define MIB (1024U * KIB)
#define CAP 1000000ULL /* namespace capacity in LBAs */
static struct xdev_ext_peer_nvme_range dst[64];
static struct xdev_ext_peer_nvme_plan plan;

/* Admit request i with 512-byte LBAs, no metadata, 1 MiB transfer limit. */
static int admit(int write, uint64_t offset, uint64_t slba, uint32_t bytes, uint32_t i)
{
 memset(&plan, 0xa5, sizeof(plan));
 return xdev_ext_peer_nvme_batch_admit(9, CAP, 0, 0, MIB, write, offset, slba, bytes,
				       dst, i, &plan);
}

int main(void)
{
 /* A 1 MiB request is one native command: 2048 LBAs, any device-memory offset. */
 CHECK(!admit(0, 3 * MIB + 512, 4096, MIB, 0) && plan.slba == 4096 && plan.bytes == MIB &&
       plan.nlb == 2047 && plan.opcode == 2 && dst[0].start == 3 * MIB + 512 && dst[0].len == MIB,
       "1 MiB read at an unaligned device-memory offset is admitted as one command");
 CHECK(admit(0, 0, 0, MIB + 512, 0) == -E2BIG, "request above the queue transfer limit refused");
 CHECK(xdev_ext_peer_nvme_batch_admit(9, CAP, 0, 0, 512 * KIB, 0, 0, 0, MIB, dst, 0, &plan) == -E2BIG,
       "transfer limit is the caller's queue limit, not a fixed constant");

 /* Destinations of one batch must be disjoint: duplicate, overlap, containment. */
 CHECK(!admit(0, 64 * KIB, 100, 8 * KIB, 0), "first read target admitted");
 CHECK(admit(0, 64 * KIB, 900, 8 * KIB, 1) == -EINVAL, "duplicate read target refused");
 CHECK(admit(0, 68 * KIB, 900, 8 * KIB, 1) == -EINVAL, "partially overlapping read target refused");
 CHECK(admit(0, 60 * KIB, 900, 32 * KIB, 1) == -EINVAL, "read target containing an earlier one refused");
 CHECK(admit(0, 66 * KIB, 900, 1 * KIB, 1) == -EINVAL, "read target inside an earlier one refused");
 CHECK(admit(0, 60 * KIB, 900, 4 * KIB + 512, 1) == -EINVAL, "one shared byte at the start refused");
 CHECK(!admit(0, 72 * KIB, 900, 4 * KIB, 1) && dst[1].start == 72 * KIB && dst[1].len == 4 * KIB,
       "adjacent read target after an earlier one admitted");
 CHECK(!admit(0, 56 * KIB, 100, 8 * KIB, 2) && dst[2].start == 56 * KIB,
       "adjacent read target before, from a duplicate source LBA, admitted (sources may overlap)");
 CHECK(admit(0, 76 * KIB - 512, 5, 1024, 3) == -EINVAL, "overlap with a later-admitted request refused");
 CHECK(!admit(0, 1, 5, 512, 3) && dst[3].start == 1,
       "random byte offset in device memory admitted (provider checks alignment and range)");

 /* Writes: the destination is the LBA range; device-memory sources may overlap. */
 CHECK(!admit(1, 0, 10, 4 * KIB, 0) && plan.opcode == 1 && dst[0].start == 10 && dst[0].len == 8,
       "write records its LBA destination");
 CHECK(admit(1, 8 * MIB, 17, 4 * KIB, 1) == -EINVAL, "write LBA destinations sharing one LBA refused");
 CHECK(admit(1, 0, 10, 4 * KIB, 1) == -EINVAL, "duplicate write destination refused");
 CHECK(!admit(1, 0, 18, 4 * KIB, 1) && dst[1].start == 18 && dst[1].len == 8,
       "adjacent write LBA range from the same device-memory source admitted");
 CHECK(!admit(1, 2 * KIB, 2, 4 * KIB, 2), "write LBA range ending where an earlier one starts admitted");

 /* Bounds and integer overflow are refused before any device sees the batch. */
 CHECK(admit(0, UINT64_MAX - 4095, 0, 8 * KIB, 0) == -EOVERFLOW, "device-memory span wrapping u64 refused");
 CHECK(admit(0, UINT64_MAX - 8191, 0, 8 * KIB, 0) == -EOVERFLOW,
       "device-memory span ending exactly at 2^64 refused (end not representable)");
 CHECK(!admit(0, UINT64_MAX - 16383, 0, 8 * KIB, 0),
       "largest non-wrapping device-memory span is left to the provider range check");
 CHECK(admit(0, 0, CAP - 1, 1024, 0) == -ERANGE, "LBA range past the namespace refused");
 CHECK(admit(0, 0, UINT64_MAX, 512, 0) == -ERANGE, "LBA wrapping u64 refused");
 CHECK(admit(0, 0, UINT64_MAX - 1, 1024, 0) == -ERANGE, "LBA range wrapping u64 refused");
 CHECK(!admit(0, 0, CAP - 2, 1024, 0) && plan.nlb == 1, "last two LBAs of the namespace admitted");
 CHECK(admit(0, 0, 0, 0, 0) == -EINVAL, "empty request refused");
 CHECK(admit(0, 0, 0, 1000, 0) == -EINVAL, "request not a whole number of LBAs refused");
 CHECK(xdev_ext_peer_nvme_batch_admit(9, CAP, 8, 0, MIB, 0, 0, 0, 4096, dst, 0, &plan) == -EOPNOTSUPP,
       "metadata namespace refused");
 CHECK(xdev_ext_peer_nvme_batch_admit(12, CAP, 0, 0, MIB, 0, 0, 7, 8192, dst, 0, &plan) == 0 &&
       plan.nlb == 1 && dst[0].start == 0 && dst[0].len == 8192, "4 KiB-LBA namespace admitted in its own LBA size");

 /* A full batch of 64 random, disjoint, out-of-order targets is admitted. */
 {
  static const uint32_t order[64] = {
   37, 5, 61, 12, 0, 48, 23, 9, 55, 30, 2, 41, 17, 63, 26, 8, 50, 33, 14, 59, 21, 4, 44, 11, 36, 53,
   1, 28, 19, 46, 7, 62, 25, 39, 15, 57, 32, 3, 49, 22, 10, 42, 58, 18, 29, 6, 52, 35, 13, 60, 24,
   45, 31, 16, 54, 40, 27, 47, 20, 56, 34, 43, 38, 51 };
  int ok = 1;
  uint32_t i;
  for (i = 0; i < 64 && ok; i++)
   ok = !admit(0, (uint64_t)order[i] * 20 * KIB + 1024, 777 * (63 - i), 16 * KIB + 1024, i);
  CHECK(ok, "64 disjoint targets in shuffled order with page tails admitted");
  CHECK(admit(0, 61 * 20 * KIB + 17 * KIB, 1, 512, 63) == -EINVAL,
        "the last request overlapping one of 63 earlier targets refused");
 }
 printf("1..%d\n", checks);
 return failures ? 1 : 0;
}
#endif
