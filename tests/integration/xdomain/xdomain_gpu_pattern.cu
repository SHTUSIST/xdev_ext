/* SPDX-License-Identifier: GPL-2.0 */
#include "xdomain_gpu_pattern.h"
static __device__ uint8_t pattern(uint64_t seed, uint64_t off)
{
 uint64_t x = seed ^ (off * UINT64_C(0x9e3779b97f4a7c15));
 x ^= x >> 30; x *= UINT64_C(0xbf58476d1ce4e5b9);
 x ^= x >> 27; x *= UINT64_C(0x94d049bb133111eb);
 x ^= x >> 31;
 return (uint8_t)x;
}
extern "C" __global__ void tb_pattern_fill(uint64_t allocation, uint64_t bytes,
                                           uint64_t seed, uint32_t guard)
{
 uint8_t *p = reinterpret_cast<uint8_t *>(allocation);
 if (guard) seed ^= UINT64_C(0xd6e8feb86659fd93);
 for (uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
      i < bytes; i += (uint64_t)blockDim.x * gridDim.x)
  p[i] = pattern(seed, i);
}
/* One CTA owns initialization and reduction: no inter-block init race. */
extern "C" __global__ void tb_pattern_verify(uint64_t allocation, uint64_t bytes,
 uint64_t extents_device, uint32_t nr, uint64_t cookie, uint64_t result_device)
{
 const uint8_t *p = reinterpret_cast<const uint8_t *>(allocation);
 const tb_verify_extent *e = reinterpret_cast<const tb_verify_extent *>(extents_device);
 tb_verify_result *r = reinterpret_cast<tb_verify_result *>(result_device);
 __shared__ unsigned long long checked, bad, first;
 if (threadIdx.x == 0) { checked = 0; bad = 0; first = UINT64_MAX; }
 __syncthreads();
 unsigned long long local_checked = 0, local_bad = 0, local_first = UINT64_MAX;
 for (uint32_t j = 0; j < nr; ++j) {
  uint64_t seed = e[j].seed;
  if (e[j].kind == TB_EXPECT_GUARD) seed ^= UINT64_C(0xd6e8feb86659fd93);
  for (uint64_t k = threadIdx.x; k < e[j].len; k += blockDim.x) {
   uint64_t dst = e[j].dst_off + k;
   uint64_t src = e[j].kind == TB_EXPECT_GUARD ? dst : e[j].src_off + k;
   ++local_checked;
   if (dst >= bytes || p[dst] != pattern(seed, src)) {
    ++local_bad;
    if (dst < local_first) local_first = dst;
   }
  }
 }
 atomicAdd(&checked, local_checked); atomicAdd(&bad, local_bad);
 atomicMin(&first, local_first);
 __syncthreads();
 if (threadIdx.x == 0) {
  r->bytes = checked; r->mismatches = bad; r->first_bad = first;
  r->launch_cookie = cookie;
 }
}
