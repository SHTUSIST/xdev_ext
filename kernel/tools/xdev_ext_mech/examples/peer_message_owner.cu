// SPDX-License-Identifier: GPL-2.0
#include <stdint.h>
extern "C" __global__ void peer_message_produce(unsigned char *payload,
	unsigned int bytes, unsigned long long key)
{
	for (unsigned int i = blockIdx.x * blockDim.x + threadIdx.x; i < bytes;
	     i += blockDim.x * gridDim.x)
		payload[i] = (unsigned char)(key * 17 + i * 13 + 29);
}
extern "C" __global__ void peer_message_consume(const unsigned char *payload,
	unsigned int bytes, unsigned long long key, unsigned int *mismatches)
{
	unsigned int bad = 0;
	for (unsigned int i = blockIdx.x * blockDim.x + threadIdx.x; i < bytes;
	     i += blockDim.x * gridDim.x)
		bad += payload[i] != (unsigned char)(key * 17 + i * 13 + 29);
	if (bad) atomicAdd(mismatches, bad);
}
