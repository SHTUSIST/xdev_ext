/* SPDX-License-Identifier: MIT */
#ifndef _NV_P2P_GPU_IDENTITY_H_
#define _NV_P2P_GPU_IDENTITY_H_

#define NV_P2P_GPU_IDENTITY_UUID_LEN 16U

static inline int
nv_p2p_gpu_identity_matches(const unsigned char *opened_uuid,
			    const unsigned char *allocation_uuid)
{
	unsigned char different = 0;
	unsigned int i;

	if (!opened_uuid || !allocation_uuid)
		return 0;
	for (i = 0; i < NV_P2P_GPU_IDENTITY_UUID_LEN; i++)
		different |= opened_uuid[i] ^ allocation_uuid[i];
	return different == 0;
}

#endif /* _NV_P2P_GPU_IDENTITY_H_ */
