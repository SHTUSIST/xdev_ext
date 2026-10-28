/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IAA_TRANSFORM_OBSERVATIONS_H
#define IAA_TRANSFORM_OBSERVATIONS_H
#include <linux/types.h>
#define IAA_OBSERVATION_GROUPS 257U
struct iaa_observation {
 __u64 dma_build,dma_complete,iaa_build,iaa_complete,errors;
 __u32 compressed[IAA_OBSERVATION_GROUPS],decompressed[IAA_OBSERVATION_GROUPS];
 __u32 decomp_input[IAA_OBSERVATION_GROUPS],comp_frame[IAA_OBSERVATION_GROUPS],sink_frame[IAA_OBSERVATION_GROUPS],source_frame[IAA_OBSERVATION_GROUPS];
};
#endif
