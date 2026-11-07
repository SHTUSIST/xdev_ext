// SPDX-License-Identifier: GPL-2.0
/* Supplemental SOURCE review counterexample, original contract wants frozen. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_step.h"
#include "contract.h"
int main(void)
{
	const struct rr_geometry g={4194304,8388608,65536,2,512};
	const struct rr_request rows[2]={
		{UINT64_MAX-1,0,1,1048576,0},{UINT64_MAX,2097152,1048577,1048576,0}};
	struct xdev_ext_mech_start start={.session_id=71,.nr_batches=2,.first_seq=UINT64_MAX-1,
		.flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_RECYCLE,
		.nr_user_frames=64,.user_frames=0x1000};
	int kernel=xdev_ext_mech_start_check(&start,XDEV_EXT_MECH_POOL_IOU_UMEM,false,32,64);
	if (kernel!=-EINVAL) {fprintf(stderr,"CONTROL actual START next-key guard=%d expected-EINVAL\n",kernel);return 2;}
	int got=rr_validate(&g,rows,2,false);
	if (got!=-EINVAL) {fprintf(stderr,"FAIL phase ending at U64_MAX cannot START: got%d want%d\n",got,-EINVAL);return 1;}
	puts("PASS actual START next-key boundary and request admission");
	return 0;
}
