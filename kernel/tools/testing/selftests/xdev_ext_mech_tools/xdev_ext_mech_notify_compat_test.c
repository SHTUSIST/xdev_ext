// SPDX-License-Identifier: GPL-2.0
/* ABI v1 and legacy eventfd/quiet-wait compatibility, without real devices. */
#include <stddef.h>
#include <stdio.h>

#include "include/uapi/linux/xdev_ext_mech.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

_Static_assert(XDEV_EXT_MECH_ABI_VERSION == 1, "retain ABI v1");
_Static_assert(XDEV_EXT_MECH_OP_CREATE == 1 && XDEV_EXT_MECH_OP_START == 2 &&
	       XDEV_EXT_MECH_OP_STOP == 3 && XDEV_EXT_MECH_OP_STATS == 4,
	       "old operation numbers are frozen");
_Static_assert(sizeof(struct io_uring_xdev_ext_mech) == 16, "v1 wrapper size");
_Static_assert(sizeof(struct xdev_ext_mech_create) == 200, "v1 CREATE size");
_Static_assert(offsetof(struct xdev_ext_mech_create, eventfd) == 36,
	       "v1 eventfd offset");
_Static_assert(offsetof(struct xdev_ext_mech_create, session_id) == 192,
	       "v1 returned session offset");
_Static_assert(sizeof(struct xdev_ext_mech_start) == 40, "v1 START size");
_Static_assert(offsetof(struct xdev_ext_mech_start, user_frames) == 32,
	       "v1 user frames pointer offset");
_Static_assert(sizeof(struct xdev_ext_mech_stats) == 168, "v1 STATS size");

int main(void)
{
	struct xdev_ext_mech_stats s = {
		.session_id = 17, .batches_done = 5, .batches_abort = 3,
		.state = XDEV_EXT_MECH_SESSION_ACTIVE,
	};
	unsigned int checks = 0;

	/* Quiet-wait still interprets eventfd as one count per finished batch.
	 * Both done and aborted batches count; a coarse wake (count 1) does not
	 * magically become a legacy proof that eight batches have finished.
	 */
	for (__u64 count = 0; count <= 9; count++) {
		checks++;
		if (xdev_ext_mech_ctl_quiet_done(count, 8, &s) != (count >= 8)) {
			fprintf(stderr, "legacy count %llu incorrectly interpreted\n",
				(unsigned long long)count);
			return 1;
		}
	}
	s.batches_abort--;
	checks++;
	if (xdev_ext_mech_ctl_quiet_done(8, 8, &s)) {
		fprintf(stderr, "legacy eventfd count bypassed STATS counters\n");
		return 1;
	}
	printf("PASS: ABI v1 and %u legacy notification checks\n", checks);
	return 0;
}
