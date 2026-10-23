// SPDX-License-Identifier: GPL-2.0
/* Guest-only STATS isolation probe. Drop all supplementary groups and IDs. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/io_uring.h"
#include "../../../../include/uapi/linux/xdev_ext_mech.h"

int main(int argc, char **argv)
{
	struct io_uring_params params = {0};
	struct xdev_ext_mech_stats stats = {0};
	struct io_uring_xdev_ext_mech req = {
		.op = XDEV_EXT_MECH_OP_STATS, .arg = (uintptr_t)&stats,
	};
	int ring, result, saved;

	if (argc != 2 || !argv[1][0] || strspn(argv[1], "0123456789") != strlen(argv[1]))
		return 2;
	errno = 0;
	stats.session_id = strtoull(argv[1], NULL, 10);
	if (errno || !stats.session_id)
		return 2;
	if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) ||
	    setresuid(65534, 65534, 65534)) {
		perror("guest UID drop");
		return 2;
	}
	/* No exec after dropping UID: initramfs test programs may be root-only.
	 * The same public STATS operation must be checked using the new identity. */
	ring = syscall(__NR_io_uring_setup, 8, &params);
	if (ring < 0) {
		perror("guest io_uring");
		return 3;
	}
	result = syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);
	saved = errno;
	close(ring);
	if (result < 0) {
		fprintf(stderr, "guest STATS %llu: %s\n", (unsigned long long)stats.session_id,
			strerror(saved));
		return 3;
	}
	puts("FAIL another UID obtained victim STATS");
	return 0;
}
