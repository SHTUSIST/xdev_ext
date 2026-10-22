// SPDX-License-Identifier: GPL-2.0
/* Host contract: NIC RX -> [CE H2D -> CE D2H] -> NVMe WRITE. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

static unsigned int checks, failures;

#define EXPECT(value) do { \
	checks++; \
	if (!(value)) { \
		fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #value); \
		failures++; \
	} \
} while (0)

struct guarded_stages {
	struct xdev_ext_mech_stage_uapi st[4];
	uint64_t guard;
};

static void test_default_two_stages(void)
{
	struct guarded_stages got;
	struct xdev_ext_mech_stage_uapi expected[2] = {
		{ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		  .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 100001 },
		{ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 100002,
		  .arg0 = (1ULL << 40) + 37, .arg1 = (1ULL << 35) + 5 },
	};
	int nr;

	memset(&got, 0xa5, sizeof(got));
	got.guard = 0x0123456789abcdefULL;
	nr = xdev_ext_mech_ctl_rx_stages(got.st, 100001, 100002, -1, -1,
				    (1ULL << 40) + 37, (1ULL << 35) + 5,
				    0, 0);
	EXPECT(nr == 2);
	EXPECT(memcmp(got.st, expected, sizeof(expected)) == 0);
	EXPECT(got.guard == 0x0123456789abcdefULL);
}

static void test_receive_ce_four_stages(void)
{
	struct guarded_stages got;
	struct xdev_ext_mech_stage_uapi expected[4] = {
		{ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		  .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 100001 },
		{ .class_id = XDEV_EXT_MECH_CLASS_CE,
		  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 100003,
		  .arg0 = (1ULL << 45) + 8192, .arg1 = (1ULL << 33) + 65536 },
		{ .class_id = XDEV_EXT_MECH_CLASS_CE,
		  .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 100004,
		  .arg0 = (1ULL << 45) + 8192, .arg1 = (1ULL << 33) + 65536 },
		{ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 100002,
		  .arg0 = 4096, .arg1 = 128 },
	};
	int nr;

	memset(&got, 0xa5, sizeof(got));
	got.guard = 0x0123456789abcdefULL;
	nr = xdev_ext_mech_ctl_rx_stages(got.st, 100001, 100002, 100003, 100004,
				    4096, 128, (1ULL << 45) + 8192,
				    (1ULL << 33) + 65536);
	EXPECT(nr == 4);
	EXPECT(memcmp(got.st, expected, sizeof(expected)) == 0);
	EXPECT(got.guard == 0x0123456789abcdefULL);
}

static void test_invalid_fds_and_zero_window_rejected(void)
{
	struct xdev_ext_mech_stage_uapi st[4];

	EXPECT(xdev_ext_mech_ctl_rx_stages(st, -1, 11, -1, -1, 4096, 128, 0, 0) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 10, -1, -1, -1, 4096, 128, 0, 0) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 10, 11, -1, -1, 4096, 0, 0, 0) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 10, 11, -1, 13, 4096, 128, 0, 8192) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 10, 11, 12, -1, 4096, 128, 0, 8192) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 10, 11, 12, 13, 4096, 0, 0, 8192) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, -1, 11, 12, 13, 4096, 128, 0, 8192) < 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 10, -1, 12, 13, 4096, 128, 0, 8192) < 0);
}

static void test_zero_is_a_valid_fd_va_and_lba(void)
{
	struct xdev_ext_mech_stage_uapi st[4];

	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 0, 0, -1, -1, 0, 128, 0, 0) == 2);
	EXPECT(st[0].fd == 0 && st[1].fd == 0);
	EXPECT(st[1].arg0 == 0);
	EXPECT(xdev_ext_mech_ctl_rx_stages(st, 0, 0, 0, 0, 0, 128, 0, 8192) == 4);
	EXPECT(st[1].fd == 0 && st[2].fd == 0);
	EXPECT(st[1].arg0 == 0 && st[2].arg0 == 0 && st[3].arg0 == 0);
}

int main(void)
{
	test_default_two_stages();
	test_receive_ce_four_stages();
	test_invalid_fds_and_zero_window_rejected();
	test_zero_is_a_valid_fd_va_and_lba();
	printf("RX stage composition: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
