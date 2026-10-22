// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "../../../../include/uapi/linux/nvme_ioctl.h"
#include "../../../../include/linux/nvme_xdev_ext_passthru.h"
#include "nvme_xdev_ext_passthru_runtime.h"
#include <linux/if_xdp.h>
#include "../../../xdev_ext_mech/xdev_ext_mech_prog.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                              \
	if (_actual != _expected) {                                            \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",             \
			__FILE__, __LINE__, _actual, _expected);                    \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

static struct nvme_xdev_ext_admission valid_input(void)
{
	struct nvme_xdev_ext_admission input = {
		.opcode = NVME_XDEV_EXT_NVM_READ,
		.lba_shift = 12,
		.namespace_ready = 1,
		.command_nsid = 7,
		.live_nsid = 7,
		.data_len = 4096,
		.cdw10 = 4,
		.capacity_lbas = 1024,
	};

	return input;
}

static void test_uapi_flags(void)
{
	EXPECT_EQ(NVME_URING_CMD_F_XDEV_EXT, 1U);
	EXPECT_EQ(NVME_URING_CMD_F_XDEV_EXT_BUILD, 2U);
	EXPECT_EQ(NVME_URING_CMD_F_KNOWN_MASK,
		  NVME_URING_CMD_F_XDEV_EXT | NVME_URING_CMD_F_XDEV_EXT_BUILD);
	EXPECT_TRUE(nvme_xdev_ext_flags_valid(0));
	EXPECT_TRUE(nvme_xdev_ext_flags_valid(NVME_URING_CMD_F_XDEV_EXT));
	EXPECT_FALSE(nvme_xdev_ext_flags_valid(NVME_URING_CMD_F_XDEV_EXT | 4U));
	EXPECT_FALSE(nvme_xdev_ext_flags_valid(1U << 31));
	EXPECT_FALSE(nvme_xdev_ext_opted_in(0));
	EXPECT_TRUE(nvme_xdev_ext_opted_in(NVME_URING_CMD_F_XDEV_EXT));

	/* A built command is an opted-in command. */
	EXPECT_TRUE(nvme_xdev_ext_flags_valid(NVME_URING_CMD_F_XDEV_EXT |
					 NVME_URING_CMD_F_XDEV_EXT_BUILD));
	EXPECT_FALSE(nvme_xdev_ext_flags_valid(NVME_URING_CMD_F_XDEV_EXT_BUILD));
	EXPECT_FALSE(nvme_xdev_ext_build_requested(0));
	EXPECT_FALSE(nvme_xdev_ext_build_requested(NVME_URING_CMD_F_XDEV_EXT));
	EXPECT_TRUE(nvme_xdev_ext_build_requested(NVME_URING_CMD_F_XDEV_EXT |
					     NVME_URING_CMD_F_XDEV_EXT_BUILD));
}

static void test_capabilities_are_trusted_facts(void)
{
	EXPECT_EQ(nvme_xdev_ext_capabilities(0, 0, 0), XDEV_EXT_BINDING_CAP_ASYNC);
	EXPECT_EQ(nvme_xdev_ext_capabilities(1, 0, 0),
		  XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_POLL);
	EXPECT_EQ(nvme_xdev_ext_capabilities(0, 1, 0),
		  XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_FIXED_FILE);
	EXPECT_EQ(nvme_xdev_ext_capabilities(0, 0, 1),
		  XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_FIXED_BUFFER);
	EXPECT_EQ(nvme_xdev_ext_capabilities(1, 1, 1),
		  XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_POLL |
		  XDEV_EXT_BINDING_CAP_FIXED_FILE |
		  XDEV_EXT_BINDING_CAP_FIXED_BUFFER);
}

static void test_vectored_length_is_snapshotted(void)
{
	uint32_t bytes = 0;

	EXPECT_EQ(nvme_xdev_ext_effective_data_len(false, false, 4096, 0,
					       &bytes), 0);
	EXPECT_EQ(bytes, 4096);
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(false, true, 4096, 8192,
					       &bytes), 0);
	EXPECT_EQ(bytes, 4096);

	/* XDEV_EXT vectors must be imported from registered buffers exactly once. */
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(true, false, 2, 8192,
					       &bytes), -EOPNOTSUPP);
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(true, true, 0, 8192,
					       &bytes), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(true, true, 2, 0,
					       &bytes), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(true, true, 2,
					       UINT64_C(1) << 32,
					       &bytes), -EOVERFLOW);
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(true, true, 3, 8192,
					       &bytes), 0);
	EXPECT_EQ(bytes, 8192);
	EXPECT_EQ(nvme_xdev_ext_effective_data_len(true, true, 3, 8192,
					       NULL), -EINVAL);

	EXPECT_EQ(nvme_xdev_ext_capabilities_vec(0, 0, 1, 0),
		  XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_FIXED_BUFFER);
	EXPECT_EQ(nvme_xdev_ext_capabilities_vec(0, 0, 1, 1),
		  XDEV_EXT_BINDING_CAP_ASYNC | XDEV_EXT_BINDING_CAP_FIXED_BUFFER |
		  XDEV_EXT_BINDING_CAP_MULTIBUFFER);
}

static void test_decode_and_bounds(void)
{
	struct nvme_xdev_ext_decoded decoded;
	struct nvme_xdev_ext_admission input = valid_input();

	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), 0);
	EXPECT_EQ(decoded.slba, 4);
	EXPECT_EQ(decoded.nlb, 1);
	EXPECT_EQ(decoded.byte_offset, UINT64_C(16384));
	EXPECT_EQ(decoded.byte_length, UINT64_C(4096));
	EXPECT_FALSE(decoded.write);

	input.opcode = NVME_XDEV_EXT_NVM_WRITE;
	input.cdw10 = UINT32_MAX;
	input.cdw11 = 1;
	input.cdw12 = UINT16_MAX;
	input.data_len = 65536U << 9;
	input.lba_shift = 9;
	input.capacity_lbas = (UINT64_C(1) << 33) + 65536;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), 0);
	EXPECT_EQ(decoded.slba, (UINT64_C(1) << 32) | UINT32_MAX);
	EXPECT_EQ(decoded.nlb, 65536);
	EXPECT_EQ(decoded.byte_length, UINT64_C(33554432));
	EXPECT_TRUE(decoded.write);

	input = valid_input();
	input.command_nsid++;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EXDEV);
	input = valid_input();
	input.namespace_ready = 0;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -ENODEV);
	input = valid_input();
	input.namespace_removing = 1;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -ENODEV);

	input = valid_input();
	input.opcode = 0;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
	input = valid_input();
	input.csi = 2;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
	input = valid_input();
	input.lba_shift = 8;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EINVAL);
	input = valid_input();
	input.lba_shift = 32;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOVERFLOW);

	input = valid_input();
	input.data_len = 0;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EINVAL);
	input = valid_input();
	input.data_len++;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EMSGSIZE);

	input = valid_input();
	input.cdw10 = 1024;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -ERANGE);
	input = valid_input();
	input.cdw10 = UINT32_MAX;
	input.cdw11 = UINT32_MAX;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOVERFLOW);

	input = valid_input();
	input.metadata = 1;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
	input = valid_input();
	input.metadata_len = 8;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
	input = valid_input();
	input.metadata_size = 8;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
	input = valid_input();
	input.pi_size = 8;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
	input = valid_input();
	input.pi_type = 1;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &decoded), -EOPNOTSUPP);
}

/* cdw12[31:16] is nvme_rw_command.control; bits from include/linux/nvme.h. */
#define TEST_RW_FUA	(1U << 14)	/* NVME_RW_FUA */
#define TEST_RW_LR	(1U << 15)	/* NVME_RW_LR */

static void put_dw(uint8_t *sqe, unsigned int dw, uint32_t value)
{
	unsigned int i;

	for (i = 0; i < 4; i++)
		sqe[4 * dw + i] = (uint8_t)(value >> (8 * i));
}

/* A built READ of 8 KiB at LBA 0x10000002 inside a 64-LBA window. */
static void valid_sqe(uint8_t *sqe)
{
	memset(sqe, 0, NVME_XDEV_EXT_SQE_SIZE);
	sqe[0] = NVME_XDEV_EXT_NVM_READ;
	put_dw(sqe, 10, 0x10000002U);
	put_dw(sqe, 11, 0);
	put_dw(sqe, 12, 1);
}

static struct nvme_xdev_ext_mech_bounds valid_bounds(void)
{
	struct nvme_xdev_ext_mech_bounds bounds = {
		.window_slba = 0x10000000U,
		.window_nlb = 64,
		.capacity_lbas = UINT64_C(0x20000000),
		.data_len = 8192,
		.lba_shift = 12,
	};

	return bounds;
}

static void test_mech_validate_accepts_built_sqe(void)
{
	uint8_t sqe[NVME_XDEV_EXT_SQE_SIZE];
	struct nvme_xdev_ext_mech_bounds bounds = valid_bounds();
	struct nvme_xdev_ext_decoded decoded;
	unsigned int dw;

	EXPECT_EQ(NVME_XDEV_EXT_SQE_SIZE, 64);
	valid_sqe(sqe);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), 0);
	EXPECT_EQ(decoded.slba, 0x10000002U);
	EXPECT_EQ(decoded.nlb, 2);
	EXPECT_EQ(decoded.byte_offset, UINT64_C(0x10000002) << 12);
	EXPECT_EQ(decoded.byte_length, 8192);
	EXPECT_FALSE(decoded.write);

	/* The accepted command is exactly 16 little-endian dwords. */
	for (dw = 0; dw < NVME_XDEV_EXT_SQE_SIZE / 4; dw++) {
		uint32_t expected = 0;

		if (dw == 0)
			expected = NVME_XDEV_EXT_NVM_READ;
		else if (dw == 10)
			expected = 0x10000002U;
		else if (dw == 12)
			expected = 1;
		EXPECT_EQ(nvme_xdev_ext_sqe_dw(sqe, dw), expected);
	}
	put_dw(sqe, 13, 0x89abcdefU);
	EXPECT_EQ(nvme_xdev_ext_sqe_dw(sqe, 13), 0x89abcdefU);

	/* A WRITE stage with FUA whitelisted, spanning the full window. */
	valid_sqe(sqe);
	sqe[0] = NVME_XDEV_EXT_NVM_WRITE;
	put_dw(sqe, 10, 0x10000000U);
	put_dw(sqe, 12, (TEST_RW_FUA << 16) | 63);
	bounds.write = 1;
	bounds.data_len = 64U << 12;
	bounds.control_allow = TEST_RW_FUA;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), 0);
	EXPECT_EQ(decoded.slba, 0x10000000U);
	EXPECT_EQ(decoded.nlb, 64);
	EXPECT_EQ(decoded.byte_length, UINT64_C(64) << 12);
	EXPECT_TRUE(decoded.write);
}

static void test_mech_validate_fail_closed(void)
{
	uint8_t sqe[NVME_XDEV_EXT_SQE_SIZE];
	struct nvme_xdev_ext_mech_bounds bounds = valid_bounds();
	struct nvme_xdev_ext_decoded decoded;
	unsigned int byte;

	EXPECT_EQ(nvme_xdev_ext_mech_validate(NULL, &bounds, &decoded), -EINVAL);
	valid_sqe(sqe);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, NULL, &decoded), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, NULL), -EINVAL);

	/* The opcode must match the stage direction. */
	bounds.write = 1;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EOPNOTSUPP);
	EXPECT_EQ(decoded.nlb, 0);
	bounds = valid_bounds();
	sqe[0] = NVME_XDEV_EXT_NVM_WRITE;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EOPNOTSUPP);
	sqe[0] = 0;	/* an empty slot, or FLUSH */
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EOPNOTSUPP);
	sqe[0] = 0x09;	/* DSM */
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EOPNOTSUPP);

	/*
	 * Every byte C or nvme-pci owns must stay zero: flags (FUSE, PSDT),
	 * command_id, nsid, cdw2, cdw3, MPTR, DPTR (PRP1/PRP2), cdw13..cdw15.
	 */
	for (byte = 1; byte < NVME_XDEV_EXT_SQE_SIZE; byte++) {
		if (byte >= 40 && byte < 52)
			continue;
		valid_sqe(sqe);
		sqe[byte] = 0x80;
		EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded),
			  -EPERM);
		EXPECT_EQ(decoded.nlb, 0);
	}
	valid_sqe(sqe);
	sqe[1] = 0x01;	/* FUSE: first command of a fused pair */
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EPERM);
	sqe[1] = 0x40;	/* PSDT: SGL for data */
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EPERM);

	/* cdw12[31:16] bits are rejected unless whitelisted. */
	valid_sqe(sqe);
	put_dw(sqe, 12, (TEST_RW_FUA << 16) | 1);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EPERM);
	bounds.control_allow = TEST_RW_FUA;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), 0);
	put_dw(sqe, 12, (TEST_RW_LR << 16) | 1);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EPERM);
	put_dw(sqe, 12, (1U << 26) | 1);	/* PRINFO */
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EPERM);
	bounds = valid_bounds();

	/* NLB must cover exactly the batch bytes. */
	valid_sqe(sqe);
	put_dw(sqe, 12, 0);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EMSGSIZE);
	put_dw(sqe, 12, 2);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EMSGSIZE);
	put_dw(sqe, 12, 1);
	bounds.data_len = 8191;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EMSGSIZE);
	bounds.data_len = 0;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EINVAL);
	bounds = valid_bounds();

	/* SLBA and SLBA + NLB stay inside the stage window. */
	put_dw(sqe, 10, 0x0fffffffU);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -ERANGE);
	EXPECT_EQ(decoded.nlb, 0);
	put_dw(sqe, 10, 0x1000003eU);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), 0);
	put_dw(sqe, 10, 0x1000003fU);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -ERANGE);
	EXPECT_EQ(decoded.nlb, 0);
	put_dw(sqe, 10, 0x10000040U);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -ERANGE);
	put_dw(sqe, 10, UINT32_MAX);
	put_dw(sqe, 11, UINT32_MAX);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -ERANGE);
	valid_sqe(sqe);
	bounds.window_nlb = 0;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -ERANGE);
	bounds = valid_bounds();

	/* ... and inside the namespace even when the window is not. */
	bounds.capacity_lbas = 0x10000003U;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -ERANGE);
	bounds.capacity_lbas = 0x10000004U;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), 0);
	bounds = valid_bounds();

	bounds.lba_shift = 8;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EINVAL);
	bounds.lba_shift = 32;
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &decoded), -EOVERFLOW);
}

/*
 * NVME_URING_CMD_F_XDEV_EXT_BUILD: the user command carries no SLBA/NLB, so the
 * initial admission checks identity and an LBA-aligned length only; the
 * built command is validated, and final admission of the command with the
 * built cdw10..cdw12 decodes to exactly what validation stored.
 */
static void test_build_admission_split(void)
{
	struct nvme_xdev_ext_admission input = valid_input();
	struct nvme_xdev_ext_mech_bounds bounds = valid_bounds();
	struct nvme_xdev_ext_decoded built, final;
	uint8_t sqe[NVME_XDEV_EXT_SQE_SIZE];

	input.data_len = 8192;
	input.cdw10 = 0;
	input.cdw11 = 0;
	input.cdw12 = 0;
	input.capacity_lbas = bounds.capacity_lbas;
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &final), -EMSGSIZE);
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), 0);
	input.cdw10 = UINT32_MAX;
	input.cdw11 = UINT32_MAX;
	input.cdw12 = UINT32_MAX;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), 0);

	valid_sqe(sqe);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &built), 0);
	input.cdw10 = nvme_xdev_ext_sqe_dw(sqe, 10);
	input.cdw11 = nvme_xdev_ext_sqe_dw(sqe, 11);
	input.cdw12 = nvme_xdev_ext_sqe_dw(sqe, 12);
	EXPECT_EQ(nvme_xdev_ext_admit(&input, &final), 0);
	EXPECT_EQ(final.slba, built.slba);
	EXPECT_EQ(final.nlb, built.nlb);
	EXPECT_EQ(final.byte_offset, built.byte_offset);
	EXPECT_EQ(final.byte_length, built.byte_length);
	EXPECT_EQ(final.write, built.write);
}

static void test_admit_identity_rejects(void)
{
	struct nvme_xdev_ext_admission input = valid_input();

	EXPECT_EQ(nvme_xdev_ext_admit_identity(NULL), -EINVAL);
	input.command_nsid++;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EXDEV);
	input = valid_input();
	input.live_nsid = 0;
	input.command_nsid = 0;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EXDEV);
	input = valid_input();
	input.namespace_ready = 0;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -ENODEV);
	input = valid_input();
	input.namespace_removing = 1;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -ENODEV);
	input = valid_input();
	input.csi = 2;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.opcode = 0;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.metadata = 1;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.metadata_len = 8;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.metadata_size = 8;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.pi_size = 8;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.pi_type = 1;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOPNOTSUPP);
	input = valid_input();
	input.lba_shift = 8;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EINVAL);
	input.lba_shift = 32;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EOVERFLOW);

	/* The length must be whole LBAs that one command can carry. */
	input = valid_input();
	input.data_len = 0;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EINVAL);
	input.data_len = 4097;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EMSGSIZE);
	input.data_len = 512;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EMSGSIZE);
	input.lba_shift = 9;
	input.data_len = 65536U << 9;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), 0);
	input.data_len += 512;
	EXPECT_EQ(nvme_xdev_ext_admit_identity(&input), -EMSGSIZE);
}

/* The user half of a built command carries no LBA, length or hint dwords. */
static void test_build_user_check(void)
{
	uint8_t sqe[NVME_XDEV_EXT_SQE_SIZE];
	unsigned int dw;

	EXPECT_EQ(nvme_xdev_ext_build_user_check(NULL), -EINVAL);
	memset(sqe, 0, sizeof(sqe));
	sqe[0] = NVME_XDEV_EXT_NVM_WRITE;
	put_dw(sqe, 1, 7);		/* nsid is the user's and admitted */
	EXPECT_EQ(nvme_xdev_ext_build_user_check(sqe), 0);
	for (dw = 2; dw < NVME_XDEV_EXT_SQE_SIZE / 4; dw++) {
		put_dw(sqe, dw, 1U << (dw % 32));
		EXPECT_EQ(nvme_xdev_ext_build_user_check(sqe),
			  dw <= 3 || dw >= 10 ? -EINVAL : 0);
		put_dw(sqe, dw, 0);
	}
}

/* Build callback result to errno for an F_XDEV_EXT_BUILD uring_cmd. */
static void test_build_errno(void)
{
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_SUBMIT, 1), 0);
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_SUBMIT, 0), -EPROTO);
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_SUBMIT, 2), -EPROTO);
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_SUBMIT, -EPROTO),
		  -EPROTO);
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_DEFAULT, 1),
		  -EOPNOTSUPP);
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_ABORT, 1), -ECANCELED);
	EXPECT_EQ(nvme_xdev_ext_build_errno(XDEV_EXT_MECH_BUILD_ABORT, 0), -ECANCELED);
	EXPECT_EQ(nvme_xdev_ext_build_errno(7, 1), -ECANCELED);
	EXPECT_EQ(nvme_xdev_ext_build_errno(-1, 1), -ECANCELED);
}

/*
 * After the built cdw10..cdw12 are written into the command that executes,
 * it is decoded again and must be exactly what validation admitted.
 */
static void test_build_redecode(void)
{
	struct nvme_xdev_ext_admission input = valid_input();
	struct nvme_xdev_ext_mech_bounds bounds = valid_bounds();
	struct nvme_xdev_ext_decoded validated, decoded;
	uint8_t sqe[NVME_XDEV_EXT_SQE_SIZE];

	valid_sqe(sqe);
	EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe, &bounds, &validated), 0);
	input.data_len = bounds.data_len;
	input.capacity_lbas = bounds.capacity_lbas;
	input.cdw10 = nvme_xdev_ext_sqe_dw(sqe, 10);
	input.cdw11 = nvme_xdev_ext_sqe_dw(sqe, 11);
	input.cdw12 = nvme_xdev_ext_sqe_dw(sqe, 12);
	EXPECT_EQ(nvme_xdev_ext_build_redecode(&input, &validated, &decoded), 0);
	EXPECT_EQ(decoded.slba, validated.slba);
	EXPECT_EQ(decoded.nlb, validated.nlb);
	EXPECT_EQ(decoded.byte_offset, validated.byte_offset);
	EXPECT_EQ(decoded.byte_length, validated.byte_length);
	EXPECT_EQ(decoded.write, validated.write);

	/* Not the command validation admitted: another LBA, or another opcode. */
	input.cdw10++;
	EXPECT_EQ(nvme_xdev_ext_build_redecode(&input, &validated, &decoded),
		  -EPROTO);
	EXPECT_EQ(decoded.nlb, 0);
	input.cdw10--;
	input.opcode = NVME_XDEV_EXT_NVM_WRITE;
	EXPECT_EQ(nvme_xdev_ext_build_redecode(&input, &validated, &decoded),
		  -EPROTO);
	input.opcode = NVME_XDEV_EXT_NVM_READ;

	/* A command final admission refuses keeps its own errno. */
	input.cdw12 = 0;
	EXPECT_EQ(nvme_xdev_ext_build_redecode(&input, &validated, &decoded),
		  -EMSGSIZE);
	input.cdw12 = nvme_xdev_ext_sqe_dw(sqe, 12);
	input.namespace_removing = 1;
	EXPECT_EQ(nvme_xdev_ext_build_redecode(&input, &validated, &decoded),
		  -ENODEV);
}

/* The program sees the native completion: no status is folded into an errno. */
static void test_mech_cqe(void)
{
	struct xdev_ext_nvme_mech_cqe cqe;

	EXPECT_EQ(sizeof(cqe), 16);
	nvme_xdev_ext_mech_cqe(0, UINT64_C(0x1122334455667788), &cqe);
	EXPECT_EQ(cqe.result, UINT64_C(0x1122334455667788));
	EXPECT_EQ(cqe.status, 0);
	EXPECT_EQ(cqe.err, 0);
	EXPECT_EQ(cqe.rsvd, 0);

	/* LBA Out of Range (SCT 0, SC 0x80) with DNR, exactly as completed. */
	nvme_xdev_ext_mech_cqe(0x4080, 0, &cqe);
	EXPECT_EQ(cqe.status, 0x4080);
	EXPECT_EQ(cqe.err, 0);
	/* Unrecovered Read Error (SCT 2, SC 0x81). */
	nvme_xdev_ext_mech_cqe(0x0281, 0, &cqe);
	EXPECT_EQ(cqe.status, 0x0281);
	EXPECT_EQ(cqe.err, 0);

	/* No status from the device: a cancelled or failed transport. */
	nvme_xdev_ext_mech_cqe(-EINTR, 5, &cqe);
	EXPECT_EQ(cqe.status, 0);
	EXPECT_EQ(cqe.err, -EINTR);
	EXPECT_EQ(cqe.result, 5);
	nvme_xdev_ext_mech_cqe(-EIO, 0, &cqe);
	EXPECT_EQ(cqe.status, 0);
	EXPECT_EQ(cqe.err, -EIO);
}

static struct nvme_xdev_ext_identity valid_identity(void)
{
	struct nvme_xdev_ext_identity id = {
		.nsid = 1,
		.lba_shift = 9,
		.namespace_ready = 1,
		.capacity_lbas = 1U << 19,
	};

	return id;
}

/* CREATE of an NVMe stage: namespace, LBA window and batch size. */
static void test_mech_bind_check(void)
{
	struct nvme_xdev_ext_identity id = valid_identity();

	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192), 0);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 0, 4096, 64, 8192), 0);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(NULL, 1, 4096, 64, 8192), -EINVAL);

	/* The window is non-empty and inside the namespace. */
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 0, 8192), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, (1U << 19) - 64, 64, 8192),
		  0);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, (1U << 19) - 63, 64, 8192),
		  -ERANGE);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, UINT64_MAX, 2, 8192),
		  -ERANGE);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 0, UINT64_MAX, 8192),
		  -ERANGE);

	/* A batch is whole LBAs one command can carry, and fits the window. */
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 0), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8000), -EMSGSIZE);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 16, 8192), 0);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 15, 8192), -ERANGE);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 0, 1U << 19,
					   (65536U << 9) + 512), -EMSGSIZE);

	/* The namespace admission of nvme_xdev_ext_admit() applies unchanged. */
	id.namespace_removing = 1;
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192), -ENODEV);
	id = valid_identity();
	id.csi = 2;
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192),
		  -EOPNOTSUPP);
	id = valid_identity();
	id.metadata_size = 8;
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192),
		  -EOPNOTSUPP);
	id = valid_identity();
	id.pi_type = 1;
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192),
		  -EOPNOTSUPP);
	id = valid_identity();
	id.nsid = 0;
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192), -EXDEV);
	id = valid_identity();
	id.lba_shift = 12;
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 8192), 0);
	EXPECT_EQ(nvme_xdev_ext_mech_bind_check(&id, 1, 4096, 64, 6144), -EMSGSIZE);
}

/* An SGL-capable QEMU I/O queue: dword DMA alignment, no virtual boundary. */
static struct nvme_xdev_ext_queue_caps sgl_caps(void)
{
	struct nvme_xdev_ext_queue_caps caps = {
		.page_size = 4096,
		.dma_align_mask = 3,
		.max_segments = 127,
		.max_segment_size = UINT32_MAX,
		.max_bytes = 512U << 10,
		.lba_size = 512,
	};

	return caps;
}

/* The S1 receiver layout: six frames, data at byte 104, 5 x 1432 + 1032. */
static int walk_s1(const struct nvme_xdev_ext_queue_caps *caps,
		   struct nvme_xdev_ext_seg_walk *walk)
{
	unsigned int i;
	int ret;

	nvme_xdev_ext_seg_walk_init(walk, caps);
	for (i = 0; i < 6; i++) {
		ret = nvme_xdev_ext_seg_add(walk, 104, i < 5 ? 1432 : 1032, 0);
		if (ret)
			return ret;
	}
	return nvme_xdev_ext_seg_done(walk);
}

/*
 * Before a bio is built from batch frames: DMA alignment, the virtual
 * boundary and the segment limit decide whether the device can take the
 * pieces as they are.  -EREMOTEIO is what blk_rq_append_bio() returns when
 * it would have to split.
 */
static void test_mech_seg_walk(void)
{
	struct nvme_xdev_ext_queue_caps caps = sgl_caps();
	struct nvme_xdev_ext_seg_walk walk;

	EXPECT_EQ(walk_s1(&caps, &walk), 0);
	EXPECT_EQ(walk.segs, 6);
	EXPECT_EQ(walk.bytes, 8192);

	/* A PRP-only queue keeps a 4 KiB virtual boundary: the gap needs a split. */
	caps.virt_boundary_mask = 4095;
	EXPECT_EQ(walk_s1(&caps, &walk), -EREMOTEIO);
	EXPECT_EQ(walk.segs, 1);
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 4096, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 4096, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 512, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_done(&walk), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 512, 512, 0), -EREMOTEIO);
	caps = sgl_caps();

	/* Byte offsets or lengths the DMA alignment refuses would bounce. */
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 105, 1432, 0), -EREMOTEIO);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 104, 1431, 0), -EREMOTEIO);
	EXPECT_EQ(walk.segs, 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 104, 0, 0), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 4000, 200, 0), -EINVAL);

	/* More pieces than the queue's segments. */
	caps.max_segments = 2;
	EXPECT_EQ(walk_s1(&caps, &walk), -EREMOTEIO);
	EXPECT_EQ(walk.segs, 2);
	caps = sgl_caps();

	/* A piece that continues the previous one in its page merges with it. */
	caps.virt_boundary_mask = 4095;
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 2048, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 2048, 2048, 1), 0);
	EXPECT_EQ(walk.segs, 1);
	EXPECT_EQ(walk.seg_len, 4096);
	/* ... only when it starts where the previous one ended. */
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 2048, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 2560, 512, 1), -EREMOTEIO);
	caps.max_segment_size = 3072;
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 2048, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 2048, 2048, 1), -EREMOTEIO);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 4096, 0), -EREMOTEIO);
	caps = sgl_caps();

	/* Bytes: within the request limit, whole LBAs, not empty. */
	caps.max_bytes = 8192;
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 4096, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 4096, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 512, 0), -EMSGSIZE);
	EXPECT_EQ(walk.bytes, 8192);
	caps = sgl_caps();
	nvme_xdev_ext_seg_walk_init(&walk, &caps);
	EXPECT_EQ(nvme_xdev_ext_seg_done(&walk), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 0, 1020, 0), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_done(&walk), -EMSGSIZE);
	EXPECT_EQ(nvme_xdev_ext_seg_add(&walk, 1020, 4, 1), 0);
	EXPECT_EQ(nvme_xdev_ext_seg_done(&walk), 0);
}

static void test_identity(void)
{
	struct nvme_xdev_ext_identity a = {
		.nsid = 7,
		.lba_shift = 12,
		.namespace_ready = 1,
		.capacity_lbas = 1024,
		.diskseq = 19,
		.csi = 2,
	};
	struct nvme_xdev_ext_identity b;

	memset(a.uuid, 0xa5, sizeof(a.uuid));
	b = a;
	EXPECT_TRUE(nvme_xdev_ext_identity_equal(&a, &b));
	b.nsid++;
	EXPECT_FALSE(nvme_xdev_ext_identity_equal(&a, &b));
	b = a;
	b.diskseq++;
	EXPECT_FALSE(nvme_xdev_ext_identity_equal(&a, &b));
	b = a;
	b.capacity_lbas--;
	EXPECT_FALSE(nvme_xdev_ext_identity_equal(&a, &b));
	b = a;
	b.uuid[15] ^= 1;
	EXPECT_FALSE(nvme_xdev_ext_identity_equal(&a, &b));
	b = a;
	b.namespace_ready = 0;
	EXPECT_FALSE(nvme_xdev_ext_identity_equal(&a, &b));
}

static void test_lifecycle(void)
{
	enum nvme_xdev_ext_lifecycle state = NVME_XDEV_EXT_LIFECYCLE_EMPTY;

	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state), 0);
	EXPECT_EQ(state, NVME_XDEV_EXT_LIFECYCLE_PREPARED);
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state), -EBUSY);
	EXPECT_TRUE(nvme_xdev_ext_lifecycle_unwind(&state));
	EXPECT_EQ(state, NVME_XDEV_EXT_LIFECYCLE_UNWOUND);
	EXPECT_FALSE(nvme_xdev_ext_lifecycle_unwind(&state));
	/* A retried command must not dispatch again after pre-accept unwind. */
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state), -EBUSY);
	state = NVME_XDEV_EXT_LIFECYCLE_EMPTY;
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state), 0);
	EXPECT_TRUE(nvme_xdev_ext_lifecycle_accept(&state));
	EXPECT_FALSE(nvme_xdev_ext_lifecycle_unwind(&state));
	EXPECT_TRUE(nvme_xdev_ext_lifecycle_complete(&state));
	EXPECT_EQ(state, NVME_XDEV_EXT_LIFECYCLE_COMPLETED);
	EXPECT_FALSE(nvme_xdev_ext_lifecycle_complete(&state));
	EXPECT_FALSE(nvme_xdev_ext_lifecycle_accept(&state));
}

static void expect_cleanup(enum nvme_xdev_ext_cleanup_action actual,
			   enum nvme_xdev_ext_cleanup_action expected)
{
	EXPECT_EQ(actual, expected);
}

static void test_resource_protocol(void)
{
	struct nvme_xdev_ext_resource_state state = {};

	/* Sidecar allocation/admission failure owns no resource. */
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_NONE);

	/* Dispatch followed by request-allocation failure puts only the token. */
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state.lifecycle), 0);
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_PUT_TOKEN);
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_NONE);

	/* A final-admission failure unwinds mapping before request and token. */
	state = (struct nvme_xdev_ext_resource_state) {};
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state.lifecycle), 0);
	nvme_xdev_ext_resource_request_allocated(&state);
	nvme_xdev_ext_resource_user_mapped(&state);
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_UNMAP);
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_FREE_REQUEST);
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_PUT_TOKEN);
	expect_cleanup(nvme_xdev_ext_preaccept_next(&state),
		       NVME_XDEV_EXT_CLEANUP_NONE);

	/* Accepted task work unmaps before policy and publishes CQE last. */
	state = (struct nvme_xdev_ext_resource_state) {};
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state.lifecycle), 0);
	nvme_xdev_ext_resource_request_allocated(&state);
	nvme_xdev_ext_resource_user_mapped(&state);
	EXPECT_TRUE(nvme_xdev_ext_lifecycle_accept(&state.lifecycle));
	expect_cleanup(nvme_xdev_ext_completion_next(&state),
		       NVME_XDEV_EXT_CLEANUP_UNMAP);
	expect_cleanup(nvme_xdev_ext_completion_next(&state),
		       NVME_XDEV_EXT_CLEANUP_COMPLETE_POLICY);
	expect_cleanup(nvme_xdev_ext_completion_next(&state),
		       NVME_XDEV_EXT_CLEANUP_DONE);
	expect_cleanup(nvme_xdev_ext_completion_next(&state),
		       NVME_XDEV_EXT_CLEANUP_NONE);
}

/*
 * A nonblocking issue that hits -EAGAIN in request allocation or user-data
 * mapping is retried by io_uring from io-wq.  That retry is correct only while
 * no policy dispatch has happened for the command; afterwards it would replay
 * policy-visible work, so the command must fail instead.
 */
static void test_issue_errno_retries_only_before_dispatch(void)
{
	struct nvme_xdev_ext_resource_state state = { 0 };

	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, -EAGAIN), -EAGAIN);
	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, -EINVAL), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, 0), 0);

	/* Request allocated and mapped, then unwound before any dispatch. */
	nvme_xdev_ext_resource_request_allocated(&state);
	nvme_xdev_ext_resource_user_mapped(&state);
	EXPECT_EQ(nvme_xdev_ext_preaccept_next(&state), NVME_XDEV_EXT_CLEANUP_UNMAP);
	EXPECT_EQ(nvme_xdev_ext_preaccept_next(&state), NVME_XDEV_EXT_CLEANUP_FREE_REQUEST);
	EXPECT_EQ(nvme_xdev_ext_preaccept_next(&state), NVME_XDEV_EXT_CLEANUP_NONE);
	EXPECT_EQ(state.lifecycle, NVME_XDEV_EXT_LIFECYCLE_EMPTY);
	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, -EAGAIN), -EAGAIN);
	/* The retry starts from an empty lifecycle and may dispatch once. */
	EXPECT_EQ(nvme_xdev_ext_lifecycle_prepare(&state.lifecycle), 0);

	/* Dispatched, then unwound: a retry would replay policy. */
	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, -EAGAIN), -EBUSY);
	EXPECT_EQ(nvme_xdev_ext_preaccept_next(&state), NVME_XDEV_EXT_CLEANUP_PUT_TOKEN);
	EXPECT_EQ(state.lifecycle, NVME_XDEV_EXT_LIFECYCLE_UNWOUND);
	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, -EAGAIN), -EBUSY);
	EXPECT_EQ(nvme_xdev_ext_issue_errno(&state, -EPERM), -EPERM);
	EXPECT_EQ(nvme_xdev_ext_issue_errno(NULL, -EAGAIN), -EBUSY);
}

static void test_runtime_ring_strides_and_encoding(void)
{
	union {
		struct io_uring_sqe alignment;
		unsigned char bytes[NVME_XDEV_EXT_RUNTIME_SQE_SIZE * 3];
	} sq_storage = {};
	union {
		struct io_uring_cqe alignment;
		unsigned char bytes[NVME_XDEV_EXT_RUNTIME_CQE_SIZE * 3];
	} cq_storage = {};
	struct nvme_xdev_ext_runtime_command command = {
		.fd = 19,
		.cmd_op = NVME_URING_CMD_IO,
		.user_data = UINT64_C(0x1122334455667788),
		.buffer = UINT64_C(0x8877665544332211),
		.data_len = 4096,
		.nsid = 7,
		.opcode = NVME_XDEV_EXT_NVM_READ,
		.slba = UINT64_C(0x123456789),
		.nlb = 8,
		.xdev_ext_flags = NVME_URING_CMD_F_XDEV_EXT,
		.uring_cmd_flags = IORING_URING_CMD_FIXED,
		.buf_index = 3,
	};
	struct io_uring_sqe *sqe;
	struct nvme_uring_cmd *cmd;

	EXPECT_EQ((unsigned char *)nvme_xdev_ext_runtime_sqe_at(sq_storage.bytes, 2) -
		  sq_storage.bytes, 2 * NVME_XDEV_EXT_RUNTIME_SQE_SIZE);
	EXPECT_EQ((unsigned char *)nvme_xdev_ext_runtime_cqe_at(cq_storage.bytes, 2) -
		  cq_storage.bytes, 2 * NVME_XDEV_EXT_RUNTIME_CQE_SIZE);

	memset(&sq_storage, 0xa5, sizeof(sq_storage));
	sqe = nvme_xdev_ext_runtime_sqe_at(sq_storage.bytes, 1);
	EXPECT_EQ(nvme_xdev_ext_runtime_encode(sqe, &command), 0);
	EXPECT_EQ(sqe->opcode, IORING_OP_URING_CMD);
	EXPECT_EQ(sqe->fd, command.fd);
	EXPECT_EQ(sqe->cmd_op, command.cmd_op);
	EXPECT_EQ(sqe->user_data, command.user_data);
	EXPECT_EQ(sqe->uring_cmd_flags, command.uring_cmd_flags);
	EXPECT_EQ(sqe->buf_index, command.buf_index);
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	EXPECT_EQ(cmd->opcode, command.opcode);
	EXPECT_EQ(cmd->nsid, command.nsid);
	EXPECT_EQ(cmd->addr, command.buffer);
	EXPECT_EQ(cmd->data_len, command.data_len);
	EXPECT_EQ(cmd->cdw10, (uint32_t)command.slba);
	EXPECT_EQ(cmd->cdw11, (uint32_t)(command.slba >> 32));
	EXPECT_EQ(cmd->cdw12, command.nlb - 1);
	EXPECT_EQ(cmd->rsvd2, command.xdev_ext_flags);
	EXPECT_EQ(sq_storage.bytes[NVME_XDEV_EXT_RUNTIME_SQE_SIZE - 1], 0xa5);
	EXPECT_EQ(sq_storage.bytes[2 * NVME_XDEV_EXT_RUNTIME_SQE_SIZE], 0xa5);

	command.nlb = 0;
	EXPECT_EQ(nvme_xdev_ext_runtime_encode(sqe, &command), -EINVAL);
	command.nlb = UINT32_MAX;
	EXPECT_EQ(nvme_xdev_ext_runtime_encode(sqe, &command), -EOVERFLOW);
}

static struct nvme_xdev_ext_runtime_safety valid_runtime_safety(void)
{
	struct nvme_xdev_ext_runtime_safety safety = {
		.device = "/dev/ng0n1",
		.canonical_device = "/dev/ng0n1",
		.model = "QEMU NVMe Ctrl",
		.serial = "UBRTEST0001",
		.character_device = 1,
		.sysfs_device_matches = 1,
		.sibling_topology_matches = 1,
		.virtual_machine = 1,
	};

	return safety;
}

static void test_runtime_safety_gate(void)
{
	struct nvme_xdev_ext_runtime_safety safety = valid_runtime_safety();

	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(NULL, 0),
		  NVME_XDEV_EXT_RUNTIME_SKIP_NO_DEVICE);
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_SAFE);
	safety.model = "QEMU NVMe Ctrl";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_SAFE);
	safety.model = "QEMU NVM Express Ctrl";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY);
	safety = valid_runtime_safety();
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 1),
		  NVME_XDEV_EXT_RUNTIME_REJECT_WRITE_NOT_ALLOWED);
	safety.allow_file_backed_write = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 1),
		  NVME_XDEV_EXT_RUNTIME_SAFE);

	safety.device = "/dev/ng1n1";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE);
	safety = valid_runtime_safety();
	safety.canonical_device = "/dev/nvme0n1";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE);
	safety = valid_runtime_safety();
	safety.model = "physical NVMe";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY);
	safety = valid_runtime_safety();
	safety.serial = "not-our-image";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY);
	safety = valid_runtime_safety();
	safety.character_device = 0;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE_TYPE);
	safety = valid_runtime_safety();
	safety.sysfs_device_matches = 0;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_SYSFS_MISMATCH);
	safety = valid_runtime_safety();
	safety.virtual_machine = 0;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_NOT_VM);
	safety = valid_runtime_safety();
	safety.sibling_topology_matches = 0;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_SIBLING_TOPOLOGY);
	safety = valid_runtime_safety();
	safety.mounted = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_MOUNTED);
	safety = valid_runtime_safety();
	safety.has_holders = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_HOLDERS);
	safety = valid_runtime_safety();
	safety.has_partitions = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_PARTITIONS);
	safety = valid_runtime_safety();
	safety.in_swap = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 0),
		  NVME_XDEV_EXT_RUNTIME_REJECT_SWAP);

	EXPECT_TRUE(nvme_xdev_ext_runtime_block_guard_valid(1, 1, 1));
	EXPECT_FALSE(nvme_xdev_ext_runtime_block_guard_valid(0, 1, 1));
	EXPECT_FALSE(nvme_xdev_ext_runtime_block_guard_valid(1, 0, 1));
	EXPECT_FALSE(nvme_xdev_ext_runtime_block_guard_valid(1, 1, 0));
}

/* --mech-s0 runs one case per attached program mode against UBRDST0001. */
static void test_runtime_mech_cases(void)
{
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse("lba"),
		  NVME_XDEV_EXT_RUNTIME_MECH_LBA);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse("window"),
		  NVME_XDEV_EXT_RUNTIME_MECH_WINDOW);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse("reserved"),
		  NVME_XDEV_EXT_RUNTIME_MECH_RESERVED);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse("no-prog"),
		  NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse("LBA"),
		  NVME_XDEV_EXT_RUNTIME_MECH_NONE);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse(""),
		  NVME_XDEV_EXT_RUNTIME_MECH_NONE);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_parse(NULL),
		  NVME_XDEV_EXT_RUNTIME_MECH_NONE);

	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_expected(NVME_XDEV_EXT_RUNTIME_MECH_LBA),
		  0);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_expected(
			NVME_XDEV_EXT_RUNTIME_MECH_WINDOW), -ERANGE);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_expected(
			NVME_XDEV_EXT_RUNTIME_MECH_RESERVED), -EPERM);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_expected(
			NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG), -EOPNOTSUPP);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_case_expected(
			NVME_XDEV_EXT_RUNTIME_MECH_NONE), -EINVAL);
	EXPECT_TRUE(!strcmp(nvme_xdev_ext_runtime_mech_case_name(
				NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG), "no-prog"));
	EXPECT_TRUE(!strcmp(nvme_xdev_ext_runtime_mech_case_key(
				NVME_XDEV_EXT_RUNTIME_MECH_LBA), "lba_from_prog"));
	EXPECT_TRUE(!strcmp(nvme_xdev_ext_runtime_mech_case_key(
				NVME_XDEV_EXT_RUNTIME_MECH_WINDOW), "window_reject"));
	EXPECT_TRUE(!strcmp(nvme_xdev_ext_runtime_mech_case_key(
				NVME_XDEV_EXT_RUNTIME_MECH_RESERVED),
			    "reserved_reject"));
	EXPECT_TRUE(!strcmp(nvme_xdev_ext_runtime_mech_case_key(
				NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG), "no_prog"));
}

/* The LBA nvme_s0.bpf.c builds in mode 0, recomputed by the runtime. */
static void test_runtime_mech_s0_slba(void)
{
	uint64_t slba = 0;

	EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(0, 4096, 64, 16, &slba), 0);
	EXPECT_EQ(slba, 4096);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(5, 4096, 64, 16, &slba), 0);
	EXPECT_EQ(slba, 4096 + 16);
	/* Only whole slots: 70 LBAs hold four 16-LBA slots. */
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(7, 4096, 70, 16, &slba), 0);
	EXPECT_EQ(slba, 4096 + 48);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(UINT64_MAX, 0, 16, 16, &slba),
		  0);
	EXPECT_EQ(slba, 0);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(1, 4096, 15, 16, &slba),
		  -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(1, 4096, 64, 0, &slba),
		  -EINVAL);
}

/*
 * What tools/xdev_ext_mech/nvme_s0.bpf.c builds for each --mech-s0 case (its
 * helpers, compiled here unchanged), admitted as the uring_cmd path does
 * (window = stage arg0/arg1, the 8 KiB WRITE): the runtime's slot rule
 * and its expected CQE result must hold for that program.
 */
static void test_runtime_mech_matches_program(void)
{
	static const uint32_t shifts[] = { 9, 12 };
	static const uint64_t windows[][2] = {
		{ 4096, 16 }, { 4096, 70 }, { 1, 2048 }, { 1ULL << 32, 256 },
	};
	struct nvme_xdev_ext_decoded decoded;
	__u64 prog = 0;
	uint64_t runtime = 0;
	unsigned int i, w, c;
	uint8_t sqe[64];
	uint64_t id;

	for (i = 0; i < 2; i++) {
		uint32_t shift = shifts[i];
		uint64_t nlb = NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES >> shift;

		for (w = 0; w < 4; w++) {
			struct nvme_xdev_ext_mech_bounds bounds = {
				.window_slba = windows[w][0],
				.window_nlb = windows[w][1] >> (shift - 9),
				.capacity_lbas = 1ULL << 40,
				.data_len = NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
				.lba_shift = shift,
				.write = true,
			};

			if (bounds.window_nlb < nlb)
				continue;
			for (id = 0; id < 300; id++) {
				EXPECT_EQ(nvme_xdev_ext_runtime_mech_s0_slba(id,
						bounds.window_slba,
						bounds.window_nlb, nlb,
						&runtime), 0);
				EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(
						bounds.window_slba,
						bounds.window_nlb, shift,
						NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
						id, XDEV_EXT_MP_NVME_MODE_WINDOW,
						&prog), 0);
				EXPECT_EQ(prog, runtime);
				for (c = NVME_XDEV_EXT_RUNTIME_MECH_LBA;
				     c <= NVME_XDEV_EXT_RUNTIME_MECH_RESERVED; c++) {
					memset(sqe, 0, sizeof(sqe));
					EXPECT_EQ(xdev_ext_mp_nvme_s0_slba(
						bounds.window_slba,
						bounds.window_nlb, shift,
						NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
						id,
						c == NVME_XDEV_EXT_RUNTIME_MECH_WINDOW ?
						XDEV_EXT_MP_NVME_MODE_OUTSIDE :
						XDEV_EXT_MP_NVME_MODE_WINDOW,
						&prog), 0);
					EXPECT_EQ(xdev_ext_mp_nvme_rw(sqe,
						XDEV_EXT_MP_DIR_TO_DEVICE, prog,
						NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
						shift), 0);
					if (c == NVME_XDEV_EXT_RUNTIME_MECH_RESERVED)
						xdev_ext_mp_nvme_set_reserved(sqe);
					EXPECT_EQ(nvme_xdev_ext_mech_validate(sqe,
							&bounds, &decoded),
						  nvme_xdev_ext_runtime_mech_case_expected(
							(enum nvme_xdev_ext_runtime_mech_case)c));
				}
			}
		}
	}
}

static void test_runtime_mech_window(void)
{
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(4096, 64, 1U << 19, 512),
		  0);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(4096, 16, 1U << 19, 512),
		  0);
	/* Room for one built 8 KiB WRITE at least. */
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(4096, 15, 1U << 19, 512),
		  -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(4096, 2, 1U << 19, 4096),
		  0);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(4096, 64, 1U << 19, 0),
		  -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(4096, 64, 1U << 19,
						     16384), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid((1U << 19) - 64, 64,
						     1U << 19, 512), 0);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid((1U << 19) - 63, 64,
						     1U << 19, 512), -ERANGE);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(UINT64_MAX, 64,
						     1U << 19, 512), -ERANGE);
	/* The runtime reads the whole window back: at most 1 MiB. */
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(0, 2048, 1U << 19, 512),
		  0);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_window_valid(0, 2049, 1U << 19, 512),
		  -E2BIG);
}

static void test_runtime_mech_names(void)
{
	char generic[32], controller[32], block[32];

	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng1n1", generic,
					      controller, block,
					      sizeof(generic)), 0);
	EXPECT_TRUE(!strcmp(generic, "ng1n1"));
	EXPECT_TRUE(!strcmp(controller, "nvme1"));
	EXPECT_TRUE(!strcmp(block, "nvme1n1"));
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng12n3", generic,
					      controller, block,
					      sizeof(generic)), 0);
	EXPECT_TRUE(!strcmp(controller, "nvme12"));
	EXPECT_TRUE(!strcmp(block, "nvme12n3"));
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/nvme1n1", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng1", generic, controller,
					      block, sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng1n", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ngn1", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng1n1p1", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng01n1", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/../dev/ng1n1", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng1234567n1", generic,
					      controller, block,
					      sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names(NULL, generic, controller,
					      block, sizeof(generic)), -EINVAL);
	EXPECT_EQ(nvme_xdev_ext_runtime_mech_names("/dev/ng1n1", generic,
					      controller, block, 7), -ENAMETOOLONG);
}

/* The mechanism cases write only the destination controller UBRDST0001. */
static void test_runtime_mech_safety_gate(void)
{
	struct nvme_xdev_ext_runtime_safety safety = valid_runtime_safety();

	safety.device = "/dev/ng1n1";
	safety.canonical_device = "/dev/ng1n1";
	safety.serial = NVME_XDEV_EXT_RUNTIME_MECH_SERIAL;
	safety.allow_file_backed_write = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety_for(&safety, 1, "/dev/ng1n1",
						    NVME_XDEV_EXT_RUNTIME_MECH_SERIAL),
		  NVME_XDEV_EXT_RUNTIME_SAFE);
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety(&safety, 1),
		  NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE);
	safety.serial = NVME_XDEV_EXT_RUNTIME_EXPECTED_SERIAL;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety_for(&safety, 1, "/dev/ng1n1",
						    NVME_XDEV_EXT_RUNTIME_MECH_SERIAL),
		  NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY);
	safety.serial = NVME_XDEV_EXT_RUNTIME_MECH_SERIAL;
	safety.canonical_device = "/dev/ng2n1";
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety_for(&safety, 1, "/dev/ng1n1",
						    NVME_XDEV_EXT_RUNTIME_MECH_SERIAL),
		  NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE);
	safety.canonical_device = "/dev/ng1n1";
	safety.allow_file_backed_write = 0;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety_for(&safety, 1, "/dev/ng1n1",
						    NVME_XDEV_EXT_RUNTIME_MECH_SERIAL),
		  NVME_XDEV_EXT_RUNTIME_REJECT_WRITE_NOT_ALLOWED);
	safety.allow_file_backed_write = 1;
	safety.mounted = 1;
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety_for(&safety, 1, "/dev/ng1n1",
						    NVME_XDEV_EXT_RUNTIME_MECH_SERIAL),
		  NVME_XDEV_EXT_RUNTIME_REJECT_MOUNTED);
	EXPECT_EQ(nvme_xdev_ext_runtime_check_safety_for(&safety, 1, NULL,
						    NVME_XDEV_EXT_RUNTIME_MECH_SERIAL),
		  NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE);
}

static void test_runtime_ambiguous_ownership(void)
{
	enum nvme_xdev_ext_runtime_backing_ownership ownership;

	EXPECT_TRUE(nvme_xdev_ext_runtime_may_release(NVME_XDEV_EXT_RUNTIME_BACKING_LOCAL));
	ownership = NVME_XDEV_EXT_RUNTIME_BACKING_PUBLISHED;
	EXPECT_FALSE(nvme_xdev_ext_runtime_may_release(ownership));
	ownership = NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED;
	EXPECT_TRUE(nvme_xdev_ext_runtime_may_release(ownership));
	ownership = NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS;
	EXPECT_FALSE(nvme_xdev_ext_runtime_may_release(ownership));
	ownership = NVME_XDEV_EXT_RUNTIME_BACKING_RETAINED_FAILURE;
	EXPECT_FALSE(nvme_xdev_ext_runtime_may_release(ownership));
	ownership = NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED;
	ownership = nvme_xdev_ext_runtime_restore_failed(ownership);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_RETAINED_FAILURE);
	ownership = NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS;
	ownership = nvme_xdev_ext_runtime_restore_failed(ownership);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
	ownership = nvme_xdev_ext_runtime_wait_result(0);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
	EXPECT_FALSE(nvme_xdev_ext_runtime_may_release(ownership));
	ownership = nvme_xdev_ext_runtime_wait_result(1);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED);
	EXPECT_TRUE(nvme_xdev_ext_runtime_may_release(ownership));
	ownership = nvme_xdev_ext_runtime_cqe_ownership(0, 1, 1);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED);
	ownership = nvme_xdev_ext_runtime_cqe_ownership(IORING_CQE_F_MORE, 1, 1);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
	ownership = nvme_xdev_ext_runtime_cqe_ownership(IORING_CQE_F_BUFFER, 1, 1);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
	ownership = nvme_xdev_ext_runtime_cqe_ownership(0, 0, 1);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
	ownership = nvme_xdev_ext_runtime_cqe_ownership(0, 1, 2);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
	ownership = nvme_xdev_ext_runtime_cqe_ownership(0, 1, 0);
	EXPECT_EQ(ownership, NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS);
}

static void test_runtime_write_baseline_gate(void)
{
	struct nvme_xdev_ext_runtime_baseline baseline = {
		.native_read_ok = 1,
		.native_cqe_ok = 1,
		.opted_read_ok = 1,
		.bytes_match = 1,
		.cqe_match = 1,
		.preflight_ok = 1,
		.block_guard_ok = 1,
		.safety_rechecked = 1,
	};

	EXPECT_TRUE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.native_read_ok = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.native_read_ok = 1;
	baseline.native_cqe_ok = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.native_cqe_ok = 1;
	baseline.opted_read_ok = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.opted_read_ok = 1;
	baseline.bytes_match = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.bytes_match = 1;
	baseline.cqe_match = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.cqe_match = 1;
	baseline.preflight_ok = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.preflight_ok = 1;
	baseline.block_guard_ok = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	baseline.block_guard_ok = 1;
	baseline.safety_rechecked = 0;
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(&baseline));
	EXPECT_FALSE(nvme_xdev_ext_runtime_write_allowed(NULL));
}

static void test_runtime_media_taint(void)
{
	enum nvme_xdev_ext_runtime_media_state state;

	state = NVME_XDEV_EXT_RUNTIME_MEDIA_ORIGINAL;
	EXPECT_TRUE(nvme_xdev_ext_runtime_media_reusable(state));
	state = NVME_XDEV_EXT_RUNTIME_MEDIA_WRITE_PUBLISHED;
	EXPECT_FALSE(nvme_xdev_ext_runtime_media_reusable(state));
	state = nvme_xdev_ext_runtime_media_write_result(1);
	EXPECT_EQ(state, NVME_XDEV_EXT_RUNTIME_MEDIA_PATTERN_PRESENT);
	EXPECT_FALSE(nvme_xdev_ext_runtime_media_reusable(state));
	state = nvme_xdev_ext_runtime_media_write_result(0);
	EXPECT_EQ(state, NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED);
	EXPECT_FALSE(nvme_xdev_ext_runtime_media_reusable(state));
	state = nvme_xdev_ext_runtime_media_restore_result(1);
	EXPECT_EQ(state, NVME_XDEV_EXT_RUNTIME_MEDIA_RESTORED);
	EXPECT_TRUE(nvme_xdev_ext_runtime_media_reusable(state));
	state = nvme_xdev_ext_runtime_media_restore_result(0);
	EXPECT_EQ(state, NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED);
	EXPECT_FALSE(nvme_xdev_ext_runtime_media_reusable(state));
}

int main(void)
{
	test_uapi_flags();
	test_capabilities_are_trusted_facts();
	test_vectored_length_is_snapshotted();
	test_decode_and_bounds();
	test_mech_validate_accepts_built_sqe();
	test_mech_validate_fail_closed();
	test_build_admission_split();
	test_admit_identity_rejects();
	test_build_user_check();
	test_build_errno();
	test_build_redecode();
	test_mech_cqe();
	test_mech_bind_check();
	test_mech_seg_walk();
	test_identity();
	test_lifecycle();
	test_resource_protocol();
	test_issue_errno_retries_only_before_dispatch();
	test_runtime_ring_strides_and_encoding();
	test_runtime_safety_gate();
	test_runtime_mech_cases();
	test_runtime_mech_s0_slba();
	test_runtime_mech_matches_program();
	test_runtime_mech_window();
	test_runtime_mech_names();
	test_runtime_mech_safety_gate();
	test_runtime_ambiguous_ownership();
	test_runtime_write_baseline_gate();
	test_runtime_media_taint();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u NVMe XDEV_EXT checks failed\n",
			failures, checks);
		return 1;
	}
	printf("PASS: %u NVMe XDEV_EXT admission/lifecycle checks\n", checks);
	return 0;
}
