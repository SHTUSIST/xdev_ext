// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <linux/if_link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

#include "../../../include/xdev_ext_xsk_redirect.h"
#include "../../../include/xdev_ext_xsk_redirect_prog.h"

/* xdev_ext_bpf_raw.h issues every command through this seam, so the encoding of
 * each attr is checked here without CAP_BPF. */
static long fake_bpf_syscall(long number, int cmd, union bpf_attr *attr,
			     unsigned int size);
#define XDEV_EXT_BPF_RAW_SYSCALL fake_bpf_syscall
#include "../../../xdev_ext_bpf_raw.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	checks++;                                                            \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		failures++;                                                   \
	}                                                                   \
} while (0)

enum fake_call {
	CALL_MAP_CREATE = 1,
	CALL_PROG_LOAD,
	CALL_PROG_ID,
	CALL_ATTACH,
	CALL_QUERY,
	CALL_UPDATE,
	CALL_DELETE,
	CALL_DETACH,
	CALL_CLOSE,
};

struct fake_control {
	int calls[32];
	unsigned int nr_calls;
	int map_create_ret;
	int prog_load_ret;
	int prog_id_ret;
	uint32_t loaded_prog_id;
	int attach_ret;
	int query_ret;
	uint32_t current_prog_id;
	int update_ret;
	int delete_ret;
	int detach_ret;
	int close_ret;
	uint32_t max_entries;
	uint32_t queue_id;
	int xsk_fd;
	uint32_t attach_flags;
	struct xdev_ext_xsk_flow_filter loaded_filter;
};

static struct fake_control fake;
static const struct xdev_ext_xsk_flow_filter valid_filter = {
	.flags = XDEV_EXT_XSK_FILTER_F_ALL,
	.src_ipv4 = UINT32_C(0xc0000201),
	.dst_ipv4 = UINT32_C(0xc0000202),
	.payload_magic = UINT32_C(0x4e585032),
	.src_port = 54321,
	.dst_port = 12345,
};

static void note(enum fake_call call)
{
	fake.calls[fake.nr_calls++] = call;
}

static void fake_reset(void)
{
	fake = (struct fake_control) {
		.map_create_ret = 10,
		.prog_load_ret = 20,
		.loaded_prog_id = 77,
		.current_prog_id = 77,
	};
}

static int fake_map_create(uint32_t max_entries)
{
	note(CALL_MAP_CREATE);
	fake.max_entries = max_entries;
	return fake.map_create_ret;
}

static int fake_prog_load(int map_fd,
			  const struct xdev_ext_xsk_flow_filter *filter)
{
	note(CALL_PROG_LOAD);
	EXPECT_EQ(map_fd, 10);
	EXPECT_EQ(filter != NULL, 1);
	if (filter)
		fake.loaded_filter = *filter;
	return fake.prog_load_ret;
}

static int fake_prog_id(int prog_fd, uint32_t *prog_id)
{
	note(CALL_PROG_ID);
	EXPECT_EQ(prog_fd, 20);
	if (fake.prog_id_ret)
		return fake.prog_id_ret;
	*prog_id = fake.loaded_prog_id;
	return 0;
}

static int fake_attach(int ifindex, int prog_fd, uint32_t xdp_flags)
{
	note(CALL_ATTACH);
	EXPECT_EQ(ifindex, 9);
	EXPECT_EQ(prog_fd, 20);
	fake.attach_flags = xdp_flags;
	return fake.attach_ret;
}

static int fake_query(int ifindex, uint32_t xdp_flags, uint32_t *prog_id)
{
	note(CALL_QUERY);
	EXPECT_EQ(ifindex, 9);
	EXPECT_EQ(xdp_flags, fake.attach_flags);
	if (fake.query_ret)
		return fake.query_ret;
	*prog_id = fake.current_prog_id;
	return 0;
}

static int fake_update(int map_fd, uint32_t queue_id, int xsk_fd)
{
	note(CALL_UPDATE);
	EXPECT_EQ(map_fd, 10);
	fake.queue_id = queue_id;
	fake.xsk_fd = xsk_fd;
	return fake.update_ret;
}

static int fake_delete(int map_fd, uint32_t queue_id)
{
	note(CALL_DELETE);
	EXPECT_EQ(map_fd, 10);
	EXPECT_EQ(queue_id, fake.queue_id);
	return fake.delete_ret;
}

static int fake_detach(int ifindex, int expected_prog_fd, uint32_t xdp_flags)
{
	note(CALL_DETACH);
	EXPECT_EQ(ifindex, 9);
	EXPECT_EQ(expected_prog_fd, 20);
	EXPECT_EQ(xdp_flags, fake.attach_flags);
	return fake.detach_ret;
}

static int fake_close(int fd)
{
	note(CALL_CLOSE);
	EXPECT_EQ(fd == 20 || fd == 10, 1);
	return fake.close_ret;
}

static const struct xdev_ext_xsk_redirect_ops fake_ops = {
	.map_create = fake_map_create,
	.prog_load = fake_prog_load,
	.prog_id = fake_prog_id,
	.attach = fake_attach,
	.query_id = fake_query,
	.map_update = fake_update,
	.map_delete = fake_delete,
	.detach = fake_detach,
	.close_fd = fake_close,
};

static void expect_reset(const struct xdev_ext_xsk_redirect *redirect)
{
	EXPECT_EQ(redirect->map_fd, -1);
	EXPECT_EQ(redirect->prog_fd, -1);
	EXPECT_EQ(redirect->attached, 0);
	EXPECT_EQ(redirect->mapped, 0);
}

static void test_attach_and_exact_owner_detach(void)
{
	struct xdev_ext_xsk_redirect redirect;

	fake_reset();
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 3,
						42, XDP_FLAGS_DRV_MODE), 0);
	EXPECT_EQ(fake.max_entries, XDEV_EXT_XSK_REDIRECT_MAX_QUEUES);
	EXPECT_EQ(fake.queue_id, 3);
	EXPECT_EQ(fake.xsk_fd, 42);
	EXPECT_EQ(fake.loaded_filter.flags, valid_filter.flags);
	EXPECT_EQ(fake.loaded_filter.src_ipv4, valid_filter.src_ipv4);
	EXPECT_EQ(fake.loaded_filter.dst_ipv4, valid_filter.dst_ipv4);
	EXPECT_EQ(fake.loaded_filter.src_port, valid_filter.src_port);
	EXPECT_EQ(fake.loaded_filter.dst_port, valid_filter.dst_port);
	EXPECT_EQ(fake.loaded_filter.payload_magic, valid_filter.payload_magic);
	EXPECT_EQ(redirect.prog_id, 77);
	EXPECT_EQ(redirect.attached, 1);
	EXPECT_EQ(redirect.mapped, 1);
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), 0);
	EXPECT_EQ(fake.nr_calls, 11);
	EXPECT_EQ(fake.calls[6], CALL_DELETE);
	EXPECT_EQ(fake.calls[7], CALL_QUERY);
	EXPECT_EQ(fake.calls[8], CALL_DETACH);
	expect_reset(&redirect);
}

static void test_map_failure_never_attaches_program(void)
{
	struct xdev_ext_xsk_redirect redirect;

	fake_reset();
	fake.update_ret = -EIO;
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 2,
						41, XDP_FLAGS_SKB_MODE), -EIO);
	EXPECT_EQ(fake.calls[3], CALL_UPDATE);
	for (unsigned int i = 0; i < fake.nr_calls; i++) {
		EXPECT_EQ(fake.calls[i] == CALL_ATTACH, 0);
		EXPECT_EQ(fake.calls[i] == CALL_DETACH, 0);
	}
	expect_reset(&redirect);
}

static void test_replacement_is_never_detached(void)
{
	struct xdev_ext_xsk_redirect redirect;
	unsigned int before;

	fake_reset();
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 1,
						40, XDP_FLAGS_DRV_MODE), 0);
	fake.current_prog_id = 88;
	before = fake.nr_calls;
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), -ESTALE);
	EXPECT_EQ(fake.calls[before], CALL_DELETE);
	EXPECT_EQ(fake.calls[before + 1], CALL_QUERY);
	EXPECT_EQ(fake.nr_calls, before + 4); /* delete, query, two closes */
	for (unsigned int i = before; i < fake.nr_calls; i++)
		EXPECT_EQ(fake.calls[i] == CALL_DETACH, 0);
	expect_reset(&redirect);
}

static void test_map_delete_failure_preserves_live_ownership(void)
{
	struct xdev_ext_xsk_redirect redirect;
	unsigned int before;

	fake_reset();
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 1,
						40, XDP_FLAGS_DRV_MODE), 0);
	fake.delete_ret = -EIO;
	before = fake.nr_calls;
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), -EIO);
	EXPECT_EQ(fake.nr_calls, before + 1);
	EXPECT_EQ(fake.calls[before], CALL_DELETE);
	EXPECT_EQ(redirect.map_fd, 10);
	EXPECT_EQ(redirect.prog_fd, 20);
	EXPECT_EQ(redirect.mapped, 1);
	EXPECT_EQ(redirect.attached, 1);

	fake.delete_ret = 0;
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), 0);
	expect_reset(&redirect);
}

static void test_detach_failure_preserves_program_for_retry(void)
{
	struct xdev_ext_xsk_redirect redirect;
	unsigned int before;

	fake_reset();
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 1,
						40, XDP_FLAGS_DRV_MODE), 0);
	fake.detach_ret = -EBUSY;
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), -EBUSY);
	EXPECT_EQ(redirect.map_fd, 10);
	EXPECT_EQ(redirect.prog_fd, 20);
	EXPECT_EQ(redirect.mapped, 0);
	EXPECT_EQ(redirect.attached, 1);

	fake.detach_ret = 0;
	before = fake.nr_calls;
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), 0);
	EXPECT_EQ(fake.calls[before], CALL_QUERY);
	EXPECT_EQ(fake.calls[before + 1], CALL_DETACH);
	expect_reset(&redirect);
}

static void test_post_attach_query_failure_uses_expected_old_detach(void)
{
	struct xdev_ext_xsk_redirect redirect;
	bool saw_detach = false;

	fake_reset();
	fake.query_ret = -EIO;
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 1,
						40, XDP_FLAGS_DRV_MODE), -EIO);
	for (unsigned int i = 0; i < fake.nr_calls; i++) {
		if (fake.calls[i] == CALL_DETACH)
			saw_detach = true;
	}
	EXPECT_EQ(saw_detach, 1);
	expect_reset(&redirect);
}

static void test_post_attach_rollback_failure_retains_live_state(void)
{
	struct xdev_ext_xsk_redirect redirect;

	fake_reset();
	fake.query_ret = -EIO;
	fake.detach_ret = -EBUSY;
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 1,
						40, XDP_FLAGS_DRV_MODE), -EIO);
	EXPECT_EQ(redirect.map_fd, 10);
	EXPECT_EQ(redirect.prog_fd, 20);
	EXPECT_EQ(redirect.mapped, 0);
	EXPECT_EQ(redirect.attached, 1);

	fake.query_ret = 0;
	fake.detach_ret = 0;
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), 0);
	expect_reset(&redirect);
}

static void test_pre_attach_failures_close_private_fds(void)
{
	struct xdev_ext_xsk_redirect redirect;

	fake_reset();
	fake.attach_ret = -EEXIST;
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 0,
						39, XDP_FLAGS_DRV_MODE), -EEXIST);
	for (unsigned int i = 0; i < fake.nr_calls; i++)
		EXPECT_EQ(fake.calls[i] == CALL_DETACH, 0);
	expect_reset(&redirect);

	fake_reset();
	fake.prog_id_ret = -EIO;
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 0,
						39, XDP_FLAGS_DRV_MODE), -EIO);
	expect_reset(&redirect);
}

static void test_invalid_inputs_are_side_effect_free(void)
{
	struct xdev_ext_xsk_redirect redirect;
	struct xdev_ext_xsk_flow_filter bad_filter = valid_filter;

	fake_reset();
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(
		&redirect, &fake_ops, &valid_filter, 9, XDEV_EXT_XSK_REDIRECT_MAX_QUEUES, 8,
		XDP_FLAGS_DRV_MODE), -EINVAL);
	EXPECT_EQ(fake.nr_calls, 0);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &valid_filter, 9, 0, 8,
						XDP_FLAGS_HW_MODE), -EINVAL);
	EXPECT_EQ(fake.nr_calls, 0);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, NULL,
						9, 0, 8, XDP_FLAGS_DRV_MODE),
		  -EINVAL);
	EXPECT_EQ(fake.nr_calls, 0);
	/* Without the payload magic the destination address and port are the
	 * whole filter; dropping either one must not widen it. */
	bad_filter.flags &= ~(XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC |
			      XDEV_EXT_XSK_FILTER_F_DST_PORT);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &bad_filter,
						9, 0, 8, XDP_FLAGS_DRV_MODE),
		  -EINVAL);
	EXPECT_EQ(fake.nr_calls, 0);
	bad_filter = valid_filter;
	bad_filter.flags &= ~(XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC |
			      XDEV_EXT_XSK_FILTER_F_DST_IPV4);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &bad_filter,
						9, 0, 8, XDP_FLAGS_DRV_MODE),
		  -EINVAL);
	EXPECT_EQ(fake.nr_calls, 0);
	bad_filter = valid_filter;
	bad_filter.flags |= 1U << 31;
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops, &bad_filter,
						9, 0, 8, XDP_FLAGS_DRV_MODE),
		  -EINVAL);
	EXPECT_EQ(fake.nr_calls, 0);
}

static void test_program_builder_routes_every_reject_to_pass(void)
{
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS] = { 0 };
	struct xdev_ext_xsk_flow_filter magic_only = {
		.flags = XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC,
		.payload_magic = valid_filter.payload_magic,
	};
	size_t count = 0;
	size_t reject_count = 0;
	bool saw_magic = false;
	bool saw_high_bit_ipv4 = false;
	bool saw_64bit_bounds = false;
	bool saw_ip_total_length = false;
	bool saw_udp_length = false;
	bool saw_variable_packet_bound = false;
	int ret;

	ret = xdev_ext_xsk_redirect_build_program(10, &valid_filter, program,
					     XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
					     &count);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(count > 2 && count <= XDEV_EXT_XSK_REDIRECT_MAX_INSNS, 1);
	EXPECT_EQ(program[count - 2].code, BPF_ALU64 | BPF_MOV | BPF_K);
	EXPECT_EQ(program[count - 2].dst_reg, BPF_REG_0);
	EXPECT_EQ(program[count - 2].imm, XDP_PASS);
	EXPECT_EQ(program[count - 1].code, BPF_JMP | BPF_EXIT);
	for (size_t i = 0; i < count; i++) {
		uint8_t klass = BPF_CLASS(program[i].code);
		uint8_t op = BPF_OP(program[i].code);

		if ((klass == BPF_JMP || klass == BPF_JMP32) &&
		    (op == BPF_JNE || op == BPF_JGT || op == BPF_JLT ||
		     op == BPF_JSET)) {
			EXPECT_EQ(i + 1 + program[i].off, count - 2);
			reject_count++;
		}
		if (klass == BPF_JMP32 && op == BPF_JNE &&
		    (uint32_t)program[i].imm == valid_filter.payload_magic)
			saw_magic = true;
		if (klass == BPF_JMP32 && op == BPF_JNE &&
		    (uint32_t)program[i].imm == valid_filter.src_ipv4)
			saw_high_bit_ipv4 = true;
		if (klass == BPF_JMP && op == BPF_JGT &&
		    BPF_SRC(program[i].code) == BPF_X)
			saw_64bit_bounds = true;
		if (program[i].code == (BPF_LDX | BPF_H | BPF_MEM) &&
		    program[i].off == 14 + 2)
			saw_ip_total_length = true;
		if (program[i].code == (BPF_LDX | BPF_H | BPF_MEM) &&
		    program[i].off == 14 + 20 + 4)
			saw_udp_length = true;
		if (program[i].code == (BPF_ALU64 | BPF_ADD | BPF_X))
			saw_variable_packet_bound = true;
	}
	EXPECT_EQ(reject_count, 13); /* bounds, lengths, L2/L3/L4, tuple, magic */
	EXPECT_EQ(saw_magic, 1);
	EXPECT_EQ(saw_high_bit_ipv4, 1);
	EXPECT_EQ(saw_64bit_bounds, 1);
	EXPECT_EQ(saw_ip_total_length, 1);
	EXPECT_EQ(saw_udp_length, 1);
	EXPECT_EQ(saw_variable_packet_bound, 1);

	/* The kernel verifier forgets every bound of a BPF_END result, and a
	 * JMP32 compare bounds only the low half, so a byte-swapped length added
	 * to a packet pointer is rejected ("makes pkt pointer be out of bounds").
	 * Each such register must be masked by a 64-bit AND first. */
	{
		bool swapped_unmasked[MAX_BPF_REG] = { false };

		for (size_t i = 0; i < count; i++) {
			uint8_t reg = program[i].dst_reg;

			if (BPF_CLASS(program[i].code) == BPF_ALU &&
			    BPF_OP(program[i].code) == BPF_END)
				swapped_unmasked[reg] = true;
			else if (program[i].code == (BPF_ALU64 | BPF_AND | BPF_K) &&
				 program[i].imm > 0 && program[i].imm <= 0xffff)
				swapped_unmasked[reg] = false;
			else if (program[i].code == (BPF_ALU64 | BPF_ADD | BPF_X))
				EXPECT_EQ(swapped_unmasked[program[i].src_reg], 0);
			else if (BPF_CLASS(program[i].code) == BPF_LDX ||
				 (BPF_CLASS(program[i].code) == BPF_ALU64 &&
				  BPF_OP(program[i].code) == BPF_MOV))
				swapped_unmasked[reg] = false;
		}
	}

	/* The compulsory protocol and magic checks remain when no tuple fields
	 * are selected, and undersized output cannot silently truncate a program. */
	EXPECT_EQ(xdev_ext_xsk_redirect_build_program(
		10, &magic_only, program, XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &count), 0);
	EXPECT_EQ(count < XDEV_EXT_XSK_REDIRECT_MAX_INSNS, 1);
	EXPECT_EQ(xdev_ext_xsk_redirect_build_program(10, &valid_filter, program,
						 count - 1, &count), -E2BIG);
}

/* Captured from tools/xdev_ext_xsk_redirect.c at a563bdb28, before the generator
 * moved into xdev_ext_xsk_redirect_prog.h.  Every existing pipeline loads the
 * payload-magic program, so its instructions must stay byte-for-byte equal. */
static const struct bpf_insn legacy_all_insns[] = {
	{ 0xbf, 6, 1, 0, 0 },
	{ 0x61, 2, 6, 4, 0 },
	{ 0x61, 1, 6, 0, 0 },
	{ 0xbf, 3, 1, 0, 0 },
	{ 0x07, 3, 0, 0, 46 },
	{ 0x2d, 3, 2, 44, 0 },
	{ 0x69, 3, 1, 12, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x56, 3, 0, 41, 2048 },
	{ 0x71, 3, 1, 14, 0 },
	{ 0x56, 3, 0, 39, 69 },
	{ 0x69, 3, 1, 20, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x46, 3, 0, 36, 16383 },
	{ 0x71, 3, 1, 23, 0 },
	{ 0x56, 3, 0, 34, 17 },
	{ 0x69, 7, 1, 16, 0 },
	{ 0xdc, 7, 0, 0, 16 },
	{ 0x57, 7, 0, 0, 65535 },
	{ 0xa6, 7, 0, 30, 32 },
	{ 0xbf, 4, 1, 0, 0 },
	{ 0x07, 4, 0, 0, 14 },
	{ 0x0f, 4, 7, 0, 0 },
	{ 0x2d, 4, 2, 26, 0 },
	{ 0x69, 4, 1, 38, 0 },
	{ 0xdc, 4, 0, 0, 16 },
	{ 0xbc, 5, 7, 0, 0 },
	{ 0x14, 5, 0, 0, 20 },
	{ 0x5e, 4, 5, 21, 0 },
	{ 0x61, 3, 1, 26, 0 },
	{ 0xdc, 3, 0, 0, 32 },
	{ 0x56, 3, 0, 18, -1073741311 },
	{ 0x61, 3, 1, 30, 0 },
	{ 0xdc, 3, 0, 0, 32 },
	{ 0x56, 3, 0, 15, -1073741310 },
	{ 0x69, 3, 1, 34, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x56, 3, 0, 12, 54321 },
	{ 0x69, 3, 1, 36, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x56, 3, 0, 9, 12345 },
	{ 0x61, 3, 1, 42, 0 },
	{ 0xdc, 3, 0, 0, 32 },
	{ 0x56, 3, 0, 6, 1314410546 },
	{ 0x61, 2, 6, 16, 0 },
	{ 0x18, 1, 1, 0, 10 },
	{ 0x00, 0, 0, 0, 0 },
	{ 0xb7, 3, 0, 0, 2 },
	{ 0x85, 0, 0, 0, 51 },
	{ 0x95, 0, 0, 0, 0 },
	{ 0xb7, 0, 0, 0, 2 },
	{ 0x95, 0, 0, 0, 0 },
};

static const struct bpf_insn legacy_magic_only_insns[] = {
	{ 0xbf, 6, 1, 0, 0 },
	{ 0x61, 2, 6, 4, 0 },
	{ 0x61, 1, 6, 0, 0 },
	{ 0xbf, 3, 1, 0, 0 },
	{ 0x07, 3, 0, 0, 46 },
	{ 0x2d, 3, 2, 32, 0 },
	{ 0x69, 3, 1, 12, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x56, 3, 0, 29, 2048 },
	{ 0x71, 3, 1, 14, 0 },
	{ 0x56, 3, 0, 27, 69 },
	{ 0x69, 3, 1, 20, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x46, 3, 0, 24, 16383 },
	{ 0x71, 3, 1, 23, 0 },
	{ 0x56, 3, 0, 22, 17 },
	{ 0x69, 7, 1, 16, 0 },
	{ 0xdc, 7, 0, 0, 16 },
	{ 0x57, 7, 0, 0, 65535 },
	{ 0xa6, 7, 0, 18, 32 },
	{ 0xbf, 4, 1, 0, 0 },
	{ 0x07, 4, 0, 0, 14 },
	{ 0x0f, 4, 7, 0, 0 },
	{ 0x2d, 4, 2, 14, 0 },
	{ 0x69, 4, 1, 38, 0 },
	{ 0xdc, 4, 0, 0, 16 },
	{ 0xbc, 5, 7, 0, 0 },
	{ 0x14, 5, 0, 0, 20 },
	{ 0x5e, 4, 5, 9, 0 },
	{ 0x61, 3, 1, 42, 0 },
	{ 0xdc, 3, 0, 0, 32 },
	{ 0x56, 3, 0, 6, 1314410546 },
	{ 0x61, 2, 6, 16, 0 },
	{ 0x18, 1, 1, 0, 10 },
	{ 0x00, 0, 0, 0, 0 },
	{ 0xb7, 3, 0, 0, 2 },
	{ 0x85, 0, 0, 0, 51 },
	{ 0x95, 0, 0, 0, 0 },
	{ 0xb7, 0, 0, 0, 2 },
	{ 0x95, 0, 0, 0, 0 },
};

static const struct bpf_insn legacy_dst_magic_insns[] = {
	{ 0xbf, 6, 1, 0, 0 },
	{ 0x61, 2, 6, 4, 0 },
	{ 0x61, 1, 6, 0, 0 },
	{ 0xbf, 3, 1, 0, 0 },
	{ 0x07, 3, 0, 0, 46 },
	{ 0x2d, 3, 2, 38, 0 },
	{ 0x69, 3, 1, 12, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x56, 3, 0, 35, 2048 },
	{ 0x71, 3, 1, 14, 0 },
	{ 0x56, 3, 0, 33, 69 },
	{ 0x69, 3, 1, 20, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x46, 3, 0, 30, 16383 },
	{ 0x71, 3, 1, 23, 0 },
	{ 0x56, 3, 0, 28, 17 },
	{ 0x69, 7, 1, 16, 0 },
	{ 0xdc, 7, 0, 0, 16 },
	{ 0x57, 7, 0, 0, 65535 },
	{ 0xa6, 7, 0, 24, 32 },
	{ 0xbf, 4, 1, 0, 0 },
	{ 0x07, 4, 0, 0, 14 },
	{ 0x0f, 4, 7, 0, 0 },
	{ 0x2d, 4, 2, 20, 0 },
	{ 0x69, 4, 1, 38, 0 },
	{ 0xdc, 4, 0, 0, 16 },
	{ 0xbc, 5, 7, 0, 0 },
	{ 0x14, 5, 0, 0, 20 },
	{ 0x5e, 4, 5, 15, 0 },
	{ 0x61, 3, 1, 30, 0 },
	{ 0xdc, 3, 0, 0, 32 },
	{ 0x56, 3, 0, 12, 167772162 },
	{ 0x69, 3, 1, 36, 0 },
	{ 0xdc, 3, 0, 0, 16 },
	{ 0x56, 3, 0, 9, 4791 },
	{ 0x61, 3, 1, 42, 0 },
	{ 0xdc, 3, 0, 0, 32 },
	{ 0x56, 3, 0, 6, -559038737 },
	{ 0x61, 2, 6, 16, 0 },
	{ 0x18, 1, 1, 0, 7 },
	{ 0x00, 0, 0, 0, 0 },
	{ 0xb7, 3, 0, 0, 2 },
	{ 0x85, 0, 0, 0, 51 },
	{ 0x95, 0, 0, 0, 0 },
	{ 0xb7, 0, 0, 0, 2 },
	{ 0x95, 0, 0, 0, 0 },
};

static const struct xdev_ext_xsk_flow_filter tuple_filter = {
	.flags = XDEV_EXT_XSK_FILTER_F_DST_IPV4 | XDEV_EXT_XSK_FILTER_F_DST_PORT,
	.dst_ipv4 = UINT32_C(0xc0000202),
	.dst_port = 12345,
};

/* A connected socket: the peer address and port join the tuple, and the
 * interface MAC and frame length bound what may enter the ring. */
static const struct xdev_ext_xsk_flow_filter connected_filter = {
	.flags = XDEV_EXT_XSK_FILTER_F_SRC_IPV4 | XDEV_EXT_XSK_FILTER_F_DST_IPV4 |
		 XDEV_EXT_XSK_FILTER_F_SRC_PORT | XDEV_EXT_XSK_FILTER_F_DST_PORT |
		 XDEV_EXT_XSK_FILTER_F_DST_MAC | XDEV_EXT_XSK_FILTER_F_MAX_LEN,
	.src_ipv4 = UINT32_C(0xc0000201),
	.dst_ipv4 = UINT32_C(0xc0000202),
	.src_port = 54321,
	.dst_port = 12345,
	.dst_mac = { 0xa2, 0x15, 0x00, 0xc0, 0xff, 0xee },
	.max_len = 1514,
};

static void expect_program(const char *name, const struct bpf_insn *actual,
			   size_t actual_count, const struct bpf_insn *expected,
			   size_t expected_count)
{
	checks++;
	if (actual_count != expected_count) {
		fprintf(stderr, "%s: %zu instructions, expected %zu\n", name,
			actual_count, expected_count);
		failures++;
		return;
	}
	for (size_t i = 0; i < expected_count; i++) {
		if (!memcmp(&actual[i], &expected[i], sizeof(expected[i])))
			continue;
		fprintf(stderr,
			"%s: instruction %zu is {%#x,%u,%u,%d,%d}, expected {%#x,%u,%u,%d,%d}\n",
			name, i, actual[i].code, actual[i].dst_reg,
			actual[i].src_reg, actual[i].off, actual[i].imm,
			expected[i].code, expected[i].dst_reg,
			expected[i].src_reg, expected[i].off, expected[i].imm);
		failures++;
		return;
	}
}

static bool is_reject_jump(const struct bpf_insn *insn)
{
	uint8_t klass = BPF_CLASS(insn->code);
	uint8_t op = BPF_OP(insn->code);

	return (klass == BPF_JMP || klass == BPF_JMP32) &&
		(op == BPF_JNE || op == BPF_JGT || op == BPF_JLT ||
		 op == BPF_JSET);
}

/* Every conditional jump in the generated programs is a reject; all of them
 * must land on the trailing "r0 = XDP_PASS; exit". */
static size_t expect_rejects_reach_pass(const struct bpf_insn *program,
					size_t count)
{
	size_t rejects = 0;

	EXPECT_EQ(count > 2, 1);
	if (count <= 2)
		return 0;
	EXPECT_EQ(program[count - 2].code, BPF_ALU64 | BPF_MOV | BPF_K);
	EXPECT_EQ(program[count - 2].dst_reg, BPF_REG_0);
	EXPECT_EQ(program[count - 2].imm, XDP_PASS);
	EXPECT_EQ(program[count - 1].code, BPF_JMP | BPF_EXIT);
	for (size_t i = 0; i < count; i++) {
		if (!is_reject_jump(&program[i]))
			continue;
		EXPECT_EQ(i + 1 + program[i].off, count - 2);
		rejects++;
	}
	return rejects;
}

static unsigned int bpf_size_bytes(uint8_t code)
{
	switch (BPF_SIZE(code)) {
	case BPF_B:
		return 1;
	case BPF_H:
		return 2;
	case BPF_W:
		return 4;
	default:
		return 8;
	}
}

static void test_payload_magic_programs_are_unchanged(void)
{
	const struct {
		const char *name;
		int map_fd;
		struct xdev_ext_xsk_flow_filter filter;
		const struct bpf_insn *expected;
		size_t count;
	} cases[] = {
		{ "legacy_all", 10, valid_filter, legacy_all_insns,
		  sizeof(legacy_all_insns) / sizeof(legacy_all_insns[0]) },
		{ "legacy_magic_only", 10,
		  { .flags = XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC,
		    .payload_magic = UINT32_C(0x4e585032) },
		  legacy_magic_only_insns,
		  sizeof(legacy_magic_only_insns) /
			sizeof(legacy_magic_only_insns[0]) },
		{ "legacy_dst_magic", 7,
		  { .flags = XDEV_EXT_XSK_FILTER_F_DST_IPV4 |
			     XDEV_EXT_XSK_FILTER_F_DST_PORT |
			     XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC,
		    .dst_ipv4 = UINT32_C(0x0a000002), .dst_port = 4791,
		    .payload_magic = UINT32_C(0xdeadbeef) },
		  legacy_dst_magic_insns,
		  sizeof(legacy_dst_magic_insns) /
			sizeof(legacy_dst_magic_insns[0]) },
	};

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS] = { 0 };
		size_t count = 0;

		EXPECT_EQ(xdev_ext_xsk_redirect_build_program(
			cases[c].map_fd, &cases[c].filter, program,
			XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &count), 0);
		expect_program(cases[c].name, program, count, cases[c].expected,
			       cases[c].count);
		memset(program, 0, sizeof(program));
		count = 0;
		EXPECT_EQ(xdev_ext_xsk_prog_build(cases[c].map_fd, &cases[c].filter,
					     0, program,
					     XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &count),
			  0);
		expect_program(cases[c].name, program, count, cases[c].expected,
			       cases[c].count);
	}
}

static void test_tuple_filter_without_magic_is_accepted(void)
{
	struct xdev_ext_xsk_redirect redirect;

	EXPECT_EQ(xdev_ext_xsk_prog_validate(&tuple_filter), 0);
	EXPECT_EQ(xdev_ext_xsk_prog_validate(&connected_filter), 0);

	fake_reset();
	xdev_ext_xsk_redirect_init(&redirect);
	EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops,
						&tuple_filter, 9, 0, 8,
						XDP_FLAGS_SKB_MODE), 0);
	EXPECT_EQ(fake.loaded_filter.flags, tuple_filter.flags);
	EXPECT_EQ(fake.loaded_filter.dst_ipv4, tuple_filter.dst_ipv4);
	EXPECT_EQ(fake.loaded_filter.dst_port, tuple_filter.dst_port);
	EXPECT_EQ(xdev_ext_xsk_redirect_detach_with(&redirect, &fake_ops), 0);
	expect_reset(&redirect);
}

static void test_tuple_program_never_reads_payload(void)
{
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS] = { 0 };
	size_t count = 0;
	bool saw_ip_length_floor = false;
	bool saw_magic = false;
	bool saw_redirect = false;

	EXPECT_EQ(xdev_ext_xsk_prog_min_len(&tuple_filter), 14 + 20 + 8);
	EXPECT_EQ(xdev_ext_xsk_prog_min_len(&valid_filter), 14 + 20 + 8 + 4);
	EXPECT_EQ(xdev_ext_xsk_redirect_build_program(10, &tuple_filter, program,
						 XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
						 &count), 0);
	/* The packet bound covers exactly Ethernet + IPv4 + UDP. */
	EXPECT_EQ(program[4].code, BPF_ALU64 | BPF_ADD | BPF_K);
	EXPECT_EQ(program[4].dst_reg, BPF_REG_3);
	EXPECT_EQ(program[4].imm, 14 + 20 + 8);
	for (size_t i = 0; i < count; i++) {
		if (BPF_CLASS(program[i].code) == BPF_LDX &&
		    program[i].src_reg == BPF_REG_1)
			EXPECT_EQ(program[i].off +
				  bpf_size_bytes(program[i].code) <= 14 + 20 + 8,
				  1);
		/* A zero-length datagram is legal: tot_len >= 20 + 8. */
		if (program[i].code == (BPF_JMP32 | BPF_JLT | BPF_K) &&
		    program[i].dst_reg == BPF_REG_7 && program[i].imm == 20 + 8)
			saw_ip_length_floor = true;
		if (program[i].code == (BPF_JMP32 | BPF_JNE | BPF_K) &&
		    (uint32_t)program[i].imm == valid_filter.payload_magic)
			saw_magic = true;
		if (program[i].code == (BPF_JMP | BPF_CALL) &&
		    program[i].imm == BPF_FUNC_redirect_map)
			saw_redirect = true;
	}
	EXPECT_EQ(saw_ip_length_floor, 1);
	EXPECT_EQ(saw_magic, 0);
	EXPECT_EQ(saw_redirect, 1);
	/* bounds, L2/L3/L4 shape, lengths, destination address and port */
	EXPECT_EQ(expect_rejects_reach_pass(program, count), 10);
}

static void test_mac_and_length_checks_fall_back_to_pass(void)
{
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS] = { 0 };
	struct xdev_ext_xsk_flow_filter widest = valid_filter;
	size_t count = 0;
	bool saw_mac_high = false;
	bool saw_mac_low = false;
	bool saw_max_len = false;

	EXPECT_EQ(xdev_ext_xsk_redirect_build_program(10, &connected_filter,
						 program,
						 XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
						 &count), 0);
	for (size_t i = 0; i + 2 < count; i++) {
		const struct bpf_insn *p = &program[i];

		if (p[0].code == (BPF_LDX | BPF_W | BPF_MEM) &&
		    p[0].src_reg == BPF_REG_1 && p[0].off == 0 &&
		    p[1].code == (BPF_ALU | BPF_END | BPF_FROM_BE) &&
		    p[1].imm == 32 &&
		    p[2].code == (BPF_JMP32 | BPF_JNE | BPF_K) &&
		    (uint32_t)p[2].imm == UINT32_C(0xa21500c0))
			saw_mac_high = true;
		if (p[0].code == (BPF_LDX | BPF_H | BPF_MEM) &&
		    p[0].src_reg == BPF_REG_1 && p[0].off == 4 &&
		    p[1].code == (BPF_ALU | BPF_END | BPF_FROM_BE) &&
		    p[1].imm == 16 &&
		    p[2].code == (BPF_JMP32 | BPF_JNE | BPF_K) &&
		    p[2].imm == 0xffee)
			saw_mac_low = true;
		/* data_end > data + max_len: the frame cannot fit an XSK frame
		 * without multi-buffer, so the stack must keep it. */
		if (p[0].code == (BPF_ALU64 | BPF_MOV | BPF_X) &&
		    p[0].dst_reg == BPF_REG_3 && p[0].src_reg == BPF_REG_1 &&
		    p[1].code == (BPF_ALU64 | BPF_ADD | BPF_K) &&
		    p[1].dst_reg == BPF_REG_3 && p[1].imm == 1514 &&
		    p[2].code == (BPF_JMP | BPF_JGT | BPF_X) &&
		    p[2].dst_reg == BPF_REG_2 && p[2].src_reg == BPF_REG_3)
			saw_max_len = true;
	}
	EXPECT_EQ(saw_mac_high, 1);
	EXPECT_EQ(saw_mac_low, 1);
	EXPECT_EQ(saw_max_len, 1);
	/* 10 tuple-mode rejects + source address and port + MAC (2) + length */
	EXPECT_EQ(expect_rejects_reach_pass(program, count), 15);

	/* The widest legal filter still fits the published instruction cap. */
	widest.flags |= XDEV_EXT_XSK_FILTER_F_DST_MAC | XDEV_EXT_XSK_FILTER_F_MAX_LEN;
	memcpy(widest.dst_mac, connected_filter.dst_mac, sizeof(widest.dst_mac));
	widest.max_len = 1514;
	EXPECT_EQ(xdev_ext_xsk_redirect_build_program(10, &widest, program,
						 XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
						 &count), 0);
	EXPECT_EQ(expect_rejects_reach_pass(program, count), 16);
}

static void test_tx_action_replaces_only_the_redirect_tail(void)
{
	struct bpf_insn redirect_program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS] = { 0 };
	struct bpf_insn tx_program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS] = { 0 };
	size_t redirect_count = 0;
	size_t tx_count = 0;
	size_t count = 0;

	EXPECT_EQ(xdev_ext_xsk_prog_build(10, &connected_filter, 0,
				     redirect_program,
				     XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
				     &redirect_count), 0);
	/* The test action needs no XSKMAP. */
	EXPECT_EQ(xdev_ext_xsk_prog_build(-1, &connected_filter,
				     XDEV_EXT_XSK_PROG_TEST_ACTION_TX, tx_program,
				     XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &tx_count), 0);
	/* ctx load, two-slot map load, fallback action, call, exit -> r0, exit */
	EXPECT_EQ(redirect_count, tx_count + 4);
	if (redirect_count != tx_count + 4 || tx_count < 4)
		return;
	for (size_t i = 0; i < tx_count - 4; i++) {
		EXPECT_EQ(tx_program[i].code, redirect_program[i].code);
		EXPECT_EQ(tx_program[i].dst_reg, redirect_program[i].dst_reg);
		EXPECT_EQ(tx_program[i].src_reg, redirect_program[i].src_reg);
		EXPECT_EQ(tx_program[i].imm, redirect_program[i].imm);
		if (!is_reject_jump(&tx_program[i]))
			EXPECT_EQ(tx_program[i].off, redirect_program[i].off);
	}
	EXPECT_EQ(tx_program[tx_count - 4].code, BPF_ALU64 | BPF_MOV | BPF_K);
	EXPECT_EQ(tx_program[tx_count - 4].dst_reg, BPF_REG_0);
	EXPECT_EQ(tx_program[tx_count - 4].imm, XDP_TX);
	EXPECT_EQ(tx_program[tx_count - 3].code, BPF_JMP | BPF_EXIT);
	for (size_t i = 0; i < tx_count; i++) {
		EXPECT_EQ(tx_program[i].code == (BPF_JMP | BPF_CALL), 0);
		EXPECT_EQ(tx_program[i].code == (BPF_LD | BPF_DW | BPF_IMM), 0);
	}
	EXPECT_EQ(expect_rejects_reach_pass(tx_program, tx_count), 15);

	/* The redirect program needs its map; unknown options are refused. */
	EXPECT_EQ(xdev_ext_xsk_prog_build(-1, &connected_filter, 0, tx_program,
				     XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &count),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_xsk_prog_build(10, &connected_filter, 1U << 31,
				     tx_program, XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
				     &count), -EINVAL);
	EXPECT_EQ(xdev_ext_xsk_prog_build(10, &connected_filter, 0, tx_program,
				     redirect_count - 1, &count), -E2BIG);
}

static void test_incomplete_tuple_filters_are_rejected(void)
{
	struct xdev_ext_xsk_flow_filter cases[10];
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS];
	struct xdev_ext_xsk_redirect redirect;
	struct xdev_ext_xsk_flow_filter magic_len = valid_filter;
	size_t count;

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++)
		cases[c] = connected_filter;
	cases[0].dst_port = 0;
	cases[1].dst_ipv4 = 0;
	memset(cases[2].dst_mac, 0, sizeof(cases[2].dst_mac));
	cases[3].dst_mac[0] |= 1;	/* group address, never an interface's */
	cases[4].max_len = 14 + 20 + 8 - 1;
	cases[5].flags |= 1U << 7;
	cases[6].flags = XDEV_EXT_XSK_FILTER_F_DST_MAC | XDEV_EXT_XSK_FILTER_F_MAX_LEN;
	cases[7].flags &= ~XDEV_EXT_XSK_FILTER_F_DST_IPV4;
	cases[8].flags &= ~XDEV_EXT_XSK_FILTER_F_DST_PORT;
	cases[9].flags = XDEV_EXT_XSK_FILTER_F_SRC_IPV4 | XDEV_EXT_XSK_FILTER_F_SRC_PORT;

	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		EXPECT_EQ(xdev_ext_xsk_prog_validate(&cases[c]), -EINVAL);
		EXPECT_EQ(xdev_ext_xsk_prog_build(10, &cases[c], 0, program,
					     XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
					     &count), -EINVAL);
		EXPECT_EQ(xdev_ext_xsk_redirect_build_program(
			10, &cases[c], program, XDEV_EXT_XSK_REDIRECT_MAX_INSNS,
			&count), -EINVAL);
		fake_reset();
		xdev_ext_xsk_redirect_init(&redirect);
		EXPECT_EQ(xdev_ext_xsk_redirect_attach_with(&redirect, &fake_ops,
							&cases[c], 9, 0, 8,
							XDP_FLAGS_SKB_MODE),
			  -EINVAL);
		EXPECT_EQ(fake.nr_calls, 0);
	}
	EXPECT_EQ(xdev_ext_xsk_prog_validate(NULL), -EINVAL);

	/* A payload-magic program must still prove the four magic bytes. */
	magic_len.flags |= XDEV_EXT_XSK_FILTER_F_MAX_LEN;
	magic_len.max_len = 14 + 20 + 8 + 4 - 1;
	EXPECT_EQ(xdev_ext_xsk_prog_validate(&magic_len), -EINVAL);
	magic_len.max_len = 14 + 20 + 8 + 4;
	EXPECT_EQ(xdev_ext_xsk_prog_validate(&magic_len), 0);
}

static struct {
	unsigned int calls;
	long number;
	int cmd;
	union bpf_attr attr;
	unsigned int size;
	long ret;
	int error;
} bpf_fake;

static long fake_bpf_syscall(long number, int cmd, union bpf_attr *attr,
			     unsigned int size)
{
	bpf_fake.calls++;
	bpf_fake.number = number;
	bpf_fake.cmd = cmd;
	bpf_fake.attr = *attr;
	bpf_fake.size = size;
	if (bpf_fake.ret < 0) {
		errno = bpf_fake.error;
		return -1;
	}
	if (cmd == BPF_PROG_TEST_RUN)
		attr->test.retval = XDP_TX;
	return bpf_fake.ret;
}

static void bpf_fake_reset(long ret)
{
	memset(&bpf_fake, 0, sizeof(bpf_fake));
	bpf_fake.ret = ret;
}

static void expect_bpf_call(int cmd)
{
	EXPECT_EQ(bpf_fake.calls, 1);
	EXPECT_EQ(bpf_fake.number, __NR_bpf);
	EXPECT_EQ(bpf_fake.cmd, cmd);
	EXPECT_EQ(bpf_fake.size, sizeof(union bpf_attr));
}

static void test_bpf_raw_encodes_each_command(void)
{
	static const char license[] = "GPL";
	struct bpf_insn program[XDEV_EXT_XSK_REDIRECT_MAX_INSNS];
	uint8_t frame[64] = { 0 };
	char log[128];
	uint32_t key = 3;
	uint32_t value = 41;
	uint32_t retval = 0;
	size_t count = 0;

	bpf_fake_reset(33);
	EXPECT_EQ(xdev_ext_bpf_raw_map_create(BPF_MAP_TYPE_XSKMAP, 4, 4, 64,
					 "xdev_ext_xsks"), 33);
	expect_bpf_call(BPF_MAP_CREATE);
	EXPECT_EQ(bpf_fake.attr.map_type, BPF_MAP_TYPE_XSKMAP);
	EXPECT_EQ(bpf_fake.attr.key_size, 4);
	EXPECT_EQ(bpf_fake.attr.value_size, 4);
	EXPECT_EQ(bpf_fake.attr.max_entries, 64);
	EXPECT_EQ(bpf_fake.attr.map_flags, 0);
	EXPECT_EQ(strcmp(bpf_fake.attr.map_name, "xdev_ext_xsks"), 0);

	/* Object names longer than BPF_OBJ_NAME_LEN - 1 are cut, not refused. */
	bpf_fake_reset(34);
	EXPECT_EQ(xdev_ext_bpf_raw_map_create(BPF_MAP_TYPE_XSKMAP, 4, 4, 1,
					 "xdev_ext_xsk_redirect_map_name"), 34);
	EXPECT_EQ(strlen(bpf_fake.attr.map_name), BPF_OBJ_NAME_LEN - 1);

	bpf_fake_reset(0);
	EXPECT_EQ(xdev_ext_bpf_raw_map_update(33, &key, &value, BPF_NOEXIST), 0);
	expect_bpf_call(BPF_MAP_UPDATE_ELEM);
	EXPECT_EQ(bpf_fake.attr.map_fd, 33);
	EXPECT_EQ(bpf_fake.attr.key, (uintptr_t)&key);
	EXPECT_EQ(bpf_fake.attr.value, (uintptr_t)&value);
	EXPECT_EQ(bpf_fake.attr.flags, BPF_NOEXIST);

	EXPECT_EQ(xdev_ext_xsk_prog_build(33, &tuple_filter, 0, program,
				     XDEV_EXT_XSK_REDIRECT_MAX_INSNS, &count), 0);
	bpf_fake_reset(35);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, "xdev_ext_xsk_rx",
					program, count, license, log,
					sizeof(log), 1), 35);
	expect_bpf_call(BPF_PROG_LOAD);
	EXPECT_EQ(bpf_fake.attr.prog_type, BPF_PROG_TYPE_XDP);
	EXPECT_EQ(bpf_fake.attr.insns, (uintptr_t)program);
	EXPECT_EQ(bpf_fake.attr.insn_cnt, count);
	EXPECT_EQ(bpf_fake.attr.license, (uintptr_t)license);
	EXPECT_EQ(bpf_fake.attr.log_buf, (uintptr_t)log);
	EXPECT_EQ(bpf_fake.attr.log_size, sizeof(log));
	EXPECT_EQ(bpf_fake.attr.log_level, 1);
	EXPECT_EQ(bpf_fake.attr.expected_attach_type, 0);
	EXPECT_EQ(strcmp(bpf_fake.attr.prog_name, "xdev_ext_xsk_rx"), 0);

	/* Without a log buffer no log level may reach the kernel. */
	bpf_fake_reset(36);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, NULL, program,
					count, license, NULL, 0, 1), 36);
	EXPECT_EQ(bpf_fake.attr.log_buf, 0);
	EXPECT_EQ(bpf_fake.attr.log_size, 0);
	EXPECT_EQ(bpf_fake.attr.log_level, 0);

	bpf_fake_reset(0);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_test_run(35, frame, sizeof(frame), &retval),
		  0);
	expect_bpf_call(BPF_PROG_TEST_RUN);
	EXPECT_EQ(bpf_fake.attr.test.prog_fd, 35);
	EXPECT_EQ(bpf_fake.attr.test.data_in, (uintptr_t)frame);
	EXPECT_EQ(bpf_fake.attr.test.data_size_in, sizeof(frame));
	EXPECT_EQ(bpf_fake.attr.test.data_out, 0);
	EXPECT_EQ(bpf_fake.attr.test.repeat, 1);
	EXPECT_EQ(bpf_fake.attr.test.flags, 0);
	EXPECT_EQ(retval, XDP_TX);

	bpf_fake_reset(37);
	EXPECT_EQ(xdev_ext_bpf_raw_link_create_xdp(35, 9, XDP_FLAGS_SKB_MODE), 37);
	expect_bpf_call(BPF_LINK_CREATE);
	EXPECT_EQ(bpf_fake.attr.link_create.prog_fd, 35);
	EXPECT_EQ(bpf_fake.attr.link_create.target_ifindex, 9);
	EXPECT_EQ(bpf_fake.attr.link_create.attach_type, BPF_XDP);
	EXPECT_EQ(bpf_fake.attr.link_create.flags, XDP_FLAGS_SKB_MODE);

	bpf_fake_reset(0);
	EXPECT_EQ(xdev_ext_bpf_raw_link_update(37, 38, 35), 0);
	expect_bpf_call(BPF_LINK_UPDATE);
	EXPECT_EQ(bpf_fake.attr.link_update.link_fd, 37);
	EXPECT_EQ(bpf_fake.attr.link_update.new_prog_fd, 38);
	EXPECT_EQ(bpf_fake.attr.link_update.flags, BPF_F_REPLACE);
	EXPECT_EQ(bpf_fake.attr.link_update.old_prog_fd, 35);

	bpf_fake_reset(0);
	EXPECT_EQ(xdev_ext_bpf_raw_link_update(37, 38, -1), 0);
	EXPECT_EQ(bpf_fake.attr.link_update.flags, 0);
	EXPECT_EQ(bpf_fake.attr.link_update.old_prog_fd, 0);

	bpf_fake_reset(0);
	EXPECT_EQ(xdev_ext_bpf_raw_link_detach(37), 0);
	expect_bpf_call(BPF_LINK_DETACH);
	EXPECT_EQ(bpf_fake.attr.link_detach.link_fd, 37);

	/* Kernel errors come back as -errno. */
	bpf_fake_reset(-1);
	bpf_fake.error = EPERM;
	EXPECT_EQ(xdev_ext_bpf_raw_link_create_xdp(35, 9, XDP_FLAGS_DRV_MODE),
		  -EPERM);
	EXPECT_EQ(bpf_fake.calls, 1);

	/* Malformed requests never reach the kernel. */
	bpf_fake_reset(0);
	EXPECT_EQ(xdev_ext_bpf_raw_map_update(-1, &key, &value, BPF_ANY), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_map_update(33, NULL, &value, BPF_ANY), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, NULL, NULL, 1,
					license, NULL, 0, 0), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, NULL, program, 0,
					license, NULL, 0, 0), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_load(BPF_PROG_TYPE_XDP, NULL, program,
					count, NULL, NULL, 0, 0), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_test_run(35, NULL, 64, &retval), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_prog_test_run(35, frame, sizeof(frame), NULL),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_link_create_xdp(35, 0, XDP_FLAGS_SKB_MODE),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_link_create_xdp(-1, 9, XDP_FLAGS_SKB_MODE),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_link_update(-1, 38, 35), -EINVAL);
	EXPECT_EQ(xdev_ext_bpf_raw_link_detach(-1), -EINVAL);
	EXPECT_EQ(bpf_fake.calls, 0);
}

int main(void)
{
	test_attach_and_exact_owner_detach();
	test_map_failure_never_attaches_program();
	test_replacement_is_never_detached();
	test_map_delete_failure_preserves_live_ownership();
	test_detach_failure_preserves_program_for_retry();
	test_post_attach_query_failure_uses_expected_old_detach();
	test_post_attach_rollback_failure_retains_live_state();
	test_pre_attach_failures_close_private_fds();
	test_invalid_inputs_are_side_effect_free();
	test_program_builder_routes_every_reject_to_pass();
	test_payload_magic_programs_are_unchanged();
	test_tuple_filter_without_magic_is_accepted();
	test_tuple_program_never_reads_payload();
	test_mac_and_length_checks_fall_back_to_pass();
	test_tx_action_replaces_only_the_redirect_tail();
	test_incomplete_tuple_filters_are_rejected();
	test_bpf_raw_encodes_each_command();
	printf("xdev_ext_xsk_redirect: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
