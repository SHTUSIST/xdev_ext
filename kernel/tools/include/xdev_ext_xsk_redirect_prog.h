/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TOOLS_XDEV_EXT_XSK_REDIRECT_PROG_H
#define __TOOLS_XDEV_EXT_XSK_REDIRECT_PROG_H

/*
 * Pure generator for the XSK redirect XDP program.  It uses no libbpf and no
 * system call, so the libbpf loader in xdev_ext_xsk_redirect.c and the LD_PRELOAD
 * front end (through xdev_ext_bpf_raw.h) load the same instructions, and unit
 * tests inspect them without CAP_BPF.
 *
 * The program admits only untagged Ethernet, option-free unfragmented IPv4
 * and UDP with consistent lengths, then the exact fields the filter selects.
 * Every other frame reaches one "return XDP_PASS", so the kernel stack keeps
 * whatever the flow does not own.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/bpf.h>

#include "xdev_ext_xsk_redirect.h"

/* Generator options, kept out of the filter flags so that no flow
 * configuration can request them.  XDEV_EXT_XSK_PROG_TEST_ACTION_TX returns XDP_TX
 * on a match instead of calling bpf_redirect_map(): under BPF_PROG_TEST_RUN an
 * empty XSKMAP turns a match and a miss alike into XDP_PASS. */
#define XDEV_EXT_XSK_PROG_TEST_ACTION_TX	(1U << 0)
#define XDEV_EXT_XSK_PROG_OPTIONS_ALL	XDEV_EXT_XSK_PROG_TEST_ACTION_TX

#define XDEV_EXT_XSK_PROG_ETH_LEN		14U
#define XDEV_EXT_XSK_PROG_IPV4_LEN		20U
#define XDEV_EXT_XSK_PROG_UDP_LEN		8U
#define XDEV_EXT_XSK_PROG_MAGIC_LEN		4U

/* Spelled out rather than taken from <linux/if_ether.h> and <linux/in.h>:
 * the latter conflicts with <netinet/in.h> in the preloaded front end. */
#define XDEV_EXT_XSK_PROG_ETH_P_IPV4		0x0800
#define XDEV_EXT_XSK_PROG_IPPROTO_UDP	17

#define XDEV_EXT_XSK_PROG_INSN(code_, dst_, src_, off_, imm_) \
	((struct bpf_insn) { .code = (code_), .dst_reg = (dst_), \
		.src_reg = (src_), .off = (off_), .imm = (imm_) })

/* Shortest frame the program can admit: the headers, plus the magic when the
 * filter carries one.  A tuple-only program never reads the payload, so a
 * zero-length datagram is a 42-byte frame. */
static inline uint32_t
xdev_ext_xsk_prog_min_len(const struct xdev_ext_xsk_flow_filter *filter)
{
	uint32_t len = XDEV_EXT_XSK_PROG_ETH_LEN + XDEV_EXT_XSK_PROG_IPV4_LEN +
		       XDEV_EXT_XSK_PROG_UDP_LEN;

	if (filter && (filter->flags & XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC))
		len += XDEV_EXT_XSK_PROG_MAGIC_LEN;
	return len;
}

static inline bool xdev_ext_xsk_prog_unicast_mac(const uint8_t mac[6])
{
	uint8_t any = 0;

	for (unsigned int i = 0; i < 6; i++)
		any |= mac[i];
	return any && !(mac[0] & 1);
}

static inline int
xdev_ext_xsk_prog_validate(const struct xdev_ext_xsk_flow_filter *filter)
{
	const uint32_t destination = XDEV_EXT_XSK_FILTER_F_DST_IPV4 |
				     XDEV_EXT_XSK_FILTER_F_DST_PORT;

	if (!filter || (filter->flags & ~XDEV_EXT_XSK_FILTER_F_KNOWN))
		return -EINVAL;
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC) {
		if (!filter->payload_magic)
			return -EINVAL;
	} else if ((filter->flags & destination) != destination ||
		   !filter->dst_ipv4 || !filter->dst_port) {
		/* Without the magic the tuple is the whole filter: an unset
		 * destination would hand other sockets' datagrams to the ring. */
		return -EINVAL;
	}
	if ((filter->flags & XDEV_EXT_XSK_FILTER_F_DST_MAC) &&
	    !xdev_ext_xsk_prog_unicast_mac(filter->dst_mac))
		return -EINVAL;
	if ((filter->flags & XDEV_EXT_XSK_FILTER_F_MAX_LEN) &&
	    filter->max_len < xdev_ext_xsk_prog_min_len(filter))
		return -EINVAL;
	return 0;
}

struct xdev_ext_xsk_prog_builder {
	struct bpf_insn *program;
	size_t capacity;
	size_t count;
	size_t pass_jumps[24];
	size_t pass_jump_count;
};

static inline int xdev_ext_xsk_prog_emit(struct xdev_ext_xsk_prog_builder *builder,
				    struct bpf_insn instruction, size_t *index)
{
	if (builder->count >= builder->capacity)
		return -E2BIG;
	if (index)
		*index = builder->count;
	builder->program[builder->count++] = instruction;
	return 0;
}

static inline int
xdev_ext_xsk_prog_emit_pass_jump(struct xdev_ext_xsk_prog_builder *builder,
			    struct bpf_insn instruction)
{
	size_t index;
	int ret;

	if (builder->pass_jump_count >=
	    sizeof(builder->pass_jumps) / sizeof(builder->pass_jumps[0]))
		return -E2BIG;
	ret = xdev_ext_xsk_prog_emit(builder, instruction, &index);
	if (ret)
		return ret;
	builder->pass_jumps[builder->pass_jump_count++] = index;
	return 0;
}

static inline int
xdev_ext_xsk_prog_emit_exact_field(struct xdev_ext_xsk_prog_builder *builder,
			      uint8_t width, int16_t offset, uint32_t value)
{
	int ret;

	ret = xdev_ext_xsk_prog_emit(builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_LDX | width | BPF_MEM, BPF_REG_3,
				  BPF_REG_1, offset, 0), NULL);
	if (ret)
		return ret;
	if (width != BPF_B) {
		ret = xdev_ext_xsk_prog_emit(builder,
			XDEV_EXT_XSK_PROG_INSN(BPF_ALU | BPF_END | BPF_FROM_BE,
					  BPF_REG_3, 0, 0,
					  width == BPF_H ? 16 : 32), NULL);
		if (ret)
			return ret;
	}
	return xdev_ext_xsk_prog_emit_pass_jump(builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_JMP32 | BPF_JNE | BPF_K, BPF_REG_3, 0,
				  0, (int32_t)value));
}

/*
 * Build the program for @filter into @program.  @map_fd is the XSKMAP the
 * program redirects into; with XDEV_EXT_XSK_PROG_TEST_ACTION_TX no map is
 * referenced and @map_fd may be negative.  Returns 0, -EINVAL for a filter
 * or option the generator does not accept, or -E2BIG when @capacity is short.
 *
 * A payload-magic filter without XDEV_EXT_XSK_FILTER_F_DST_MAC and
 * XDEV_EXT_XSK_FILTER_F_MAX_LEN produces exactly the instructions it always has.
 */
static inline int xdev_ext_xsk_prog_build(int map_fd,
				     const struct xdev_ext_xsk_flow_filter *filter,
				     uint32_t options, struct bpf_insn *program,
				     size_t capacity, size_t *count)
{
	const int16_t eth_type_offset = 12;
	const int16_t ip_offset = XDEV_EXT_XSK_PROG_ETH_LEN;
	const int16_t ip_total_length_offset = ip_offset + 2;
	const int16_t ip_frag_offset = ip_offset + 6;
	const int16_t ip_protocol_offset = ip_offset + 9;
	const int16_t src_ipv4_offset = ip_offset + 12;
	const int16_t dst_ipv4_offset = ip_offset + 16;
	const int16_t udp_offset = ip_offset + XDEV_EXT_XSK_PROG_IPV4_LEN;
	const int16_t udp_length_offset = udp_offset + 4;
	const int16_t payload_offset = udp_offset + XDEV_EXT_XSK_PROG_UDP_LEN;
	struct xdev_ext_xsk_prog_builder builder = {
		.program = program,
		.capacity = capacity,
	};
	uint32_t minimum_length;
	size_t pass_index;
	bool magic;
	int ret;

	if (!program || !count || (options & ~XDEV_EXT_XSK_PROG_OPTIONS_ALL) ||
	    (map_fd < 0 && !(options & XDEV_EXT_XSK_PROG_TEST_ACTION_TX)))
		return -EINVAL;
	ret = xdev_ext_xsk_prog_validate(filter);
	if (ret)
		return ret;
	magic = filter->flags & XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC;
	minimum_length = xdev_ext_xsk_prog_min_len(filter);

#define XDEV_EXT_XSK_PROG_EMIT(instruction_) do { \
	ret = xdev_ext_xsk_prog_emit(&builder, (instruction_), NULL); \
	if (ret) \
		return ret; \
} while (0)

	/* r6 retains xdp_md; r1 is the packet base after the bounds proof. */
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
					    BPF_REG_6, BPF_REG_1, 0, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LDX | BPF_W | BPF_MEM,
					    BPF_REG_2, BPF_REG_6,
					    offsetof(struct xdp_md, data_end),
					    0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LDX | BPF_W | BPF_MEM,
					    BPF_REG_1, BPF_REG_6,
					    offsetof(struct xdp_md, data), 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
					    BPF_REG_3, BPF_REG_1, 0, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_ADD | BPF_K,
					    BPF_REG_3, 0, 0,
					    (int32_t)minimum_length));
	ret = xdev_ext_xsk_prog_emit_pass_jump(&builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_JGT | BPF_X, BPF_REG_3,
				  BPF_REG_2, 0, 0));
	if (ret)
		return ret;

	/* An XSK bound without multi-buffer drops a frame longer than one XSK
	 * frame (-ENOSPC in xsk_rcv_check()) where the stack would have kept
	 * it, so pass when data_end > data + max_len. */
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_MAX_LEN) {
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
						    BPF_REG_3, BPF_REG_1, 0,
						    0));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_ADD | BPF_K,
						    BPF_REG_3, 0, 0,
						    filter->max_len));
		ret = xdev_ext_xsk_prog_emit_pass_jump(&builder,
			XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_JGT | BPF_X,
					  BPF_REG_2, BPF_REG_3, 0, 0));
		if (ret)
			return ret;
	}
	/* Frames addressed to another station, broadcast or a multicast group
	 * stay with the stack. */
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_DST_MAC) {
		const uint8_t *mac = filter->dst_mac;

		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_W, 0,
			(uint32_t)mac[0] << 24 | (uint32_t)mac[1] << 16 |
			(uint32_t)mac[2] << 8 | mac[3]);
		if (ret)
			return ret;
		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_H, 4,
			(uint32_t)mac[4] << 8 | mac[5]);
		if (ret)
			return ret;
	}

	ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_H, eth_type_offset,
					    XDEV_EXT_XSK_PROG_ETH_P_IPV4);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_B, ip_offset, 0x45);
	if (ret)
		return ret;
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LDX | BPF_H | BPF_MEM,
					    BPF_REG_3, BPF_REG_1,
					    ip_frag_offset, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU | BPF_END | BPF_FROM_BE,
					    BPF_REG_3, 0, 0, 16));
	ret = xdev_ext_xsk_prog_emit_pass_jump(&builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_JMP32 | BPF_JSET | BPF_K, BPF_REG_3, 0,
				  0, 0x3fff));
	if (ret)
		return ret;
	ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_B,
					    ip_protocol_offset,
					    XDEV_EXT_XSK_PROG_IPPROTO_UDP);
	if (ret)
		return ret;

	/* The fixed packet prefix was proved above.  Now reject contradictory
	 * protocol lengths and prove that the complete IPv4 datagram is present.
	 * r7 retains host-order ip->tot_len; r4/r5 are scratch registers. */
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LDX | BPF_H | BPF_MEM,
					    BPF_REG_7, BPF_REG_1,
					    ip_total_length_offset, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU | BPF_END | BPF_FROM_BE,
					    BPF_REG_7, 0, 0, 16));
	/* The verifier keeps no bound for a BPF_END result and the JMP32 below
	 * bounds only the low half; mask so r7 can be added to a packet pointer. */
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_AND | BPF_K,
					    BPF_REG_7, 0, 0, 0xffff));
	ret = xdev_ext_xsk_prog_emit_pass_jump(&builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_JMP32 | BPF_JLT | BPF_K, BPF_REG_7, 0, 0,
				  XDEV_EXT_XSK_PROG_IPV4_LEN + XDEV_EXT_XSK_PROG_UDP_LEN +
				  (magic ? XDEV_EXT_XSK_PROG_MAGIC_LEN : 0)));
	if (ret)
		return ret;
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
					    BPF_REG_4, BPF_REG_1, 0, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_ADD | BPF_K,
					    BPF_REG_4, 0, 0, ip_offset));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_ADD | BPF_X,
					    BPF_REG_4, BPF_REG_7, 0, 0));
	ret = xdev_ext_xsk_prog_emit_pass_jump(&builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_JGT | BPF_X, BPF_REG_4,
				  BPF_REG_2, 0, 0));
	if (ret)
		return ret;
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LDX | BPF_H | BPF_MEM,
					    BPF_REG_4, BPF_REG_1,
					    udp_length_offset, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU | BPF_END | BPF_FROM_BE,
					    BPF_REG_4, 0, 0, 16));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU | BPF_MOV | BPF_X,
					    BPF_REG_5, BPF_REG_7, 0, 0));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU | BPF_SUB | BPF_K,
					    BPF_REG_5, 0, 0,
					    XDEV_EXT_XSK_PROG_IPV4_LEN));
	ret = xdev_ext_xsk_prog_emit_pass_jump(&builder,
		XDEV_EXT_XSK_PROG_INSN(BPF_JMP32 | BPF_JNE | BPF_X, BPF_REG_4,
				  BPF_REG_5, 0, 0));
	if (ret)
		return ret;

	if (filter->flags & XDEV_EXT_XSK_FILTER_F_SRC_IPV4) {
		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_W,
						    src_ipv4_offset,
						    filter->src_ipv4);
		if (ret)
			return ret;
	}
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_DST_IPV4) {
		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_W,
						    dst_ipv4_offset,
						    filter->dst_ipv4);
		if (ret)
			return ret;
	}
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_SRC_PORT) {
		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_H, udp_offset,
						    filter->src_port);
		if (ret)
			return ret;
	}
	if (filter->flags & XDEV_EXT_XSK_FILTER_F_DST_PORT) {
		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_H,
						    udp_offset + 2,
						    filter->dst_port);
		if (ret)
			return ret;
	}
	if (magic) {
		ret = xdev_ext_xsk_prog_emit_exact_field(&builder, BPF_W,
						    payload_offset,
						    filter->payload_magic);
		if (ret)
			return ret;
	}

	if (options & XDEV_EXT_XSK_PROG_TEST_ACTION_TX) {
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_K,
						    BPF_REG_0, 0, 0, XDP_TX));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0,
						    0));
	} else {
		/* r2 = ctx->rx_queue_index; r1 = private XSKMAP; r3 = XDP_PASS
		 * fallback when the configured queue has no socket. */
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LDX | BPF_W | BPF_MEM,
			BPF_REG_2, BPF_REG_6,
			offsetof(struct xdp_md, rx_queue_index), 0));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_LD | BPF_DW | BPF_IMM,
						    BPF_REG_1,
						    BPF_PSEUDO_MAP_FD, 0,
						    map_fd));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(0, 0, 0, 0, 0));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_K,
						    BPF_REG_3, 0, 0, XDP_PASS));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
						    BPF_FUNC_redirect_map));
		XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0,
						    0));
	}

	pass_index = builder.count;
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_ALU64 | BPF_MOV | BPF_K,
					    BPF_REG_0, 0, 0, XDP_PASS));
	XDEV_EXT_XSK_PROG_EMIT(XDEV_EXT_XSK_PROG_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0));
	for (size_t i = 0; i < builder.pass_jump_count; i++) {
		size_t jump = builder.pass_jumps[i];
		size_t distance = pass_index - jump - 1;

		if (distance > INT16_MAX)
			return -E2BIG;
		builder.program[jump].off = (int16_t)distance;
	}
	*count = builder.count;
	return 0;
#undef XDEV_EXT_XSK_PROG_EMIT
}

#endif /* __TOOLS_XDEV_EXT_XSK_REDIRECT_PROG_H */
