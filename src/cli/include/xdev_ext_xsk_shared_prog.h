/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_XSK_SHARED_PROG_H
#define XDEV_EXT_XSK_SHARED_PROG_H
#include "xdev_ext_xsk_redirect_prog.h"
#include "xdev_ext_xsk_shared.h"
#include <errno.h>
#include <string.h>

struct xdev_ext_shared_builder {
	struct bpf_insn *p;
	size_t n, cap, jumps[48], nr_jumps;
};
static inline int xdev_ext_shared_emit(struct xdev_ext_shared_builder *b,
				       struct bpf_insn insn, bool pass)
{
	if (b->n >= b->cap || (pass && b->nr_jumps >= 48))
		return -E2BIG;
	if (pass)
		b->jumps[b->nr_jumps++] = b->n;
	b->p[b->n++] = insn;
	return 0;
}
static inline int xdev_ext_shared_program(int xsks, int flows,
					  struct bpf_insn *p, size_t cap,
					  size_t *count)
{
	struct xdev_ext_shared_builder b = {.p = p, .cap = cap};
	size_t skip, i, pass;
	int ret;
	if (count)
		*count = 0;
	if (!p || !count || xsks < 0 || flows < 0)
		return -EINVAL;
#define I(c, d, s, o, v) XDEV_EXT_XSK_PROG_INSN(c, d, s, o, v)
#define E(c, d, s, o, v)                                                       \
	do {                                                                   \
		ret = xdev_ext_shared_emit(&b, I(c, d, s, o, v), false);       \
		if (ret)                                                       \
			return ret;                                            \
	} while (0)
#define J(c, d, s, v)                                                          \
	do {                                                                   \
		ret = xdev_ext_shared_emit(&b, I(c, d, s, 0, v), true);        \
		if (ret)                                                       \
			return ret;                                            \
	} while (0)
#define MOV(d, s) E(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define LOAD(d, s, o, w) E(BPF_LDX | BPF_MEM | w, d, s, o, 0)
#define BE(d, w) E(BPF_ALU | BPF_END | BPF_FROM_BE, d, 0, 0, w)
#define EXACT(o, w, v)                                                         \
	do {                                                                   \
		LOAD(3, 7, o, w);                                              \
		if ((w) != BPF_B)                                              \
			BE(3, (w) == BPF_H ? 16 : 32);                         \
		J(BPF_JMP32 | BPF_JNE | BPF_K, 3, 0, v);                       \
	} while (0)
#define MAP(d, fd)                                                             \
	do {                                                                   \
		E(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_MAP_FD, 0, fd);     \
		E(0, 0, 0, 0, 0);                                              \
	} while (0)
	MOV(6, 1);
	LOAD(7, 6, offsetof(struct xdp_md, data), BPF_W);
	LOAD(8, 6, offsetof(struct xdp_md, data_end), BPF_W);
	MOV(3, 7);
	E(BPF_ALU64 | BPF_ADD | BPF_K, 3, 0, 0, 46);
	J(BPF_JMP | BPF_JGT | BPF_X, 3, 8, 0);
	EXACT(12, BPF_H, 0x0800);
	EXACT(14, BPF_B, 0x45);
	EXACT(23, BPF_B, 17);
	LOAD(3, 7, 20, BPF_H);
	BE(3, 16);
	J(BPF_JMP32 | BPF_JSET | BPF_K, 3, 0, 0x3fff);
	LOAD(3, 7, 16, BPF_H);
	BE(3, 16);
	J(BPF_JMP32 | BPF_JLT | BPF_K, 3, 0, 32);
	MOV(4, 3);
	E(BPF_ALU64 | BPF_ADD | BPF_K, 4, 0, 0, 14);
	MOV(2, 7);
	E(BPF_ALU64 | BPF_ADD | BPF_X, 2, 4, 0, 0);
	J(BPF_JMP | BPF_JGT | BPF_X, 2, 8, 0);
	LOAD(4, 7, 38, BPF_H);
	BE(4, 16);
	J(BPF_JMP32 | BPF_JLT | BPF_K, 4, 0, 12);
	E(BPF_ALU64 | BPF_ADD | BPF_K, 4, 0, 0, 20);
	J(BPF_JMP32 | BPF_JNE | BPF_X, 4, 3, 0);
	E(BPF_ST | BPF_MEM | BPF_DW, 10, 0, -16, 0);
	E(BPF_ST | BPF_MEM | BPF_DW, 10, 0, -8, 0);
	LOAD(3, 7, 30, BPF_W);
	BE(3, 32);
	E(BPF_STX | BPF_MEM | BPF_W, 10, 3, -16, 0);
	LOAD(3, 7, 42, BPF_W);
	BE(3, 32);
	E(BPF_STX | BPF_MEM | BPF_W, 10, 3, -12, 0);
	LOAD(3, 7, 36, BPF_H);
	BE(3, 16);
	E(BPF_STX | BPF_MEM | BPF_H, 10, 3, -8, 0);
	MAP(1, flows);
	MOV(2, 10);
	E(BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -16);
	E(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem);
	J(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0);
	MOV(9, 0);
	LOAD(3, 6, offsetof(struct xdp_md, rx_queue_index), BPF_W);
	LOAD(2, 9, offsetof(struct xdev_ext_xsk_shared_flow, queue_id), BPF_W);
	J(BPF_JMP32 | BPF_JNE | BPF_X, 3, 2, 0);
#define OPTIONAL(flag)                                                         \
	do {                                                                   \
		LOAD(4, 9, offsetof(struct xdev_ext_xsk_shared_flow, flags),   \
		     BPF_W);                                                   \
		E(BPF_ALU | BPF_AND | BPF_K, 4, 0, 0, flag);                   \
		skip = b.n;                                                    \
		E(BPF_JMP32 | BPF_JEQ | BPF_K, 4, 0, 0, 0);                    \
	} while (0)
#define END_OPTIONAL()                                                         \
	do {                                                                   \
		b.p[skip].off = (int16_t)(b.n - skip - 1);                     \
	} while (0)
	OPTIONAL(XDEV_EXT_XSK_FILTER_F_SRC_IPV4);
	LOAD(3, 7, 26, BPF_W);
	BE(3, 32);
	LOAD(2, 9, offsetof(struct xdev_ext_xsk_shared_flow, src_ipv4), BPF_W);
	J(BPF_JMP32 | BPF_JNE | BPF_X, 3, 2, 0);
	END_OPTIONAL();
	OPTIONAL(XDEV_EXT_XSK_FILTER_F_SRC_PORT);
	LOAD(3, 7, 34, BPF_H);
	BE(3, 16);
	LOAD(2, 9, offsetof(struct xdev_ext_xsk_shared_flow, src_port), BPF_H);
	J(BPF_JMP32 | BPF_JNE | BPF_X, 3, 2, 0);
	END_OPTIONAL();
	OPTIONAL(XDEV_EXT_XSK_FILTER_F_MAX_LEN);
	MOV(3, 8);
	E(BPF_ALU64 | BPF_SUB | BPF_X, 3, 7, 0, 0);
	LOAD(2, 9, offsetof(struct xdev_ext_xsk_shared_flow, max_len), BPF_H);
	J(BPF_JMP | BPF_JGT | BPF_X, 3, 2, 0);
	END_OPTIONAL();
	OPTIONAL(XDEV_EXT_XSK_FILTER_F_DST_MAC);
	for (i = 0; i < 6; i++) {
		LOAD(3, 7, (int16_t)i, BPF_B);
		LOAD(2, 9,
		     (int16_t)(offsetof(struct xdev_ext_xsk_shared_flow,
					dst_mac) +
			       i),
		     BPF_B);
		J(BPF_JMP32 | BPF_JNE | BPF_X, 3, 2, 0);
	}
	END_OPTIONAL();
	MAP(1, xsks);
	LOAD(2, 9, offsetof(struct xdev_ext_xsk_shared_flow, queue_id), BPF_W);
	E(BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, XDP_PASS);
	E(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_redirect_map);
	E(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	pass = b.n;
	E(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, XDP_PASS);
	E(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
	for (i = 0; i < b.nr_jumps; i++)
		b.p[b.jumps[i]].off = (int16_t)(pass - b.jumps[i] - 1);
	*count = b.n;
#undef END_OPTIONAL
#undef OPTIONAL
#undef MAP
#undef EXACT
#undef BE
#undef LOAD
#undef MOV
#undef J
#undef E
#undef I
	return 0;
}
#endif
