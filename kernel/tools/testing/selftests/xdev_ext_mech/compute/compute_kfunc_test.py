#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the production compute kfuncs of io_uring/xdev_ext_mech_ops.c on the host.

bpf_xdev_ext_frame_len(), bpf_xdev_ext_frame_rw() and bpf_xdev_ext_frame_set_len()
are copied verbatim with their helpers and called on a hand-built call
envelope: their bounds, the member gate (compute only), the latched protocol
error, and that the read-only frame view stays available to compute. The
fixture supplies only kernel types and crc32c(); see compute_extract.py.
No kernel, guest or BPF program is involved.
"""
import unittest

from compute_extract import compile_and_run, function, source

PRELUDE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_cpu_core.h"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t s32; typedef int64_t s64;
#define __bpf_kfunc
#define READ_ONCE(x) (x)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define XDEV_EXT_MECH_CALL_MAGIC 0x55424d43U
struct xdev_ext_mech_frame {
	void *kaddr; u64 umem_addr; u32 index; u32 data_off; u32 data_len; void *pool_priv;
};
struct xdev_ext_mech_call {
	struct xdev_ext_mech_ctx ctx;
	u32 magic;
	u8 member, callsite, hold_calls, protocol_error;
	const struct xdev_ext_mech_frame *frames;
	u32 nr_frames;
	u32 frame_size;
	u32 *out_len;
	s32 len_delta;
};
static struct xdev_ext_mech_call *xdev_ext_mech_call_of(const struct xdev_ext_mech_ctx *ctx)
{
	struct xdev_ext_mech_call *c = container_of(ctx, struct xdev_ext_mech_call, ctx);

	return READ_ONCE(c->magic) == XDEV_EXT_MECH_CALL_MAGIC ? c : NULL;
}
static unsigned int crc_calls;
static u32 crc32c(u32 seed, const void *p, size_t len)
{
	(void)p;
	crc_calls++;
	return seed ^ (u32)len;
}
'''

MAIN = r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
#define FS 4096U
static u8 chunk[2][FS];
static struct xdev_ext_mech_frame f[2];
static struct xdev_ext_mech_call c;
static u32 out[2];

static void reset(u32 member, s32 delta)
{
	memset(&c, 0, sizeof(c));
	f[0] = (struct xdev_ext_mech_frame) { .kaddr = chunk[0], .data_off = 360, .data_len = 1432 };
	f[1] = (struct xdev_ext_mech_frame) { .kaddr = chunk[1], .data_off = 0, .data_len = 1032 };
	out[0] = f[0].data_len;
	out[1] = f[1].data_len;
	c.magic = XDEV_EXT_MECH_CALL_MAGIC;
	c.member = member;
	c.callsite = XDEV_EXT_MECH_SITE_WORKER;
	c.frames = f;
	c.nr_frames = 2;
	c.frame_size = FS;
	c.out_len = out;
	c.len_delta = delta;
}

int main(void)
{
	const struct xdev_ext_mech_ctx *ctx = &c.ctx;
	static const u32 other[] = { XDEV_EXT_MECH_MEMBER_PREPARE, XDEV_EXT_MECH_MEMBER_BUILD,
				     XDEV_EXT_MECH_MEMBER_COMPLETE, 0, 5 };
	unsigned int i;

	/* frame_len: the entry length of each frame; a bad position is misuse. */
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	CHECK(bpf_xdev_ext_frame_len(ctx, 0) == 1432 && bpf_xdev_ext_frame_len(ctx, 1) == 1032);
	CHECK(!c.protocol_error);
	CHECK(bpf_xdev_ext_frame_len(ctx, 2) == 0 && c.protocol_error);
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	CHECK(bpf_xdev_ext_frame_len(ctx, UINT32_MAX) == 0 && c.protocol_error);

	/* frame_rw: offsets from the first valid byte, bounded by the capacity. */
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	CHECK(bpf_xdev_ext_frame_rw(ctx, 0, 0, 1) == chunk[0] + 360);
	CHECK(bpf_xdev_ext_frame_rw(ctx, 0, 1432, 4) == chunk[0] + 360 + 1432);
	CHECK(bpf_xdev_ext_frame_rw(ctx, 0, 3735, 1) == chunk[0] + 4095);
	CHECK(bpf_xdev_ext_frame_rw(ctx, 0, 3732, 4) == chunk[0] + 4092);
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 3736, 1));
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 3733, 4));
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 3737));
	CHECK(bpf_xdev_ext_frame_rw(ctx, 0, 0, 3736) == chunk[0] + 360);
	CHECK(bpf_xdev_ext_frame_rw(ctx, 1, 0, FS) == chunk[1]);
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 1, 1, FS));
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 0));
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, UINT32_MAX, 2));
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 2, 0, 1));
	/* A NULL view is an answer, not misuse. */
	CHECK(!c.protocol_error);
	f[0].kaddr = NULL;
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 1));
	f[0].kaddr = chunk[0];
	f[0].data_off = FS;
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 1));
	f[0].data_off = FS + 1;
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 1));

	/* set_len: exactly entry length + D, inside the capacity. */
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 1432) == 0 && out[0] == 1432 && !c.protocol_error);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 1433) == -EINVAL && out[0] == 1432 &&
	      c.protocol_error);
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 4);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 1, 1036) == 0 && out[1] == 1036 && !c.protocol_error);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 1436) == 0 && out[0] == 1436);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 1, 1032) == -EINVAL && out[1] == 1036 &&
	      c.protocol_error);
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, -4);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 1, 1028) == 0 && out[1] == 1028);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 2, 1028) == -EINVAL && c.protocol_error);
	/* L + D past the capacity can never be recorded. */
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 8);
	f[0].data_len = 3732;
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 3740) == -EINVAL && out[0] == 1432 &&
	      c.protocol_error);
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	c.out_len = NULL;
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 1432) == -EINVAL && c.protocol_error);

	/* Only compute gets the writable kfuncs; any other member is misuse. */
	for (i = 0; i < sizeof(other) / sizeof(other[0]); i++) {
		reset(other[i], 0);
		CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 1));
		CHECK(bpf_xdev_ext_frame_len(ctx, 0) == 0 && c.protocol_error);
		reset(other[i], 0);
		CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 1432) == -EINVAL && c.protocol_error);
		CHECK(out[0] == 1432);
	}
	/* An unsealed context gets nothing. */
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	c.magic = 0;
	CHECK(!bpf_xdev_ext_frame_rw(ctx, 0, 0, 1));
	CHECK(bpf_xdev_ext_frame_len(ctx, 0) == 0);
	CHECK(bpf_xdev_ext_frame_set_len(ctx, 0, 1432) == -EINVAL && out[0] == 1432);

	/* The read-only view and frame CRC keep chunk offsets in compute too. */
	reset(XDEV_EXT_MECH_MEMBER_COMPUTE, 0);
	CHECK(bpf_xdev_ext_frame(ctx, 0, 0, 4) == chunk[0]);
	CHECK(bpf_xdev_ext_frame(ctx, 0, 360, 1432) == chunk[0] + 360);
	CHECK(!bpf_xdev_ext_frame(ctx, 0, 4093, 4));
	CHECK(bpf_xdev_ext_frame_crc32c(ctx, 0, 360, 1432, 7) == (7U ^ 1432U) && crc_calls == 1);
	CHECK(!c.protocol_error);
	CHECK(bpf_xdev_ext_frame_crc32c(ctx, 0, 4000, 200, 7) == 0 && c.protocol_error);
	reset(XDEV_EXT_MECH_MEMBER_PREPARE, 0);
	CHECK(!bpf_xdev_ext_frame(ctx, 0, 0, 4));
	puts("PASS production compute kfuncs: bounds, member gate, latched misuse, read-only view");
	return 0;
}
'''


class ComputeKfuncs(unittest.TestCase):
    def test_production_kfuncs(self):
        ops = source('io_uring/xdev_ext_mech_ops.c')
        names = ('xdev_ext_mech_frame_bytes', 'xdev_ext_mech_compute_frame',
                 'bpf_xdev_ext_frame', 'bpf_xdev_ext_frame_crc32c',
                 'bpf_xdev_ext_frame_len', 'bpf_xdev_ext_frame_rw',
                 'bpf_xdev_ext_frame_set_len')
        code = PRELUDE + '\n'.join(function(ops, n) for n in names) + MAIN
        rc, output = compile_and_run(code)
        print(output.strip())
        self.assertEqual(rc, 0, output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
