#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the production xdev_ext_mech_batch_compute() of io_uring/xdev_ext_mech.c.

The function and xdev_ext_mech_worker_args() are copied verbatim; the fixture
stands in for the program call (xdev_ext_mech_call()), the per-frame length
store (xdev_ext_mech_batch_cpu_length()) and the counters, and records what
they saw. Checked: the length rule runs before the program, the program's
return value and kfunc misuse decide the batch, lengths are applied only after
every frame met L + D, and the call is the compute member at the worker.
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
struct xdev_ext_mech_frame {
	void *kaddr; u64 umem_addr; u32 index; u32 data_off; u32 data_len; void *pool_priv;
};
struct xdev_ext_mech_hold_intent;
struct xdev_ext_mech_class_ops {
	u32 desc_size, desc_cap, info_size, cqe_size, cqe_cap;
};
struct xdev_ext_mech_batch;
struct xdev_ext_mech_call_args {
	u32 member, callsite;
	const struct xdev_ext_binding_ctx_v2 *base;
	struct xdev_ext_mech_batch *b;
	u64 batch_id;
	const struct xdev_ext_mech_frame *frames;
	u32 nr_frames, frame_size, hdr_room, batch_frames, info_size;
	const void *info;
	u8 *scratch;
	u32 desc_size, desc_cap;
	const void *cqe;
	u32 cqe_size, cqe_cap;
	u32 *out_len;
	s32 len_delta;
};
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage {
	struct xdev_ext_mech_session *s;
	const struct xdev_ext_mech_class_ops *cls;
	u32 class_id, direction, index;
};
struct xdev_ext_mech_session {
	struct { u32 frame_size; } pool;
	struct xdev_ext_mech_stage st[4];
	void *info, *cqe;
	u8 *scratch;
	unsigned long protocol_errors;
};
struct xdev_ext_mech_batch {
	struct xdev_ext_mech_session *s;
	struct { u32 stage; } bs;
	u64 bytes;
	u32 nr_frames;
	struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
};
static struct xdev_ext_binding_ctx_v2 xdev_ext_mech_base(const struct xdev_ext_mech_stage *st, u64 bytes)
{
	struct xdev_ext_binding_ctx_v2 base;

	(void)st;
	memset(&base, 0, sizeof(base));
	base.length = bytes;
	return base;
}
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s, u32 counter, u64 n)
{
	if (counter == XDEV_EXT_MECH_CNT_PROTOCOL_ERR)
		s->protocol_errors += n;
}
/* The program: what it returns, which lengths it records, how the call ends. */
static int mode_call_rc;
static s32 mode_ret;
static bool mode_set;
static u32 mode_extra;
static unsigned int calls;
static struct xdev_ext_mech_call_args seen;
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_call_args *a,
			      s32 *ret, struct xdev_ext_mech_hold_intent *hold)
{
	u32 i;

	(void)st;
	if (hold)
		abort();
	calls++;
	seen = *a;
	if (mode_set)
		for (i = 0; i < a->nr_frames; i++)
			a->out_len[i] = (u32)((s64)a->frames[i].data_len + a->len_delta);
	if (mode_extra)
		a->out_len[a->nr_frames - 1] += mode_extra;
	if (mode_call_rc)
		return mode_call_rc;
	*ret = mode_ret;
	return 0;
}
static unsigned int lengths;
static u32 applied[XDEV_EXT_MECH_MAX_FRAMES];
static int length_rc;
static int xdev_ext_mech_batch_cpu_length(struct xdev_ext_mech_batch *b, u32 pos, u32 len)
{
	if (length_rc)
		return length_rc;
	if (pos >= b->nr_frames)
		abort();
	applied[pos] = len;
	lengths++;
	return 0;
}
'''

MAIN = r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s (calls=%u lengths=%u proto=%lu)\n", \
	__LINE__, #x, calls, lengths, s.protocol_errors); return 1; } } while (0)
static struct xdev_ext_mech_class_ops cls = { .desc_size = 16, .desc_cap = 1 };
static struct xdev_ext_mech_session s;
static struct xdev_ext_mech_batch b;
static u8 scratch[16];

static void reset(void)
{
	memset(&s, 0, sizeof(s));
	memset(&b, 0, sizeof(b));
	memset(applied, 0, sizeof(applied));
	s.pool.frame_size = 4096;
	s.scratch = scratch;
	s.st[1] = (struct xdev_ext_mech_stage) { .s = &s, .cls = &cls,
		.class_id = XDEV_EXT_MECH_CLASS_CPU, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .index = 1 };
	b.s = &s;
	b.bs.stage = 1;
	b.nr_frames = 3;
	b.f[0] = (struct xdev_ext_mech_frame) { .data_off = 360, .data_len = 1432 };
	b.f[1] = (struct xdev_ext_mech_frame) { .data_off = 360, .data_len = 1432 };
	b.f[2] = (struct xdev_ext_mech_frame) { .data_off = 360, .data_len = 1032 };
	b.bytes = 1432 + 1432 + 1032;
	mode_call_rc = 0; mode_ret = 0; mode_set = false; mode_extra = 0;
	calls = 0; lengths = 0; length_rc = 0;
	memset(&seen, 0, sizeof(seen));
}

int main(void)
{
	/* D = 0 and a program that records nothing: every length stays. */
	reset();
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == 0);
	CHECK(calls == 1 && lengths == 3 && applied[0] == 1432 && applied[2] == 1032);
	CHECK(seen.member == XDEV_EXT_MECH_MEMBER_COMPUTE && seen.callsite == XDEV_EXT_MECH_SITE_WORKER);
	CHECK(seen.b == &b && seen.frames == b.f && seen.nr_frames == 3 && seen.len_delta == 0);
	CHECK(seen.out_len && !seen.scratch && !seen.cqe && !seen.desc_size && !seen.cqe_size);
	CHECK(seen.base && !s.protocol_errors);
	/* D = 4 and a program that records L + 4 for every frame. */
	reset();
	mode_set = true;
	CHECK(xdev_ext_mech_batch_compute(&b, 4) == 0);
	CHECK(lengths == 3 && applied[0] == 1436 && applied[1] == 1436 && applied[2] == 1036);
	CHECK(seen.len_delta == 4);
	reset();
	mode_set = true;
	CHECK(xdev_ext_mech_batch_compute(&b, -4) == 0);
	CHECK(applied[0] == 1428 && applied[2] == 1028);
	/* D = 4 but no length recorded: refused, nothing applied. */
	reset();
	CHECK(xdev_ext_mech_batch_compute(&b, 4) == -EPROTO);
	CHECK(calls == 1 && lengths == 0 && s.protocol_errors == 1);
	/* A length other than L + D in the array is refused as well. */
	reset();
	mode_set = true;
	mode_extra = 1;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EPROTO);
	CHECK(lengths == 0 && s.protocol_errors == 1);
	/* The program's own error completes the batch; nothing applied. */
	reset();
	mode_set = true;
	mode_ret = -EBADMSG;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EBADMSG);
	CHECK(lengths == 0 && !s.protocol_errors);
	reset();
	mode_ret = -4095;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -4095 && !lengths);
	/* An illegal return value is a protocol error. */
	reset();
	mode_ret = 1;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EPROTO);
	CHECK(lengths == 0 && s.protocol_errors == 1);
	reset();
	mode_ret = -4096;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EPROTO && s.protocol_errors == 1);
	/* A kfunc latched misuse; no compute program in the generation. */
	reset();
	mode_set = true;
	mode_call_rc = -EPROTO;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EPROTO && !lengths && s.protocol_errors == 1);
	reset();
	mode_call_rc = -ENOENT;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EOPNOTSUPP && !lengths);
	/* The length rule runs before the program: it is not called at all. */
	reset();
	b.f[1].data_len = 4096 - 360 - 3;
	CHECK(xdev_ext_mech_batch_compute(&b, 4) == -EMSGSIZE && !calls && !lengths);
	reset();
	b.f[2].data_len = 3;
	CHECK(xdev_ext_mech_batch_compute(&b, -4) == -EBADMSG && !calls && !lengths);
	reset();
	b.f[0].data_len = 4096 - 360;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == 0 && calls == 1);
	reset();
	b.f[0].data_len = 4096 - 360 + 1;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EINVAL && !calls);
	reset();
	b.f[0].data_off = 4097;
	b.f[0].data_len = 0;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EINVAL && !calls);
	reset();
	CHECK(xdev_ext_mech_batch_compute(&b, XDEV_EXT_CPU_BPF_DELTA_MAX + 1) == -EINVAL && !calls);
	/* Only a CPU stage, only a real batch. */
	reset();
	s.st[1].class_id = XDEV_EXT_MECH_CLASS_NVME;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EINVAL && !calls);
	reset();
	b.nr_frames = 0;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EINVAL && !calls);
	reset();
	b.nr_frames = XDEV_EXT_MECH_MAX_FRAMES + 1;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -EINVAL && !calls);
	/* A refused length store fails the batch. */
	reset();
	length_rc = -ESTALE;
	CHECK(xdev_ext_mech_batch_compute(&b, 0) == -ESTALE);
	puts("PASS production batch compute: length rule first, program verdict, exact L + D, compute at worker");
	return 0;
}
'''


class BatchCompute(unittest.TestCase):
    def test_production_batch_compute(self):
        mech = source('io_uring/xdev_ext_mech.c')
        code = (PRELUDE + function(mech, 'xdev_ext_mech_worker_args') + '\n' +
                function(mech, 'xdev_ext_mech_batch_compute') + MAIN)
        rc, output = compile_and_run(code)
        print(output.strip())
        self.assertEqual(rc, 0, output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
