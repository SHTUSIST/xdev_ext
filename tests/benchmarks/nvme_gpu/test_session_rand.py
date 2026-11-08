#!/usr/bin/env python3
"""Random reads in the session arm: the NVMe plan program follows the rand schedule.

The baselines read schedule position i of pass p from block
xg_block(g, p, i) (nvme_gpu_core.h).  The session arm cannot pick keys per
batch (START numbers them first_seq, first_seq+1, ...), so the NVMe plan
program nvme_rand.bpf.c maps batch k to block xg_block(g, 0, k) itself.
These checks run on any Linux host: the pure helpers of
xdev_ext_mech_prog.h against nvme_gpu_core.h, and the program's own build
callback compiled for the host.  The verifier and a kernel run are KVM work.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
KERNEL = REPO / "kernel"
PROGRAM = KERNEL / "tools/xdev_ext_mech/nvme_rand.bpf.c"

HELPERS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"
#include "NVME_GPU_CORE"

static unsigned long checks, failures;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; if (failures < 20) { \
	fprintf(stderr, "FAIL line %d: ", __LINE__); fprintf(stderr, __VA_ARGS__); \
	fputc('\n', stderr); } } } while (0)

static uint64_t ref_add(uint64_t n, uint32_t seed)
{
	return xg_mix64(((uint64_t)seed << 32) ^ (0 + 0x5bd1e995ULL)) % n;
}

int main(void)
{
	static const uint64_t ns[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 30, 32, 64, 100,
		210, 256, 1000, 2310, 4096, 30030, 65536, 262144, 510510, 1 << 20,
		9699690, 1 << 24 };
	static const uint32_t seeds[] = { 0, 1, 2, 7, 12345, 0xffffffffU };
	unsigned a, b;

	for (a = 0; a < sizeof(ns) / sizeof(ns[0]); a++) {
		for (b = 0; b < sizeof(seeds) / sizeof(seeds[0]); b++) {
			uint64_t n = ns[a], add, i;
			__u64 mul = 0, group;
			uint32_t seed = seeds[b];
			struct xg_geometry g = { .size = 4096, .qd = 1, .window = n * 4096,
						 .passes = 1, .pattern = XG_RAND, .seed = seed };

			CHECK(!xdev_ext_mp_affine_mul(n, seed, &mul), "mul n=%llu", (unsigned long long)n);
			CHECK(mul == xg_rand_mul(n, seed, 0), "mul n=%llu seed=%u got=%llu want=%llu",
			      (unsigned long long)n, seed, (unsigned long long)mul,
			      (unsigned long long)xg_rand_mul(n, seed, 0));
			add = xdev_ext_mp_affine_add(n, seed);
			CHECK(add == ref_add(n, seed), "add n=%llu seed=%u", (unsigned long long)n, seed);
			for (i = 0; i < n && i < 4096; i++) {
				uint64_t k = i < 2048 ? i : n - 1 - (i - 2048);

				CHECK(!xdev_ext_mp_affine_group(n, mul, add, k, &group) &&
				      group == xg_block(&g, 0, k),
				      "group n=%llu seed=%u i=%llu got=%llu want=%llu",
				      (unsigned long long)n, seed, (unsigned long long)k,
				      (unsigned long long)group, (unsigned long long)xg_block(&g, 0, k));
			}
			/* A session longer than one pass repeats the pass-0 schedule. */
			CHECK(!xdev_ext_mp_affine_group(n, mul, add, n + 1, &group) &&
			      group == xg_block(&g, 0, 1 % n), "wrap n=%llu", (unsigned long long)n);
		}
	}
	/* Every position of a small window names a distinct group. */
	for (a = 1; a <= 3000; a++) {
		static unsigned char seen[3000];
		uint64_t add, i;
		__u64 mul, group;

		memset(seen, 0, sizeof(seen));
		CHECK(!xdev_ext_mp_affine_mul(a, 1, &mul), "mul %u", a);
		add = xdev_ext_mp_affine_add(a, 1);
		for (i = 0; i < a; i++) {
			CHECK(!xdev_ext_mp_affine_group(a, mul, add, i, &group) && group < a &&
			      !seen[group]++, "permutation n=%u i=%llu", a, (unsigned long long)i);
		}
	}
	/* The largest window the helpers take (no product overflows): n < 2^32. */
	{
		uint64_t add, n = 0xffffffffULL;
		__u64 mul, group;

		CHECK(!xdev_ext_mp_affine_mul(n, 3, &mul) && mul > 1 && mul < n, "mul 2^32-1");
		add = xdev_ext_mp_affine_add(n, 3);
		CHECK(!xdev_ext_mp_affine_group(n, mul, add, n - 1, &group) &&
		      group == (uint64_t)(((unsigned __int128)mul * (n - 1) + add) % n), "2^32-1");
		CHECK(xdev_ext_mp_affine_mul(n + 1, 3, &mul) == -EOVERFLOW, "2^32 groups");
		CHECK(xdev_ext_mp_affine_mul(0, 3, &mul) == -EINVAL, "no group");
		CHECK(xdev_ext_mp_affine_group(0, 1, 0, 0, &group) == -EINVAL, "no group");
		CHECK(xdev_ext_mp_affine_group(8, 8, 0, 0, &group) == -EINVAL, "mul == n");
		CHECK(xdev_ext_mp_affine_group(8, 0, 0, 0, &group) == -EINVAL, "mul 0");
		CHECK(xdev_ext_mp_affine_group(8, 3, 8, 0, &group) == -EINVAL, "add == n");
		CHECK(xdev_ext_mp_affine_group(n + 1, 3, 0, 0, &group) == -EINVAL, "2^32 groups");
	}
	printf("affine order: %lu checks, %lu failures\n", checks, failures);
	return failures != 0;
}
'''

PRELUDE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"
#include "NVME_GPU_CORE"
#define BPF_PROG(name, args...) name(unsigned long long *ctx, args)
static struct xdev_ext_nvme_mech_info nvme_info;
static unsigned char nvme_sqe[64];
static bool no_info, no_desc;
static __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, size_t n)
{ (void)ctx; assert(n == sizeof(nvme_info)); return no_info ? NULL : (void *)&nvme_info; }
static __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot, size_t n)
{ (void)ctx; assert(!slot && n == sizeof(nvme_sqe)); return no_desc ? NULL : nvme_sqe; }
'''

DRIVER = r'''
static unsigned long checks, failures;
#define CHECK(c, ...) do { checks++; if (!(c)) { failures++; if (failures < 20) { \
	fprintf(stderr, "FAIL line %d: ", __LINE__); fprintf(stderr, __VA_ARGS__); \
	fputc('\n', stderr); } } } while (0)

static unsigned long long le64(const unsigned char *p)
{ unsigned long long v = 0; for (unsigned i = 0; i < 8; i++) v |= (unsigned long long)p[i] << (8 * i); return v; }
static unsigned le16(const unsigned char *p) { return p[0] | p[1] << 8; }

static struct xdev_ext_mech_ctx m;

static void window(uint64_t slba, uint64_t nlb, uint32_t group, uint32_t shift, uint32_t max_nlb)
{
	memset(&nvme_info, 0, sizeof(nvme_info));
	nvme_info.l = (struct xdev_ext_mech_layout){ .frame_size = 4096, .seg_len = 4096, .group_bytes = group };
	nvme_info.lba_shift = shift;
	nvme_info.max_nlb = max_nlb;
	nvme_info.window_slba = slba;
	nvme_info.window_nlb = nlb;
	nvme_info.capacity_lbas = slba + nlb;
	m.base.length = group;
}

/* Batches 0..n-1 of one window read blocks xg_block(g, 0, k) in order. */
static void campaign(uint64_t slba, uint64_t n, uint32_t size, uint32_t shift, uint32_t seed,
		     uint32_t direction)
{
	struct xg_geometry g = { .size = size, .qd = 1, .window = n * size, .passes = 1,
				 .pattern = XG_RAND, .seed = seed };
	uint64_t k, blocks = size >> shift;

	window(slba, n * blocks, size, shift, 65536);
	m.base.direction = direction;
	for (k = 0; k < n; k++) {
		int ret;

		memset(nvme_sqe, 0xa5, sizeof(nvme_sqe));
		m.base.src_offset = key_base + k;
		ret = nvme_rand_build(NULL, &m);
		CHECK(ret == XDEV_EXT_MP_BUILD_SUBMIT, "n=%llu k=%llu ret=%d", (unsigned long long)n,
		      (unsigned long long)k, ret);
		CHECK(le64(nvme_sqe + 40) == slba + xg_block(&g, 0, k) * blocks,
		      "n=%llu seed=%u k=%llu slba=%llu want block %llu", (unsigned long long)n, seed,
		      (unsigned long long)k, le64(nvme_sqe + 40),
		      (unsigned long long)xg_block(&g, 0, k));
		CHECK(le16(nvme_sqe + 48) == blocks - 1, "nlb");
		CHECK(nvme_sqe[0] == (direction == XDEV_EXT_MECH_DIR_TO_DEVICE ? 0x01 : 0x02), "opcode");
	}
}

int main(void)
{
	static const uint64_t ns[] = { 1, 2, 3, 4, 8, 12, 100, 256, 1000, 4096 };
	unsigned i;

	CHECK(key_base == 1, "the arm starts every pass at first_seq 1");
	/* rand_seed is set when the object is loaded (ctl attach --set), so a
	 * new seed is a new load: the cache starts empty. */
	for (i = 0; i < sizeof(ns) / sizeof(ns[0]); i++) {
		rand_seed = 1;
		rand_cache = 0;
		campaign(4096, ns[i], 8192, 9, 1, XDEV_EXT_MECH_DIR_FROM_DEVICE);
		rand_seed = 77;
		rand_cache = 0;
		campaign(0, ns[i], 4096, 12, 77, XDEV_EXT_MECH_DIR_TO_DEVICE);
	}
	/* Two windows in turn: the cached multiplier is keyed by the window. */
	rand_seed = 5;
	rand_cache = 0;
	for (i = 0; i < 6; i++) {
		campaign(100 * 8, i & 1 ? 12 : 1000, 4096, 9, 5, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	}

	/* Refusals. */
	rand_seed = 1;
	rand_cache = 0;
	window(4096, 64 * 16, 8192, 9, 65536);
	m.base.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	m.base.src_offset = key_base - 1;
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "key below key_base");
	m.base.src_offset = key_base;
	m.base.length = 1ULL << 32;
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "length beyond 32 bits");
	window(4096, 64 * 16, 8192, 9, 15);
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "16 LBAs over max_nlb 15");
	window(4096, 64 * 16, 8192, 9, 16);
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_SUBMIT, "16 LBAs at max_nlb 16");
	window(4096, 15, 8192, 9, 65536);
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "window holds no group");
	window(4096, 64 * 16, 8192, 8, 65536);
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "LBA shift below 9");
	window(4096, 64 * 16, 8192, 9, 65536);
	no_info = true;
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "no info");
	no_info = false;
	no_desc = true;
	CHECK(nvme_rand_build(NULL, &m) == XDEV_EXT_MP_BUILD_ABORT, "no descriptor");
	no_desc = false;
	printf("nvme_rand_build: %lu checks, %lu failures\n", checks, failures);
	return failures != 0;
}
'''


def function(source, name):
    start = source.index("__s32 BPF_PROG(" + name + ",")
    brace = source.index("{", start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


class RandOrder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cc = shutil.which(os.environ.get("CC", "cc"))
        if not cls.cc:
            raise unittest.SkipTest("no C compiler")
        cls.temp = tempfile.TemporaryDirectory(prefix="nvme-gpu-rand-")
        cls.out = Path(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def build_and_run(self, name, source):
        path = self.out / (name + ".c")
        path.write_text(source.replace("NVME_GPU_CORE", str(HERE / "nvme_gpu_core.h")))
        subprocess.run([self.cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                        "-I" + str(KERNEL), str(path), "-o", str(self.out / name)], check=True)
        return subprocess.run([str(self.out / name)], text=True, capture_output=True, timeout=120)

    def test_pure_helpers_follow_the_baseline_schedule(self):
        result = self.build_and_run("helpers", HELPERS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"affine order: \d+ checks, 0 failures")

    def test_program_reads_the_rand_blocks(self):
        source = PROGRAM.read_text()
        globals_ = "".join(m.group(0) + "\n" for m in
                           re.finditer(r"^__u(?:32|64) \w+(?: = \d+)?;", source, re.M))
        self.assertIn("rand_seed", globals_)
        self.assertIn("rand_cache", globals_)
        program = PRELUDE + globals_ + function(source, "nvme_rand_build") + DRIVER
        result = self.build_and_run("program", program)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"nvme_rand_build: \d+ checks, 0 failures")

    def test_program_is_a_complete_nvme_plan(self):
        source = PROGRAM.read_text()
        self.assertIn('SEC("struct_ops/nvme_rand_build")', source)
        self.assertIn('SEC("struct_ops/nvme_rand_complete")', source)
        self.assertRegex(source, r"struct xdev_ext_nvme_mech_ops nvme_rand_ops = \{")
        self.assertIn("return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);",
                      source)
        makefile = (KERNEL / "tools/xdev_ext_mech/Makefile").read_text()
        self.assertRegex(makefile, r"BPF_NAMES :=.*\bnvme_rand\b")


if __name__ == "__main__":
    unittest.main()
