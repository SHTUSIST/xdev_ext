/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_SELFTEST_XDEV_EXT_MECH_TEST_H
#define __BPF_SELFTEST_XDEV_EXT_MECH_TEST_H

#include <linux/types.h>

/*
 * Shared by test_progs, bpf_testmod and the progs/xdev_ext_mech_*.c programs.
 * bpf_testmod drives one mechanism callback per write through
 * xdev_ext_mech_call_active(), with synthetic frames in a module-owned area of
 * BPF_TESTMOD_XDEV_EXT_MECH_FRAMES chunks; a read returns the last response.
 */
#define BPF_TESTMOD_XDEV_EXT_MECH_FILE	"/sys/kernel/bpf_testmod_xdev_ext_mech"
#define BPF_TESTMOD_XDEV_EXT_MECH_FRAMES	32	/* XDEV_EXT_MECH_MAX_FRAMES */
#define BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE	4096
#define BPF_TESTMOD_XDEV_EXT_MECH_INFO_MAX	576
#define BPF_TESTMOD_XDEV_EXT_MECH_CQE_MAX	256
#define BPF_TESTMOD_XDEV_EXT_MECH_SCRATCH_MAX 768
#define BPF_TESTMOD_XDEV_EXT_MECH_DATA_MAX	1024

enum bpf_testmod_xdev_ext_mech_command {
	BPF_TESTMOD_XDEV_EXT_MECH_FRAME_WRITE,	/* data -> chunk frame at offset */
	BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ,	/* chunk frame at offset -> data */
	BPF_TESTMOD_XDEV_EXT_MECH_CALL,		/* one callback */
	BPF_TESTMOD_XDEV_EXT_MECH_MK3,		/* timed NVMe build + validate loop */
};

/* MK3 arms: the published program, or C reference ops on the same path. */
enum bpf_testmod_xdev_ext_mech_arm {
	BPF_TESTMOD_XDEV_EXT_MECH_ARM_E,
	BPF_TESTMOD_XDEV_EXT_MECH_ARM_C,		/* CONFIG_XDEV_EXT_MECH_C_REFERENCE */
};

#define BPF_TESTMOD_XDEV_EXT_MECH_MK3_MAX	10000000ULL

#define BPF_TESTMOD_XDEV_EXT_MECH_CFG_MECH		0x1U
#define BPF_TESTMOD_XDEV_EXT_MECH_CFG_C_REFERENCE	0x2U

/*
 * What a positive program's build or complete saw of frame 0 through the
 * frame and CRC kfuncs; a .bss variable the test reads back.
 */
struct xdev_ext_mech_obs {
	__u64 calls;
	__u64 head;		/* first 8 data bytes, little endian */
	__u32 head_crc;		/* bpf_xdev_ext_crc32c() of a stack copy of them */
	__u32 data_crc;		/* bpf_xdev_ext_frame_crc32c() of the data span */
};

/* Batch frame i is chunk i of the module area. */
struct bpf_testmod_xdev_ext_mech_frame {
	__u64 umem_addr;
	__u32 data_off;
	__u32 data_len;
};

/* Filled by every write; a read returns it with the request. */
struct bpf_testmod_xdev_ext_mech_out {
	__s32 return_value;		/* command errno or xdev_ext_mech_call_active() */
	__s32 prog_ret;			/* raw program value */
	__s32 resolved;			/* what C acts on, per xdev_ext_mech_core.h */
	__u32 illegal;			/* resolved replaced an illegal value */
	__s32 slots_used;		/* build: xdev_ext_mech_slots_used() */
	__s32 validate_ret;		/* NVMe build: nvme_xdev_ext_mech_validate() */
	__u32 config;			/* BPF_TESTMOD_XDEV_EXT_MECH_CFG_* */
	__u32 reserved;
	__u64 hold_key;			/* intent recorded by bpf_xdev_ext_afxdp_hold() */
	__u32 hold_pos;
	__u32 hold_count;
	__u32 hold_span_off;
	__u32 hold_span_len;
	__u64 elapsed_ns;		/* MK3: ktime_get_ns() around the loop */
	__u64 done;			/* MK3: iterations completed */
	__u64 c_calls;			/* MK3: C reference builds run */
};

/* Binary request/response shared only by test_progs and bpf_testmod. */
struct bpf_testmod_xdev_ext_mech {
	__u32 command;
	__u32 class_id;			/* enum xdev_ext_mech_class */
	__u32 member;			/* enum xdev_ext_mech_member */
	__u32 callsite;			/* enum xdev_ext_mech_callsite */

	__u32 direction;		/* enum xdev_ext_mech_dir */
	__u32 nr_frames;
	__u32 frame_size;
	__u32 hdr_room;

	__u32 info_size;
	__u32 desc_size;		/* build */
	__u32 desc_cap;
	__u32 cqe_size;			/* complete */

	__u32 cqe_cap;
	__u32 frame;			/* FRAME_*: chunk */
	__u32 offset;			/* FRAME_*: byte in the chunk */
	__u32 length;			/* FRAME_*: bytes */

	__u64 batch_id;			/* ctx.batch_id, base.request_id */
	__u64 session_id;		/* base.chain_id */
	__u64 key;			/* base.src_offset */
	__u64 bytes;			/* base.length */
	__u32 arm;			/* MK3: enum bpf_testmod_xdev_ext_mech_arm */
	__u32 batch_frames;		/* CALL: frames per batch, the RX hold count */
	__u64 iterations;		/* MK3 */

	struct bpf_testmod_xdev_ext_mech_out out;

	struct bpf_testmod_xdev_ext_mech_frame frames[BPF_TESTMOD_XDEV_EXT_MECH_FRAMES];
	__u8 info[BPF_TESTMOD_XDEV_EXT_MECH_INFO_MAX];
	__u8 cqe[BPF_TESTMOD_XDEV_EXT_MECH_CQE_MAX];
	__u8 scratch[BPF_TESTMOD_XDEV_EXT_MECH_SCRATCH_MAX];
	__u8 data[BPF_TESTMOD_XDEV_EXT_MECH_DATA_MAX];
};

/* One sysfs write moves at most a page; info is read as a u64 structure. */
_Static_assert(sizeof(struct bpf_testmod_xdev_ext_mech) <= 4096,
	       "bpf_testmod_xdev_ext_mech must fit one sysfs write");
_Static_assert(__builtin_offsetof(struct bpf_testmod_xdev_ext_mech, info) % 8 == 0,
	       "class info must be u64 aligned");
_Static_assert(__builtin_offsetof(struct bpf_testmod_xdev_ext_mech, cqe) % 8 == 0,
	       "completion copies must be u64 aligned");

#endif /* __BPF_SELFTEST_XDEV_EXT_MECH_TEST_H */
