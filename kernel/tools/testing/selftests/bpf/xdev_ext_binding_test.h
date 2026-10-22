/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_SELFTEST_XDEV_EXT_BINDING_TEST_H
#define __BPF_SELFTEST_XDEV_EXT_BINDING_TEST_H

#include <linux/types.h>

#define BPF_TESTMOD_XDEV_EXT_BINDING_FILE "/sys/kernel/bpf_testmod_xdev_ext_binding"
#define BPF_TESTMOD_XDEV_EXT_PLAN_SENTINEL ((__u32)~0U)

enum bpf_testmod_xdev_ext_command {
	BPF_TESTMOD_XDEV_EXT_RESET,
	BPF_TESTMOD_XDEV_EXT_DISPATCH,
	BPF_TESTMOD_XDEV_EXT_COMPLETE,
	BPF_TESTMOD_XDEV_EXT_TOKEN_PUT,
	BPF_TESTMOD_XDEV_EXT_INJECT_OFF_TOKEN,
	BPF_TESTMOD_XDEV_EXT_FAKE_AFXDP_SEND,
};

#define BPF_TESTMOD_XDEV_EXT_F_NULL_CTX	0x01U
#define BPF_TESTMOD_XDEV_EXT_F_NULL_TOKEN	0x02U
#define BPF_TESTMOD_XDEV_EXT_F_NULL_PLAN	0x04U
#define BPF_TESTMOD_XDEV_EXT_F_BAD_EVENT	0x08U
#define BPF_TESTMOD_XDEV_EXT_F_PRE_NATIVE_FAIL	0x10U
#define BPF_TESTMOD_XDEV_EXT_F_USE_IO_URING_UMEM	0x20U
#define BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX	0x40U

/* Binary request/response shared only by test_progs and bpf_testmod. */
struct bpf_testmod_xdev_ext_binding {
	__u32 command;
	__u32 backend;
	__u32 flags;
	__s32 completion_result;

	__s32 return_value;
	__u32 token_live;
	__u32 config_enabled;
	__u32 reserved;

	__u32 action;
	__u32 recipe;
	__u32 next_stage;
	__u32 profile;

	__s32 policy_return_value;
	__u32 native_calls;
	__u64 src_offset;
	__u64 length;
};

#endif /* __BPF_SELFTEST_XDEV_EXT_BINDING_TEST_H */
