// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/delay.h>
#include <linux/error-injection.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/sysfs.h>
#include <linux/tracepoint.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/nsproxy.h>
#include <linux/xdev_ext_binding.h>
#include <linux/xdev_ext_mech.h>
#include <linux/math64.h>
#include <linux/nvme.h>
#include <linux/timekeeping.h>
#include <linux/nvme_xdev_ext_passthru.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/filter.h>
#include <net/sock.h>
#include <linux/namei.h>
#include "bpf_testmod.h"
#include "bpf_testmod_kfunc.h"
#include "../xdev_ext_binding_test.h"
#include "../xdev_ext_mech_test.h"
#include "../../../../../io_uring/xdev_ext_send_hook.h"
#include "../../../../../io_uring/xdev_ext_mech_core.h"

#define CREATE_TRACE_POINTS
#include "bpf_testmod-events.h"

#define CONNECT_TIMEOUT_SEC 1

typedef int (*func_proto_typedef)(long);
typedef int (*func_proto_typedef_nested1)(func_proto_typedef);
typedef int (*func_proto_typedef_nested2)(func_proto_typedef_nested1);

DEFINE_PER_CPU(int, bpf_testmod_ksym_percpu) = 123;
long bpf_testmod_test_struct_arg_result;
static DEFINE_MUTEX(sock_lock);
static struct socket *sock;

struct bpf_testmod_struct_arg_1 {
	int a;
};
struct bpf_testmod_struct_arg_2 {
	long a;
	long b;
};

struct bpf_testmod_struct_arg_3 {
	int a;
	int b[];
};

struct bpf_testmod_struct_arg_4 {
	u64 a;
	int b;
};

struct bpf_testmod_struct_arg_5 {
	char a;
	short b;
	int c;
	long d;
};

__bpf_hook_start();

noinline int
bpf_testmod_test_struct_arg_1(struct bpf_testmod_struct_arg_2 a, int b, int c) {
	bpf_testmod_test_struct_arg_result = a.a + a.b  + b + c;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_2(int a, struct bpf_testmod_struct_arg_2 b, int c) {
	bpf_testmod_test_struct_arg_result = a + b.a + b.b + c;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_3(int a, int b, struct bpf_testmod_struct_arg_2 c) {
	bpf_testmod_test_struct_arg_result = a + b + c.a + c.b;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_4(struct bpf_testmod_struct_arg_1 a, int b,
			      int c, int d, struct bpf_testmod_struct_arg_2 e) {
	bpf_testmod_test_struct_arg_result = a.a + b + c + d + e.a + e.b;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_5(void) {
	bpf_testmod_test_struct_arg_result = 1;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_6(struct bpf_testmod_struct_arg_3 *a) {
	bpf_testmod_test_struct_arg_result = a->b[0];
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_7(u64 a, void *b, short c, int d, void *e,
			      struct bpf_testmod_struct_arg_4 f)
{
	bpf_testmod_test_struct_arg_result = a + (long)b + c + d +
		(long)e + f.a + f.b;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_8(u64 a, void *b, short c, int d, void *e,
			      struct bpf_testmod_struct_arg_4 f, int g)
{
	bpf_testmod_test_struct_arg_result = a + (long)b + c + d +
		(long)e + f.a + f.b + g;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_9(u64 a, void *b, short c, int d, void *e, char f,
			      short g, struct bpf_testmod_struct_arg_5 h, long i)
{
	bpf_testmod_test_struct_arg_result = a + (long)b + c + d + (long)e +
		f + g + h.a + h.b + h.c + h.d + i;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_arg_ptr_to_struct(struct bpf_testmod_struct_arg_1 *a) {
	bpf_testmod_test_struct_arg_result = a->a;
	return bpf_testmod_test_struct_arg_result;
}

__weak noinline void bpf_testmod_looooooooooooooooooooooooooooooong_name(void)
{
}

__bpf_kfunc void
bpf_testmod_test_mod_kfunc(int i)
{
	*(int *)this_cpu_ptr(&bpf_testmod_ksym_percpu) = i;
}

__bpf_kfunc int bpf_iter_testmod_seq_new(struct bpf_iter_testmod_seq *it, s64 value, int cnt)
{
	it->cnt = cnt;

	if (cnt < 0)
		return -EINVAL;

	it->value = value;

	return 0;
}

__bpf_kfunc s64 *bpf_iter_testmod_seq_next(struct bpf_iter_testmod_seq* it)
{
	if (it->cnt <= 0)
		return NULL;

	it->cnt--;

	return &it->value;
}

__bpf_kfunc s64 bpf_iter_testmod_seq_value(int val, struct bpf_iter_testmod_seq* it__iter)
{
	if (it__iter->cnt < 0)
		return 0;

	return val + it__iter->value;
}

__bpf_kfunc void bpf_iter_testmod_seq_destroy(struct bpf_iter_testmod_seq *it)
{
	it->cnt = 0;
}

__bpf_kfunc void bpf_kfunc_common_test(void)
{
}

__bpf_kfunc void bpf_kfunc_dynptr_test(struct bpf_dynptr *ptr,
				       struct bpf_dynptr *ptr__nullable)
{
}

__bpf_kfunc struct sk_buff *bpf_kfunc_nested_acquire_nonzero_offset_test(struct sk_buff_head *ptr)
{
	return NULL;
}

__bpf_kfunc struct sk_buff *bpf_kfunc_nested_acquire_zero_offset_test(struct sock_common *ptr)
{
	return NULL;
}

__bpf_kfunc void bpf_kfunc_nested_release_test(struct sk_buff *ptr)
{
}

__bpf_kfunc void bpf_kfunc_trusted_vma_test(struct vm_area_struct *ptr)
{
}

__bpf_kfunc void bpf_kfunc_trusted_task_test(struct task_struct *ptr)
{
}

__bpf_kfunc void bpf_kfunc_trusted_num_test(int *ptr)
{
}

__bpf_kfunc void bpf_kfunc_rcu_task_test(struct task_struct *ptr)
{
}

__bpf_kfunc struct bpf_testmod_ctx *
bpf_testmod_ctx_create(int *err)
{
	struct bpf_testmod_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx) {
		*err = -ENOMEM;
		return NULL;
	}
	refcount_set(&ctx->usage, 1);

	return ctx;
}

static void testmod_free_cb(struct rcu_head *head)
{
	struct bpf_testmod_ctx *ctx;

	ctx = container_of(head, struct bpf_testmod_ctx, rcu);
	kfree(ctx);
}

__bpf_kfunc void bpf_testmod_ctx_release(struct bpf_testmod_ctx *ctx)
{
	if (!ctx)
		return;
	if (refcount_dec_and_test(&ctx->usage))
		call_rcu(&ctx->rcu, testmod_free_cb);
}

static struct bpf_testmod_ops3 *st_ops3;

static int bpf_testmod_test_3(void)
{
	return 0;
}

static int bpf_testmod_test_4(void)
{
	return 0;
}

static struct bpf_testmod_ops3 __bpf_testmod_ops3 = {
	.test_1 = bpf_testmod_test_3,
	.test_2 = bpf_testmod_test_4,
};

static void bpf_testmod_test_struct_ops3(void)
{
	if (st_ops3)
		st_ops3->test_1();
}

__bpf_kfunc void bpf_testmod_ops3_call_test_1(void)
{
	st_ops3->test_1();
}

__bpf_kfunc void bpf_testmod_ops3_call_test_2(void)
{
	st_ops3->test_2();
}

struct bpf_testmod_btf_type_tag_1 {
	int a;
};

struct bpf_testmod_btf_type_tag_2 {
	struct bpf_testmod_btf_type_tag_1 __user *p;
};

struct bpf_testmod_btf_type_tag_3 {
	struct bpf_testmod_btf_type_tag_1 __percpu *p;
};

noinline int
bpf_testmod_test_btf_type_tag_user_1(struct bpf_testmod_btf_type_tag_1 __user *arg) {
	BTF_TYPE_EMIT(func_proto_typedef);
	BTF_TYPE_EMIT(func_proto_typedef_nested1);
	BTF_TYPE_EMIT(func_proto_typedef_nested2);
	return arg->a;
}

noinline int
bpf_testmod_test_btf_type_tag_user_2(struct bpf_testmod_btf_type_tag_2 *arg) {
	return arg->p->a;
}

noinline int
bpf_testmod_test_btf_type_tag_percpu_1(struct bpf_testmod_btf_type_tag_1 __percpu *arg) {
	return arg->a;
}

noinline int
bpf_testmod_test_btf_type_tag_percpu_2(struct bpf_testmod_btf_type_tag_3 *arg) {
	return arg->p->a;
}

noinline int bpf_testmod_loop_test(int n)
{
	/* Make sum volatile, so smart compilers, such as clang, will not
	 * optimize the code by removing the loop.
	 */
	volatile int sum = 0;
	int i;

	/* the primary goal of this test is to test LBR. Create a lot of
	 * branches in the function, so we can catch it easily.
	 */
	for (i = 0; i < n; i++)
		sum += i;
	return sum;
}

__weak noinline struct file *bpf_testmod_return_ptr(int arg)
{
	static struct file f = {};

	switch (arg) {
	case 1: return (void *)EINVAL;		/* user addr */
	case 2: return (void *)0xcafe4a11;	/* user addr */
	case 3: return (void *)-EINVAL;		/* canonical, but invalid */
	case 4: return (void *)(1ull << 60);	/* non-canonical and invalid */
	case 5: return (void *)~(1ull << 30);	/* trigger extable */
	case 6: return &f;			/* valid addr */
	case 7: return (void *)((long)&f | 1);	/* kernel tricks */
#ifdef CONFIG_X86_64
	case 8: return (void *)VSYSCALL_ADDR;   /* vsyscall page address */
#endif
	default: return NULL;
	}
}

noinline int bpf_testmod_fentry_test1(int a)
{
	return a + 1;
}

noinline int bpf_testmod_fentry_test2(int a, u64 b)
{
	return a + b;
}

noinline int bpf_testmod_fentry_test3(char a, int b, u64 c)
{
	return a + b + c;
}

noinline int bpf_testmod_fentry_test7(u64 a, void *b, short c, int d,
				      void *e, char f, int g)
{
	return a + (long)b + c + d + (long)e + f + g;
}

noinline int bpf_testmod_fentry_test11(u64 a, void *b, short c, int d,
				       void *e, char f, int g,
				       unsigned int h, long i, __u64 j,
				       unsigned long k)
{
	return a + (long)b + c + d + (long)e + f + g + h + i + j + k;
}

int bpf_testmod_fentry_ok;

noinline ssize_t
bpf_testmod_test_read(struct file *file, struct kobject *kobj,
		      const struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_test_read_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};
	struct bpf_testmod_struct_arg_1 struct_arg1 = {10}, struct_arg1_2 = {-1};
	struct bpf_testmod_struct_arg_2 struct_arg2 = {2, 3};
	struct bpf_testmod_struct_arg_3 *struct_arg3;
	struct bpf_testmod_struct_arg_4 struct_arg4 = {21, 22};
	struct bpf_testmod_struct_arg_5 struct_arg5 = {23, 24, 25, 26};
	int i = 1;

	while (bpf_testmod_return_ptr(i))
		i++;

	(void)bpf_testmod_test_struct_arg_1(struct_arg2, 1, 4);
	(void)bpf_testmod_test_struct_arg_2(1, struct_arg2, 4);
	(void)bpf_testmod_test_struct_arg_3(1, 4, struct_arg2);
	(void)bpf_testmod_test_struct_arg_4(struct_arg1, 1, 2, 3, struct_arg2);
	(void)bpf_testmod_test_struct_arg_5();
	(void)bpf_testmod_test_struct_arg_7(16, (void *)17, 18, 19,
					    (void *)20, struct_arg4);
	(void)bpf_testmod_test_struct_arg_8(16, (void *)17, 18, 19,
					    (void *)20, struct_arg4, 23);
	(void)bpf_testmod_test_struct_arg_9(16, (void *)17, 18, 19, (void *)20,
					    21, 22, struct_arg5, 27);

	(void)bpf_testmod_test_arg_ptr_to_struct(&struct_arg1_2);

	(void)trace_bpf_testmod_test_raw_tp_null_tp(NULL);

	bpf_testmod_test_struct_ops3();

	struct_arg3 = kmalloc((sizeof(struct bpf_testmod_struct_arg_3) +
				sizeof(int)), GFP_KERNEL);
	if (struct_arg3 != NULL) {
		struct_arg3->b[0] = 1;
		(void)bpf_testmod_test_struct_arg_6(struct_arg3);
		kfree(struct_arg3);
	}

	/* This is always true. Use the check to make sure the compiler
	 * doesn't remove bpf_testmod_loop_test.
	 */
	if (bpf_testmod_loop_test(101) > 100)
		trace_bpf_testmod_test_read(current, &ctx);

	trace_bpf_testmod_test_nullable_bare_tp(NULL);

	/* Magic number to enable writable tp */
	if (len == 64) {
		struct bpf_testmod_test_writable_ctx writable = {
			.val = 1024,
		};
		trace_bpf_testmod_test_writable_bare_tp(&writable);
		if (writable.early_ret)
			return snprintf(buf, len, "%d\n", writable.val);
	}

	if (bpf_testmod_fentry_test1(1) != 2 ||
	    bpf_testmod_fentry_test2(2, 3) != 5 ||
	    bpf_testmod_fentry_test3(4, 5, 6) != 15 ||
	    bpf_testmod_fentry_test7(16, (void *)17, 18, 19, (void *)20,
			21, 22) != 133 ||
	    bpf_testmod_fentry_test11(16, (void *)17, 18, 19, (void *)20,
			21, 22, 23, 24, 25, 26) != 231)
		goto out;

	bpf_testmod_fentry_ok = 1;
out:
	return -EIO; /* always fail */
}
EXPORT_SYMBOL(bpf_testmod_test_read);
ALLOW_ERROR_INJECTION(bpf_testmod_test_read, ERRNO);

noinline ssize_t
bpf_testmod_test_write(struct file *file, struct kobject *kobj,
		      const struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_test_write_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};

	trace_bpf_testmod_test_write_bare_tp(current, &ctx);

	return -EIO; /* always fail */
}
EXPORT_SYMBOL(bpf_testmod_test_write);
ALLOW_ERROR_INJECTION(bpf_testmod_test_write, ERRNO);

noinline int bpf_fentry_shadow_test(int a)
{
	return a + 2;
}
EXPORT_SYMBOL_GPL(bpf_fentry_shadow_test);

__bpf_hook_end();

static struct bin_attribute bin_attr_bpf_testmod_file __ro_after_init = {
	.attr = { .name = "bpf_testmod", .mode = 0666, },
	.read = bpf_testmod_test_read,
	.write = bpf_testmod_test_write,
};

static DEFINE_MUTEX(bpf_testmod_xdev_ext_mutex);
static struct xdev_ext_binding_token bpf_testmod_xdev_ext_token;
static struct bpf_testmod_xdev_ext_binding bpf_testmod_xdev_ext_response;

static struct xdev_ext_binding_ctx_v2
bpf_testmod_xdev_ext_make_ctx(__u32 backend, __u32 flags, __u64 src_offset,
			 __u64 length)
{
	struct xdev_ext_binding_ctx_v2 ctx;

	switch (backend) {
	case XDEV_EXT_BINDING_BACKEND_SOCKET:
		ctx = xdev_ext_binding_make_socket_send_ctx(length);
		break;
	case XDEV_EXT_BINDING_BACKEND_AFXDP:
		if (flags & BPF_TESTMOD_XDEV_EXT_F_AFXDP_RX_CTX)
			ctx = xdev_ext_binding_make_afxdp_rx_ctx(src_offset, length, 0);
		else
			ctx = xdev_ext_send_hook_make_ctx(true, false, src_offset, length);
		break;
	case XDEV_EXT_BINDING_BACKEND_NVME:
		ctx = xdev_ext_binding_make_nvme_ctx(0, 0, length);
		break;
	case XDEV_EXT_BINDING_BACKEND_IAA:
		ctx = xdev_ext_binding_make_iaa_ctx(0, src_offset, 0, length);
		break;
	case XDEV_EXT_BINDING_BACKEND_GPU:
		ctx = xdev_ext_binding_make_gpu_ctx(XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
					       src_offset, 0, length);
		break;
	default: {
		ctx = xdev_ext_binding_make_socket_send_ctx(length);

		ctx.backend = backend;
		break;
	}
	}
	return ctx;
}

static int
bpf_testmod_xdev_ext_fake_native(struct bpf_testmod_xdev_ext_binding *response)
{
	response->native_calls++;
	return response->completion_result;
}

static int
bpf_testmod_xdev_ext_fake_afxdp_send(struct bpf_testmod_xdev_ext_binding *response,
				struct xdev_ext_binding_ctx_v2 *ctx,
				struct xdev_ext_binding_plan *plan)
{
	struct xdev_ext_send_hook_state hook = {};
	bool use_umem = response->flags &
		BPF_TESTMOD_XDEV_EXT_F_USE_IO_URING_UMEM;
	bool native_called = false;
	int policy_ret;
	int ret;

	ret = xdev_ext_send_hook_check_umem_compat(true, use_umem, false);
	if (ret)
		return ret;

	ret = xdev_ext_send_hook_dispatch_binding(&hook, ctx,
					     &bpf_testmod_xdev_ext_token, plan,
					     &policy_ret);
	response->policy_return_value = policy_ret;
	if (!ret) {
		if (response->flags & BPF_TESTMOD_XDEV_EXT_F_PRE_NATIVE_FAIL)
			ret = response->completion_result;
		else
			ret = xdev_ext_send_hook_call_native(&native_called,
							bpf_testmod_xdev_ext_fake_native(response));
	}

	policy_ret = xdev_ext_send_hook_finish_binding(&hook, ctx,
						  &bpf_testmod_xdev_ext_token,
						  native_called, ret, plan);
	if (native_called && hook.policy_dispatched)
		response->policy_return_value = policy_ret;
	return ret;
}

static ssize_t
bpf_testmod_xdev_ext_read(struct file *file, struct kobject *kobj,
		     const struct bin_attribute *bin_attr,
		     char *buf, loff_t off, size_t len)
{
	(void)file;
	(void)kobj;
	(void)bin_attr;
	if (off)
		return 0;
	if (len < sizeof(bpf_testmod_xdev_ext_response))
		return -EINVAL;

	mutex_lock(&bpf_testmod_xdev_ext_mutex);
	memcpy(buf, &bpf_testmod_xdev_ext_response,
	       sizeof(bpf_testmod_xdev_ext_response));
	mutex_unlock(&bpf_testmod_xdev_ext_mutex);
	return sizeof(bpf_testmod_xdev_ext_response);
}

static ssize_t
bpf_testmod_xdev_ext_write(struct file *file, struct kobject *kobj,
		      const struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_xdev_ext_binding response;
	struct xdev_ext_binding_ctx_v2 ctx;
	struct xdev_ext_binding_plan plan = {
		.action = BPF_TESTMOD_XDEV_EXT_PLAN_SENTINEL,
		.recipe = BPF_TESTMOD_XDEV_EXT_PLAN_SENTINEL,
		.next_stage = BPF_TESTMOD_XDEV_EXT_PLAN_SENTINEL,
		.profile = BPF_TESTMOD_XDEV_EXT_PLAN_SENTINEL,
	};
	struct xdev_ext_binding_token *token;
	struct xdev_ext_binding_plan *plan_arg;
	struct xdev_ext_binding_ctx_v2 *ctx_arg;

	(void)file;
	(void)kobj;
	(void)bin_attr;
	if (off || len != sizeof(response))
		return -EINVAL;
	memcpy(&response, buf, sizeof(response));
	response.return_value = 0;
	response.token_live = 0;
	response.reserved = 0;
	response.policy_return_value = 0;
	response.native_calls = 0;
#ifdef CONFIG_IO_URING_XDEV_EXT_BPF_POLICY
	response.config_enabled = 1;
#else
	response.config_enabled = 0;
#endif
	response.action = plan.action;
	response.recipe = plan.recipe;
	response.next_stage = plan.next_stage;
	response.profile = plan.profile;

	ctx = bpf_testmod_xdev_ext_make_ctx(response.backend, response.flags,
				       response.src_offset, response.length);
	ctx.event = response.command == BPF_TESTMOD_XDEV_EXT_COMPLETE ?
		XDEV_EXT_BINDING_EVENT_COMPLETE : XDEV_EXT_BINDING_EVENT_DISPATCH;
	if (response.command == BPF_TESTMOD_XDEV_EXT_COMPLETE)
		ctx.result = response.completion_result;
	if (response.flags & BPF_TESTMOD_XDEV_EXT_F_BAD_EVENT)
		ctx.event = XDEV_EXT_BINDING_EVENT_UNSPEC;
	ctx_arg = response.flags & BPF_TESTMOD_XDEV_EXT_F_NULL_CTX ? NULL : &ctx;
	token = response.flags & BPF_TESTMOD_XDEV_EXT_F_NULL_TOKEN ?
		NULL : &bpf_testmod_xdev_ext_token;
	plan_arg = response.flags & BPF_TESTMOD_XDEV_EXT_F_NULL_PLAN ? NULL : &plan;

	mutex_lock(&bpf_testmod_xdev_ext_mutex);
	switch (response.command) {
	case BPF_TESTMOD_XDEV_EXT_RESET:
		xdev_ext_binding_token_put(&bpf_testmod_xdev_ext_token);
		break;
	case BPF_TESTMOD_XDEV_EXT_DISPATCH:
		response.return_value =
			xdev_ext_binding_dispatch(ctx_arg, token, plan_arg);
		break;
	case BPF_TESTMOD_XDEV_EXT_COMPLETE:
		response.return_value =
			xdev_ext_binding_complete(ctx_arg, token, plan_arg);
		break;
	case BPF_TESTMOD_XDEV_EXT_TOKEN_PUT:
		xdev_ext_binding_token_put(&bpf_testmod_xdev_ext_token);
		break;
	case BPF_TESTMOD_XDEV_EXT_INJECT_OFF_TOKEN:
#ifdef CONFIG_IO_URING_XDEV_EXT_BPF_POLICY
		response.return_value = -EOPNOTSUPP;
#else
		if (bpf_testmod_xdev_ext_token.private)
			response.return_value = -EBUSY;
		else
			bpf_testmod_xdev_ext_token.private = (void *)1UL;
#endif
		break;
	case BPF_TESTMOD_XDEV_EXT_FAKE_AFXDP_SEND:
		if (response.backend != XDEV_EXT_BINDING_BACKEND_AFXDP) {
			response.return_value = -EINVAL;
			break;
		}
		response.return_value =
			bpf_testmod_xdev_ext_fake_afxdp_send(&response, &ctx, &plan);
		break;
	default:
		response.return_value = -EINVAL;
		break;
	}
	if (plan_arg) {
		response.action = plan.action;
		response.recipe = plan.recipe;
		response.next_stage = plan.next_stage;
		response.profile = plan.profile;
	}
	response.token_live = !!bpf_testmod_xdev_ext_token.private;
	bpf_testmod_xdev_ext_response = response;
	mutex_unlock(&bpf_testmod_xdev_ext_mutex);
	return len;
}

static struct bin_attribute bin_attr_bpf_testmod_xdev_ext_file __ro_after_init = {
	.attr = { .name = "bpf_testmod_xdev_ext_binding", .mode = 0600, },
	.read = bpf_testmod_xdev_ext_read,
	.write = bpf_testmod_xdev_ext_write,
};

static int register_bpf_testmod_xdev_ext(void)
{
	return sysfs_create_bin_file(kernel_kobj,
				     &bin_attr_bpf_testmod_xdev_ext_file);
}

static void unregister_bpf_testmod_xdev_ext(void)
{
	sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_xdev_ext_file);
	mutex_lock(&bpf_testmod_xdev_ext_mutex);
	xdev_ext_binding_token_put(&bpf_testmod_xdev_ext_token);
	mutex_unlock(&bpf_testmod_xdev_ext_mutex);
}

/*
 * Mechanism-layer test entry: each write runs one callback of the class
 * program published now through xdev_ext_mech_call_active() and reports the raw
 * program value, the scratch bytes, the hold intent and what the C rules of
 * io_uring/xdev_ext_mech_core.h make of them.  Frames are chunks of a synthetic
 * module-owned UMEM.
 */
static DEFINE_MUTEX(bpf_testmod_xdev_ext_mech_mutex);
static struct bpf_testmod_xdev_ext_mech bpf_testmod_xdev_ext_mech_io;

#ifdef CONFIG_XDEV_EXT_MECH
static u8 bpf_testmod_xdev_ext_mech_area[BPF_TESTMOD_XDEV_EXT_MECH_FRAMES *
				    BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE]
	__aligned(PAGE_SIZE);
static struct xdev_ext_mech_frame
	bpf_testmod_xdev_ext_mech_frames[BPF_TESTMOD_XDEV_EXT_MECH_FRAMES];

static_assert(BPF_TESTMOD_XDEV_EXT_MECH_FRAMES == XDEV_EXT_MECH_MAX_FRAMES);
static_assert(sizeof(struct xdev_ext_nvme_mech_info) <=
	      BPF_TESTMOD_XDEV_EXT_MECH_INFO_MAX &&
	      sizeof(struct xdev_ext_afxdp_mech_info) <=
	      BPF_TESTMOD_XDEV_EXT_MECH_INFO_MAX &&
	      sizeof(struct xdev_ext_ce_mech_info) <= BPF_TESTMOD_XDEV_EXT_MECH_INFO_MAX);

static int bpf_testmod_xdev_ext_mech_check(const struct bpf_testmod_xdev_ext_mech *io)
{
	u32 i;

	switch (io->command) {
	case BPF_TESTMOD_XDEV_EXT_MECH_FRAME_WRITE:
	case BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ:
		if (io->frame >= BPF_TESTMOD_XDEV_EXT_MECH_FRAMES ||
		    io->length > BPF_TESTMOD_XDEV_EXT_MECH_DATA_MAX ||
		    !xdev_ext_mech_span_in(io->offset, io->length,
				      BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE))
			return -EINVAL;
		return 0;
	case BPF_TESTMOD_XDEV_EXT_MECH_CALL:
	case BPF_TESTMOD_XDEV_EXT_MECH_MK3:
		break;
	default:
		return -EINVAL;
	}

	if (!xdev_ext_mech_class_known(io->class_id) ||
	    io->member < XDEV_EXT_MECH_MEMBER_PREPARE ||
	    io->member > XDEV_EXT_MECH_MEMBER_COMPLETE ||
	    io->nr_frames > BPF_TESTMOD_XDEV_EXT_MECH_FRAMES || !io->frame_size ||
	    io->frame_size > BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE ||
	    io->hdr_room > io->frame_size ||
	    io->info_size > BPF_TESTMOD_XDEV_EXT_MECH_INFO_MAX ||
	    (u64)io->desc_size * io->desc_cap >
	    BPF_TESTMOD_XDEV_EXT_MECH_SCRATCH_MAX ||
	    (u64)io->cqe_size * io->cqe_cap > BPF_TESTMOD_XDEV_EXT_MECH_CQE_MAX)
		return -EINVAL;
	for (i = 0; i < io->nr_frames; i++)
		if (!xdev_ext_mech_span_in(io->frames[i].data_off,
				      io->frames[i].data_len, io->frame_size))
			return -EINVAL;
	return 0;
}

/* base as the class C builds it; the mechanism fields per xdev_ext_mech_ctx. */
static struct xdev_ext_binding_ctx_v2
bpf_testmod_xdev_ext_mech_base(const struct bpf_testmod_xdev_ext_mech *io)
{
	bool to_device = io->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	struct xdev_ext_binding_ctx_v2 base;

	switch (io->class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:
		base = xdev_ext_binding_make_nvme_ctx(to_device, 0, io->bytes);
		break;
	case XDEV_EXT_MECH_CLASS_AFXDP:
		base = to_device ? xdev_ext_binding_make_afxdp_tx_ctx(io->bytes) :
			xdev_ext_binding_make_afxdp_rx_ctx(0, io->bytes, 0);
		break;
	default:
		base = xdev_ext_binding_make_gpu_ctx(io->direction, 0, 0, io->bytes);
		break;
	}
	base.request_id = io->batch_id;
	base.chain_id = io->session_id;
	base.src_offset = io->key;
	return base;
}

static void bpf_testmod_xdev_ext_mech_args(struct bpf_testmod_xdev_ext_mech *io,
				      const struct xdev_ext_binding_ctx_v2 *base,
				      struct xdev_ext_mech_call_args *a)
{
	bool build = io->member == XDEV_EXT_MECH_MEMBER_BUILD;
	bool complete = io->member == XDEV_EXT_MECH_MEMBER_COMPLETE;
	u32 i;

	for (i = 0; i < io->nr_frames; i++)
		bpf_testmod_xdev_ext_mech_frames[i] = (struct xdev_ext_mech_frame) {
			.kaddr = bpf_testmod_xdev_ext_mech_area +
				 (size_t)i * BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE,
			.umem_addr = io->frames[i].umem_addr,
			.index = i,
			.data_off = io->frames[i].data_off,
			.data_len = io->frames[i].data_len,
		};
	*a = (struct xdev_ext_mech_call_args) {
		.member = io->member,
		.callsite = io->callsite,
		.base = base,
		.batch_id = io->batch_id,
		.frames = bpf_testmod_xdev_ext_mech_frames,
		.nr_frames = io->nr_frames,
		.frame_size = io->frame_size,
		.hdr_room = io->hdr_room,
		.batch_frames = io->batch_frames,
		.info_size = io->info_size,
		.info = io->info,
		.scratch = build ? io->scratch : NULL,
		.desc_size = build ? io->desc_size : 0,
		.desc_cap = build ? io->desc_cap : 0,
		.cqe = complete ? io->cqe : NULL,
		.cqe_size = complete ? io->cqe_size : 0,
		.cqe_cap = complete ? io->cqe_cap : 0,
	};
}

/* What the NVMe class admits a built SQE against, from the info. */
static int
bpf_testmod_xdev_ext_mech_nvme_bounds(const struct bpf_testmod_xdev_ext_mech *io,
				 struct nvme_xdev_ext_mech_bounds *bounds)
{
	const struct xdev_ext_nvme_mech_info *info = (const void *)io->info;

	if (io->info_size != sizeof(*info) ||
	    io->desc_size != NVME_XDEV_EXT_SQE_SIZE || info->lba_shift > U8_MAX ||
	    io->bytes > U32_MAX)
		return -EINVAL;
	*bounds = (struct nvme_xdev_ext_mech_bounds) {
		.window_slba = info->window_slba,
		.window_nlb = info->window_nlb,
		.capacity_lbas = info->capacity_lbas,
		.data_len = io->bytes,
		.lba_shift = info->lba_shift,
		.write = io->direction == XDEV_EXT_MECH_DIR_TO_DEVICE,
	};
	return 0;
}

/* The NVMe class check of a built SQE. */
static int
bpf_testmod_xdev_ext_mech_nvme_validate(const struct bpf_testmod_xdev_ext_mech *io)
{
	struct nvme_xdev_ext_mech_bounds bounds;
	struct nvme_xdev_ext_decoded decoded;
	int ret;

	ret = bpf_testmod_xdev_ext_mech_nvme_bounds(io, &bounds);
	return ret ?: nvme_xdev_ext_mech_validate(io->scratch, &bounds, &decoded);
}

static void bpf_testmod_xdev_ext_mech_call(struct bpf_testmod_xdev_ext_mech *io)
{
	struct xdev_ext_binding_ctx_v2 base = bpf_testmod_xdev_ext_mech_base(io);
	const struct xdev_ext_mech_frame *rx = bpf_testmod_xdev_ext_mech_frames;
	struct bpf_testmod_xdev_ext_mech_out *out = &io->out;
	struct xdev_ext_mech_hold_intent hold = {};
	bool illegal = false, native, intent_ok;
	struct xdev_ext_mech_call_args args;
	s32 ret = 0;

	bpf_testmod_xdev_ext_mech_args(io, &base, &args);
	memset(io->scratch, 0, sizeof(io->scratch));
	out->return_value = xdev_ext_mech_call_active(io->class_id, &args, &ret,
						 &hold);
	out->prog_ret = ret;
	out->hold_key = hold.key;
	out->hold_pos = hold.pos;
	out->hold_count = hold.count;
	out->hold_span_off = hold.span_off;
	out->hold_span_len = hold.span_len;
	if (out->return_value)
		return;

	if (io->member == XDEV_EXT_MECH_MEMBER_BUILD) {
		out->slots_used = xdev_ext_mech_slots_used(io->scratch,
						      io->desc_size,
						      io->desc_cap);
		if (io->class_id == XDEV_EXT_MECH_CLASS_NVME)
			out->validate_ret =
				bpf_testmod_xdev_ext_mech_nvme_validate(io);
	}
	if (io->member == XDEV_EXT_MECH_MEMBER_COMPLETE &&
	    (io->callsite == XDEV_EXT_MECH_SITE_RX_GENERIC ||
	     io->callsite == XDEV_EXT_MECH_SITE_RX_NATIVE)) {
		intent_ok = hold.count && io->nr_frames &&
			    !xdev_ext_mech_hold_check(hold.pos, hold.count,
						 hold.span_off, hold.span_len,
						 rx->data_off, rx->data_len);
		out->resolved = xdev_ext_mech_rx_resolve(io->callsite, ret,
						    intent_ok, &illegal,
						    &native);
	} else {
		out->resolved = xdev_ext_mech_ret_resolve(io->class_id, io->member,
						     io->callsite, ret,
						     &illegal);
	}
	out->illegal = illegal;
}

/* C reference builds run by MK3; stays 0 unless the C arm ran. */
static u64 bpf_testmod_xdev_ext_mech_c_calls;

#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
/*
 * The MK3 C arm: line for line the build of progs/xdev_ext_mech_mk3.c.  It reads
 * the envelope directly where the program calls bpf_xdev_ext_info() and
 * bpf_xdev_ext_desc(), and makes the same checks those kfuncs make.
 */
static __s32 bpf_testmod_xdev_ext_mech_c_build(const struct xdev_ext_mech_ctx *ctx)
{
	struct xdev_ext_mech_call *call = xdev_ext_mech_call_of(ctx);
	const struct xdev_ext_nvme_mech_info *info;
	struct nvme_rw_command *sqe;
	u64 nlb, slots, rem;

	bpf_testmod_xdev_ext_mech_c_calls++;
	if (!call || !call->info || call->info_size != sizeof(*info))
		return XDEV_EXT_MECH_BUILD_ABORT;
	info = call->info;
	nlb = ctx->base.length >> info->lba_shift;
	if (!nlb || nlb > info->window_nlb)
		return XDEV_EXT_MECH_BUILD_ABORT;
	slots = div64_u64(info->window_nlb, nlb);
	if (!call->scratch || call->desc_size != sizeof(*sqe) ||
	    !call->desc_cap)
		return XDEV_EXT_MECH_BUILD_ABORT;
	sqe = (struct nvme_rw_command *)call->scratch;
	sqe->opcode = ctx->base.direction == XDEV_EXT_MECH_DIR_TO_DEVICE ?
		      nvme_cmd_write : nvme_cmd_read;
	div64_u64_rem(ctx->batch_id, slots, &rem);
	sqe->slba = cpu_to_le64(info->window_slba + rem * nlb);
	sqe->length = cpu_to_le16(nlb - 1);
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

static __s32 bpf_testmod_xdev_ext_mech_c_complete(const struct xdev_ext_mech_ctx *ctx)
{
	return XDEV_EXT_MECH_DONE;
}

static const struct xdev_ext_mech_c_ops bpf_testmod_xdev_ext_mech_c_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = bpf_testmod_xdev_ext_mech_c_build,
	.complete = bpf_testmod_xdev_ext_mech_c_complete,
};
#endif

/*
 * MK3 (plan section 6.2): io->iterations x (zero the scratch, run the NVMe
 * build, then the slot rule and the NVMe class validation), timed around
 * the loop only.  Arm E runs the published program; arm C runs the
 * reference ops through the same xdev_ext_mech_call_active() path.
 */
static int bpf_testmod_xdev_ext_mech_mk3(struct bpf_testmod_xdev_ext_mech *io)
{
	struct xdev_ext_binding_ctx_v2 base = bpf_testmod_xdev_ext_mech_base(io);
	struct bpf_testmod_xdev_ext_mech_out *out = &io->out;
	bool c_arm = io->arm == BPF_TESTMOD_XDEV_EXT_MECH_ARM_C;
	struct nvme_xdev_ext_mech_bounds bounds;
	struct nvme_xdev_ext_decoded decoded;
	struct xdev_ext_mech_call_args args;
	u64 i, start, c_calls;
	s32 ret = 0;
	int err;

	if (io->class_id != XDEV_EXT_MECH_CLASS_NVME ||
	    io->member != XDEV_EXT_MECH_MEMBER_BUILD || io->desc_cap != 1 ||
	    !io->iterations || io->iterations > BPF_TESTMOD_XDEV_EXT_MECH_MK3_MAX ||
	    io->arm > BPF_TESTMOD_XDEV_EXT_MECH_ARM_C)
		return -EINVAL;
	err = bpf_testmod_xdev_ext_mech_nvme_bounds(io, &bounds);
	if (err)
		return err;
	if (c_arm) {
#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
		err = xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME,
					 &bpf_testmod_xdev_ext_mech_c_ops);
		if (err)
			return err;
#else
		return -EOPNOTSUPP;
#endif
	}

	bpf_testmod_xdev_ext_mech_args(io, &base, &args);
	c_calls = bpf_testmod_xdev_ext_mech_c_calls;
	start = ktime_get_ns();
	for (i = 0; i < io->iterations; i++) {
		memset(io->scratch, 0, NVME_XDEV_EXT_SQE_SIZE);
		args.batch_id = i;
		err = xdev_ext_mech_call_active(XDEV_EXT_MECH_CLASS_NVME, &args, &ret,
					   NULL);
		if (!err && (ret != XDEV_EXT_MECH_BUILD_SUBMIT ||
			     xdev_ext_mech_slots_used(io->scratch, NVME_XDEV_EXT_SQE_SIZE,
						 1) != 1))
			err = -EPROTO;
		if (!err)
			err = nvme_xdev_ext_mech_validate(io->scratch, &bounds,
						     &decoded);
		if (err)
			break;
	}
	out->elapsed_ns = ktime_get_ns() - start;
	out->done = i;
	out->c_calls = bpf_testmod_xdev_ext_mech_c_calls - c_calls;
#ifdef CONFIG_XDEV_EXT_MECH_C_REFERENCE
	if (c_arm)
		xdev_ext_mech_set_c_ops(XDEV_EXT_MECH_CLASS_NVME, NULL);
#endif
	/* Each arm ran its own callbacks, every time. */
	if (!err && out->c_calls != (c_arm ? i : 0))
		err = -EPROTO;
	return err;
}

static int bpf_testmod_xdev_ext_mech_run(struct bpf_testmod_xdev_ext_mech *io)
{
	u8 *chunk = bpf_testmod_xdev_ext_mech_area;
	int ret;

	ret = bpf_testmod_xdev_ext_mech_check(io);
	if (ret)
		return ret;
	switch (io->command) {
	case BPF_TESTMOD_XDEV_EXT_MECH_FRAME_WRITE:
		chunk += (size_t)io->frame * BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE;
		memcpy(chunk + io->offset, io->data, io->length);
		return 0;
	case BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ:
		chunk += (size_t)io->frame * BPF_TESTMOD_XDEV_EXT_MECH_FRAME_SIZE;
		memcpy(io->data, chunk + io->offset, io->length);
		return 0;
	case BPF_TESTMOD_XDEV_EXT_MECH_MK3:
		return bpf_testmod_xdev_ext_mech_mk3(io);
	default:
		bpf_testmod_xdev_ext_mech_call(io);
		return io->out.return_value;
	}
}
#else
static int bpf_testmod_xdev_ext_mech_run(struct bpf_testmod_xdev_ext_mech *io)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_XDEV_EXT_MECH */

static ssize_t
bpf_testmod_xdev_ext_mech_read(struct file *file, struct kobject *kobj,
			  const struct bin_attribute *bin_attr,
			  char *buf, loff_t off, size_t len)
{
	(void)file;
	(void)kobj;
	(void)bin_attr;
	if (off)
		return 0;
	if (len < sizeof(bpf_testmod_xdev_ext_mech_io))
		return -EINVAL;

	mutex_lock(&bpf_testmod_xdev_ext_mech_mutex);
	memcpy(buf, &bpf_testmod_xdev_ext_mech_io, sizeof(bpf_testmod_xdev_ext_mech_io));
	mutex_unlock(&bpf_testmod_xdev_ext_mech_mutex);
	return sizeof(bpf_testmod_xdev_ext_mech_io);
}

static ssize_t
bpf_testmod_xdev_ext_mech_write(struct file *file, struct kobject *kobj,
			   const struct bin_attribute *bin_attr,
			   char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_xdev_ext_mech *io = &bpf_testmod_xdev_ext_mech_io;

	(void)file;
	(void)kobj;
	(void)bin_attr;
	if (off || len != sizeof(*io))
		return -EINVAL;

	mutex_lock(&bpf_testmod_xdev_ext_mech_mutex);
	memcpy(io, buf, sizeof(*io));
	memset(&io->out, 0, sizeof(io->out));
	if (IS_ENABLED(CONFIG_XDEV_EXT_MECH))
		io->out.config |= BPF_TESTMOD_XDEV_EXT_MECH_CFG_MECH;
	if (IS_ENABLED(CONFIG_XDEV_EXT_MECH_C_REFERENCE))
		io->out.config |= BPF_TESTMOD_XDEV_EXT_MECH_CFG_C_REFERENCE;
	io->out.return_value = bpf_testmod_xdev_ext_mech_run(io);
	mutex_unlock(&bpf_testmod_xdev_ext_mech_mutex);
	return len;
}

static struct bin_attribute bin_attr_bpf_testmod_xdev_ext_mech_file __ro_after_init = {
	.attr = { .name = "bpf_testmod_xdev_ext_mech", .mode = 0600, },
	.read = bpf_testmod_xdev_ext_mech_read,
	.write = bpf_testmod_xdev_ext_mech_write,
};

static int register_bpf_testmod_xdev_ext_mech(void)
{
	return sysfs_create_bin_file(kernel_kobj,
				     &bin_attr_bpf_testmod_xdev_ext_mech_file);
}

static void unregister_bpf_testmod_xdev_ext_mech(void)
{
	sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_xdev_ext_mech_file);
}

/* bpf_testmod_uprobe sysfs attribute is so far enabled for x86_64 only,
 * please see test_uretprobe_regs_change test
 */
#ifdef __x86_64__

static int
uprobe_ret_handler(struct uprobe_consumer *self, unsigned long func,
		   struct pt_regs *regs, __u64 *data)

{
	regs->ax  = 0x12345678deadbeef;
	regs->cx  = 0x87654321feebdaed;
	regs->r11 = (u64) -1;
	return true;
}

struct testmod_uprobe {
	struct path path;
	struct uprobe *uprobe;
	struct uprobe_consumer consumer;
};

static DEFINE_MUTEX(testmod_uprobe_mutex);

static struct testmod_uprobe uprobe = {
	.consumer.ret_handler = uprobe_ret_handler,
};

static int testmod_register_uprobe(loff_t offset)
{
	int err = -EBUSY;

	if (uprobe.uprobe)
		return -EBUSY;

	mutex_lock(&testmod_uprobe_mutex);

	if (uprobe.uprobe)
		goto out;

	err = kern_path("/proc/self/exe", LOOKUP_FOLLOW, &uprobe.path);
	if (err)
		goto out;

	uprobe.uprobe = uprobe_register(d_real_inode(uprobe.path.dentry),
					offset, 0, &uprobe.consumer);
	if (IS_ERR(uprobe.uprobe)) {
		err = PTR_ERR(uprobe.uprobe);
		path_put(&uprobe.path);
		uprobe.uprobe = NULL;
	}
out:
	mutex_unlock(&testmod_uprobe_mutex);
	return err;
}

static void testmod_unregister_uprobe(void)
{
	mutex_lock(&testmod_uprobe_mutex);

	if (uprobe.uprobe) {
		uprobe_unregister_nosync(uprobe.uprobe, &uprobe.consumer);
		uprobe_unregister_sync();
		path_put(&uprobe.path);
		uprobe.uprobe = NULL;
	}

	mutex_unlock(&testmod_uprobe_mutex);
}

static ssize_t
bpf_testmod_uprobe_write(struct file *file, struct kobject *kobj,
			 const struct bin_attribute *bin_attr,
			 char *buf, loff_t off, size_t len)
{
	unsigned long offset = 0;
	int err = 0;

	if (kstrtoul(buf, 0, &offset))
		return -EINVAL;

	if (offset)
		err = testmod_register_uprobe(offset);
	else
		testmod_unregister_uprobe();

	return err ?: strlen(buf);
}

static struct bin_attribute bin_attr_bpf_testmod_uprobe_file __ro_after_init = {
	.attr = { .name = "bpf_testmod_uprobe", .mode = 0666, },
	.write = bpf_testmod_uprobe_write,
};

static int register_bpf_testmod_uprobe(void)
{
	return sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_testmod_uprobe_file);
}

static void unregister_bpf_testmod_uprobe(void)
{
	testmod_unregister_uprobe();
	sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_uprobe_file);
}

#else
static int register_bpf_testmod_uprobe(void)
{
	return 0;
}

static void unregister_bpf_testmod_uprobe(void) { }
#endif

BTF_KFUNCS_START(bpf_testmod_common_kfunc_ids)
BTF_ID_FLAGS(func, bpf_iter_testmod_seq_new, KF_ITER_NEW)
BTF_ID_FLAGS(func, bpf_iter_testmod_seq_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_testmod_seq_destroy, KF_ITER_DESTROY)
BTF_ID_FLAGS(func, bpf_iter_testmod_seq_value)
BTF_ID_FLAGS(func, bpf_kfunc_common_test)
BTF_ID_FLAGS(func, bpf_kfunc_dynptr_test)
BTF_ID_FLAGS(func, bpf_kfunc_nested_acquire_nonzero_offset_test, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_kfunc_nested_acquire_zero_offset_test, KF_ACQUIRE)
BTF_ID_FLAGS(func, bpf_kfunc_nested_release_test, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_trusted_vma_test, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_kfunc_trusted_task_test, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_kfunc_trusted_num_test, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_kfunc_rcu_task_test, KF_RCU)
BTF_ID_FLAGS(func, bpf_testmod_ctx_create, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_testmod_ctx_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_testmod_ops3_call_test_1)
BTF_ID_FLAGS(func, bpf_testmod_ops3_call_test_2)
BTF_KFUNCS_END(bpf_testmod_common_kfunc_ids)

BTF_ID_LIST(bpf_testmod_dtor_ids)
BTF_ID(struct, bpf_testmod_ctx)
BTF_ID(func, bpf_testmod_ctx_release)

static const struct btf_kfunc_id_set bpf_testmod_common_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_testmod_common_kfunc_ids,
};

__bpf_kfunc u64 bpf_kfunc_call_test1(struct sock *sk, u32 a, u64 b, u32 c, u64 d)
{
	return a + b + c + d;
}

__bpf_kfunc int bpf_kfunc_call_test2(struct sock *sk, u32 a, u32 b)
{
	return a + b;
}

__bpf_kfunc struct sock *bpf_kfunc_call_test3(struct sock *sk)
{
	return sk;
}

__bpf_kfunc long noinline bpf_kfunc_call_test4(signed char a, short b, int c, long d)
{
	/* Provoke the compiler to assume that the caller has sign-extended a,
	 * b and c on platforms where this is required (e.g. s390x).
	 */
	return (long)a + (long)b + (long)c + d;
}

static struct prog_test_ref_kfunc prog_test_struct = {
	.a = 42,
	.b = 108,
	.next = &prog_test_struct,
	.cnt = REFCOUNT_INIT(1),
};

__bpf_kfunc struct prog_test_ref_kfunc *
bpf_kfunc_call_test_acquire(unsigned long *scalar_ptr)
{
	refcount_inc(&prog_test_struct.cnt);
	return &prog_test_struct;
}

__bpf_kfunc void bpf_kfunc_call_test_offset(struct prog_test_ref_kfunc *p)
{
	WARN_ON_ONCE(1);
}

__bpf_kfunc struct prog_test_member *
bpf_kfunc_call_memb_acquire(void)
{
	WARN_ON_ONCE(1);
	return NULL;
}

__bpf_kfunc void bpf_kfunc_call_memb1_release(struct prog_test_member1 *p)
{
	WARN_ON_ONCE(1);
}

static int *__bpf_kfunc_call_test_get_mem(struct prog_test_ref_kfunc *p, const int size)
{
	if (size > 2 * sizeof(int))
		return NULL;

	return (int *)p;
}

__bpf_kfunc int *bpf_kfunc_call_test_get_rdwr_mem(struct prog_test_ref_kfunc *p,
						  const int rdwr_buf_size)
{
	return __bpf_kfunc_call_test_get_mem(p, rdwr_buf_size);
}

__bpf_kfunc int *bpf_kfunc_call_test_get_rdonly_mem(struct prog_test_ref_kfunc *p,
						    const int rdonly_buf_size)
{
	return __bpf_kfunc_call_test_get_mem(p, rdonly_buf_size);
}

/* the next 2 ones can't be really used for testing expect to ensure
 * that the verifier rejects the call.
 * Acquire functions must return struct pointers, so these ones are
 * failing.
 */
__bpf_kfunc int *bpf_kfunc_call_test_acq_rdonly_mem(struct prog_test_ref_kfunc *p,
						    const int rdonly_buf_size)
{
	return __bpf_kfunc_call_test_get_mem(p, rdonly_buf_size);
}

__bpf_kfunc void bpf_kfunc_call_int_mem_release(int *p)
{
}

__bpf_kfunc void bpf_kfunc_call_test_pass_ctx(struct __sk_buff *skb)
{
}

__bpf_kfunc void bpf_kfunc_call_test_pass1(struct prog_test_pass1 *p)
{
}

__bpf_kfunc void bpf_kfunc_call_test_pass2(struct prog_test_pass2 *p)
{
}

__bpf_kfunc void bpf_kfunc_call_test_fail1(struct prog_test_fail1 *p)
{
}

__bpf_kfunc void bpf_kfunc_call_test_fail2(struct prog_test_fail2 *p)
{
}

__bpf_kfunc void bpf_kfunc_call_test_fail3(struct prog_test_fail3 *p)
{
}

__bpf_kfunc void bpf_kfunc_call_test_mem_len_pass1(void *mem, int mem__sz)
{
}

__bpf_kfunc void bpf_kfunc_call_test_mem_len_fail1(void *mem, int len)
{
}

__bpf_kfunc void bpf_kfunc_call_test_mem_len_fail2(u64 *mem, int len)
{
}

__bpf_kfunc void bpf_kfunc_call_test_ref(struct prog_test_ref_kfunc *p)
{
	/* p != NULL, but p->cnt could be 0 */
}

__bpf_kfunc void bpf_kfunc_call_test_destructive(void)
{
}

__bpf_kfunc static u32 bpf_kfunc_call_test_static_unused_arg(u32 arg, u32 unused)
{
	return arg;
}

__bpf_kfunc void bpf_kfunc_call_test_sleepable(void)
{
}

__bpf_kfunc int bpf_kfunc_init_sock(struct init_sock_args *args)
{
	int proto;
	int err;

	mutex_lock(&sock_lock);

	if (sock) {
		pr_err("%s called without releasing old sock", __func__);
		err = -EPERM;
		goto out;
	}

	switch (args->af) {
	case AF_INET:
	case AF_INET6:
		proto = args->type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
		break;
	case AF_UNIX:
		proto = PF_UNIX;
		break;
	default:
		pr_err("invalid address family %d\n", args->af);
		err = -EINVAL;
		goto out;
	}

	err = sock_create_kern(current->nsproxy->net_ns, args->af, args->type,
			       proto, &sock);

	if (!err)
		/* Set timeout for call to kernel_connect() to prevent it from hanging,
		 * and consider the connection attempt failed if it returns
		 * -EINPROGRESS.
		 */
		sock->sk->sk_sndtimeo = CONNECT_TIMEOUT_SEC * HZ;
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc void bpf_kfunc_close_sock(void)
{
	mutex_lock(&sock_lock);

	if (sock) {
		sock_release(sock);
		sock = NULL;
	}

	mutex_unlock(&sock_lock);
}

__bpf_kfunc int bpf_kfunc_call_kernel_connect(struct addr_args *args)
{
	int err;

	if (args->addrlen > sizeof(args->addr))
		return -EINVAL;

	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = kernel_connect(sock, (struct sockaddr *)&args->addr,
			     args->addrlen, 0);
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc int bpf_kfunc_call_kernel_bind(struct addr_args *args)
{
	int err;

	if (args->addrlen > sizeof(args->addr))
		return -EINVAL;

	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = kernel_bind(sock, (struct sockaddr *)&args->addr, args->addrlen);
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc int bpf_kfunc_call_kernel_listen(void)
{
	int err;

	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = kernel_listen(sock, 128);
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc int bpf_kfunc_call_kernel_sendmsg(struct sendmsg_args *args)
{
	struct msghdr msg = {
		.msg_name	= &args->addr.addr,
		.msg_namelen	= args->addr.addrlen,
	};
	struct kvec iov;
	int err;

	if (args->addr.addrlen > sizeof(args->addr.addr) ||
	    args->msglen > sizeof(args->msg))
		return -EINVAL;

	iov.iov_base = args->msg;
	iov.iov_len  = args->msglen;

	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = kernel_sendmsg(sock, &msg, &iov, 1, args->msglen);
	args->addr.addrlen = msg.msg_namelen;
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc int bpf_kfunc_call_sock_sendmsg(struct sendmsg_args *args)
{
	struct msghdr msg = {
		.msg_name	= &args->addr.addr,
		.msg_namelen	= args->addr.addrlen,
	};
	struct kvec iov;
	int err;

	if (args->addr.addrlen > sizeof(args->addr.addr) ||
	    args->msglen > sizeof(args->msg))
		return -EINVAL;

	iov.iov_base = args->msg;
	iov.iov_len  = args->msglen;

	iov_iter_kvec(&msg.msg_iter, ITER_SOURCE, &iov, 1, args->msglen);
	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = sock_sendmsg(sock, &msg);
	args->addr.addrlen = msg.msg_namelen;
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc int bpf_kfunc_call_kernel_getsockname(struct addr_args *args)
{
	int err;

	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = kernel_getsockname(sock, (struct sockaddr *)&args->addr);
	if (err < 0)
		goto out;

	args->addrlen = err;
	err = 0;
out:
	mutex_unlock(&sock_lock);

	return err;
}

__bpf_kfunc int bpf_kfunc_call_kernel_getpeername(struct addr_args *args)
{
	int err;

	mutex_lock(&sock_lock);

	if (!sock) {
		pr_err("%s called without initializing sock", __func__);
		err = -EPERM;
		goto out;
	}

	err = kernel_getpeername(sock, (struct sockaddr *)&args->addr);
	if (err < 0)
		goto out;

	args->addrlen = err;
	err = 0;
out:
	mutex_unlock(&sock_lock);

	return err;
}

static DEFINE_MUTEX(st_ops_mutex);
static struct bpf_testmod_st_ops *st_ops;

__bpf_kfunc int bpf_kfunc_st_ops_test_prologue(struct st_ops_args *args)
{
	int ret = -1;

	mutex_lock(&st_ops_mutex);
	if (st_ops && st_ops->test_prologue)
		ret = st_ops->test_prologue(args);
	mutex_unlock(&st_ops_mutex);

	return ret;
}

__bpf_kfunc int bpf_kfunc_st_ops_test_epilogue(struct st_ops_args *args)
{
	int ret = -1;

	mutex_lock(&st_ops_mutex);
	if (st_ops && st_ops->test_epilogue)
		ret = st_ops->test_epilogue(args);
	mutex_unlock(&st_ops_mutex);

	return ret;
}

__bpf_kfunc int bpf_kfunc_st_ops_test_pro_epilogue(struct st_ops_args *args)
{
	int ret = -1;

	mutex_lock(&st_ops_mutex);
	if (st_ops && st_ops->test_pro_epilogue)
		ret = st_ops->test_pro_epilogue(args);
	mutex_unlock(&st_ops_mutex);

	return ret;
}

__bpf_kfunc int bpf_kfunc_st_ops_inc10(struct st_ops_args *args)
{
	args->a += 10;
	return args->a;
}

BTF_KFUNCS_START(bpf_testmod_check_kfunc_ids)
BTF_ID_FLAGS(func, bpf_testmod_test_mod_kfunc)
BTF_ID_FLAGS(func, bpf_kfunc_call_test1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test3)
BTF_ID_FLAGS(func, bpf_kfunc_call_test4)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_mem_len_pass1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_mem_len_fail1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_mem_len_fail2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_memb_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_memb1_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_get_rdwr_mem, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_get_rdonly_mem, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_acq_rdonly_mem, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_int_mem_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_pass_ctx)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_pass1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_pass2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fail1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fail2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fail3)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_ref, KF_TRUSTED_ARGS | KF_RCU)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_destructive, KF_DESTRUCTIVE)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_static_unused_arg)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_offset)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_sleepable, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_init_sock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_close_sock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_kernel_connect, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_kernel_bind, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_kernel_listen, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_kernel_sendmsg, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_sock_sendmsg, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_kernel_getsockname, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_call_kernel_getpeername, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_st_ops_test_prologue, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_st_ops_test_epilogue, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_st_ops_test_pro_epilogue, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_kfunc_st_ops_inc10, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(bpf_testmod_check_kfunc_ids)

static int bpf_testmod_ops_init(struct btf *btf)
{
	return 0;
}

static bool bpf_testmod_ops_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_testmod_ops_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	if (member->offset == offsetof(struct bpf_testmod_ops, data) * 8) {
		/* For data fields, this function has to copy it and return
		 * 1 to indicate that the data has been handled by the
		 * struct_ops type, or the verifier will reject the map if
		 * the value of the data field is not zero.
		 */
		((struct bpf_testmod_ops *)kdata)->data = ((struct bpf_testmod_ops *)udata)->data;
		return 1;
	}
	return 0;
}

static const struct btf_kfunc_id_set bpf_testmod_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_testmod_check_kfunc_ids,
};

static const struct bpf_verifier_ops bpf_testmod_verifier_ops = {
	.get_func_proto	 = bpf_base_func_proto,
	.is_valid_access = bpf_testmod_ops_is_valid_access,
};

static const struct bpf_verifier_ops bpf_testmod_verifier_ops3 = {
	.is_valid_access = bpf_testmod_ops_is_valid_access,
};

static int bpf_dummy_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_testmod_ops *ops = kdata;

	if (ops->test_1)
		ops->test_1();
	/* Some test cases (ex. struct_ops_maybe_null) may not have test_2
	 * initialized, so we need to check for NULL.
	 */
	if (ops->test_2)
		ops->test_2(4, ops->data);

	return 0;
}

static void bpf_dummy_unreg(void *kdata, struct bpf_link *link)
{
}

static int bpf_testmod_test_1(void)
{
	return 0;
}

static void bpf_testmod_test_2(int a, int b)
{
}

static int bpf_testmod_tramp(int value)
{
	return 0;
}

static int bpf_testmod_ops__test_maybe_null(int dummy,
					    struct task_struct *task__nullable)
{
	return 0;
}

static int bpf_testmod_ops__test_refcounted(int dummy,
					    struct task_struct *task__ref)
{
	return 0;
}

static struct task_struct *
bpf_testmod_ops__test_return_ref_kptr(int dummy, struct task_struct *task__ref,
				      struct cgroup *cgrp)
{
	return NULL;
}

static struct bpf_testmod_ops __bpf_testmod_ops = {
	.test_1 = bpf_testmod_test_1,
	.test_2 = bpf_testmod_test_2,
	.test_maybe_null = bpf_testmod_ops__test_maybe_null,
	.test_refcounted = bpf_testmod_ops__test_refcounted,
	.test_return_ref_kptr = bpf_testmod_ops__test_return_ref_kptr,
};

struct bpf_struct_ops bpf_bpf_testmod_ops = {
	.verifier_ops = &bpf_testmod_verifier_ops,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = bpf_dummy_reg,
	.unreg = bpf_dummy_unreg,
	.cfi_stubs = &__bpf_testmod_ops,
	.name = "bpf_testmod_ops",
	.owner = THIS_MODULE,
};

static int bpf_dummy_reg2(void *kdata, struct bpf_link *link)
{
	struct bpf_testmod_ops2 *ops = kdata;

	ops->test_1();
	return 0;
}

static struct bpf_testmod_ops2 __bpf_testmod_ops2 = {
	.test_1 = bpf_testmod_test_1,
};

struct bpf_struct_ops bpf_testmod_ops2 = {
	.verifier_ops = &bpf_testmod_verifier_ops,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = bpf_dummy_reg2,
	.unreg = bpf_dummy_unreg,
	.cfi_stubs = &__bpf_testmod_ops2,
	.name = "bpf_testmod_ops2",
	.owner = THIS_MODULE,
};

static int st_ops3_reg(void *kdata, struct bpf_link *link)
{
	int err = 0;

	mutex_lock(&st_ops_mutex);
	if (st_ops3) {
		pr_err("st_ops has already been registered\n");
		err = -EEXIST;
		goto unlock;
	}
	st_ops3 = kdata;

unlock:
	mutex_unlock(&st_ops_mutex);
	return err;
}

static void st_ops3_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&st_ops_mutex);
	st_ops3 = NULL;
	mutex_unlock(&st_ops_mutex);
}

static void test_1_recursion_detected(struct bpf_prog *prog)
{
	struct bpf_prog_stats *stats;

	stats = this_cpu_ptr(prog->stats);
	printk("bpf_testmod: oh no, recursing into test_1, recursion_misses %llu",
	       u64_stats_read(&stats->misses));
}

static int st_ops3_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_testmod_ops3, test_1):
		prog->aux->priv_stack_requested = true;
		prog->aux->recursion_detected = test_1_recursion_detected;
		fallthrough;
	default:
		break;
	}
	return 0;
}

struct bpf_struct_ops bpf_testmod_ops3 = {
	.verifier_ops = &bpf_testmod_verifier_ops3,
	.init = bpf_testmod_ops_init,
	.init_member = bpf_testmod_ops_init_member,
	.reg = st_ops3_reg,
	.unreg = st_ops3_unreg,
	.check_member = st_ops3_check_member,
	.cfi_stubs = &__bpf_testmod_ops3,
	.name = "bpf_testmod_ops3",
	.owner = THIS_MODULE,
};

static int bpf_test_mod_st_ops__test_prologue(struct st_ops_args *args)
{
	return 0;
}

static int bpf_test_mod_st_ops__test_epilogue(struct st_ops_args *args)
{
	return 0;
}

static int bpf_test_mod_st_ops__test_pro_epilogue(struct st_ops_args *args)
{
	return 0;
}

static int bpf_cgroup_from_id_id;
static int bpf_cgroup_release_id;

static int st_ops_gen_prologue_with_kfunc(struct bpf_insn *insn_buf, bool direct_write,
					  const struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	/* r8 = r1; // r8 will be "u64 *ctx".
	 * r1 = 0;
	 * r0 = bpf_cgroup_from_id(r1);
	 * if r0 != 0 goto pc+5;
	 * r6 = r8[0]; // r6 will be "struct st_ops *args".
	 * r7 = r6->a;
	 * r7 += 1000;
	 * r6->a = r7;
	 * goto pc+2;
	 * r1 = r0;
	 * bpf_cgroup_release(r1);
	 * r1 = r8;
	 */
	*insn++ = BPF_MOV64_REG(BPF_REG_8, BPF_REG_1);
	*insn++ = BPF_MOV64_IMM(BPF_REG_1, 0);
	*insn++ = BPF_CALL_KFUNC(0, bpf_cgroup_from_id_id);
	*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 5);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_8, 0);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, offsetof(struct st_ops_args, a));
	*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 1000);
	*insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_7, offsetof(struct st_ops_args, a));
	*insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 2);
	*insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
	*insn++ = BPF_CALL_KFUNC(0, bpf_cgroup_release_id);
	*insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
	*insn++ = prog->insnsi[0];

	return insn - insn_buf;
}

static int st_ops_gen_epilogue_with_kfunc(struct bpf_insn *insn_buf, const struct bpf_prog *prog,
					  s16 ctx_stack_off)
{
	struct bpf_insn *insn = insn_buf;

	/* r1 = 0;
	 * r6 = 0;
	 * r0 = bpf_cgroup_from_id(r1);
	 * if r0 != 0 goto pc+6;
	 * r1 = stack[ctx_stack_off]; // r1 will be "u64 *ctx"
	 * r1 = r1[0]; // r1 will be "struct st_ops *args"
	 * r6 = r1->a;
	 * r6 += 10000;
	 * r1->a = r6;
	 * goto pc+2
	 * r1 = r0;
	 * bpf_cgroup_release(r1);
	 * r0 = r6;
	 * r0 *= 2;
	 * BPF_EXIT;
	 */
	*insn++ = BPF_MOV64_IMM(BPF_REG_1, 0);
	*insn++ = BPF_MOV64_IMM(BPF_REG_6, 0);
	*insn++ = BPF_CALL_KFUNC(0, bpf_cgroup_from_id_id);
	*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 6);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, ctx_stack_off);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, offsetof(struct st_ops_args, a));
	*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 10000);
	*insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offsetof(struct st_ops_args, a));
	*insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 2);
	*insn++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
	*insn++ = BPF_CALL_KFUNC(0, bpf_cgroup_release_id);
	*insn++ = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
	*insn++ = BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, 2);
	*insn++ = BPF_EXIT_INSN();

	return insn - insn_buf;
}

#define KFUNC_PRO_EPI_PREFIX "test_kfunc_"
static int st_ops_gen_prologue(struct bpf_insn *insn_buf, bool direct_write,
			       const struct bpf_prog *prog)
{
	struct bpf_insn *insn = insn_buf;

	if (strcmp(prog->aux->attach_func_name, "test_prologue") &&
	    strcmp(prog->aux->attach_func_name, "test_pro_epilogue"))
		return 0;

	if (!strncmp(prog->aux->name, KFUNC_PRO_EPI_PREFIX, strlen(KFUNC_PRO_EPI_PREFIX)))
		return st_ops_gen_prologue_with_kfunc(insn_buf, direct_write, prog);

	/* r6 = r1[0]; // r6 will be "struct st_ops *args". r1 is "u64 *ctx".
	 * r7 = r6->a;
	 * r7 += 1000;
	 * r6->a = r7;
	 */
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, offsetof(struct st_ops_args, a));
	*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 1000);
	*insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_7, offsetof(struct st_ops_args, a));
	*insn++ = prog->insnsi[0];

	return insn - insn_buf;
}

static int st_ops_gen_epilogue(struct bpf_insn *insn_buf, const struct bpf_prog *prog,
			       s16 ctx_stack_off)
{
	struct bpf_insn *insn = insn_buf;

	if (strcmp(prog->aux->attach_func_name, "test_epilogue") &&
	    strcmp(prog->aux->attach_func_name, "test_pro_epilogue"))
		return 0;

	if (!strncmp(prog->aux->name, KFUNC_PRO_EPI_PREFIX, strlen(KFUNC_PRO_EPI_PREFIX)))
		return st_ops_gen_epilogue_with_kfunc(insn_buf, prog, ctx_stack_off);

	/* r1 = stack[ctx_stack_off]; // r1 will be "u64 *ctx"
	 * r1 = r1[0]; // r1 will be "struct st_ops *args"
	 * r6 = r1->a;
	 * r6 += 10000;
	 * r1->a = r6;
	 * r0 = r6;
	 * r0 *= 2;
	 * BPF_EXIT;
	 */
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, ctx_stack_off);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
	*insn++ = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, offsetof(struct st_ops_args, a));
	*insn++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 10000);
	*insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offsetof(struct st_ops_args, a));
	*insn++ = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
	*insn++ = BPF_ALU64_IMM(BPF_MUL, BPF_REG_0, 2);
	*insn++ = BPF_EXIT_INSN();

	return insn - insn_buf;
}

static int st_ops_btf_struct_access(struct bpf_verifier_log *log,
				    const struct bpf_reg_state *reg,
				    int off, int size)
{
	if (off < 0 || off + size > sizeof(struct st_ops_args))
		return -EACCES;
	return 0;
}

static const struct bpf_verifier_ops st_ops_verifier_ops = {
	.is_valid_access = bpf_testmod_ops_is_valid_access,
	.btf_struct_access = st_ops_btf_struct_access,
	.gen_prologue = st_ops_gen_prologue,
	.gen_epilogue = st_ops_gen_epilogue,
	.get_func_proto = bpf_base_func_proto,
};

static struct bpf_testmod_st_ops st_ops_cfi_stubs = {
	.test_prologue = bpf_test_mod_st_ops__test_prologue,
	.test_epilogue = bpf_test_mod_st_ops__test_epilogue,
	.test_pro_epilogue = bpf_test_mod_st_ops__test_pro_epilogue,
};

static int st_ops_reg(void *kdata, struct bpf_link *link)
{
	int err = 0;

	mutex_lock(&st_ops_mutex);
	if (st_ops) {
		pr_err("st_ops has already been registered\n");
		err = -EEXIST;
		goto unlock;
	}
	st_ops = kdata;

unlock:
	mutex_unlock(&st_ops_mutex);
	return err;
}

static void st_ops_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&st_ops_mutex);
	st_ops = NULL;
	mutex_unlock(&st_ops_mutex);
}

static int st_ops_init(struct btf *btf)
{
	struct btf *kfunc_btf;

	bpf_cgroup_from_id_id = bpf_find_btf_id("bpf_cgroup_from_id", BTF_KIND_FUNC, &kfunc_btf);
	bpf_cgroup_release_id = bpf_find_btf_id("bpf_cgroup_release", BTF_KIND_FUNC, &kfunc_btf);
	if (bpf_cgroup_from_id_id < 0 || bpf_cgroup_release_id < 0)
		return -EINVAL;

	return 0;
}

static int st_ops_init_member(const struct btf_type *t,
			      const struct btf_member *member,
			      void *kdata, const void *udata)
{
	return 0;
}

static struct bpf_struct_ops testmod_st_ops = {
	.verifier_ops = &st_ops_verifier_ops,
	.init = st_ops_init,
	.init_member = st_ops_init_member,
	.reg = st_ops_reg,
	.unreg = st_ops_unreg,
	.cfi_stubs = &st_ops_cfi_stubs,
	.name = "bpf_testmod_st_ops",
	.owner = THIS_MODULE,
};

extern int bpf_fentry_test1(int a);

static int bpf_testmod_init(void)
{
	const struct btf_id_dtor_kfunc bpf_testmod_dtors[] = {
		{
			.btf_id		= bpf_testmod_dtor_ids[0],
			.kfunc_btf_id	= bpf_testmod_dtor_ids[1]
		},
	};
	void **tramp;
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_testmod_common_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_testmod_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_testmod_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_testmod_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_testmod_kfunc_set);
	ret = ret ?: register_bpf_struct_ops(&bpf_bpf_testmod_ops, bpf_testmod_ops);
	ret = ret ?: register_bpf_struct_ops(&bpf_testmod_ops2, bpf_testmod_ops2);
	ret = ret ?: register_bpf_struct_ops(&bpf_testmod_ops3, bpf_testmod_ops3);
	ret = ret ?: register_bpf_struct_ops(&testmod_st_ops, bpf_testmod_st_ops);
	ret = ret ?: register_btf_id_dtor_kfuncs(bpf_testmod_dtors,
						 ARRAY_SIZE(bpf_testmod_dtors),
						 THIS_MODULE);
	if (ret < 0)
		return ret;
	if (bpf_fentry_test1(0) < 0)
		return -EINVAL;
	sock = NULL;
	mutex_init(&sock_lock);
	ret = sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	if (ret < 0)
		return ret;
	ret = register_bpf_testmod_uprobe();
	if (ret < 0)
		goto err_remove_testmod_file;
	ret = register_bpf_testmod_xdev_ext();
	if (ret < 0)
		goto err_unregister_uprobe;
	ret = register_bpf_testmod_xdev_ext_mech();
	if (ret < 0)
		goto err_unregister_xdev_ext;

	/* Ensure nothing is between tramp_1..tramp_40 */
	BUILD_BUG_ON(offsetof(struct bpf_testmod_ops, tramp_1) + 40 * sizeof(long) !=
		     offsetofend(struct bpf_testmod_ops, tramp_40));
	tramp = (void **)&__bpf_testmod_ops.tramp_1;
	while (tramp <= (void **)&__bpf_testmod_ops.tramp_40)
		*tramp++ = bpf_testmod_tramp;

	return 0;

err_unregister_xdev_ext:
	unregister_bpf_testmod_xdev_ext();
err_unregister_uprobe:
	unregister_bpf_testmod_uprobe();
err_remove_testmod_file:
	sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	return ret;
}

static void bpf_testmod_exit(void)
{
        /* Need to wait for all references to be dropped because
         * bpf_kfunc_call_test_release() which currently resides in kernel can
         * be called after bpf_testmod is unloaded. Once release function is
         * moved into the module this wait can be removed.
         */
	while (refcount_read(&prog_test_struct.cnt) > 1)
		msleep(20);

	bpf_kfunc_close_sock();
	unregister_bpf_testmod_xdev_ext_mech();
	unregister_bpf_testmod_xdev_ext();
	sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
	unregister_bpf_testmod_uprobe();
}

module_init(bpf_testmod_init);
module_exit(bpf_testmod_exit);

MODULE_AUTHOR("Andrii Nakryiko");
MODULE_DESCRIPTION("BPF selftests module");
MODULE_LICENSE("Dual BSD/GPL");
