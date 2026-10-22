/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_BPF_RAW_H
#define XDEV_EXT_BPF_RAW_H

/*
 * The BPF map, program and link commands the LD_PRELOAD front end needs,
 * issued through syscall(SYS_bpf) alone.  libbpf is never linked into a
 * preloaded process: it would add its own symbols, allocations and logging
 * callbacks to an application that did not ask for them.
 *
 * Each helper returns the new fd, or 0, on success and -errno on failure; a
 * failure leaves errno set.  Malformed arguments are refused before the
 * system call.  Unit tests define XDEV_EXT_BPF_RAW_SYSCALL before including this
 * header to inspect every bpf_attr without CAP_BPF.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>

#ifndef XDEV_EXT_BPF_RAW_SYSCALL
#define XDEV_EXT_BPF_RAW_SYSCALL syscall
#endif

static inline uint64_t xdev_ext_bpf_raw_ptr(const void *pointer)
{
	return (uint64_t)(uintptr_t)pointer;
}

/* The whole zeroed union is passed: the kernel accepts a larger attr as long
 * as every byte it does not know is zero. */
static inline int xdev_ext_bpf_raw_call(int cmd, union bpf_attr *attr)
{
	long ret = XDEV_EXT_BPF_RAW_SYSCALL(SYS_bpf, cmd, attr,
				       (unsigned int)sizeof(*attr));

	if (ret < 0)
		return errno ? -errno : -EIO;
	return (int)ret;
}

/* Object names longer than BPF_OBJ_NAME_LEN - 1 are cut; attr is zeroed, so
 * the copy stays terminated. */
static inline void xdev_ext_bpf_raw_name(char name_field[BPF_OBJ_NAME_LEN],
				    const char *name)
{
	if (name)
		memcpy(name_field, name, strnlen(name, BPF_OBJ_NAME_LEN - 1));
}

static inline int xdev_ext_bpf_raw_map_create(enum bpf_map_type type,
					 uint32_t key_size,
					 uint32_t value_size,
					 uint32_t max_entries,
					 const char *name)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	xdev_ext_bpf_raw_name(attr.map_name, name);
	return xdev_ext_bpf_raw_call(BPF_MAP_CREATE, &attr);
}

static inline int xdev_ext_bpf_raw_map_update(int map_fd, const void *key,
					 const void *value, uint64_t flags)
{
	union bpf_attr attr;

	if (map_fd < 0 || !key || !value)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = xdev_ext_bpf_raw_ptr(key);
	attr.value = xdev_ext_bpf_raw_ptr(value);
	attr.flags = flags;
	return xdev_ext_bpf_raw_call(BPF_MAP_UPDATE_ELEM, &attr);
}

/* A log level reaches the kernel only together with a log buffer; the
 * kernel refuses one without the other. */
static inline int xdev_ext_bpf_raw_prog_load(enum bpf_prog_type type,
					const char *name,
					const struct bpf_insn *insns,
					size_t insn_cnt, const char *license,
					char *log_buf, uint32_t log_size,
					uint32_t log_level)
{
	union bpf_attr attr;

	if (!insns || !insn_cnt || insn_cnt > UINT32_MAX || !license)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = type;
	attr.insns = xdev_ext_bpf_raw_ptr(insns);
	attr.insn_cnt = (uint32_t)insn_cnt;
	attr.license = xdev_ext_bpf_raw_ptr(license);
	if (log_buf && log_size) {
		log_buf[0] = '\0';
		attr.log_buf = xdev_ext_bpf_raw_ptr(log_buf);
		attr.log_size = log_size;
		attr.log_level = log_level;
	}
	xdev_ext_bpf_raw_name(attr.prog_name, name);
	return xdev_ext_bpf_raw_call(BPF_PROG_LOAD, &attr);
}

/* One run of @prog_fd over a copy of @data; *retval is the program's
 * return value. */
static inline int xdev_ext_bpf_raw_prog_test_run(int prog_fd, const void *data,
					    uint32_t size, uint32_t *retval)
{
	union bpf_attr attr;
	int ret;

	if (prog_fd < 0 || !data || !size || !retval)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = (uint32_t)prog_fd;
	attr.test.data_in = xdev_ext_bpf_raw_ptr(data);
	attr.test.data_size_in = size;
	attr.test.repeat = 1;
	ret = xdev_ext_bpf_raw_call(BPF_PROG_TEST_RUN, &attr);
	if (ret < 0)
		return ret;
	*retval = attr.test.retval;
	return 0;
}

/* @xdp_flags is XDP_FLAGS_SKB_MODE or XDP_FLAGS_DRV_MODE.  Unlike a netlink
 * attach, the link goes away with its last fd, and the kernel refuses it
 * while another XDP program is attached. */
static inline int xdev_ext_bpf_raw_link_create_xdp(int prog_fd, int ifindex,
					      uint32_t xdp_flags)
{
	union bpf_attr attr;

	if (prog_fd < 0 || ifindex <= 0)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = (uint32_t)prog_fd;
	attr.link_create.target_ifindex = (uint32_t)ifindex;
	attr.link_create.attach_type = BPF_XDP;
	attr.link_create.flags = xdp_flags;
	return xdev_ext_bpf_raw_call(BPF_LINK_CREATE, &attr);
}

/* Swap the link's program.  With @old_prog_fd >= 0 the swap happens only if
 * the link still runs that program (BPF_F_REPLACE). */
static inline int xdev_ext_bpf_raw_link_update(int link_fd, int new_prog_fd,
					  int old_prog_fd)
{
	union bpf_attr attr;

	if (link_fd < 0 || new_prog_fd < 0)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.link_update.link_fd = (uint32_t)link_fd;
	attr.link_update.new_prog_fd = (uint32_t)new_prog_fd;
	if (old_prog_fd >= 0) {
		attr.link_update.flags = BPF_F_REPLACE;
		attr.link_update.old_prog_fd = (uint32_t)old_prog_fd;
	}
	return xdev_ext_bpf_raw_call(BPF_LINK_UPDATE, &attr);
}

/* Detach now, even while a forked child still holds a copy of @link_fd. */
static inline int xdev_ext_bpf_raw_link_detach(int link_fd)
{
	union bpf_attr attr;

	if (link_fd < 0)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.link_detach.link_fd = (uint32_t)link_fd;
	return xdev_ext_bpf_raw_call(BPF_LINK_DETACH, &attr);
}

#endif /* XDEV_EXT_BPF_RAW_H */
