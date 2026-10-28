/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_REFERENCE_POLICY_CORE_H
#define XDEV_EXT_REFERENCE_POLICY_CORE_H

#include <errno.h>
#include <stddef.h>
#include <stdio.h>

#include "xdev_ext_reference_policy_abi.h"

#define XDEV_EXT_REFERENCE_POLICY_COUNT 5U

struct xdev_ext_reference_policy_descriptor {
	const char *map_name;
	const char *backend_name;
	unsigned int backend;
};

static const struct xdev_ext_reference_policy_descriptor
xdev_ext_reference_policy_descriptors[XDEV_EXT_REFERENCE_POLICY_COUNT] = {
	{ "socket_policy", "socket", XDEV_EXT_BINDING_BACKEND_SOCKET },
	{ "afxdp_policy", "afxdp", XDEV_EXT_BINDING_BACKEND_AFXDP },
	{ "nvme_policy", "nvme", XDEV_EXT_BINDING_BACKEND_NVME },
	{ "iaa_policy", "iaa", XDEV_EXT_BINDING_BACKEND_IAA },
	{ "gpu_policy", "gpu", XDEV_EXT_BINDING_BACKEND_GPU },
};

#define XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT 8U
#define XDEV_EXT_REFERENCE_POLICY_LINE_MAX 512U

/* Every stage a backend accepts in the kernel's stage/direction check. */
struct xdev_ext_reference_policy_stage_descriptor {
	unsigned int backend;
	const char *stage_name;
	unsigned int stage;
};

static const struct xdev_ext_reference_policy_stage_descriptor
xdev_ext_reference_policy_stage_descriptors[XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT] = {
	{ XDEV_EXT_BINDING_BACKEND_SOCKET, "send", XDEV_EXT_BINDING_STAGE_SEND },
	{ XDEV_EXT_BINDING_BACKEND_AFXDP, "afxdp_tx", XDEV_EXT_BINDING_STAGE_AFXDP_TX },
	{ XDEV_EXT_BINDING_BACKEND_AFXDP, "afxdp_rx", XDEV_EXT_BINDING_STAGE_AFXDP_RX },
	{ XDEV_EXT_BINDING_BACKEND_NVME, "nvme_read", XDEV_EXT_BINDING_STAGE_NVME_READ },
	{ XDEV_EXT_BINDING_BACKEND_NVME, "nvme_write",
	  XDEV_EXT_BINDING_STAGE_NVME_WRITE },
	{ XDEV_EXT_BINDING_BACKEND_IAA, "iaa_compress",
	  XDEV_EXT_BINDING_STAGE_IAA_COMPRESS },
	{ XDEV_EXT_BINDING_BACKEND_IAA, "iaa_decompress",
	  XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS },
	{ XDEV_EXT_BINDING_BACKEND_GPU, "gpu_copy", XDEV_EXT_BINDING_STAGE_GPU_COPY },
};

typedef int (*xdev_ext_reference_policy_emit_fn)(const char *line, void *opaque);

struct xdev_ext_reference_policy_runtime {
	void *object;
	void *links[XDEV_EXT_REFERENCE_POLICY_COUNT];
	size_t attached;
};

struct xdev_ext_reference_policy_ops {
	int (*attach)(void *object, const char *map_name, void **link_out);
	void (*destroy_link)(void *link);
	void (*close_object)(void *object);
};

static inline int
xdev_ext_reference_policy_stats_value_size_valid(size_t value_size)
{
	return value_size == sizeof(struct xdev_ext_reference_policy_stats);
}

static inline void
xdev_ext_reference_policy_stop(struct xdev_ext_reference_policy_runtime *runtime,
			  const struct xdev_ext_reference_policy_ops *ops)
{
	if (!runtime || !ops)
		return;

	while (runtime->attached) {
		size_t index = --runtime->attached;

		if (runtime->links[index])
			ops->destroy_link(runtime->links[index]);
		runtime->links[index] = NULL;
	}
	if (runtime->object) {
		ops->close_object(runtime->object);
		runtime->object = NULL;
	}
}

static inline int
xdev_ext_reference_policy_start(struct xdev_ext_reference_policy_runtime *runtime,
			   void *object,
			   const struct xdev_ext_reference_policy_ops *ops)
{
	size_t index;
	int ret;

	if (!runtime || !object || !ops || !ops->attach ||
	    !ops->destroy_link || !ops->close_object)
		return -EINVAL;
	if (runtime->object || runtime->attached)
		return -EBUSY;

	runtime->object = object;
	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_COUNT; index++) {
		void *link = NULL;

		ret = ops->attach(object,
				  xdev_ext_reference_policy_descriptors[index].map_name,
				  &link);
		if (ret)
			goto rollback;
		if (!link) {
			ret = -EPROTO;
			goto rollback;
		}
		runtime->links[index] = link;
		runtime->attached++;
	}

	return 0;

rollback:
	xdev_ext_reference_policy_stop(runtime, ops);
	return ret;
}

/* Append the shared counter fields after a header of header_len bytes. */
static inline int
xdev_ext_reference_policy_finish_line(
	char *buffer, size_t capacity, int header_len,
	const struct xdev_ext_reference_policy_backend_stats *stats)
{
	size_t used;
	int written;

	if (header_len < 0)
		return -EIO;
	used = (size_t)header_len;
	if (used >= capacity)
		return -ENOSPC;
	written = snprintf(
		buffer + used, capacity - used,
		"dispatch_callback=%llu dispatch_kfunc_ok=%llu "
		"dispatch_kfunc_errors=%llu complete_callback=%llu "
		"complete_kfunc_ok=%llu complete_kfunc_errors=%llu "
		"result_ok=%llu result_errors=%llu bytes=%llu "
		"last_result=%lld\n",
		(unsigned long long)stats->dispatch_callbacks,
		(unsigned long long)stats->dispatch_kfunc_ok,
		(unsigned long long)stats->dispatch_kfunc_errors,
		(unsigned long long)stats->complete_callbacks,
		(unsigned long long)stats->complete_kfunc_ok,
		(unsigned long long)stats->complete_kfunc_errors,
		(unsigned long long)stats->result_ok,
		(unsigned long long)stats->result_errors,
		(unsigned long long)stats->bytes_done,
		(long long)stats->last_result);
	if (written < 0)
		return -EIO;
	if ((size_t)written >= capacity - used)
		return -ENOSPC;
	return header_len + written;
}

static inline int
xdev_ext_reference_policy_format_backend(
	char *buffer, size_t capacity, size_t descriptor_index,
	const struct xdev_ext_reference_policy_backend_stats *stats)
{
	const struct xdev_ext_reference_policy_descriptor *descriptor;

	if (!buffer || !capacity || !stats ||
	    descriptor_index >= XDEV_EXT_REFERENCE_POLICY_COUNT)
		return -EINVAL;
	descriptor = &xdev_ext_reference_policy_descriptors[descriptor_index];
	return xdev_ext_reference_policy_finish_line(
		buffer, capacity,
		snprintf(buffer, capacity,
			 "XDEV_EXT_REFERENCE_POLICY_FINAL backend=%s id=%u ",
			 descriptor->backend_name, descriptor->backend),
		stats);
}

static inline const struct xdev_ext_reference_policy_descriptor *
xdev_ext_reference_policy_descriptor_for_backend(unsigned int backend)
{
	size_t index;

	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_COUNT; index++)
		if (xdev_ext_reference_policy_descriptors[index].backend == backend)
			return &xdev_ext_reference_policy_descriptors[index];
	return NULL;
}

/*
 * A separate record keeps every XDEV_EXT_REFERENCE_POLICY_FINAL line unchanged and
 * a "^XDEV_EXT_REFERENCE_POLICY_FINAL" count at five.
 */
static inline int
xdev_ext_reference_policy_format_stage(
	char *buffer, size_t capacity, size_t stage_index,
	const struct xdev_ext_reference_policy_backend_stats *stats)
{
	const struct xdev_ext_reference_policy_stage_descriptor *stage;
	const struct xdev_ext_reference_policy_descriptor *descriptor;

	if (!buffer || !capacity || !stats ||
	    stage_index >= XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT)
		return -EINVAL;
	stage = &xdev_ext_reference_policy_stage_descriptors[stage_index];
	descriptor = xdev_ext_reference_policy_descriptor_for_backend(stage->backend);
	if (!descriptor)
		return -EINVAL;
	return xdev_ext_reference_policy_finish_line(
		buffer, capacity,
		snprintf(buffer, capacity,
			 "XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL backend=%s id=%u "
			 "stage=%s stage_id=%u ",
			 descriptor->backend_name, descriptor->backend,
			 stage->stage_name, stage->stage),
		stats);
}

/* Five backend lines in descriptor order, then one line per owned stage. */
static inline int
xdev_ext_reference_policy_emit_snapshot(const struct xdev_ext_reference_policy_stats *stats,
				   xdev_ext_reference_policy_emit_fn emit,
				   void *opaque)
{
	char line[XDEV_EXT_REFERENCE_POLICY_LINE_MAX];
	size_t index;
	int ret;

	if (!stats || !emit)
		return -EINVAL;
	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_COUNT; index++) {
		unsigned int backend =
			xdev_ext_reference_policy_descriptors[index].backend;

		ret = xdev_ext_reference_policy_format_backend(
			line, sizeof(line), index, &stats->backend[backend]);
		if (ret < 0)
			return ret;
		ret = emit(line, opaque);
		if (ret)
			return ret;
	}
	for (index = 0; index < XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT; index++) {
		unsigned int stage =
			xdev_ext_reference_policy_stage_descriptors[index].stage;

		ret = xdev_ext_reference_policy_format_stage(
			line, sizeof(line), index, &stats->stage[stage]);
		if (ret < 0)
			return ret;
		ret = emit(line, opaque);
		if (ret)
			return ret;
	}
	return 0;
}

#endif /* XDEV_EXT_REFERENCE_POLICY_CORE_H */
