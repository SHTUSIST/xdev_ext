/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBXDEV_EXT_H
#define LIBXDEV_EXT_H

/*
 * libxdev_ext: a thin user-space wrapper over the XDEV_EXT session control
 * plane.  Semantics, ownership and error codes: SPEC.md in this directory.
 * All functions return 0 or a negative errno and never print.
 */

#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>

#include "../../../include/uapi/linux/xdev_ext_mech.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LIBXDEV_EXT_VERSION		1U

#define XDEV_EXT_FRAME_SIZE		4096U
#define XDEV_EXT_DEFAULT_FRAMES		4096U
#define XDEV_EXT_MAX_FRAMES		65536U
#define XDEV_EXT_PROG_MAX_GLOBALS	16U
#define XDEV_EXT_MAX_PROGS		4U
#define XDEV_EXT_STOP_RETRIES		1000U

/* xsk_mode of an XSK pool: the bound mode must equal the request. */
enum xdev_ext_xsk_mode {
	XDEV_EXT_XSK_ZEROCOPY	= 0,
	XDEV_EXT_XSK_COPY	= 1,
};

/* Set sz to the caller's struct size; unnamed fields are zero. */
#define XDEV_EXT_OPTS_INIT(type, ...) \
	((struct type){ .sz = sizeof(struct type), __VA_ARGS__ })

struct xdev_ext_prog;
struct xdev_ext_session;

/* --- class programs (struct_ops) --- */

struct xdev_ext_prog_global {
	const char *name;
	__u64 value;
};

struct xdev_ext_prog_opts {
	size_t sz;
	const char *obj_path;
	const char *map_name;
	const char *pin_path;		/* optional */
	const struct xdev_ext_prog_global *globals;
	__u32 nr_globals;
	__u32 flags;			/* must be 0 */
};

int xdev_ext_prog_attach(const struct xdev_ext_prog_opts *o,
			 struct xdev_ext_prog **out);
int xdev_ext_prog_detach(struct xdev_ext_prog *p);

/* --- session steps --- */

struct xdev_ext_pool_opts {
	size_t sz;
	__u32 pool_kind;		/* XDEV_EXT_MECH_POOL_XSK or _IOU_UMEM */
	__u32 xsk_mode;			/* enum xdev_ext_xsk_mode */
	const char *ifname;		/* XSK only, required */
	__u32 queue;			/* XSK only */
	__u32 nr_frames;		/* 0: XDEV_EXT_DEFAULT_FRAMES */
	__u32 flags;			/* must be 0 */
};

struct xdev_ext_create_opts {
	size_t sz;
	__u32 group_bytes;
	__u32 depth;
	__u32 mtu;			/* 0: XSK ifname MTU, IOU_UMEM 1500 */
	__u32 nr_stages;
	struct xdev_ext_mech_layout layout;	/* all zero: computed */
	struct xdev_ext_mech_peer peer;		/* zero local_mac: ifname MAC */
	struct xdev_ext_mech_stage_uapi st[XDEV_EXT_MECH_MAX_STAGES];
	__u32 flags;			/* must be 0 */
};

struct xdev_ext_start_opts {
	size_t sz;
	__u64 nr_batches;
	__u64 first_seq;		/* 0: 1 */
	__u32 flags;			/* must be 0 */
};

/* Existing registered allocation authority; duplicated CLOEXEC by the library. */
struct xdev_ext_peer_pool_opts {
	size_t sz;
	int allocation_fd;
	__u32 flags;
};
struct xdev_ext_start_frames_opts {
	size_t sz;
	__u64 nr_batches, first_seq;
	const __u32 *indices;
	__u32 nr_indices, flags;
};
struct xdev_ext_peer_span {
	__u64 offset, device_address;
	__u32 frame_index, data_len, capacity;
};
struct xdev_ext_link_snapshot {
	__u64 token, local_inc, remote_inc;
	__u32 channels, up, closing, nhi_gone;
	char service[256];
};
int xdev_ext_link_read(const char *sysfs_root, const char *service,
	struct xdev_ext_link_snapshot *out);
int xdev_ext_link_discover(const char *sysfs_root, __u64 wanted_token,
	struct xdev_ext_link_snapshot *out);

int xdev_ext_session_open_peer(const struct xdev_ext_peer_pool_opts *o,
			       struct xdev_ext_session **out);
int xdev_ext_session_start_frames(struct xdev_ext_session *s,
				 const struct xdev_ext_start_frames_opts *o);
int xdev_ext_session_stage_caps(struct xdev_ext_session *s, __u32 stage,
			       struct xdev_ext_mech_stage_caps *out);
int xdev_ext_stage_xdomain(struct xdev_ext_mech_stage_uapi *out, int control_fd,
			  __u64 link_token, __u32 direction, __u32 flags);

int xdev_ext_session_open(const struct xdev_ext_pool_opts *o,
			  struct xdev_ext_session **out);
int xdev_ext_session_create(struct xdev_ext_session *s,
			    const struct xdev_ext_create_opts *o);
/* Explicit diagnostics: syscall delivery and report.result are distinct.
 * Each call clears out first. Only a delivered, validated report has nonzero
 * size/version; a transport or schema error leaves out zero. Copy historical
 * reports elsewhere before reusing out. Retained failed CREATE has no session
 * ID; close preserves its owner handles. */
int xdev_ext_session_create_report(struct xdev_ext_session *s,
    const struct xdev_ext_create_opts *o, struct xdev_ext_mech_create_report *out);
int xdev_ext_create_report_read(int owning_ring_fd,
    const struct xdev_ext_mech_create *create, struct xdev_ext_mech_create_report *out);
int xdev_ext_session_arm(struct xdev_ext_session *s, __u64 batches_target,
			 __u64 published_target);
int xdev_ext_session_start(struct xdev_ext_session *s,
			   const struct xdev_ext_start_opts *o);
int xdev_ext_session_wait(struct xdev_ext_session *s, int timeout_ms,
			  struct xdev_ext_mech_stats *out);
int xdev_ext_session_stats(struct xdev_ext_session *s,
			   struct xdev_ext_mech_stats *out);
int xdev_ext_session_nic_accounting(struct xdev_ext_session *s,
				    struct xdev_ext_mech_transport_stats_v3 *out);
int xdev_ext_session_stop(struct xdev_ext_session *s);
int xdev_ext_session_close(struct xdev_ext_session *s);

int xdev_ext_session_eventfd(const struct xdev_ext_session *s);
int xdev_ext_session_ring_fd(const struct xdev_ext_session *s);
int xdev_ext_session_xsk_fd(const struct xdev_ext_session *s);
__u64 xdev_ext_session_id(const struct xdev_ext_session *s);
bool xdev_ext_session_zero_copy(const struct xdev_ext_session *s);
bool xdev_ext_session_retained(const struct xdev_ext_session *s);

/* --- USER stage (SPEC.md section 8) --- */

struct xdev_ext_user_stage;

struct xdev_ext_user_stage_opts {
	size_t sz;
	int ring_fd;			/* io_uring fd for XDEV_EXT_MECH_OP_USER_STAGE */
	void *umem;			/* pool UMEM base for frame pointers, or NULL */
	__u32 entries;			/* power of two >= CREATE depth; 0: 64 */
	__u32 flags;			/* 0 or XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL */
};

/* One batch the user thread holds until xdev_ext_user_stage_complete(). */
struct xdev_ext_user_batch {
	__u32 slot;
	__u32 nr_frames;
	__u64 ticket;
	__u64 batch_id;
	__u64 key;
	__u64 arg;
	/* The library's copy of the slot's frames; set f[i].out_len. */
	struct xdev_ext_user_frame f[XDEV_EXT_MECH_MAX_FRAMES];
	void *data[XDEV_EXT_MECH_MAX_FRAMES];	/* umem + umem_addr + data_off */
};

int xdev_ext_user_stage_open(const struct xdev_ext_user_stage_opts *o,
			     struct xdev_ext_user_stage **out);
int xdev_ext_user_stage_fd(const struct xdev_ext_user_stage *u);
__u32 xdev_ext_user_stage_entries(const struct xdev_ext_user_stage *u);
int xdev_ext_user_stage_next(struct xdev_ext_user_stage *u, int timeout_ms,
			     struct xdev_ext_user_batch *b);
int xdev_ext_user_stage_complete(struct xdev_ext_user_stage *u,
				 const struct xdev_ext_user_batch *b, int status);
int xdev_ext_user_stage_close(struct xdev_ext_user_stage *u);
int xdev_ext_user_batch_peer_span(const struct xdev_ext_user_batch *b, __u32 pos,
	__u64 allocation_va, __u64 allocation_bytes, __u32 frame_size,
	struct xdev_ext_peer_span *out);
int xdev_ext_user_stage_control(struct xdev_ext_user_stage *u, void **base,
	struct xdev_ext_user_ring_offsets *off);
int xdev_ext_user_stage_ctl_attach(struct xdev_ext_user_stage *u);
int xdev_ext_user_stage_ctl_detach(struct xdev_ext_user_stage *u);

/* --- one call: NVMe READ -> AF_XDP TX --- */

struct xdev_ext_nvme_nic_opts {
	size_t sz;
	const char *nvme_path;		/* /dev/ngXnY */
	__u64 slba, nlb;
	const char *ifname;
	__u32 queue;
	__u32 xsk_mode;
	struct xdev_ext_mech_peer peer;
	__u32 group_bytes;
	__u32 depth;
	__u64 nr_batches;
	int timeout_ms;			/* negative: no deadline */
	__u32 nr_progs;
	const struct xdev_ext_prog_opts *progs;	/* optional */
	__u32 flags;			/* must be 0 */
};

struct xdev_ext_run_result {
	size_t sz;
	__u64 session_id;
	bool zero_copy;
	bool retained;
	int wait_err, nic_err, stop_err;
	struct xdev_ext_mech_stats stats;
	struct xdev_ext_mech_transport_stats_v3 nic;
	struct xdev_ext_session *session;	/* only when retained */
};

int xdev_ext_nvme_to_nic(const struct xdev_ext_nvme_nic_opts *o,
			 struct xdev_ext_run_result *r);

#ifdef __cplusplus
}
#endif

#endif /* LIBXDEV_EXT_H */
