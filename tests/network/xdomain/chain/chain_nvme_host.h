/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Installed as "nvme.h" for the NVMe class unit only.  Upstream NVMe host
 * structures are reduced to the members the class and storage family read;
 * run.py appends nvme_xdev_ext_capture_identity() verbatim from the real
 * drivers/nvme/host/nvme.h.  Declarations of the real NVMe functions follow
 * that header.
 */
#ifndef CHAIN_NVME_HOST_H
#define CHAIN_NVME_HOST_H
#include <linux/nvme_xdev_ext_passthru.h>
typedef struct { __u8 b[16]; } uuid_t;
struct xdev_ext_peer_nvme_rw;
struct nvme_ns;
struct nvme_ctrl_ops {
	const char *name;
	int (*peer_rw)(struct nvme_ns *, const struct xdev_ext_peer_nvme_rw *, struct file *, bool *accepted);
};
struct nvme_ctrl { enum nvme_ctrl_state state; struct device *dev; const struct nvme_ctrl_ops *ops;
	bool sgls; };
struct nvme_ns_ids { __u8 eui64[8]; __u8 nguid[16]; uuid_t uuid; __u8 csi; };
struct nvme_ns_head { struct nvme_ns_ids ids; __u32 ns_id; __u16 ms; __u8 lba_shift, pi_size, pi_type; };
struct nvme_ns { struct nvme_ctrl *ctrl; unsigned long flags; struct nvme_ns_head *head;
	struct gendisk *disk; struct request_queue *queue; struct cdev cdev; };
static inline enum nvme_ctrl_state nvme_ctrl_state(struct nvme_ctrl *ctrl) { return ctrl->state; }
static inline bool nvme_ctrl_sgl_supported(struct nvme_ctrl *ctrl) { return ctrl->sgls; }
int nvme_ns_chr_uring_cmd(struct io_uring_cmd *ioucmd, unsigned int issue_flags);
void nvme_init_request(struct request *req, struct nvme_command *cmd);
bool nvme_cmd_allowed(struct nvme_ns *ns, struct nvme_command *c, unsigned flags, bool open_for_write);
struct xdev_ext_stor_rw;
struct xdev_ext_stor_extent;
int nvme_xdev_ext_peer_build_cmd(
		const struct xdev_ext_stor_rw *rw, u32 nsid,
		bool sgl_supported, bool strict_single,
		const struct xdev_ext_stor_extent *spans, u32 nr,
		struct xdev_ext_stor_extent *work, u32 capacity,
		void *list_cpu, u64 list_dma, u32 list_bytes,
		struct nvme_command *cmd);
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage;
bool nvme_xdev_ext_mech_cmd_allowed(struct nvme_ns *ns, struct file *file, bool write);
void nvme_xdev_ext_mech_fill_info(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, void *info);
int nvme_xdev_ext_mech_stage_matches(struct xdev_ext_mech_stage *st, struct nvme_ns *ns,
				     const struct nvme_xdev_ext_identity *identity);
void nvme_xdev_ext_mech_init(void);
void nvme_xdev_ext_mech_exit(void);
#define CHAIN_NVME_CAPTURE_IDENTITY
#endif
