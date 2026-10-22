/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_SENDPATH_BASELINE_CORE_H
#define XDEV_EXT_SENDPATH_BASELINE_CORE_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <linux/bpf.h>
#include <liburing.h>

#include "../nvme_xdp_pipeline_core.h"

#ifndef O_DIRECT
#error "xdev_ext_sendpath_baseline_core.h needs _GNU_SOURCE for O_DIRECT"
#endif

#define SPB_PIPELINE_FRAME_SIZE UINT32_C(4096)
#define SPB_PIPELINE_PKT_HDR_SIZE (14 + 20 + 8)
#define SPB_PIPELINE_PKT_HEADER_ROOM 64
#define SPB_PIPELINE_RX_DATA_OFFSET                                         \
	((uint32_t)(XDP_PACKET_HEADROOM +                                    \
		    (SPB_PIPELINE_PKT_HEADER_ROOM - SPB_PIPELINE_PKT_HDR_SIZE) + \
		    SPB_PIPELINE_PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN))
#define SPB_PIPELINE_VECTOR_ALIGNMENT ((uint32_t)sizeof(uint64_t))
#define SPB_GROUP_TIMEOUT_NS UINT64_C(1000000000)
#define SPB_IDLE_TIMEOUT_NS UINT64_C(5000000000)
#define SPB_MAX_DEPTH 2048

enum spb_drop_reason {
	SPB_DROP_TRUNCATED = 0,
	SPB_DROP_OVERSIZE,
	SPB_DROP_MALFORMED,
	SPB_DROP_CHECKSUM,
	SPB_DROP_DIRECTION,
	SPB_DROP_SESSION,
	SPB_DROP_LAYOUT,
	SPB_DROP_DUPLICATE,
	SPB_DROP_OUT_OF_ORDER,
	SPB_DROP_STALE,
	SPB_DROP_NO_SLOT,
	SPB_DROP_PROTOCOL,
	SPB_DROP_REASON_COUNT,
};

/* How a write was handed to the kernel.  io_uring writes are classified by
 * the opcode of the SQE actually submitted, so a tier-2 run that fell back to
 * IORING_OP_WRITE is visible in the counts. */
enum spb_write_op {
	SPB_WRITE_OP_WRITE = 0,		/* IORING_OP_WRITE */
	SPB_WRITE_OP_WRITE_FIXED,	/* IORING_OP_WRITE_FIXED */
	SPB_WRITE_OP_PWRITE,		/* pwrite(2) */
	SPB_WRITE_OP_COUNT,
};

/* Writes handed to the kernel and not yet completed, the deepest that number
 * got, and the operations that carried them. */
struct spb_write_stats {
	uint64_t ops[SPB_WRITE_OP_COUNT];
	uint32_t inflight;
	uint32_t max_inflight;
};

struct spb_counters {
	uint64_t datagrams;
	uint64_t packets_accepted;
	uint64_t packets_dropped;
	uint64_t dropped[SPB_DROP_REASON_COUNT];
	uint64_t groups_completed;
	uint64_t groups_expired;
};

struct spb_config {
	uint64_t session_id;
	uint64_t start_lba;
	uint64_t capacity_lbas;
	uint32_t lba_size;
	uint32_t bytes;
	uint32_t mtu;
	uint32_t groups;
	uint32_t depth;
	uint64_t group_timeout_ns;
};

enum spb_group_state {
	SPB_GROUP_FREE = 0,
	SPB_GROUP_COLLECTING,
	SPB_GROUP_READY,
	SPB_GROUP_WRITING,
};

struct spb_group {
	enum spb_group_state state;
	struct nxp_wire_group_rx rx;
	uint64_t request_index;
	uint64_t lba;
	uint64_t byte_offset;
	uint64_t begin_ns;
	uint64_t first_accept_ns;
	uint64_t last_arrival_ns;	/* the datagram that completed it */
	uint8_t *buffer;
};

struct spb_receiver {
	struct spb_config config;
	struct nxp_wire_layout layout;
	struct spb_group *groups;
	int active;
	uint32_t last_generation;
	uint32_t outstanding;
	uint64_t next_request;
	uint64_t last_arrival_ns;	/* the last group to complete */
	struct spb_counters counters;
	struct spb_write_stats writes;
};

enum spb_feed_outcome {
	SPB_FEED_ACCEPTED = 0,
	SPB_FEED_COMPLETED,
	SPB_FEED_DROPPED,
};

struct spb_feed_result {
	enum spb_feed_outcome outcome;
	enum spb_drop_reason reason;
	int error;
	int group;
};

static inline bool spb_power_of_two(uint32_t value)
{
	return value && !(value & (value - 1));
}

/* Plan the segmentation the pipeline expects for one logical request.  The
 * frame size, data offset, and alignment are the pipeline's RX-write values
 * (nvme_xdp_pipeline.c: FRAME_SIZE, NXP_LAYOUT_DATA_OFFSET,
 * NXP_VECTOR_ALIGNMENT), so a datagram the XDEV_EXT sender emits for a given MTU
 * has exactly the shape this baseline accepts. */
static inline int spb_layout_plan(const struct spb_config *config,
				  uint32_t generation,
				  struct nxp_wire_layout *layout)
{
	return nxp_wire_mtu_layout_plan(config->session_id, generation,
					config->bytes, config->mtu,
					SPB_PIPELINE_FRAME_SIZE,
					SPB_PIPELINE_RX_DATA_OFFSET,
					SPB_PIPELINE_VECTOR_ALIGNMENT, layout);
}

/* Geometry checks mirror nvme_xdp_pipeline.c main(): nonzero session, LBA
 * size a power of two of at least 512 bytes that divides -B, at most
 * NXP_NVME_MAX_BLOCKS blocks per request, positive group count, depth in
 * [1, MAX_INFLIGHT], a packetizable layout, and an authorized window
 * [start_lba, start_lba + groups * blocks) that fits the target. */
static inline int spb_config_validate(const struct spb_config *config,
				      struct nxp_wire_layout *layout)
{
	struct nxp_wire_layout planned;
	uint64_t blocks, authorized, end, end_bytes;
	int ret;

	if (!config || !config->session_id)
		return -EINVAL;
	if (config->lba_size < NXP_NVME_MIN_LBA_SIZE ||
	    !spb_power_of_two(config->lba_size))
		return -EINVAL;
	if (!config->bytes || config->lba_size > config->bytes ||
	    config->bytes % config->lba_size)
		return -EINVAL;
	blocks = config->bytes / config->lba_size;
	if (blocks > NXP_NVME_MAX_BLOCKS)
		return -E2BIG;
	if (!config->groups || !config->depth ||
	    config->depth > SPB_MAX_DEPTH || !config->group_timeout_ns)
		return -EINVAL;
	ret = spb_layout_plan(config, 1, &planned);
	if (ret)
		return ret;
	if (nxp_u64_mul_overflow(config->groups, blocks, &authorized) ||
	    nxp_u64_add_overflow(config->start_lba, authorized, &end) ||
	    nxp_u64_mul_overflow(end, config->lba_size, &end_bytes))
		return -EOVERFLOW;
	if (end > config->capacity_lbas)
		return -ERANGE;
	if (layout)
		*layout = planned;
	return 0;
}

/* Local window mapping, arithmetic identical to nxp_plan_nvme_io():
 * LBA = start_lba + request_index * (bytes / lba_size).  The request index
 * is the receiver's local completed-group counter; no wire field is ever
 * used as a storage address. */
static inline int spb_local_lba(const struct spb_config *config,
				uint64_t request_index, uint64_t *lba,
				uint64_t *byte_offset)
{
	uint64_t blocks, authorized, relative, slba, end, offset;

	if (!config || !lba || !byte_offset || !config->lba_size ||
	    !config->bytes || config->bytes % config->lba_size)
		return -EINVAL;
	blocks = config->bytes / config->lba_size;
	if (nxp_u64_mul_overflow(config->groups, blocks, &authorized) ||
	    nxp_u64_mul_overflow(request_index, blocks, &relative) ||
	    nxp_u64_add_overflow(config->start_lba, relative, &slba) ||
	    nxp_u64_add_overflow(slba, blocks, &end) ||
	    nxp_u64_mul_overflow(slba, config->lba_size, &offset))
		return -EOVERFLOW;
	if (!authorized || relative >= authorized ||
	    blocks > authorized - relative)
		return -EACCES;
	if (slba >= config->capacity_lbas ||
	    blocks > config->capacity_lbas - slba)
		return -ERANGE;
	*lba = slba;
	*byte_offset = offset;
	return 0;
}

/* Parse and validate one UDP payload (NXP2 header + data).  The socket has
 * already removed Ethernet/IPv4/UDP; the remaining checks are, in order,
 * those of parse_wire_packet() (minimum length, path MTU, then
 * nxp_wire_header_parse() with its CRC32C) and pipeline_validate_rx_packet()
 * (direction, total length, session, MTU-derived segment shape). */
static inline int spb_payload_parse(const struct spb_config *config,
				    const uint8_t *payload, size_t len,
				    struct nxp_wire_segment *segment,
				    const uint8_t **data,
				    enum spb_drop_reason *reason)
{
	struct nxp_wire_layout layout;
	struct nxp_wire_segment expected;
	struct nxp_wire_span span;
	int ret;

	if (!config || !segment || !data || !reason)
		return -EINVAL;
	if (!payload || len < NXP_WIRE_HEADER_LEN) {
		*reason = SPB_DROP_TRUNCATED;
		return -EPROTO;
	}
	if (len > (size_t)UINT32_MAX - NXP_WIRE_IPV4_UDP_LEN ||
	    len + NXP_WIRE_IPV4_UDP_LEN > config->mtu) {
		*reason = SPB_DROP_OVERSIZE;
		return -EPROTO;
	}
	span.data = payload + NXP_WIRE_HEADER_LEN;
	span.len = (uint32_t)(len - NXP_WIRE_HEADER_LEN);
	ret = nxp_wire_header_parse(payload, NXP_WIRE_HEADER_LEN, &span, 1,
				    segment);
	if (ret) {
		if (ret == -EMSGSIZE || ret == -EINVAL)
			*reason = SPB_DROP_TRUNCATED;
		else if (ret == -EBADMSG)
			*reason = SPB_DROP_CHECKSUM;
		else
			*reason = SPB_DROP_MALFORMED;
		return ret;
	}
	if (segment->direction == NXP_IO_READ) {
		*reason = SPB_DROP_DIRECTION;
		return -EACCES;
	}
	if (segment->direction != NXP_IO_WRITE) {
		*reason = SPB_DROP_MALFORMED;
		return -EPROTO;
	}
	if (segment->total_len != config->bytes) {
		*reason = SPB_DROP_LAYOUT;
		return -EPROTO;
	}
	if (segment->session_id != config->session_id) {
		*reason = SPB_DROP_SESSION;
		return -ESTALE;
	}
	ret = spb_layout_plan(config, segment->generation, &layout);
	if (!ret)
		ret = nxp_wire_segment_at(&layout, NXP_IO_WRITE,
					  segment->segment_index, &expected);
	if (ret || segment->segment_count != expected.segment_count ||
	    segment->relative_offset != expected.relative_offset ||
	    segment->payload_len != expected.payload_len) {
		*reason = SPB_DROP_LAYOUT;
		return -EPROTO;
	}
	*data = span.data;
	return 0;
}

static inline void spb_group_clear(struct spb_group *group)
{
	uint8_t *buffer = group->buffer;

	memset(group, 0, sizeof(*group));
	group->buffer = buffer;
	group->state = SPB_GROUP_FREE;
}

static inline int spb_receiver_init(struct spb_receiver *rx,
				    const struct spb_config *config,
				    struct spb_group *groups,
				    uint8_t *const *buffers)
{
	struct nxp_wire_layout layout;
	int ret;

	if (!rx || !groups || !buffers)
		return -EINVAL;
	ret = spb_config_validate(config, &layout);
	if (ret)
		return ret;
	for (uint32_t i = 0; i < config->depth; i++)
		if (!buffers[i])
			return -EINVAL;
	memset(rx, 0, sizeof(*rx));
	rx->config = *config;
	rx->layout = layout;
	rx->groups = groups;
	rx->active = -1;
	for (uint32_t i = 0; i < config->depth; i++) {
		groups[i].buffer = buffers[i];
		spb_group_clear(&groups[i]);
	}
	return 0;
}

/* Mirrors the pipeline's RX consumption guard: a datagram is taken only while
 * fewer than depth groups are ready or being written, and fewer than the
 * configured number of groups have been reassembled. */
static inline bool spb_receiver_can_accept(const struct spb_receiver *rx)
{
	return rx && rx->groups && rx->next_request < rx->config.groups &&
	       rx->outstanding < rx->config.depth;
}

static inline enum spb_drop_reason spb_sequence_reason(int error)
{
	switch (error) {
	case -EALREADY:
		return SPB_DROP_DUPLICATE;
	case -EPIPE:
		return SPB_DROP_OUT_OF_ORDER;
	case -ESTALE:
	case -EOVERFLOW:
		return SPB_DROP_STALE;
	case -ENOBUFS:
		return SPB_DROP_NO_SLOT;
	default:
		return SPB_DROP_PROTOCOL;
	}
}

static inline int spb_drop(struct spb_receiver *rx,
			   struct spb_feed_result *result,
			   enum spb_drop_reason reason, int error)
{
	rx->counters.packets_dropped++;
	rx->counters.dropped[reason]++;
	result->outcome = SPB_FEED_DROPPED;
	result->reason = reason;
	result->error = error;
	result->group = -1;
	return 0;
}

/* Feed one received datagram payload.  Returns 0 when the datagram was
 * accepted or dropped as ordinary input loss (see result), -EBUSY without
 * consuming it when spb_receiver_can_accept() is false, or another negative
 * errno for an internal fault that must stop the run (fail-closed).
 *
 * Sequencing is the pipeline's run_rx_write_pipeline(): one group collects at
 * a time; its first datagram begins it with nxp_wire_group_begin() against the
 * last committed generation, and every datagram is ordered by
 * nxp_wire_group_accept() (future segments and future generations are
 * dropped, earlier ones are duplicates).  The generation is committed only
 * when the group completes, so an expired group can be retried with the same
 * generation. */
static inline int spb_receiver_feed(struct spb_receiver *rx,
				    const uint8_t *payload, size_t len,
				    uint64_t now_ns,
				    struct spb_feed_result *result)
{
	struct nxp_wire_segment segment;
	enum spb_drop_reason reason = SPB_DROP_PROTOCOL;
	const uint8_t *data = NULL;
	struct spb_group *group;
	int ret;

	if (!rx || !rx->groups || !result)
		return -EINVAL;
	memset(result, 0, sizeof(*result));
	result->group = -1;
	if (!spb_receiver_can_accept(rx))
		return -EBUSY;
	rx->counters.datagrams++;
	ret = spb_payload_parse(&rx->config, payload, len, &segment, &data,
				&reason);
	if (ret)
		return spb_drop(rx, result, reason, ret);

	if (rx->active < 0) {
		int free_index = -1;

		for (uint32_t i = 0; i < rx->config.depth; i++) {
			if (rx->groups[i].state == SPB_GROUP_FREE) {
				free_index = (int)i;
				break;
			}
		}
		if (free_index < 0)
			return spb_drop(rx, result, SPB_DROP_NO_SLOT, -ENOBUFS);
		group = &rx->groups[free_index];
		spb_group_clear(group);
		group->rx.last_generation = rx->last_generation;
		ret = nxp_wire_group_begin(&group->rx, rx->config.session_id,
					   segment.generation, NXP_IO_WRITE,
					   segment.total_len,
					   segment.segment_count);
		if (ret) {
			spb_group_clear(group);
			return spb_drop(rx, result, spb_sequence_reason(ret),
					ret);
		}
		group->state = SPB_GROUP_COLLECTING;
		group->begin_ns = now_ns;
		group->request_index = rx->next_request;
		rx->active = free_index;
	}

	group = &rx->groups[rx->active];
	if (group->state != SPB_GROUP_COLLECTING)
		return -EPROTO;
	ret = nxp_wire_group_accept(&group->rx, &segment);
	if (ret)
		return spb_drop(rx, result, spb_sequence_reason(ret), ret);
	if (segment.relative_offset > rx->config.bytes ||
	    segment.payload_len > rx->config.bytes - segment.relative_offset)
		return -EPROTO;
	/* The traditional path's user-space copy: recv() buffer -> request. */
	memcpy(group->buffer + segment.relative_offset, data,
	       segment.payload_len);
	if (group->rx.next_segment == 1)
		group->first_accept_ns = now_ns;
	rx->counters.packets_accepted++;
	result->group = rx->active;
	result->outcome = SPB_FEED_ACCEPTED;
	if (nxp_wire_group_finish(&group->rx) != 0)
		return 0;

	ret = spb_local_lba(&rx->config, group->request_index, &group->lba,
			    &group->byte_offset);
	if (ret)
		return ret;
	group->state = SPB_GROUP_READY;
	/* The group arrived with this datagram (see spb_arrival_report()). */
	group->last_arrival_ns = now_ns;
	rx->last_arrival_ns = now_ns;
	rx->last_generation = group->rx.last_generation;
	rx->next_request++;
	rx->outstanding++;
	rx->active = -1;
	rx->counters.groups_completed++;
	result->outcome = SPB_FEED_COMPLETED;
	return 0;
}

/* Mirrors pipeline_rx_expire_group(): an incomplete group older than the
 * group timeout (measured from the datagram that began it) is discarded
 * without committing its generation.  Returns 1 when a group expired. */
static inline int spb_receiver_expire(struct spb_receiver *rx, uint64_t now_ns)
{
	struct spb_group *group;

	if (!rx || !rx->groups)
		return -EINVAL;
	if (rx->active < 0)
		return 0;
	if ((uint32_t)rx->active >= rx->config.depth)
		return -ERANGE;
	group = &rx->groups[rx->active];
	if (now_ns < group->begin_ns ||
	    now_ns - group->begin_ns < rx->config.group_timeout_ns)
		return 0;
	spb_group_clear(group);
	rx->active = -1;
	rx->counters.groups_expired++;
	return 1;
}

static inline int spb_receiver_transition(struct spb_receiver *rx, int group,
					  enum spb_group_state from,
					  enum spb_group_state to)
{
	if (!rx || !rx->groups || group < 0 ||
	    (uint32_t)group >= rx->config.depth)
		return -EINVAL;
	if (rx->groups[group].state != from)
		return -EPROTO;
	rx->groups[group].state = to;
	return 0;
}

/* READY -> WRITING once the write has been handed to the kernel. */
static inline int spb_receiver_submit(struct spb_receiver *rx, int group)
{
	return spb_receiver_transition(rx, group, SPB_GROUP_READY,
				       SPB_GROUP_WRITING);
}

/* WRITING -> FREE after the write's own completion (success or error). */
static inline int spb_receiver_complete(struct spb_receiver *rx, int group)
{
	int ret = spb_receiver_transition(rx, group, SPB_GROUP_WRITING,
					  SPB_GROUP_FREE);

	if (ret)
		return ret;
	spb_group_clear(&rx->groups[group]);
	rx->outstanding--;
	return 0;
}

/* The run loop's only consumption guard: take another datagram only while
 * the run has not stopped and the receiver can accept one (fewer than depth
 * requests ready or being written, fewer than -n reassembled).  Pending write
 * completions are deliberately not part of the test, so up to depth writes
 * stay outstanding while datagrams of later groups are received. */
static inline bool spb_loop_may_receive(const struct spb_receiver *rx,
					bool stop)
{
	return !stop && spb_receiver_can_accept(rx);
}

/* READY -> WRITING once the write has been handed to the kernel with op.
 * At most depth writes are ever in flight; max_inflight records the deepest
 * point reached. */
static inline int spb_receiver_issue(struct spb_receiver *rx, int group,
				     enum spb_write_op op)
{
	int ret;

	if (!rx || (unsigned int)op >= SPB_WRITE_OP_COUNT)
		return -EINVAL;
	if (rx->writes.inflight >= rx->config.depth)
		return -EOVERFLOW;
	ret = spb_receiver_submit(rx, group);
	if (ret)
		return ret;
	rx->writes.ops[op]++;
	rx->writes.inflight++;
	if (rx->writes.inflight > rx->writes.max_inflight)
		rx->writes.max_inflight = rx->writes.inflight;
	return 0;
}

/* WRITING -> FREE after that write's own completion (success or error). */
static inline int spb_receiver_retire(struct spb_receiver *rx, int group)
{
	int ret;

	if (!rx)
		return -EINVAL;
	if (!rx->writes.inflight)
		return -EPROTO;
	ret = spb_receiver_complete(rx, group);
	if (ret)
		return ret;
	rx->writes.inflight--;
	return 0;
}

/* Only the two io_uring write opcodes are counted; anything else is a
 * defect and fails closed. */
static inline int spb_uring_write_op(uint8_t opcode, enum spb_write_op *op)
{
	if (!op)
		return -EINVAL;
	switch (opcode) {
	case IORING_OP_WRITE:
		*op = SPB_WRITE_OP_WRITE;
		return 0;
	case IORING_OP_WRITE_FIXED:
		*op = SPB_WRITE_OP_WRITE_FIXED;
		return 0;
	default:
		return -EPROTO;
	}
}

/* Prepare the io_uring write of a READY request: IORING_OP_WRITE_FIXED on
 * registered buffer index == slot for tier 2 (fixed), IORING_OP_WRITE from
 * the same buffer for tier 1.  The token carries the request index in the
 * high half and the slot in the low half, so each CQE is attributed to
 * exactly one outstanding request.  *op is classified from the prepared SQE,
 * and an SQE whose opcode is not the tier's own fails closed. */
static inline int spb_prep_uring_write(const struct spb_receiver *rx,
				       int group, int fd, bool fixed,
				       struct io_uring_sqe *sqe,
				       enum spb_write_op *op)
{
	const struct spb_group *request;
	int ret;

	if (!rx || !rx->groups || !sqe || !op || group < 0 ||
	    (uint32_t)group >= rx->config.depth)
		return -EINVAL;
	request = &rx->groups[group];
	if (request->state != SPB_GROUP_READY)
		return -EPROTO;
	/* Newer liburing prep helpers leave fields such as flags to
	 * io_uring_get_sqe(); clear the SQE here so its contents do not
	 * depend on the liburing version. */
	memset(sqe, 0, sizeof(*sqe));
	if (fixed)
		io_uring_prep_write_fixed(sqe, fd, request->buffer,
					  rx->config.bytes, request->byte_offset,
					  group);
	else
		io_uring_prep_write(sqe, fd, request->buffer, rx->config.bytes,
				    request->byte_offset);
	sqe->user_data = (request->request_index << 32) | (uint32_t)group;
	ret = spb_uring_write_op(sqe->opcode, op);
	if (ret)
		return ret;
	if (fixed != (*op == SPB_WRITE_OP_WRITE_FIXED))
		return -EPROTO;
	return 0;
}

/* Count an io_uring write by the opcode of the SQE that was submitted (the
 * SQE in the ring, read at the submission site), then READY -> WRITING. */
static inline int spb_receiver_issue_sqe(struct spb_receiver *rx, int group,
					 const struct io_uring_sqe *sqe)
{
	enum spb_write_op op;
	int ret;

	if (!sqe)
		return -EINVAL;
	ret = spb_uring_write_op(sqe->opcode, &op);
	if (ret)
		return ret;
	return spb_receiver_issue(rx, group, op);
}

/* fcntl(F_GETFL) of the opened target must carry O_DIRECT.  The traditional
 * tiers are defined as page-cache-bypassing writes, so a target the kernel
 * did not open O_DIRECT is refused instead of measured as buffered I/O. */
static inline int spb_target_flags_check(int flags)
{
	if (flags < 0)
		return -EINVAL;
	return (flags & O_DIRECT) ? 0 : -EOPNOTSUPP;
}

/* Read "<major>:<minor>" from <node>/dev.  Returns 0, -ENOENT when node has
 * no dev attribute, -EPROTO when the attribute is not a device number, or
 * another negative errno. */
static inline int spb_sysfs_read_devnum(const char *node,
					unsigned int *major_number,
					unsigned int *minor_number)
{
	char path[PATH_MAX], text[64] = { 0 }, trailing = '\n';
	FILE *file;
	int ret = 0, fields;

	if ((size_t)snprintf(path, sizeof(path), "%s/dev", node) >= sizeof(path))
		return -ENAMETOOLONG;
	file = fopen(path, "r");
	if (!file)
		return -errno;
	fields = fgets(text, sizeof(text), file) ?
		 sscanf(text, "%u:%u%c", major_number, minor_number, &trailing) :
		 0;
	if (fields < 2 || trailing != '\n')
		ret = -EPROTO;
	fclose(file);
	return ret;
}

/* Resolve <sysfs_root>/dev/block/<major>:<minor>, the lookup
 * nvme_xdp_pipeline.c resolve_device_paths() performs, and fail closed with
 * -EXDEV when that node is a partition.  The pipeline rejects a partition
 * because its node does not sit directly below the NVMe controller beside the
 * generic character node; a partition's node sits below its whole disk's node
 * instead.  The same placement is tested here without an NVMe controller: the
 * target is a partition when its parent directory is itself the node of a
 * block device (the parent's dev number resolves back to the parent through
 * <sysfs_root>/dev/block), or when the kernel marks it with a "partition"
 * attribute.  A node that cannot be resolved is refused, never assumed whole.
 * sysfs_root is "/sys" at run time and a fake tree in the tests. */
static inline int spb_block_partition_check(const char *sysfs_root,
					    unsigned int major_number,
					    unsigned int minor_number)
{
	char link[PATH_MAX], node[PATH_MAX], parent[PATH_MAX];
	char path[PATH_MAX], resolved[PATH_MAX];
	unsigned int parent_major, parent_minor;
	struct stat st;
	char *slash;
	int ret;

	if (!sysfs_root || !sysfs_root[0])
		return -EINVAL;
	if ((size_t)snprintf(link, sizeof(link), "%s/dev/block/%u:%u",
			     sysfs_root, major_number, minor_number) >=
	    sizeof(link))
		return -ENAMETOOLONG;
	if (!realpath(link, node))
		return -errno;
	if ((size_t)snprintf(path, sizeof(path), "%s/partition", node) >=
	    sizeof(path))
		return -ENAMETOOLONG;
	if (!stat(path, &st))
		return -EXDEV;
	if (errno != ENOENT)
		return -errno;
	memcpy(parent, node, sizeof(parent));
	slash = strrchr(parent, '/');
	if (!slash || slash == parent)
		return -EXDEV;
	*slash = '\0';
	ret = spb_sysfs_read_devnum(parent, &parent_major, &parent_minor);
	if (ret == -ENOENT)
		return 0;	/* the parent is not a device node */
	if (ret)
		return ret;
	if ((size_t)snprintf(path, sizeof(path), "%s/dev/block/%u:%u",
			     sysfs_root, parent_major, parent_minor) >=
	    sizeof(path))
		return -ENAMETOOLONG;
	if (!realpath(path, resolved)) {
		if (errno == ENOENT)
			return 0;	/* e.g. an NVMe controller's char dev */
		return -errno;
	}
	return strcmp(resolved, parent) == 0 ? -EXDEV : 0;
}

/* Classify an fstat()ed target: a whole block device ("block") or a regular
 * file ("file").  A partition is refused with -EXDEV, as nvme_xdp_pipeline
 * refuses it, because -l would otherwise name partition-relative LBAs, a
 * different physical window than the pipeline's namespace LBAs.  Anything
 * else fails closed. */
static inline int spb_target_classify(const struct stat *st,
				      const char *sysfs_root,
				      const char **kind)
{
	int ret;

	if (!st || !kind)
		return -EINVAL;
	if (S_ISBLK(st->st_mode)) {
		ret = spb_block_partition_check(sysfs_root, major(st->st_rdev),
						minor(st->st_rdev));
		if (ret)
			return ret;
		*kind = "block";
		return 0;
	}
	if (S_ISREG(st->st_mode)) {
		*kind = "file";
		return 0;
	}
	return -ENOTBLK;
}

static inline int spb_u64_compare(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static inline void spb_sort_u64(uint64_t *values, size_t count)
{
	if (values && count > 1)
		qsort(values, count, sizeof(*values), spb_u64_compare);
}

/* Nearest-rank percentile of an ascending array: rank = ceil(p * n / 100). */
static inline uint64_t spb_nearest_rank(const uint64_t *sorted, size_t count,
					unsigned int percent)
{
	uint64_t rank;

	if (!sorted || !count)
		return 0;
	if (percent > 100)
		percent = 100;
	rank = ((uint64_t)percent * count + 99) / 100;
	if (!rank)
		rank = 1;
	return sorted[rank - 1];
}

/* The four arrival fields of SENDPATH_BASELINE_SUMMARY, with the definitions
 * of PIPELINE_RX_SUMMARY (nvme_xdp_pipeline_core.h).  A datagram arrives when
 * recv() returns it, and a group arrives with the datagram that completes
 * it; a time of 0 has not been seen.
 *
 *   rx_span_us             first datagram received (the start of wall_us)
 *                          to the arrival of the last group to arrive;
 *   tail_us                that arrival to end_ns, the end of wall_us;
 *   post_arrival_us_p50/99 nearest rank over the written groups of the
 *                          time from a group's arrival to its write
 *                          completion (the post_arrival_ns samples, which
 *                          are sorted in place). */
struct spb_arrival_report {
	uint64_t rx_span_us;
	uint64_t tail_us;
	uint64_t post_arrival_us_p50;
	uint64_t post_arrival_us_p99;
};

static inline void spb_arrival_report(uint64_t first_datagram_ns,
				      uint64_t last_arrival_ns, uint64_t end_ns,
				      uint64_t *post_arrival_ns, size_t samples,
				      struct spb_arrival_report *out)
{
	memset(out, 0, sizeof(*out));
	if (first_datagram_ns && last_arrival_ns > first_datagram_ns)
		out->rx_span_us =
			(last_arrival_ns - first_datagram_ns) / UINT64_C(1000);
	if (last_arrival_ns && end_ns > last_arrival_ns)
		out->tail_us = (end_ns - last_arrival_ns) / UINT64_C(1000);
	if (samples && post_arrival_ns) {
		spb_sort_u64(post_arrival_ns, samples);
		out->post_arrival_us_p50 =
			spb_nearest_rank(post_arrival_ns, samples, 50) /
			UINT64_C(1000);
		out->post_arrival_us_p99 =
			spb_nearest_rank(post_arrival_ns, samples, 99) /
			UINT64_C(1000);
	}
}

static inline const char *spb_drop_reason_name(enum spb_drop_reason reason)
{
	static const char *const names[SPB_DROP_REASON_COUNT] = {
		[SPB_DROP_TRUNCATED] = "truncated",
		[SPB_DROP_OVERSIZE] = "oversize",
		[SPB_DROP_MALFORMED] = "malformed",
		[SPB_DROP_CHECKSUM] = "checksum",
		[SPB_DROP_DIRECTION] = "direction",
		[SPB_DROP_SESSION] = "session",
		[SPB_DROP_LAYOUT] = "layout",
		[SPB_DROP_DUPLICATE] = "duplicate",
		[SPB_DROP_OUT_OF_ORDER] = "out_of_order",
		[SPB_DROP_STALE] = "stale",
		[SPB_DROP_NO_SLOT] = "no_slot",
		[SPB_DROP_PROTOCOL] = "protocol",
	};

	if ((unsigned int)reason >= SPB_DROP_REASON_COUNT)
		return NULL;
	return names[reason];
}

#endif /* XDEV_EXT_SENDPATH_BASELINE_CORE_H */
