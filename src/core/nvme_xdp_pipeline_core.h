/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NVME_XDP_PIPELINE_CORE_H
#define NVME_XDP_PIPELINE_CORE_H

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>

#define NXP_STABLE_ID_MAX 192
#define NXP_CONTROLLER_SERIAL_MAX 128
#define NXP_PCI_BDF_MAX 32
#define NXP_NVME_MAX_BLOCKS UINT32_C(65536)
#define NXP_NVME_MIN_LBA_SIZE UINT32_C(512)

/* Classify a poll performed only after an RX loop iteration made no progress.
 * POLLERR/POLLHUP/POLLNVAL are reported even when the caller requested only
 * POLLIN.  A positive POLLIN result can race the next RX-ring peek or be
 * spurious, so it is retryable only until the shared absolute idle deadline. */
static inline int nxp_rx_idle_poll_result(int poll_result, short revents,
					  uint64_t now_ns,
					  uint64_t deadline_ns)
{
	if (poll_result < 0 || !deadline_ns)
		return -EINVAL;
	if (poll_result > 0 && (revents & POLLNVAL))
		return -EBADF;
	if (poll_result > 0 && (revents & POLLHUP))
		return -EPIPE;
	if (poll_result > 0 && (revents & POLLERR))
		return -EIO;
	if (now_ns >= deadline_ns)
		return -ETIMEDOUT;
	return -EAGAIN;
}

/* rx-write stops issuing NVMe WRITEs once SIGTERM or SIGINT (stop_signal) is
 * received, drains the ones in flight and returns every frame.  A stop is not
 * a success: the run fails with -EINTR when it left any of the requested
 * groups unwritten, and not when every group was already written. */
static inline int nxp_rx_stop_result(int stop_signal, uint64_t finished,
				     uint64_t requested)
{
	return stop_signal && finished < requested ? -EINTR : 0;
}

/* The exit status of a failed run.  When the run's only failure is the stop
 * above (first_error -EINTR, no teardown error), the status is 128 + the
 * signal number, the status a shell reports for a process that signal ended;
 * every other failure, a teardown failure after the stop included, is 1. */
static inline int nxp_stop_exit_status(int first_error, int teardown_error,
				       int stop_signal)
{
	if (first_error == -EINTR && !teardown_error &&
	    stop_signal > 0 && stop_signal < 128)
		return 128 + stop_signal;
	return 1;
}

/* SQE128 and CQE32 keep the base UAPI type sizes (64 and 16 bytes) while
 * doubling the array stride.  Centralize the byte calculation so both ring
 * accessors use the same overflow-checked rule. */
static inline int nxp_ring_entry_offset(uint32_t index, uint32_t mask,
					size_t entry_size, unsigned int shift,
					size_t *offset)
{
	size_t slot;

	if (!offset || !entry_size || shift > 1)
		return -EINVAL;
	slot = (size_t)(index & mask);
	if (shift && slot > SIZE_MAX / 2)
		return -EOVERFLOW;
	slot <<= shift;
	if (slot > SIZE_MAX / entry_size)
		return -EOVERFLOW;
	*offset = slot * entry_size;
	return 0;
}

/* Linux exposes an NVMe generic namespace character node (ngXnY) and the
 * corresponding whole-namespace block node (nvmeXnY) as distinct children of
 * the same controller directory.  Compare canonical absolute paths without
 * assuming either leaf name can be derived from the other. */
static inline bool nxp_paths_share_parent(const char *left, const char *right)
{
	const char *left_slash;
	const char *right_slash;
	size_t left_parent_len;
	size_t right_parent_len;

	if (!left || !right || left[0] != '/' || right[0] != '/' ||
	    !left[1] || !right[1] || strcmp(left, right) == 0)
		return false;
	left_slash = strrchr(left, '/');
	right_slash = strrchr(right, '/');
	if (!left_slash || !right_slash || left_slash == left ||
	    right_slash == right || !left_slash[1] || !right_slash[1])
		return false;
	left_parent_len = (size_t)(left_slash - left);
	right_parent_len = (size_t)(right_slash - right);
	return left_parent_len == right_parent_len &&
	       memcmp(left, right, left_parent_len) == 0;
}

static inline bool nxp_is_hex_digit(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static inline bool nxp_is_pci_bdf(const char *address)
{
	if (!address || strlen(address) != 12 || address[4] != ':' ||
	    address[7] != ':' || address[10] != '.' || address[11] < '0' ||
	    address[11] > '7')
		return false;
	for (size_t i = 0; i < 12; i++) {
		if (i == 4 || i == 7 || i == 10 || i == 11)
			continue;
		if (!nxp_is_hex_digit(address[i]))
			return false;
	}
	return true;
}

static inline int nxp_nvme_result_errno(int result)
{
	if (result < 0)
		return result;
	return result > 0 ? -EIO : 0;
}

static inline void nxp_latch_error(int *first_error, int error)
{
	if (!first_error || !error || *first_error)
		return;
	*first_error = error < 0 ? error : -EIO;
}

static inline bool nxp_retryable_error(int error, bool wait_path)
{
	return error == -EINTR || error == -EAGAIN || error == -EBUSY ||
	       (wait_path && error == -ETIME);
}

/* Return zero while another retry is permitted; otherwise return the terminal
 * error.  A budget counts retries, so zero always terminates. */
static inline int nxp_retry_consume(int error, bool wait_path,
				    unsigned int *remaining)
{
	if (!remaining)
		return -EINVAL;
	if (!nxp_retryable_error(error, wait_path))
		return error;
	if (!*remaining)
		return -ETIMEDOUT;
	(*remaining)--;
	return 0;
}

static inline int nxp_parse_u64(const char *text, uint64_t *out)
{
	unsigned long long value;
	char *end;

	if (!text || !out || text[0] < '0' || text[0] > '9')
		return -EINVAL;
	errno = 0;
	value = strtoull(text, &end, 0);
	if (errno == ERANGE || value > UINT64_MAX)
		return -ERANGE;
	if (end == text || *end != '\0')
		return -EINVAL;
	*out = (uint64_t)value;
	return 0;
}

static inline int nxp_parse_u32(const char *text, uint32_t *out)
{
	uint64_t value;
	int ret = nxp_parse_u64(text, &value);

	if (ret)
		return ret;
	if (value > UINT32_MAX)
		return -ERANGE;
	*out = (uint32_t)value;
	return 0;
}

static inline int nxp_parse_positive_int(const char *text, int maximum,
					 int *out)
{
	uint64_t value;
	int ret;

	if (!out || maximum < 1)
		return -EINVAL;
	ret = nxp_parse_u64(text, &value);
	if (ret)
		return ret;
	if (!value || value > (uint64_t)maximum)
		return -ERANGE;
	*out = (int)value;
	return 0;
}

/* Immutable namespace facts gathered from retained character and block fds. */
struct nxp_namespace {
	uint32_t nsid;
	uint32_t lba_size;
	uint64_t capacity_lbas;
	uint16_t metadata_size;
	uint8_t pi_type;
	bool char_is_namespace;
	bool block_is_whole_namespace;
	bool same_namespace;
	bool stable_id_present;
	bool controller_serial_present;
	bool pci_bdf_present;
	uint64_t char_rdev;
	uint64_t block_rdev;
	uint64_t diskseq;
	uint8_t stable_id[NXP_STABLE_ID_MAX];
	uint8_t stable_id_len;
	uint8_t controller_serial[NXP_CONTROLLER_SERIAL_MAX];
	uint8_t controller_serial_len;
	uint8_t pci_bdf[NXP_PCI_BDF_MAX];
	uint8_t pci_bdf_len;
};

/* Facts that can be re-read from already retained file descriptors without
 * issuing an NVMe admin command.  The startup snapshot proves the complete
 * namespace identity and geometry once; this epoch catches descriptor reuse,
 * namespace replacement, and removal immediately before SQ publication. */
struct nxp_namespace_epoch {
	uint32_t nsid;
	bool char_is_namespace;
	bool block_is_whole_namespace;
	uint64_t char_rdev;
	uint64_t block_rdev;
	uint64_t diskseq;
};

struct nxp_io_limits {
	uint64_t authorized_first_lba;
	uint64_t authorized_lbas;
	uint64_t frame_size;
	uint32_t payload_offset;
	uint32_t packet_header_len;
	uint32_t l2_header_len;
	uint32_t mtu;
};

struct nxp_nvme_read {
	uint64_t slba;
	uint32_t blocks;
	uint16_t nlb;
	uint32_t data_len;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
};

static inline int nxp_namespace_validate(const struct nxp_namespace *ns)
{
	if (!ns || !ns->nsid)
		return -ENODEV;
	if (ns->lba_size < NXP_NVME_MIN_LBA_SIZE ||
	    (ns->lba_size & (ns->lba_size - 1)))
		return -EINVAL;
	if (!ns->capacity_lbas)
		return -ENOSPC;
	if (ns->metadata_size || ns->pi_type)
		return -EOPNOTSUPP;
	if (!ns->char_is_namespace)
		return -ENOTTY;
	if (!ns->block_is_whole_namespace)
		return -ENOTBLK;
	if (!ns->same_namespace)
		return -EXDEV;
	if (!ns->stable_id_present || !ns->stable_id_len ||
	    ns->stable_id_len > NXP_STABLE_ID_MAX || !ns->char_rdev ||
	    !ns->block_rdev || !ns->diskseq ||
	    !ns->controller_serial_present || !ns->controller_serial_len ||
	    ns->controller_serial_len > NXP_CONTROLLER_SERIAL_MAX ||
	    !ns->pci_bdf_present || !ns->pci_bdf_len ||
	    ns->pci_bdf_len > NXP_PCI_BDF_MAX)
		return -ENODATA;
	return 0;
}

static inline int
nxp_namespace_same_generation(const struct nxp_namespace *frozen,
			      const struct nxp_namespace *current)
{
	int ret;

	ret = nxp_namespace_validate(frozen);
	if (ret)
		return ret;
	ret = nxp_namespace_validate(current);
	if (ret)
		return ret;
	if (frozen->nsid != current->nsid ||
	    frozen->lba_size != current->lba_size ||
	    frozen->capacity_lbas != current->capacity_lbas ||
	    frozen->metadata_size != current->metadata_size ||
	    frozen->pi_type != current->pi_type ||
	    frozen->char_rdev != current->char_rdev ||
	    frozen->block_rdev != current->block_rdev ||
	    frozen->diskseq != current->diskseq ||
	    frozen->stable_id_len != current->stable_id_len ||
	    memcmp(frozen->stable_id, current->stable_id,
		   frozen->stable_id_len) != 0 ||
	    frozen->controller_serial_len != current->controller_serial_len ||
	    memcmp(frozen->controller_serial, current->controller_serial,
		   frozen->controller_serial_len) != 0 ||
	    frozen->pci_bdf_len != current->pci_bdf_len ||
	    memcmp(frozen->pci_bdf, current->pci_bdf,
		   frozen->pci_bdf_len) != 0)
		return -ESTALE;
	return 0;
}

static inline int
nxp_namespace_epoch_check_one(const struct nxp_namespace_epoch *epoch)
{
	if (!epoch)
		return -EINVAL;
	if (!epoch->char_is_namespace)
		return -ENOTTY;
	if (!epoch->block_is_whole_namespace)
		return -ENOTBLK;
	if (!epoch->nsid || !epoch->char_rdev || !epoch->block_rdev)
		return -ENODEV;
	if (!epoch->diskseq)
		return -ENODATA;
	return 0;
}

static inline int
nxp_namespace_epoch_from_snapshot(const struct nxp_namespace *snapshot,
				  struct nxp_namespace_epoch *epoch)
{
	int ret;

	if (!snapshot || !epoch)
		return -EINVAL;
	ret = nxp_namespace_validate(snapshot);
	if (ret)
		return ret;
	*epoch = (struct nxp_namespace_epoch) {
		.nsid = snapshot->nsid,
		.char_is_namespace = snapshot->char_is_namespace,
		.block_is_whole_namespace = snapshot->block_is_whole_namespace,
		.char_rdev = snapshot->char_rdev,
		.block_rdev = snapshot->block_rdev,
		.diskseq = snapshot->diskseq,
	};
	return 0;
}

static inline int
nxp_namespace_epoch_validate(const struct nxp_namespace_epoch *frozen,
			     const struct nxp_namespace_epoch *current)
{
	int ret;

	ret = nxp_namespace_epoch_check_one(frozen);
	if (ret)
		return ret;
	ret = nxp_namespace_epoch_check_one(current);
	if (ret)
		return ret;
	if (frozen->nsid != current->nsid ||
	    frozen->char_rdev != current->char_rdev ||
	    frozen->block_rdev != current->block_rdev ||
	    frozen->diskseq != current->diskseq)
		return -ESTALE;
	return 0;
}

static inline bool nxp_u64_add_overflow(uint64_t a, uint64_t b, uint64_t *out)
{
	*out = a + b;
	return *out < a;
}

static inline bool nxp_u64_mul_overflow(uint64_t a, uint64_t b, uint64_t *out)
{
	if (a && b > UINT64_MAX / a)
		return true;
	*out = a * b;
	return false;
}

enum nxp_io_direction {
	NXP_IO_READ = 1,
	NXP_IO_WRITE = 2,
};

#define NXP_NVME_OP_WRITE UINT8_C(0x01)
#define NXP_NVME_OP_READ  UINT8_C(0x02)

/* The executor creates this position from local configuration.  In
 * particular, nxp_wire_segment.relative_offset must never be copied into
 * block_offset: the wire offset is an offset inside one transfer, while this
 * value selects storage inside the locally authorized namespace window. */
struct nxp_local_io_position {
	uint64_t request_index;
	uint64_t block_offset;
};

struct nxp_nvme_io_plan {
	enum nxp_io_direction direction;
	uint8_t opcode;
	uint64_t slba;
	uint32_t blocks;
	uint16_t nlb;
	uint32_t data_len;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
};

/* Build one logical NVMe command independently of its packetization.  Both
 * request_index and block_offset are relative to the locally configured
 * authorized_first_lba; no peer-provided absolute address is accepted. */
static inline int
nxp_plan_nvme_io(const struct nxp_namespace *ns,
		 const struct nxp_io_limits *limits,
		 enum nxp_io_direction direction,
		 const struct nxp_local_io_position *position,
		 uint64_t data_len, struct nxp_nvme_io_plan *out)
{
	uint64_t blocks, request_delta, relative_lba, slba, end_lba;
	int ret;

	if (!limits || !position || !out)
		return -EINVAL;
	if (direction != NXP_IO_READ && direction != NXP_IO_WRITE)
		return -EINVAL;
	ret = nxp_namespace_validate(ns);
	if (ret)
		return ret;
	if (!data_len || data_len > UINT32_MAX || data_len % ns->lba_size)
		return -EINVAL;
	blocks = data_len / ns->lba_size;
	if (!blocks || blocks > NXP_NVME_MAX_BLOCKS)
		return -E2BIG;
	if (nxp_u64_mul_overflow(position->request_index, blocks,
				 &request_delta) ||
	    nxp_u64_add_overflow(request_delta, position->block_offset,
				 &relative_lba) ||
	    nxp_u64_add_overflow(limits->authorized_first_lba, relative_lba,
				 &slba) ||
	    nxp_u64_add_overflow(slba, blocks, &end_lba))
		return -EOVERFLOW;
	if (!limits->authorized_lbas ||
	    relative_lba >= limits->authorized_lbas ||
	    blocks > limits->authorized_lbas - relative_lba)
		return -EACCES;
	if (slba >= ns->capacity_lbas || blocks > ns->capacity_lbas - slba)
		return -ERANGE;

	out->direction = direction;
	out->opcode = direction == NXP_IO_READ ? NXP_NVME_OP_READ :
						     NXP_NVME_OP_WRITE;
	out->slba = slba;
	out->blocks = (uint32_t)blocks;
	out->nlb = (uint16_t)(blocks - 1);
	out->data_len = (uint32_t)data_len;
	out->cdw10 = (uint32_t)slba;
	out->cdw11 = (uint32_t)(slba >> 32);
	out->cdw12 = (uint32_t)(blocks - 1);
	return 0;
}

#define NXP_WIRE_MAGIC UINT32_C(0x4e585032) /* "NXP2" */
#define NXP_WIRE_VERSION UINT8_C(2)
#define NXP_WIRE_HEADER_LEN UINT8_C(40)
#define NXP_WIRE_MAX_SEGMENTS UINT16_C(256)
#define NXP_WIRE_MAX_PAYLOAD_SPANS UINT16_C(18)
#define NXP_WIRE_IPV4_UDP_LEN UINT32_C(28)

/* The serialized wire header is deliberately not exposed as a C structure:
 * its byte order and size are fixed, and it contains no namespace, SLBA, or
 * other storage address. */
struct nxp_wire_segment {
	/* Destination action carried by the message.  A source NVMe READ that
	 * transports data to a storage receiver is encoded as NXP_IO_WRITE. */
	enum nxp_io_direction direction;
	uint64_t session_id;
	uint32_t generation;
	uint16_t segment_index;
	uint16_t segment_count;
	uint32_t total_len;
	uint32_t relative_offset;
	uint32_t payload_len;
};

struct nxp_wire_layout {
	uint64_t session_id;
	uint32_t generation;
	uint32_t total_len;
	uint32_t segment_data_limit;
	uint16_t segment_count;
};

struct nxp_wire_span {
	const uint8_t *data;
	uint32_t len;
};

enum nxp_rx_frame_state {
	NXP_RX_FRAME_FREE = 0,
	NXP_RX_FRAME_FILL,
	NXP_RX_FRAME_RECEIVED,
	NXP_RX_FRAME_IO,
};

static inline int nxp_rx_frame_transition(enum nxp_rx_frame_state *state,
					 enum nxp_rx_frame_state from,
					 enum nxp_rx_frame_state to)
{
	if (!state)
		return -EINVAL;
	if (*state == to || (*state == NXP_RX_FRAME_FREE && to == NXP_RX_FRAME_FREE))
		return -EALREADY;
	if (*state != from)
		return -EPROTO;
	*state = to;
	return 0;
}

static inline int nxp_rx_frame_to_fill(enum nxp_rx_frame_state *state)
{
	return nxp_rx_frame_transition(state, NXP_RX_FRAME_FREE,
				       NXP_RX_FRAME_FILL);
}

static inline int nxp_rx_frame_to_received(enum nxp_rx_frame_state *state)
{
	return nxp_rx_frame_transition(state, NXP_RX_FRAME_FILL,
				       NXP_RX_FRAME_RECEIVED);
}

static inline int nxp_rx_frame_hold_for_io(enum nxp_rx_frame_state *state)
{
	return nxp_rx_frame_transition(state, NXP_RX_FRAME_RECEIVED,
				       NXP_RX_FRAME_IO);
}

static inline int nxp_rx_frame_recycle_after_io(enum nxp_rx_frame_state *state)
{
	return nxp_rx_frame_transition(state, NXP_RX_FRAME_IO,
				       NXP_RX_FRAME_FREE);
}

static inline int nxp_rx_frame_drop(enum nxp_rx_frame_state *state)
{
	return nxp_rx_frame_transition(state, NXP_RX_FRAME_RECEIVED,
				       NXP_RX_FRAME_FREE);
}

/* Frames by state at one instant; rx-write takes it when its loop ends.  A
 * RECEIVED or IO frame is still owned by the program and was never released;
 * a FREE or FILL frame is not.  A value outside the enum is counted apart and
 * is outstanding too, so a corrupted state cannot drop out of the count. */
struct nxp_rx_frame_census {
	uint64_t free;
	uint64_t fill;
	uint64_t received;
	uint64_t io;
	uint64_t invalid;
};

static inline int
nxp_rx_frame_census_take(const enum nxp_rx_frame_state *states, size_t count,
			 struct nxp_rx_frame_census *census)
{
	if (!states || !census)
		return -EINVAL;
	memset(census, 0, sizeof(*census));
	for (size_t i = 0; i < count; i++) {
		switch (states[i]) {
		case NXP_RX_FRAME_FREE:
			census->free++;
			break;
		case NXP_RX_FRAME_FILL:
			census->fill++;
			break;
		case NXP_RX_FRAME_RECEIVED:
			census->received++;
			break;
		case NXP_RX_FRAME_IO:
			census->io++;
			break;
		default:
			census->invalid++;
			break;
		}
	}
	return 0;
}

/* Frames the program still owns and has not released; nonzero without a
 * census. */
static inline uint64_t
nxp_rx_frame_census_outstanding(const struct nxp_rx_frame_census *census)
{
	if (!census)
		return UINT64_MAX;
	return census->received + census->io + census->invalid;
}

static inline int
nxp_wire_segment_validate(const struct nxp_wire_segment *segment)
{
	uint64_t end;

	if (!segment || !segment->session_id || !segment->generation ||
	    (segment->direction != NXP_IO_READ &&
	     segment->direction != NXP_IO_WRITE) ||
	    !segment->segment_count ||
	    segment->segment_count > NXP_WIRE_MAX_SEGMENTS ||
	    segment->segment_index >= segment->segment_count ||
	    !segment->total_len || !segment->payload_len)
		return -EINVAL;
	end = (uint64_t)segment->relative_offset + segment->payload_len;
	if (end > segment->total_len)
		return -ERANGE;
	if (!segment->segment_index && segment->relative_offset)
		return -ERANGE;
	if (segment->segment_index == segment->segment_count - 1) {
		if (end != segment->total_len)
			return -ERANGE;
	} else if (end >= segment->total_len) {
		return -ERANGE;
	}
	return 0;
}

/* Plan ordinary (one-descriptor) packets for one logical, vectored NVMe I/O.
 * mtu is the L3 MTU, while data_offset is the byte offset of packet data in
 * each UMEM frame after Ethernet/IP/UDP and the NXP wire header.  Alignment is
 * for per-segment CPU/vector access; the logical total is separately checked
 * against the namespace LBA size by nxp_plan_nvme_io(). */
static inline int
nxp_wire_mtu_layout_plan(uint64_t session_id, uint32_t generation,
			 uint64_t total_len,
			 uint32_t mtu, uint32_t frame_size,
			 uint32_t data_offset, uint32_t alignment,
			 struct nxp_wire_layout *out)
{
	uint32_t mtu_data, frame_data, segment_data;
	uint64_t segments;

	if (!out || !session_id || !generation || !total_len)
		return -EINVAL;
	if (total_len > UINT32_MAX)
		return -E2BIG;
	if (!alignment || (alignment & (alignment - 1)) ||
	    data_offset >= frame_size)
		return -EINVAL;
	if (mtu <= NXP_WIRE_IPV4_UDP_LEN + NXP_WIRE_HEADER_LEN)
		return -EMSGSIZE;
	mtu_data = mtu - NXP_WIRE_IPV4_UDP_LEN - NXP_WIRE_HEADER_LEN;
	frame_data = frame_size - data_offset;
	segment_data = mtu_data < frame_data ? mtu_data : frame_data;
	segment_data &= ~(alignment - 1);
	if (!segment_data)
		return -EMSGSIZE;
	segments = 1 + (total_len - 1) / segment_data;
	if (segments > NXP_WIRE_MAX_SEGMENTS)
		return -E2BIG;

	out->session_id = session_id;
	out->generation = generation;
	out->total_len = (uint32_t)total_len;
	out->segment_data_limit = segment_data;
	out->segment_count = (uint16_t)segments;
	return 0;
}

/* Bound the maximum number of frames retained by a logical-I/O window.  The
 * caller supplies the actual configured capacities; checking every XSK ring
 * keeps startup behavior independent of which direction is selected later. */
static inline int
nxp_group_capacity_validate(uint32_t depth, uint16_t segments_per_group,
			    uint32_t available_frames, uint32_t tx_entries,
			    uint32_t completion_entries, uint32_t fill_entries,
			    uint32_t rx_entries)
{
	uint64_t required;

	if (!depth || !segments_per_group || !available_frames || !tx_entries ||
	    !completion_entries || !fill_entries || !rx_entries)
		return -EINVAL;
	required = (uint64_t)depth * segments_per_group;
	if (required > available_frames || required > tx_entries ||
	    required > completion_entries || required > fill_entries ||
	    required > rx_entries)
		return -E2BIG;
	return 0;
}

static inline int
nxp_wire_segment_at(const struct nxp_wire_layout *layout,
		    enum nxp_io_direction direction, uint16_t index,
		    struct nxp_wire_segment *out)
{
	uint64_t offset, remaining, payload;
	int ret;

	if (!layout || !out ||
	    (direction != NXP_IO_READ && direction != NXP_IO_WRITE) ||
	    !layout->session_id || !layout->generation || !layout->total_len ||
	    !layout->segment_data_limit || !layout->segment_count)
		return -EINVAL;
	if (index >= layout->segment_count)
		return -ERANGE;
	offset = (uint64_t)index * layout->segment_data_limit;
	if (offset >= layout->total_len)
		return -ERANGE;
	remaining = layout->total_len - offset;
	payload = remaining < layout->segment_data_limit ?
		  remaining : layout->segment_data_limit;

	*out = (struct nxp_wire_segment) {
		.direction = direction,
		.session_id = layout->session_id,
		.generation = layout->generation,
		.segment_index = index,
		.segment_count = layout->segment_count,
		.total_len = layout->total_len,
		.relative_offset = (uint32_t)offset,
		.payload_len = (uint32_t)payload,
	};
	ret = nxp_wire_segment_validate(out);
	if (ret)
		return ret;
	return 0;
}

static inline void nxp_wire_put_be16(uint8_t *dst, uint16_t value)
{
	dst[0] = (uint8_t)(value >> 8);
	dst[1] = (uint8_t)value;
}

static inline void nxp_wire_put_be32(uint8_t *dst, uint32_t value)
{
	dst[0] = (uint8_t)(value >> 24);
	dst[1] = (uint8_t)(value >> 16);
	dst[2] = (uint8_t)(value >> 8);
	dst[3] = (uint8_t)value;
}

static inline void nxp_wire_put_be64(uint8_t *dst, uint64_t value)
{
	nxp_wire_put_be32(dst, (uint32_t)(value >> 32));
	nxp_wire_put_be32(dst + 4, (uint32_t)value);
}

static inline uint16_t nxp_wire_get_be16(const uint8_t *src)
{
	return ((uint16_t)src[0] << 8) | src[1];
}

static inline uint32_t nxp_wire_get_be32(const uint8_t *src)
{
	return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
	       ((uint32_t)src[2] << 8) | src[3];
}

static inline uint64_t nxp_wire_get_be64(const uint8_t *src)
{
	return ((uint64_t)nxp_wire_get_be32(src) << 32) |
	       nxp_wire_get_be32(src + 4);
}

static inline uint32_t
nxp_wire_crc32c_update(uint32_t crc, const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (unsigned int bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^
			      (UINT32_C(0x82f63b78) &
			       (uint32_t)-(int32_t)(crc & 1));
	}
	return crc;
}

static inline int
nxp_wire_span_total(const struct nxp_wire_span *spans, size_t span_count,
		    uint32_t *total)
{
	uint64_t sum = 0;

	if (!spans || !total || !span_count ||
	    span_count > NXP_WIRE_MAX_PAYLOAD_SPANS)
		return -EINVAL;
	for (size_t i = 0; i < span_count; i++) {
		if (!spans[i].data || !spans[i].len)
			return -EINVAL;
		sum += spans[i].len;
		if (sum > UINT32_MAX)
			return -EOVERFLOW;
	}
	*total = (uint32_t)sum;
	return 0;
}

static inline uint32_t
nxp_wire_checksum(const uint8_t header[NXP_WIRE_HEADER_LEN],
		  const struct nxp_wire_span *spans, size_t span_count)
{
	static const uint8_t zero_checksum[4] = { 0, 0, 0, 0 };
	uint32_t crc = UINT32_MAX;

	crc = nxp_wire_crc32c_update(crc, header, 36);
	crc = nxp_wire_crc32c_update(crc, zero_checksum,
				     sizeof(zero_checksum));
	for (size_t i = 0; i < span_count; i++)
		crc = nxp_wire_crc32c_update(crc, spans[i].data, spans[i].len);
	return ~crc;
}

static inline int
nxp_wire_header_encode(uint8_t *header, size_t header_capacity,
		       const struct nxp_wire_segment *segment,
		       const struct nxp_wire_span *spans, size_t span_count)
{
	uint32_t payload_len, checksum;
	int ret;

	if (!header || header_capacity < NXP_WIRE_HEADER_LEN)
		return -EMSGSIZE;
	ret = nxp_wire_segment_validate(segment);
	if (ret)
		return ret;
	ret = nxp_wire_span_total(spans, span_count, &payload_len);
	if (ret)
		return ret;
	if (payload_len != segment->payload_len)
		return -EMSGSIZE;

	memset(header, 0, NXP_WIRE_HEADER_LEN);
	nxp_wire_put_be32(header, NXP_WIRE_MAGIC);
	header[4] = NXP_WIRE_VERSION;
	header[5] = NXP_WIRE_HEADER_LEN;
	header[6] = (uint8_t)segment->direction;
	header[7] = 0;
	nxp_wire_put_be64(header + 8, segment->session_id);
	nxp_wire_put_be32(header + 16, segment->generation);
	nxp_wire_put_be16(header + 20, segment->segment_index);
	nxp_wire_put_be16(header + 22, segment->segment_count);
	nxp_wire_put_be32(header + 24, segment->total_len);
	nxp_wire_put_be32(header + 28, segment->relative_offset);
	nxp_wire_put_be32(header + 32, segment->payload_len);
	checksum = nxp_wire_checksum(header, spans, span_count);
	nxp_wire_put_be32(header + 36, checksum);
	return 0;
}

static inline int
nxp_wire_header_parse(const uint8_t *header, size_t header_len,
		      const struct nxp_wire_span *spans, size_t span_count,
		      struct nxp_wire_segment *out)
{
	uint32_t payload_len, expected_checksum;
	int ret;

	if (!header || !out)
		return -EINVAL;
	if (header_len != NXP_WIRE_HEADER_LEN)
		return -EMSGSIZE;
	if (nxp_wire_get_be32(header) != NXP_WIRE_MAGIC)
		return -EPROTO;
	if (header[4] != NXP_WIRE_VERSION)
		return -EPROTONOSUPPORT;
	if (header[5] != NXP_WIRE_HEADER_LEN || header[7])
		return -EPROTO;
	ret = nxp_wire_span_total(spans, span_count, &payload_len);
	if (ret)
		return ret;
	if (payload_len != nxp_wire_get_be32(header + 32))
		return -EMSGSIZE;
	expected_checksum = nxp_wire_checksum(header, spans, span_count);
	if (expected_checksum != nxp_wire_get_be32(header + 36))
		return -EBADMSG;

	*out = (struct nxp_wire_segment) {
		.direction = (enum nxp_io_direction)header[6],
		.session_id = nxp_wire_get_be64(header + 8),
		.generation = nxp_wire_get_be32(header + 16),
		.segment_index = nxp_wire_get_be16(header + 20),
		.segment_count = nxp_wire_get_be16(header + 22),
		.total_len = nxp_wire_get_be32(header + 24),
		.relative_offset = nxp_wire_get_be32(header + 28),
		.payload_len = payload_len,
	};
	ret = nxp_wire_segment_validate(out);
	return ret ? -EPROTO : 0;
}

enum nxp_wire_group_state {
	NXP_WIRE_GROUP_IDLE = 0,
	NXP_WIRE_GROUP_ACTIVE,
	NXP_WIRE_GROUP_COMPLETE,
};

/* Ordered receiver state is constant-size.  It rejects future segments but
 * remains active, allowing a caller with an ordered retry queue to supply the
 * missing segment. */
struct nxp_wire_group_rx {
	enum nxp_wire_group_state state;
	enum nxp_io_direction direction;
	uint64_t session_id;
	uint32_t generation;
	uint32_t last_generation;
	uint32_t total_len;
	uint32_t received_len;
	uint16_t segment_count;
	uint16_t next_segment;
};

static inline int
nxp_wire_group_begin(struct nxp_wire_group_rx *rx, uint64_t session_id,
		     uint32_t generation,
		     enum nxp_io_direction direction, uint32_t total_len,
		     uint16_t segment_count)
{
	if (!rx || !session_id || !generation || !total_len || !segment_count ||
	    segment_count > NXP_WIRE_MAX_SEGMENTS ||
	    (direction != NXP_IO_READ && direction != NXP_IO_WRITE))
		return -EINVAL;
	if (rx->state == NXP_WIRE_GROUP_ACTIVE)
		return -EBUSY;
	if (rx->last_generation == UINT32_MAX)
		return -EOVERFLOW;
	if (generation == rx->last_generation)
		return -EALREADY;
	if (generation < rx->last_generation + 1)
		return -ESTALE;
	if (generation > rx->last_generation + 1)
		return -EPIPE;
	rx->state = NXP_WIRE_GROUP_ACTIVE;
	rx->direction = direction;
	rx->session_id = session_id;
	rx->generation = generation;
	rx->total_len = total_len;
	rx->received_len = 0;
	rx->segment_count = segment_count;
	rx->next_segment = 0;
	return 0;
}

static inline int
nxp_wire_group_accept(struct nxp_wire_group_rx *rx,
		      const struct nxp_wire_segment *segment)
{
	int ret;

	if (!rx || !segment)
		return -EINVAL;
	/* Check the process/session identity before interpreting generation state.
	 * A delayed packet from an earlier process must never be classified as a
	 * duplicate belonging to the current receiver. */
	if (segment->session_id != rx->session_id)
		return -ESTALE;
	if (rx->state == NXP_WIRE_GROUP_COMPLETE) {
		if (segment->generation == rx->last_generation)
			return -EALREADY;
		if (rx->last_generation == UINT32_MAX)
			return -EOVERFLOW;
		return segment->generation < rx->last_generation ?
		       -ESTALE : -EPIPE;
	}
	if (rx->state != NXP_WIRE_GROUP_ACTIVE)
		return -EINVAL;
	if (segment->generation != rx->generation)
		return -ESTALE;
	if (segment->direction != rx->direction ||
	    segment->total_len != rx->total_len ||
	    segment->segment_count != rx->segment_count)
		return -EPROTO;
	ret = nxp_wire_segment_validate(segment);
	if (ret)
		return -EPROTO;
	if (segment->segment_index < rx->next_segment)
		return -EALREADY;
	if (segment->segment_index > rx->next_segment ||
	    segment->relative_offset != rx->received_len)
		return -EPIPE;
	if (segment->payload_len > rx->total_len - rx->received_len)
		return -EPROTO;

	rx->received_len += segment->payload_len;
	rx->next_segment++;
	if (rx->next_segment == rx->segment_count) {
		if (rx->received_len != rx->total_len)
			return -EPROTO;
		rx->state = NXP_WIRE_GROUP_COMPLETE;
		rx->last_generation = rx->generation;
	}
	return 0;
}

static inline int nxp_wire_group_finish(const struct nxp_wire_group_rx *rx)
{
	if (!rx)
		return -EINVAL;
	if (rx->state == NXP_WIRE_GROUP_COMPLETE)
		return 0;
	if (rx->state == NXP_WIRE_GROUP_ACTIVE)
		return -ENODATA;
	return -EINVAL;
}

static inline int nxp_encode_read(const struct nxp_namespace *ns,
				  const struct nxp_io_limits *limits,
				  uint64_t start_lba,
				  uint64_t request_index,
				  uint64_t data_len,
				  struct nxp_nvme_read *out)
{
	uint64_t blocks, delta, slba, packet_len;
	int ret;

	if (!limits || !out)
		return -EINVAL;
	ret = nxp_namespace_validate(ns);
	if (ret)
		return ret;
	if (!data_len || data_len > UINT32_MAX || data_len % ns->lba_size)
		return -EINVAL;
	blocks = data_len / ns->lba_size;
	if (blocks > NXP_NVME_MAX_BLOCKS)
		return -E2BIG;
	if (nxp_u64_mul_overflow(request_index, blocks, &delta) ||
	    nxp_u64_add_overflow(start_lba, delta, &slba))
		return -EOVERFLOW;
	if (slba >= ns->capacity_lbas || blocks > ns->capacity_lbas - slba)
		return -ERANGE;
	if (!limits->authorized_lbas || slba < limits->authorized_first_lba ||
	    slba - limits->authorized_first_lba >= limits->authorized_lbas ||
	    blocks > limits->authorized_lbas -
		     (slba - limits->authorized_first_lba))
		return -EACCES;
	if (limits->payload_offset < limits->packet_header_len)
		return -EINVAL;
	if (data_len > limits->frame_size ||
	    limits->payload_offset > limits->frame_size - data_len)
		return -ENOBUFS;
	if (nxp_u64_add_overflow(data_len, limits->packet_header_len,
				 &packet_len) ||
	    packet_len > (uint64_t)limits->mtu + limits->l2_header_len)
		return -EMSGSIZE;

	out->slba = slba;
	out->blocks = (uint32_t)blocks;
	out->nlb = (uint16_t)(blocks - 1);
	out->data_len = (uint32_t)data_len;
	out->cdw10 = (uint32_t)slba;
	out->cdw11 = (uint32_t)(slba >> 32);
	out->cdw12 = (uint32_t)(blocks - 1);
	return 0;
}

enum nxp_request_state {
	NXP_REQ_FREE = 0,
	NXP_REQ_PREPARED,
	NXP_REQ_PUBLISHED,
	NXP_REQ_ACCEPTED,
	NXP_REQ_COMPLETED,
};

struct nxp_request {
	enum nxp_request_state state;
	uint32_t slot;
	uint32_t generation;
	uint64_t token;
	bool owns_backing;
};

struct nxp_submit_result {
	uint32_t accepted;
	bool invalidate;
};

static inline int nxp_request_prepare(struct nxp_request *req, uint32_t slot,
				      uint32_t *next_generation)
{
	uint32_t generation;

	if (!req || !next_generation || req->owns_backing ||
	    (req->state != NXP_REQ_FREE && req->state != NXP_REQ_COMPLETED))
		return -EBUSY;
	generation = ++*next_generation;
	if (!generation)
		generation = ++*next_generation;
	req->state = NXP_REQ_PREPARED;
	req->slot = slot;
	req->generation = generation;
	req->token = ((uint64_t)generation << 32) | slot;
	req->owns_backing = true;
	return 0;
}

static inline int nxp_request_publish(struct nxp_request *req)
{
	if (!req || req->state != NXP_REQ_PREPARED || !req->owns_backing)
		return -EINVAL;
	req->state = NXP_REQ_PUBLISHED;
	return 0;
}

static inline int nxp_request_accept(struct nxp_request *req)
{
	if (!req || req->state != NXP_REQ_PUBLISHED || !req->owns_backing)
		return -EINVAL;
	req->state = NXP_REQ_ACCEPTED;
	return 0;
}

static inline struct nxp_submit_result
nxp_submit_classify(int submit_ret, uint32_t wanted, uint32_t sq_head_before,
		    uint32_t sq_head_after)
{
	struct nxp_submit_result result = { 0 };
	uint32_t consumed = sq_head_after - sq_head_before;
	uint32_t returned = submit_ret > 0 ? (uint32_t)submit_ret : 0;

	if (!wanted) {
		result.invalidate = true;
		return result;
	}
	if (consumed > wanted || returned > wanted) {
		result.invalidate = true;
		result.accepted = wanted;
		return result;
	}
	result.accepted = consumed > returned ? consumed : returned;
	if (submit_ret < 0 && submit_ret != -EINTR && submit_ret != -EAGAIN &&
	    submit_ret != -EBUSY)
		result.invalidate = true;
	return result;
}

static inline int nxp_request_complete(struct nxp_request *req, uint64_t token)
{
	if (!req)
		return -EINVAL;
	if (token != req->token)
		return -ESTALE;
	if (req->state == NXP_REQ_COMPLETED)
		return -EALREADY;
	if (req->state != NXP_REQ_ACCEPTED || !req->owns_backing)
		return -EPROTO;
	req->state = NXP_REQ_COMPLETED;
	req->owns_backing = false;
	return 0;
}

static inline int nxp_request_wait_failed(const struct nxp_request *req, int err)
{
	if (!req || req->state != NXP_REQ_ACCEPTED || !req->owns_backing)
		return -EPROTO;
	return err < 0 ? err : -err;
}

static inline int nxp_request_release_unaccepted(struct nxp_request *req,
					 bool ring_rebuilt)
{
	if (!req || !req->owns_backing)
		return -EINVAL;
	if (req->state == NXP_REQ_ACCEPTED)
		return -EBUSY;
	if (req->state == NXP_REQ_PUBLISHED && !ring_rebuilt)
		return -EBUSY;
	if (req->state != NXP_REQ_PREPARED && req->state != NXP_REQ_PUBLISHED)
		return -EPROTO;
	req->state = NXP_REQ_COMPLETED;
	req->owns_backing = false;
	return 0;
}

enum nxp_data_stage {
	NXP_DATA_EMPTY = 0,
	NXP_DATA_DMA_DONE,
	NXP_DATA_COPIED,
	NXP_DATA_PROCESSED,
	NXP_DATA_HEADERS_DONE,
	NXP_DATA_READY,
};

struct nxp_data_progress {
	enum nxp_data_stage stage;
	bool staging;
};

static inline void nxp_data_begin(struct nxp_data_progress *p, bool staging)
{
	p->stage = NXP_DATA_EMPTY;
	p->staging = staging;
}

static inline int nxp_data_dma_done(struct nxp_data_progress *p)
{
	if (!p || p->stage != NXP_DATA_EMPTY)
		return -EINVAL;
	p->stage = NXP_DATA_DMA_DONE;
	return 0;
}

static inline int nxp_data_copy(struct nxp_data_progress *p)
{
	if (!p || !p->staging || p->stage != NXP_DATA_DMA_DONE)
		return -EAGAIN;
	p->stage = NXP_DATA_COPIED;
	return 0;
}

static inline int nxp_data_process(struct nxp_data_progress *p)
{
	if (!p || p->stage != (p->staging ? NXP_DATA_COPIED :
					       NXP_DATA_DMA_DONE))
		return -EAGAIN;
	p->stage = NXP_DATA_PROCESSED;
	return 0;
}

static inline int nxp_data_headers(struct nxp_data_progress *p)
{
	if (!p || p->stage != NXP_DATA_PROCESSED)
		return -EAGAIN;
	p->stage = NXP_DATA_HEADERS_DONE;
	return 0;
}

static inline int nxp_data_publish(struct nxp_data_progress *p)
{
	if (!p || p->stage != NXP_DATA_HEADERS_DONE)
		return -EAGAIN;
	p->stage = NXP_DATA_READY;
	return 0;
}

enum nxp_stat_event {
	NXP_STAT_READ_ISSUED,
	NXP_STAT_READ_OK,
	NXP_STAT_READ_FAILED,
	NXP_STAT_SUBMIT_ERROR,
	NXP_STAT_WAIT_ERROR,
	NXP_STAT_TX_SUBMITTED,
	NXP_STAT_TX_RECLAIMED,
	NXP_STAT_KICK_ERROR,
	NXP_STAT_DROP,
	NXP_STAT_PROTOCOL_ERROR,
};

struct nxp_stats {
	uint64_t read_issued;
	uint64_t read_ok;
	uint64_t read_failed;
	uint64_t submit_errors;
	uint64_t wait_errors;
	uint64_t tx_submitted;
	uint64_t tx_reclaimed;
	uint64_t kick_errors;
	uint64_t drops;
	uint64_t protocol_errors;
};

static inline void nxp_stats_note(struct nxp_stats *stats,
				  enum nxp_stat_event event)
{
	if (!stats)
		return;
	switch (event) {
	case NXP_STAT_READ_ISSUED:
		stats->read_issued++;
		break;
	case NXP_STAT_READ_OK:
		stats->read_ok++;
		break;
	case NXP_STAT_READ_FAILED:
		stats->read_failed++;
		break;
	case NXP_STAT_SUBMIT_ERROR:
		stats->submit_errors++;
		break;
	case NXP_STAT_WAIT_ERROR:
		stats->wait_errors++;
		break;
	case NXP_STAT_TX_SUBMITTED:
		stats->tx_submitted++;
		break;
	case NXP_STAT_TX_RECLAIMED:
		stats->tx_reclaimed++;
		break;
	case NXP_STAT_KICK_ERROR:
		stats->kick_errors++;
		break;
	case NXP_STAT_DROP:
		stats->drops++;
		break;
	case NXP_STAT_PROTOCOL_ERROR:
		stats->protocol_errors++;
		break;
	}
}

#define NXP_RESOURCE_CHAR_FD       (UINT32_C(1) << 0)
#define NXP_RESOURCE_BLOCK_FD      (UINT32_C(1) << 1)
#define NXP_RESOURCE_RING          (UINT32_C(1) << 2)
#define NXP_RESOURCE_FIXED_FILE    (UINT32_C(1) << 3)
#define NXP_RESOURCE_UMEM_MAP      (UINT32_C(1) << 4)
#define NXP_RESOURCE_FIXED_BUFFER  (UINT32_C(1) << 5)
#define NXP_RESOURCE_UMEM          (UINT32_C(1) << 6)
#define NXP_RESOURCE_XSK           (UINT32_C(1) << 7)

static inline uint32_t nxp_cleanup_next(uint32_t live)
{
	static const uint32_t reverse_order[] = {
		NXP_RESOURCE_FIXED_BUFFER,
		NXP_RESOURCE_XSK,
		NXP_RESOURCE_UMEM,
		NXP_RESOURCE_UMEM_MAP,
		NXP_RESOURCE_FIXED_FILE,
		NXP_RESOURCE_RING,
		NXP_RESOURCE_BLOCK_FD,
		NXP_RESOURCE_CHAR_FD,
	};

	for (size_t i = 0; i < sizeof(reverse_order) / sizeof(reverse_order[0]); i++)
		if (live & reverse_order[i])
			return reverse_order[i];
	return 0;
}

static inline bool nxp_iopoll_proven(uint64_t controller_poll_queues,
				     uint64_t namespace_io_poll)
{
	return controller_poll_queues > 0 && namespace_io_poll == 1;
}

/* ---- rx-write receive summary (the PIPELINE_RX_SUMMARY line) ----
 *
 * The NIC->NVMe A/B compares this receiver with the traditional UDP recv() ->
 * O_DIRECT write receiver, tools/xdev_ext_sendpath_baseline.c, whose
 * SENDPATH_BASELINE_SUMMARY line uses the same definitions:
 *
 *   groups, bytes_written  groups whose write completed successfully, and
 *                          their bytes;
 *   packets_accepted       packets accepted into group reassembly;
 *   packets_dropped        every other packet examined, so that accepted +
 *                          dropped = packets examined;
 *   write_errors           groups whose write failed: not accepted at
 *                          submission, or completed with an error;
 *   group service time     CLOCK_MONOTONIC from the first accepted packet of a
 *                          group to that group's successful write completion;
 *                          p50/p99 are nearest rank, rank = ceil(p * n / 100),
 *                          over the completed groups;
 *   cpu_user_us/sys_us     getrusage(RUSAGE_SELF) difference across the
 *                          receive loop;
 *   wall_us                first packet examined (accepted or dropped) to the
 *                          last completion, or to the end of the receive loop
 *                          when nothing completed;
 *   nvme_cmds              NVMe WRITE commands accepted by the kernel;
 *   max_inflight           the most of those accepted and not yet completed
 *                          at the same time.
 *
 * Three frame-retirement fields follow; the baseline has no UMEM frames and
 * no counterpart:
 *
 *   frames_received        RX frames the loop took off the RX ring (each
 *                          FILL -> RECEIVED transition);
 *   frames_returned        RX frames the loop released again (each RECEIVED
 *                          -> FREE drop and IO -> FREE recycle);
 *   frames_outstanding     the census when the loop ends: frames still
 *                          RECEIVED or IO, which the program never released.
 *                          Any, or counters that do not add up to it, fail
 *                          the run with -EPROTO.
 *
 * Four arrival fields follow, with the same definitions in the baseline's
 * line.  A packet's arrival is the clock the receiver reads for it before
 * examining it, and a group arrives with the packet that completes it:
 *
 *   rx_span_us             first packet examined (the start of wall_us) to
 *                          the arrival of the last group to arrive; 0 when no
 *                          group arrived;
 *   tail_us                that arrival to the end of wall_us, 0 when the end
 *                          is not later; rx_span_us + tail_us is wall_us to
 *                          within the truncation to whole microseconds;
 *   group post-arrival     CLOCK_MONOTONIC from a group's arrival to that
 *   time                   group's successful write completion; p50/p99
 *                          (group_post_arrival_us_p50/_p99) are nearest rank
 *                          over the completed groups, as the service time.
 *
 * Every A/B receiver is fed by the same open-loop sender, so wall_us cannot
 * be shorter than the span of that sender's packets: rx_span_us records that
 * span as the receiver saw it, and the post-arrival time leaves it out.
 *
 * Everything here is I/O-free: callers pass timestamps and CPU times in, and
 * the line is formatted into a caller-supplied buffer.  <sys/resource.h> is
 * included only so that callers have struct rusage for the CPU samples. */

#define NXP_RX_SUMMARY_TAG "PIPELINE_RX_SUMMARY"
/* The tag and nineteen fields with 20-digit values need 704 bytes. */
#define NXP_RX_SUMMARY_LINE_MAX 768

/* When the first accepted packet of the group collecting in one slot was
 * seen, and when the group arrived.  The next group in the slot re-arms it
 * with its own first accepted packet, which also clears the arrival, and a
 * completion consumes both, so a group is sampled at most once and an
 * expired or failed group is never sampled. */
struct nxp_rx_group_clock {
	uint64_t first_accept_ns;
	bool armed;
	uint64_t arrival_ns;
	bool arrived;
};

struct nxp_rx_summary {
	uint64_t groups;
	uint64_t packets_accepted;
	uint64_t packets_dropped;
	uint64_t bytes_written;
	uint64_t write_errors;
	uint64_t nvme_cmds;
	uint64_t inflight;
	uint64_t max_inflight;
	uint64_t frames_received;
	uint64_t frames_returned;
	uint64_t frames_outstanding;
	uint64_t first_rx_ns;
	uint64_t end_ns;
	bool first_rx_seen;
	bool end_seen;
	uint64_t *service_ns;		/* caller-owned, service_capacity entries */
	size_t service_capacity;
	size_t service_count;
	struct nxp_rx_group_clock *clocks; /* caller-owned, one per slot */
	size_t clock_count;
	uint64_t last_arrival_ns;
	bool last_arrival_seen;
	uint64_t *post_arrival_ns;	/* caller-owned, may be NULL */
	size_t post_arrival_capacity;
	size_t post_arrival_count;
};

/* The values printed on the line, in line order. */
struct nxp_rx_summary_report {
	uint64_t groups;
	uint64_t packets_accepted;
	uint64_t packets_dropped;
	uint64_t bytes_written;
	uint64_t write_errors;
	uint64_t cpu_user_us;
	uint64_t cpu_sys_us;
	uint64_t wall_us;
	uint64_t group_service_us_p50;
	uint64_t group_service_us_p99;
	uint64_t nvme_cmds;
	uint64_t max_inflight;
	uint64_t frames_received;
	uint64_t frames_returned;
	uint64_t frames_outstanding;
	uint64_t rx_span_us;
	uint64_t tail_us;
	uint64_t group_post_arrival_us_p50;
	uint64_t group_post_arrival_us_p99;
};

static inline int nxp_rx_summary_init(struct nxp_rx_summary *s,
				      uint64_t *service_ns,
				      size_t service_capacity,
				      struct nxp_rx_group_clock *clocks,
				      size_t clock_count)
{
	if (!s || !service_ns || !clocks || !clock_count)
		return -EINVAL;
	memset(s, 0, sizeof(*s));
	memset(clocks, 0, clock_count * sizeof(*clocks));
	s->service_ns = service_ns;
	s->service_capacity = service_capacity;
	s->clocks = clocks;
	s->clock_count = clock_count;
	return 0;
}

/* Record the post-arrival samples in post_arrival_ns (caller-owned, capacity
 * entries).  nxp_rx_summary_init() clears this; without it the post-arrival
 * percentiles are 0. */
static inline int
nxp_rx_summary_track_post_arrival(struct nxp_rx_summary *s,
				  uint64_t *post_arrival_ns, size_t capacity)
{
	if (!s || !post_arrival_ns)
		return -EINVAL;
	s->post_arrival_ns = post_arrival_ns;
	s->post_arrival_capacity = capacity;
	s->post_arrival_count = 0;
	return 0;
}

/* The first packet examined, accepted or dropped, starts the wall clock. */
static inline void nxp_rx_summary_note_rx(struct nxp_rx_summary *s,
					  uint64_t now_ns)
{
	if (!s || s->first_rx_seen)
		return;
	s->first_rx_seen = true;
	s->first_rx_ns = now_ns;
}

/* Called exactly once for every packet examined. */
static inline void nxp_rx_summary_note_packet(struct nxp_rx_summary *s,
					      bool accepted)
{
	if (!s)
		return;
	if (accepted)
		s->packets_accepted++;
	else
		s->packets_dropped++;
}

/* The first packet of the group collecting in slot was accepted at
 * first_accept_ns; this replaces whatever an earlier group left. */
static inline int nxp_rx_summary_arm_group(struct nxp_rx_summary *s,
					   uint32_t slot,
					   uint64_t first_accept_ns)
{
	if (!s || !s->clocks)
		return -EINVAL;
	if (slot >= s->clock_count)
		return -ERANGE;
	s->clocks[slot].first_accept_ns = first_accept_ns;
	s->clocks[slot].armed = true;
	s->clocks[slot].arrived = false;
	return 0;
}

/* The group collecting in slot arrived at arrival_ns: the arrival of the
 * packet that completed it.  The latest arrival ends rx_span_us, and this one
 * starts the group's post-arrival time. */
static inline int nxp_rx_summary_note_group_arrived(struct nxp_rx_summary *s,
						    uint32_t slot,
						    uint64_t arrival_ns)
{
	if (!s || !s->clocks)
		return -EINVAL;
	if (slot >= s->clock_count)
		return -ERANGE;
	s->clocks[slot].arrival_ns = arrival_ns;
	s->clocks[slot].arrived = true;
	s->last_arrival_ns = arrival_ns;
	s->last_arrival_seen = true;
	return 0;
}

/* count NVMe WRITE commands were accepted by the kernel. */
static inline void nxp_rx_summary_note_submitted(struct nxp_rx_summary *s,
						 uint64_t count)
{
	if (!s)
		return;
	s->nvme_cmds += count;
	s->inflight += count;
	if (s->inflight > s->max_inflight)
		s->max_inflight = s->inflight;
}

/* count complete groups whose WRITE was not accepted by the kernel. */
static inline void nxp_rx_summary_note_submit_failed(struct nxp_rx_summary *s,
						     uint64_t count)
{
	if (s)
		s->write_errors += count;
}

/* The NVMe WRITE CQE of the group in slot was reaped at *now_ns (NULL when no
 * time could be read).  Every completion, failed or not, moves the end of the
 * wall clock; only a successful one is written and sampled: its service time
 * when its first accepted packet armed the slot's clock, and its post-arrival
 * time when its arrival was recorded. */
static inline int nxp_rx_summary_note_completion(struct nxp_rx_summary *s,
						 uint32_t slot, bool success,
						 uint64_t bytes,
						 const uint64_t *now_ns)
{
	struct nxp_rx_group_clock *clock;
	bool armed, arrived;

	if (!s || !s->clocks)
		return -EINVAL;
	if (slot >= s->clock_count)
		return -ERANGE;
	if (!s->inflight)
		return -EPROTO;
	clock = &s->clocks[slot];
	armed = clock->armed;
	clock->armed = false;
	arrived = clock->arrived;
	clock->arrived = false;
	s->inflight--;
	if (now_ns) {
		s->end_ns = *now_ns;
		s->end_seen = true;
	}
	if (!success) {
		s->write_errors++;
		return 0;
	}
	s->groups++;
	s->bytes_written += bytes;
	if (armed && now_ns && s->service_ns &&
	    s->service_count < s->service_capacity)
		s->service_ns[s->service_count++] =
			*now_ns > clock->first_accept_ns ?
			*now_ns - clock->first_accept_ns : 0;
	if (arrived && now_ns && s->post_arrival_ns &&
	    s->post_arrival_count < s->post_arrival_capacity)
		s->post_arrival_ns[s->post_arrival_count++] =
			*now_ns > clock->arrival_ns ?
			*now_ns - clock->arrival_ns : 0;
	return 0;
}

/* One RX frame moved FILL -> RECEIVED. */
static inline void nxp_rx_summary_note_frame_received(struct nxp_rx_summary *s)
{
	if (s)
		s->frames_received++;
}

/* One RX frame moved RECEIVED -> FREE or IO -> FREE. */
static inline void nxp_rx_summary_note_frame_returned(struct nxp_rx_summary *s)
{
	if (s)
		s->frames_returned++;
}

/* Record the census taken when the loop ended.  Every frame received must
 * have been returned exactly once: -EPROTO when a frame is still outstanding,
 * or when the counted transitions do not add up to the census. */
static inline int
nxp_rx_summary_note_census(struct nxp_rx_summary *s,
			   const struct nxp_rx_frame_census *census)
{
	uint64_t outstanding;

	if (!s || !census)
		return -EINVAL;
	outstanding = nxp_rx_frame_census_outstanding(census);
	s->frames_outstanding = outstanding;
	if (outstanding || s->frames_returned > s->frames_received ||
	    s->frames_received - s->frames_returned != outstanding)
		return -EPROTO;
	return 0;
}

/* The receive loop ended at now_ns: the wall clock ends here only when no
 * completion was seen. */
static inline void nxp_rx_summary_note_loop_end(struct nxp_rx_summary *s,
						uint64_t now_ns)
{
	if (!s || s->end_seen)
		return;
	s->end_ns = now_ns;
	s->end_seen = true;
}

static inline int nxp_u64_compare(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static inline void nxp_sort_u64(uint64_t *values, size_t count)
{
	if (values && count > 1)
		qsort(values, count, sizeof(*values), nxp_u64_compare);
}

/* Nearest-rank percentile of an ascending array: rank = ceil(p * n / 100),
 * with p clamped to 100 and rank at least 1; 0 when there are no samples. */
static inline uint64_t nxp_nearest_rank(const uint64_t *sorted, size_t count,
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

static inline uint64_t nxp_timeval_us(const struct timeval *tv)
{
	if (!tv || tv->tv_sec < 0 || tv->tv_usec < 0)
		return 0;
	return (uint64_t)tv->tv_sec * UINT64_C(1000000) +
	       (uint64_t)tv->tv_usec;
}

static inline uint64_t nxp_cpu_delta_us(uint64_t start_us, uint64_t end_us)
{
	return end_us > start_us ? end_us - start_us : 0;
}

/* Derive the printed values.  Sorts the recorded service and post-arrival
 * times in place. */
static inline int nxp_rx_summary_report(struct nxp_rx_summary *s,
					uint64_t cpu_user_us,
					uint64_t cpu_sys_us,
					struct nxp_rx_summary_report *out)
{
	size_t samples;

	if (!s || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->groups = s->groups;
	out->packets_accepted = s->packets_accepted;
	out->packets_dropped = s->packets_dropped;
	out->bytes_written = s->bytes_written;
	out->write_errors = s->write_errors;
	out->cpu_user_us = cpu_user_us;
	out->cpu_sys_us = cpu_sys_us;
	out->nvme_cmds = s->nvme_cmds;
	out->max_inflight = s->max_inflight;
	out->frames_received = s->frames_received;
	out->frames_returned = s->frames_returned;
	out->frames_outstanding = s->frames_outstanding;
	if (s->first_rx_seen && s->end_seen && s->end_ns > s->first_rx_ns)
		out->wall_us = (s->end_ns - s->first_rx_ns) / UINT64_C(1000);
	if (s->first_rx_seen && s->last_arrival_seen &&
	    s->last_arrival_ns > s->first_rx_ns)
		out->rx_span_us =
			(s->last_arrival_ns - s->first_rx_ns) / UINT64_C(1000);
	if (s->last_arrival_seen && s->end_seen &&
	    s->end_ns > s->last_arrival_ns)
		out->tail_us = (s->end_ns - s->last_arrival_ns) / UINT64_C(1000);
	samples = s->service_count < s->service_capacity ?
		  s->service_count : s->service_capacity;
	if (samples && s->service_ns) {
		nxp_sort_u64(s->service_ns, samples);
		out->group_service_us_p50 =
			nxp_nearest_rank(s->service_ns, samples, 50) /
			UINT64_C(1000);
		out->group_service_us_p99 =
			nxp_nearest_rank(s->service_ns, samples, 99) /
			UINT64_C(1000);
	}
	samples = s->post_arrival_count < s->post_arrival_capacity ?
		  s->post_arrival_count : s->post_arrival_capacity;
	if (samples && s->post_arrival_ns) {
		nxp_sort_u64(s->post_arrival_ns, samples);
		out->group_post_arrival_us_p50 =
			nxp_nearest_rank(s->post_arrival_ns, samples, 50) /
			UINT64_C(1000);
		out->group_post_arrival_us_p99 =
			nxp_nearest_rank(s->post_arrival_ns, samples, 99) /
			UINT64_C(1000);
	}
	return 0;
}

/* Format the line, without a trailing newline.  Returns its length. */
static inline int nxp_rx_summary_format(const struct nxp_rx_summary_report *r,
					char *buf, size_t size)
{
	int len;

	if (!r || !buf || !size)
		return -EINVAL;
	len = snprintf(buf, size,
		       NXP_RX_SUMMARY_TAG " groups=%llu packets_accepted=%llu "
		       "packets_dropped=%llu bytes_written=%llu "
		       "write_errors=%llu cpu_user_us=%llu cpu_sys_us=%llu "
		       "wall_us=%llu group_service_us_p50=%llu "
		       "group_service_us_p99=%llu nvme_cmds=%llu "
		       "max_inflight=%llu frames_received=%llu "
		       "frames_returned=%llu frames_outstanding=%llu "
		       "rx_span_us=%llu tail_us=%llu "
		       "group_post_arrival_us_p50=%llu "
		       "group_post_arrival_us_p99=%llu",
		       (unsigned long long)r->groups,
		       (unsigned long long)r->packets_accepted,
		       (unsigned long long)r->packets_dropped,
		       (unsigned long long)r->bytes_written,
		       (unsigned long long)r->write_errors,
		       (unsigned long long)r->cpu_user_us,
		       (unsigned long long)r->cpu_sys_us,
		       (unsigned long long)r->wall_us,
		       (unsigned long long)r->group_service_us_p50,
		       (unsigned long long)r->group_service_us_p99,
		       (unsigned long long)r->nvme_cmds,
		       (unsigned long long)r->max_inflight,
		       (unsigned long long)r->frames_received,
		       (unsigned long long)r->frames_returned,
		       (unsigned long long)r->frames_outstanding,
		       (unsigned long long)r->rx_span_us,
		       (unsigned long long)r->tail_us,
		       (unsigned long long)r->group_post_arrival_us_p50,
		       (unsigned long long)r->group_post_arrival_us_p99);
	if (len < 0)
		return -EIO;
	if ((size_t)len >= size)
		return -ENOSPC;
	return len;
}

#endif /* NVME_XDP_PIPELINE_CORE_H */
