/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Fixture interface shared by chain_boundary.c (XDOMAIN stack environment,
 * lease provider, link, scheduler), chain_nvme_glue.c (NVMe controller
 * model) and cases.c (independent assertions).  Only plain C types cross;
 * kernel objects of another unit are opaque pointers.
 */
#ifndef CHAIN_API_H
#define CHAIN_API_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum chain_device_kind { CHAIN_DEV_NVME = 1, CHAIN_DEV_NHI = 2 };
#define CHAIN_ENDPOINTS 2
#define CHAIN_PAGE 4096u

/* Every DMA address the lease provider hands out lies in one requester's
 * window; a page of the endpoint's frame memory appears there at a
 * permuted position, so contiguity across pages is never implied. */
struct chain_window { uint64_t base; uint32_t pages; };

/* Lease provider and device memory (chain_boundary.c). */
void chain_register_device(const void *device, unsigned endpoint, enum chain_device_kind kind);
int chain_dma_access(const void *device, uint64_t dma, void *buf, uint32_t len, bool device_writes);
uint8_t *chain_frame_memory(unsigned endpoint, size_t *bytes);
uint64_t chain_device_dma(unsigned endpoint, enum chain_device_kind kind, uint64_t offset);

/* NVMe controller model (chain_nvme_glue.c). */
struct chain_nvme_command {
	unsigned endpoint;
	uint8_t opcode;
	uint64_t slba;
	uint32_t nlb, bytes;
	uint32_t spans;
	uint64_t span_addr[64];
	uint32_t span_len[64];
	uint64_t order;     /* submission order on this controller */
	uint64_t worker;    /* core worker running when it was submitted */
};
void *chain_nvme_create(unsigned endpoint, uint32_t lba_shift, uint64_t lbas, bool write_open,
			void **file_out);
uint8_t *chain_nvme_disk(unsigned endpoint, size_t *bytes);
void chain_nvme_hold(unsigned endpoint, bool hold);
bool chain_nvme_ready(void);
int chain_nvme_complete_one(void);
unsigned chain_nvme_pending(unsigned endpoint);
size_t chain_nvme_log_count(void);
const struct chain_nvme_command *chain_nvme_log(size_t i);
void chain_nvme_init_class(void);

/* Composite world and scheduler (chain_boundary.c). */
struct xdev_ext_mech_session;
/* window_tx/window_rx: groups each XDOMAIN stage may keep in flight, passed in
 * bits 32..63 of the stage's arg1 (0 = the stage default, one group). */
struct chain_link_config { uint32_t frame_size, nr_frames, depth, group_bytes; bool early;
			   uint32_t window_tx, window_rx; };
int chain_world(const struct chain_link_config *cfg);
int chain_pump(unsigned budget, uint64_t advance_ns);
uint64_t chain_link_token(unsigned endpoint);
struct xdev_ext_mech_session *chain_tx_session(int *err, uint64_t token_override);
struct xdev_ext_mech_session *chain_rx_session(int *err);
int chain_start(struct xdev_ext_mech_session *s, uint64_t batches, uint64_t first_seq);
void chain_hold_tx_completions(unsigned endpoint, bool hold);
void chain_hold_ack(unsigned endpoint, bool hold);
/* Hold @endpoint's outgoing control messages of one wire type on the wire. */
void chain_hold_control(unsigned endpoint, unsigned type, bool hold);
int chain_inject_stale_control(unsigned from_endpoint, unsigned type, uint64_t nth);
unsigned chain_worker_of(struct xdev_ext_mech_session *s);

/* Observations recorded at real boundaries (chain_boundary.c). */
enum chain_event_kind {
	CHAIN_EV_NVME_SUBMIT = 1,   /* blk_execute_rq_nowait of a real NVMe command */
	CHAIN_EV_NVME_COMPLETE,     /* the controller model called end_io */
	CHAIN_EV_DATA_TX_POST,      /* real X4 posted a data-ring TX frame */
	CHAIN_EV_DATA_RX_POST,
	CHAIN_EV_DATA_TX_DONE,      /* real NHI TX callback of a data frame */
	CHAIN_EV_DATA_DELIVER,      /* link model copied TX bytes into an RX buffer */
	CHAIN_EV_CTL_TX,            /* control ring message accepted for TX */
	CHAIN_EV_CTL_RX,            /* control ring message delivered */
	CHAIN_EV_WORKER,            /* a core kthread work function ran */
	CHAIN_EV_LEASE,             /* lease provider acquire */
	CHAIN_EV_RELEASE,           /* lease provider release */
	CHAIN_EV_PROGRAM,           /* program member invoked */
	CHAIN_EV_START,             /* fixture START */
	CHAIN_EV_INJECT,            /* injected duplicate control bytes */
};
struct chain_event {
	uint64_t id, now_ns;
	uint32_t kind, endpoint, worker, stage, member, control_type;
	uint64_t address, length, group, offset, session;
	int32_t status;
	bool quiesced;
	const void *device;
	uint32_t wire;      /* DATA_DELIVER: 1-based slot of the bytes the link carried */
};
void chain_record(struct chain_event e);
size_t chain_event_count(void);
unsigned chain_control_tx_count(unsigned endpoint, unsigned type);
unsigned chain_data_tx_done(unsigned endpoint);
const void *chain_device(unsigned endpoint, enum chain_device_kind kind);
unsigned chain_violations(void);
unsigned chain_live_leases(unsigned endpoint, enum chain_device_kind kind, uint64_t offset, uint32_t len);
const void *chain_stage_requester(struct xdev_ext_mech_session *s, unsigned stage);
bool chain_real_peer_mode(void);
bool chain_stage_admission(struct xdev_ext_mech_session *s, unsigned stage, uint32_t *backing,
			   uint32_t *reachability, uint32_t *refused);
const struct chain_event *chain_event_get(size_t i);
/* The bytes a DATA_DELIVER event carried, as read from the sender's frame memory. */
const uint8_t *chain_delivered_bytes(const struct chain_event *e);
#endif
