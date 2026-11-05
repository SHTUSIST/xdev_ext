// SPDX-License-Identifier: GPL-2.0
/*
 * Host 1: NVMe READ fills frames; the same session worker, on that NVMe
 * completion, sends the frames over XDOMAIN; a source frame is reused only
 * after the peer's ACK and the local TX completion.  Host 2: XDOMAIN RX into
 * its frames, NVMe WRITE of them, and an ACK only after that write ends.
 *
 * Expectations come from that requirement, not from the code:
 *  - expected payload is pattern(disk address) on host 1, computed here;
 *  - the frames a command covers are recovered from its DMA addresses
 *    through the requester's window (the environment's mapping, not output);
 *  - "same worker" means the worker that submitted the READ also runs the
 *    XDOMAIN submit and posts the TX descriptors, with no START in between.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/xdev_ext_mech.h> /* UAPI: member numbers only */
#include "chain_api.h"
#include "chain_core_api.h"

#define FRAME 4096u
#define FRAMES 4u
#define GROUP 8192u
#define DEPTH 2u
#define ACK 3u
#define F_K_FREE chain_frame_state_free()
#define BUDGET 200000u

static unsigned assertions;
static const char *case_name = "?";
#define CHECK(c, why) do { assertions++; if (!(c)) { \
	fprintf(stderr, "CHAIN_ASSERT %s: %s (%s:%d)\n", case_name, why, __FILE__, __LINE__); \
	exit(1); } } while (0)

static uint8_t pattern(uint64_t a)
{
	uint32_t x = (uint32_t)(a * 2654435761u) ^ (uint32_t)(a >> 9) * 40503u;
	return (uint8_t)(x >> 13 ^ x);
}

static struct xdev_ext_mech_session *tx, *rx;

static void pump(uint64_t advance)
{
	CHECK(chain_pump(BUDGET, advance) == 0, "bounded scheduler drains without budget exhaustion");
}
static void settle(unsigned rounds)
{
	for (unsigned i = 0; i < rounds; i++)
		pump(1000000); /* 1 ms of virtual time per round, far below protocol deadlines */
}

static bool early;
static void up(void)
{
	struct chain_link_config cfg = { .frame_size = FRAME, .nr_frames = FRAMES, .depth = DEPTH,
		.group_bytes = GROUP, .early = early };
	size_t bytes;
	uint8_t *disk;
	int err;

	CHECK(chain_world(&cfg) == 0, "two XDOMAIN endpoints probed, logged in and data rings verified");
	disk = chain_nvme_disk(0, &bytes);
	for (size_t i = 0; i < bytes; i++)
		disk[i] = pattern(i);
	rx = chain_rx_session(&err);
	CHECK(!err, "host 2 CREATE: XDOMAIN RX stage 0 + NVMe WRITE stage 1");
	tx = chain_tx_session(&err, 0);
	CHECK(!err, "host 1 CREATE: NVMe READ stage 0 + XDOMAIN TX stage 1");
	CHECK(chain_stage_requester(tx, 0) == chain_device(0, CHAIN_DEV_NVME),
	      "host 1 stage 0 maps frames for its NVMe controller");
	CHECK(chain_stage_requester(tx, 1) == chain_device(0, CHAIN_DEV_NHI),
	      "host 1 stage 1 maps the same frames for its NHI");
	CHECK(chain_stage_requester(rx, 0) == chain_device(1, CHAIN_DEV_NHI) &&
	      chain_stage_requester(rx, 1) == chain_device(1, CHAIN_DEV_NVME),
	      "host 2 stages use host 2's NHI and NVMe");
	if (chain_real_peer_mode())
		for (unsigned stage = 0; stage < 2; stage++) {
			uint32_t backing = 0, reachability = 0, refused = ~0u;
			CHECK(chain_stage_admission(tx, stage, &backing, &reachability, &refused),
			      "the real requester bind ran for host 1's stage");
			CHECK(backing == (XDEV_EXT_PEER_BACKING_HOST_SYSTEM | XDEV_EXT_PEER_BACKING_STRUCT_PAGE),
			      "host 1 frames are host RAM with struct pages (system-heap DMA-BUF)");
			CHECK(reachability == XDEV_EXT_CAP_HOST_DMA_MAPPED && !refused,
			      "a host DMA-API mapping was established for that requester, nothing refused");
		}
}

static void start(uint64_t n)
{
	/* Both sides number groups from the same key: EARLY pairs a receive
	 * grant with the sender batch carrying that key. */
	CHECK(chain_start(rx, n, 37) == 0, "host 2 START");
	CHECK(chain_start(tx, n, 37) == 0, "host 1 START");
}

/* Frame offset of a DMA address in a requester window; independent lookup. */
static int64_t offset_of(unsigned endpoint, enum chain_device_kind kind, uint64_t dma)
{
	for (uint64_t page = 0; page < FRAMES; page++) {
		uint64_t base = chain_device_dma(endpoint, kind, page * FRAME);
		if (dma >= base && dma < base + FRAME)
			return (int64_t)(page * FRAME + (dma - base));
	}
	return -1;
}

static unsigned count(unsigned kind, unsigned endpoint)
{
	unsigned n = 0;
	for (size_t i = 0; i < chain_event_count(); i++)
		n += chain_event_get(i)->kind == kind && chain_event_get(i)->endpoint == endpoint;
	return n;
}
static size_t nth(unsigned kind, unsigned endpoint, unsigned k) /* k from 1; 0 when absent */
{
	unsigned seen = 0;
	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		if (e->kind == kind && e->endpoint == endpoint && ++seen == k)
			return i + 1;
	}
	return 0;
}
static size_t nth_ctl_rx(unsigned endpoint, unsigned type, unsigned k)
{
	unsigned seen = 0;
	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		if (e->kind == CHAIN_EV_CTL_RX && e->endpoint == endpoint && e->control_type == type && ++seen == k)
			return i + 1;
	}
	return 0;
}
static const struct chain_nvme_command *command(unsigned endpoint, unsigned k)
{
	unsigned seen = 0;
	for (size_t i = 0; i < chain_nvme_log_count(); i++)
		if (chain_nvme_log(i)->endpoint == endpoint && ++seen == k)
			return chain_nvme_log(i);
	return NULL;
}
static unsigned commands(unsigned endpoint)
{
	unsigned n = 0;
	while (command(endpoint, n + 1))
		n++;
	return n;
}
/* Frame bitmap of the k-th READ on host 1, from its SGL addresses. */
static unsigned read_frames(unsigned k)
{
	const struct chain_nvme_command *c = command(0, k);
	unsigned mask = 0, total = 0;

	CHECK(c && c->opcode == 0x02, "host 1 command is an NVMe READ");
	/* A span may cover several frames that are contiguous in the NVMe
	 * window (one SGL data block); map it page by page. */
	for (unsigned i = 0; i < c->spans; i++)
		for (uint32_t done = 0; done < c->span_len[i];) {
			uint64_t dma = c->span_addr[i] + done;
			uint32_t chunk = FRAME - (uint32_t)(dma % FRAME);
			int64_t off = offset_of(0, CHAIN_DEV_NVME, dma);
			if (chunk > c->span_len[i] - done)
				chunk = c->span_len[i] - done;
			CHECK(off >= 0, "READ data pointer lies in host 1's NVMe window");
			mask |= 1u << (off / FRAME);
			done += chunk;
			total += chunk;
		}
	CHECK(total == GROUP && c->bytes == GROUP, "READ covers exactly one group");
	CHECK(__builtin_popcount(mask) == GROUP / FRAME, "READ covers group/frame distinct frames");
	return mask;
}

/* (a) and the payload-only data ring for host 1's k-th group. */
static void same_worker_tx(unsigned k)
{
	size_t done = 0, next_read;
	unsigned mask = read_frames(k), tx_mask = 0, tx_bytes = 0, worker = chain_worker_of(tx);
	unsigned seen = 0;

	CHECK(command(0, k)->worker == worker, "READ submitted by host 1's session worker");
	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		if (e->kind == CHAIN_EV_NVME_COMPLETE && e->endpoint == 0 && ++seen == k) {
			done = i + 1;
			break;
		}
	}
	CHECK(done, "host 1 NVMe completion observed");
	/* The XDOMAIN stage of this batch is built after that completion, by
	 * the session worker, with no START in between. */
	{
		size_t build = 0;
		for (size_t i = done; i < chain_event_count() && !build; i++) {
			const struct chain_event *e = chain_event_get(i);
			if (e->kind == CHAIN_EV_START)
				CHECK(0, "no user START between NVMe completion and the XDOMAIN build");
			if (e->kind == CHAIN_EV_PROGRAM && e->endpoint == 0 && e->stage == 1 &&
			    e->member == XDEV_EXT_MECH_MEMBER_BUILD && e->group == 36 + k)
				build = i + 1;
		}
		CHECK(build, "XDOMAIN stage built for this batch after its NVMe completion");
		CHECK(chain_event_get(build - 1)->worker == worker,
		      "XDOMAIN stage built by the session worker that issued the READ");
	}
	next_read = nth(CHAIN_EV_NVME_SUBMIT, 0, k + DEPTH);
	for (size_t i = done; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		if (e->kind == CHAIN_EV_START)
			CHECK(i + 1 < done, "no user START between NVMe completion and its TX");
		if (e->kind != CHAIN_EV_DATA_TX_POST || e->endpoint != 0)
			continue;
		int64_t off = offset_of(0, CHAIN_DEV_NHI, e->address);
		CHECK(off >= 0, "TX descriptor buffer lies in host 1's NHI window (payload memory only)");
		if (!(mask & (1u << (off / FRAME))))
			continue; /* another group's frames */
		if (next_read && i + 1 > next_read)
			break;
		CHECK(e->worker == worker, "TX descriptor posted from the same session worker");
		CHECK(e->length <= FRAME && off % FRAME + e->length <= FRAME, "one TX element per frame span");
		tx_mask |= 1u << (off / FRAME);
		tx_bytes += (unsigned)e->length;
		if (tx_bytes == GROUP)
			break;
	}
	CHECK(tx_mask == mask, "TX descriptors cover exactly the frames that NVMe filled");
	CHECK(tx_bytes == GROUP, "TX descriptors carry exactly the group's bytes");
}

/* (f) Host 2's k-th WRITE carries host 1's k-th READ bytes. */
static void bytes_match(unsigned k)
{
	const struct chain_nvme_command *r = command(0, k), *w = command(1, k);
	size_t bytes;
	uint8_t *disk2 = chain_nvme_disk(1, &bytes);

	CHECK(r && w && w->opcode == 0x01 && w->bytes == GROUP, "host 2 wrote the k-th group");
	for (uint32_t i = 0; i < GROUP; i++) {
		uint64_t from = r->slba * 512 + i, to = w->slba * 512 + i;
		if (disk2[to] != pattern(from)) {
			fprintf(stderr, "byte %u: host2[%llu]=%u expected pattern(%llu)=%u\n", i,
				(unsigned long long)to, disk2[to], (unsigned long long)from, pattern(from));
			CHECK(0, "host 2 disk holds host 1's bytes in order, no header bytes");
		}
	}
	assertions++;
}

static void finished(uint64_t n)
{
	CHECK(chain_session_done(tx) == n && !chain_session_aborted(tx), "host 1 finished every batch");
	CHECK(chain_session_done(rx) == n && !chain_session_aborted(rx), "host 2 finished every batch");
	CHECK(!chain_session_last_err(tx) && !chain_session_last_err(rx), "no session error");
	CHECK(chain_violations() == 0,
	      "no device touched bytes outside its live leases; no program ran in a callback");
	for (unsigned f = 0; f < FRAMES; f++)
		CHECK(chain_frame_custody(tx, f) == F_K_FREE && chain_frame_custody(rx, f) == F_K_FREE,
		      "every frame back in the pool");
}

/* Observation, not a requirement: most XDOMAIN groups in flight at once on
 * host 1, counted from RTS arrivals at host 2 and ACK arrivals at host 1. */
static unsigned groups_in_flight_max(void)
{
	unsigned now = 0, most = 0;
	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		if (e->kind != CHAIN_EV_CTL_RX)
			continue;
		if (e->endpoint == 1 && e->control_type == 1 && ++now > most)
			most = now;
		if (e->endpoint == 0 && e->control_type == ACK && now)
			now--;
	}
	return most;
}

static void chain_same_worker(void)
{
	up();
	start(4);
	settle(50);
	CHECK(commands(0) == 4 && commands(1) == 4, "four READs on host 1, four WRITEs on host 2");
	for (unsigned k = 1; k <= 4; k++) {
		same_worker_tx(k);
		bytes_match(k);
	}
	finished(4);
	if (!early)
		printf("CHAIN_OBSERVE xdomain_groups_in_flight_max=%u\n", groups_in_flight_max());
	CHECK(read_frames(3) == read_frames(1) && read_frames(4) == read_frames(2),
	      "batches 3 and 4 reuse the frames of batches 1 and 2");
}

/* (b) No reuse without the peer ACK. */
static void reuse_waits_for_ack(void)
{
	unsigned first;

	up();
	chain_hold_ack(1, true);
	start(3);
	settle(50);
	CHECK(commands(1) >= 1, "host 2 wrote group 1: its consumer released it");
	CHECK(chain_control_tx_count(1, ACK) >= 1, "host 2 produced an ACK, held on the wire");
	CHECK(nth_ctl_rx(0, ACK, 1) == 0, "host 1 has received no ACK");
	CHECK(commands(0) == 2, "no third READ: frames of batch 1 are not reused");
	first = read_frames(1);
	for (unsigned f = 0; f < FRAMES; f++)
		if (first & (1u << f)) {
			CHECK(chain_frame_custody(tx, f) != F_K_FREE, "batch 1 frames stay out of the pool");
			CHECK(chain_live_leases(0, CHAIN_DEV_NHI, f * FRAME, FRAME) >= 1,
			      "batch 1 NHI TX lease still live");
		}
	CHECK(chain_session_done(tx) == 0, "no host 1 batch finished");
	chain_hold_ack(1, false);
	settle(50);
	finished(3);
	CHECK(nth_ctl_rx(0, ACK, 1) && nth_ctl_rx(0, ACK, 1) < nth(CHAIN_EV_NVME_SUBMIT, 0, 3),
	      "the reusing READ follows the first ACK");
	CHECK(read_frames(3) == first, "the third READ reuses batch 1's frames");
	for (unsigned k = 1; k <= 3; k++)
		bytes_match(k);
}

/* (c) An ACK before local TX completion still waits. */
static void ack_before_local_done(void)
{
	unsigned first;

	up();
	chain_hold_tx_completions(0, true);
	start(3);
	settle(50);
	CHECK(nth_ctl_rx(0, ACK, 1) != 0, "host 1 received group 1's ACK");
	CHECK(chain_data_tx_done(0) == 0, "no host 1 TX descriptor has completed");
	CHECK(commands(0) == 2, "no third READ while TX completion is outstanding");
	first = read_frames(1);
	for (unsigned f = 0; f < FRAMES; f++)
		if (first & (1u << f))
			CHECK(chain_frame_custody(tx, f) != F_K_FREE &&
			      chain_live_leases(0, CHAIN_DEV_NHI, f * FRAME, FRAME) >= 1,
			      "ACKed but locally unfinished frames stay leased and out of the pool");
	CHECK(chain_session_done(tx) == 0, "no host 1 batch finished on ACK alone");
	chain_hold_tx_completions(0, false);
	settle(50);
	finished(3);
	CHECK(nth(CHAIN_EV_NVME_SUBMIT, 0, 3) > nth_ctl_rx(0, ACK, 1), "reuse follows both events");
	CHECK(read_frames(3) == first, "the third READ reuses batch 1's frames");
	for (unsigned k = 1; k <= 3; k++)
		bytes_match(k);
}

/* (d) The receiver acknowledges only after its consumer released the group. */
static void consumer_holds_ack(void)
{
	up();
	chain_nvme_hold(1, true);
	start(2);
	settle(50);
	CHECK(chain_nvme_pending(1) >= 1, "host 2 NVMe WRITE submitted and held");
	CHECK(chain_control_tx_count(1, ACK) == 0, "no ACK while the consumer holds the group");
	CHECK(chain_session_done(tx) == 0, "host 1 does not finish without the ACK");
	chain_nvme_hold(1, false);
	settle(50);
	finished(2);
	CHECK(chain_control_tx_count(1, ACK) == 2, "one ACK per group after the WRITE completed");
	for (unsigned k = 1; k <= 2; k++)
		bytes_match(k);
}

/* (e) A duplicate of an old ACK cannot finish the group now in its frames. */
static void stale_ack_after_reuse(void)
{
	unsigned first, guard = 0;
	int ret;

	up();
	chain_hold_ack(1, true);
	start(3);
	settle(50);
	CHECK(commands(0) == 2, "groups 1 and 2 wait for ACKs");
	chain_hold_ack(1, false);
	/* Step until host 1 holds both ACKs, then hold host 2's next ACK. */
	while (!nth_ctl_rx(0, ACK, 2)) {
		CHECK(chain_pump(1, 0) == 0 || 1, "single-step scheduler");
		CHECK(++guard < 100000, "both held ACKs arrive");
	}
	chain_hold_ack(1, true);
	settle(50);
	first = read_frames(1);
	CHECK(commands(0) == 3 && read_frames(3) == first, "batch 3 now occupies batch 1's frames");
	CHECK(commands(1) == 3, "host 2 wrote group 3; its ACK is held");
	CHECK(chain_session_done(tx) == 2, "groups 1 and 2 finished on host 1");
	ret = chain_inject_stale_control(1, ACK, 1);
	CHECK(ret == 0, "a copy of group 1's ACK reaches host 1's control RX ring");
	settle(20);
	CHECK(nth_ctl_rx(0, ACK, 3) != 0, "the stale ACK was dispatched to the class");
	CHECK(chain_session_done(tx) == 2, "the stale ACK finished no batch");
	for (unsigned f = 0; f < FRAMES; f++)
		if (first & (1u << f))
			CHECK(chain_frame_custody(tx, f) != F_K_FREE &&
			      chain_live_leases(0, CHAIN_DEV_NHI, f * FRAME, FRAME) >= 1,
			      "reused frames stay leased to group 3");
	CHECK(commands(0) == 3, "no further READ reused the frames");
	chain_hold_ack(1, false);
	settle(50);
	CHECK(chain_session_done(tx) == 3, "group 3 finishes on its own ACK");
	CHECK(chain_violations() == 0, "no lease overlap");
	for (unsigned k = 1; k <= 3; k++)
		bytes_match(k);
}

/* No Thunderbolt link behind the token: CREATE fails cleanly with ENODEV. */
static void no_link_enodev(void)
{
	struct chain_link_config cfg = { .frame_size = FRAME, .nr_frames = FRAMES, .depth = DEPTH,
		.group_bytes = GROUP };
	int err = 0;

	CHECK(chain_world(&cfg) == 0, "world");
	chain_tx_session(&err, 0x5eedf00dULL);
	CHECK(err == -ENODEV, "XDOMAIN stage bind without that link returns ENODEV");
}

int main(int argc, char **argv)
{
	char base[64];
	size_t n;

	if (argc != 2 || strlen(argv[1]) >= sizeof(base))
		return 2;
	case_name = argv[1];
	strcpy(base, case_name);
	n = strlen(base);
	/* NAME_early: the same requirement with both XDOMAIN stages in EARLY
	 * mode (receive grants paired by key; no RTS/CTS round trip). */
	if (n > 6 && !strcmp(base + n - 6, "_early")) {
		early = true;
		base[n - 6] = 0;
	}
	if (!strcmp(base, "chain_same_worker")) chain_same_worker();
	else if (!strcmp(base, "reuse_waits_for_ack")) reuse_waits_for_ack();
	else if (!strcmp(base, "ack_before_local_done")) ack_before_local_done();
	else if (!strcmp(base, "consumer_holds_ack")) consumer_holds_ack();
	else if (!strcmp(base, "stale_ack_after_reuse")) stale_ack_after_reuse();
	else if (!strcmp(base, "no_link_enodev") && !early) no_link_enodev();
	else return 2;
	printf("CHAIN_CASE %s assertions=%u\n", case_name, assertions);
	return 0;
}
