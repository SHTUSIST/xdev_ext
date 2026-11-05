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
 *
 * In-flight window (NAME_wN and the window_* cases): each XDOMAIN stage takes
 * a window W in bits 32..63 of its arg1.  The sender keeps at most W groups
 * in flight (announced and not yet finished) and the receiver keeps at most W
 * groups between its RX stage and their final reply, while
 *  - every group still reaches the peer in key order (host 2's k-th WRITE
 *    holds host 1's k-th READ);
 *  - a group's data is posted only into receive buffers the peer posted for
 *    that group, and the peer posts one group's buffers at a time (version 1);
 *  - reuse still waits for the peer's ACK and the local TX completion, and an
 *    old ACK still finishes nothing;
 *  - a window of 1 behaves exactly as no window (the runner compares traces).
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
#define MAX_FRAMES 32u
#define GROUP 8192u
#define RTS 1u
#define CTS 2u
#define ACK 3u
#define FAIL 5u
#define CANCEL 6u
#define F_K_FREE chain_frame_state_free()
#define BUDGET 200000u

static unsigned assertions;
static const char *case_name = "?";
#define CHECK(c, why) do { assertions++; if (!(c)) { \
	fprintf(stderr, "CHAIN_ASSERT %s: %s (%s:%d)\n", case_name, why, __FILE__, __LINE__); \
	exit(1); } } while (0)

/* Session shape of this case; the defaults are the original composition. */
static unsigned depth = 2, frames = 4, window_tx, window_rx;

static uint8_t pattern(uint64_t a)
{
	uint32_t x = (uint32_t)(a * 2654435761u) ^ (uint32_t)(a >> 9) * 40503u;
	return (uint8_t)(x >> 13 ^ x);
}

static struct xdev_ext_mech_session *tx, *rx;

/* Most of each quantity seen between any two scheduler steps. */
static struct { unsigned tx_stage, rx_stage, rx_held; } peak;
static unsigned limit(unsigned w) { return w > 1 ? w : 1; }
static void observe(void)
{
	unsigned tx_stage, rx_stage, rx_held = 0;
	bool aborted;

	if (!tx || !rx)
		return;
	/* Groups host 1 has in flight at its XDOMAIN stage (accepted, not landed). */
	tx_stage = (unsigned)(chain_stage_submitted(tx, 1) - chain_stage_completed(tx, 1));
	/* Groups host 2 has in its XDOMAIN RX stage. */
	rx_stage = (unsigned)(chain_stage_submitted(rx, 0) - chain_stage_completed(rx, 0));
	/* Groups host 2 took in and has not finished (RX stage or consumer);
	 * exact only while no host 2 batch was aborted (an abort may end a batch
	 * that never entered the RX stage). */
	aborted = chain_session_aborted(rx) != 0;
	if (!aborted)
		rx_held = (unsigned)(chain_stage_submitted(rx, 0) - chain_session_done(rx));
	if (tx_stage > peak.tx_stage)
		peak.tx_stage = tx_stage;
	if (rx_stage > peak.rx_stage)
		peak.rx_stage = rx_stage;
	if (rx_held > peak.rx_held)
		peak.rx_held = rx_held;
	CHECK(tx_stage <= limit(window_tx), "host 1 never has more XDOMAIN groups in flight than its window");
	CHECK(rx_stage <= 1, "host 2 has at most one group in its XDOMAIN RX stage (one posted group, version 1)");
	if (window_rx > 1 && !aborted)
		CHECK(rx_held <= window_rx, "host 2 never holds more groups than the window it armed");
}

/* The bounded deterministic scheduler, one step at a time so the window
 * rules hold between any two steps. @advance moves virtual time first. */
static void pump(uint64_t advance)
{
	unsigned steps = 0;

	while (chain_pump(1, advance) == -ELOOP) {
		advance = 0;
		observe();
		CHECK(++steps < BUDGET, "bounded scheduler drains without budget exhaustion");
	}
	observe();
}
static void settle(unsigned rounds)
{
	for (unsigned i = 0; i < rounds; i++)
		pump(1000000); /* 1 ms of virtual time per round, far below protocol deadlines */
}

static bool early;
static void up(void)
{
	struct chain_link_config cfg = { .frame_size = FRAME, .nr_frames = frames, .depth = depth,
		.group_bytes = GROUP, .early = early, .window_tx = window_tx, .window_rx = window_rx };
	size_t bytes;
	uint8_t *disk;
	int err;

	CHECK(frames <= MAX_FRAMES, "case shape fits the oracle tables");
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
	for (uint64_t page = 0; page < frames; page++) {
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
	next_read = nth(CHAIN_EV_NVME_SUBMIT, 0, k + depth);
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

/* (f) at host 1: every byte the link read from host 1's frames for the k-th
 * group is the byte the k-th READ placed at that frame offset, per the oracle
 * of host 1's disk address (the READ's SGL order gives each frame byte's
 * position in the transfer). */
static void sent_bytes_match(unsigned k)
{
	const struct chain_nvme_command *r = command(0, k);
	static uint8_t expect[MAX_FRAMES * FRAME];
	static bool known[MAX_FRAMES * FRAME];
	uint64_t position = 0;
	uint32_t sent = 0;
	size_t done = nth(CHAIN_EV_NVME_COMPLETE, 0, k);

	CHECK(r && r->opcode == 0x02 && r->bytes == GROUP && done, "host 1 read and completed the k-th group");
	memset(known, 0, sizeof(known));
	for (unsigned i = 0; i < r->spans; i++)
		for (uint32_t moved = 0; moved < r->span_len[i];) {
			uint64_t dma = r->span_addr[i] + moved;
			uint32_t chunk = FRAME - (uint32_t)(dma % FRAME);
			int64_t off = offset_of(0, CHAIN_DEV_NVME, dma);
			if (chunk > r->span_len[i] - moved)
				chunk = r->span_len[i] - moved;
			CHECK(off >= 0, "READ data pointer lies in host 1's NVMe window");
			for (uint32_t t = 0; t < chunk; t++) {
				expect[off + t] = pattern(r->slba * 512 + position + t);
				known[off + t] = true;
			}
			position += chunk;
			moved += chunk;
		}
	for (size_t i = done; i < chain_event_count() && sent < GROUP; i++) {
		const struct chain_event *e = chain_event_get(i);
		int64_t off;
		const uint8_t *bytes;

		if (e->kind != CHAIN_EV_DATA_DELIVER || e->endpoint != 0)
			continue;
		off = offset_of(0, CHAIN_DEV_NHI, e->address);
		if (off < 0 || !known[off])
			continue; /* control ring, or another group's frames */
		bytes = chain_delivered_bytes(e);
		CHECK(!e->status && bytes, "the link read host 1's frame and delivered it");
		for (uint32_t t = 0; t < e->length; t++)
			if (off + t >= frames * FRAME || !known[off + t] || bytes[t] != expect[off + t]) {
				fprintf(stderr, "frame offset %lld: sent %u expected %u\n", (long long)(off + t),
					bytes[t], off + t < frames * FRAME ? expect[off + t] : 0);
				CHECK(0, "host 1 sent the bytes its READ placed in those frames");
			}
		sent += (uint32_t)e->length;
	}
	CHECK(sent == GROUP, "the link carried the whole group from host 1's frames");
	assertions++;
}

/* (f) at host 2: host 2's k-th WRITE carries host 1's k-th READ bytes. */
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

/* Receive-side credit, from the record of real data-ring posts: host 1 posts
 * a group's data only after host 2 posted receive buffers for that group, and
 * host 2 posts the next group's buffers only after every buffer it posted
 * before was filled (one posted group per data RX ring, version 1). */
static void credit_rule(void)
{
	uint64_t rx_groups[64], last = 0;
	unsigned nrx = 0, posted = 0, filled = 0;
	bool started = false;

	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);

		if (e->kind == CHAIN_EV_START)
			started = true;
		if (!started)
			continue; /* link start-up verification uses its own scratch buffers */
		if (e->kind == CHAIN_EV_DATA_RX_POST && e->endpoint == 1) {
			if (e->group != last) {
				CHECK(filled == posted,
				      "host 2 posts a group's receive buffers only after its earlier ones were filled");
				CHECK(nrx < 64, "bounded group record");
				rx_groups[nrx++] = last = e->group;
			}
			posted++;
		}
		if (e->kind == CHAIN_EV_DATA_DELIVER && e->endpoint == 0 && !e->status &&
		    offset_of(1, CHAIN_DEV_NHI, e->offset) >= 0)
			filled++;
		if (e->kind == CHAIN_EV_DATA_TX_POST && e->endpoint == 0) {
			bool armed = false;
			for (unsigned g = 0; g < nrx; g++)
				armed |= rx_groups[g] == e->group;
			CHECK(armed, "host 1 posts a group's data only into buffers host 2 posted for that group");
		}
	}
	CHECK(filled <= posted, "no data frame landed outside a posted receive buffer");
}

static void finished(uint64_t n)
{
	CHECK(chain_session_done(tx) == n && !chain_session_aborted(tx), "host 1 finished every batch");
	CHECK(chain_session_done(rx) == n && !chain_session_aborted(rx), "host 2 finished every batch");
	CHECK(!chain_session_last_err(tx) && !chain_session_last_err(rx), "no session error");
	CHECK(chain_violations() == 0,
	      "no device touched bytes outside its live leases; no program ran in a callback");
	for (unsigned f = 0; f < frames; f++)
		CHECK(chain_frame_custody(tx, f) == F_K_FREE && chain_frame_custody(rx, f) == F_K_FREE,
		      "every frame back in the pool");
	credit_rule();
}

/* Most XDOMAIN groups in flight at once on host 1, counted from RTS
 * arrivals at host 2 and ACK arrivals at host 1 (ordinary mode). */
static unsigned groups_in_flight_max(void)
{
	unsigned now = 0, most = 0;
	for (size_t i = 0; i < chain_event_count(); i++) {
		const struct chain_event *e = chain_event_get(i);
		if (e->kind != CHAIN_EV_CTL_RX)
			continue;
		if (e->endpoint == 1 && e->control_type == RTS && ++now > most)
			most = now;
		if (e->endpoint == 0 && e->control_type == ACK && now)
			now--;
	}
	return most;
}

static void chain_same_worker(void)
{
	unsigned n = 2 * depth;

	up();
	start(n);
	settle(50);
	CHECK(commands(0) == n && commands(1) == n, "every READ on host 1 and every WRITE on host 2");
	for (unsigned k = 1; k <= n; k++) {
		same_worker_tx(k);
		sent_bytes_match(k);
		bytes_match(k);
	}
	finished(n);
	if (!early)
		printf("CHAIN_OBSERVE xdomain_groups_in_flight_max=%u\n", groups_in_flight_max());
	printf("CHAIN_OBSERVE tx_stage_peak=%u rx_held_peak=%u\n", peak.tx_stage, peak.rx_held);
	if (!early)
		CHECK(groups_in_flight_max() <= limit(window_tx), "RTS minus ACK never exceeds the window");
	for (unsigned k = 1; k <= depth; k++)
		CHECK(read_frames(k + depth) == read_frames(k),
		      "the second round of batches reuses the frames of the first round");
}

/* (b) No reuse without the peer ACK. */
static void reuse_waits_for_ack(void)
{
	unsigned first;

	up();
	chain_hold_ack(1, true);
	start(depth + 1);
	settle(50);
	CHECK(commands(1) >= 1, "host 2 wrote group 1: its consumer released it");
	CHECK(chain_control_tx_count(1, ACK) >= 1, "host 2 produced an ACK, held on the wire");
	CHECK(nth_ctl_rx(0, ACK, 1) == 0, "host 1 has received no ACK");
	CHECK(commands(0) == depth, "no further READ: frames of batch 1 are not reused");
	if (window_tx > 1)
		CHECK(peak.tx_stage == window_tx, "with every ACK held, host 1 fills its window");
	first = read_frames(1);
	for (unsigned f = 0; f < frames; f++)
		if (first & (1u << f)) {
			CHECK(chain_frame_custody(tx, f) != F_K_FREE, "batch 1 frames stay out of the pool");
			CHECK(chain_live_leases(0, CHAIN_DEV_NHI, f * FRAME, FRAME) >= 1,
			      "batch 1 NHI TX lease still live");
		}
	CHECK(chain_session_done(tx) == 0, "no host 1 batch finished");
	chain_hold_ack(1, false);
	settle(50);
	finished(depth + 1);
	CHECK(nth_ctl_rx(0, ACK, 1) && nth_ctl_rx(0, ACK, 1) < nth(CHAIN_EV_NVME_SUBMIT, 0, depth + 1),
	      "the reusing READ follows the first ACK");
	CHECK(read_frames(depth + 1) == first, "the reusing READ takes batch 1's frames");
	for (unsigned k = 1; k <= depth + 1; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
}

/* (c) An ACK before local TX completion still waits. */
static void ack_before_local_done(void)
{
	unsigned first;

	up();
	chain_hold_tx_completions(0, true);
	start(depth + 1);
	settle(50);
	CHECK(nth_ctl_rx(0, ACK, 1) != 0, "host 1 received group 1's ACK");
	CHECK(chain_data_tx_done(0) == 0, "no host 1 TX descriptor has completed");
	CHECK(commands(0) == depth, "no further READ while TX completion is outstanding");
	if (window_tx > 1)
		CHECK(peak.tx_stage == window_tx, "with every TX completion held, host 1 fills its window");
	first = read_frames(1);
	for (unsigned f = 0; f < frames; f++)
		if (first & (1u << f))
			CHECK(chain_frame_custody(tx, f) != F_K_FREE &&
			      chain_live_leases(0, CHAIN_DEV_NHI, f * FRAME, FRAME) >= 1,
			      "ACKed but locally unfinished frames stay leased and out of the pool");
	CHECK(chain_session_done(tx) == 0, "no host 1 batch finished on ACK alone");
	chain_hold_tx_completions(0, false);
	settle(50);
	finished(depth + 1);
	CHECK(nth(CHAIN_EV_NVME_SUBMIT, 0, depth + 1) > nth_ctl_rx(0, ACK, 1), "reuse follows both events");
	CHECK(read_frames(depth + 1) == first, "the reusing READ takes batch 1's frames");
	for (unsigned k = 1; k <= depth + 1; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
}

/* (d) The receiver acknowledges only after its consumer released the group. */
static void consumer_holds_ack(void)
{
	up();
	chain_nvme_hold(1, true);
	start(depth);
	settle(50);
	CHECK(chain_nvme_pending(1) >= 1, "host 2 NVMe WRITE submitted and held");
	if (window_rx > 1)
		CHECK(chain_nvme_pending(1) == window_rx, "host 2 took in as many groups as its window");
	CHECK(chain_control_tx_count(1, ACK) == 0, "no ACK while the consumer holds the group");
	CHECK(chain_session_done(tx) == 0, "host 1 does not finish without the ACK");
	chain_nvme_hold(1, false);
	settle(50);
	finished(depth);
	CHECK(chain_control_tx_count(1, ACK) == depth, "one ACK per group after the WRITE completed");
	for (unsigned k = 1; k <= depth; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
}

/* (e) A duplicate of an old ACK cannot finish the group now in its frames. */
static void stale_ack_after_reuse(void)
{
	unsigned first, guard = 0;
	int ret;

	up();
	chain_hold_ack(1, true);
	start(depth + 1);
	settle(50);
	CHECK(commands(0) == depth, "the first round of groups waits for ACKs");
	chain_hold_ack(1, false);
	/* Step until host 1 holds every held ACK, then hold host 2's next ACK. */
	while (!nth_ctl_rx(0, ACK, depth)) {
		CHECK(chain_pump(1, 0) == 0 || 1, "single-step scheduler");
		observe();
		CHECK(++guard < 100000, "every held ACK arrives");
	}
	chain_hold_ack(1, true);
	settle(50);
	first = read_frames(1);
	CHECK(commands(0) == depth + 1 && read_frames(depth + 1) == first,
	      "the next batch now occupies batch 1's frames");
	CHECK(commands(1) == depth + 1, "host 2 wrote that group; its ACK is held");
	CHECK(chain_session_done(tx) == depth, "the first round finished on host 1");
	ret = chain_inject_stale_control(1, ACK, 1);
	CHECK(ret == 0, "a copy of group 1's ACK reaches host 1's control RX ring");
	settle(20);
	CHECK(nth_ctl_rx(0, ACK, depth + 1) != 0, "the stale ACK was dispatched to the class");
	CHECK(chain_session_done(tx) == depth, "the stale ACK finished no batch");
	for (unsigned f = 0; f < frames; f++)
		if (first & (1u << f))
			CHECK(chain_frame_custody(tx, f) != F_K_FREE &&
			      chain_live_leases(0, CHAIN_DEV_NHI, f * FRAME, FRAME) >= 1,
			      "reused frames stay leased to the group now in them");
	CHECK(commands(0) == depth + 1, "no further READ reused the frames");
	chain_hold_ack(1, false);
	settle(50);
	CHECK(chain_session_done(tx) == depth + 1, "that group finishes on its own ACK");
	CHECK(chain_violations() == 0, "no lease overlap");
	for (unsigned k = 1; k <= depth + 1; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
	credit_rule();
}

/* Window of W on both stages, host 2's consumer holding every group, more
 * batches than the window: host 1 reaches exactly W groups in flight, host 2
 * holds exactly W, nothing more is announced, and after the release every
 * group arrives in order. Ordinary mode needs no timer for any of this. */
static void window_fills(void)
{
	unsigned n = depth + 2;

	up();
	chain_nvme_hold(1, true);
	start(n);
	pump(0); /* event driven: no protocol, retry or worker timer may be needed */
	CHECK(chain_nvme_pending(1) == window_rx, "host 2 took in and holds W groups");
	CHECK(peak.tx_stage == window_tx, "host 1 reached W groups in flight at its XDOMAIN stage");
	CHECK(peak.rx_held == window_rx, "host 2 held W groups at once");
	if (!early) {
		CHECK(chain_control_tx_count(0, RTS) == window_tx, "group W+1 is not announced while W are unfinished");
		CHECK(groups_in_flight_max() == window_tx, "RTS minus ACK reached W");
	}
	CHECK(chain_control_tx_count(1, ACK) == 0 && chain_session_done(tx) == 0,
	      "no ACK and no finished group while the consumer holds them");
	CHECK(commands(0) == depth, "host 1 read ahead into every batch it has");
	chain_nvme_hold(1, false);
	settle(50);
	finished(n);
	CHECK(commands(1) == n, "host 2 wrote every group");
	for (unsigned k = 1; k <= n; k++) {
		same_worker_tx(k);
		sent_bytes_match(k);
		bytes_match(k);
	}
	printf("CHAIN_OBSERVE tx_stage_peak=%u rx_held_peak=%u\n", peak.tx_stage, peak.rx_held);
}

/* The receiver arms fewer groups than the sender's window: host 1 has in
 * flight what host 2 holds plus at most the one group it announced, and posts
 * data only for groups host 2 posted buffers for. */
static void window_waits_for_receiver(void)
{
	unsigned announced = early ? 0 : 1, n = depth;

	up();
	chain_nvme_hold(1, true);
	start(n);
	pump(0);
	CHECK(chain_nvme_pending(1) == window_rx, "host 2 holds the groups it armed for");
	CHECK(peak.rx_held == window_rx, "host 2 never took more than its window");
	CHECK(peak.tx_stage == window_rx + announced,
	      "host 1 waits for host 2: what host 2 holds, plus one announced group in ordinary mode");
	if (!early)
		CHECK(chain_control_tx_count(0, RTS) == window_rx + 1, "only the next group is announced ahead");
	credit_rule();
	chain_nvme_hold(1, false);
	settle(50);
	finished(n);
	for (unsigned k = 1; k <= n; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
	printf("CHAIN_OBSERVE tx_stage_peak=%u rx_held_peak=%u\n", peak.tx_stage, peak.rx_held);
}

static bool rx_posted(uint64_t group)
{
	for (size_t i = 0; i < chain_event_count(); i++)
		if (chain_event_get(i)->kind == CHAIN_EV_DATA_RX_POST && chain_event_get(i)->endpoint == 1 &&
		    chain_event_get(i)->group == group)
			return true;
	return false;
}

/* The receiver refills its RX stage when a group leaves it, not on a timer.
 * Host 2's data completions are held, so group 1 stays in host 2's RX stage
 * while host 1 already announced group 2 (ordinary mode); once the
 * completions run, group 1 moves on to its consumer and group 2 must be posted
 * in the same event-driven drain, with no virtual time passing. */
static void window_refills_receiver(void)
{
	up();
	chain_nvme_hold(1, true);
	chain_hold_tx_completions(1, true); /* host 2's data-ring callbacks */
	start(depth);
	pump(0);
	CHECK(rx_posted(1) && !rx_posted(2), "group 1 is posted at host 2 and waits for its completions");
	CHECK(chain_stage_completed(rx, 0) == 0 && chain_stage_submitted(rx, 0) == 1,
	      "group 1 is still in host 2's RX stage");
	if (!early)
		CHECK(nth_ctl_rx(1, RTS, 2) != 0, "group 2's announcement already reached host 2");
	chain_hold_tx_completions(1, false);
	pump(0);
	CHECK(chain_stage_completed(rx, 0) >= 1, "group 1 left host 2's RX stage");
	CHECK(rx_posted(2), "group 2 was posted at host 2 in the same drain, without a timer");
	CHECK(peak.rx_held == window_rx, "host 2 holds W groups");
	if (!early)
		CHECK(nth_ctl_rx(0, CTS, 2) != 0, "host 1 got group 2's clear-to-send");
	CHECK(peak.tx_stage == window_tx, "host 1 posted group 2 in the same drain");
	chain_nvme_hold(1, false);
	settle(50);
	finished(depth);
	for (unsigned k = 1; k <= depth; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
}

/* The next group goes out when the previous group's clear-to-send has been
 * processed, not when it finishes. Host 2's CTS is held until host 1 has read
 * ahead into every batch (they wait at its XDOMAIN stage); once released,
 * host 1 fills its window in the same event-driven drain (ordinary mode). */
static void window_next_after_cts(void)
{
	up();
	chain_nvme_hold(1, true);
	chain_hold_control(1, CTS, true);
	start(depth);
	pump(0);
	CHECK(commands(0) == depth, "host 1 read ahead into every batch");
	CHECK(chain_control_tx_count(0, RTS) == 1, "only group 1 is announced while its CTS is held");
	CHECK(peak.tx_stage == 1, "one group in flight while its CTS is held");
	chain_hold_control(1, CTS, false);
	pump(0);
	CHECK(peak.tx_stage == window_tx, "host 1 reached its window once group 1's CTS was processed");
	CHECK(nth_ctl_rx(1, RTS, 2) != 0 && chain_session_done(tx) == 0,
	      "group 2 was announced before group 1 finished");
	chain_nvme_hold(1, false);
	settle(50);
	finished(depth);
	for (unsigned k = 1; k <= depth; k++) {
		sent_bytes_match(k);
		bytes_match(k);
	}
}

/* STOP while W groups are in flight and host 1's TX completions are held, so
 * their local native outcome is unknown: no group is reported delivered and
 * no frame of those groups returns to the pool or is leased again. */
static void window_stop_unknown(void)
{
	unsigned frames_in_flight = 0;

	up();
	chain_hold_tx_completions(0, true);
	chain_hold_ack(1, true);
	start(depth);
	settle(5);
	CHECK(peak.tx_stage == window_tx, "W groups in flight at host 1");
	CHECK(chain_data_tx_done(0) == 0, "no host 1 TX completion");
	for (unsigned k = 1; k <= window_tx; k++)
		frames_in_flight |= read_frames(k);
	CHECK(chain_session_stop(tx, -ECANCELED) == 0, "host 1 STOP");
	pump(1500000000ULL); /* past the 1 s stop grace */
	settle(50);
	printf("CHAIN_OBSERVE stop_unknown done=%llu aborted=%llu session_state=%u\n",
	       (unsigned long long)chain_session_done(tx), (unsigned long long)chain_session_aborted(tx),
	       chain_session_state(tx));
	CHECK(chain_session_done(tx) == 0, "no group with an unknown TX completion is reported delivered");
	CHECK(commands(0) == depth, "no READ after STOP");
	for (unsigned f = 0; f < frames; f++)
		if (frames_in_flight & (1u << f))
			CHECK(chain_frame_custody(tx, f) != F_K_FREE && chain_frame_custody(tx, f) != 0 /* USER */,
			      "a frame whose TX completion is unknown never returns to the pool or the application");
	chain_hold_tx_completions(0, false);
	settle(50);
	for (unsigned f = 0; f < frames; f++)
		if (frames_in_flight & (1u << f))
			CHECK(chain_frame_custody(tx, f) != F_K_FREE && chain_frame_custody(tx, f) != 0 /* USER */,
			      "a late TX completion does not return a retired frame");
	CHECK(chain_session_done(tx) == 0, "nor report its group delivered");
	CHECK(chain_violations() == 0, "nothing leased over retained bytes, no device outside its leases");
}

/* An announced group the receiver never posted buffers for is withdrawn and
 * refused, then the receiver arms its first batch. No later group of host 1
 * may take that receive batch: host 2 must not write host 1's second group
 * where the first belongs, and host 1 reports no group delivered. */
static void window_withdrawn_head(void)
{
	unsigned guard = 0;

	up();
	CHECK(chain_start(tx, 2, 37) == 0, "host 1 START; host 2 has not started");
	settle(20);
	CHECK(commands(0) == 2, "host 1 read both groups");
	CHECK(chain_control_tx_count(0, RTS) >= 1, "host 1 announced group 1");
	/* Past the sender's 15 s withdrawal point, then one step at a time until
	 * host 2 has refused group 1. */
	CHECK(chain_pump(1, 15500000000ULL) == -ELOOP, "the withdrawal timer runs");
	observe();
	while (chain_control_tx_count(1, FAIL) == 0) {
		CHECK(chain_pump(1, 0) == -ELOOP, "the refusal is reached without more time");
		observe();
		CHECK(++guard < BUDGET, "bounded");
	}
	CHECK(chain_control_tx_count(0, CANCEL) >= 1, "host 1 withdrew group 1");
	CHECK(chain_start(rx, 2, 37) == 0, "host 2 START right after it refused group 1");
	settle(50);
	for (unsigned k = 1; k <= commands(1); k++)
		bytes_match(k);
	CHECK(commands(1) == 0, "host 2 wrote nothing: no later group took group 1's receive batch");
	CHECK(count(CHAIN_EV_DATA_TX_POST, 0) == 0, "host 1 posted no data");
	CHECK(chain_session_done(tx) == 0 && chain_session_aborted(tx) == 2,
	      "host 1 reports neither group delivered");
	CHECK(chain_session_stop(rx, -ECANCELED) == 0, "host 2 STOP");
	settle(50);
	CHECK(chain_violations() == 0, "no device touched bytes outside its live leases");
	for (unsigned f = 0; f < frames; f++)
		CHECK(chain_frame_custody(tx, f) == F_K_FREE && chain_frame_custody(rx, f) == F_K_FREE,
		      "every frame back in the pool");
}

/* No Thunderbolt link behind the token: CREATE fails cleanly with ENODEV. */
static void no_link_enodev(void)
{
	struct chain_link_config cfg = { .frame_size = FRAME, .nr_frames = frames, .depth = depth,
		.group_bytes = GROUP };
	int err = 0;

	CHECK(chain_world(&cfg) == 0, "world");
	chain_tx_session(&err, 0x5eedf00dULL);
	CHECK(err == -ENODEV, "XDOMAIN stage bind without that link returns ENODEV");
}

static bool strip(char *name, const char *suffix)
{
	size_t n = strlen(name), s = strlen(suffix);

	if (n <= s || strcmp(name + n - s, suffix))
		return false;
	name[n - s] = 0;
	return true;
}

int main(int argc, char **argv)
{
	char base[64];
	unsigned w = 0;

	if (argc != 2 || strlen(argv[1]) >= sizeof(base))
		return 2;
	case_name = argv[1];
	strcpy(base, case_name);
	/* NAME_early: the same requirement with both XDOMAIN stages in EARLY
	 * mode (receive grants paired by key; no RTS/CTS round trip). */
	early = strip(base, "_early");
	/* NAME_wN: both stages with window N, depth max(2, N), two frames a group. */
	if (strip(base, "_w1"))
		w = 1;
	else if (strip(base, "_w2"))
		w = 2;
	else if (strip(base, "_w4"))
		w = 4;
	if (w) {
		window_tx = window_rx = w;
		depth = w > 2 ? w : 2;
		frames = 2 * depth;
	}
	if (!strcmp(base, "window_fills")) {
		if (w < 2)
			return 2;
		depth = w + 2; /* more batches than the window */
		frames = 2 * depth;
		window_fills();
	} else if (!strcmp(base, "window_waits_for_receiver") && !w) {
		window_tx = 4;
		window_rx = 2;
		depth = 6;
		frames = 12;
		window_waits_for_receiver();
	} else if (!strcmp(base, "window_refills_receiver") && !w) {
		window_tx = window_rx = 2;
		window_refills_receiver();
	} else if (!strcmp(base, "window_next_after_cts") && !w && !early) {
		window_tx = window_rx = 2;
		depth = 4;
		frames = 8;
		window_next_after_cts();
	} else if (!strcmp(base, "window_stop_unknown") && !w) {
		window_tx = window_rx = 2;
		window_stop_unknown();
	} else if (!strcmp(base, "window_withdrawn_head") && !w && !early) {
		window_tx = window_rx = 2;
		window_withdrawn_head();
	} else if (!strcmp(base, "chain_same_worker")) chain_same_worker();
	else if (!strcmp(base, "reuse_waits_for_ack")) reuse_waits_for_ack();
	else if (!strcmp(base, "ack_before_local_done")) ack_before_local_done();
	else if (!strcmp(base, "consumer_holds_ack")) consumer_holds_ack();
	else if (!strcmp(base, "stale_ack_after_reuse")) stale_ack_after_reuse();
	else if (!strcmp(base, "no_link_enodev") && !early && !w) no_link_enodev();
	else return 2;
	printf("CHAIN_CASE %s assertions=%u\n", case_name, assertions);
	return 0;
}
