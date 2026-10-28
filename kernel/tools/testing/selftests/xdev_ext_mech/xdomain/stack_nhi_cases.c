/* SPDX-License-Identifier: GPL-2.0 */
/* The original independent wire/address/custody oracle remains unchanged.
 * These cases add observations at the real NHI descriptor/callback boundary.
 * NO_INTERRUPT, batching and tiny rings are host adapter stress modes only.
 */
#define main stack_model_main
#include "stack_cases.c"
#undef main

/* Literal NHI descriptor flag values keep this assertion driver independent
 * from the production flag helpers and descriptor construction code. */
#define NHI_COMPLETED 0x2U
#define NHI_POSTED 0x4U
#define NHI_INTERRUPT 0x8U

static size_t data_events(struct stack_world *w, unsigned kind, unsigned endpoint)
{
	size_t n = 0;

	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event e = ev(w, i);

		if (e.kind == kind && e.endpoint == endpoint && !e.control)
			n++;
	}
	return n;
}

/* A frame address can be reused in a later window. Correlate each accepted
 * lifetime separately, bounded by its next DATA_POST, not by pointer alone.
 * The expected physical address is computed from fixture geometry, not from
 * either the accepted ring_frame or the descriptor being checked.
 */
static void nhi_descriptors(struct stack_world *w, const struct stack_config *c,
			    unsigned groups)
{
	size_t accepted = 0, multi_descriptor_bells = 0;
	unsigned previous[2] = { 0, 0 }, seen[2] = { 0, 0 }, wraps[2] = { 0, 0 };

	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event a = ev(w, i);

		if (a.kind == STACK_EV_NHI_DOORBELL && !a.control && a.length > 1)
			multi_descriptor_bells++;
		if (a.kind != STACK_EV_DATA_POST)
			continue;
		accepted++;
		uint64_t end = UINT64_MAX;
		for (size_t j = i + 1; j < stack_log_count(w); j++) {
			struct stack_event next = ev(w, j);

			if (next.kind == STACK_EV_DATA_POST && next.endpoint == a.endpoint &&
			    next.owner == a.owner) {
				end = next.id;
				break;
			}
		}
		unsigned frame = (a.seq % c->native_elems) / 2;
		unsigned chunk = (a.seq % c->native_elems) % 2;
		CHECK(frame < c->nr_frames, "independent fixture frame ordinal");
		uint64_t want = c->mapping_base[a.endpoint] +
			c->span[frame].allocation_off + c->span[frame].data_off + chunk * 4096;
		unsigned posts = 0, completed = 0, callbacks = 0;
		uint64_t posted_at = 0, completed_at = 0, callback_at = 0, x4_at = 0;
		for (size_t j = i + 1; j < stack_log_count(w); j++) {
			struct stack_event e = ev(w, j);

			if (e.id >= end)
				break;
			if (e.endpoint != a.endpoint || e.owner != a.owner || e.control)
				continue;
			if (e.kind == STACK_EV_NHI_POST) {
				posts++;
				posted_at = e.id;
				CHECK(e.address == want, "doorbell-visible real descriptor has independent physical address");
				CHECK(e.flags & NHI_POSTED, "actual descriptor has POSTED flag before hardware completion");
				CHECK(!!(e.flags & NHI_INTERRUPT) == !c->nhi_poll,
				      "NO_INTERRUPT suppresses actual descriptor interrupt bit");
				if (a.direction == 1) {
					CHECK(e.length == 4096 && e.pdf == 0x201,
					      "actual TX descriptor has independent length and SOF/EOF");
				}
				if (c->nhi_ring_size) {
					CHECK(e.seq < c->nhi_ring_size, "actual descriptor index bounded by tiny data ring");
					if (seen[a.endpoint]++ && e.seq < previous[a.endpoint])
						wraps[a.endpoint]++;
					previous[a.endpoint] = e.seq;
				}
			} else if (e.kind == STACK_EV_NHI_COMPLETE) {
				completed++;
				completed_at = e.id;
				CHECK(e.address == want && e.length == 4096 && e.pdf == 0x201,
				      "completed real descriptor preserves physical address, length and SOF/EOF");
				CHECK(e.flags & NHI_COMPLETED, "hardware boundary marks actual descriptor completed");
			} else if (e.kind == STACK_EV_NHI_CALLBACK) {
				callbacks++;
				callback_at = e.id;
				CHECK(e.status == 0, "successful transfer callback is not synthesized cancellation");
				CHECK(e.flags == (c->nhi_poll ? 2U : 1U),
				      "callback originates from real poll return or real ring work");
			} else if (e.kind == STACK_EV_DATA_CALLBACK) {
				x4_at = e.id;
			}
		}
		CHECK(posts == 1 && completed == 1 && callbacks == 1,
		      "each accepted X4 frame crosses one real NHI descriptor, completion and callback");
		CHECK(a.id < posted_at && posted_at < completed_at && completed_at < callback_at &&
		      callback_at < x4_at,
		      "actual NHI completion precedes actual X4 callback in the same frame lifetime");
	}
	CHECK(accepted == 2U * groups * c->native_elems,
	      "both endpoints pass every window through the real NHI boundary");
	if (c->nhi_ring_size)
		CHECK(wraps[0] > 0 && wraps[1] > 0, "both actual descriptor rings wrap while draining queued frames");
	if (c->nhi_batch)
		CHECK(multi_descriptor_bells > 0, "one actual doorbell publishes multiple descriptors");
	if (c->nhi_poll)
		CHECK(count(w, STACK_EV_NHI_IRQ_ALLOC, -1, -1) == 0,
		      "NO_INTERRUPT composed rings allocate no IRQ");
	else
		CHECK(count(w, STACK_EV_NHI_IRQ_ALLOC, -1, -1) > 0,
		      "production configuration exercises actual NHI IRQ allocation");
}

static void configured_windows(bool poll, bool batch)
{
	struct stack_config c = geometry();

	c.nhi_poll = poll;
	c.nhi_batch = batch;
	c.nhi_ring_size = 3; /* Two usable hardware slots, four frames per group. */
	struct stack_world *w = create(&c);
	login(w);
	sessions(w, 9, 0);
	for (unsigned g = 0; g < 9; g++) {
		start(w, c.first_seq + g, 0);
		pump(w, 1000000);
		CHECK(count(w, STACK_EV_CONTROL_TX, 1, 3) == g,
		      "existing chain-release boundary still gates final ACK with real NHI");
		release_group(w, c.first_seq + g);
	}
	addresses(w, &c);
	wire(w, 1);
	wire(w, 2);
	wire(w, 3);
	nhi_descriptors(w, &c, 9);
	CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 9 &&
	      count(w, STACK_EV_PUBLISH, 1, -1) == 9,
	      "nine groups publish once at both ends through finite NHI rings");
	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event e = ev(w, i);

		if (e.kind == STACK_EV_PUBLISH)
			CHECK(e.status == 0 && e.bytes == 16384 && e.elems_done == 4,
			      "real class CQE preserves independent byte/element geometry");
	}
	CHECK(stack_stop(w, 0) == 0 && stack_stop(w, 1) == 0,
	      "completed composed sessions drain through existing STOP contract");
	safety(w);
	stack_destroy(w);
}

static void production_happy_path(void)
{
	/* The original twelve-case suite and its expected file are unmodified. */
	multiwindow_happy_path();
}

static void production_ack_orders(void)
{
	ack_before_tx_callback();
	struct stack_config c = geometry();
	struct stack_world *w = create(&c);
	login(w);
	sessions(w, 1, 0);
	fault(w, STACK_FAULT_HOLD_CONTROL, 1, 3, 0, 1, 0);
	start(w, c.first_seq, 0);
	pump(w, 1000000);
	release_group(w, c.first_seq);
	CHECK(data_events(w, STACK_EV_NHI_CALLBACK, 0) == 4,
	      "all local TX frames complete through real NHI before held ACK");
	CHECK(count(w, STACK_EV_CONTROL_TX, 1, 3) == 1 &&
	      count(w, STACK_EV_CONTROL_RX, 0, 3) == 0,
	      "actual X4 accepted final ACK remains at wire boundary");
	CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 0 &&
	      count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0,
	      "local descriptor completion alone cannot publish or release sender ownership");
	fault(w, STACK_FAULT_RELEASE_CONTROLS, 1, 3, 0, 0, 0);
	pump(w, 1000000);
	CHECK(count(w, STACK_EV_PUBLISH, 0, -1) == 1,
	      "delayed actual ACK completes sender exactly once after native completion");
	CHECK(first(w, STACK_EV_DATA_CALLBACK, 0, -1) < first(w, STACK_EV_CONTROL_RX, 0, 3),
	      "observed native-completion-before-ACK ordering");
	addresses(w, &c);
	nhi_descriptors(w, &c, 1);
	safety(w);
	stack_destroy(w);
}

static void production_stop_phases(void)
{
	stop_all_commitment_phases();
}

static void production_loss_teardown(void)
{
	loss_and_teardown();
}

static void no_interrupt_poll_refill(void)
{
	configured_windows(true, false);
}

static void batched_doorbells_wrap(void)
{
	configured_windows(false, true);
}

static void poll_batch_retirement(void)
{
	struct stack_config c = geometry();

	c.nhi_poll = true;
	c.nhi_batch = true;
	c.nhi_ring_size = 3;
	struct stack_world *w = create(&c);
	login(w);
	sessions(w, 1, 0);
	/* Withhold hardware TX completion, not its eventual production callback.
	 * Two descriptors can be visible; the remaining two stay in real queue. */
	fault(w, STACK_FAULT_HOLD_CALLBACK, 0, 0, 0, 1, 0);
	start(w, c.first_seq, 0);
	pump(w, 1000000);
	CHECK(count(w, STACK_EV_DATA_POST, 0, -1) == 4 &&
	      data_events(w, STACK_EV_NHI_POST, 0) == 2,
	      "real size-three TX ring owns two posted and two queued X4 frames");
	CHECK(data_events(w, STACK_EV_NHI_CALLBACK, 0) == 0,
	      "withheld completion cannot invoke native callback early");
	CHECK(count(w, STACK_EV_NHI_IRQ_ALLOC, -1, -1) == 0,
	      "poll/batch teardown fixture allocated no interrupt");
	fault(w, STACK_FAULT_GOING_AWAY, 0, 0, 0, 1, 0);
	CHECK(stack_remove(w, 0) == 0, "actual X3 removal reaches real NHI quarantine");
	CHECK(data_events(w, STACK_EV_NHI_CALLBACK, 0) == 4,
	      "real retirement ring_work returns posted and queued owners exactly once");
	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event a = ev(w, i);

		if (a.kind != STACK_EV_DATA_POST || a.endpoint != 0)
			continue;
		unsigned returned = 0;
		for (size_t j = i + 1; j < stack_log_count(w); j++) {
			struct stack_event e = ev(w, j);

			if (e.kind == STACK_EV_NHI_CALLBACK && e.endpoint == 0 &&
			    !e.control && e.owner == a.owner)
				returned++;
		}
		CHECK(returned == 1, "every distinct posted or queued frame owner crosses retirement barrier once");
	}
	uint64_t last_callback = 0, data_retire = 0;
	unsigned retired = 0;
	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event e = ev(w, i);

		if (e.endpoint != 0)
			continue;
		if (e.kind == STACK_EV_NHI_CALLBACK && !e.control) {
			CHECK(e.status == -ECANCELED && e.flags == 1,
			      "real ring_work cancels ownership after deterministic poller exclusion");
			last_callback = e.id;
		} else if (e.kind == STACK_EV_NHI_RETIRE) {
			retired++;
			CHECK(e.status == -ENOLINK && e.address && e.length,
			      "UNKNOWN actual descriptor backing remains explicitly retained");
			CHECK(e.bytes == 0, "real quarantine never frees unknown descriptor DMA backing");
			CHECK(e.flags == 0, "retired ring has no key in independent lockdep registry");
			if (!e.control && e.direction == 1)
				data_retire = e.id;
		}
	}
	CHECK(retired == 4 && last_callback && data_retire > last_callback,
	      "all four endpoint rings retire only after actual data callback barrier");
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0 &&
	      count(w, STACK_EV_RETAIN, 0, -1) > 0,
	      "UNKNOWN native cancellation retains payload custody without false safe release");
	size_t callbacks = data_events(w, STACK_EV_NHI_CALLBACK, 0);
	pump(w, 1000000);
	pump(w, 2000000000);
	CHECK(data_events(w, STACK_EV_NHI_CALLBACK, 0) == callbacks,
	      "retired descriptor owner cannot produce a later poll or work callback");
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0,
	      "later scheduler progress cannot falsely release unknown DMA ownership");
	safety(w);
	stack_destroy(w);
}

static const struct named nhi_cases[] = {
	{ "production_happy_path", production_happy_path },
	{ "production_ack_orders", production_ack_orders },
	{ "production_stop_phases", production_stop_phases },
	{ "production_loss_teardown", production_loss_teardown },
	{ "no_interrupt_poll_refill", no_interrupt_poll_refill },
	{ "batched_doorbells_wrap", batched_doorbells_wrap },
	{ "poll_batch_retirement", poll_batch_retirement },
};

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: nhi-stack-cases NAME EVENT_BUDGET\n");
		return 2;
	}
	case_name = argv[1];
	budget = (unsigned)strtoul(argv[2], NULL, 10);
	if (!budget)
		return 2;
	for (size_t i = 0; i < sizeof(nhi_cases) / sizeof(nhi_cases[0]); i++) {
		if (strcmp(case_name, nhi_cases[i].name))
			continue;
		nhi_cases[i].run();
		printf("NHI_STACK_CASE_ASSERTIONS %s %u\n", case_name, assertions);
		return 0;
	}
	fprintf(stderr, "unknown frozen NHI stack case %s\n", case_name);
	return 2;
}
