/* SPDX-License-Identifier: GPL-2.0 */
/* N1 requirements: real production batching, finite native pending ownership.
 * Breaks caught: per-element notify, <=255 software admission, lost queued
 * callback, premature UNKNOWN lease release. The original stack oracle is
 * included unchanged; adapter batching is deliberately disabled in all cases.
 */
#define main original_stack_main
#include "stack_cases.c"
#undef main

void native_progress_counts(unsigned endpoint, unsigned *inflight, unsigned *queued);
void native_progress_complete_one(unsigned endpoint);
void native_progress_race_enable(unsigned endpoint);
unsigned native_progress_race_accepted(void);

static size_t data_count(struct stack_world *w, unsigned kind, unsigned endpoint)
{
	size_t result = 0;
	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event e = ev(w, i);
		if (e.kind == kind && e.endpoint == endpoint && !e.control)
			result++;
	}
	return result;
}

static struct stack_config sixteen(void)
{
	struct stack_config c = geometry();
	c.depth = 16;
	c.nr_frames = 8;
	c.native_elems = 16;
	for (unsigned i = 0; i < 8; i++)
		c.span[i] = (struct stack_span){65536ULL * (i + 1), 4096, 8192};
	return c;
}

static void batch_one_notify(void)
{
	struct stack_config c = sixteen();
	c.depth = 1;
	struct stack_world *w = create(&c);
	login(w);
	sessions(w, 1, 0);
	start(w, c.first_seq, 0);
	pump(w, 1000000);
	for (unsigned endpoint = 0; endpoint < 2; endpoint++) {
		size_t posts = 0, bells = 0;
		for (size_t i = 0; i < stack_log_count(w); i++) {
			struct stack_event e = ev(w, i);
			if (e.endpoint != endpoint || e.control)
				continue;
			if (e.kind == STACK_EV_NHI_DOORBELL)
				bells++;
			if (e.kind != STACK_EV_NHI_POST)
				continue;
			unsigned frame = posts / 2, chunk = posts % 2;
			CHECK(frame < 8, "no extra native descriptor in a sixteen-element group");
			uint64_t want = c.mapping_base[endpoint] + 65536ULL * (frame + 1) +
				4096 + 4096 * chunk;
			CHECK(e.address == want, "real descriptor address equals independent lease geometry");
			CHECK(e.flags & 4U, "real descriptor is POSTED before hardware completion");
			posts++;
		}
		CHECK(posts == 16, "one full sixteen-element group crosses real descriptors");
		fprintf(stderr, "NATIVE_BATCH endpoint=%u descriptors=%zu doorbells=%zu expected=1\n",
			endpoint, posts, bells);
		CHECK(bells == 1, "one data group must publish all descriptors with one explicit notify");
	}
	release_group(w, c.first_seq);
	addresses(w, &c);
	safety(w);
	stack_destroy(w);
}

static void pending_256(void)
{
	struct stack_config c = sixteen();
	struct stack_world *w = create(&c);
	login(w);
	/* This is the public bind behavior, not a direct call to budget_ok. */
	struct stack_session_config rx = {.direction = 2, .groups = 16};
	struct stack_session_config tx = {.direction = 1, .groups = 16};
	int result = stack_session(w, 1, &rx);
	fprintf(stderr, "NATIVE_CAPACITY depth=16 elems=16 ring=256 receiver_bind=%d expected=0\n", result);
	CHECK(result == 0, "depth16 times sixteen elements is valid software pending capacity");
	CHECK(stack_session(w, 0, &tx) == 0, "sender also admits depth16 times sixteen elements");
	fault(w, STACK_FAULT_HOLD_CALLBACK, 0, 0, 0, 1, 0);
	for (unsigned g = 0; g < 16; g++) {
		start(w, c.first_seq + g, 0);
		pump(w, 1000000);
		if (g < 15)
			release_group(w, c.first_seq + g);
	}
	unsigned inflight, queued;
	native_progress_counts(0, &inflight, &queued);
	CHECK(data_count(w, STACK_EV_DATA_POST, 0) == 256, "real X4 accepts all256 TX elements");
	CHECK(inflight == 255 && queued == 1, "real NHI holds255 in-flight and one software pending");
	CHECK(data_count(w, STACK_EV_NHI_CALLBACK, 0) == 0, "no held TX descriptor completed early");
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0, "queued and posted leases remain held");
	native_progress_complete_one(0);
	pump(w, 1000000);
	native_progress_counts(0, &inflight, &queued);
	CHECK(inflight == 255 && queued == 0, "real completion reclaims one descriptor and refills pending frame");
	CHECK(data_count(w, STACK_EV_NHI_POST, 0) == 256, "queued element entered actual descriptor");
	release_group(w, c.first_seq + 15);
	fault(w, STACK_FAULT_RELEASE_CALLBACKS, 0, 0, 0, 0, 0);
	pump(w, 1000000);
	CHECK(data_count(w, STACK_EV_NHI_CALLBACK, 0) == 256, "all256 TX accepted elements complete exactly once");
	addresses(w, &c);
	safety(w);
	stack_destroy(w);
}

static void pending_stop(void)
{
	/* Tiny hardware ring isolates accepted pending custody before capacity
 * admission changes: depth3*4 is already valid at the production bind. */
	struct stack_config c = geometry();
	c.nhi_ring_size = 3;
	struct stack_world *w = create(&c);
	login(w);
	sessions(w, 1, 0);
	fault(w, STACK_FAULT_HOLD_CALLBACK, 0, 0, 0, 1, 0);
	start(w, c.first_seq, 0);
	pump(w, 1000000);
	unsigned inflight, queued;
	native_progress_counts(0, &inflight, &queued);
	CHECK(inflight == 2 && queued == 2, "actual ring has both in-flight and software-pending frames");
	CHECK(data_count(w, STACK_EV_NHI_CALLBACK, 0) == 0, "no accepted frame returned before stop barrier");
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0, "pending placement cannot release lease early");
	fault(w, STACK_FAULT_GOING_AWAY, 0, 0, 0, 1, 0);
	CHECK(stack_remove(w, 0) == 0, "real endpoint removal stops unavailable NHI");
	CHECK(data_count(w, STACK_EV_NHI_CALLBACK, 0) == 4, "stop returns all posted and queued owners");
	for (size_t i = 0; i < stack_log_count(w); i++) {
		struct stack_event a = ev(w, i);
		if (a.kind == STACK_EV_NHI_RETIRE && a.endpoint == 0 && !a.control) {
			CHECK(a.status == -ENOLINK && a.address && a.length, "UNKNOWN actual descriptor backing survives");
			CHECK(a.bytes == 0, "UNKNOWN retirement frees no DMA backing");
		}
		if (a.kind != STACK_EV_DATA_POST || a.endpoint != 0)
			continue;
		unsigned returned = 0;
		for (size_t j = i + 1; j < stack_log_count(w); j++) {
			struct stack_event cb = ev(w, j);
			if (cb.kind == STACK_EV_NHI_CALLBACK && !cb.control && cb.endpoint == 0 && cb.owner == a.owner)
				returned++;
		}
		CHECK(returned == 1, "each accepted queued or in-flight owner gets exactly one terminal callback");
	}
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0 && count(w, STACK_EV_RETAIN, 0, -1) > 0,
	      "UNKNOWN payload custody retained regardless of software queue placement");
	pump(w, 2000000000);
	CHECK(data_count(w, STACK_EV_NHI_CALLBACK, 0) == 4, "no stale queued callback survives retirement");
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0, "later work cannot release UNKNOWN custody");
	safety(w);
	stack_destroy(w);
}

static void post_stop_interleave(void)
{
	struct stack_config c = sixteen();
	c.depth = 1;
	struct stack_world *w = create(&c);
	login(w);
	sessions(w, 1, 0);
	native_progress_race_enable(0);
	start(w, c.first_seq, 0);
	pump(w, 1000000);
	CHECK(native_progress_race_accepted() == 16,
	      "real competing STOP cannot acquire link lock until whole sixteen-element native group accepted");
	CHECK(data_count(w, STACK_EV_DATA_POST, 0) == 16,
	      "post-stop interleave accepts complete group without partial native submission");
	CHECK(data_count(w, STACK_EV_NHI_CALLBACK, 0) == 16,
	      "real stop completes every element accepted in the interleaved group exactly once");
	CHECK(count(w, STACK_EV_LEASE_RELEASE, 0, -1) == 0,
	      "stop cancellation cannot falsely quiesce interleaved accepted leases");
	safety(w);
	stack_destroy(w);
}

static const struct named native_cases[] = {
	{"batch-one-notify", batch_one_notify},
	{"pending-256", pending_256},
	{"pending-stop", pending_stop},
	{"post-stop-interleave", post_stop_interleave},
};

int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	case_name = argv[1];
	budget = (unsigned)strtoul(argv[2], NULL, 10);
	for (size_t i = 0; i < sizeof(native_cases) / sizeof(native_cases[0]); i++) {
		if (strcmp(case_name, native_cases[i].name))
			continue;
		native_cases[i].run();
		printf("NATIVE_PROGRESS_ASSERTIONS %s %u\n", case_name, assertions);
		return 0;
	}
	return 2;
}
