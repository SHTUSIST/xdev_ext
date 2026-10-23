// SPDX-License-Identifier: GPL-2.0
/*
 * Per-unit latency distribution of nnb_producer.c, as host C with synthetic
 * stamps: no clock is read for the samples and nothing here is a measurement.
 *
 *   test_latency            unit_latencies() and the nearest-rank percentiles
 *   test_latency --record   one measured-mode forward "trial" record printed by
 *                           the real run_trial() for a fake posix arm whose
 *                           stamps are fixed numbers, against a fake peer on a
 *                           socketpair; test_offline.py validates it with
 *                           results.check_trial(measured=True).
 */
#define main nnb_producer_main
#include "nnb_producer.c"
#undef main

#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "test_latency: line %d: %s\n", \
	__LINE__, #cond); exit(1); } } while (0)

static int none_setup(struct nnb_arm *a) { (void)a; return -EOPNOTSUPP; }
static int none_run(struct nnb_arm *a, struct nnb_trial *t) { (void)a; (void)t; return -EOPNOTSUPP; }
static void none_teardown(struct nnb_arm *a) { (void)a; }
const struct nnb_arm_ops nnb_uring_ops = { "uring", none_setup, none_run, none_teardown };
const struct nnb_arm_ops nnb_session_ops = { "session", none_setup, none_run, none_teardown };

#define UNITS 4U

/* Unit u takes 1000 * (u + 1) ns; the trial ends 10000 ns after it began. */
static int fake_run(struct nnb_arm *a, struct nnb_trial *t)
{
	const struct nnb_geom *g = a->g;

	for (uint64_t u = 0; u < t->units; u++) {
		nnb_stamp(t->lat_start, u, 500 + u);
		nnb_stamp(t->lat_done, u, 500 + u + 1000 * (u + 1));
	}
	t->t_release = t->t_start + 10000;
	t->counts.read_ops = t->units, t->counts.read_bytes = t->units * g->size;
	t->counts.datagrams = t->groups * g->dgrams;
	t->counts.send_calls = t->groups;
	t->counts.send_bytes = t->units * g->size + t->counts.datagrams * NNB_HDR_LEN;
	return 0;
}

static const struct nnb_arm_ops fake_ops = { "posix", none_setup, fake_run, none_teardown };

struct fake_peer {
	int fd;
	const struct nnb_geom *g;
};

/* READY for BEGIN, then the receipt for END: f[8] = one buffer per group. */
static void *peer_thread(void *arg)
{
	struct fake_peer *fp = arg;
	struct nnb_msg m;
	uint64_t f[9] = { 0 };

	if (nnb_msg_expect(fp->fd, 1, NNB_BEGIN, &m, 5000))
		return NULL;
	f[0] = m.f[0];
	nnb_msg_send(fp->fd, 1, NNB_READY, f, 1);
	f[1] = m.f[3] * fp->g->dgrams;
	f[2] = UNITS * (fp->g->size + (uint64_t)fp->g->dgrams_per_unit * NNB_HDR_LEN);
	f[8] = m.f[3];
	if (nnb_msg_expect(fp->fd, 1, NNB_END, &m, 5000))
		return NULL;
	nnb_msg_send(fp->fd, 1, NNB_RECEIPT, f, 9);
	return NULL;
}

static int record(void)
{
	struct nnb_cfg c = { .qd = 2, .size = 65536, .run_id = 1 };
	struct nnb_geom g;
	struct nnb_arm a = { .ops = &fake_ops, .c = &c, .g = &g, .next_gen = 1, .wire_session = 7,
			     .effective_qd = 2, .xsk_zerocopy = -1, .port = 1 };
	struct fake_peer fp = { .g = &g };
	pthread_t th;
	int sv[2], ret;

	CHECK(!nnb_geom_init(&g, 1500, 65536, 8U << 20));
	a.inflight_bytes = (uint64_t)c.qd * g.size;
	CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	a.ctl = sv[0], fp.fd = sv[1];
	CHECK(!pthread_create(&th, NULL, peer_thread, &fp));
	ret = run_trial(&a, 1, UNITS, "trial", 0, 0);
	pthread_join(th, NULL);
	if (ret)
		fprintf(stderr, "test_latency: run_trial: %s (%s)\n", strerror(-ret), a.diag);
	return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
	uint64_t start[1000], done[1000];
	struct nnb_arm a = { 0 };

	if (argc == 2 && !strcmp(argv[1], "--record"))
		return record();
	/* Durations 1..1000 ns in a scrambled order (7 is coprime to 1000). */
	for (unsigned u = 0; u < 1000; u++)
		start[u] = 100 + u, done[u] = start[u] + 1 + (u * 7) % 1000;
	CHECK(!unit_latencies(&a, start, done, 1000));
	for (unsigned u = 0; u < 1000; u++)
		CHECK(start[u] == u + 1);
	CHECK(rank(start, 1000, 1, 2) == 500 && rank(start, 1000, 9, 10) == 900);
	CHECK(rank(start, 1000, 99, 100) == 990 && rank(start, 1000, 999, 1000) == 999);
	/* Nearest rank of few samples: four units, p99 and p99.9 are the maximum. */
	CHECK(rank(start, 4, 1, 2) == 2 && rank(start, 4, 99, 100) == 4 && rank(start, 4, 999, 1000) == 4);
	CHECK(rank(start, 1, 1, 2) == 1);
	/* A unit without a start stamp, or ending before it began, is a defect. */
	start[3] = 0, done[3] = 50;
	CHECK(unit_latencies(&a, start, done, 4) == -EPROTO && strstr(a.diag, "unit 3"));
	for (unsigned u = 0; u < 4; u++)
		start[u] = 10, done[u] = 20;
	done[2] = 9;
	CHECK(unit_latencies(&a, start, done, 4) == -EPROTO);
	puts("nnb latency: per-unit stamps, missing stamps refused, nearest-rank percentiles PASS");
	return 0;
}
