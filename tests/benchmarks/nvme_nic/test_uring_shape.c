// SPDX-License-Identifier: GPL-2.0
/*
 * Submission shape of the reverse uring arm (nnb_uring.c, post_recvs), as
 * host C against a real ring that is never submitted with these SQEs.
 *
 * Several READV_FIXED requests outstanding on one UDP socket do not complete
 * in posting order: each one that sees -EAGAIN arms a non-exclusive poll
 * entry at the head of the socket's wait queue, so a wakeup reaches the
 * newest request first.  The arm therefore posts its receives as one
 * IOSQE_IO_LINK chain (a linked request is issued only after the previous one
 * completed) and posts the next chain only after every receive of the
 * current one completed.  This test pins that shape: every receive SQE except
 * the last of a chain carries IOSQE_IO_LINK, a chain is never split across a
 * submit, no receive is posted while a chain is still owed, and a chain is
 * not posted when the CQ could not hold its completions.  Run order on a
 * kernel with READV_FIXED is not verified by this test.
 */
#define NNB_HAVE_URING 1
#include "nnb_uring.c"

#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "test_uring_shape: line %d: %s\n", \
	__LINE__, #cond); exit(1); } } while (0)

uint64_t nnb_now(void) { return 1; }
uint64_t nnb_unit_gen(const struct nnb_trial *t, const struct nnb_geom *g, uint64_t u)
{
	return t->first_gen + u * g->groups_per_unit;
}
uint64_t nnb_unit_offset(const struct nnb_arm *a, const struct nnb_trial *t, uint64_t u)
{
	return nnb_gen_offset(a->g, nnb_unit_gen(t, a->g, u));
}
int nnb_udp_socket(const struct nnb_arm *a, int connect_peer, int gso)
{
	(void)a, (void)connect_peer, (void)gso;
	return -ENODEV;
}
void *nnb_alloc(size_t bytes) { return calloc(1, bytes); }
int nnb_rev_go(struct nnb_arm *a, const struct nnb_trial *t, uint32_t burst)
{
	(void)a, (void)t, (void)burst;
	return 0;
}
int nnb_rev_sent(struct nnb_arm *a, const struct nnb_trial *t, uint32_t burst)
{
	(void)a, (void)t, (void)burst;
	return 0;
}
int nnb_fill_headers(const struct nnb_geom *g, unsigned char *hdrs, uint64_t session)
{
	(void)g, (void)hdrs, (void)session;
	return 0;
}
void nnb_set_unit_gen(const struct nnb_geom *g, unsigned char *hdrs, uint64_t gen0)
{
	(void)g, (void)hdrs, (void)gen0;
}

static unsigned pending(const struct upriv *p)
{
	return p->ring.sq.sqe_tail - p->ring.sq.sqe_head;
}

static const struct io_uring_sqe *sqe_at(const struct upriv *p, unsigned i)
{
	return &p->ring.sq.sqes[(p->ring.sq.sqe_head + i) & *p->ring.sq.kring_mask];
}

/* The @n unsubmitted SQEs are one chain for receives first..first+n-1. */
static void check_chain(const struct nnb_arm *a, const struct upriv *p, uint64_t first, unsigned n)
{
	const struct nnb_geom *g = a->g;

	CHECK(pending(p) == n);
	for (unsigned i = 0; i < n; i++) {
		const struct io_uring_sqe *sqe = sqe_at(p, i);
		uint64_t d = first + i;
		unsigned slot = (unsigned)(d / g->dgrams_per_unit);
		uint32_t dj = (uint32_t)(d % g->dgrams_per_unit), k = dj / g->dgrams, rel, len;
		const struct iovec *iov = (const struct iovec *)(uintptr_t)sqe->addr;

		nnb_dgram(g, dj % g->dgrams, &rel, &len);
		CHECK(sqe->opcode == IORING_OP_READV_FIXED);
		CHECK(sqe->fd == p->sock && sqe->off == 0 && sqe->len == 2);
		CHECK(sqe->buf_index == slot);
		CHECK(sqe->user_data == ud(U_RECV, slot, dj));
		CHECK(iov[0].iov_base == p->slot[slot].hdrs + (size_t)dj * NNB_HDR_LEN &&
		      iov[0].iov_len == NNB_HDR_LEN);
		CHECK(iov[1].iov_base == p->slot[slot].payload + (size_t)k * g->group + rel &&
		      iov[1].iov_len == len);
		/* Linked in posting order; the chain ends at its last receive. */
		if (i + 1 < n)
			CHECK(sqe->flags & IOSQE_IO_LINK);
		else
			CHECK(!(sqe->flags & IOSQE_IO_LINK));
	}
}

static void slots(struct upriv *p, const struct nnb_geom *g, unsigned qd)
{
	size_t hdr_bytes = ((size_t)g->dgrams_per_unit * NNB_HDR_LEN + 4095) & ~(size_t)4095;

	for (unsigned i = 0; i < qd; i++) {
		struct uslot *s = &p->slot[i];

		s->bytes = hdr_bytes + g->size;
		s->base = calloc(1, s->bytes);
		s->iov = calloc(2 * (size_t)g->dgrams_per_unit, sizeof(*s->iov));
		CHECK(s->base && s->iov);
		s->hdrs = s->base, s->payload = s->base + hdr_bytes;
	}
}

/* A probe that lists exactly the opcodes in @ops. */
static struct io_uring_probe *probe_of(const unsigned *ops, unsigned n)
{
	struct io_uring_probe *probe = calloc(1, sizeof(*probe) + 256 * sizeof(probe->ops[0]));

	CHECK(probe);
	probe->last_op = IORING_OP_LAST - 1;
	probe->ops_len = IORING_OP_LAST;
	for (unsigned i = 0; i < n; i++)
		probe->ops[ops[i]].flags = IO_URING_OP_SUPPORTED;
	return probe;
}

static void check_probe(void)
{
	/* 6.1..6.14: SENDMSG_ZC without fixed vectors, no READV_FIXED. */
	static const unsigned pre_6_15[] = { IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
					     IORING_OP_SENDMSG_ZC };
	static const unsigned v6_15[] = { IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
					  IORING_OP_SENDMSG_ZC, IORING_OP_READV_FIXED };
	struct io_uring_probe *old = probe_of(pre_6_15, 3), *cur = probe_of(v6_15, 4);

	CHECK(!uring_kernel_ok(old, 0) && !uring_kernel_ok(old, 1));
	CHECK(uring_kernel_ok(cur, 0) && uring_kernel_ok(cur, 1));
	free(old), free(cur);
}

int main(void)
{
	struct nnb_cfg c = { .reverse = 1, .qd = 8 };
	struct nnb_geom g;
	struct nnb_arm a = { .c = &c, .g = &g, .wire_session = 7 };
	static struct upriv p;
	uint64_t total, posted = 0;
	unsigned owed = 0, filler = 0;

	check_probe();
	CHECK(!nnb_geom_init(&g, 1500, 65536, 8U << 20));
	total = (uint64_t)c.qd * g.dgrams_per_unit;
	CHECK(total > U_RECV_WINDOW && total < 2 * U_RECV_WINDOW);
	if (io_uring_queue_init(U_RING_ENTRIES, &p.ring, 0) < 0) {
		fprintf(stderr, "test_uring_shape: io_uring_queue_init refused on this host\n");
		return 1;
	}
	p.ring_ok = 1;
	p.sock = 1000;	/* never submitted with a receive */
	p.cq_entries = *p.ring.cq.kring_entries;
	slots(&p, &g, c.qd);

	/* First chain: U_RECV_WINDOW linked receives. */
	CHECK(!post_recvs(&a, &p, &posted, total, &owed));
	CHECK(posted == U_RECV_WINDOW && owed == U_RECV_WINDOW && p.outstanding == U_RECV_WINDOW);
	check_chain(&a, &p, 0, U_RECV_WINDOW);
	/* Nothing more while the chain is owed, even after some completions. */
	owed -= 10, p.outstanding -= 10;
	CHECK(!post_recvs(&a, &p, &posted, total, &owed));
	CHECK(posted == U_RECV_WINDOW && pending(&p) == U_RECV_WINDOW);
	/* Chain done: the rest is the next chain. */
	io_uring_queue_exit(&p.ring);
	CHECK(io_uring_queue_init(U_RING_ENTRIES, &p.ring, 0) == 0);
	owed = 0, p.outstanding = 0;
	CHECK(!post_recvs(&a, &p, &posted, total, &owed));
	CHECK(posted == total && owed == total - U_RECV_WINDOW);
	check_chain(&a, &p, U_RECV_WINDOW, (unsigned)(total - U_RECV_WINDOW));

	/* A chain that does not fit the CQ is deferred, not truncated. */
	io_uring_queue_exit(&p.ring);
	CHECK(io_uring_queue_init(U_RING_ENTRIES, &p.ring, 0) == 0);
	posted = 0, owed = 0, p.outstanding = p.cq_entries - 10;
	CHECK(!post_recvs(&a, &p, &posted, total, &owed));
	CHECK(posted == 0 && owed == 0 && pending(&p) == 0);

	/* A full SQ is submitted before the chain, so the chain is never split. */
	p.outstanding = 0;
	while (io_uring_sq_space_left(&p.ring) > 100) {
		io_uring_prep_nop(io_uring_get_sqe(&p.ring));
		filler++;
	}
	CHECK(!post_recvs(&a, &p, &posted, total, &owed));
	CHECK(posted == U_RECV_WINDOW);
	check_chain(&a, &p, 0, U_RECV_WINDOW);
	CHECK(filler > 0);

	io_uring_queue_exit(&p.ring);
	puts("nnb uring shape: probe needs the 6.15 fixed-vector opcodes in both directions, "
	     "reverse receives one IOSQE_IO_LINK chain at a time, never split, CQ room checked PASS");
	return 0;
}
