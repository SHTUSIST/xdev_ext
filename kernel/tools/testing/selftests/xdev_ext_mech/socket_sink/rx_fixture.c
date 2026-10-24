/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Socket adapter FROM_DEVICE (NIC-boundary copy RX) and copy-mode accounting,
 * from track S API.md sections 2.2, 3.1-3.9 and 1.3. Appended after shim.h and
 * the production text of io_uring/xdev_ext_mech_socket.c (everything before the
 * class table). Real loopback UDP sockets carry the datagrams; the session,
 * worker kick, completion and counter boundaries are the shim's.
 * One case per run: rx_fixture <case>.
 */
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

static const char *test_case;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL case=%s line=%d: %s (errno=%d)\n", \
	test_case, __LINE__, #x, errno); exit(1); } } while (0)

#define DEPTH 8U
#define FRAME 2048U
#define HDR 16U
#define SEG 1000U
#define GROUP 1500U
#define CANARY 0xa5

struct rx {
	struct sock sk;
	struct socket sock;
	struct file file;
	struct xdev_ext_mech_session s;
	struct xdev_ext_mech_stage st;
	struct xdev_ext_mech_batch b[DEPTH];
	struct xdev_ext_socket_send_desc d[DEPTH][2];
	u8 pages[2 * DEPTH][FRAME];
	int fd, peer;
	u64 next_ticket;
};

static int original_ready_calls;
static void original_ready(struct sock *sk) { (void)sk; original_ready_calls++; }

static void reset_counters(void)
{
	memset(shim_counters, 0, sizeof(shim_counters));
	shim_kicks = 0; recv_calls = 0; forced_recv = 999999; recv_hook = NULL;
	shim_fail_alloc_at = 0;
}

/* A bound loopback receiver and a connected sender. */
static void sockets(struct rx *r, int family)
{
	struct sockaddr_storage a = { 0 };
	socklen_t alen;
	int big = 1 << 22;

	r->fd = socket(family, SOCK_DGRAM, 0);
	r->peer = socket(family, SOCK_DGRAM, 0);
	CHECK(r->fd >= 0 && r->peer >= 0);
	if (family == AF_INET) {
		struct sockaddr_in *in = (void *)&a;
		in->sin_family = AF_INET; in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		alen = sizeof(*in);
	} else {
		struct sockaddr_in6 *in6 = (void *)&a;
		in6->sin6_family = AF_INET6; in6->sin6_addr = in6addr_loopback;
		alen = sizeof(*in6);
	}
	(void)setsockopt(r->fd, SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	CHECK(!bind(r->fd, (void *)&a, alen));
	CHECK(!getsockname(r->fd, (void *)&a, &alen));
	CHECK(!connect(r->peer, (void *)&a, alen));
}

static void batch_init(struct rx *r, u32 k)
{
	struct xdev_ext_mech_batch *b = &r->b[k];
	u32 i;

	memset(b, 0, sizeof(*b));
	b->nr = 2; b->bytes = GROUP; b->slot = k; b->key = k + 1;
	b->ticket = ++r->next_ticket;
	for (i = 0; i < 2; i++) {
		u32 idx = 2 * k + i;
		b->f[i] = (struct xdev_ext_mech_frame) {
			.kaddr = r->pages[idx], .umem_addr = (u64)idx * FRAME, .index = idx,
			.data_off = HDR, .data_len = i ? GROUP - SEG : SEG,
		};
		r->d[k][i] = (struct xdev_ext_socket_send_desc) {
			.frame_pos = i, .frame_off = HDR, .len = b->f[i].data_len,
		};
		r->s.pool.state[idx] = XDEV_EXT_MECH_F_INFLIGHT;
		memset(r->pages[idx], CANARY, FRAME);
	}
}

static void setup_family(struct rx *r, int family)
{
	u32 k;

	memset(r, 0, sizeof(*r));
	reset_counters();
	sockets(r, family);
	r->sk = (struct sock) { .sk_family = family, .sk_protocol = IPPROTO_UDP,
				.sk_state = 7 /* TCP_CLOSE: bound, not connected */ };
	r->sk.sk_data_ready = original_ready;
	r->sock = (struct socket) { .type = SOCK_DGRAM, .fd = r->fd, .sk = &r->sk };
	r->file.sock = &r->sock;
	r->s = (struct xdev_ext_mech_session) { .depth = DEPTH, .admits = true,
		.pool = { .frame_size = FRAME, .nr_frames = 2 * DEPTH },
		.l = { .frame_size = FRAME, .hdr_room = HDR, .seg_len = SEG, .group_bytes = GROUP } };
	r->st = (struct xdev_ext_mech_stage) { .file = &r->file, .s = &r->s,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .class_id = XDEV_EXT_MECH_CLASS_SOCKET };
	for (k = 0; k < DEPTH; k++)
		batch_init(r, k);
}

static int bind_rx(struct rx *r)
{
	struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_SOCKET,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 3 };

	return xdev_ext_socket_class_bind(&r->st, &u);
}

static void setup(struct rx *r, int family)
{
	setup_family(r, family);
	CHECK(bind_rx(r) == 0);
}

static void teardown(struct rx *r)
{
	xdev_ext_socket_class_unbind(&r->st);
	CHECK(r->sk.sk_data_ready == original_ready);
	CHECK(r->sk.sk_user_data == NULL);
	close(r->fd); close(r->peer);
}

static void arm(struct rx *r, u32 k)
{
	CHECK(!xdev_ext_socket_validate(&r->st, &r->b[k], (const u8 *)r->d[k], 2));
	CHECK(xdev_ext_socket_class_submit(&r->st, &r->b[k]) == 0);
}

static void rearm(struct rx *r, u32 k)
{
	batch_init(r, k);
	arm(r, k);
}

static u8 pattern(u32 seed, u32 i) { return (u8)(seed * 131u + i * 7u + 3u); }

static void send_dgram(struct rx *r, u32 len, u32 seed)
{
	static u8 buf[70000];
	u32 i;

	for (i = 0; i < len; i++)
		buf[i] = pattern(seed, i);
	CHECK(send(r->peer, buf, len, 0) == (ssize_t)len);
}

/* The softirq side: UDP enqueue invokes sk->sk_data_ready. */
static void softirq_ready(struct rx *r) { r->sk.sk_data_ready(&r->sk); }

static void check_payload(struct rx *r, u32 k, u32 len, u32 seed)
{
	struct xdev_ext_mech_batch *b = &r->b[k];
	u32 i, f;

	for (i = 0; i < len; i++) {
		u32 pos = i < SEG ? 0 : 1, off = i < SEG ? i : i - SEG;
		CHECK(((u8 *)b->f[pos].kaddr)[HDR + off] == pattern(seed, i));
	}
	/* Nothing outside the datagram's bytes inside the spans, nor outside the spans. */
	for (f = 0; f < 2; f++) {
		u8 *p = b->f[f].kaddr;
		u32 lo = HDR + (f ? (len > SEG ? len - SEG : 0) : (len < SEG ? len : SEG));
		for (i = 0; i < HDR; i++)
			CHECK(p[i] == CANARY);
		for (i = lo; i < FRAME; i++)
			CHECK(p[i] == CANARY);
	}
}

static void check_ok(struct rx *r, u32 k, u32 len, u32 seed)
{
	struct xdev_ext_socket_mech_cqe cqe;

	CHECK(r->b[k].completions == 1 && !r->b[k].cancelled && !r->b[k].stale);
	CHECK(r->b[k].status == 0 && r->b[k].produced == len);
	check_payload(r, k, len, seed);
	memset(&cqe, 0xff, sizeof(cqe));
	xdev_ext_socket_class_fill_cqe(&r->st, &r->b[k], &cqe);
	CHECK(cqe.status == 0 && cqe.bytes_received == len && cqe.bytes_sent == 0 && cqe.flags == 0);
}

static void check_no_zc(void)
{
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_ZC_OPS] == 0);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_ZC_BYTES] == 0);
}

/* --- cases ------------------------------------------------------------- */

static int bind_rules(void)
{
	struct rx r;
	struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_SOCKET,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 3 };
	int allocs, frees, n, ok_allocs;

	setup_family(&r, AF_INET);
#define REFUSED(expr, want) do { allocs = shim_alloc_calls; frees = shim_free_calls; \
	CHECK((expr) == (want)); \
	CHECK(shim_alloc_calls - allocs == shim_free_calls - frees); \
	CHECK(r.sk.sk_data_ready == original_ready && r.st.priv == NULL); \
	CHECK(host_cred.refs == 1); } while (0)
	u.flags = 1; REFUSED(xdev_ext_socket_class_bind(&r.st, &u), -EINVAL); u.flags = 0;
	u.arg0 = 1; REFUSED(xdev_ext_socket_class_bind(&r.st, &u), -EINVAL); u.arg0 = 0;
	u.arg1 = 1; REFUSED(xdev_ext_socket_class_bind(&r.st, &u), -EINVAL); u.arg1 = 0;
	r.file.sock = NULL; REFUSED(bind_rx(&r), -ENOTSOCK); r.file.sock = &r.sock;
	r.sock.type = SOCK_STREAM; REFUSED(bind_rx(&r), -EPROTONOSUPPORT); r.sock.type = SOCK_DGRAM;
	r.sk.sk_protocol = IPPROTO_TCP; REFUSED(bind_rx(&r), -EPROTONOSUPPORT); r.sk.sk_protocol = IPPROTO_UDP;
	r.sk.sk_family = AF_UNIX; REFUSED(bind_rx(&r), -EPROTONOSUPPORT); r.sk.sk_family = AF_INET;
	r.sock.sk = NULL; REFUSED(bind_rx(&r), -EPROTONOSUPPORT); r.sock.sk = &r.sk;
	r.sk.sk_shutdown = RCV_SHUTDOWN; REFUSED(bind_rx(&r), -ESHUTDOWN); r.sk.sk_shutdown = 0;
	r.sk.udp.gro = true; REFUSED(bind_rx(&r), -EOPNOTSUPP); r.sk.udp.gro = false;
	r.sk.udp.encap = true; REFUSED(bind_rx(&r), -EOPNOTSUPP); r.sk.udp.encap = false;
	r.sk.sk_user_data = &r; REFUSED(bind_rx(&r), -EBUSY);
	CHECK(r.sk.sk_user_data == &r); r.sk.sk_user_data = NULL;
	r.st.direction = 7; REFUSED(bind_rx(&r), -EINVAL); r.st.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;

	/* Success on a bound, unconnected socket; callbacks installed under the writer lock. */
	allocs = shim_alloc_calls; frees = shim_free_calls; n = shim_write_locks;
	CHECK(bind_rx(&r) == 0);
	ok_allocs = shim_alloc_calls - allocs;
	CHECK(ok_allocs >= 1 && r.st.priv != NULL);
	CHECK(r.sk.sk_user_data != NULL && r.sk.sk_data_ready != original_ready);
	CHECK(shim_write_locks > n && r.sk.sk_callback_lock.v == 0);
	CHECK(host_cred.refs == 2);
	/* A second receiver on the same socket is refused. */
	{
		struct xdev_ext_mech_stage st2 = r.st;
		st2.priv = NULL;
		CHECK(xdev_ext_socket_class_bind(&st2, &u) == -EBUSY && st2.priv == NULL);
	}
	n = shim_write_locks;
	xdev_ext_socket_class_unbind(&r.st);
	CHECK(shim_write_locks > n && r.sk.sk_callback_lock.v == 0);
	CHECK(r.sk.sk_data_ready == original_ready && r.sk.sk_user_data == NULL && r.st.priv == NULL);
	CHECK(shim_alloc_calls - allocs == shim_free_calls - frees);
	CHECK(host_cred.refs == 1);

	/* Every allocation failure is clean. */
	for (n = 1; n <= ok_allocs; n++) {
		shim_alloc_calls = 0; shim_free_calls = 0; shim_fail_alloc_at = n;
		CHECK(bind_rx(&r) == -ENOMEM);
		CHECK(shim_alloc_calls - 1 == shim_free_calls);
		CHECK(r.sk.sk_data_ready == original_ready && r.sk.sk_user_data == NULL && r.st.priv == NULL);
		CHECK(host_cred.refs == 1);
	}
	shim_fail_alloc_at = 0;
	close(r.fd); close(r.peer);
#undef REFUSED
	puts("PASS socket rx bind_rules");
	return 0;
}

static int fifo_exact(int family)
{
	struct rx r;
	int recv0, kicks0;

	setup(&r, family);
	{
		struct xdev_ext_socket_mech_info info;

		xdev_ext_socket_fill_info(&r.st, &r.b[3], &info);	/* shared with TX */
		CHECK(info.nr_frames == 2 && info.max_datagram == XDEV_EXT_SOCKET_MAX_DATAGRAM);
		CHECK(info.f[0].data_off == HDR && info.f[0].data_len == SEG && info.f[1].data_len == GROUP - SEG);
		CHECK(info.l.group_bytes == GROUP && info.f[1].umem_addr == 7ULL * FRAME);
	}
	arm(&r, 3); arm(&r, 0); arm(&r, 5);
	send_dgram(&r, GROUP, 11); send_dgram(&r, GROUP, 22); send_dgram(&r, GROUP, 33);
	recv0 = recv_calls; kicks0 = shim_kicks;
	softirq_ready(&r);
	CHECK(recv_calls == recv0);		/* data_ready never receives */
	CHECK(shim_kicks > kicks0);		/* it wakes the session worker */
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	check_ok(&r, 3, GROUP, 11); check_ok(&r, 0, GROUP, 22); check_ok(&r, 5, GROUP, 33);
	CHECK(r.b[3].order < r.b[0].order && r.b[0].order < r.b[5].order);
	CHECK(r.b[1].completions == 0 && r.b[2].completions == 0);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 3);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == 3 * GROUP);
	check_no_zc();
	/* Nothing armed: progress does not touch the socket. */
	recv0 = recv_calls;
	CHECK(xdev_ext_socket_progress(&r.st) == 0 && recv_calls == recv0);
	teardown(&r);
	printf("PASS socket rx fifo_exact family=%d\n", family);
	return 0;
}

static int short_datagram(void)
{
	struct rx r;

	setup(&r, AF_INET);
	arm(&r, 2);
	send_dgram(&r, 700, 5);
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	check_ok(&r, 2, 700, 5);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 1);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == 700);
	teardown(&r);
	puts("PASS socket rx short_datagram");
	return 0;
}

static int truncation(void)
{
	struct rx r;
	struct xdev_ext_socket_mech_cqe cqe;
	u32 f, i;

	setup(&r, AF_INET);
	arm(&r, 0); arm(&r, 1);
	send_dgram(&r, GROUP + 100, 7);
	send_dgram(&r, GROUP, 8);
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(r.b[0].completions == 1 && r.b[0].status == -EMSGSIZE && r.b[0].produced == 0 && !r.b[0].cancelled);
	xdev_ext_socket_class_fill_cqe(&r.st, &r.b[0], &cqe);
	CHECK(cqe.status == -EMSGSIZE && cqe.bytes_received == 0 && cqe.bytes_sent == 0 &&
	      cqe.flags == XDEV_EXT_SOCKET_CQE_F_TRUNC);
	/* The receive never wrote outside the batch spans. */
	for (f = 0; f < 2; f++) {
		u8 *p = r.b[0].f[f].kaddr;
		for (i = 0; i < HDR; i++)
			CHECK(p[i] == CANARY);
		for (i = HDR + r.b[0].f[f].data_len; i < FRAME; i++)
			CHECK(p[i] == CANARY);
	}
	/* The truncated remainder did not leak into the next batch. */
	check_ok(&r, 1, GROUP, 8);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 1);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == GROUP);
	check_no_zc();
	teardown(&r);
	puts("PASS socket rx truncation");
	return 0;
}

static int zero_length(void)
{
	struct rx r;
	struct xdev_ext_socket_mech_cqe cqe;

	setup(&r, AF_INET);
	arm(&r, 0);
	send_dgram(&r, 0, 0);
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(r.b[0].completions == 1 && r.b[0].status == -ENODATA && r.b[0].produced == 0);
	xdev_ext_socket_class_fill_cqe(&r.st, &r.b[0], &cqe);
	CHECK(cqe.status == -ENODATA && cqe.bytes_received == 0 && cqe.flags == 0);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 0);
	teardown(&r);
	puts("PASS socket rx zero_length");
	return 0;
}

static int native_error(void)
{
	struct rx r;
	struct xdev_ext_socket_mech_cqe cqe;

	setup(&r, AF_INET);
	arm(&r, 4);
	forced_recv = -ECONNREFUSED;
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(r.b[4].completions == 1 && r.b[4].status == -ECONNREFUSED && !r.b[4].cancelled);
	xdev_ext_socket_class_fill_cqe(&r.st, &r.b[4], &cqe);
	CHECK(cqe.status == -ECONNREFUSED && cqe.bytes_received == 0);
	forced_recv = 999999;
	rearm(&r, 4);
	send_dgram(&r, GROUP, 9);
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	check_ok(&r, 4, GROUP, 9);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 1);
	teardown(&r);
	puts("PASS socket rx native_error");
	return 0;
}

static int no_polling(void)
{
	struct rx r;
	int i, recv0, kicks0;

	setup(&r, AF_INET);
	recv0 = recv_calls;
	arm(&r, 0); arm(&r, 1);		/* submit never returns -EAGAIN (1-jiffy retry timer) */
	CHECK(r.b[0].completions == 0 && r.b[1].completions == 0);
	for (i = 0; i < 100; i++)
		CHECK(xdev_ext_socket_progress(&r.st) == 0);	/* never a delayed re-poll */
	/* Empty socket: at most one would-block receive per call, never a retry loop. */
	CHECK(recv_calls - recv0 <= 102);
	CHECK(r.b[0].completions == 0 && r.b[1].completions == 0);
	kicks0 = shim_kicks; recv0 = recv_calls;
	softirq_ready(&r);		/* spurious wakeup */
	CHECK(shim_kicks > kicks0 && recv_calls == recv0);
	send_dgram(&r, GROUP, 1);
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	check_ok(&r, 0, GROUP, 1);
	CHECK(r.b[1].completions == 0);
	/* The remaining armed request is cancelled at STOP so drain can finish. */
	r.s.admits = false;
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(r.b[1].completions == 1 && r.b[1].cancelled == 1);
	teardown(&r);
	puts("PASS socket rx no_polling");
	return 0;
}

static int queued_before_arm(void)
{
	struct rx r;
	int kicks0;

	setup(&r, AF_INET);
	send_dgram(&r, GROUP, 44);
	softirq_ready(&r);		/* event with nothing armed */
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(r.b[6].completions == 0);
	kicks0 = shim_kicks;
	arm(&r, 6);
	if (r.b[6].completions == 0) {
		/* No further data_ready will come: submit must have woken the worker. */
		CHECK(shim_kicks > kicks0);
		CHECK(xdev_ext_socket_progress(&r.st) == 0);
	}
	check_ok(&r, 6, GROUP, 44);
	teardown(&r);
	puts("PASS socket rx queued_before_arm");
	return 0;
}

static struct rx *hook_rx;
static int hook_kicks_before, hook_kicks_after, hook_fired;
static void ready_after_would_block(int rc)
{
	if (rc != -EAGAIN || hook_fired)
		return;
	hook_fired = 1;
	send_dgram(hook_rx, GROUP, 55);
	hook_kicks_before = shim_kicks;
	softirq_ready(hook_rx);		/* arrives while the worker is inside progress */
	hook_kicks_after = shim_kicks;
}

static int ready_during_progress(void)
{
	struct rx r;

	setup(&r, AF_INET);
	arm(&r, 7);
	hook_rx = &r; recv_hook = ready_after_would_block;
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	recv_hook = NULL;
	CHECK(hook_fired == 1);
	CHECK(hook_kicks_after > hook_kicks_before);	/* not suppressed while progress runs */
	if (r.b[7].completions == 0)
		CHECK(xdev_ext_socket_progress(&r.st) == 0);	/* the kicked pass */
	check_ok(&r, 7, GROUP, 55);
	teardown(&r);
	puts("PASS socket rx ready_during_progress");
	return 0;
}

static int drain_all_in_one_pass(void)
{
	struct rx r;
	int allocs, recv0, kicks0;
	u32 k;

	setup(&r, AF_INET);
	allocs = shim_alloc_calls;
	for (k = 0; k < DEPTH; k++)
		arm(&r, k);		/* depth requests in flight at once */
	for (k = 0; k < DEPTH + 1; k++)
		send_dgram(&r, GROUP, 100 + k);
	recv0 = recv_calls;
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	for (k = 0; k < DEPTH; k++)
		check_ok(&r, k, GROUP, 100 + k);
	CHECK(recv_calls - recv0 >= (int)DEPTH && recv_calls - recv0 <= (int)DEPTH + 1);
	kicks0 = shim_kicks;
	rearm(&r, 0);
	if (r.b[0].completions == 0) {
		CHECK(shim_kicks > kicks0);
		CHECK(xdev_ext_socket_progress(&r.st) == 0);
	}
	check_ok(&r, 0, GROUP, 100 + DEPTH);
	CHECK(shim_alloc_calls == allocs);	/* no per-datagram allocation */
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == DEPTH + 1);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == (DEPTH + 1) * GROUP);
	check_no_zc();
	teardown(&r);
	puts("PASS socket rx drain_all_in_one_pass depth=8");
	return 0;
}

static int duplicate_arm(void)
{
	struct rx r;

	setup(&r, AF_INET);
	arm(&r, 2);
	CHECK(xdev_ext_socket_class_submit(&r.st, &r.b[2]) == -EBUSY);
	send_dgram(&r, GROUP, 3); send_dgram(&r, GROUP, 4);
	softirq_ready(&r);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	check_ok(&r, 2, GROUP, 3);	/* one completion, the second datagram stays queued */
	rearm(&r, 2);
	if (r.b[2].completions == 0)
		CHECK(xdev_ext_socket_progress(&r.st) == 0);
	check_ok(&r, 2, GROUP, 4);
	teardown(&r);
	puts("PASS socket rx duplicate_arm");
	return 0;
}

static int submit_guards(void)
{
	struct rx r;
	int c, recv0;

	for (c = 0; c < 5; c++) {
		int want[] = { -ENODEV, -ESHUTDOWN, -EINVAL, -ESHUTDOWN, -EBUSY };

		setup(&r, AF_INET);
		CHECK(!xdev_ext_socket_validate(&r.st, &r.b[1], (const u8 *)r.d[1], 2));
		if (c == 0) xdev_ext_socket_class_mark_dead(&r.st);
		if (c == 1) r.s.admits = false;
		if (c == 2) r.b[1].slot = DEPTH;
		if (c == 3) r.sk.sk_shutdown = RCV_SHUTDOWN;
		if (c == 4) r.s.pool.state[3] = XDEV_EXT_MECH_F_HELD;
		recv0 = recv_calls;
		CHECK(xdev_ext_socket_class_submit(&r.st, &r.b[1]) == want[c]);
		CHECK(recv_calls == recv0 && r.b[1].completions == 0);
		/* Nothing was armed: no completion can follow. */
		r.s.admits = true; r.sk.sk_shutdown = 0;
		send_dgram(&r, GROUP, 1);
		softirq_ready(&r);
		CHECK(xdev_ext_socket_progress(&r.st) == 0);
		CHECK(r.b[1].completions == 0);
		teardown(&r);
	}
	puts("PASS socket rx submit_guards");
	return 0;
}

static int stop_cancels(void)
{
	struct rx r;
	struct xdev_ext_socket_mech_cqe cqe;
	int recv0;

	setup(&r, AF_INET);
	arm(&r, 5); arm(&r, 1); arm(&r, 6);
	send_dgram(&r, GROUP, 1);
	r.s.admits = false;		/* STOP */
	recv0 = recv_calls;
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(recv_calls == recv0);
	CHECK(r.b[5].cancelled == 1 && r.b[1].cancelled == 1 && r.b[6].cancelled == 1);
	CHECK(r.b[5].status == -ESHUTDOWN && r.b[1].status == -ESHUTDOWN && r.b[6].status == -ESHUTDOWN);
	CHECK(r.b[5].completions == 1 && r.b[1].completions == 1 && r.b[6].completions == 1);
	CHECK(r.b[5].order < r.b[1].order && r.b[1].order < r.b[6].order);
	xdev_ext_socket_class_fill_cqe(&r.st, &r.b[1], &cqe);
	CHECK(cqe.status == -ESHUTDOWN && cqe.bytes_received == 0 && cqe.flags == 0);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 0);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(r.b[5].completions == 1 && r.b[1].completions == 1 && r.b[6].completions == 1);
	teardown(&r);
	puts("PASS socket rx stop_cancels");
	return 0;
}

static int dead_cancels(void)
{
	struct rx r;
	int kicks0, recv0;

	setup(&r, AF_INET);
	arm(&r, 0); arm(&r, 3);
	send_dgram(&r, GROUP, 1);
	kicks0 = shim_kicks; recv0 = recv_calls;
	xdev_ext_socket_class_mark_dead(&r.st);
	CHECK(shim_kicks > kicks0 && recv_calls == recv0);
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(recv_calls == recv0);
	CHECK(r.b[0].cancelled == 1 && r.b[3].cancelled == 1);
	CHECK(r.b[0].status == -ENODEV && r.b[3].status == -ENODEV);
	CHECK(r.b[0].order < r.b[3].order);
	batch_init(&r, 2);
	CHECK(!xdev_ext_socket_validate(&r.st, &r.b[2], (const u8 *)r.d[2], 2));
	CHECK(xdev_ext_socket_class_submit(&r.st, &r.b[2]) == -ENODEV);
	teardown(&r);
	puts("PASS socket rx dead_cancels");
	return 0;
}

static int credentials(void)
{
	static struct cred worker = { .refs = 1 };
	struct rx r;

	setup(&r, AF_INET);
	CHECK(host_cred.refs == 2);
	arm(&r, 0);
	host_active_cred = &worker;	/* the shared session worker */
	CHECK(xdev_ext_socket_progress(&r.st) == 0);	/* would-block receive */
	CHECK(recv_calls == 0 || recv_cred == &host_cred);
	CHECK(host_active_cred == &worker);
	send_dgram(&r, GROUP, 2);
	softirq_ready(&r);
	recv_cred = NULL;
	CHECK(xdev_ext_socket_progress(&r.st) == 0);
	CHECK(recv_cred == &host_cred);	/* LSM recvmsg hook sees the CREATE caller */
	CHECK(host_active_cred == &worker);
	check_ok(&r, 0, GROUP, 2);
	host_active_cred = &host_cred;
	teardown(&r);
	CHECK(host_cred.refs == 1 && worker.refs == 1);
	puts("PASS socket rx credentials");
	return 0;
}

/* A softirq that read the installed callback pointer may enter it after unbind. */
static atomic_int race_stop, race_calls;
static void (*race_cb)(struct sock *);
static struct sock *race_sk;
static void *race_thread(void *arg)
{
	(void)arg;
	while (!atomic_load(&race_stop)) {
		race_cb(race_sk);
		atomic_fetch_add(&race_calls, 1);
	}
	race_cb(race_sk);
	return NULL;
}

static int teardown_race(void)
{
	int round;

	for (round = 0; round < 50; round++) {
		struct rx *r = calloc(1, sizeof(*r));
		pthread_t t;
		int seen;

		CHECK(r);
		setup(r, AF_INET);
		race_cb = r->sk.sk_data_ready; race_sk = &r->sk;
		CHECK(race_cb != original_ready);
		atomic_store(&race_stop, 0); atomic_store(&race_calls, 0);
		CHECK(!pthread_create(&t, NULL, race_thread, NULL));
		while (atomic_load(&race_calls) < 2)
			sched_yield();
		xdev_ext_socket_class_unbind(&r->st);	/* frees RX state */
		CHECK(r->sk.sk_data_ready == original_ready && r->sk.sk_user_data == NULL);
		seen = atomic_load(&race_calls);
		while (atomic_load(&race_calls) < seen + 50)
			sched_yield();		/* stale-pointer entries after unbind */
		atomic_store(&race_stop, 1);
		CHECK(!pthread_join(t, NULL));
		close(r->fd); close(r->peer);
		free(r);
	}
	puts("PASS socket rx teardown_race rounds=50");
	return 0;
}

/*
 * Deterministic version: a softirq enters the installed callback exactly while
 * unbind holds sk_callback_lock for writing, before it restores and frees.
 * The callback must not have taken sk_user_data before that lock (or must be
 * inside an RCU section that unbind waits for). AddressSanitizer reports any
 * use of the freed RX state.
 */
static atomic_int inter_done, inter_unbound;
static pthread_t inter_thread;
static __thread int inter_is_softirq;
/* The softirq reader, once it holds the read lock, resumes only after unbind returned. */
static void inter_after_read_lock(void)
{
	if (!inter_is_softirq)
		return;
	while (!atomic_load(&inter_unbound))
		sched_yield();
}
static void *inter_softirq(void *arg)
{
	(void)arg;
	inter_is_softirq = 1;
	race_cb(race_sk);
	atomic_store(&inter_done, 1);
	return NULL;
}
static void inter_during_unbind(void)
{
	shim_write_lock_hook = NULL;
	CHECK(!pthread_create(&inter_thread, NULL, inter_softirq, NULL));
	while (!atomic_load(&inter_done) && !__atomic_load_n(&shim_read_waiters, __ATOMIC_SEQ_CST))
		sched_yield();
}

static int teardown_interleaved(void)
{
	int round;

	for (round = 0; round < 20; round++) {
		struct rx *r = calloc(1, sizeof(*r));

		CHECK(r);
		setup(r, AF_INET);
		arm(r, 0);
		CHECK(xdev_ext_socket_progress(&r->st) == 0);	/* would-block: stays armed */
		r->s.admits = false;
		CHECK(xdev_ext_socket_progress(&r->st) == 0);	/* STOP cancels before unbind */
		CHECK(r->b[0].cancelled == 1);
		race_cb = r->sk.sk_data_ready; race_sk = &r->sk;
		atomic_store(&inter_done, 0); atomic_store(&inter_unbound, 0);
		shim_read_lock_hook = inter_after_read_lock;
		shim_write_lock_hook = inter_during_unbind;
		xdev_ext_socket_class_unbind(&r->st);
		shim_write_lock_hook = NULL;
		atomic_store(&inter_unbound, 1);
		CHECK(!pthread_join(inter_thread, NULL));
		shim_read_lock_hook = NULL;
		CHECK(atomic_load(&inter_done) == 1);
		CHECK(r->sk.sk_data_ready == original_ready && r->sk.sk_user_data == NULL);
		close(r->fd); close(r->peer);
		free(r);
	}
	puts("PASS socket rx teardown_interleaved rounds=20");
	return 0;
}

/* TX copy accounting through the same class entry points. */
static int tx_accounting(void)
{
	struct sock sk = { .sk_family = AF_INET, .sk_protocol = IPPROTO_UDP, .sk_state = TCP_ESTABLISHED };
	struct socket sock = { .type = SOCK_DGRAM, .sk = &sk };
	struct file file = { .sock = &sock };
	struct xdev_ext_mech_session s = { .depth = 8, .admits = true,
		.pool = { .frame_size = FRAME, .nr_frames = 2 },
		.l = { .frame_size = FRAME, .hdr_room = HDR, .seg_len = SEG, .group_bytes = GROUP } };
	struct xdev_ext_mech_stage st = { .file = &file, .s = &s, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE };
	struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_SOCKET,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 3 };
	struct xdev_ext_mech_batch b = { .nr = 2, .bytes = GROUP, .ticket = 1 };
	struct xdev_ext_socket_send_desc d[2] = { { 0, HDR, SEG, 0 }, { 1, HDR, GROUP - SEG, 0 } };
	struct xdev_ext_socket_mech_cqe cqe;
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t alen = sizeof(a);
	static u8 pages[2][FRAME], got[GROUP + 1];
	int peer = socket(AF_INET, SOCK_DGRAM, 0), recv0, g;
	void (*ready)(struct sock *) = original_ready;

	reset_counters();
	sk.sk_data_ready = ready;
	CHECK(peer >= 0 && !bind(peer, (void *)&a, sizeof(a)) && !getsockname(peer, (void *)&a, &alen));
	sock.fd = socket(AF_INET, SOCK_DGRAM, 0);
	CHECK(sock.fd >= 0 && !connect(sock.fd, (void *)&a, sizeof(a)));
	for (g = 0; g < 2; g++) {
		b.f[g] = (struct xdev_ext_mech_frame) { .kaddr = pages[g], .index = g, .data_off = HDR,
			.data_len = g ? GROUP - SEG : SEG };
		s.pool.state[g] = XDEV_EXT_MECH_F_INFLIGHT;
	}
	CHECK(xdev_ext_socket_class_bind(&st, &u) == 0);
	CHECK(sk.sk_data_ready == ready && sk.sk_user_data == NULL);	/* TX installs no callback */
	for (g = 0; g < 5; g++) {
		b.ticket++; b.completions = 0;
		CHECK(!xdev_ext_socket_validate(&st, &b, (const u8 *)d, 2));
		CHECK(xdev_ext_socket_class_submit(&st, &b) == 0 && b.completions == 1 && !b.status);
		CHECK(recv(peer, got, sizeof(got), MSG_DONTWAIT) == GROUP);
		xdev_ext_socket_class_fill_cqe(&st, &b, &cqe);
		CHECK(!cqe.status && cqe.bytes_sent == GROUP && cqe.bytes_received == 0 && cqe.flags == 0);
	}
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 5);
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == 5 * GROUP);
	forced_send = -EAGAIN; CHECK(xdev_ext_socket_class_submit(&st, &b) == -EAGAIN);
	forced_send = -ECONNREFUSED; CHECK(xdev_ext_socket_class_submit(&st, &b) == 0 && b.status == -ECONNREFUSED);
	forced_send = 123; CHECK(xdev_ext_socket_class_submit(&st, &b) == 0 && b.status == -EIO);
	forced_send = 999999;
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 5);	/* refusals/failures not counted */
	CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == 5 * GROUP);
	check_no_zc();
	recv0 = recv_calls;
	CHECK(xdev_ext_socket_progress(&st) == 0 && recv_calls == recv0);
	xdev_ext_socket_class_mark_dead(&st);
	CHECK(xdev_ext_socket_class_submit(&st, &b) == -ENODEV);
	xdev_ext_socket_class_unbind(&st);
	CHECK(st.priv == NULL && sk.sk_data_ready == ready);
	close(peer); close(sock.fd);
	puts("PASS socket tx copy accounting");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	test_case = argv[1];
	if (!strcmp(test_case, "bind_rules")) return bind_rules();
	if (!strcmp(test_case, "fifo_exact4")) return fifo_exact(AF_INET);
	if (!strcmp(test_case, "fifo_exact6")) return fifo_exact(AF_INET6);
	if (!strcmp(test_case, "short_datagram")) return short_datagram();
	if (!strcmp(test_case, "truncation")) return truncation();
	if (!strcmp(test_case, "zero_length")) return zero_length();
	if (!strcmp(test_case, "native_error")) return native_error();
	if (!strcmp(test_case, "no_polling")) return no_polling();
	if (!strcmp(test_case, "queued_before_arm")) return queued_before_arm();
	if (!strcmp(test_case, "ready_during_progress")) return ready_during_progress();
	if (!strcmp(test_case, "drain_all_in_one_pass")) return drain_all_in_one_pass();
	if (!strcmp(test_case, "duplicate_arm")) return duplicate_arm();
	if (!strcmp(test_case, "submit_guards")) return submit_guards();
	if (!strcmp(test_case, "stop_cancels")) return stop_cancels();
	if (!strcmp(test_case, "dead_cancels")) return dead_cancels();
	if (!strcmp(test_case, "credentials")) return credentials();
	if (!strcmp(test_case, "teardown_race")) return teardown_race();
	if (!strcmp(test_case, "teardown_interleaved")) return teardown_interleaved();
	if (!strcmp(test_case, "tx_accounting")) return tx_accounting();
	return 2;
}
