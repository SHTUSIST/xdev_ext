/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GUEST TEST ONLY. The same registered backing and frame 0 survive A's
 * UNKNOWN WRITE and controller reset, then carry C's different source data.
 * The keeper only keeps the UMEM registration alive until C is created;
 * it is not an active borrower while A is quarantined.
 */
static void reuse_keeper_up(struct session *keeper, const struct session *a,
			    struct bpf_map *ops)
{
	struct io_uring_params params = {};
	struct io_uring_xdev_ext_umem_reg reg = {
		.addr = (uintptr_t)a->pool, .size = a->pool_bytes, .frame_size = FRAME,
	};
	unsigned i;

	memset(keeper, 0, sizeof(*keeper));
	keeper->pool = a->pool;
	keeper->pool_bytes = a->pool_bytes;
	keeper->ring = syscall(__NR_io_uring_setup, 8, &params);
	CHECK(keeper->ring >= 0, "keeper io_uring ring");
	CHECK(!syscall(__NR_io_uring_register, keeper->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1),
	      "keeper registers the same address, size and frame size before A runs");
	for (i = 0; i < GROUPS; i++)
		keeper->frames[i] = i;
	for (i = 0; i < 2; i++) {
		keeper->links[i] = bpf_map__attach_struct_ops(ops);
		CHECK(keeper->links[i] && !libbpf_get_error(keeper->links[i]),
		      "keeper attaches its PRIVATE stage link");
	}
	printf("XDEV_EXT_WINDOW_REUSE_BACKING a_ring=%d keeper_ring=%d addr=%p size=%zu frame_size=%u frame=0\n",
	       a->ring, keeper->ring, a->pool, a->pool_bytes, FRAME);
}

static void reuse_start_one(struct session *s)
{
	struct xdev_ext_mech_start st = {
		.session_id = s->id, .nr_batches = 1, .first_seq = FIRST_KEY,
		.flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
		.nr_user_frames = 1, .user_frames = (uintptr_t)&s->frames[0],
	};

	CHECK_EQ(s->frames[0], 0, "START names the original frame 0");
	CHECK_EQ(mech(s->ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&st), 0,
		 "one batch borrows exactly the original frame 0");
}

static void reuse_pool_check(const struct session *s, const unsigned char *source,
			     unsigned w)
{
	const unsigned char *pool = s->pool;
	size_t b;

	CHECK(!memcmp(pool, source + win(w) * LBA, FRAME),
	      "original frame 0 contains the current source group from device READ");
	for (b = FRAME; b < s->pool_bytes && pool[b] == 0x97; b++)
		;
	CHECK(b == s->pool_bytes, "unused frames 1..7 retain their initial guards");
}

static void reuse_destination(const unsigned char *source, const unsigned char *dest)
{
	unsigned char *expect = malloc(SPAN);
	bool old_landed;

	CHECK(expect, "reuse destination oracle memory");
	old_landed = !memcmp(dest, source, GROUP);
	memset(expect, GUARD, SPAN);
	if (old_landed)
		memcpy(expect, source, GROUP);
	memcpy(expect + WIN_BYTES, source + WIN_BYTES, GROUP);
	CHECK(!memcmp(dest, expect, SPAN),
	      "A first group is old source or guard; C first group is new source; every other byte guard");
	free(expect);
}

static int reuse_main(char **argv)
{
	struct xdev_ext_mech_stats failed, st;
	struct session a, keeper;
	struct object o;
	unsigned char *source, *dest, *aux;
	__u64 source_bytes, dest_bytes, aux_bytes, b;
	int src, srcng, dst, dstng, auxblk, h[4], ret = 0, i;
	const char *disk = strrchr(argv[3], '/');
	__u64 old_id;

	who = "frame-reuse";
	CHECK(getenv("XDEV_EXT_WINDOW_GUEST") && !strcmp(getenv("XDEV_EXT_WINDOW_GUEST"), "1"),
	      "guest-only opt-in");
	CHECK(disk && !strncmp(disk + 1, "nvme", 4), "DST is an NVMe namespace block node");
	disk++;
	src = open_ok(argv[1], O_RDONLY);
	srcng = open_ok(argv[2], O_RDWR);
	dst = open_ok(argv[3], O_RDWR);
	dstng = open_ok(argv[4], O_RDWR);
	auxblk = open_ok(argv[7], O_RDONLY);
	CHECK(!ioctl(src, BLKGETSIZE64, &source_bytes) &&
	      !ioctl(dst, BLKGETSIZE64, &dest_bytes) && !ioctl(auxblk, BLKGETSIZE64, &aux_bytes),
	      "source, destination and AUX capacities");
	CHECK(source_bytes == SPAN && dest_bytes == SPAN && aux_bytes == SPAN,
	      "all images have the exact oracle span");
	source = malloc(SPAN); dest = malloc(SPAN); aux = malloc(SPAN);
	CHECK(source && dest && aux, "whole-disk verification buffers");
	read_disk(src, source, SPAN, "read original source");
	check_source(source, SPAN);
	CHECK(memcmp(source, source + WIN_BYTES, GROUP), "W0 and W1 source groups differ");
	read_disk(dst, dest, SPAN, "read initial destination");
	for (b = 0; b < SPAN && dest[b] == GUARD; b++)
		;
	CHECK(b == SPAN, "entire destination initially guard");
	read_disk(auxblk, aux, SPAN, "read initial unused AUX");
	for (b = 0; b < SPAN && aux[b] == M_AUX_FILL; b++)
		;
	CHECK(b == SPAN, "entire unused AUX initially guard");
	object_open(argv[5], &o);
	ring_up(&a, o.window, o.window);
	reuse_keeper_up(&keeper, &a, o.window);
	h[0] = issue_ok(srcng, win(0), WIN_NLB, RD, "A source W0 handle");
	h[1] = issue_ok(dstng, win(0), WIN_NLB, WR, "A destination W0 handle");
	h[2] = issue_ok(srcng, win(1), WIN_NLB, RD, "C source W1 handle");
	h[3] = issue_ok(dstng, win(1), WIN_NLB, WR, "C destination W1 handle");
	CHECK_EQ(create(&a, (struct stage){ h[0], win(0), WIN_NLB },
			(struct stage){ h[1], win(0), WIN_NLB }), 0, "CREATE A on the original backing");
	old_id = a.id;
	m_fault(R_UNKNOWN, disk, true);
	reuse_start_one(&a);
	failed = wait_quiet(&a, true);
	CHECK(failed.batches_done == 0 && failed.batches_abort == 1 && failed.sequestered == 1 &&
	      !failed.inflight && failed.last_err < 0 && failed.submitted[0] == 1 &&
	      failed.submitted[1] == 1 && !failed.rejects && !failed.protocol_err,
	      "A READ succeeded then its UNKNOWN WRITE failed with frame 0 sequestered and no I/O in flight");
	reuse_pool_check(&a, source, 0);
	CHECK_EQ(mech(a.ring, XDEV_EXT_MECH_OP_STOP, old_id), -EBUSY,
		 "A failed STOP quarantines the session before reset");
	m_fault(R_UNKNOWN, disk, false);
	m_reset_controller(disk);
	for (i = 0; i < WAIT_MS / 5; i++) {
		memset(&st, 0, sizeof(st));
		st.session_id = old_id;
		ret = mech(keeper.ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st);
		if (ret == -ENOENT)
			break;
		CHECK_EQ(ret, 0, "keeper queries A while reset release is pending");
		usleep(5000);
	}
	CHECK_EQ(ret, -ENOENT, "reset proof releases A while the same backing stays registered");
	CHECK_EQ(mech(a.ring, XDEV_EXT_MECH_OP_STOP, old_id), -ENOENT,
		 "failed A remains released, never turns into a successful old session");
	/* No pool write, unmap or UMEM re-registration occurs between A and C. */
	reuse_pool_check(&keeper, source, 0);
	CHECK_EQ(create(&keeper, (struct stage){ h[2], win(1), WIN_NLB },
			(struct stage){ h[3], win(1), WIN_NLB }), 0,
		 "CREATE C on keeper's unchanged registered backing");
	CHECK(keeper.id != old_id, "C has a distinct session id");
	reuse_start_one(&keeper);
	st = wait_quiet(&keeper, true);
	CHECK(st.batches_done == 1 && !st.batches_abort && !st.rejects && !st.protocol_err &&
	      !st.timeouts && !st.sequestered && !st.last_err && !st.inflight &&
	      st.state == XDEV_EXT_MECH_SESSION_ACTIVE && st.submitted[0] == 1 &&
	      st.completed[0] == 1 && st.submitted[1] == 1 && st.completed[1] == 1,
	      "C reuses original frame 0 and completes exactly once without abort");
	reuse_pool_check(&keeper, source, 1);
	stop_ok(&keeper, "C STOP succeeds after actual frame reuse");
	read_disk(dst, dest, SPAN, "read final destination");
	reuse_destination(source, dest);
	read_disk(src, dest, SPAN, "read final source");
	CHECK(!memcmp(dest, source, SPAN), "entire source remains unchanged");
	read_disk(auxblk, dest, SPAN, "read final unused AUX");
	CHECK(!memcmp(dest, aux, SPAN), "entire unused AUX remains unchanged");
	printf("XDEV_EXT_WINDOW_REUSE_OLD done=%llu abort=%llu last_err=%d stop=-%d\n",
	       (unsigned long long)failed.batches_done, (unsigned long long)failed.batches_abort,
	       failed.last_err, EBUSY);
	for (i = 0; i < 4; i++)
		CHECK(!close(h[i]), "close a window handle");
	bpf_link__destroy(keeper.links[0]); bpf_link__destroy(keeper.links[1]);
	CHECK(!close(keeper.ring), "close keeper ring after C completes");
	ring_down(&a);
	bpf_object__close(o.obj);
	CHECK(!close(src) && !close(srcng) && !close(dst) && !close(dstng) && !close(auxblk),
	      "close namespace nodes");
	free(source); free(dest); free(aux);
	printf("1..%u\nXDEV_EXT_WINDOW_FRAME_REUSE=PASS\n", checks);
	return 0;
}
