// SPDX-License-Identifier: GPL-2.0
/*
 * Guest tool of the BPF compute examples KVM run (examples_kvm.sh). Correctness
 * only; nothing is timed.
 *
 *   compute_examples_guest verify OBJ...
 *	Load each object without attaching it, with the verifier statistics log
 *	(log_level 4), and print per program the "processed N insns" count of
 *	that log and bpf_prog_info.verified_insns.
 *
 *   compute_examples_guest run --out FILE --seed N --input KIND [--negatives]
 *	--stage XFORM:ARG [--stage XFORM:ARG] (--spans SEG:HDR | --frames SEG:GROUP:HDR:BATCHES)...
 *	For each --spans/--frames layout, one session of the given CPU stages over
 *	an IOU UMEM pool, CREATE depth 1. Each START lends one batch: with --spans
 *	one frame of a chosen length (USER_SPANS; lengths 1..300 and the
 *	frame-size edges up to SEG), with --frames one layout group (USER_FRAMES,
 *	SEG-byte frames, the last one shorter). The tool waits for the batch to
 *	finish and the frames to return to user space, then reads them back.
 *	Every batch becomes one record of FILE: the input bytes, done or aborted,
 *	the output bytes and any byte of the chunk changed outside them.
 *	KIND: random, sealed (each frame ends with its CRC32C), parse:H (a header
 *	of H bytes whose first word is the payload length). --negatives follows
 *	every sealed or parse batch with a corrupted copy.
 *	The CPU program must already be attached (xdev_ext_mech_ctl attach).
 *
 * Inputs depend only on --seed, the layout, the length and the batch, so the
 * fixed-transform run and the BPF run of one case see identical bytes. Sealed
 * and parse inputs are built with the independent oracle of xform_oracle.h.
 * The host validator (examples_validate.py) judges the records.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "include/uapi/linux/io_uring.h"
#include "io_uring/xdev_ext_mech_cpu_core.h"
#include "xform_oracle.h"

#define FRAME_SIZE	4096U
#define POOL_FRAMES	4096U
#define FILL		0xa5
#define MAX_FRAMES	XDEV_EXT_MECH_MAX_FRAMES
#define MAX_LAYOUTS	8
#define BATCH_TIMEOUT_MS 20000
#define LOG_SIZE	(1U << 16)
#define FAIL_LOG_SIZE	(1U << 24)

#define STREAM_MAGIC	0x4d525453584558ULL	/* "XEXSTRM" */
#define REC_MAGIC	0x52584558U		/* "XEXR" */
#define END_MAGIC	0x45584558U		/* "XEXE" */

/* File layout, little endian: one stream header, records, one end record. */
struct stream_hdr {
	__u64 magic;
	__u32 version;		/* 1 */
	__u32 nr_stages;
	__u32 xform[2];
	__u64 arg[2];
	__u64 seed;
	__s32 delta;		/* sum of the stages' length changes */
	__u32 negatives;
	char input[32];
};

struct rec_hdr {
	__u32 magic;
	__u32 spans;		/* 1: USER_SPANS batch, 0: USER_FRAMES group */
	__u32 hdr_room, seg_len, group_bytes;
	__u32 nframes;
	__u32 corrupted;	/* the tool corrupted this input on purpose */
	__u32 outcome;		/* 0 batch done, 1 batch aborted */
	__s32 last_err;		/* session last_err after the batch */
	__u32 stray;		/* chunk bytes changed outside the output span */
	__u32 in_len[MAX_FRAMES];
	__u32 out_len[MAX_FRAMES];
	/* in bytes of every frame, then out bytes of every frame */
};

struct end_rec {
	__u32 magic;
	__u32 records;
	__u32 done, aborted;
};

/* examples_validate.py unpacks these exact sizes. */
_Static_assert(sizeof(struct stream_hdr) == 88, "stream header layout");
_Static_assert(sizeof(struct rec_hdr) == 296, "record header layout");
_Static_assert(sizeof(struct end_rec) == 16, "end record layout");

struct layout_arg {
	bool spans;
	__u32 seg, group, hdr, batches;
};

struct opts {
	const char *out, *input;
	__u64 seed;
	bool negatives;
	__u32 nr_stages, xform[2];
	__u64 arg[2];
	__u32 nr_layouts;
	struct layout_arg layout[MAX_LAYOUTS];
	__u32 parse_hdr;
	__s64 delta;
};

struct session {
	int ring, efd;
	__u8 *umem;
	__u64 id, seq;
	__u32 next_frame;
	struct xdev_ext_mech_layout l;
};

#define err_out(...) fprintf(stderr, "compute_examples_guest: " __VA_ARGS__)

/* --- verifier statistics ------------------------------------------------ */

static int verify_one(const char *path)
{
	struct bpf_object *obj = bpf_object__open_file(path, NULL);
	struct bpf_program *prog;
	char *logs[16] = { 0 };
	const char *base = strrchr(path, '/');
	unsigned int n = 0, i;
	int err;

	base = base ? base + 1 : path;
	if (!obj) {
		err_out("%s: open: %s\n", path, strerror(errno));
		return -1;
	}
	bpf_object__for_each_program(prog, obj) {
		if (n == 16) {
			bpf_object__close(obj);
			return -1;
		}
		logs[n] = calloc(1, LOG_SIZE);
		if (!logs[n] || bpf_program__set_log_buf(prog, logs[n], LOG_SIZE) ||
		    bpf_program__set_log_level(prog, 4)) {
			err = -1;
			goto out;
		}
		n++;
	}
	err = bpf_object__load(obj);
	if (err) {
		printf("XDEV_EXT_EXAMPLE_VERIFIER=FAIL object=%s err=%d\n", base, err);
		goto out;
	}
	i = 0;
	bpf_object__for_each_program(prog, obj) {
		struct bpf_prog_info info;
		__u32 len = sizeof(info);
		const char *line = strstr(logs[i], "processed ");
		unsigned long processed = 0;
		char stats[256] = "";

		memset(&info, 0, sizeof(info));
		if (bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &len)) {
			err = -1;
			goto out;
		}
		if (line) {
			size_t k = strcspn(line, "\n");

			processed = strtoul(line + strlen("processed "), NULL, 10);
			snprintf(stats, sizeof(stats), "%.*s", (int)(k < 255 ? k : 255), line);
		}
		printf("XDEV_EXT_EXAMPLE_VERIFIER object=%s program=%s processed_insns=%lu "
		       "verified_insns=%u xlated_insns=%u stats=\"%s\"\n", base,
		       bpf_program__name(prog), processed, info.verified_insns,
		       info.xlated_prog_len / 8, stats);
		if (!line || !processed || processed != info.verified_insns)
			err = -1;
		i++;
	}
out:
	bpf_object__close(obj);
	for (i = 0; i < n; i++)
		free(logs[i]);
	return err;
}

/* On a refused object: the verifier's own words, from a full log. */
static void verify_explain(const char *path)
{
	struct bpf_object *obj = bpf_object__open_file(path, NULL);
	struct bpf_program *prog;
	char *log = calloc(1, FAIL_LOG_SIZE);

	if (!obj || !log)
		goto out;
	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_log_buf(prog, log, FAIL_LOG_SIZE);
		bpf_program__set_log_level(prog, 1 | 4);
	}
	if (bpf_object__load(obj)) {
		size_t len = strlen(log), from = len > 6000 ? len - 6000 : 0;

		printf("XDEV_EXT_EXAMPLE_VERIFIER_LOG_TAIL object=%s\n%s\n", path, log + from);
	}
out:
	if (obj)
		bpf_object__close(obj);
	free(log);
}

static int cmd_verify(int argc, char **argv)
{
	int i, bad = 0;

	for (i = 1; i < argc; i++)
		if (verify_one(argv[i])) {
			verify_explain(argv[i]);
			bad++;
		}
	printf("XDEV_EXT_EXAMPLE_VERIFIER_DONE objects=%d failed=%d\n", argc - 1, bad);
	return bad ? 1 : 0;
}

/* --- inputs --------------------------------------------------------------- */

static __u64 splitmix(__u64 *s)
{
	__u64 z = (*s += 0x9E3779B97F4A7C15ULL);

	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

static void random_bytes(__u8 *p, __u32 n, __u64 *s)
{
	__u32 i;

	for (i = 0; i < n; i++)
		p[i] = (__u8)splitmix(s);
}

/* One frame of @kind; @corrupt breaks a sealed CRC or a parse length word. */
static void make_input(const struct opts *o, __u8 *p, __u32 len, __u64 *s, bool corrupt)
{
	random_bytes(p, len, s);
	if (!strcmp(o->input, "sealed") && len >= 4) {
		oracle_put_le32(p + len - 4, oracle_crc32c(p, len - 4));
		if (corrupt) {
			__u64 r = splitmix(s);

			p[r % len] ^= (__u8)(1U << ((r >> 32) % 8));
		}
	} else if (o->parse_hdr && len >= o->parse_hdr) {
		oracle_put_le32(p, len - o->parse_hdr + (corrupt ? 1 : 0));
	}
}

/* --- session -------------------------------------------------------------- */

static int ring_register(int ring, unsigned int op, void *arg)
{
	int ret = (int)syscall(__NR_io_uring_register, ring, op, arg, 1);

	return ret < 0 ? -errno : ret;
}

static int mech(struct session *s, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };

	return ring_register(s->ring, IORING_REGISTER_XDEV_EXT_MECH, &req);
}

static int stats(struct session *s, struct xdev_ext_mech_stats *st)
{
	memset(st, 0, sizeof(*st));
	st->session_id = s->id;
	return mech(s, XDEV_EXT_MECH_OP_STATS, (uintptr_t)st);
}

/*
 * STOP, then release. STOP returns the session's first error after a full
 * release; only STATS answering -ENOENT proves the session is gone. 0, or
 * -EBUSY when the kernel still holds the session.
 */
static int session_close(struct session *s)
{
	struct xdev_ext_mech_stats st;
	unsigned int tries;
	int ret = 0, gone = 0;

	if (s->id) {
		for (tries = 0; tries < 1000; tries++) {
			ret = mech(s, XDEV_EXT_MECH_OP_STOP, s->id);
			if (ret != -EAGAIN)
				break;
			usleep(1000);
		}
		if (stats(s, &st) != -ENOENT) {
			err_out("STOP: %s; the session was not released\n", strerror(-ret));
			gone = -EBUSY;
		}
	}
	if (s->ring >= 0)
		close(s->ring);
	if (s->efd >= 0)
		close(s->efd);
	if (s->umem && s->umem != MAP_FAILED)
		munmap(s->umem, (size_t)POOL_FRAMES * FRAME_SIZE);
	memset(s, 0, sizeof(*s));
	s->ring = s->efd = -1;
	return gone;
}

static int session_open(struct session *s, const struct opts *o, const struct layout_arg *la)
{
	struct io_uring_params p;
	struct io_uring_xdev_ext_umem_reg reg = { 0 };
	struct xdev_ext_mech_create c = { 0 };
	__u32 i;
	int ret;

	memset(s, 0, sizeof(*s));
	s->ring = s->efd = -1;
	memset(&p, 0, sizeof(p));
	s->ring = (int)syscall(__NR_io_uring_setup, 8, &p);
	s->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (s->ring < 0 || s->efd < 0)
		return -errno;
	s->umem = mmap(NULL, (size_t)POOL_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (s->umem == MAP_FAILED)
		return -errno;
	reg.addr = (uintptr_t)s->umem;
	reg.size = (__u64)POOL_FRAMES * FRAME_SIZE;
	reg.frame_size = FRAME_SIZE;
	ret = ring_register(s->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
	if (ret)
		return ret;
	s->l = (struct xdev_ext_mech_layout) {
		.frame_size = FRAME_SIZE, .hdr_room = la->hdr,
		.seg_len = la->seg, .group_bytes = la->spans ? la->seg : la->group,
	};
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = o->nr_stages;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.layout = s->l;
	c.depth = 1;
	c.eventfd = s->efd;
	for (i = 0; i < o->nr_stages; i++)
		c.st[i] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CPU,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = -1,
			.arg0 = o->xform[i], .arg1 = o->arg[i],
		};
	ret = mech(s, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c);
	if (ret)
		return ret;
	s->id = c.session_id;
	s->seq = 1;
	return 0;
}

/* START one batch over @idx; 0 with *@outcome 0 (done) or 1 (aborted). */
static int run_batch(struct session *s, const __u32 *idx, __u32 n, __u32 span_len,
		     __u32 *outcome, __s32 *last_err)
{
	struct xdev_ext_mech_user_span span = { .index = idx[0], .len = span_len };
	struct xdev_ext_mech_stats before, after;
	struct xdev_ext_mech_start st = {
		.session_id = s->id, .nr_batches = 1, .first_seq = s->seq++,
		.flags = XDEV_EXT_MECH_START_F_USER_FRAMES, .nr_user_frames = n,
		.user_frames = (uintptr_t)idx,
	};
	struct pollfd pfd = { .fd = s->efd, .events = POLLIN };
	unsigned int tries;
	__u64 count;
	int ret;

	if (span_len) {
		st.flags |= XDEV_EXT_MECH_START_F_USER_SPANS;
		st.user_frames = (uintptr_t)&span;
	}
	ret = stats(s, &before);
	if (ret)
		return ret;
	for (tries = 0; tries < 1000; tries++) {
		ret = mech(s, XDEV_EXT_MECH_OP_START, (uintptr_t)&st);
		if (ret != -EBUSY)
			break;
		usleep(1000);
	}
	if (ret) {
		err_out("START: %s\n", strerror(-ret));
		return ret;
	}
	ret = poll(&pfd, 1, BATCH_TIMEOUT_MS);
	if (ret <= 0) {
		err_out("batch: no notification within %d ms\n", BATCH_TIMEOUT_MS);
		return -ETIMEDOUT;
	}
	if (read(s->efd, &count, sizeof(count)) < 0 && errno != EAGAIN)
		return -errno;
	/* The frames return to user space with the batch; wait until settled. */
	for (tries = 0; tries < 5000; tries++) {
		ret = stats(s, &after);
		if (ret)
			return ret;
		if (after.batches_done + after.batches_abort >
		    before.batches_done + before.batches_abort && !after.inflight)
			break;
		usleep(1000);
	}
	if (tries == 5000) {
		err_out("batch did not settle\n");
		return -ETIMEDOUT;
	}
	if (after.batches_done + after.batches_abort !=
	    before.batches_done + before.batches_abort + 1 || after.sequestered ||
	    after.state != XDEV_EXT_MECH_SESSION_ACTIVE) {
		err_out("batch: done %llu->%llu abort %llu->%llu sequestered %llu state %u\n",
			(unsigned long long)before.batches_done,
			(unsigned long long)after.batches_done,
			(unsigned long long)before.batches_abort,
			(unsigned long long)after.batches_abort,
			(unsigned long long)after.sequestered, after.state);
		return -EPROTO;
	}
	*outcome = after.batches_done > before.batches_done ? 0 : 1;
	*last_err = after.last_err;
	return 0;
}

/* --- run ------------------------------------------------------------------ */

static const __u32 span_edges[] = {
	301, 383, 384, 385, 511, 512, 513, 1023, 1024, 1025, 1431, 1432, 1433,
	2047, 2048, 2049, 3000, 3735, 3736, 4087, 4088, 4091, 4092, 4095, 4096,
};

struct counts {
	__u32 records, done, aborted;
};

static int write_all(FILE *f, const void *p, size_t n)
{
	return fwrite(p, 1, n, f) == n ? 0 : -EIO;
}

static __u8 saved[MAX_FRAMES][FRAME_SIZE];

/* One batch of frames with lengths @lens; appends one record. */
static int one_batch(struct session *s, const struct opts *o, const struct layout_arg *la,
		     FILE *f, const __u32 *lens, __u32 n, __u64 rng, bool corrupt,
		     struct counts *cnt)
{
	struct rec_hdr r = { .magic = REC_MAGIC, .spans = la->spans, .hdr_room = la->hdr,
			     .seg_len = s->l.seg_len, .group_bytes = s->l.group_bytes,
			     .nframes = n, .corrupted = corrupt };
	__u32 idx[MAX_FRAMES], i, j;
	int ret;

	for (i = 0; i < n; i++) {
		__u8 *chunk;

		idx[i] = s->next_frame;
		s->next_frame = (s->next_frame + 1) % POOL_FRAMES;
		chunk = s->umem + (size_t)idx[i] * FRAME_SIZE;
		memset(chunk, FILL, FRAME_SIZE);
		/* A corrupted batch breaks its middle frame only. */
		make_input(o, chunk + la->hdr, lens[i], &rng, corrupt && i == n / 2);
		r.in_len[i] = lens[i];
	}
	/* Inputs are recorded before the kernel sees them. */
	for (i = 0; i < n; i++)
		memcpy(saved[i], s->umem + (size_t)idx[i] * FRAME_SIZE + la->hdr, lens[i]);
	ret = run_batch(s, idx, n, la->spans ? lens[0] : 0, &r.outcome, &r.last_err);
	if (ret)
		return ret;
	for (i = 0; i < n; i++) {
		__u8 *chunk = s->umem + (size_t)idx[i] * FRAME_SIZE;
		__s64 out = r.outcome ? lens[i] : (__s64)lens[i] + o->delta;

		if (out < 0 || out > FRAME_SIZE - la->hdr)
			return -ERANGE;
		r.out_len[i] = (__u32)out;
		for (j = 0; j < FRAME_SIZE; j++)
			if ((j < la->hdr || j >= la->hdr + r.out_len[i]) && chunk[j] != FILL)
				r.stray++;
	}
	ret = write_all(f, &r, sizeof(r));
	for (i = 0; !ret && i < n; i++)
		ret = write_all(f, saved[i], lens[i]);
	for (i = 0; !ret && i < n; i++)
		ret = write_all(f, s->umem + (size_t)idx[i] * FRAME_SIZE + la->hdr, r.out_len[i]);
	cnt->records++;
	if (r.outcome)
		cnt->aborted++;
	else
		cnt->done++;
	return ret;
}

static int run_layout(const struct opts *o, const struct layout_arg *la, FILE *f,
		      struct counts *cnt)
{
	struct session s;
	bool negatives = o->negatives;
	__u32 lens[MAX_FRAMES], n, i, len;
	__u64 base = o->seed * 0x100000001B3ULL ^ ((__u64)la->seg << 32 | la->group << 8 | la->hdr);
	unsigned int k;
	int ret = 0, pass;

	if (!la->spans && (la->group + la->seg - 1) / la->seg > MAX_FRAMES)
		return -E2BIG;
	ret = session_open(&s, o, la);
	if (ret) {
		err_out("session (seg %u group %u hdr %u): %s\n", la->seg, la->group, la->hdr,
			strerror(-ret));
		session_close(&s);
		return ret;
	}
	if (la->spans) {
		/* 1..300, then every edge up to the span capacity SEG. */
		for (k = 0; k < 300 + sizeof(span_edges) / sizeof(span_edges[0]); k++) {
			len = k < 300 ? k + 1 : span_edges[k - 300];
			if (len > la->seg)
				continue;
			for (pass = 0; pass < 1 + negatives; pass++) {
				ret = one_batch(&s, o, la, f, &len, 1, base + len, pass, cnt);
				if (ret)
					goto out;
			}
		}
	} else {
		n = (la->group + la->seg - 1) / la->seg;
		for (i = 0; i < n; i++)
			lens[i] = i + 1 < n ? la->seg : la->group - (n - 1) * la->seg;
		for (i = 0; i < la->batches; i++)
			for (pass = 0; pass < 1 + negatives; pass++) {
				ret = one_batch(&s, o, la, f, lens, n, base + 977 * i, pass, cnt);
				if (ret)
					goto out;
			}
	}
out:
	if (ret)
		err_out("layout seg %u group %u hdr %u: %s\n", la->seg, la->group, la->hdr,
			strerror(-ret));
	if (session_close(&s) && !ret)
		ret = -EBUSY;
	return ret;
}

static int parse_stage(const char *arg, struct opts *o)
{
	char *end;
	unsigned long x;
	__u64 a;

	if (o->nr_stages == 2)
		return -EINVAL;
	x = strtoul(arg, &end, 0);
	if (*end != ':')
		return -EINVAL;
	/* A negative length change in two's complement, or any 64-bit seed. */
	errno = 0;
	a = end[1] == '-' ? (__u64)strtoll(end + 1, &end, 0) : strtoull(end + 1, &end, 0);
	if (*end || errno)
		return -EINVAL;
	o->xform[o->nr_stages] = (__u32)x;
	o->arg[o->nr_stages++] = a;
	return 0;
}

static int parse_layout(const char *arg, bool spans, struct opts *o)
{
	struct layout_arg *la;
	int got;

	if (o->nr_layouts == MAX_LAYOUTS)
		return -EINVAL;
	la = &o->layout[o->nr_layouts];
	memset(la, 0, sizeof(*la));
	la->spans = spans;
	got = spans ? sscanf(arg, "%u:%u", &la->seg, &la->hdr) :
		      sscanf(arg, "%u:%u:%u:%u", &la->seg, &la->group, &la->hdr, &la->batches);
	if (got != (spans ? 2 : 4) || !la->seg || la->seg + la->hdr > FRAME_SIZE)
		return -EINVAL;
	o->nr_layouts++;
	return 0;
}

static int cmd_run(int argc, char **argv)
{
	static const struct option longopts[] = {
		{ "out", required_argument, NULL, 'o' },
		{ "seed", required_argument, NULL, 's' },
		{ "input", required_argument, NULL, 'i' },
		{ "negatives", no_argument, NULL, 'n' },
		{ "stage", required_argument, NULL, 't' },
		{ "spans", required_argument, NULL, 'S' },
		{ "frames", required_argument, NULL, 'F' },
		{ 0 }
	};
	struct stream_hdr h = { .magic = STREAM_MAGIC, .version = 1 };
	struct counts cnt = { 0 };
	struct end_rec e = { .magic = END_MAGIC };
	struct opts o = { 0 };
	__u32 i;
	FILE *f;
	int c, ret = 0;

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case 'o': o.out = optarg; break;
		case 's': o.seed = strtoull(optarg, NULL, 0); break;
		case 'i': o.input = optarg; break;
		case 'n': o.negatives = true; break;
		case 't': ret = parse_stage(optarg, &o); break;
		case 'S': ret = parse_layout(optarg, true, &o); break;
		case 'F': ret = parse_layout(optarg, false, &o); break;
		default: ret = -EINVAL; break;
		}
		if (ret)
			break;
	}
	if (ret || !o.out || !o.input || !o.nr_stages || !o.nr_layouts) {
		err_out("usage: run --out FILE --seed N --input KIND --stage X:A "
			"(--spans SEG:HDR | --frames SEG:GROUP:HDR:BATCHES)...\n");
		return 2;
	}
	if (!strncmp(o.input, "parse:", 6))
		o.parse_hdr = (__u32)strtoul(o.input + 6, NULL, 0);
	else if (strcmp(o.input, "random") && strcmp(o.input, "sealed"))
		return 2;
	for (i = 0; i < o.nr_stages; i++) {
		__s64 d;

		if (xdev_ext_mech_cpu_len_delta(o.xform[i], o.arg[i], &d)) {
			err_out("stage %u: no fixed length change\n", i);
			return 2;
		}
		o.delta += d;
	}
	h.nr_stages = o.nr_stages;
	memcpy(h.xform, o.xform, sizeof(h.xform));
	memcpy(h.arg, o.arg, sizeof(h.arg));
	h.seed = o.seed;
	h.delta = (__s32)o.delta;
	h.negatives = o.negatives;
	snprintf(h.input, sizeof(h.input), "%s", o.input);
	f = fopen(o.out, "w");
	if (!f) {
		err_out("%s: %s\n", o.out, strerror(errno));
		return 1;
	}
	ret = write_all(f, &h, sizeof(h));
	for (i = 0; !ret && i < o.nr_layouts; i++)
		ret = run_layout(&o, &o.layout[i], f, &cnt);
	e.records = cnt.records;
	e.done = cnt.done;
	e.aborted = cnt.aborted;
	if (!ret)
		ret = write_all(f, &e, sizeof(e));
	if (fclose(f) && !ret)
		ret = -EIO;
	printf("XDEV_EXT_EXAMPLE_RUN out=%s result=%s records=%u done=%u aborted=%u\n", o.out,
	       ret ? "FAIL" : "PASS", cnt.records, cnt.done, cnt.aborted);
	return ret ? 1 : 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc >= 2 && !strcmp(argv[1], "verify"))
		return cmd_verify(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "run"))
		return cmd_run(argc - 1, argv + 1);
	err_out("usage: verify OBJ... | run ...\n");
	return 2;
}
