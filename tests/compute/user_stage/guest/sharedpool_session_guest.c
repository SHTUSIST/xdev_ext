// SPDX-License-Identifier: GPL-2.0
/* Actual shared-UMEM custody: two USER sessions, no DMA/performance measure. */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_policy.h"
#include "libxdev_ext.h"
#include "fd_check.h"

#define SP_FRAME_SIZE 4096U
#define SP_NR_FRAMES 2U
#define SP_POOL_FRAMES 6U
#define SP_HDR_ROOM 64U
#define SP_SEG_LEN (SP_FRAME_SIZE - SP_HDR_ROOM)
#define SP_GROUP_BYTES 4096U
#define SP_HOLD_BYTES (SP_NR_FRAMES * SP_FRAME_SIZE)
#define SP_POOL_BYTES (SP_POOL_FRAMES * SP_FRAME_SIZE)
#define SP_USER_DEADLINE_MS 60000U
#define SP_WAIT_MS 5000U
#define SP_HOLD_BUDGET_MS 10000U
#define SP_CASE_BUDGET_MS 20000U

struct sp_hold_snapshot {
	struct xdev_ext_user_batch batch;
	struct xdev_ext_mech_stats stats;
	__u32 expected_indices[SP_NR_FRAMES];
	__u32 ready_prod, ready_cons, done_prod, done_cons;
	__u64 live_ticket;
	unsigned char frame_bytes[SP_HOLD_BYTES];
};

static bool sp_hold_valid(const struct sp_hold_snapshot *s)
{
	unsigned int i;

	if (!s || s->batch.slot || s->batch.nr_frames != SP_NR_FRAMES ||
	    !s->batch.ticket || s->live_ticket != s->batch.ticket ||
	    !s->batch.batch_id || s->batch.key != 1 || s->batch.arg ||
	    s->ready_prod != 1 || s->ready_cons != 1 || s->done_prod || s->done_cons ||
	    !s->stats.session_id || s->stats.state != XDEV_EXT_MECH_SESSION_ACTIVE ||
	    s->stats.inflight != 1 || s->stats.batches_done || s->stats.batches_abort ||
	    s->stats.published || s->stats.sequestered || s->stats.last_err ||
	    s->stats.rejects || s->stats.protocol_err || s->stats.timeouts ||
	    s->stats.submitted[0] != 1 || s->stats.completed[0])
		return false;
	for (i = 1; i < XDEV_EXT_MECH_MAX_STAGES; i++)
		if (s->stats.submitted[i] || s->stats.completed[i])
			return false;
	for (i = 0; i < SP_NR_FRAMES; i++) {
		const struct xdev_ext_user_frame *f = &s->batch.f[i];

		if (s->expected_indices[i] >= SP_POOL_FRAMES ||
		    s->expected_indices[0] == s->expected_indices[1] ||
		    f->umem_addr != (__u64)s->expected_indices[i] * SP_FRAME_SIZE ||
		    f->data_off != SP_HDR_ROOM || f->capacity != SP_SEG_LEN ||
		    f->data_len != (i ? SP_GROUP_BYTES - SP_SEG_LEN : SP_SEG_LEN) ||
		    f->out_len != f->data_len || !s->batch.data[i])
			return false;
	}
	return true;
}

static bool sp_held_equal(const struct sp_hold_snapshot *a, const struct sp_hold_snapshot *b)
{
	unsigned int i;

	if (!sp_hold_valid(a) || !sp_hold_valid(b))
		return false;
/* Compare semantic fields, never padding in public structs. */
#define SAME(field) do { if (a->field != b->field) return false; } while (0)
	SAME(batch.slot); SAME(batch.nr_frames); SAME(batch.ticket);
	SAME(batch.batch_id); SAME(batch.key); SAME(batch.arg); SAME(live_ticket);
	SAME(ready_prod); SAME(ready_cons); SAME(done_prod); SAME(done_cons);
	SAME(stats.session_id); SAME(stats.batches_done); SAME(stats.batches_abort);
	SAME(stats.rejects); SAME(stats.recycled); SAME(stats.held); SAME(stats.sequestered);
	SAME(stats.timeouts); SAME(stats.inflight); SAME(stats.native_publish);
	SAME(stats.protocol_err); SAME(stats.published); SAME(stats.last_err); SAME(stats.state);
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) {
		SAME(stats.submitted[i]); SAME(stats.completed[i]);
	}
	for (i = 0; i < SP_NR_FRAMES; i++) {
		SAME(expected_indices[i]);
		SAME(batch.f[i].umem_addr); SAME(batch.f[i].data_off);
		SAME(batch.f[i].data_len); SAME(batch.f[i].capacity);
		SAME(batch.f[i].out_len); SAME(batch.data[i]);
	}
#undef SAME
	return !memcmp(a->frame_bytes, b->frame_bytes, sizeof(a->frame_bytes));
}

struct sp_side {
	__u64 id;
	__u32 indices[SP_NR_FRAMES];
	int efd;
	struct xdev_ext_user_stage *user;
	void *control;
	struct xdev_ext_user_ring_offsets off;
	struct xdev_ext_user_batch batch;
	struct xdev_ext_mech_stats stop_stats;
	uint64_t hold_end;
	bool holding, released, stop_attempted;
	int stop_error;
};

struct sp_owner {
	int ring;
	unsigned char *umem;
	struct xdev_ext_prog *prog;
	struct sp_side side[2];
	uint64_t case_end;
	bool unsafe;
};

static uint64_t sp_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int sp_remaining(const struct sp_owner *o, const struct sp_side *s)
{
	uint64_t now = sp_now_ms(), end = o->case_end, left;

	if (s && s->hold_end && s->hold_end < end)
		end = s->hold_end;
	if (!now || now >= end)
		return -ETIMEDOUT;
	left = end - now;
	return (int)(left < SP_WAIT_MS ? left : SP_WAIT_MS);
}

static int sp_mech(const struct sp_owner *o, __u32 op, __u64 arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };
	int ret = (int)syscall(__NR_io_uring_register, o->ring,
			      IORING_REGISTER_XDEV_EXT_MECH, &req, 1);

	return ret < 0 ? -errno : ret;
}

static int sp_stats(const struct sp_owner *o, const struct sp_side *s,
		    struct xdev_ext_mech_stats *stats)
{
	int ret;

	memset(stats, 0, sizeof(*stats));
	stats->session_id = s->id;
	ret = sp_mech(o, XDEV_EXT_MECH_OP_STATS, (uintptr_t)stats);
	return ret ? ret : stats->session_id == s->id ? 0 : -EPROTO;
}

static unsigned char sp_byte(size_t off)
{
	return (unsigned char)(off * 73U + (off >> 7) + 0x5aU);
}

static int sp_bytes(const struct sp_owner *o)
{
	for (size_t i = 0; i < SP_POOL_BYTES; i++)
		if (o->umem[i] != sp_byte(i))
			return -EBADMSG;
	return 0;
}

static struct xdev_ext_user_slot *sp_slot(const struct sp_side *s)
{
	return (void *)((char *)s->control + s->off.slots);
}

static int sp_setup(struct sp_owner *o, const char *obj_path)
{
	struct xdev_ext_prog_opts prog = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts,
		.obj_path = obj_path, .map_name = "chain_user_ops");
	struct io_uring_params params = { 0 };
	struct io_uring_xdev_ext_umem_reg reg;
	int ret = xdev_ext_prog_attach(&prog, &o->prog);

	if (ret)
		return ret;
	o->ring = (int)syscall(__NR_io_uring_setup, 8, &params);
	if (o->ring < 0)
		return -errno;
	o->umem = mmap(NULL, SP_POOL_BYTES, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (o->umem == MAP_FAILED) {
		o->umem = NULL;
		return -errno;
	}
	for (size_t i = 0; i < SP_POOL_BYTES; i++)
		o->umem[i] = sp_byte(i);
	reg = (struct io_uring_xdev_ext_umem_reg){
		.addr = (uintptr_t)o->umem, .size = SP_POOL_BYTES, .frame_size = SP_FRAME_SIZE,
	};
	if (syscall(__NR_io_uring_register, o->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1) < 0)
		return -errno;
	for (unsigned int i = 0; i < 2; i++) {
		struct sp_side *s = &o->side[i];
		struct xdev_ext_user_stage_opts opts = XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
			.ring_fd = o->ring, .umem = o->umem, .entries = 1,
			.flags = XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL);
		struct xdev_ext_mech_create_report report = { 0 };
		struct xdev_ext_mech_create create = {
			.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 1,
			.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1, .depth = 1,
			.layout = { .frame_size = SP_FRAME_SIZE, .hdr_room = SP_HDR_ROOM,
				.seg_len = SP_SEG_LEN, .group_bytes = SP_GROUP_BYTES },
		};
		/* Public CREATE_PROGRAMS: -1 selects the existing global default.
		 * A global link fd must never be passed as a PRIVATE selector. */
		int selectors[1] = { -1 };

		s->indices[0] = 1;
		s->indices[1] = 4;
		s->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (s->efd < 0)
			return -errno;
		ret = xdev_ext_user_stage_open(&opts, &s->user);
		if (!ret)
			ret = xdev_ext_user_stage_control(s->user, &s->control, &s->off);
		if (ret)
			return ret;
		create.eventfd = s->efd;
		create.st[0] = (struct xdev_ext_mech_stage_uapi){
			.class_id = XDEV_EXT_MECH_CLASS_USER, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
			.fd = xdev_ext_user_stage_fd(s->user), .arg0 = SP_USER_DEADLINE_MS,
		};
		ret = xdev_ext_create_programs_read(o->ring, &create, selectors, 1, &report);
		if (ret) {
			if (report.size != sizeof(report) ||
			    report.cleanup == XDEV_EXT_MECH_CREATE_CLEANUP_RETAINED)
				o->unsafe = true;
			return ret;
		}
		s->id = report.session_id;
	}
	if (o->side[0].id == o->side[1].id)
		return -EPROTO;
	fprintf(stderr, "SHAREDPOOL_IDS a=%llu b=%llu selector=global-default\n",
		(unsigned long long)o->side[0].id, (unsigned long long)o->side[1].id);
	return 0;
}

static int sp_start(struct sp_owner *o, struct sp_side *s)
{
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = s->id, .batches_target = 1, .published_target = SP_NR_FRAMES,
	};
	struct xdev_ext_mech_start start = {
		.session_id = s->id, .nr_batches = 1, .first_seq = 1,
		.flags = XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_ORDERED_FRAMES,
		.nr_user_frames = SP_NR_FRAMES, .user_frames = (uintptr_t)s->indices,
	};
	int ret = sp_remaining(o, NULL);

	if (ret < 0)
		return ret;
	ret = sp_mech(o, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
	if (!ret) {
		ret = sp_mech(o, XDEV_EXT_MECH_OP_START, (uintptr_t)&start);
		if (ret && ret != -EBUSY)
			/* The concurrent START case has two control threads. */
			__atomic_store_n(&o->unsafe, true, __ATOMIC_RELAXED);
	}
	return ret;
}

static int sp_observe(const struct sp_owner *o, const struct sp_side *s,
		      struct sp_hold_snapshot *out)
{
	const struct xdev_ext_user_ring_hdr *hdr = (void *)((char *)s->control + s->off.hdr);
	const struct xdev_ext_user_slot *slot = sp_slot(s);
	const struct xdev_ext_user_ready *ready = (void *)((char *)s->control + s->off.ready);
	int ret;

	memset(out, 0, sizeof(*out));
	out->batch = s->batch;
	memcpy(out->expected_indices, s->indices, sizeof(out->expected_indices));
	for (;;) {
		ret = sp_remaining(o, s);
		if (ret < 0)
			return ret;
		ret = sp_stats(o, s, &out->stats);
		if (ret)
			return ret;
		if (out->stats.submitted[0] || out->stats.state != XDEV_EXT_MECH_SESSION_ACTIVE ||
		    out->stats.last_err || out->stats.sequestered)
			break;
		sched_yield(); /* bounded wait for the submit counter after ready publication */
	}
	out->live_ticket = __atomic_load_n(&slot->ticket, __ATOMIC_ACQUIRE);
	if (out->live_ticket != s->batch.ticket ||
	    __atomic_load_n(&slot->nr_frames, __ATOMIC_RELAXED) != SP_NR_FRAMES)
		return -ESTALE;
	out->ready_prod = __atomic_load_n(&hdr->ready_prod, __ATOMIC_ACQUIRE);
	out->ready_cons = __atomic_load_n(&hdr->ready_cons, __ATOMIC_ACQUIRE);
	out->done_prod = __atomic_load_n(&hdr->done_prod, __ATOMIC_ACQUIRE);
	out->done_cons = __atomic_load_n(&hdr->done_cons, __ATOMIC_ACQUIRE);
	out->batch.slot = __atomic_load_n(&ready->slot, __ATOMIC_RELAXED);
	out->batch.nr_frames = __atomic_load_n(&ready->nr_frames, __ATOMIC_RELAXED);
	out->batch.ticket = __atomic_load_n(&ready->ticket, __ATOMIC_RELAXED);
	out->batch.batch_id = __atomic_load_n(&ready->batch_id, __ATOMIC_RELAXED);
	out->batch.key = __atomic_load_n(&ready->key, __ATOMIC_RELAXED);
	out->batch.arg = __atomic_load_n(&ready->arg, __ATOMIC_RELAXED);
	if (out->batch.slot != s->batch.slot || out->batch.nr_frames != SP_NR_FRAMES ||
	    out->batch.ticket != s->batch.ticket || out->batch.batch_id != s->batch.batch_id ||
	    out->batch.key != s->batch.key || out->batch.arg != s->batch.arg)
		return -ESTALE;
	for (unsigned int i = 0; i < SP_NR_FRAMES; i++) {
		struct xdev_ext_user_frame *f = &out->batch.f[i];

		f->umem_addr = __atomic_load_n(&slot->f[i].umem_addr, __ATOMIC_RELAXED);
		f->data_off = __atomic_load_n(&slot->f[i].data_off, __ATOMIC_RELAXED);
		f->data_len = __atomic_load_n(&slot->f[i].data_len, __ATOMIC_RELAXED);
		f->capacity = __atomic_load_n(&slot->f[i].capacity, __ATOMIC_RELAXED);
		f->out_len = __atomic_load_n(&slot->f[i].out_len, __ATOMIC_RELAXED);
		if (f->umem_addr > SP_POOL_BYTES - SP_FRAME_SIZE ||
		    f->data_off >= SP_FRAME_SIZE ||
		    out->batch.data[i] != o->umem + f->umem_addr + f->data_off)
			return -EPROTO;
		memcpy(out->frame_bytes + i * SP_FRAME_SIZE, o->umem + f->umem_addr, SP_FRAME_SIZE);
	}
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	if (__atomic_load_n(&slot->ticket, __ATOMIC_RELAXED) != out->live_ticket)
		return -ESTALE;
	ret = sp_remaining(o, s);
	if (ret < 0)
		return ret;
	return sp_hold_valid(out) ? sp_bytes(o) : -EPROTO;
}

static int sp_take(struct sp_owner *o, struct sp_side *s, struct sp_hold_snapshot *out)
{
	int wait = sp_remaining(o, NULL), ret;
	uint64_t now;

	if (wait < 0)
		return wait;
	ret = xdev_ext_user_stage_next(s->user, wait, &s->batch);
	if (ret)
		return ret;
	s->holding = true;
	now = sp_now_ms();
	if (!now)
		return -EIO;
	s->hold_end = now + SP_HOLD_BUDGET_MS;
	return sp_observe(o, s, out);
}

static int sp_finish(struct sp_owner *o, struct sp_side *s)
{
	struct xdev_ext_mech_stats stats;
	uint64_t count;
	int ret = sp_remaining(o, s);

	if (ret < 0)
		return ret;
	for (unsigned int i = 0; i < s->batch.nr_frames; i++)
		s->batch.f[i].out_len = s->batch.f[i].data_len;
	/* Ring publication can precede an ioctl error; never complete twice. */
	s->holding = false;
	ret = xdev_ext_user_stage_complete(s->user, &s->batch, 0);
	if (ret)
		return ret;
	for (;;) {
		struct pollfd p = { .fd = s->efd, .events = POLLIN };
		int wait = sp_remaining(o, s);

		if (wait < 0)
			return wait;
		ret = poll(&p, 1, wait);
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return ret ? -errno : -ETIMEDOUT;
		if (p.revents & (POLLERR | POLLHUP | POLLNVAL))
			return -EIO;
		if (read(s->efd, &count, sizeof(count)) == sizeof(count))
			break;
		if (errno != EINTR && errno != EAGAIN)
			return -EIO;
	}
	ret = sp_stats(o, s, &stats);
	if (ret)
		return ret;
	if (count != 1 || stats.state != XDEV_EXT_MECH_SESSION_ACTIVE || stats.inflight ||
	    stats.batches_done != 1 || stats.published != SP_NR_FRAMES || stats.last_err ||
	    stats.batches_abort || stats.sequestered || stats.rejects || stats.protocol_err ||
	    stats.timeouts || stats.submitted[0] != 1 || stats.completed[0] != 1)
		return -EPROTO;
	ret = sp_remaining(o, s);
	return ret < 0 ? ret : sp_bytes(o);
}

static int sp_idle(const struct sp_owner *o, const struct sp_side *s)
{
	const struct xdev_ext_user_ring_hdr *hdr = (void *)((char *)s->control + s->off.hdr);
	struct xdev_ext_mech_stats stats;
	int ret = sp_stats(o, s, &stats);

	if (ret)
		return ret;
	if (stats.state != XDEV_EXT_MECH_SESSION_ACTIVE || stats.inflight ||
	    stats.batches_done || stats.published || stats.last_err || stats.batches_abort ||
	    stats.sequestered || stats.rejects || stats.protocol_err || stats.timeouts ||
	    stats.submitted[0] || stats.completed[0] ||
	    __atomic_load_n(&hdr->ready_prod, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&hdr->ready_cons, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&hdr->done_prod, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&hdr->done_cons, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&sp_slot(s)->ticket, __ATOMIC_ACQUIRE))
		return -EPROTO;
	return 0;
}

static int sp_stop(struct sp_owner *o, struct sp_side *s)
{
	struct xdev_ext_mech_stop_report report = {
		.size = sizeof(report), .version = XDEV_EXT_MECH_STOP_REPORT_VERSION,
		.session_id = s->id,
	};
	int ret;

	if (!s->id || s->released)
		return 0;
	if (s->stop_attempted)
		return s->stop_error;
	s->stop_attempted = true;
	ret = sp_mech(o, XDEV_EXT_MECH_OP_STOP_REPORT, (uintptr_t)&report);
	if (!ret && (report.stats.session_id != s->id || report.stats.inflight ||
		     report.stats.sequestered))
		ret = -EPROTO;
	s->stop_error = ret;
	fprintf(stderr, "SHAREDPOOL_STOP id=%llu result=%d\n", (unsigned long long)s->id, ret);
	if (ret)
		o->unsafe = true;
	else {
		s->stop_stats = report.stats;
		s->released = true;
		/* Non-strict USER STOP revokes the grant, not raw CPU mappings.
		 * Every caller must have stopped payload access before STOP. */
		s->holding = false;
	}
	return ret;
}

static int sp_cleanup(struct sp_owner *o)
{
	int ret = 0, error;

	for (unsigned int i = 0; i < 2; i++) {
		struct sp_side *s = &o->side[i];

		if (s->holding && __atomic_load_n(&sp_slot(s)->ticket, __ATOMIC_ACQUIRE) == s->batch.ticket) {
			s->holding = false;
			/* CPU owner relinquishes a still-current grant; verdict stays FAIL. */
			(void)xdev_ext_user_stage_complete(s->user, &s->batch, 0);
		}
		error = sp_stop(o, s);
		if (error && !ret)
			ret = error;
	}
	if (o->unsafe) {
		fprintf(stderr, "SHAREDPOOL_OWNER=RETAINED\n");
		return ret ? ret : -EBUSY;
	}
	for (unsigned int i = 0; i < 2; i++) {
		error = xdev_ext_user_stage_close(o->side[i].user);
		if (error && !ret)
			ret = error;
		if (o->side[i].efd >= 0 && close(o->side[i].efd) && !ret)
			ret = -errno;
	}
	if (o->ring >= 0 && close(o->ring) && !ret)
		ret = -errno;
	if (o->umem && munmap(o->umem, SP_POOL_BYTES) && !ret)
		ret = -errno;
	if (o->prog) {
		error = xdev_ext_prog_detach(o->prog);
		if (error && !ret)
			ret = error;
	}
	return ret;
}

enum sp_case_kind {
	SP_RETURNED_STOP,
	SP_BUSY_START,
	SP_DUPLICATE_START,
	SP_CONCURRENT_START,
	SP_STALE_COMPLETION,
	SP_EARLY_STOP,
	SP_CASE_COUNT,
};

static const char *const sp_case_names[SP_CASE_COUNT] = {
	"returned-stop", "busy-start", "duplicate-start", "concurrent-start",
	"stale-completion", "early-stop",
};

struct sp_start_thread {
	struct sp_owner *owner;
	struct sp_side *side;
	int *go;
	int result;
};

static void *sp_start_thread(void *arg)
{
	struct sp_start_thread *t = arg;
	int go;

	while (!(go = __atomic_load_n(t->go, __ATOMIC_ACQUIRE)))
		sched_yield();
	t->result = go < 0 ? -ECANCELED : sp_start(t->owner, t->side);
	return NULL;
}

/* The winning grant remains held until both START syscalls have returned.
 * Scheduling order may vary; exactly one success and one EBUSY is mandatory. */
static int sp_start_pair(struct sp_owner *o, unsigned int *winner)
{
	pthread_t thread[2];
	int go = 0, ret = 0, error;
	unsigned int nr = 0;
	struct sp_start_thread args[2] = {
		{ .owner = o, .side = &o->side[0], .go = &go },
		{ .owner = o, .side = &o->side[1], .go = &go },
	};

	for (nr = 0; nr < 2; nr++) {
		error = pthread_create(&thread[nr], NULL, sp_start_thread, &args[nr]);
		if (error) {
			ret = -error;
			break;
		}
	}
	__atomic_store_n(&go, ret ? -1 : 1, __ATOMIC_RELEASE);
	for (unsigned int i = 0; i < nr; i++) {
		error = pthread_join(thread[i], NULL);
		if (error && !ret)
			ret = -error;
	}
	if (ret)
		return ret;
	fprintf(stderr, "SHAREDPOOL_START_PAIR a=%d b=%d\n", args[0].result, args[1].result);
	if (!args[0].result && args[1].result == -EBUSY)
		*winner = 0;
	else if (!args[1].result && args[0].result == -EBUSY)
		*winner = 1;
	else
		return -EPROTO;
	return 0;
}

/* A duplicate completion is deliberately sent to A's own USER stage. A
 * completion ticket is scoped to its stage fd, not a cross-session token. */
static int sp_stale_completion(struct sp_owner *o, struct sp_side *a)
{
	const struct xdev_ext_user_ring_hdr *hdr = (void *)((char *)a->control + a->off.hdr);
	struct xdev_ext_mech_stats stats;
	uint64_t count;
	int ret;

	/* The original completion must have left this one-entry ring. */
	while (__atomic_load_n(&hdr->done_cons, __ATOMIC_ACQUIRE) != 1) {
		if (sp_remaining(o, NULL) < 0)
			return -ETIMEDOUT;
		sched_yield();
	}
	ret = xdev_ext_user_stage_complete(a->user, &a->batch, 0);
	if (ret)
		return ret;
	for (;;) {
		if (sp_remaining(o, NULL) < 0)
			return -ETIMEDOUT;
		ret = sp_stats(o, a, &stats);
		if (ret)
			return ret;
		if ((stats.rejects && __atomic_load_n(&hdr->done_cons, __ATOMIC_ACQUIRE) == 2) ||
		    stats.state != XDEV_EXT_MECH_SESSION_ACTIVE || stats.last_err || stats.sequestered)
			break;
		sched_yield();
	}
	if (stats.rejects != 1 || stats.state != XDEV_EXT_MECH_SESSION_ACTIVE ||
	    stats.inflight || stats.batches_done != 1 || stats.batches_abort ||
	    stats.published != SP_NR_FRAMES || stats.last_err || stats.sequestered ||
	    stats.protocol_err || stats.timeouts || stats.submitted[0] != 1 ||
	    stats.completed[0] != 1 ||
	    __atomic_load_n(&sp_slot(a)->ticket, __ATOMIC_ACQUIRE) ||
	    __atomic_load_n(&hdr->done_prod, __ATOMIC_ACQUIRE) != 2 ||
	    __atomic_load_n(&hdr->done_cons, __ATOMIC_ACQUIRE) != 2)
		return -EPROTO;
	/* A's terminal notification was already consumed by sp_finish(). */
	if (read(a->efd, &count, sizeof(count)) != -1 || errno != EAGAIN)
		return -EPROTO;
	return 0;
}

static int sp_case(const char *obj_path, enum sp_case_kind kind)
{
	struct sp_owner o = { .ring = -1, .side = { { .efd = -1 }, { .efd = -1 } } };
	struct sp_side *a = &o.side[0], *b = &o.side[1];
	struct sp_hold_snapshot before, after;
	unsigned int winner;
	int fd_before = eval_fd_count(), ret, cleanup;
	uint64_t now;

	if (fd_before < 0)
		return -EIO;
	ret = sp_setup(&o, obj_path);
	if (ret)
		goto out;
	now = sp_now_ms();
	if (!now) {
		ret = -EIO;
		goto out;
	}
	o.case_end = now + SP_CASE_BUDGET_MS;
	if (kind == SP_CONCURRENT_START) {
		ret = sp_start_pair(&o, &winner);
		if (!ret) {
			a = &o.side[winner];
			b = &o.side[winner ^ 1U];
		}
	} else {
		ret = sp_start(&o, a);
	}
	if (!ret)
		ret = sp_take(&o, a, &before);
	if (ret)
		goto out;
	if (kind == SP_BUSY_START || kind == SP_DUPLICATE_START) {
		ret = sp_start(&o, kind == SP_DUPLICATE_START ? a : b);
		if (ret != -EBUSY) {
			ret = -EPROTO;
			goto out;
		}
	}
	if (kind == SP_BUSY_START || kind == SP_DUPLICATE_START || kind == SP_CONCURRENT_START) {
		ret = sp_idle(&o, b);
		if (!ret)
			ret = sp_observe(&o, a, &after);
		if (!ret && !sp_held_equal(&before, &after))
			ret = -EPROTO;
		if (ret)
			goto out;
	}
	if (kind == SP_EARLY_STOP) {
		/* A's CPU owner is this thread and has stopped all payload access.
		 * B holds a disjoint grant; STOP must cancel A without touching B. */
		b->indices[0] = 2;
		b->indices[1] = 5;
		ret = sp_start(&o, b);
		if (!ret)
			ret = sp_take(&o, b, &before);
		if (!ret)
			ret = sp_stop(&o, a);
		if (!ret && (a->stop_stats.batches_done || a->stop_stats.batches_abort != 1 ||
			     a->stop_stats.published != SP_NR_FRAMES ||
			     __atomic_load_n(&sp_slot(a)->ticket, __ATOMIC_ACQUIRE)))
			ret = -EPROTO;
		if (!ret)
			ret = sp_observe(&o, b, &after);
		if (!ret && !sp_held_equal(&before, &after))
			ret = -EPROTO;
		if (!ret)
			ret = sp_finish(&o, b);
		goto out;
	}
	ret = sp_finish(&o, a);
	if (!ret)
		ret = sp_start(&o, b);
	if (!ret)
		ret = sp_take(&o, b, &before);
	if (ret)
		goto out;
	if (kind == SP_RETURNED_STOP || kind == SP_STALE_COMPLETION) {
		ret = sp_remaining(&o, b);
		if (ret > 0)
			ret = kind == SP_RETURNED_STOP ? sp_stop(&o, a) : sp_stale_completion(&o, a);
		if (!ret)
			ret = sp_observe(&o, b, &after);
		if (!ret && !sp_held_equal(&before, &after))
			ret = -EPROTO;
		if (ret)
			goto out;
	}
	ret = sp_finish(&o, b);
	if (!ret && sp_remaining(&o, NULL) < 0)
		ret = -ETIMEDOUT;
out:
	cleanup = sp_cleanup(&o);
	if (!ret)
		ret = cleanup;
	if (eval_fd_check(fd_before) && !ret)
		ret = -EIO;
	if (!ret && o.case_end && sp_remaining(&o, NULL) < 0)
		ret = -ETIMEDOUT;
	fprintf(stderr, "SHAREDPOOL_CASE case=%s result=%d\n",
		sp_case_names[kind], ret);
	return ret;
}

int main(int argc, char **argv)
{
	static const struct option options[] = {
		{ "case", required_argument, NULL, 'c' },
		{ "plan-obj", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 },
	};
	const char *which = NULL, *obj_path = NULL;
	int opt, ret = 0, first = 0, last = SP_CASE_COUNT;

	while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if (opt == 'c')
			which = optarg;
		else if (opt == 'p')
			obj_path = optarg;
		else
			return 2;
	}
	if (which && strcmp(which, "all")) {
		for (first = 0; first < SP_CASE_COUNT; first++)
			if (!strcmp(which, sp_case_names[first]))
				break;
		last = first + 1;
	}
	if (!which || !obj_path || optind != argc || first >= SP_CASE_COUNT) {
		fprintf(stderr, "usage: sharedpool_session_guest --case returned-stop|busy-start|duplicate-start|"
			"concurrent-start|stale-completion|early-stop|all --plan-obj PATH\n");
		return 2;
	}
	for (int i = first; i < last && !ret; i++)
		ret = sp_case(obj_path, i);
	printf("SHAREDPOOL_KERNEL_QUALIFICATION=%s case=%s\n", ret ? "FAIL" : "PASS", which);
	return ret ? 1 : 0;
}
