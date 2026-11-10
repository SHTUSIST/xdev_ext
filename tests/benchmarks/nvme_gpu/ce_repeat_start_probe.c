// SPDX-License-Identifier: GPL-2.0-only
/* One CREATE, seven START-to-terminal-wake rounds. Internal component diagnostic;
 * retaining UMEM/mapping/window/channel/worker does not isolate channel cost.
 * CUDA seeds/readbacks are outside t0/t1; this is not a paper/eval baseline. */
#define _GNU_SOURCE
#include <stdlib.h>
#include "eval_session.h"
#include "ce_worker_accounting.h"
#ifndef CE_REPEAT_SOURCE
#define CE_REPEAT_SOURCE "unqualified"
#endif
#define RP_SIZE 65536U
#define RP_FRAME 4096U
#define RP_DEPTH 4U
#define RP_BATCHES 32U
#define RP_ROUNDS 7U
#define RP_FRAMES (RP_DEPTH * RP_SIZE / RP_FRAME)
#define RP_BYTES (RP_DEPTH * RP_SIZE)

static int rp_valid(const struct xdev_ext_mech_stats *s, __u64 session,
                    __u64 done, __u64 published)
{
 unsigned int i;
 if (s->session_id != session || s->state != XDEV_EXT_MECH_SESSION_ACTIVE ||
     s->last_err || s->batches_done != done || s->published != published ||
     s->batches_abort || s->rejects || s->held || s->sequestered ||
     s->timeouts || s->protocol_err || s->inflight)
  return -EIO;
 for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++)
  if (s->submitted[i] != (i ? 0 : done) || s->completed[i] != (i ? 0 : done))
   return -EIO;
 return 0;
}

static unsigned char rp_pattern(unsigned int round, unsigned int offset)
{
 return (unsigned char)(53U + round * 29U + offset * 17U + (offset >> 8));
}

static int rp_check(const unsigned char *buf, unsigned int round)
{
 unsigned int i;
 for (i = 0; i < RP_BYTES; i++) {
  unsigned int off = i % RP_FRAME;
  unsigned char expected = (53U + 29U * round + 17U * off + off / 256U) & 255U;
  if (buf[i] != expected)
   return -EIO;
 }
 return 0;
}

/* Empty the prior arm outside the timer; the new arm must not wake before START. */
static int rp_arm(const struct es_run *r, __u64 done, __u64 published)
{
 struct xdev_ext_mech_notify_arm arm;
 uint64_t count;
 ssize_t n;
 int ret;
 if (done > UINT64_MAX - RP_BATCHES || published > UINT64_MAX - RP_FRAMES)
  return -EOVERFLOW;
 do {
  n = read(r->efd, &count, sizeof(count));
 } while (n == sizeof(count) || (n < 0 && errno == EINTR));
 if (n >= 0 || errno != EAGAIN)
  return n < 0 ? -errno : -EIO;
 arm = (struct xdev_ext_mech_notify_arm) {
  .session_id = r->session, .batches_target = done + RP_BATCHES,
  .published_target = published + RP_FRAMES,
 };
 ret = es_mech(r->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
 if (ret)
  return ret;
 do {
  n = read(r->efd, &count, sizeof(count));
 } while (n < 0 && errno == EINTR);
 return n < 0 && errno == EAGAIN ? 0 : (n < 0 ? -errno : -EIO);
}

static unsigned int rp_rounds(bool aba) { return RP_ROUNDS * (aba ? 3U : 1U); }
static bool rp_is_spin(bool aba, unsigned int round) { return aba && round / RP_ROUNDS == 1; }

static int rp_spin(const struct es_run *r, __u64 deadline)
{
 uint64_t count; ssize_t n;
 for (;;) {
  __u64 now = es_now_ns();
  if (!now || now >= deadline) return -ETIMEDOUT;
  n = read(r->efd, &count, sizeof(count));
  if (n == sizeof(count)) return 0;
  if (n >= 0) return -EIO;
  if (errno != EAGAIN && errno != EINTR) return -errno;
 }
}
static __u64 rp_cpu_ns(void)
{
 struct timespec ts;
 return clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) ? 0 :
        (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static void rp_report(bool aba, unsigned int round, __u64 session,
                      const struct xdev_ext_mech_stats *s, __u64 t0, __u64 t1, __u64 cpu)
{
 __u64 before = (__u64)round * RP_BATCHES, target = before + RP_BATCHES;
 if (aba)
  printf("CE_WAIT_ABA phase=%u mode=%s local_round=%u global_round=%u "
         "start_ns=%llu terminal_ns=%llu caller_cpu_ns=%llu "
         "caller_cpu_scope=guest-thread-before-t0_after-t1 ", round / RP_ROUNDS,
         rp_is_spin(aba, round) ? "spin" : "block", round % RP_ROUNDS, round,
         (unsigned long long)t0, (unsigned long long)t1, (unsigned long long)cpu);
 else fputs("CE_REPEAT_START ", stdout);
 printf("SOURCE=%s session=%llu round=%u size=%u frame=%u depth=%u "
         "batches=%u first_seq=%llu absolute_notify_target=%llu published=%llu "
         "native_submitted=%llu native_completed=%llu done=%llu delta_done=%llu "
         "elapsed_ns=%llu oracle=PASS diagnostic=internal\n", CE_REPEAT_SOURCE,
         (unsigned long long)session, round, RP_SIZE, RP_FRAME, RP_DEPTH, RP_BATCHES,
         (unsigned long long)(before + 1), (unsigned long long)target,
         (unsigned long long)s->published, (unsigned long long)s->submitted[0],
         (unsigned long long)s->completed[0], (unsigned long long)s->batches_done,
         (unsigned long long)(s->batches_done - before), (unsigned long long)(t1 - t0));
}


static void rp_worker_snapshot(unsigned int round, uint64_t sid, const char *edge,
                               const struct cwa_identity *id,
                               const struct cwa_snapshot *sample, int error)
{
 printf("CE_WORKER_ACCOUNTING_SNAPSHOT SOURCE=%s session=%llu round=%u edge=%s status=%s error=%d ",
        CE_REPEAT_SOURCE, (unsigned long long)sid, round, edge, error ? "HOLD" : "VALID", error);
 if (id->pid > 0)
  printf("pid=%d start_ticks=%llu comm=%s", id->pid,
         (unsigned long long)id->start_ticks, id->comm);
 else
  fputs("pid=UNKNOWN start_ticks=UNKNOWN comm=UNKNOWN", stdout);
 if (!error)
  printf(" runtime_ns=%llu run_delay_ns=%llu pcount=%llu read_begin_ns=%llu read_end_ns=%llu",
         (unsigned long long)sample->runtime_ns, (unsigned long long)sample->run_delay_ns,
         (unsigned long long)sample->pcount, (unsigned long long)sample->read_begin_ns,
         (unsigned long long)sample->read_end_ns);
 putchar('\n');
}

static int rp_worker_report(unsigned int round, uint64_t sid,
                             const struct cwa_identity *id,
                             const struct cwa_snapshot *pre, const struct cwa_snapshot *post,
                             int discovery, int pre_error, int post_error, int prior_error,
                             uint64_t t0, uint64_t t1)
{
 struct cwa_delta delta = {0};
 const char *reason = "none";
 int error = 0, have_delta = 0;
 rp_worker_snapshot(round, sid, "pre", id, pre, pre_error);
 rp_worker_snapshot(round, sid, "post", id, post, post_error);
 if (discovery) { error = discovery; reason = "discovery"; }
 else if (pre_error) { error = pre_error; reason = error == -ESTALE ? "identity" : "pre-read"; }
 else if (post_error) { error = post_error; reason = error == -ESTALE ? "identity" : "post-read"; }
 else {
  error = prior_error ? prior_error : cwa_delta(pre, post, &delta);
  if (error == -ESTALE) reason = "identity";
  else if (error == -ERANGE) reason = "counter-regression";
  else if (error == -EINVAL) reason = "read-order";
  else {
   if (pre->read_end_ns > t0 || t0 >= t1 || t1 > post->read_begin_ns) {
    error = -EINVAL; reason = "read-order";
   } else {
    have_delta = 1;
    if (error) reason = "no-progress";
   }
  }
 }
 printf("CE_WORKER_ACCOUNTING SOURCE=%s session=%llu round=%u status=%s reason=%s "
        "timed_begin_ns=%llu timed_end_ns=%llu scope=guest-worker-outer-read-settle",
        CE_REPEAT_SOURCE, (unsigned long long)sid, round, error ? "HOLD" : "VALID", reason,
        (unsigned long long)t0, (unsigned long long)t1);
 if (have_delta)
  printf(" runtime_delta_ns=%llu run_delay_delta_ns=%llu pcount_delta=%llu outer_begin_ns=%llu outer_end_ns=%llu",
         (unsigned long long)delta.runtime_ns, (unsigned long long)delta.run_delay_ns,
         (unsigned long long)delta.pcount, (unsigned long long)pre->read_begin_ns,
         (unsigned long long)post->read_end_ns);
 putchar('\n');
 return error != 0;
}

int main(int argc, char **argv)
{
 const char *dev = "/dev/nvidia0";
 bool wait_aba = false, worker_accounting = false;
 struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
 struct es_run r = { .ring = -1, .efd = -1 };
 struct xdev_ext_mech_create c = { 0 };
 struct xdev_ext_mech_stats s;
 struct io_uring_xdev_ext_umem_reg reg = { .size = RP_BYTES, .frame_size = RP_FRAME };
 unsigned char *umem = MAP_FAILED, *buf = NULL;
 __u32 user[RP_FRAMES];
 struct cwa_identity worker = {0};
 struct cwa_snapshot worker_last = {0};
 int worker_last_valid = 0;
 __u64 accounting_session = 0;
 unsigned int worker_valid = 0, worker_hold = 0;
 int worker_discovery = 0;
 unsigned int round, i;
 int fd_before, ret, stop;
 if (argc == 2 && !strcmp(argv[1], "--help")) {
  puts("usage: ce_repeat_start_probe [--ce-dev /dev/nvidiaN] [--wait-aba|--worker-accounting]\n"
       "fixed 64KiB/F4KiB/D4/N32/7START; --wait-aba BLOCK7/SPIN7/BLOCK7; internal only, never a paper result");
  return XG_EXIT_PASS;
 }
 for (i = 1; i < (unsigned int)argc; i++) {
  if (!strcmp(argv[i], "--wait-aba") && !wait_aba) wait_aba = true;
  else if (!strcmp(argv[i], "--worker-accounting") && !worker_accounting) worker_accounting = true;
  else if (!strcmp(argv[i], "--ce-dev") && i + 1 < (unsigned int)argc) dev = argv[++i];
  else return XG_EXIT_USAGE;
 }
 if (worker_accounting && wait_aba) return XG_EXIT_USAGE;
 if (es_ce_is_sim(dev) || !strcmp(CE_REPEAT_SOURCE, "unqualified"))
  return XG_EXIT_USAGE;
 ret = es_ce_runtime_begin(dev, &fd_before);
 if (ret)
  return ret;
 ret = es_ce_open(&ce, dev, 1, ES_CE_VMM, 0, RP_BYTES);
 if (ret)
  goto out;
 umem = mmap(NULL, RP_BYTES, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
 buf = malloc(RP_BYTES);
 if (umem == MAP_FAILED || !buf) { ret = XG_EXIT_FAIL; goto out; }
 for (i = 0; i < RP_FRAMES; i++)
  user[i] = i;
 reg.addr = (uintptr_t)umem;
 ret = es_ring_open(&r);
 if (!ret)
  ret = es_register(r.ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
 if (ret) { ret = XG_EXIT_UNAVAILABLE; goto out; }
 c.layout = (struct xdev_ext_mech_layout) {
  .frame_size = RP_FRAME, .seg_len = RP_FRAME, .group_bytes = RP_SIZE,
 };
 c.nr_stages = 1; c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM; c.pool_fd = -1;
 c.depth = RP_DEPTH;
 c.st[0] = (struct xdev_ext_mech_stage_uapi) {
  .class_id = XDEV_EXT_MECH_CLASS_CE, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
  .fd = ce.fd[0], .arg0 = ce.va, .arg1 = RP_BYTES,
 };
 ret = es_create(&r, &c, RP_BATCHES);
 if (!ret)
  ret = es_stats(&r, &s);
 if (ret) { ret = XG_EXIT_FAIL; goto out; }
 if (worker_accounting) {
  accounting_session = r.session;
  worker_discovery = cwa_discover("/proc", r.session, &worker);
 }
 for (round = 0; round < rp_rounds(wait_aba); round++) {
  struct cwa_snapshot worker_pre = {0}, worker_post = {0};
  int worker_pre_error = 0, worker_post_error = 0, worker_prior_error = 0;
  __u64 before = (__u64)round * RP_BATCHES, target = before + RP_BATCHES;
  __u64 published = (__u64)round * RP_FRAMES, t0, t1, deadline, cpu0 = 0, cpu1 = 0;
  struct xdev_ext_mech_start start = {
   .session_id = r.session, .nr_batches = RP_BATCHES, .first_seq = before + 1,
   .flags = XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_RECYCLE,
   .nr_user_frames = RP_FRAMES, .user_frames = (uintptr_t)user,
  };
  /* Terminal wake is gated by start_return_pending; exact published proves
   * every lent frame is USER before any subsequent CPU write. */
  if (rp_valid(&s, r.session, before, published)) { ret = XG_EXIT_FAIL; break; }
  for (i = 0; i < RP_BYTES; i++)
   umem[i] = rp_pattern(round, i % RP_FRAME);
  memset(buf, 0xa5 ^ round, RP_BYTES);
  if (es_ce_access(&ce, true, 0, buf, RP_BYTES) || rp_arm(&r, before, published)) {
   ret = XG_EXIT_FAIL; break;
  }
  deadline = es_now_ns() + 10000000000ULL;
  if (wait_aba && !(cpu0 = rp_cpu_ns())) { ret = XG_EXIT_FAIL; break; }
  if (worker_accounting)
   worker_pre_error = worker_discovery ? worker_discovery : cwa_snapshot("/proc", &worker, &worker_pre);
  t0 = es_now_ns();
  ret = es_mech(r.ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start);
  if (!ret)
   ret = rp_is_spin(wait_aba, round) ? rp_spin(&r, deadline) : es_wait_terminal(&r, deadline);
  t1 = es_now_ns();
  if (wait_aba) cpu1 = rp_cpu_ns();
  if (!ret)
   ret = es_settle(&r, target, deadline, &s);
  else
   (void)es_stats(&r, &s);
  if (worker_accounting)
   worker_post_error = worker_discovery ? worker_discovery : ret ? -ECANCELED : cwa_snapshot("/proc", &worker, &worker_post);
  es_print_stats(&s);
  if (ret || !t0 || t1 <= t0 || (wait_aba && (!cpu1 || cpu1 < cpu0)) || rp_valid(&s, r.session, target, published + RP_FRAMES) ||
      es_ce_access(&ce, false, 0, buf, RP_BYTES) || rp_check(buf, round)) {
   ret = XG_EXIT_FAIL; break;
  }
  rp_report(wait_aba, round, r.session, &s, t0, t1, cpu1 - cpu0);
  if (worker_accounting) {
   if (worker_last_valid && !worker_pre_error) {
    struct cwa_delta gap;
    worker_prior_error = cwa_delta(&worker_last, &worker_pre, &gap);
    if (worker_prior_error == -ENODATA) worker_prior_error = 0;
   }
   if (rp_worker_report(round, r.session, &worker, &worker_pre, &worker_post,
                        worker_discovery, worker_pre_error, worker_post_error, worker_prior_error, t0, t1))
    worker_hold++;
   else worker_valid++;
   if (!worker_post_error) { worker_last = worker_post; worker_last_valid = 1; }
  }
 }
 if (wait_aba && ret)
  fprintf(stderr, "CE_WAIT_ABA_FAILURE global_round=%u phase=%u mode=%s error=%d\n",
          round, round / RP_ROUNDS, rp_is_spin(wait_aba, round) ? "spin" : "block", ret);
 out:
 if (r.session) {
  stop = es_mech(r.ring, XDEV_EXT_MECH_OP_STOP, r.session);
  fprintf(stderr, "EVAL_STOP=%s result=%d\n", stop ? "FAIL" : "PASS", stop);
  if (stop) {
   fprintf(stderr, "CE_REPEAT_START=FAIL release=withheld\n");
   fflush(stdout); fflush(stderr); _exit(XG_EXIT_FAIL);
  }
  r.session = 0;
 }
 (void)es_close(&r);
 free(buf);
 if (umem != MAP_FAILED)
  munmap(umem, RP_BYTES);
 if (es_ce_close(&ce))
  ret = XG_EXIT_FAIL;
 if (eval_fd_check(fd_before))
  ret = XG_EXIT_FAIL;
 printf("%s result=%s rounds=%u diagnostic=internal "
        "scope=session-local-not-channel-causality\n", wait_aba ? "CE_WAIT_ABA_DONE" : "CE_REPEAT_START_DONE",
        ret ? "FAIL" : "PASS", ret ? 0 : rp_rounds(wait_aba));
 if (worker_accounting)
  fprintf(stderr, "CE_WORKER_ACCOUNTING_DONE SOURCE=%s session=%llu observations=%u valid=%u hold=%u "
          "status=%s data=%s scope=guest-worker-outer-read-settle\n", CE_REPEAT_SOURCE,
          (unsigned long long)accounting_session, worker_valid + worker_hold, worker_valid, worker_hold,
          !ret && worker_valid == RP_ROUNDS && !worker_hold ? "VALID" : "HOLD", ret ? "FAIL" : "PASS");
 return ret ? (ret == XG_EXIT_UNAVAILABLE ? ret : XG_EXIT_FAIL) : XG_EXIT_PASS;
}
