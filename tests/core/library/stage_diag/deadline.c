/* SPDX-License-Identifier: GPL-2.0 */
/* Direct production-function boundary, NOT a reachable XDOMAIN CLI campaign.
 * Current normal CLI has no START/wait command that constructs XDOMAIN. */
#define main stage_diag_original_ctl_main
#include "xdev_ext_mech_ctl.c"
#undef main

static unsigned tests, failures, ops[64], stages[8], nops, nstages, polls;
static __u64 fake_now;
static int diag_error, stop_error, bad;

static void expect(bool yes, const char *name)
{
 printf("%s %u - %s\n", yes ? "ok" : "not ok", ++tests, name);
 if (!yes) failures++;
}
int __wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
 if (id != CLOCK_MONOTONIC) bad++;
 ts->tv_sec = fake_now / 1000000000;
 ts->tv_nsec = fake_now % 1000000000;
 return 0;
}
int __wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
 (void)fds;
 if (n != 1 || timeout <= 0 || timeout > 11) bad++;
 if (++polls == 1) { fake_now += 4000000; errno = EINTR; return -1; }
 fake_now += 6000000;
 if (polls > 2) { bad++; fake_now += 1000000000; }
 return 0;
}
long __wrap_syscall(long nr, ...)
{
 va_list ap;
 va_start(ap, nr);
 if (nr != __NR_io_uring_register) { va_end(ap); bad++; errno = ENOSYS; return -1; }
 int fd = va_arg(ap, int);
 unsigned opcode = va_arg(ap, unsigned);
 void *arg = va_arg(ap, void *);
 unsigned count = va_arg(ap, unsigned);
 va_end(ap);
 if (fd != 417 || opcode != IORING_REGISTER_XDEV_EXT_MECH || count != 1) bad++;
 struct io_uring_xdev_ext_mech *m = arg;
 if (nops < 64) ops[nops++] = m->op;
 else bad++;
 if (m->op == XDEV_EXT_MECH_OP_STATS) {
  struct xdev_ext_mech_stats *s = (void *)(uintptr_t)m->arg;
  s->state = XDEV_EXT_MECH_SESSION_ACTIVE;
  return 0;
 }
 if (m->op == XDEV_EXT_MECH_OP_STAGE_DIAG) {
  struct xdev_ext_mech_stage_diag *d = (void *)(uintptr_t)m->arg;
  struct xdev_ext_mech_stage_diag input = {
   .size = sizeof(*d), .version = 1, .session_id = 771, .stage = d->stage
  };
  if (memcmp(d, &input, sizeof(input))) bad++;
  if (nstages < 8) stages[nstages++] = d->stage;
  else bad++;
  if (diag_error) { errno = -diag_error; return -1; }
  d->class_id = XDEV_EXT_MECH_CLASS_XDOMAIN;
  d->valid = XDEV_EXT_MECH_DIAG_IDENTITY;
  d->capture_begin_ns = fake_now;
  d->capture_end_ns = fake_now + 1;
  return 0;
 }
 if (m->op == XDEV_EXT_MECH_OP_TRANSPORT_STATS) { errno = EOPNOTSUPP; return -1; }
 if (m->op == XDEV_EXT_MECH_OP_STOP) {
  if (m->arg != 771) bad++;
  if (stop_error) { errno = -stop_error; return -1; }
  return 0;
 }
 bad++; errno = EINVAL; return -1;
}
static void run(bool coarse, int diag_err, int stop_err, bool with_xdomain)
{
 struct ctl_run r = { .ring = 417, .efd = -1, .session = 771,
  .deadline_ns = 1010000000, .poll_ms = 10 };
 struct xdev_ext_mech_create create = { .nr_stages = 4 };
 struct xdev_ext_mech_stats stats = {};
 __u64 target = 1;
 char name[160];
 if (with_xdomain) {
  create.st[1].class_id = XDEV_EXT_MECH_CLASS_XDOMAIN;
  create.st[3].class_id = XDEV_EXT_MECH_CLASS_XDOMAIN;
 }
 create.st[0].class_id = XDEV_EXT_MECH_CLASS_NVME;
 create.st[2].class_id = XDEV_EXT_MECH_CLASS_USER;
 nops = nstages = polls = bad = 0;
 diag_error = diag_err; stop_error = stop_err; fake_now = 1000000000;
 ctl_diag_stages(&r, &create);
 int ret = coarse ? ctl_wait_coarse(&r, target, &stats) :
  ctl_wait(&r, ctl_done_batches, &target, &stats);
 snprintf(name, sizeof(name), "%s diag=%d keeps timeout and original deadline after EINTR", coarse ? "coarse" : "polling", diag_err);
 expect(ret == -ETIMEDOUT && r.deadline_ns == 1010000000 && polls == 2, name);
 snprintf(name, sizeof(name), "%s queries only selected XDOMAIN stages through normal library", coarse ? "coarse" : "polling");
 expect(with_xdomain ? nstages == 2 && stages[0] == 1 && stages[1] == 3 : nstages == 0, name);
 unsigned diag_last = 0;
 for (unsigned i = 0; i < nops; i++) if (ops[i] == XDEV_EXT_MECH_OP_STAGE_DIAG) diag_last = i;
 ret = ctl_finish_reliable(&r, &stats, ret, NULL);
 unsigned stop_count = 0, stop_pos = 0;
 for (unsigned i = 0; i < nops; i++) if (ops[i] == XDEV_EXT_MECH_OP_STOP) { stop_count++; stop_pos = i; }
 snprintf(name, sizeof(name), "%s preserves timeout over query/STOP errors and still reaches original STOP", coarse ? "coarse" : "polling");
 expect(ret == -ETIMEDOUT && stop_count == 1 && (!with_xdomain || diag_last < stop_pos) && !r.session, name);
 expect(!bad, "deadline path syscall inputs retain exact owning ring/session and clean schema");
}
int main(void)
{
 run(false, 0, 0, true);
 run(false, -ESTALE, -EIO, true);
 run(true, 0, 0, true);
 run(true, -EOPNOTSUPP, -EBUSY, true);
 run(false, 0, 0, false);
 run(true, 0, 0, false);
 printf("1..%u\n", tests);
 return failures ? 1 : 0;
}
