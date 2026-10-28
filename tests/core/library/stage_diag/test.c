/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"
#include "include/uapi/linux/io_uring.h"

static unsigned checks, failures, calls[12];
static int ring_fd, expected_fd, hook_bad, query_error, corrupt, stop_error;
static bool stats_gone, retained_create;
static __u64 expected_id = 0x123456789abcULL;
static __u32 expected_stage = 2;
static struct xdev_ext_mech_stage_diag reply;

static void check(bool value, const char *name)
{
 ++checks;
 printf("%s %u - %s\n", value ? "ok" : "not ok", checks, name);
 if (!value) ++failures;
}
static bool zero(const void *p, size_t n)
{
 const unsigned char *b = p;
 while (n--) if (*b++) return false;
 return true;
}
static void valid_reply(void)
{
 reply = (struct xdev_ext_mech_stage_diag){
  .size = sizeof(reply), .version = 1, .session_id = expected_id,
  .stage = expected_stage, .class_id = XDEV_EXT_MECH_CLASS_XDOMAIN,
  .valid = 63, .readiness = 63, .token = 101, .local_inc = 202,
  .remote_inc = 303, .pool_generation = 404,
  .capture_begin_ns = 999, .capture_end_ns = 1007,
  .native_inflight = 3, .software_pending = 9, .rx_native_posted = 2,
  .ctl_tx_free = 4, .cts_owed = 5, .ack_owed = 6, .fail_owed = 7,
  .final_waiting_chain = 8, .downstream_release_pending = 10,
  .retention = { .generations = 4, .retained_generations = 2,
   .reserved_bytes = 8000, .retained_bytes = 4000,
   .global_reserved_bytes = 32000, .global_retained_bytes = 16000,
   .global_limit = 64000 }
 };
}
static int setup(unsigned int entries, struct io_uring_params *p)
{
 (void)entries; (void)p;
 ring_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
 return ring_fd;
}
static int reg(int fd, unsigned opcode, void *arg, unsigned nr)
{
 if (opcode == IORING_REGISTER_XDEV_EXT_UMEM ||
     opcode == IORING_UNREGISTER_XDEV_EXT_UMEM) return 0;
 if (opcode != IORING_REGISTER_XDEV_EXT_MECH || nr != 1) {
  hook_bad++; return -EINVAL;
 }
 struct io_uring_xdev_ext_mech *m = arg;
 if (m->op >= 12) { hook_bad++; return -EINVAL; }
 calls[m->op]++;
 if (m->rsvd) hook_bad++;
 if (m->op == XDEV_EXT_MECH_OP_STAGE_DIAG) {
  struct xdev_ext_mech_stage_diag *d = (void *)(uintptr_t)m->arg;
  struct xdev_ext_mech_stage_diag input = {
   .size = sizeof(*d), .version = 1, .session_id = expected_id,
   .stage = expected_stage
  };
  if (fd != expected_fd || memcmp(d, &input, sizeof(input))) hook_bad++;
  if (query_error) {
   memset(d, 0xcc, sizeof(*d)); /* Failed copyout cannot escape as success. */
   return query_error;
  }
  *d = reply;
  switch (corrupt) {
  case 1: d->size--; break;
  case 2: d->version++; break;
  case 3: d->session_id++; break;
  case 4: d->stage++; break;
  case 5: d->valid |= 1U << 31; break;
  case 6: d->readiness |= 1U << 31; break;
  case 7: d->rsvd = 1; break;
  case 8: d->class_id = XDEV_EXT_MECH_CLASS_NVME; break;
  case 9: d->capture_end_ns = d->capture_begin_ns - 1; break;
  case 10: d->size = 0; break;
  case 11: d->version = 0; break;
  case 12: d->session_id = 0; break;
  case 13: d->valid &= ~XDEV_EXT_MECH_DIAG_IDENTITY; break;
  default: break;
  }
  return 0;
 }
 if (m->op == XDEV_EXT_MECH_OP_CREATE) {
  struct xdev_ext_mech_create *c = (void *)(uintptr_t)m->arg;
  c->session_id = expected_id;
  return 0;
 }
 if (m->op == XDEV_EXT_MECH_OP_CREATE_REPORT && retained_create) {
  struct xdev_ext_mech_create_with_report *e = (void *)(uintptr_t)m->arg;
  e->report = (struct xdev_ext_mech_create_report){
   .size = sizeof(e->report), .version = 1, .result = -EIO,
   .phase = XDEV_EXT_MECH_CREATE_CLASS_BIND, .failed_stage = 0,
   .cleanup = XDEV_EXT_MECH_CREATE_CLEANUP_RETAINED
  };
  return 0;
 }
 if (m->op == XDEV_EXT_MECH_OP_STOP) return stop_error;
 if (m->op == XDEV_EXT_MECH_OP_STATS) {
  if (stats_gone) return -ENOENT;
  return 0;
 }
 hook_bad++; return -EINVAL;
}
static void no_sleep(unsigned usec) { (void)usec; }
static const struct xdev_ext_sys hooks = {
 .io_uring_setup = setup, .io_uring_register = reg, .usleep = no_sleep
};
static struct xdev_ext_session *open_session(void)
{
 struct xdev_ext_session *s = NULL;
 struct xdev_ext_pool_opts p = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
  .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .nr_frames = 16);
 int ret = xdev_ext_session_open(&p, &s);
 check(ret == 0 && s != NULL, "normal IOU_UMEM session opens");
 return s;
}
static struct xdev_ext_create_opts opts(void)
{
 struct xdev_ext_create_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
  .nr_stages = 3, .group_bytes = 4096, .depth = 1);
 o.st[0].class_id = XDEV_EXT_MECH_CLASS_NVME;
 o.st[1].class_id = XDEV_EXT_MECH_CLASS_NVME;
 o.st[2].class_id = XDEV_EXT_MECH_CLASS_XDOMAIN;
 return o;
}
int main(void)
{
 struct xdev_ext_mech_stage_diag out;
 int ret;
 xdev_ext__set_sys(&hooks);
 expected_fd = 417;
 valid_reply();
 memset(&out, 0xa5, sizeof(out));
 ret = xdev_ext_stage_diag_read(expected_fd, expected_id, expected_stage, &out);
 check(ret == 0 && !memcmp(&out, &reply, sizeof(out)) && !hook_bad,
       "raw query uses exact ring/id/stage and zero input output fields");
 const char *names[] = {"", "wrong size", "wrong version", "wrong session",
  "wrong stage", "unknown valid bit", "unknown readiness bit", "reserved field",
  "wrong class", "reversed capture interval", "zero size", "zero version",
  "zero session", "missing identity validity"};
 for (corrupt = 1; corrupt <= 13; ++corrupt) {
  memset(&out, 0xa5, sizeof(out));
  ret = xdev_ext_stage_diag_read(expected_fd, expected_id, expected_stage, &out);
  char name[128]; snprintf(name, sizeof(name), "%s rejects complete output with EPROTO", names[corrupt]);
  check(ret == -EPROTO && zero(&out, sizeof(out)), name);
 }
 corrupt = 0;
 const int errors[] = {-EOPNOTSUPP, -EINVAL, -ENOENT, -ESTALE, -EFAULT, -EIO};
 for (unsigned i = 0; i < sizeof(errors)/sizeof(errors[0]); ++i) {
  query_error = errors[i]; memset(&out, 0xa5, sizeof(out));
  ret = xdev_ext_stage_diag_read(expected_fd, expected_id, expected_stage, &out);
  char name[128]; snprintf(name, sizeof(name), "syscall error %d preserved with zero output", errors[i]);
  check(ret == errors[i] && zero(&out, sizeof(out)), name);
 }
 query_error = 0;
 valid_reply();
 reply.valid = XDEV_EXT_MECH_DIAG_IDENTITY | XDEV_EXT_MECH_DIAG_RETENTION;
 reply.readiness = XDEV_EXT_MECH_DIAG_NHI_GONE | XDEV_EXT_MECH_DIAG_CLOSING;
 reply.native_inflight = reply.software_pending = reply.rx_native_posted = 0;
 check(xdev_ext_stage_diag_read(expected_fd, expected_id, expected_stage, &out) == 0 &&
       !memcmp(&out, &reply, sizeof(out)), "retired native rings retain identity/retention without native validity");
 valid_reply();
 unsigned before = calls[11];
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_stage_diag_read(-1, expected_id, expected_stage, &out) == -EINVAL &&
       zero(&out, sizeof(out)) && calls[11] == before, "invalid owning fd never submits");
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_stage_diag_read(expected_fd, 0, expected_stage, &out) == -EINVAL &&
       zero(&out, sizeof(out)) && calls[11] == before, "zero session never submits");
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_stage_diag_read(expected_fd, expected_id, XDEV_EXT_MECH_MAX_STAGES, &out) == -EINVAL &&
       zero(&out, sizeof(out)) && calls[11] == before, "invalid stage never submits");
 check(xdev_ext_stage_diag_read(expected_fd, expected_id, expected_stage, NULL) == -EINVAL &&
       calls[11] == before, "NULL output never submits");
 struct xdev_ext_session *s = open_session();
 if (!s) return 2;
 expected_fd = xdev_ext_session_ring_fd(s);
 struct xdev_ext_create_opts o = opts();
 before = calls[11];
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_session_stage_diag(s, 2, &out) == -ENOTCONN &&
       zero(&out, sizeof(out)) && calls[11] == before, "uncreated handle has no query ID");
 check(xdev_ext_session_create(s, &o) == 0 && xdev_ext_session_id(s) == expected_id,
       "normal legacy CREATE sets session ownership");
 unsigned create_before = calls[XDEV_EXT_MECH_OP_CREATE];
 check(xdev_ext_session_stage_diag(s, 2, &out) == 0 &&
       !memcmp(&out, &reply, sizeof(out)) && calls[XDEV_EXT_MECH_OP_CREATE] == create_before,
       "created handle queries its exact owning ring without CREATE");
 stop_error = -EBUSY;
 check(xdev_ext_session_stop(s) == -EBUSY && xdev_ext_session_retained(s),
       "normal STOP retains created session on EBUSY");
 before = calls[11];
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_session_stage_diag(s, 2, &out) == 0 && calls[11] == before + 1 &&
       !memcmp(&out, &reply, sizeof(out)), "stopping retained created handle remains diagnosable");
 stats_gone = true;
 check(xdev_ext_session_close(s) == 0, "close releases retained handle only after ENOENT");
 stats_gone = false; stop_error = 0;
 s = open_session(); if (!s) return 2;
 expected_fd = xdev_ext_session_ring_fd(s);
 check(xdev_ext_session_create(s, &o) == 0 && xdev_ext_session_stop(s) == 0,
       "normal successful STOP releases the owned session");
 before = calls[11];
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_session_stage_diag(s, 2, &out) == -ENOTCONN &&
       zero(&out, sizeof(out)) && calls[11] == before,
       "released session is rejected without submitting against a stale ID");
 check(xdev_ext_session_close(s) == 0, "released handle closes normally");
 before = calls[11];
 memset(&out, 0xa5, sizeof(out));
 check(xdev_ext_session_stage_diag(NULL, 2, &out) == -EINVAL &&
       zero(&out, sizeof(out)) && calls[11] == before, "NULL session is rejected with zero output");
 s = open_session(); if (!s) return 2;
 expected_fd = xdev_ext_session_ring_fd(s);
 retained_create = true;
 struct xdev_ext_mech_create_report report;
 check(xdev_ext_session_create_report(s, &o, &report) == -EIO &&
       xdev_ext_session_retained(s) && !xdev_ext_session_id(s),
       "retained failed CREATE has no published session ID");
 before = calls[11]; unsigned stats_before = calls[XDEV_EXT_MECH_OP_STATS];
 unsigned stop_before = calls[XDEV_EXT_MECH_OP_STOP];
 create_before = calls[XDEV_EXT_MECH_OP_CREATE];
 memset(&out, 0xa5, sizeof(out));
 ret = xdev_ext_session_stage_diag(s, 2, &out);
 check(ret < 0 && zero(&out, sizeof(out)) && calls[11] == before,
       "failed retained CREATE cannot issue op11 against ID zero");
 check(xdev_ext_session_close(s) == -EBUSY && calls[XDEV_EXT_MECH_OP_STATS] == stats_before,
       "failed retained CREATE close never queries STATS zero");
 check(xdev_ext_session_create(s, &o) == -EBUSY && calls[XDEV_EXT_MECH_OP_CREATE] == create_before &&
       xdev_ext_session_stop(s) == -EBUSY && calls[XDEV_EXT_MECH_OP_STOP] == stop_before,
       "failed retained CREATE never recreates or STOPs ID zero");
 check(!hook_bad, "all syscall envelopes match declared contract");
 printf("1..%u\n", checks);
 return failures ? 1 : 0;
}
