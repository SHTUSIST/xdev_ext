/* SPDX-License-Identifier: GPL-2.0 */
/* Independent requirements tests: SDD 2026-10-26, sections 3 and 4. */
#include "epoch_control.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); exit(1); \
} } while (0)
#define NS_MS UINT64_C(1000000)
#define MAX_CALLS 256U
enum call { C_RING = 100, C_EVENT, C_POLL, C_READ, C_CLOSE_RING, C_CLOSE_EVENT };
struct ledger {
 struct tb_guard *guard;
 /* Final release-side observation is independent of STATS query injections. */
 struct xdev_ext_mech_stop_report final_report;
 unsigned int calls[MAX_CALLS], nr, count[128];
 uint64_t now, absolute_deadline, poll_deadlines[MAX_CALLS];
 unsigned int polls, reads, snapshots, closes, stop_calls;
 int create_error, arm_error, start_error, stop_error, stats_error, transport_error;
 int poll_error, read_error;
 unsigned int stop_eagain, poll_eintr;
 bool output_id_on_failure, controls_settle, inflight_forever, abort_batch;
 bool bad_size, bad_version, wrong_session, wrong_transport_session, reject_batch, protocol_error;
 bool timeout_batch, sequester_batch, last_error, overdone;
 bool observed_create_attempt, hold_during_create, no_event;
 const struct xdev_ext_mech_create *caller_request;
};
struct fixture {
 struct tb_guard *g;
 struct tb_epoch e;
 struct ledger l;
 struct xdev_ext_mech_create request;
};

static void record(struct ledger *l, unsigned int op)
{
 CHECK(l->nr < MAX_CALLS);
 CHECK(op < 128);
 l->calls[l->nr++] = op;
 l->count[op]++;
}
static int ring_setup(void *opaque)
{
 struct ledger *l = opaque;
 record(l, C_RING);
 return 41;
}
static int event_open(void *opaque)
{
 struct ledger *l = opaque;
 record(l, C_EVENT);
 return 42;
}
/* These legacy scenarios inject malformed/error STATS observations, then
 * separately configure successful or failed STOP. The final report is explicit;
 * query-only injected counters are not a model of persistent native custody. */
static void returned_stop_report(struct ledger *l,
                                 struct xdev_ext_mech_stop_report *r)
{
 const struct xdev_ext_mech_stats empty_stats = {0};
 const struct xdev_ext_mech_transport_stats_v4 empty_transport = {0};
 CHECK(r->size == sizeof(*r));
 CHECK(r->version == XDEV_EXT_MECH_STOP_REPORT_VERSION && r->session_id == 991);
 CHECK(memcmp(&r->stats, &empty_stats, sizeof(r->stats)) == 0);
 CHECK(memcmp(&r->transport, &empty_transport, sizeof(r->transport)) == 0);
 *r = l->final_report;
}
static int mech(void *opaque, int fd, uint32_t op, void *arg)
{
 struct ledger *l = opaque;
 CHECK(fd == 41);
 record(l, op);
 switch (op) {
 case XDEV_EXT_MECH_OP_CREATE: {
  struct xdev_ext_mech_create *c = arg;
  struct tb_guard_snapshot s = {0};
  tb_guard_snapshot(l->guard, &s);
  CHECK(c != l->caller_request);
  CHECK(c->eventfd == 42);
  CHECK(c->pool_fd == 73);
  l->observed_create_attempt = s.phase == TB_PHASE_CREATE_ATTEMPTED && !s.native_safe;
  CHECK(l->observed_create_attempt);
  if (!l->create_error || l->output_id_on_failure)
   c->session_id = 991;
  if (l->hold_during_create)
   tb_guard_hold(l->guard, TB_HOLD_SIGNAL);
  return l->create_error;
 }
 case XDEV_EXT_MECH_OP_NOTIFY_ARM: {
  struct xdev_ext_mech_notify_arm *a = arg;
  CHECK(a->session_id == 991);
  CHECK(a->batches_target == 3);
  CHECK(a->published_target == 0 && a->flags == 0 && a->rsvd == 0);
  return l->arm_error;
 }
 case XDEV_EXT_MECH_OP_START: {
  struct xdev_ext_mech_start *s = arg;
  CHECK(s->session_id == 991 && s->nr_batches == 3 && s->first_seq == 17);
  CHECK(s->flags == 0 && s->nr_user_frames == 0 && s->user_frames == 0);
  return l->start_error;
 }
 case XDEV_EXT_MECH_OP_STOP_REPORT: {
  l->stop_calls++;
  if (l->stop_eagain) {
   l->stop_eagain--;
   l->now += 5 * NS_MS;
   return -EAGAIN;
  }
  if (!l->stop_error)
   returned_stop_report(l, arg);
  return l->stop_error;
 }
 case XDEV_EXT_MECH_OP_STATS: {
  struct xdev_ext_mech_stats *s = arg;
  CHECK(s->session_id == 991);
  if (l->stats_error)
   return l->stats_error;
  memset(s, 0, sizeof(*s));
  s->session_id = l->wrong_session ? 992 : 991;
  s->batches_done = l->abort_batch ? 2 : (l->overdone ? 4 : 3);
  s->batches_abort = l->abort_batch ? 1 : 0;
  s->inflight = l->inflight_forever ? 1 : 0;
  s->rejects = l->reject_batch ? 1 : 0;
  s->protocol_err = l->protocol_error ? 1 : 0;
  s->timeouts = l->timeout_batch ? 1 : 0;
  s->sequestered = l->sequester_batch ? 1 : 0;
  s->last_err = l->last_error ? -EIO : 0;
  s->state = XDEV_EXT_MECH_SESSION_ACTIVE;
  l->snapshots++;
  return 0;
 }
 case XDEV_EXT_MECH_OP_TRANSPORT_STATS: {
  struct xdev_ext_mech_transport_stats_v4 *t = arg;
  CHECK(t->v3.v2.v1.session_id == 991);
  CHECK(t->v3.v2.v1.size == sizeof(*t));
  CHECK(t->v3.v2.v1.version == XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4);
  if (l->transport_error)
   return l->transport_error;
  memset(t, 0, sizeof(*t));
  t->v3.v2.v1.session_id = l->wrong_transport_session ? 992 : 991;
  t->v3.v2.v1.size = l->bad_size ? sizeof(*t) - 1 : sizeof(*t);
  t->v3.v2.v1.version = l->bad_version ? 3 : XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4;
  if (l->controls_settle && l->snapshots == 1) {
   t->v3.v2.v1.native_controls = 1;
   t->v3.v2.v1.pending_acks = 1;
   t->v3.v2.v1.uncertain_controls = 1;
  }
  return 0;
 }
 default:
  CHECK(!"unexpected mech operation");
  return -EINVAL;
 }
}
static int poll_event(void *opaque, int fd, uint64_t deadline)
{
 struct ledger *l = opaque;
 CHECK(fd == 42);
 record(l, C_POLL);
 CHECK(l->polls < MAX_CALLS);
 l->poll_deadlines[l->polls++] = deadline;
 CHECK(deadline > l->now);
 CHECK(deadline <= l->absolute_deadline);
 CHECK(deadline - l->now <= 20 * NS_MS);
 if (l->poll_error)
  return l->poll_error;
 if (l->poll_eintr) {
  l->poll_eintr--;
  l->now += NS_MS;
  return -EINTR;
 }
 if (!l->reads && !l->no_event)
  return 1;
 l->now = deadline;
 return 0;
}
static int event_read(void *opaque, int fd, uint64_t *value)
{
 struct ledger *l = opaque;
 CHECK(fd == 42);
 record(l, C_READ);
 CHECK(++l->reads == 1); /* Exactly one terminal event is ever delivered. */
 if (l->read_error)
  return l->read_error;
 *value = 1;
 return 0;
}
static uint64_t now_ns(void *opaque)
{
 struct ledger *l = opaque;
 return l->now;
}
static int fd_close(void *opaque, int fd)
{
 struct ledger *l = opaque;
 CHECK(fd == 41 || fd == 42); /* Pool/provider 73 is caller-owned. */
 record(l, fd == 41 ? C_CLOSE_RING : C_CLOSE_EVENT);
 l->closes++;
 CHECK(l->count[C_CLOSE_RING] <= 1 && l->count[C_CLOSE_EVENT] <= 1);
 return 0;
}
static void fixture_init(struct fixture *f)
{
 struct tb_epoch_io io;
 memset(f, 0, sizeof(*f));
 CHECK(tb_guard_new(TB_BACKING_EXISTING_PROVIDER, &f->g) == 0);
 CHECK(tb_guard_external_ready(f->g, TB_READY_EXISTING_PROVIDER_REGISTERED) == 0);
 f->l.guard = f->g;
 /* Existing STOP success was separately configured from read-side STATS
  * counter/identity/failure injection. Make its actual report data explicit. */
 f->l.final_report.size = sizeof(f->l.final_report);
 f->l.final_report.version = XDEV_EXT_MECH_STOP_REPORT_VERSION;
 f->l.final_report.session_id = 991;
 f->l.final_report.stats.session_id = 991;
 f->l.final_report.stats.batches_done = 3;
 f->l.final_report.stats.state = XDEV_EXT_MECH_SESSION_STOPPED;
 f->l.final_report.transport.v3.v2.v1.session_id = 991;
 f->l.final_report.transport.v3.v2.v1.size = sizeof(f->l.final_report.transport);
 f->l.final_report.transport.v3.v2.v1.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4;
 f->l.now = 100 * NS_MS;
 f->l.absolute_deadline = 200 * NS_MS;
 f->request = (struct xdev_ext_mech_create){
  .abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
  .pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = 73,
  .layout = {65536, 0, 65536, 65536}, .depth = 1, .eventfd = -1,
 };
 f->request.st[0] = (struct xdev_ext_mech_stage_uapi){
  .class_id = XDEV_EXT_MECH_CLASS_NVME,
  .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 74, .arg1 = 128,
 };
 f->request.st[1] = (struct xdev_ext_mech_stage_uapi){
  .class_id = XDEV_EXT_MECH_CLASS_NVME,
  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 75, .arg1 = 128,
 };
 f->l.caller_request = &f->request;
 io = (struct tb_epoch_io){.opaque = &f->l, .ring_setup = ring_setup,
  .event_open = event_open, .mech = mech, .poll_event = poll_event,
  .event_read = event_read, .now_ns = now_ns, .fd_close = fd_close};
 CHECK(tb_epoch_init(&f->e, f->g, &io) == 0);
}
static void open_ok(struct fixture *f)
{
 CHECK(tb_epoch_open(&f->e, &f->request) == 0);
 CHECK(f->e.created && f->e.fate == TB_EPOCH_ACTIVE);
 CHECK(f->e.session_id == 991 && f->request.session_id == 0);
 CHECK(f->l.nr == 3 && f->l.calls[0] == C_RING && f->l.calls[1] == C_EVENT);
 CHECK(f->l.calls[2] == XDEV_EXT_MECH_OP_CREATE);
 CHECK(f->l.count[XDEV_EXT_MECH_OP_START] == 0);
}
static void start_ok(struct fixture *f)
{
 open_ok(f);
 CHECK(tb_epoch_start(&f->e, 3, 17) == 0);
 CHECK(f->e.start_accepted);
 CHECK(f->l.calls[3] == XDEV_EXT_MECH_OP_NOTIFY_ARM);
 CHECK(f->l.calls[4] == XDEV_EXT_MECH_OP_START);
}
static void held_no_reclaim(struct fixture *f)
{
 struct tb_guard_snapshot s = {0};
 struct tb_epoch_result r = {0};
 unsigned int nr = f->l.nr;
 uint64_t ticket = 0;
 tb_guard_snapshot(f->g, &s);
 CHECK(s.held && s.phase == TB_PHASE_HELD && s.cleanup_permissions == 0);
 CHECK(f->e.fate == TB_EPOCH_HELD);
 CHECK(tb_guard_cleanup_permissions(f->g) == 0);
 CHECK(tb_epoch_stop(&f->e, f->l.absolute_deadline, &r) == -EPERM);
 CHECK(tb_epoch_close(&f->e) == -EPERM);
 CHECK(tb_epoch_start(&f->e, 3, 17) < 0);
 CHECK(tb_epoch_open(&f->e, &f->request) < 0);
 CHECK(tb_guard_begin(f->g, TB_OP_GPU_FILL, &ticket) == -EPERM);
 CHECK(tb_guard_begin(f->g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
 CHECK(tb_guard_delete(f->g) == -EPERM);
 CHECK(f->l.nr == nr && f->l.closes == 0);
 CHECK(f->e.ring_fd == 41 && f->e.event_fd == 42);
}
static void stop_close(struct fixture *f)
{
 struct tb_epoch_result r = {0};
 unsigned int stops;
 CHECK(tb_epoch_stop(&f->e, f->l.absolute_deadline, &r) == 0);
 CHECK(r.stop_proved && f->e.stop_proved);
 CHECK(r.stop_error == 0 && f->e.stop_error == 0);
 CHECK(r.fate == (r.first_error ? TB_EPOCH_FAILED_SAFE : TB_EPOCH_SAFE));
 stops = f->l.stop_calls;
 CHECK(tb_epoch_stop(&f->e, f->l.absolute_deadline, &r) == 0);
 CHECK(f->l.stop_calls == stops);
 CHECK(tb_epoch_close(&f->e) == 0);
 CHECK(f->l.closes == 2 && f->e.ring_fd == -1 && f->e.event_fd == -1);
 CHECK(tb_epoch_close(&f->e) == 0);
 CHECK(f->l.closes == 2 && f->l.stop_calls == stops);
 CHECK(tb_guard_delete(f->g) == 0);
}
static void prevalidate(void)
{
 struct fixture f;
 fixture_init(&f);
 f.request.nr_stages = 0;
 CHECK(tb_epoch_open(&f.e, &f.request) < 0);
 CHECK(f.e.fate == TB_EPOCH_FAILED_SAFE && f.e.first_error < 0);
 CHECK(f.l.nr == 0 && !f.e.created);
 CHECK(tb_epoch_close(&f.e) == 0);
 CHECK(tb_guard_delete(f.g) == 0);
}
static void create_failure(int error, bool output)
{
 struct fixture f;
 fixture_init(&f);
 f.l.create_error = error;
 f.l.output_id_on_failure = output;
 CHECK(tb_epoch_open(&f.e, &f.request) == error);
 CHECK(f.e.first_error == error && f.e.stop_error == 0);
 CHECK(!f.e.created && f.l.observed_create_attempt);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_CREATE] == 1);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == 0 && f.l.stop_calls == 0);
 CHECK(f.e.session_id == (output ? 991U : 0U));
 CHECK(f.request.session_id == 0);
 held_no_reclaim(&f);
}
static void start_failure(bool arm)
{
 struct fixture f;
 fixture_init(&f);
 open_ok(&f);
 if (arm) f.l.arm_error = -EIO; else f.l.start_error = -EAGAIN;
 CHECK(tb_epoch_start(&f.e, 3, 17) == (arm ? -EIO : -EAGAIN));
 CHECK(f.e.first_error == (arm ? -EIO : -EAGAIN));
 CHECK(!f.e.start_accepted && f.e.fate == TB_EPOCH_ACTIVE);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_NOTIFY_ARM] == 1);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == (arm ? 0U : 1U));
 CHECK(tb_epoch_start(&f.e, 3, 17) < 0);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_NOTIFY_ARM] == 1);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == (arm ? 0U : 1U));
 stop_close(&f);
}
static void accepted_once(void)
{
 struct fixture f;
 fixture_init(&f);
 start_ok(&f);
 CHECK(tb_epoch_start(&f.e, 3, 17) < 0);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == 1);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_NOTIFY_ARM] == 1);
 /* Refusing a duplicate does not revoke already accepted native custody. */
 CHECK(f.e.fate == TB_EPOCH_ACTIVE);
 stop_close(&f);
}
static void stop_eagain(void)
{
 struct fixture f;
 fixture_init(&f);
 start_ok(&f);
 f.l.stop_eagain = 2;
 stop_close(&f);
 CHECK(f.l.stop_calls == 3 && f.l.now < f.l.absolute_deadline);
}
static void stop_failure(int error, bool prior_error)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 fixture_init(&f);
 open_ok(&f);
 if (prior_error) {
  f.l.arm_error = -EIO;
  CHECK(tb_epoch_start(&f.e, 3, 17) == -EIO);
 }
 f.l.stop_error = error;
 CHECK(tb_epoch_stop(&f.e, f.l.absolute_deadline, &r) == error);
 CHECK(f.e.stop_error == error && r.stop_error == error);
 if (prior_error) CHECK(f.e.first_error == -EIO && r.first_error == -EIO);
 CHECK(f.l.stop_calls == 1 && !f.e.stop_proved);
 held_no_reclaim(&f);
}
static void terminal_inflight(bool call_wait)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 struct tb_guard_snapshot s = {0};
 fixture_init(&f);
 start_ok(&f);
 f.l.inflight_forever = true;
 if (call_wait) {
  CHECK(tb_epoch_wait(&f.e, f.l.absolute_deadline, &r) < 0);
  CHECK(f.l.now == f.l.absolute_deadline);
  CHECK(f.l.polls >= 2 && f.l.reads == 1 && f.l.snapshots >= 2);
  CHECK(f.l.stop_calls == 0);
  tb_guard_snapshot(f.g, &s);
  CHECK(s.hold_reasons & TB_HOLD_DEADLINE);
  held_no_reclaim(&f);
 } else {
  CHECK(tb_epoch_snapshot(&f.e, &r) == 0);
  CHECK(r.stats_valid && r.transport_valid && r.stats.inflight == 1);
  CHECK(!r.stop_proved && f.e.fate == TB_EPOCH_ACTIVE);
  CHECK(tb_guard_cleanup_permissions(f.g) == 0);
  CHECK(tb_epoch_close(&f.e) == -EPERM && f.l.closes == 0);
  stop_close(&f);
 }
}
static void controls_settle(void)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 fixture_init(&f);
 start_ok(&f);
 f.l.controls_settle = true;
 CHECK(tb_epoch_wait(&f.e, f.l.absolute_deadline, &r) == 0);
 CHECK(f.l.reads == 1 && f.l.polls >= 2 && f.l.snapshots >= 2);
 CHECK(f.l.now < f.l.absolute_deadline);
 CHECK(r.first_error == 0 && f.e.first_error == 0);
 CHECK(r.stats_valid && r.transport_valid && !r.stop_proved);
 CHECK(r.transport.v3.v2.v1.native_controls == 0);
 CHECK(r.transport.v3.v2.v1.pending_acks == 0);
 CHECK(r.transport.v3.v2.v1.uncertain_controls == 0);
 CHECK(tb_guard_cleanup_permissions(f.g) == 0);
 CHECK(tb_epoch_close(&f.e) == -EPERM && f.l.closes == 0);
 stop_close(&f);
}
static void semantic_error(unsigned int kind)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 struct tb_guard_snapshot s = {0};
 int error;
 fixture_init(&f);
 start_ok(&f);
 switch (kind) {
 case 0: f.l.abort_batch = true; break;
 case 1: f.l.reject_batch = true; break;
 case 2: f.l.protocol_error = true; break;
 case 3: f.l.timeout_batch = true; break;
 case 4: f.l.sequester_batch = true; break;
 case 5: f.l.last_error = true; break;
 case 6: f.l.wrong_session = true; break;
 case 7: f.l.overdone = true; break;
 case 8: f.l.stats_error = -EIO; break;
 case 9: f.l.transport_error = -EIO; break;
 case 10: f.l.poll_error = -EIO; break;
 case 11: f.l.read_error = -EIO; break;
 default: f.l.wrong_transport_session = true; break;
 }
 error = tb_epoch_wait(&f.e, f.l.absolute_deadline, &r);
 CHECK(error < 0 && f.e.first_error == error && r.first_error == error);
 CHECK(f.l.now < f.l.absolute_deadline);
 tb_guard_snapshot(f.g, &s);
 CHECK(!s.held && f.e.fate == TB_EPOCH_ACTIVE && !r.stop_proved);
 CHECK(f.l.stop_calls == 0 && f.l.closes == 0);
 if (kind == 8) CHECK(!r.stats_valid);
 if (kind == 9) CHECK(!r.transport_valid);
 stop_close(&f);
}
static void transport_invalid(bool version)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 fixture_init(&f);
 start_ok(&f);
 f.l.bad_version = version;
 f.l.bad_size = !version;
 CHECK(tb_epoch_wait(&f.e, f.l.absolute_deadline, &r) < 0);
 CHECK(!r.transport_valid && f.e.first_error < 0);
 stop_close(&f);
}
static void groups_invalid(uint64_t groups, uint64_t first)
{
 struct fixture f;
 fixture_init(&f);
 open_ok(&f);
 CHECK(tb_epoch_start(&f.e, groups, first) < 0);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_NOTIFY_ARM] == 0);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == 0);
 CHECK(f.e.fate == TB_EPOCH_ACTIVE);
 stop_close(&f);
}
static void poll_eintr_deadline(void)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 fixture_init(&f);
 start_ok(&f);
 f.l.poll_eintr = 1;
 f.l.no_event = true;
 CHECK(tb_epoch_wait(&f.e, f.l.absolute_deadline, &r) < 0);
 CHECK(f.l.now == f.l.absolute_deadline && f.l.polls >= 3);
 CHECK(f.l.reads == 0 && f.l.stop_calls == 0);
 held_no_reclaim(&f);
}
static void stop_retry_deadline(void)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 fixture_init(&f);
 start_ok(&f);
 f.l.stop_eagain = 100;
 CHECK(tb_epoch_stop(&f.e, f.l.absolute_deadline, &r) < 0);
 CHECK(f.l.now >= f.l.absolute_deadline);
 CHECK(f.l.stop_calls > 1 && !r.stop_proved && r.stop_error < 0);
 held_no_reclaim(&f);
}
static void create_late_hold(void)
{
 struct fixture f;
 fixture_init(&f);
 f.l.hold_during_create = true;
 CHECK(tb_epoch_open(&f.e, &f.request) < 0);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_CREATE] == 1);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == 0);
 held_no_reclaim(&f);
}
static void held_no_stop(void)
{
 struct fixture f;
 fixture_init(&f);
 start_ok(&f);
 tb_guard_hold(f.g, TB_HOLD_EOF);
 /* Snapshot may observe HELD but must never use STATS as release proof. */
 {
  struct tb_epoch_result r = {0};
  (void)tb_epoch_snapshot(&f.e, &r);
 }
 held_no_reclaim(&f);
 CHECK(f.l.stop_calls == 0);
}
static void snapshot_validity_reset(void)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 fixture_init(&f);
 start_ok(&f);
 CHECK(tb_epoch_snapshot(&f.e, &r) == 0);
 CHECK(r.stats_valid && r.transport_valid);
 f.l.stats_error = -EIO;
 CHECK(tb_epoch_snapshot(&f.e, &r) == -EIO);
 CHECK(!r.stats_valid);
 f.l.stats_error = 0;
 f.l.transport_error = -EIO;
 CHECK(tb_epoch_snapshot(&f.e, &r) == -EIO);
 CHECK(!r.transport_valid);
 stop_close(&f);
}

static int guarded_fd_close(void *opaque, int fd)
{
 struct ledger *l = opaque;
 uint64_t competing_ticket = 0;
 /* Reentrant admission must fail while controller owns EPOCH_CLOSE. This
  * catches a permission-only close that bypasses the shared begin gate. */
 CHECK(tb_guard_begin(l->guard, TB_OP_EPOCH_CLOSE, &competing_ticket) < 0);
 return fd_close(opaque, fd);
}
static void pristine_close(bool gpu)
{
 struct fixture f;
 struct tb_guard_snapshot before = {0}, after = {0};
 uint64_t ticket = 0;
 fixture_init(&f);
 if (gpu) {
  CHECK(tb_guard_delete(f.g) == 0);
  CHECK(tb_guard_new(TB_BACKING_GPU, &f.g) == 0);
  f.e.guard = f.g;
  f.l.guard = f.g;
  CHECK(tb_guard_begin(f.g, TB_OP_GPU_OPEN, &ticket) == 0);
  CHECK(tb_guard_end(f.g, ticket, TB_PHASE_GPU_READY, true, true) == 0);
 }
 tb_guard_snapshot(f.g, &before);
 CHECK(before.phase == (gpu ? TB_PHASE_GPU_READY : TB_PHASE_EXTERNAL_READY));
 CHECK(before.cleanup_permissions & TB_CLEANUP_EPOCH_FDS);
 /* Model already-created empty authority fds, before any CREATE attempt. */
 f.e.ring_fd = ring_setup(&f.l);
 f.e.event_fd = event_open(&f.l);
 f.e.io.fd_close = guarded_fd_close;
 CHECK(tb_epoch_close(&f.e) == 0);
 CHECK(f.e.ring_fd == -1 && f.e.event_fd == -1 && f.l.closes == 2);
 CHECK(tb_epoch_close(&f.e) == 0 && f.l.closes == 2);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_CREATE] == 0);
 CHECK(f.l.count[XDEV_EXT_MECH_OP_START] == 0 && f.l.stop_calls == 0);
 CHECK(f.l.count[C_CLOSE_RING] == 1 && f.l.count[C_CLOSE_EVENT] == 1);
 tb_guard_snapshot(f.g, &after);
 CHECK(after.phase == before.phase && !after.held);
 CHECK(after.cleanup_permissions == before.cleanup_permissions);
 CHECK(f.request.pool_fd == 73);
 CHECK(tb_guard_delete(f.g) == 0);
}
enum overdue_return { LATE_POLL, LATE_READ, LATE_STATS, LATE_TRANSPORT };
static enum overdue_return overdue_stage;
static int overdue_poll(void *opaque, int fd, uint64_t deadline)
{
 struct ledger *l = opaque;
 int ret = poll_event(opaque, fd, deadline);
 if (ret == 1 && overdue_stage == LATE_POLL)
  l->now = l->absolute_deadline + 1;
 return ret;
}
static int overdue_read(void *opaque, int fd, uint64_t *value)
{
 struct ledger *l = opaque;
 int ret = event_read(opaque, fd, value);
 if (!ret && overdue_stage == LATE_READ)
  l->now = l->absolute_deadline + 1;
 return ret;
}
static int overdue_mech(void *opaque, int fd, uint32_t op, void *arg)
{
 struct ledger *l = opaque;
 int ret = mech(opaque, fd, op, arg);
 if (!ret && ((op == XDEV_EXT_MECH_OP_STATS && overdue_stage == LATE_STATS) ||
              (op == XDEV_EXT_MECH_OP_TRANSPORT_STATS && overdue_stage == LATE_TRANSPORT)))
  l->now = l->absolute_deadline + 1;
 return ret;
}
static void completion_after_deadline(enum overdue_return stage)
{
 struct fixture f;
 struct tb_epoch_result r = {0};
 struct tb_guard_snapshot s = {0};
 int ret;
 fixture_init(&f);
 start_ok(&f);
 overdue_stage = stage;
 f.e.io.poll_event = overdue_poll;
 f.e.io.event_read = overdue_read;
 f.e.io.mech = overdue_mech;
 ret = tb_epoch_wait(&f.e, f.l.absolute_deadline, &r);
 tb_guard_snapshot(f.g, &s);
 printf("late_stage=%u wait_rc=%d now=%" PRIu64 " deadline=%" PRIu64
        " held=%d reads=%u stats=%u transport=%u\n", (unsigned int)stage,
        ret, f.l.now, f.l.absolute_deadline, s.held, f.l.reads,
        f.l.count[XDEV_EXT_MECH_OP_STATS], f.l.count[XDEV_EXT_MECH_OP_TRANSPORT_STATS]);
 CHECK(ret < 0);
 CHECK(s.held && (s.hold_reasons & TB_HOLD_DEADLINE));
 CHECK(r.fate == TB_EPOCH_HELD && r.first_error < 0 && !r.stop_proved);
 CHECK(f.l.now > f.l.absolute_deadline);
 if (stage == LATE_POLL) CHECK(f.l.reads == 0);
 if (stage <= LATE_READ) CHECK(f.l.count[XDEV_EXT_MECH_OP_STATS] == 0);
 if (stage <= LATE_STATS) CHECK(f.l.count[XDEV_EXT_MECH_OP_TRANSPORT_STATS] == 0);
 held_no_reclaim(&f);
}
struct admission_ledger {
 struct fixture f;
 unsigned int rings, events, closed;
 int allocations[16], closed_fds[16];
 unsigned int allocated;
 unsigned int ring_attempts, event_attempts;
 bool fail_ring, fail_event, require_close_gate;
};
static int admission_ring(void *opaque)
{
 struct admission_ledger *a = opaque;
 int fd = 100 + (int)++a->rings;
 CHECK(a->allocated < 16);
 a->allocations[a->allocated++] = fd;
 return fd;
}
static int admission_event(void *opaque)
{
 struct admission_ledger *a = opaque;
 int fd = 200 + (int)++a->events;
 CHECK(a->allocated < 16);
 a->allocations[a->allocated++] = fd;
 return fd;
}
static int admission_mech(void *opaque, int fd, uint32_t op, void *arg)
{
 struct admission_ledger *a = opaque;
 record(&a->f.l, op);
 CHECK(fd == 100 + (int)a->rings);
 if (op == XDEV_EXT_MECH_OP_CREATE) {
  struct xdev_ext_mech_create *c = arg;
  struct tb_guard_snapshot s = {0};
  tb_guard_snapshot(a->f.g, &s);
  CHECK(s.phase == TB_PHASE_CREATE_ATTEMPTED && !s.native_safe);
  CHECK(c != &a->f.request && c->pool_fd == 73);
  CHECK(c->eventfd == 200 + (int)a->events);
  c->session_id = 991;
  return 0;
 }
 CHECK(op == XDEV_EXT_MECH_OP_STOP_REPORT);
 a->f.l.stop_calls++;
 returned_stop_report(&a->f.l, arg);
 return 0;
}
static uint64_t admission_now(void *opaque)
{
 struct admission_ledger *a = opaque;
 return a->f.l.now;
}
static int admission_close(void *opaque, int fd)
{
 struct admission_ledger *a = opaque;
 bool allocated = false;
 uint64_t competing_ticket = 0;
 CHECK(fd != 73 && a->closed < 16);
 if (a->require_close_gate)
  CHECK(tb_guard_begin(a->f.g, TB_OP_EPOCH_CLOSE, &competing_ticket) < 0);
 for (unsigned int i = 0; i < a->allocated; i++)
  if (a->allocations[i] == fd) allocated = true;
 CHECK(allocated);
 for (unsigned int i = 0; i < a->closed; i++) CHECK(a->closed_fds[i] != fd);
 a->closed_fds[a->closed++] = fd;
 return 0;
}
static void denied_create_retry_no_fd_loss(void)
{
 struct admission_ledger a = {0};
 struct tb_epoch_result r = {0};
 uint64_t ticket = 0;
 int first_open, first_ring, first_event;
 unsigned int denied_allocations;
 fixture_init(&a.f);
 CHECK(tb_guard_delete(a.f.g) == 0);
 CHECK(tb_guard_new(TB_BACKING_GPU, &a.f.g) == 0);
 a.f.e.guard = a.f.g;
 a.f.l.guard = a.f.g;
 CHECK(tb_guard_begin(a.f.g, TB_OP_GPU_OPEN, &ticket) == 0);
 CHECK(tb_guard_end(a.f.g, ticket, TB_PHASE_GPU_READY, true, true) == 0);
 a.f.e.io.opaque = &a;
 a.f.e.io.ring_setup = admission_ring;
 a.f.e.io.event_open = admission_event;
 a.f.e.io.mech = admission_mech;
 a.f.e.io.now_ns = admission_now;
 a.f.e.io.fd_close = admission_close;
 first_open = tb_epoch_open(&a.f.e, &a.f.request);
 CHECK(first_open == -EPERM);
 denied_allocations = a.allocated;
 first_ring = a.f.e.ring_fd;
 first_event = a.f.e.event_fd;
 CHECK(a.f.l.count[XDEV_EXT_MECH_OP_CREATE] == 0);
 CHECK(tb_guard_begin(a.f.g, TB_OP_GPU_FILL, &ticket) == 0);
 CHECK(tb_guard_end(a.f.g, ticket, TB_PHASE_GPU_READY, true, true) == 0);
 CHECK(tb_epoch_open(&a.f.e, &a.f.request) == 0);
 CHECK(tb_epoch_stop(&a.f.e, a.f.l.absolute_deadline, &r) == 0);
 CHECK(tb_epoch_close(&a.f.e) == 0);
 printf("denied_allocations=%u first_ring=%d first_event=%d final_allocated=%u closed=%u\n",
        denied_allocations, first_ring, first_event, a.allocated, a.closed);
 CHECK(denied_allocations == 0 && first_ring == -1 && first_event == -1);
 CHECK(a.allocated == 2 && a.closed == a.allocated);
 CHECK(a.rings == 1 && a.events == 1);
 CHECK(a.f.l.count[XDEV_EXT_MECH_OP_CREATE] == 1);
 CHECK(a.f.l.count[XDEV_EXT_MECH_OP_START] == 0 && a.f.l.stop_calls == 1);
 CHECK(a.f.e.ring_fd == -1 && a.f.e.event_fd == -1);
 CHECK(tb_guard_pair_stopped(a.f.g) == 0);
 CHECK(tb_guard_delete(a.f.g) == 0);
}
static int allocation_ring(void *opaque)
{
 struct admission_ledger *a = opaque;
 a->ring_attempts++;
 return a->fail_ring ? -EMFILE : admission_ring(opaque);
}
static int allocation_event(void *opaque)
{
 struct admission_ledger *a = opaque;
 a->event_attempts++;
 return a->fail_event ? -ENOMEM : admission_event(opaque);
}
static void local_allocation_failure(bool ring)
{
 struct admission_ledger a = {0};
 struct tb_guard_snapshot s = {0};
 int error = ring ? -EMFILE : -ENOMEM;
 fixture_init(&a.f);
 a.fail_ring = ring;
 a.fail_event = !ring;
 a.require_close_gate = true;
 a.f.e.io.opaque = &a;
 a.f.e.io.ring_setup = allocation_ring;
 a.f.e.io.event_open = allocation_event;
 a.f.e.io.mech = admission_mech;
 a.f.e.io.now_ns = admission_now;
 a.f.e.io.fd_close = admission_close;
 CHECK(tb_epoch_open(&a.f.e, &a.f.request) == error);
 tb_guard_snapshot(a.f.g, &s);
 printf("allocation_failure=%s fate=%d phase=%d first_error=%d held=%d allocated=%u closed=%u\n",
        ring ? "ring" : "event", a.f.e.fate, s.phase, a.f.e.first_error,
        s.held, a.allocated, a.closed);
 CHECK(a.f.e.fate == TB_EPOCH_FAILED_SAFE && a.f.e.first_error == error);
 CHECK(s.phase == TB_PHASE_FAILED_SAFE && !s.held && s.native_safe && s.gpu_safe);
 CHECK(s.cleanup_permissions & TB_CLEANUP_EPOCH_FDS);
 CHECK(!s.pair_stop_proved && !a.f.e.created && !a.f.e.stop_proved);
 CHECK(a.f.l.count[XDEV_EXT_MECH_OP_CREATE] == 0 && a.f.l.stop_calls == 0);
 CHECK(a.f.l.count[XDEV_EXT_MECH_OP_START] == 0);
 CHECK(a.ring_attempts == 1 && a.event_attempts == (ring ? 0U : 1U));
 CHECK(tb_epoch_close(&a.f.e) == 0);
 CHECK(a.allocated == (ring ? 0U : 1U) && a.closed == a.allocated);
 CHECK(a.f.e.ring_fd == -1 && a.f.e.event_fd == -1);
 CHECK(tb_epoch_close(&a.f.e) == 0 && a.closed == a.allocated);
 CHECK(tb_guard_delete(a.f.g) == 0);
}
static const char *const names[] = {
 "prevalidate-no-create", "create-bind-uncertain", "create-output-id-then-fail",
 "create-eintr-unknown", "create-ebusy-no-retry", "arm-fail-stop-zero",
 "start-eagain-no-retry", "accepted-start-once", "stop-eagain-zero",
 "stop-ebusy-held", "stop-enoent-held", "terminal-inflight-not-safe",
 "done-event-controls-one-then-zero-no-second-event",
 "terminal-inflight-never-settles-deadline-held", "aborted-not-positive",
 "transport-version-size-invalid", "groups-zero-overflow", "poll-eintr-deadline",
 "held-no-stop-reclaim", "first-error-stop-error-independent",
 "stop-eagain-absolute-deadline", "semantic-counter-errors-stop-safe",
 "snapshot-failure-not-zero-valid", "late-create-success-held",
 "poll-read-error-can-stop", "snapshot-validity-reset",
 "transport-session-mismatch-not-positive", "pristine-gpu-ready-epoch-close-common-gate",
 "pristine-external-ready-epoch-close-common-gate",
 "late-poll-success-deadline-held", "late-event-read-success-deadline-held",
 "late-stats-success-deadline-held", "late-transport-success-deadline-held",
 "create-admission-denied-no-fd-allocation-or-retry-loss",
 "ring-allocation-failure-precreate-safe-common-cleanup",
 "event-allocation-failure-precreate-safe-common-cleanup"
};
int main(int argc, char **argv)
{
 size_t i;
 if (argc == 2 && !strcmp(argv[1], "--list")) {
  for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) puts(names[i]);
  return 0;
 }
 CHECK(argc == 2);
 for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
  if (!strcmp(argv[1], names[i])) break;
 CHECK(i < sizeof(names) / sizeof(names[0]));
 switch (i) {
 case 0: prevalidate(); break;
 case 1: create_failure(-EINVAL, false); break;
 case 2: create_failure(-EIO, true); break;
 case 3: create_failure(-EINTR, false); break;
 case 4: create_failure(-EBUSY, false); break;
 case 5: start_failure(true); break;
 case 6: start_failure(false); break;
 case 7: accepted_once(); break;
 case 8: stop_eagain(); break;
 case 9: stop_failure(-EBUSY, false); break;
 case 10: stop_failure(-ENOENT, false); break;
 case 11: terminal_inflight(false); break;
 case 12: controls_settle(); break;
 case 13: terminal_inflight(true); break;
 case 14: semantic_error(0); break;
 case 15: transport_invalid(false); transport_invalid(true); break;
 case 16:
  groups_invalid(0, 0); groups_invalid(10001, 0); groups_invalid(3, UINT64_MAX - 1);
  break;
 case 17: poll_eintr_deadline(); break;
 case 18: held_no_stop(); break;
 case 19: stop_failure(-EBUSY, true); break;
 case 20: stop_retry_deadline(); break;
 case 21: for (unsigned int k = 1; k <= 7; k++) semantic_error(k); break;
 case 22: semantic_error(8); semantic_error(9); break;
 case 23: create_late_hold(); break;
 case 24: semantic_error(10); semantic_error(11); break;
 case 25: snapshot_validity_reset(); break;
 case 26: semantic_error(12); break;
 case 27: pristine_close(true); break;
 case 28: pristine_close(false); break;
 case 29: completion_after_deadline(LATE_POLL); break;
 case 30: completion_after_deadline(LATE_READ); break;
 case 31: completion_after_deadline(LATE_STATS); break;
 case 32: completion_after_deadline(LATE_TRANSPORT); break;
 case 33: denied_create_retry_no_fd_loss(); break;
 case 34: local_allocation_failure(true); break;
 case 35: local_allocation_failure(false); break;
 default: CHECK(0);
 }
 printf("ok - %s\n", argv[1]);
 return 0;
}
