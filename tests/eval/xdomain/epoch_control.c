/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "epoch_control.h"
#include <errno.h>
#include <limits.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define TB_SLICE_NS 20000000ULL
static uint64_t real_now(void *opaque)
{
 struct timespec ts;
 (void)opaque;
 if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
 return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static int real_ring(void *opaque)
{
 struct io_uring_params p = {0};
 int rc;
 (void)opaque;
 rc = (int)syscall(__NR_io_uring_setup, 8, &p);
 return rc < 0 ? -errno : rc;
}
static int real_event(void *opaque)
{
 int rc;
 (void)opaque;
 rc = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
 return rc < 0 ? -errno : rc;
}
static int real_mech(void *opaque, int fd, uint32_t op, void *arg)
{
 struct io_uring_xdev_ext_mech r = {.op = op, .arg = (uintptr_t)arg};
 int rc;
 (void)opaque;
 rc = (int)syscall(__NR_io_uring_register, fd, IORING_REGISTER_XDEV_EXT_MECH, &r, 1);
 return rc < 0 ? -errno : rc;
}
static int real_poll(void *opaque, int fd, uint64_t deadline)
{
 struct pollfd p = {.fd = fd, .events = POLLIN};
 uint64_t now = real_now(opaque), remain;
 int ms, rc;
 if (now >= deadline) return 0;
 remain = deadline - now;
 ms = remain / 1000000ULL >= INT_MAX ? INT_MAX :
      (int)(remain / 1000000ULL + (remain % 1000000ULL != 0));
 rc = poll(&p, 1, ms);
 if (rc < 0) return -errno;
 if (!rc) return 0;
 if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return -EIO;
 return p.revents & POLLIN ? 1 : -EIO;
}
static int real_read(void *opaque, int fd, uint64_t *value)
{
 ssize_t rc;
 (void)opaque;
 rc = read(fd, value, sizeof(*value));
 return rc < 0 ? -errno : rc == sizeof(*value) ? 0 : -EIO;
}
static int real_close(void *opaque, int fd)
{
 (void)opaque;
 return close(fd) < 0 ? -errno : 0;
}
static const struct tb_epoch_io real_io = {
 .ring_setup = real_ring, .event_open = real_event, .mech = real_mech,
 .poll_event = real_poll, .event_read = real_read, .now_ns = real_now,
 .fd_close = real_close
};
static void remember(struct tb_epoch *e, int rc)
{
 if (rc && !e->first_error) e->first_error = rc;
}
static void result_meta(const struct tb_epoch *e, struct tb_epoch_result *r)
{
 r->fate = e->fate; r->first_error = e->first_error;
 r->stop_error = e->stop_error; r->start_accepted = e->start_accepted;
 r->stop_proved = e->stop_proved;
}
static bool held(struct tb_epoch *e)
{
 struct tb_guard_snapshot s;
 tb_guard_snapshot(e->guard, &s);
 if (s.held) e->fate = TB_EPOCH_HELD;
 return s.held;
}
static int hold(struct tb_epoch *e, int rc, uint32_t reason)
{
 remember(e, rc); tb_guard_hold(e->guard, reason); e->fate = TB_EPOCH_HELD;
 return rc;
}
static uint64_t slice(struct tb_epoch *e, uint64_t deadline)
{
 uint64_t now = e->io.now_ns(e->io.opaque);
 return now < deadline && deadline - now > TB_SLICE_NS ? now + TB_SLICE_NS : deadline;
}
int tb_epoch_init(struct tb_epoch *e, struct tb_guard *g, const struct tb_epoch_io *io)
{
 if (!e || !g) return -EINVAL;
 if (io && (!io->ring_setup || !io->event_open || !io->mech ||
            !io->poll_event || !io->event_read || !io->now_ns || !io->fd_close))
  return -EINVAL;
 memset(e, 0, sizeof(*e)); e->guard = g; e->io = io ? *io : real_io;
 e->ring_fd = e->event_fd = -1; e->fate = TB_EPOCH_EMPTY;
 return 0;
}
static int validate_create(const struct xdev_ext_mech_create *c)
{
 uint64_t frames;
 if (!c || (c->abi_version != XDEV_EXT_MECH_ABI_VERSION &&
            c->abi_version != XDEV_EXT_CE_MECH_ABI_VERSION) ||
     !c->nr_stages || c->nr_stages > XDEV_EXT_MECH_MAX_STAGES ||
     !c->depth || !c->layout.frame_size || !c->layout.seg_len ||
     !c->layout.group_bytes || c->layout.hdr_room > c->layout.frame_size ||
     c->layout.seg_len > c->layout.frame_size - c->layout.hdr_room ||
     c->pool_kind < XDEV_EXT_MECH_POOL_XSK || c->pool_kind > XDEV_EXT_MECH_POOL_PEER ||
     (c->pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM && c->pool_fd < 0))
  return -EINVAL;
 frames = ((uint64_t)c->layout.group_bytes + c->layout.seg_len - 1) / c->layout.seg_len;
 return frames > XDEV_EXT_MECH_MAX_FRAMES ? -EINVAL : 0;
}
int tb_epoch_open(struct tb_epoch *e, const struct xdev_ext_mech_create *input)
{
 struct xdev_ext_mech_create c;
 uint64_t ticket;
 int rc;
 if (!e || !e->guard) return -EINVAL;
 if (held(e) || e->fate != TB_EPOCH_EMPTY) return -EPERM;
 rc = validate_create(input);
 if (rc) { remember(e, rc); e->fate = TB_EPOCH_FAILED_SAFE; return rc; }
 /* Admission precedes even local fd acquisition: a denied retry owns nothing. */
 rc = tb_guard_begin(e->guard, TB_OP_CREATE, &ticket);
 if (rc) return rc;
 e->ring_fd = e->io.ring_setup(e->io.opaque);
 if (e->ring_fd < 0) {
  rc = e->ring_fd; e->ring_fd = -1;
  goto local_failure;
 }
 e->event_fd = e->io.event_open(e->io.opaque);
 if (e->event_fd < 0) {
  rc = e->event_fd; e->event_fd = -1;
  goto local_failure;
 }
 if (held(e)) return -ECANCELED;
 c = *input; c.eventfd = e->event_fd;
 e->fate = TB_EPOCH_CREATE_ATTEMPTED;
 rc = e->io.mech(e->io.opaque, e->ring_fd, XDEV_EXT_MECH_OP_CREATE, &c);
 e->session_id = c.session_id;
 if (rc) return hold(e, rc, TB_HOLD_CREATE_UNKNOWN);
 e->created = true; e->nr_stages = c.nr_stages; e->fate = TB_EPOCH_ACTIVE;
 rc = tb_guard_end(e->guard, ticket, TB_PHASE_SESSION_CREATED, false, true);
 if (rc) { held(e); remember(e, rc); }
 return rc;
 local_failure:
 remember(e, rc);
 {
  struct tb_guard_snapshot before;
  int endrc;
  tb_guard_snapshot(e->guard, &before);
  endrc = tb_guard_end(e->guard, ticket, TB_PHASE_FAILED_SAFE, true, before.gpu_safe);
  e->fate = TB_EPOCH_FAILED_SAFE;
  if (endrc) { held(e); return endrc; }
 }
 return rc;
}
int tb_epoch_start(struct tb_epoch *e, uint64_t groups, uint64_t first_seq)
{
 struct xdev_ext_mech_notify_arm arm = {0};
 struct xdev_ext_mech_start start = {0};
 uint64_t ticket;
 int rc, endrc;
 if (!e || !e->guard) return -EINVAL;
 if (held(e) || !e->created || e->fate != TB_EPOCH_ACTIVE || e->arm_attempted)
  return -EPERM;
 if (!groups || groups > TB_MAX_GROUPS || first_seq > UINT64_MAX - (groups - 1)) {
  remember(e, -EINVAL); return -EINVAL;
 }
 rc = tb_guard_begin(e->guard, TB_OP_START, &ticket);
 if (rc) return rc;
 e->groups = groups; e->first_seq = first_seq;
 arm.session_id = e->session_id; arm.batches_target = groups;
 e->arm_attempted = true;
 rc = e->io.mech(e->io.opaque, e->ring_fd, XDEV_EXT_MECH_OP_NOTIFY_ARM, &arm);
 if (!rc && !held(e)) {
  start.session_id = e->session_id; start.nr_batches = groups; start.first_seq = first_seq;
  e->start_attempted = true;
  rc = e->io.mech(e->io.opaque, e->ring_fd, XDEV_EXT_MECH_OP_START, &start);
  if (!rc) e->start_accepted = true;
 }
 endrc = tb_guard_end(e->guard, ticket,
                       e->start_accepted ? TB_PHASE_START_ACCEPTED : TB_PHASE_SESSION_CREATED,
                       false, true);
 if (!rc) rc = endrc;
 remember(e, rc); held(e);
 return rc;
}
static int authorized_wait(struct tb_epoch *e, uint64_t deadline)
{
 if (held(e)) return -EPERM;
 if (e->io.now_ns(e->io.opaque) >= deadline)
  return hold(e, -ETIMEDOUT, TB_HOLD_DEADLINE);
 return 0;
}
static int snapshot_at(struct tb_epoch *e, struct tb_epoch_result *r,
                       bool bounded, uint64_t deadline)
{
 int rc, rc2;
 if (!e || !r || !e->guard) return -EINVAL;
 memset(r, 0, sizeof(*r)); held(e); result_meta(e, r);
 if (!e->created) return -EPERM;
 r->stats.session_id = e->session_id;
 rc = e->io.mech(e->io.opaque, e->ring_fd, XDEV_EXT_MECH_OP_STATS, &r->stats);
 if (!rc && r->stats.session_id != e->session_id) rc = -EPROTO;
 r->stats_valid = rc == 0;
 if (bounded) {
  int auth = authorized_wait(e, deadline);
  if (auth) { result_meta(e, r); return auth; }
 }
 r->transport.v3.v2.v1.size = sizeof(r->transport);
 r->transport.v3.v2.v1.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4;
 r->transport.v3.v2.v1.session_id = e->session_id;
 rc2 = e->io.mech(e->io.opaque, e->ring_fd, XDEV_EXT_MECH_OP_TRANSPORT_STATS, &r->transport);
 if (!rc2 && (r->transport.v3.v2.v1.size != sizeof(r->transport) ||
              r->transport.v3.v2.v1.version != XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4 ||
              r->transport.v3.v2.v1.session_id != e->session_id)) rc2 = -EPROTO;
 r->transport_valid = rc2 == 0;
 if (bounded) {
  int auth = authorized_wait(e, deadline);
  if (auth) { result_meta(e, r); return auth; }
 }
 if (!rc) rc = rc2;
 remember(e, rc); result_meta(e, r);
 return rc;
}
int tb_epoch_snapshot(struct tb_epoch *e, struct tb_epoch_result *r)
{
 return snapshot_at(e, r, false, 0);
}
static int semantic(const struct tb_epoch *e, const struct tb_epoch_result *r)
{
 const struct xdev_ext_mech_stats *s = &r->stats;
 if (s->last_err) return s->last_err < 0 ? s->last_err : -EIO;
 if (s->batches_abort || s->rejects || s->timeouts || s->protocol_err || s->sequestered)
  return -EIO;
 if (s->batches_done > e->groups) return -EPROTO;
 return 0;
}
static bool settled(const struct tb_epoch *e, const struct tb_epoch_result *r)
{
 const struct xdev_ext_mech_transport_stats *t = &r->transport.v3.v2.v1;
 return r->stats.batches_done == e->groups && !r->stats.inflight &&
        !t->native_controls && !t->pending_acks && !t->uncertain_controls;
}
int tb_epoch_wait(struct tb_epoch *e, uint64_t deadline, struct tb_epoch_result *r)
{
 uint64_t ticket, value;
 bool event_seen = false;
 int rc;
 if (!e || !e->guard || !r) return -EINVAL;
 memset(r, 0, sizeof(*r));
 if (held(e) || !e->start_accepted || e->fate != TB_EPOCH_ACTIVE) {
  result_meta(e, r); return -EPERM;
 }
 rc = tb_guard_begin(e->guard, TB_OP_WAIT, &ticket);
 if (rc) return rc;
 for (;;) {
  if (held(e)) { rc = -EPERM; break; }
  if (e->io.now_ns(e->io.opaque) >= deadline) {
   rc = hold(e, -ETIMEDOUT, TB_HOLD_DEADLINE); break;
  }
  rc = e->io.poll_event(e->io.opaque, e->event_fd, slice(e, deadline));
  {
   int auth = authorized_wait(e, deadline);
   if (auth) { rc = auth; break; }
  }
  if (rc == -EINTR) continue;
  if (rc < 0) break;
  if (rc > 0) {
   rc = e->io.event_read(e->io.opaque, e->event_fd, &value);
   {
    int auth = authorized_wait(e, deadline);
    if (auth) { rc = auth; break; }
   }
   if (rc == -EINTR || rc == -EAGAIN) continue;
   if (rc) break;
   if (!value) { rc = -EPROTO; break; }
   event_seen = true;
  }
  rc = snapshot_at(e, r, true, deadline);
  if (rc) break;
  rc = semantic(e, r);
  if (rc) break;
  if (event_seen && settled(e, r)) {
   rc = tb_guard_end(e->guard, ticket, TB_PHASE_TRANSPORT_DONE, false, true);
   held(e); result_meta(e, r); return rc;
  }
 }
 remember(e, rc);
 if (!held(e)) {
  int endrc = tb_guard_end(e->guard, ticket, TB_PHASE_START_ACCEPTED, false, true);
  if (!rc) rc = endrc;
 }
 result_meta(e, r);
 return rc;
}
int tb_epoch_stop(struct tb_epoch *e, uint64_t deadline, struct tb_epoch_result *r)
{
 uint64_t ticket;
 int rc;
 if (!e || !e->guard || !r) return -EINVAL;
 if (held(e)) { result_meta(e, r); return -EPERM; }
 if (e->stop_proved) { result_meta(e, r); return 0; }
 if (!e->created || e->fate != TB_EPOCH_ACTIVE) { result_meta(e, r); return -EPERM; }
 rc = tb_guard_begin(e->guard, TB_OP_STOP, &ticket);
 if (rc) { result_meta(e, r); return rc; }
 for (;;) {
  if (held(e)) { rc = -EPERM; break; }
  if (e->io.now_ns(e->io.opaque) >= deadline) { rc = -ETIMEDOUT; break; }
  rc = e->io.mech(e->io.opaque, e->ring_fd, XDEV_EXT_MECH_OP_STOP,
                   (void *)(uintptr_t)e->session_id);
  if (rc != -EAGAIN) break;
  if (held(e)) { rc = -EPERM; break; }
  if (e->io.now_ns(e->io.opaque) >= deadline) { rc = -ETIMEDOUT; break; }
  rc = e->io.poll_event(e->io.opaque, e->event_fd, slice(e, deadline));
  if (rc == -EINTR) continue;
  if (rc < 0) break;
  if (rc > 0) {
   uint64_t ignored;
   rc = e->io.event_read(e->io.opaque, e->event_fd, &ignored);
   if (rc && rc != -EAGAIN && rc != -EINTR) break;
  }
 }
 if (!rc) {
  rc = tb_guard_end(e->guard, ticket, TB_PHASE_DRAINED_SAFE, true, true);
  if (!rc) {
   e->stop_proved = true;
   e->fate = e->first_error ? TB_EPOCH_FAILED_SAFE : TB_EPOCH_SAFE;
  }
 }
 if (rc) {
  e->stop_error = rc;
  hold(e, rc, rc == -ETIMEDOUT ? TB_HOLD_DEADLINE : TB_HOLD_STOP_UNKNOWN);
 }
 result_meta(e, r);
 return rc;
}
int tb_epoch_close(struct tb_epoch *e)
{
 uint64_t ticket;
 struct tb_guard_snapshot s;
 int rc = 0, err;
 if (!e || !e->guard) return -EINVAL;
 if (held(e)) return -EPERM;
 tb_guard_snapshot(e->guard, &s);
 if (!(s.cleanup_permissions & TB_CLEANUP_EPOCH_FDS)) return -EPERM;
 if (e->ring_fd < 0 && e->event_fd < 0) return 0;
 rc = tb_guard_begin(e->guard, TB_OP_EPOCH_CLOSE, &ticket);
 if (rc) return rc;
 if (e->event_fd >= 0) {
  int fd = e->event_fd; e->event_fd = -1;
  rc = e->io.fd_close(e->io.opaque, fd);
 }
 if (e->ring_fd >= 0) {
  int fd = e->ring_fd; e->ring_fd = -1;
  err = e->io.fd_close(e->io.opaque, fd); if (!rc) rc = err;
 }
 err = tb_guard_end(e->guard, ticket, s.phase, true, true); if (!rc) rc = err;
 remember(e, rc);
 return rc;
}
