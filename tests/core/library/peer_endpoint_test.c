// SPDX-License-Identifier: GPL-2.0
/* Independent endpoint contract: 2026-10-28 plan + root's frozen handoff.
 * No endpoint implementation was read. Real library objects and real fd/mmap
 * ownership are exercised; only kernel register/ioctl replies are injected.
 * This is host API evidence, never actual GPU/transport correctness.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#ifndef XDEV_EXT_ENDPOINT_CONTRACT
#define XDEV_EXT_ENDPOINT_CONTRACT "tools/xdev_ext_mech/lib/libxdev_ext_peer_message.h"
#endif
#include XDEV_EXT_ENDPOINT_CONTRACT
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"
#pragma weak xdev_ext_peer_endpoint_open
#pragma weak xdev_ext_peer_endpoint_create
#pragma weak xdev_ext_peer_endpoint_start
#pragma weak xdev_ext_peer_endpoint_next
#pragma weak xdev_ext_peer_endpoint_complete
#pragma weak xdev_ext_peer_endpoint_stop
#pragma weak xdev_ext_peer_endpoint_close
#pragma weak xdev_ext_peer_endpoint_session
#pragma weak xdev_ext_peer_endpoint_user
#pragma weak xdev_ext_user_stage_control
#pragma weak xdev_ext_user_stage_ctl_attach
#pragma weak xdev_ext_user_stage_ctl_detach

static unsigned checks, failures, tests;
#define EQ(actual, expected) do { \
 long long a_ = (long long)(actual), e_ = (long long)(expected); checks++; \
 if (a_ != e_) { fprintf(stderr, "# line %d %s: got %lld expected %lld\n", \
 __LINE__, #actual, a_, e_); failures++; } \
} while (0)
#define YES(v) EQ(!!(v), 1)
#define API(fn) do { YES(fn != NULL); if (!(fn)) return; } while (0)
#define ENDPOINT_API() do { API(xdev_ext_peer_endpoint_open); \
 API(xdev_ext_peer_endpoint_create); API(xdev_ext_peer_endpoint_next); \
 API(xdev_ext_peer_endpoint_complete); API(xdev_ext_peer_endpoint_close); \
 API(xdev_ext_peer_endpoint_user); } while (0)
#define FS 4096U
#define RO 4096U
#define DO 8192U
#define SO 12288U
#define TOKEN 0x12345678abcULL
#define TX XDEV_EXT_MECH_DIR_TO_DEVICE
#define RX XDEV_EXT_MECH_DIR_FROM_DEVICE
#define PROD XDEV_EXT_PEER_PRODUCER
#define TERM XDEV_EXT_PEER_TX_TERMINAL
#define CONS XDEV_EXT_PEER_RX_CONSUMER

struct user_record {
 int fd; __u32 entries, flags; void *map; size_t bytes; bool attached, bound;
};
struct session_record {
 __u64 id; struct xdev_ext_mech_create create;
 struct xdev_ext_mech_stats stats; bool live;
};
static struct user_record users[16];
static struct session_record sessions[8];
static unsigned nu, ns, creates, stops, umem, user_requests, fail_user, starts, arms;
static int create_ret, stop_ret, stats_ret;
static struct xdev_ext_mech_create seen_create;
static struct xdev_ext_mech_start seen_start;
static __u32 seen_indices[64];

static int fds(void)
{
 DIR *d = opendir("/proc/self/fd"); struct dirent *e; int n = 0;
 if (!d) return -1;
 while ((e = readdir(d))) n += e->d_name[0] != '.';
 closedir(d); return n - 1;
}
static int newfd(const char *label)
{
 int fd = memfd_create(label, MFD_CLOEXEC);
 YES(fd >= 0); if (fd >= 0) EQ(ftruncate(fd, 16 * FS), 0); return fd;
}
static struct user_record *ufd(int fd)
{
 unsigned i = nu; while (i--) if (users[i].fd == fd) return &users[i];
 return NULL;
}
static struct session_record *sid(__u64 id)
{
 unsigned i; for (i = 0; i < ns; i++) if (sessions[i].id == id) return &sessions[i];
 return NULL;
}
static int setup(unsigned entries, struct io_uring_params *p)
{ (void)entries; (void)p; return eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK); }
static int regcall(int fd, unsigned opcode, void *arg, unsigned nr)
{
 struct io_uring_xdev_ext_mech *r = arg; void *p; unsigned i;
 YES(fd >= 0); EQ(nr, 1);
 if (opcode == IORING_REGISTER_XDEV_EXT_UMEM) { umem++; return 0; }
 if (opcode != IORING_REGISTER_XDEV_EXT_MECH) return -EINVAL;
 p = (void *)(uintptr_t)r->arg;
 switch (r->op) {
 case XDEV_EXT_MECH_OP_USER_STAGE: {
  struct xdev_ext_mech_user_stage *u = p; struct user_record *v;
  if (++user_requests == fail_user) return -ENOMEM;
  if (nu == 16) return -ENOSPC;
  v = &users[nu++]; v->entries = u->entries; v->flags = u->flags;
  v->fd = memfd_create("endpoint-user", MFD_CLOEXEC);
  v->bytes = SO + (size_t)v->entries * sizeof(struct xdev_ext_user_slot) + FS;
  if (v->fd < 0 || ftruncate(v->fd, v->bytes)) return -ENOMEM;
  v->map = mmap(NULL, v->bytes, PROT_READ | PROT_WRITE, MAP_SHARED, v->fd, 0);
  if (v->map == MAP_FAILED) return -ENOMEM;
  u->fd = v->fd;
  u->off = (struct xdev_ext_user_ring_offsets) {
   .mmap_size = v->bytes, .hdr = 0, .ready = RO, .done = DO, .slots = SO };
  return 0;
 }
 case XDEV_EXT_MECH_OP_CREATE: {
  struct xdev_ext_mech_create *c = p; struct session_record *s;
  creates++; seen_create = *c;
  if (create_ret) return create_ret;
  if (ns == 8) return -ENOSPC;
  s = &sessions[ns++]; s->id = 76 + ns; s->create = *c; s->live = true;
  s->stats.state = XDEV_EXT_MECH_SESSION_ACTIVE; c->session_id = s->id;
  for (i = 0; i < c->nr_stages; i++) if (c->st[i].class_id == XDEV_EXT_MECH_CLASS_USER) {
   struct user_record *v = ufd(c->st[i].fd); if (!v) return -EBADF; v->bound = true;
  }
  return 0;
 }
 case XDEV_EXT_MECH_OP_START:
  starts++; seen_start = *(struct xdev_ext_mech_start *)p;
  if (seen_start.user_frames && seen_start.nr_user_frames <= 64)
   memcpy(seen_indices, (void *)(uintptr_t)seen_start.user_frames,
          seen_start.nr_user_frames * sizeof(*seen_indices));
  return 0;
 case XDEV_EXT_MECH_OP_NOTIFY_ARM: arms++; return 0;
 case XDEV_EXT_MECH_OP_STATS: {
  struct session_record *s; if (stats_ret) return stats_ret;
  s = sid(*(__u64 *)p); if (!s || !s->live) return -ENOENT;
  s->stats.session_id = s->id; *(struct xdev_ext_mech_stats *)p = s->stats; return 0;
 }
 case XDEV_EXT_MECH_OP_STAGE_CAPS: return 0; /* no fabricated established capability */
 case XDEV_EXT_MECH_OP_STOP: {
  struct session_record *s = sid(r->arg); stops++;
  if (!s) return -ENOENT;
  if (stop_ret) return stop_ret;
  s->live = false;
  for (i = 0; i < s->create.nr_stages; i++)
   if (s->create.st[i].class_id == XDEV_EXT_MECH_CLASS_USER) {
    struct user_record *v = ufd(s->create.st[i].fd); if (v) v->bound = false;
   }
  return 0;
 }
 default: return -EINVAL;
 }
}
static int ioctlcall(int fd, unsigned long req, unsigned long arg)
{
 struct user_record *v = ufd(fd); if (!v) return -EBADF;
 EQ(arg, 0); if (req == XDEV_EXT_USER_IOC_KICK) return 0;
 if (!(v->flags & XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL)) return -EOPNOTSUPP;
 if (req == XDEV_EXT_USER_IOC_CTL_ATTACH) {
  if (v->attached) return -EALREADY;
  if (v->bound) return -EBUSY;
  v->attached = true; return 0;
 }
 if (req == XDEV_EXT_USER_IOC_CTL_DETACH) {
  if (!v->attached) return -ENOENT;
  if (v->bound) return -EBUSY;
  v->attached = false; return 0;
 }
 return -ENOTTY;
}
static void sleepcall(unsigned usec) { (void)usec; }
static const struct xdev_ext_sys sys = {
 .io_uring_setup = setup, .io_uring_register = regcall, .ioctl = ioctlcall, .usleep = sleepcall };
static void reset(void)
{
 unsigned i;
 for (i = 0; i < nu; i++) if (users[i].map && users[i].map != MAP_FAILED)
  EQ(munmap(users[i].map, users[i].bytes), 0);
 memset(users, 0, sizeof(users)); memset(sessions, 0, sizeof(sessions));
 nu = ns = creates = stops = umem = user_requests = fail_user = starts = arms = 0;
 create_ret = stop_ret = stats_ret = 0;
}
static struct xdev_ext_peer_endpoint_opts options(int a, int c, __u32 dir, bool ext)
{
 return (struct xdev_ext_peer_endpoint_opts) {
  .sz = sizeof(struct xdev_ext_peer_endpoint_opts), .allocation_fd = a, .control_fd = c,
  .link_token = TOKEN, .direction = dir, .depth = 2, .group_bytes = 8192, .deadline_ms = 1000,
  .layout = { .frame_size = FS, .seg_len = FS, .group_bytes = 8192 },
  .flags = ext ? XDEV_EXT_PEER_ENDPOINT_F_EXTERNAL_CTL : 0 };
}
static struct xdev_ext_peer_endpoint *open_ep(__u32 dir, bool ext, int *a, int *c, bool create)
{
 struct xdev_ext_peer_endpoint_opts o; struct xdev_ext_peer_endpoint *ep = NULL;
 *a = newfd("endpoint-authority"); *c = newfd("endpoint-control"); o = options(*a, *c, dir, ext);
 EQ(xdev_ext_peer_endpoint_open(&o, &ep), 0); YES(ep != NULL);
 if (ep && create) EQ(xdev_ext_peer_endpoint_create(ep), 0);
 return ep;
}
static void callers(int a, int c) { EQ(close(a), 0); EQ(close(c), 0); }
static struct user_record *role_user(struct xdev_ext_peer_endpoint *ep, enum xdev_ext_peer_role role)
{
 struct xdev_ext_user_stage *u = xdev_ext_peer_endpoint_user(ep, role);
 struct user_record *v = u ? ufd(xdev_ext_user_stage_fd(u)) : NULL; YES(v != NULL); return v;
}
static struct xdev_ext_user_ring_hdr *h(struct user_record *v) { return v->map; }
static struct xdev_ext_user_done *d(struct user_record *v) { return (void *)((char *)v->map + DO); }
static struct xdev_ext_user_slot *sl(struct user_record *v) { return (void *)((char *)v->map + SO); }
static bool take_slot(struct xdev_ext_peer_endpoint *ep, struct user_record *v,
 enum xdev_ext_peer_role role, __u32 slot, __u64 ticket, __u64 key, __u32 frame, struct xdev_ext_peer_message *m)
{
 struct xdev_ext_user_ready *r = (void *)((char *)v->map + RO); unsigned i; int ret;
 sl(v)[slot].ticket = ticket; sl(v)[slot].nr_frames = 2;
 for (i = 0; i < 2; i++) sl(v)[slot].f[i] = (struct xdev_ext_user_frame) {
  .umem_addr = (frame + i) * (uint64_t)FS, .data_len = FS, .capacity = FS, .out_len = FS };
 r[h(v)->ready_prod & (v->entries - 1)] = (struct xdev_ext_user_ready) {
  .slot = slot, .nr_frames = 2, .ticket = ticket, .batch_id = key + 1000, .key = key };
 __atomic_store_n(&h(v)->ready_prod, h(v)->ready_prod + 1, __ATOMIC_RELEASE);
 memset(m, 0, sizeof(*m)); ret = xdev_ext_peer_endpoint_next(ep, 0, m); EQ(ret, 0);
 if (ret) return false;
 EQ(m->role, role); YES(m->origin != 0); EQ(m->batch.ticket, ticket); EQ(m->batch.key, key);
 EQ(m->batch.f[0].umem_addr, frame * (uint64_t)FS);
 EQ(m->batch.f[1].umem_addr, (frame + 1) * (uint64_t)FS);
 for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) YES(m->batch.data[i] == NULL);
 return true;
}
static bool take(struct xdev_ext_peer_endpoint *ep, struct user_record *v,
 enum xdev_ext_peer_role role, __u64 ticket, __u64 key, __u32 frame, struct xdev_ext_peer_message *m)
{ return take_slot(ep, v, role, 0, ticket, key, frame, m); }

static void tx_prepare_attach_create(void)
{
 struct xdev_ext_peer_endpoint *ep; struct xdev_ext_user_stage *p, *t;
 struct stat sa, sc, got; int a, c, ap, cp;
 ENDPOINT_API(); API(xdev_ext_user_stage_ctl_attach); API(xdev_ext_user_stage_ctl_detach);
 ep = open_ep(TX, true, &a, &c, false); if (!ep) { callers(a, c); return; }
 EQ(creates, 0); EQ(nu, 2); EQ(umem, 0);
 p = xdev_ext_peer_endpoint_user(ep, PROD); t = xdev_ext_peer_endpoint_user(ep, TERM);
 YES(p && t && p != t); YES(xdev_ext_peer_endpoint_user(ep, CONS) == NULL);
 EQ(xdev_ext_user_stage_ctl_attach(p), 0); EQ(xdev_ext_user_stage_ctl_attach(t), 0); EQ(creates, 0);
 EQ(fstat(a, &sa), 0); EQ(fstat(c, &sc), 0); callers(a, c);
 EQ(xdev_ext_peer_endpoint_create(ep), 0); EQ(creates, 1); EQ(seen_create.nr_stages, 3);
 EQ(seen_create.pool_kind, XDEV_EXT_MECH_POOL_PEER);
 ap = seen_create.pool_fd; cp = seen_create.st[1].fd;
 YES(ap >= 0 && ap != a); YES(cp >= 0 && cp != c);
 EQ(fstat(ap, &got), 0); EQ(got.st_ino, sa.st_ino); EQ(got.st_dev, sa.st_dev);
 EQ(fstat(cp, &got), 0); EQ(got.st_ino, sc.st_ino); EQ(got.st_dev, sc.st_dev);
 YES(fcntl(ap, F_GETFD) & FD_CLOEXEC); YES(fcntl(cp, F_GETFD) & FD_CLOEXEC);
 EQ(seen_create.st[0].class_id, XDEV_EXT_MECH_CLASS_USER);
 EQ(seen_create.st[0].fd, xdev_ext_user_stage_fd(p));
 EQ(seen_create.st[0].flags, XDEV_EXT_USER_F_STRICT_ASYNC | XDEV_EXT_MECH_STAGE_F_POLL);
 EQ(seen_create.st[0].arg1, 0); EQ(seen_create.st[0].direction, TX);
 EQ(seen_create.st[1].class_id, XDEV_EXT_MECH_CLASS_XDOMAIN);
 EQ(seen_create.st[1].direction, TX); EQ(seen_create.st[1].arg0, TOKEN); EQ(seen_create.st[1].arg1, 0);
 EQ(seen_create.st[2].class_id, XDEV_EXT_MECH_CLASS_USER);
 EQ(seen_create.st[2].fd, xdev_ext_user_stage_fd(t));
 EQ(seen_create.st[2].flags, XDEV_EXT_USER_F_STRICT_ASYNC | XDEV_EXT_MECH_STAGE_F_POLL);
 EQ(xdev_ext_user_stage_ctl_detach(p), -EBUSY);
 EQ(xdev_ext_peer_endpoint_stop(ep), 0); EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
 YES(fcntl(ap, F_GETFD) >= 0); YES(fcntl(cp, F_GETFD) >= 0);
 /* Real CUDA synchronize/unregister precedes detach in the owner's workflow. */
 EQ(xdev_ext_user_stage_ctl_detach(p), 0); EQ(xdev_ext_user_stage_ctl_detach(t), 0);
 EQ(xdev_ext_peer_endpoint_close(ep), 0); EQ(fcntl(ap, F_GETFD), -1); EQ(fcntl(cp, F_GETFD), -1);
}
static void rx_chain_and_actual_role(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *v; struct xdev_ext_peer_message m, bad;
 int a, c; ENDPOINT_API();
 ep = open_ep(RX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 EQ(seen_create.nr_stages, 2); EQ(nu, 1);
 EQ(seen_create.st[0].class_id, XDEV_EXT_MECH_CLASS_XDOMAIN); EQ(seen_create.st[0].direction, RX);
 EQ(seen_create.st[0].arg0, TOKEN); EQ(seen_create.st[1].class_id, XDEV_EXT_MECH_CLASS_USER);
 EQ(seen_create.st[1].direction, TX);
 EQ(seen_create.st[1].flags, XDEV_EXT_USER_F_STRICT_ASYNC | XDEV_EXT_MECH_STAGE_F_POLL);
 YES(xdev_ext_peer_endpoint_user(ep, PROD) == NULL); YES(xdev_ext_peer_endpoint_user(ep, TERM) == NULL);
 v = role_user(ep, CONS);
 if (v && take(ep, v, CONS, 302, 11, 9, &m)) {
  bad = m; bad.role = PROD; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0); EQ(h(v)->done_prod, 0);
  EQ(xdev_ext_peer_endpoint_complete(ep, &m, 0), 0); EQ(d(v)[0].ticket, 302); EQ(d(v)[0].status, 0);
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void create_failure_cleanup(void)
{
 struct xdev_ext_peer_endpoint *ep; int a, c, ap, cp; ENDPOINT_API();
 ep = open_ep(TX, false, &a, &c, false); if (!ep) { callers(a, c); return; }
 create_ret = -EXDEV; EQ(xdev_ext_peer_endpoint_create(ep), -EXDEV);
 ap = seen_create.pool_fd; cp = seen_create.st[1].fd;
 EQ(xdev_ext_peer_endpoint_close(ep), 0); EQ(fcntl(ap, F_GETFD), -1); EQ(fcntl(cp, F_GETFD), -1);
 YES(fcntl(a, F_GETFD) >= 0); YES(fcntl(c, F_GETFD) >= 0); callers(a, c);
}
static void open_failure_cleanup_and_validation(void)
{
 struct xdev_ext_peer_endpoint_opts o; struct xdev_ext_peer_endpoint *ep = (void *)1;
 int a, c, before = fds(); ENDPOINT_API();
 a = newfd("endpoint-authority"); c = newfd("endpoint-control"); o = options(a, c, TX, false);
 YES(xdev_ext_peer_endpoint_open(NULL, &ep) < 0); YES(xdev_ext_peer_endpoint_open(&o, NULL) < 0);
 o.sz--; YES(xdev_ext_peer_endpoint_open(&o, &ep) < 0); o.sz = sizeof(o);
 o.flags = 1U << 30; YES(xdev_ext_peer_endpoint_open(&o, &ep) < 0); o.flags = 0;
 o.direction = 99; YES(xdev_ext_peer_endpoint_open(&o, &ep) < 0); o.direction = TX;
 o.control_fd = -1; YES(xdev_ext_peer_endpoint_open(&o, &ep) < 0); o.control_fd = c;
 fail_user = 2; EQ(xdev_ext_peer_endpoint_open(&o, &ep), -ENOMEM); EQ((uintptr_t)ep, 1);
 EQ(creates, 0); EQ(fds(), before + 2); callers(a, c);
}
static void ordered_start_requires_create(void)
{
 __u32 ix[] = {7, 3, 9, 1}; struct xdev_ext_start_frames_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_start_frames_opts,
  .nr_batches = 2, .first_seq = 101, .indices = ix, .nr_indices = 4);
 struct xdev_ext_peer_endpoint *ep; int a, c; ENDPOINT_API(); API(xdev_ext_peer_endpoint_start);
 ep = open_ep(TX, false, &a, &c, false); if (!ep) { callers(a, c); return; }
 YES(xdev_ext_peer_endpoint_start(ep, &o) < 0); EQ(starts, 0);
 EQ(xdev_ext_peer_endpoint_create(ep), 0); EQ(xdev_ext_peer_endpoint_start(ep, &o), 0);
 EQ(starts, 1); EQ(arms, 1); EQ(seen_start.first_seq, 101); EQ(seen_start.nr_user_frames, 4);
 EQ(memcmp(ix, seen_indices, sizeof(ix)), 0);
 EQ(seen_start.flags, XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_ORDERED_FRAMES);
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void tx_actual_producer_and_terminal(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p, *t; struct xdev_ext_peer_message m;
 int a, c; ENDPOINT_API(); ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 p = role_user(ep, PROD); t = role_user(ep, TERM);
 if (p && take(ep, p, PROD, 501, 101, 7, &m)) {
  EQ(xdev_ext_peer_endpoint_complete(ep, &m, 0), 0); EQ(h(p)->done_prod, 1); EQ(d(p)[0].ticket, 501);
 }
 if (t && take(ep, t, TERM, 503, 101, 7, &m)) {
  EQ(xdev_ext_peer_endpoint_complete(ep, &m, 0), 0); EQ(h(t)->done_prod, 1); EQ(d(t)[0].ticket, 503);
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void wrong_role_matching_ticket_rejected(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p, *t; struct xdev_ext_peer_message mp, mt, bad;
 int a, c; ENDPOINT_API(); ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 p = role_user(ep, PROD); t = role_user(ep, TERM);
 if (p && t && take(ep, p, PROD, 601, 200, 7, &mp) && take(ep, t, TERM, 601, 199, 3, &mt)) {
  bad = mp; bad.role = TERM; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0);
  bad = mt; bad.role = PROD; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0);
  EQ(h(p)->done_prod, 0); EQ(h(t)->done_prod, 0);
  EQ(xdev_ext_peer_endpoint_complete(ep, &mp, 0), 0); EQ(xdev_ext_peer_endpoint_complete(ep, &mt, 0), 0);
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void identical_metadata_wrong_endpoint_rejected(void)
{
 struct xdev_ext_peer_endpoint *ea, *eb; struct user_record *pa, *pb;
 struct xdev_ext_peer_message ma, mb; int aa, ca, ab, cb; ENDPOINT_API();
 ea = open_ep(TX, false, &aa, &ca, true); eb = open_ep(TX, false, &ab, &cb, true);
 if (!ea || !eb) { if (ea) xdev_ext_peer_endpoint_close(ea); if (eb) xdev_ext_peer_endpoint_close(eb);
  callers(aa, ca); callers(ab, cb); return; }
 pa = role_user(ea, PROD); pb = role_user(eb, PROD);
 if (pa && pb && take(ea, pa, PROD, 701, 301, 7, &ma)) {
  YES(xdev_ext_peer_endpoint_complete(eb, &ma, 0) < 0); EQ(h(pb)->done_prod, 0);
  if (take(eb, pb, PROD, 701, 301, 7, &mb)) {
   EQ(memcmp(&ma.batch, &mb.batch, sizeof(ma.batch)), 0); EQ(ma.role, mb.role); YES(ma.origin != mb.origin);
   YES(xdev_ext_peer_endpoint_complete(eb, &ma, 0) < 0); YES(xdev_ext_peer_endpoint_complete(ea, &mb, 0) < 0);
   EQ(h(pa)->done_prod, 0); EQ(h(pb)->done_prod, 0);
   EQ(xdev_ext_peer_endpoint_complete(eb, &mb, 0), 0);
  }
  EQ(xdev_ext_peer_endpoint_complete(ea, &ma, 0), 0);
 }
 EQ(xdev_ext_peer_endpoint_close(ea), 0); EQ(xdev_ext_peer_endpoint_close(eb), 0);
 callers(aa, ca); callers(ab, cb);
}
static void old_duplicate_and_modified_fields_rejected(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p; struct xdev_ext_peer_message old, fresh, bad;
 int a, c; ENDPOINT_API(); ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 p = role_user(ep, PROD);
 if (p && take(ep, p, PROD, 801, 401, 7, &old)) {
  bad = old; bad.origin = 0; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0);
  bad = old; bad.batch.key++; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0);
  bad = old; bad.batch.f[0].umem_addr += FS; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0);
  bad = old; bad.batch.nr_frames--; YES(xdev_ext_peer_endpoint_complete(ep, &bad, 0) < 0);
  EQ(h(p)->done_prod, 0); EQ(xdev_ext_peer_endpoint_complete(ep, &old, 0), 0);
  YES(xdev_ext_peer_endpoint_complete(ep, &old, 0) < 0); EQ(h(p)->done_prod, 1);
  h(p)->done_cons = 1; sl(p)[0].ticket = 0;
  if (take(ep, p, PROD, 802, 402, 3, &fresh)) {
   YES(xdev_ext_peer_endpoint_complete(ep, &old, 0) < 0); EQ(h(p)->done_prod, 1);
   EQ(sl(p)[0].f[0].out_len, FS); EQ(xdev_ext_peer_endpoint_complete(ep, &fresh, 0), 0);
   EQ(h(p)->done_prod, 2); EQ(d(p)[1].ticket, 802);
  }
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void held_stop_close_retains_late_done(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p; struct xdev_ext_peer_message m;
 struct xdev_ext_session *s; int a, c, ap, cp, held; ENDPOINT_API();
 API(xdev_ext_peer_endpoint_stop); API(xdev_ext_peer_endpoint_session);
 ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 ap = seen_create.pool_fd; cp = seen_create.st[1].fd; s = xdev_ext_peer_endpoint_session(ep); p = role_user(ep, PROD);
 if (p && take(ep, p, PROD, 901, 501, 7, &m)) {
  held = fds(); stop_ret = -EBUSY;
  EQ(xdev_ext_peer_endpoint_stop(ep), -EBUSY); EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
  EQ(fds(), held); YES(xdev_ext_peer_endpoint_session(ep) == s);
  YES(fcntl(ap, F_GETFD) >= 0); YES(fcntl(cp, F_GETFD) >= 0);
  EQ(xdev_ext_peer_endpoint_complete(ep, &m, 0), 0); EQ(h(p)->done_prod, 1); EQ(d(p)[0].ticket, 901);
  stats_ret = -ENOENT; /* definite kernel release for fixture cleanup */
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void unknown_retains_authority(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p; struct xdev_ext_peer_message m;
 int a, c, ap, cp; ENDPOINT_API(); API(xdev_ext_peer_endpoint_stop);
 ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 ap = seen_create.pool_fd; cp = seen_create.st[1].fd; p = role_user(ep, PROD);
 if (p && take(ep, p, PROD, 1001, 601, 7, &m)) {
  EQ(xdev_ext_peer_endpoint_complete(ep, &m, -EIO), 0); EQ(d(p)[0].status, -EIO);
  stop_ret = -EBUSY; sessions[0].stats.state = XDEV_EXT_MECH_SESSION_ZOMBIE; sessions[0].stats.sequestered = 1;
  EQ(xdev_ext_peer_endpoint_stop(ep), -EBUSY); EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
  stats_ret = -EIO; EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
  YES(fcntl(ap, F_GETFD) >= 0); YES(fcntl(cp, F_GETFD) >= 0);
  YES(fcntl(a, F_GETFD) >= 0); YES(fcntl(c, F_GETFD) >= 0);
  stats_ret = -ENOENT; /* fixture cleanup, never proof of UNKNOWN GPU recovery */
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void external_control_survives_payload_and_stop(void)
{
 struct xdev_ext_peer_endpoint *ep; struct xdev_ext_user_stage *up, *ut; struct user_record *p;
 struct xdev_ext_peer_message m; struct xdev_ext_user_ring_offsets off; void *base = NULL;
 struct xdev_ext_user_ring_hdr *hdr; struct xdev_ext_user_ready *ready, owned;
 struct xdev_ext_user_slot *slot; struct xdev_ext_user_done *done;
 int a, c, ap, cp; ENDPOINT_API(); API(xdev_ext_user_stage_control);
 API(xdev_ext_user_stage_ctl_attach); API(xdev_ext_user_stage_ctl_detach);
 ep = open_ep(TX, true, &a, &c, false); if (!ep) { callers(a, c); return; }
 up = xdev_ext_peer_endpoint_user(ep, PROD); ut = xdev_ext_peer_endpoint_user(ep, TERM);
 EQ(xdev_ext_user_stage_control(up, &base, &off), 0); YES(base != NULL);
 EQ(xdev_ext_user_stage_ctl_attach(up), 0); EQ(xdev_ext_user_stage_ctl_attach(ut), 0); EQ(creates, 0);
 EQ(xdev_ext_peer_endpoint_create(ep), 0); ap = seen_create.pool_fd; cp = seen_create.st[1].fd;
 p = role_user(ep, PROD);
 if (p) {
  hdr = base; ready = (void *)((char *)base + off.ready);
  slot = (void *)((char *)base + off.slots); done = (void *)((char *)base + off.done);
  slot[0].ticket = 1101; slot[0].nr_frames = 2;
  for (unsigned i = 0; i < 2; i++) slot[0].f[i] = (struct xdev_ext_user_frame) {
   .umem_addr = (7 + i) * (uint64_t)FS, .data_len = FS, .capacity = FS, .out_len = FS };
  ready[0] = (struct xdev_ext_user_ready) {
   .slot = 0, .nr_frames = 2, .ticket = 1101, .batch_id = 1701, .key = 701 };
  __atomic_store_n(&h(p)->ready_prod, 1, __ATOMIC_RELEASE);
  /* The CPU endpoint must leave custody to the attached external owner. */
  EQ(xdev_ext_peer_endpoint_next(ep, 0, &m), -EBUSY);
  EQ(hdr->ready_cons, 0); EQ(h(p)->ready_cons, 0); EQ(hdr->done_prod, 0);
  /* Simulate the GPU owner's metadata protocol through the exported map;
   * this is host lifecycle evidence, not execution of a CUDA device kernel. */
  EQ(__atomic_load_n(&hdr->ready_prod, __ATOMIC_ACQUIRE), 1);
  owned = ready[hdr->ready_cons & (p->entries - 1)];
  EQ(owned.ticket, 1101); EQ(owned.batch_id, 1701); EQ(owned.key, 701);
  EQ(owned.slot, 0); EQ(owned.nr_frames, 2); EQ(slot[owned.slot].ticket, owned.ticket);
  EQ(slot[owned.slot].f[0].umem_addr, 7 * (uint64_t)FS);
  EQ(slot[owned.slot].f[1].umem_addr, 8 * (uint64_t)FS);
  __atomic_store_n(&hdr->ready_cons, 1, __ATOMIC_RELEASE);
  done[0] = (struct xdev_ext_user_done) { .slot = owned.slot, .ticket = owned.ticket, .status = 0 };
  __atomic_store_n(&hdr->done_prod, 1, __ATOMIC_RELEASE);
  EQ(h(p)->ready_cons, 1); EQ(h(p)->done_prod, 1); EQ(d(p)[0].ticket, 1101); EQ(d(p)[0].status, 0);
 }
 EQ(xdev_ext_peer_endpoint_stop(ep), 0); EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
 YES(fcntl(ap, F_GETFD) >= 0); YES(fcntl(cp, F_GETFD) >= 0);
 EQ(((struct xdev_ext_user_ring_hdr *)base)->ready_cons, 1);
 EQ(xdev_ext_user_stage_ctl_detach(up), 0); EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
 EQ(xdev_ext_user_stage_ctl_detach(ut), 0); EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void failed_create_preserves_external_attach(void)
{
 struct xdev_ext_peer_endpoint *ep; struct xdev_ext_user_stage *up, *ut; int a, c;
 ENDPOINT_API(); API(xdev_ext_user_stage_ctl_attach); API(xdev_ext_user_stage_ctl_detach);
 ep = open_ep(TX, true, &a, &c, false); if (!ep) { callers(a, c); return; }
 up = xdev_ext_peer_endpoint_user(ep, PROD); ut = xdev_ext_peer_endpoint_user(ep, TERM);
 EQ(xdev_ext_user_stage_ctl_attach(up), 0); EQ(xdev_ext_user_stage_ctl_attach(ut), 0);
 create_ret = -EXDEV; EQ(xdev_ext_peer_endpoint_create(ep), -EXDEV);
 EQ(xdev_ext_peer_endpoint_close(ep), -EBUSY);
 YES(fcntl(xdev_ext_user_stage_fd(up), F_GETFD) >= 0); YES(fcntl(xdev_ext_user_stage_fd(ut), F_GETFD) >= 0);
 EQ(xdev_ext_user_stage_ctl_detach(up), 0); EQ(xdev_ext_user_stage_ctl_detach(ut), 0);
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void two_same_role_leases_preserve_independent_tickets(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p; struct xdev_ext_peer_message first, second;
 int a, c; ENDPOINT_API(); ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 p = role_user(ep, PROD);
 if (p && take(ep, p, PROD, 1201, 801, 7, &first) &&
     take_slot(ep, p, PROD, 1, 1202, 802, 3, &second)) {
  EQ(xdev_ext_peer_endpoint_complete(ep, &second, 0), 0);
  EQ(xdev_ext_peer_endpoint_complete(ep, &first, 0), 0);
  EQ(h(p)->done_prod, 2); EQ(d(p)[0].ticket, 1202); EQ(d(p)[1].ticket, 1201);
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void new_endpoint_never_accepts_closed_endpoint_origin(void)
{
 struct xdev_ext_peer_endpoint *ep; struct user_record *p; struct xdev_ext_peer_message old, fresh;
 int a, c; ENDPOINT_API(); ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 p = role_user(ep, PROD);
 if (!p || !take(ep, p, PROD, 1301, 901, 7, &old)) {
  xdev_ext_peer_endpoint_close(ep); callers(a, c); return;
 }
 EQ(xdev_ext_peer_endpoint_complete(ep, &old, 0), 0);
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
 ep = open_ep(TX, false, &a, &c, true); if (!ep) { callers(a, c); return; }
 p = role_user(ep, PROD);
 if (p && take(ep, p, PROD, 1301, 901, 7, &fresh)) {
  EQ(memcmp(&old.batch, &fresh.batch, sizeof(old.batch)), 0); YES(old.origin != fresh.origin);
  YES(xdev_ext_peer_endpoint_complete(ep, &old, 0) < 0); EQ(h(p)->done_prod, 0);
  EQ(xdev_ext_peer_endpoint_complete(ep, &fresh, 0), 0);
 }
 EQ(xdev_ext_peer_endpoint_close(ep), 0); callers(a, c);
}
static void run(void (*fn)(void), const char *name)
{
 unsigned before = failures; int initial;
 reset(); xdev_ext__set_sys(&sys); initial = fds(); fn(); EQ(fds(), initial); xdev_ext__set_sys(NULL);
 printf("%s %u - %s\n", failures == before ? "ok" : "not ok", ++tests, name);
}
#define RUN(fn) run(fn, #fn)
int main(void)
{
 printf("TAP version 13\n1..15\n");
 RUN(tx_prepare_attach_create); RUN(rx_chain_and_actual_role); RUN(create_failure_cleanup);
 RUN(open_failure_cleanup_and_validation); RUN(ordered_start_requires_create);
 RUN(tx_actual_producer_and_terminal); RUN(wrong_role_matching_ticket_rejected);
 RUN(identical_metadata_wrong_endpoint_rejected); RUN(old_duplicate_and_modified_fields_rejected);
 RUN(held_stop_close_retains_late_done); RUN(unknown_retains_authority);
 RUN(external_control_survives_payload_and_stop); RUN(failed_create_preserves_external_attach);
 RUN(two_same_role_leases_preserve_independent_tickets);
 RUN(new_endpoint_never_accepts_closed_endpoint_origin);
 reset(); printf("# checks=%u failures=%u\n", checks, failures); return failures ? 1 : 0;
}
