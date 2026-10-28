/* SPDX-License-Identifier: GPL-2.0 */
/* A1 requirement tests; root CONTROL freeze, accepted baseline a22768a. */
#include "check_contract.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); exit(1); \
} } while (0)
/* Formal declaration setup after the preserved numeric runtime RED. */
_Static_assert(TB_OP_GPU_OPEN == 0, "preserve original operation numbering");
_Static_assert(TB_OP_GPU_CLOSE == 9, "preserve original operation numbering");
_Static_assert(TB_OP_CONTROL == 10, "append CONTROL without renumbering");
static const enum tb_operation control_op = TB_OP_CONTROL;

enum state {
 NEW, OPEN_UNFILLED, FILLED, EXTERNAL_READY, CREATED, CREATED_GPU_UNSAFE,
 STARTED, DONE, STOPPED_NO_PAIR, PAIR, VISIBLE, VERIFIED,
 OPEN_BUSY, FILL_BUSY, VERIFY_BUSY, CREATE_BUSY, HELD, FAILED_SAFE, CLOSED,
 PAIR_GPU_UNSAFE, PROVIDER_NEW, PROVIDER_CREATED
};
static struct tb_guard_snapshot snap(struct tb_guard *g)
{
 struct tb_guard_snapshot s = {0};
 tb_guard_snapshot(g, &s);
 CHECK(s.size == sizeof(s) && s.version == TB_CHECK_VERSION);
 CHECK(s.cleanup_permissions == tb_guard_cleanup_permissions(g));
 return s;
}
static void success(struct tb_guard *g, enum tb_operation op,
                    enum tb_phase phase, bool native_safe, bool gpu_safe)
{
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, op, &ticket) == 0 && ticket != 0);
 CHECK(tb_guard_end(g, ticket, phase, native_safe, gpu_safe) == 0);
}
static struct tb_guard *make_state(enum state state)
{
 struct tb_guard *g = NULL;
 uint64_t ticket = 0;
 bool provider = state == EXTERNAL_READY || state == PROVIDER_NEW || state == PROVIDER_CREATED;
 CHECK(tb_guard_new(provider ? TB_BACKING_EXISTING_PROVIDER : TB_BACKING_GPU, &g) == 0);
 if (state == NEW || state == PROVIDER_NEW) return g;
 if (provider) {
  CHECK(tb_guard_external_ready(g, TB_READY_EXISTING_PROVIDER_REGISTERED) == 0);
  if (state == PROVIDER_CREATED)
   success(g, TB_OP_CREATE, TB_PHASE_SESSION_CREATED, false, true);
  return g;
 }
 if (state == HELD) {
  tb_guard_hold(g, TB_HOLD_SIGNAL);
  return g;
 }
 if (state == OPEN_BUSY || state == FAILED_SAFE) {
  CHECK(tb_guard_begin(g, TB_OP_GPU_OPEN, &ticket) == 0);
  if (state == FAILED_SAFE)
   CHECK(tb_guard_end(g, ticket, TB_PHASE_FAILED_SAFE, true, true) == 0);
  return g;
 }
 success(g, TB_OP_GPU_OPEN, TB_PHASE_GPU_READY, true, true);
 if (state == OPEN_UNFILLED) return g;
 if (state == CLOSED) {
  success(g, TB_OP_GPU_CLOSE, TB_PHASE_CLOSED, true, true);
  return g;
 }
 if (state == FILL_BUSY) {
  CHECK(tb_guard_begin(g, TB_OP_GPU_FILL, &ticket) == 0);
  return g;
 }
 success(g, TB_OP_GPU_FILL, TB_PHASE_GPU_READY, true, true);
 if (state == FILLED) return g;
 if (state == CREATE_BUSY) {
  CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == 0);
  return g;
 }
 success(g, TB_OP_CREATE, TB_PHASE_SESSION_CREATED, false,
         state != CREATED_GPU_UNSAFE && state != PAIR_GPU_UNSAFE);
 if (state == CREATED || state == CREATED_GPU_UNSAFE) return g;
 if (state == PAIR_GPU_UNSAFE) {
  success(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, false);
  CHECK(tb_guard_pair_stopped(g) == 0);
  return g;
 }
 success(g, TB_OP_START, TB_PHASE_START_ACCEPTED, false, true);
 if (state == STARTED) return g;
 success(g, TB_OP_WAIT, TB_PHASE_TRANSPORT_DONE, false, true);
 if (state == DONE) return g;
 success(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, true);
 if (state == STOPPED_NO_PAIR) return g;
 CHECK(tb_guard_pair_stopped(g) == 0);
 if (state == PAIR) return g;
 success(g, TB_OP_VISIBLE, TB_PHASE_DRAINED_SAFE, true, true);
 if (state == VISIBLE) return g;
 if (state == VERIFY_BUSY) {
  CHECK(tb_guard_begin(g, TB_OP_GPU_VERIFY, &ticket) == 0);
  return g;
 }
 success(g, TB_OP_GPU_VERIFY, TB_PHASE_VERIFIED, true, true);
 return g;
}
static void same_facts(const struct tb_guard_snapshot *a,
                       const struct tb_guard_snapshot *b)
{
 CHECK(a->phase == b->phase && a->held == b->held);
 CHECK(a->native_safe == b->native_safe && a->gpu_safe == b->gpu_safe);
 CHECK(a->hold_reasons == b->hold_reasons);
 CHECK(a->pair_stop_proved == b->pair_stop_proved);
 CHECK(a->gpu_applicable == b->gpu_applicable && a->backing_mode == b->backing_mode);
 CHECK(a->external_ready_proof == b->external_ready_proof);
}
static void admit(enum state state)
{
 struct tb_guard *g = make_state(state);
 struct tb_guard_snapshot before = snap(g), during, after;
 uint64_t ticket = 0;
 int ret = tb_guard_begin(g, control_op, &ticket);
 printf("control_admission state=%u phase=%u native=%d gpu=%d ret=%d\n",
        (unsigned int)state, (unsigned int)before.phase,
        before.native_safe, before.gpu_safe, ret);
 CHECK(ret == 0 && ticket != 0);
 during = snap(g);
 same_facts(&before, &during);
 CHECK(during.operation_ticket == ticket);
 CHECK(during.cleanup_permissions == 0);
 CHECK(tb_guard_end(g, ticket, before.phase, before.native_safe, before.gpu_safe) == 0);
 after = snap(g);
 same_facts(&before, &after);
 CHECK(before.cleanup_permissions == after.cleanup_permissions);
}
static void deny(enum state state)
{
 struct tb_guard *g = make_state(state);
 struct tb_guard_snapshot before = snap(g), after;
 uint64_t ticket = 0;
 unsigned int external_acquisitions = 0;
 int ret = tb_guard_begin(g, control_op, &ticket);
 if (!ret) external_acquisitions++;
 CHECK(ret == -EPERM);
 CHECK(external_acquisitions == 0);
 after = snap(g);
 same_facts(&before, &after);
 CHECK(before.cleanup_permissions == after.cleanup_permissions);
}
static void busy_no_cleanup(void)
{
 struct tb_guard *g = make_state(FILLED);
 struct tb_guard_snapshot entry = snap(g);
 uint64_t ticket = 0, second = 0;
 CHECK(entry.cleanup_permissions & TB_CLEANUP_PEER_FD);
 CHECK(tb_guard_begin(g, control_op, &ticket) == 0);
 CHECK(tb_guard_cleanup_permissions(g) == 0);
 CHECK(tb_guard_begin(g, control_op, &second) < 0);
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &second) < 0);
 CHECK(tb_guard_begin(g, TB_OP_GPU_FILL, &second) < 0);
 CHECK(tb_guard_begin(g, TB_OP_EPOCH_CLOSE, &second) < 0);
 CHECK(tb_guard_begin(g, TB_OP_GPU_CLOSE, &second) < 0);
 CHECK(tb_guard_end(g, ticket, entry.phase, entry.native_safe, entry.gpu_safe) == 0);
 CHECK(tb_guard_cleanup_permissions(g) & TB_CLEANUP_PEER_FD);
 /* CONTROL admission never substitutes for a subsequent close admission. */
 CHECK(tb_guard_begin(g, TB_OP_EPOCH_CLOSE, &second) == 0);
 CHECK(tb_guard_cleanup_permissions(g) == 0);
 CHECK(tb_guard_end(g, second, entry.phase, entry.native_safe, entry.gpu_safe) == 0);
}
enum invalid_change { CHANGE_PHASE, UPGRADE_NATIVE, DOWNGRADE_NATIVE, UPGRADE_GPU, DOWNGRADE_GPU };
static void invalid_end(enum invalid_change change)
{
 enum state state = change == UPGRADE_NATIVE ? CREATED :
                    change == UPGRADE_GPU ? CREATED_GPU_UNSAFE : FILLED;
 struct tb_guard *g = make_state(state);
 struct tb_guard_snapshot entry = snap(g), after;
 enum tb_phase phase = entry.phase;
 bool native_safe = entry.native_safe, gpu_safe = entry.gpu_safe;
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, control_op, &ticket) == 0);
 switch (change) {
 case CHANGE_PHASE: phase = TB_PHASE_VERIFIED; break;
 case UPGRADE_NATIVE: native_safe = true; break;
 case DOWNGRADE_NATIVE: native_safe = false; break;
 case UPGRADE_GPU: gpu_safe = true; break;
 case DOWNGRADE_GPU: gpu_safe = false; break;
 }
 CHECK(tb_guard_end(g, ticket, phase, native_safe, gpu_safe) < 0);
 after = snap(g);
 CHECK(after.phase == entry.phase || after.phase == TB_PHASE_HELD);
 CHECK(after.native_safe == entry.native_safe && after.gpu_safe == entry.gpu_safe);
 CHECK(after.cleanup_permissions == 0);
}
static void fill_pair_visibility_preserved(void)
{
 struct tb_guard *g = make_state(FILLED);
 struct tb_guard_snapshot entry = snap(g);
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, control_op, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket, entry.phase, entry.native_safe, entry.gpu_safe) == 0);
 /* FILL proof survives CONTROL, so CREATE still has its real prerequisite. */
 success(g, TB_OP_CREATE, TB_PHASE_SESSION_CREATED, false, true);
 success(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, true);
 CHECK(tb_guard_pair_stopped(g) == 0);
 entry = snap(g);
 CHECK(tb_guard_begin(g, control_op, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket, entry.phase, entry.native_safe, entry.gpu_safe) == 0);
 CHECK(snap(g).pair_stop_proved);
 /* Pair proof is preserved; CONTROL must not manufacture visibility. */
 CHECK(tb_guard_begin(g, TB_OP_GPU_VERIFY, &ticket) == -EPERM);
 success(g, TB_OP_VISIBLE, TB_PHASE_DRAINED_SAFE, true, true);
 entry = snap(g);
 CHECK(tb_guard_begin(g, control_op, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket, entry.phase, entry.native_safe, entry.gpu_safe) == 0);
 /* Existing visibility likewise survives metadata acquisition. */
 success(g, TB_OP_GPU_VERIFY, TB_PHASE_VERIFIED, true, true);
}
struct concurrent {
 pthread_mutex_t lock;
 pthread_cond_t cond;
 struct tb_guard *g;
 bool admitted, release;
 int resource[2], end_ret;
};
static void *inflight_resource(void *opaque)
{
 struct concurrent *c = opaque;
 struct tb_guard_snapshot entry = snap(c->g);
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(c->g, control_op, &ticket) == 0);
 CHECK(pipe(c->resource) == 0); /* Actual owned host resource, no SDK. */
 CHECK(pthread_mutex_lock(&c->lock) == 0);
 c->admitted = true;
 CHECK(pthread_cond_signal(&c->cond) == 0);
 while (!c->release) CHECK(pthread_cond_wait(&c->cond, &c->lock) == 0);
 CHECK(pthread_mutex_unlock(&c->lock) == 0);
 c->end_ret = tb_guard_end(c->g, ticket, entry.phase, entry.native_safe, entry.gpu_safe);
 return NULL;
}
static void late_resource_held(void)
{
 struct concurrent c = {.lock = PTHREAD_MUTEX_INITIALIZER,
  .cond = PTHREAD_COND_INITIALIZER, .g = make_state(FILLED), .resource = {-1, -1}};
 struct tb_guard_snapshot s;
 pthread_t worker;
 uint64_t ticket = 0;
 CHECK(pthread_create(&worker, NULL, inflight_resource, &c) == 0);
 CHECK(pthread_mutex_lock(&c.lock) == 0);
 while (!c.admitted) CHECK(pthread_cond_wait(&c.cond, &c.lock) == 0);
 tb_guard_hold(c.g, TB_HOLD_DEADLINE);
 tb_guard_hold(c.g, TB_HOLD_SIGNAL);
 c.release = true;
 CHECK(pthread_cond_signal(&c.cond) == 0);
 CHECK(pthread_mutex_unlock(&c.lock) == 0);
 CHECK(pthread_join(worker, NULL) == 0);
 CHECK(c.end_ret == -ECANCELED);
 s = snap(c.g);
 CHECK(s.held && s.phase == TB_PHASE_HELD && s.cleanup_permissions == 0);
 CHECK((s.hold_reasons & (TB_HOLD_DEADLINE | TB_HOLD_SIGNAL)) ==
       (TB_HOLD_DEADLINE | TB_HOLD_SIGNAL));
 CHECK(fcntl(c.resource[0], F_GETFD) >= 0 && fcntl(c.resource[1], F_GETFD) >= 0);
 CHECK(tb_guard_begin(c.g, control_op, &ticket) == -EPERM);
 CHECK(tb_guard_begin(c.g, TB_OP_CREATE, &ticket) == -EPERM);
 CHECK(tb_guard_begin(c.g, TB_OP_START, &ticket) == -EPERM);
 CHECK(tb_guard_begin(c.g, TB_OP_EPOCH_CLOSE, &ticket) == -EPERM);
 CHECK(tb_guard_begin(c.g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
 CHECK(tb_guard_delete(c.g) == -EPERM);
 /* Intentionally retained until this isolated test process ends. */
 CHECK(pthread_cond_destroy(&c.cond) == 0);
 CHECK(pthread_mutex_destroy(&c.lock) == 0);
}
static void hold_wins_before_begin(void)
{
 struct tb_guard *g = make_state(FILLED);
 uint64_t ticket = 0;
 unsigned int resource_calls = 0;
 tb_guard_hold(g, TB_HOLD_CANCEL);
 if (!tb_guard_begin(g, control_op, &ticket)) resource_calls++;
 CHECK(resource_calls == 0);
 CHECK(snap(g).held && tb_guard_cleanup_permissions(g) == 0);
}
static void invalid_ticket(void)
{
 struct tb_guard *g = make_state(FILLED);
 struct tb_guard_snapshot entry = snap(g), after;
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, control_op, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket + 1, entry.phase, entry.native_safe, entry.gpu_safe) < 0);
 after = snap(g);
 CHECK(after.phase == entry.phase || after.phase == TB_PHASE_HELD);
 CHECK(after.native_safe == entry.native_safe && after.gpu_safe == entry.gpu_safe);
 CHECK(after.cleanup_permissions == 0);
}
struct matrix_case { const char *name; enum state state; bool legal; };
static const struct matrix_case matrix[] = {
 {"control-filled-gpu-ready", FILLED, true},
 {"control-existing-provider-ready", EXTERNAL_READY, true},
 {"control-session-created-initial-config", CREATED, true},
 {"control-session-created-preserves-unsafe-proof", CREATED_GPU_UNSAFE, true},
 {"control-provider-session-created", PROVIDER_CREATED, true},
 {"control-safe-pair-drained", PAIR, true},
 {"control-safe-visible-drained", VISIBLE, true},
 {"control-verified", VERIFIED, true},
 {"control-new-denied", NEW, false},
 {"control-provider-new-denied", PROVIDER_NEW, false},
 {"control-gpu-open-unfilled-denied", OPEN_UNFILLED, false},
 {"control-started-denied", STARTED, false},
 {"control-transport-done-denied", DONE, false},
 {"control-local-stop-no-pair-denied", STOPPED_NO_PAIR, false},
 {"control-pair-gpu-unsafe-denied", PAIR_GPU_UNSAFE, false},
 {"control-open-busy-denied", OPEN_BUSY, false},
 {"control-fill-busy-denied", FILL_BUSY, false},
 {"control-verifying-denied", VERIFY_BUSY, false},
 {"control-create-busy-denied", CREATE_BUSY, false},
 {"control-held-denied", HELD, false},
 {"control-failed-safe-denied", FAILED_SAFE, false},
 {"control-closed-denied", CLOSED, false},
};
static const char *const extra[] = {
 "control-busy-no-cleanup-or-second-op", "control-invalid-end-phase",
 "control-invalid-native-upgrade", "control-invalid-native-downgrade",
 "control-invalid-gpu-upgrade", "control-invalid-gpu-downgrade",
 "control-preserves-fill-pair-visibility", "control-late-resource-held",
 "control-hold-before-admission-no-resource", "control-invalid-ticket-no-proof-or-cleanup"
};
int main(int argc, char **argv)
{
 size_t i;
 if (argc == 2 && !strcmp(argv[1], "--list")) {
  for (i = 0; i < sizeof(matrix) / sizeof(matrix[0]); i++) puts(matrix[i].name);
  for (i = 0; i < sizeof(extra) / sizeof(extra[0]); i++) puts(extra[i]);
  return 0;
 }
 CHECK(argc == 2);
 for (i = 0; i < sizeof(matrix) / sizeof(matrix[0]); i++) {
  if (!strcmp(argv[1], matrix[i].name)) {
   if (matrix[i].legal) admit(matrix[i].state); else deny(matrix[i].state);
   printf("ok - %s\n", argv[1]);
   return 0;
  }
 }
 for (i = 0; i < sizeof(extra) / sizeof(extra[0]); i++)
  if (!strcmp(argv[1], extra[i])) break;
 CHECK(i < sizeof(extra) / sizeof(extra[0]));
 switch (i) {
 case 0: busy_no_cleanup(); break;
 case 1: invalid_end(CHANGE_PHASE); break;
 case 2: invalid_end(UPGRADE_NATIVE); break;
 case 3: invalid_end(DOWNGRADE_NATIVE); break;
 case 4: invalid_end(UPGRADE_GPU); break;
 case 5: invalid_end(DOWNGRADE_GPU); break;
 case 6: fill_pair_visibility_preserved(); break;
 case 7: late_resource_held(); break;
 case 8: hold_wins_before_begin(); break;
 case 9: invalid_ticket(); break;
 default: CHECK(0);
 }
 printf("ok - %s\n", argv[1]);
 return 0;
}
