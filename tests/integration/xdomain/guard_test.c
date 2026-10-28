/* SPDX-License-Identifier: GPL-2.0 */
/* Independent phase/proof expectations frozen from SDD sections 3 and 3.1. */
#include "check_contract.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #x); exit(1); \
} } while (0)
#define GPU_PERMS (TB_CLEANUP_PEER_FD | TB_CLEANUP_GPU_FREE | TB_CLEANUP_CONTEXT_DESTROY)
#define BIT(op) (UINT32_C(1) << (op))

static struct tb_guard_snapshot snapshot(struct tb_guard *g)
{
 struct tb_guard_snapshot s = {0};
 tb_guard_snapshot(g, &s);
 CHECK(s.size == sizeof(s) && s.version == TB_CHECK_VERSION);
 CHECK(s.cleanup_permissions == tb_guard_cleanup_permissions(g));
 return s;
}
static void operation(struct tb_guard *g, enum tb_operation op, enum tb_phase next,
                      bool native_safe, bool gpu_safe)
{
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, op, &ticket) == 0);
 CHECK(ticket != 0);
 CHECK(tb_guard_end(g, ticket, next, native_safe, gpu_safe) == 0);
 CHECK(snapshot(g).phase == next);
}
enum stage {
 S_NEW, S_OPEN, S_FILLED, S_CREATED, S_STARTED, S_DONE,
 S_STOPPED, S_PAIR, S_VISIBLE, S_VERIFIED, S_CLOSED, S_HELD
};
static struct tb_guard *at_stage(enum stage stage)
{
 struct tb_guard *g = NULL;
 CHECK(tb_guard_new(TB_BACKING_GPU, &g) == 0 && g != NULL);
 if (stage == S_NEW) return g;
 if (stage == S_HELD) {
  tb_guard_hold(g, TB_HOLD_CANCEL);
  return g;
 }
 operation(g, TB_OP_GPU_OPEN, TB_PHASE_GPU_READY, true, true);
 if (stage == S_OPEN) return g;
 if (stage == S_CLOSED) {
  operation(g, TB_OP_GPU_CLOSE, TB_PHASE_CLOSED, true, true);
  return g;
 }
 operation(g, TB_OP_GPU_FILL, TB_PHASE_GPU_READY, true, true);
 if (stage == S_FILLED) return g;
 operation(g, TB_OP_CREATE, TB_PHASE_SESSION_CREATED, false, true);
 if (stage == S_CREATED) return g;
 operation(g, TB_OP_START, TB_PHASE_START_ACCEPTED, false, true);
 if (stage == S_STARTED) return g;
 operation(g, TB_OP_WAIT, TB_PHASE_TRANSPORT_DONE, false, true);
 if (stage == S_DONE) return g;
 operation(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, true);
 if (stage == S_STOPPED) return g;
 CHECK(tb_guard_pair_stopped(g) == 0);
 if (stage == S_PAIR) return g;
 operation(g, TB_OP_VISIBLE, TB_PHASE_DRAINED_SAFE, true, true);
 if (stage == S_VISIBLE) return g;
 operation(g, TB_OP_GPU_VERIFY, TB_PHASE_VERIFIED, true, true);
 return g;
}
static void matrix(void)
{
 /* Rows distinguish equal phases with different FILL/pair/visibility proofs. */
 static const struct {
  enum stage stage;
  uint32_t admitted;
 } expected[] = {
  {S_NEW, BIT(TB_OP_GPU_OPEN) | BIT(TB_OP_EPOCH_CLOSE)},
  {S_OPEN, BIT(TB_OP_GPU_FILL) | BIT(TB_OP_EPOCH_CLOSE) | BIT(TB_OP_GPU_CLOSE)},
  {S_FILLED, BIT(TB_OP_GPU_FILL) | BIT(TB_OP_CREATE) | BIT(TB_OP_EPOCH_CLOSE) | BIT(TB_OP_GPU_CLOSE)},
  {S_CREATED, BIT(TB_OP_START) | BIT(TB_OP_STOP)},
  {S_STARTED, BIT(TB_OP_WAIT) | BIT(TB_OP_STOP)},
  {S_DONE, BIT(TB_OP_STOP)},
  {S_STOPPED, BIT(TB_OP_EPOCH_CLOSE)},
  {S_PAIR, BIT(TB_OP_GPU_FILL) | BIT(TB_OP_VISIBLE) |
   BIT(TB_OP_EPOCH_CLOSE) | BIT(TB_OP_GPU_CLOSE)},
  {S_VISIBLE, BIT(TB_OP_GPU_FILL) | BIT(TB_OP_VISIBLE) | BIT(TB_OP_GPU_VERIFY) |
   BIT(TB_OP_EPOCH_CLOSE) | BIT(TB_OP_GPU_CLOSE)},
  {S_VERIFIED, BIT(TB_OP_GPU_FILL) | BIT(TB_OP_EPOCH_CLOSE) | BIT(TB_OP_GPU_CLOSE)},
  {S_CLOSED, 0}, {S_HELD, 0},
 };
 size_t i;
 for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
  for (int op = TB_OP_GPU_OPEN; op <= TB_OP_GPU_CLOSE; op++) {
   struct tb_guard *g = at_stage(expected[i].stage);
   uint64_t ticket = 0;
   int ret = tb_guard_begin(g, (enum tb_operation)op, &ticket);
   bool allow = (expected[i].admitted & BIT(op)) != 0;
   if ((allow && ret != 0) || (!allow && ret != -EPERM)) {
    fprintf(stderr, "phase-table row=%zu op=%d expected=%s got=%d\n",
            i, op, allow ? "admit" : "deny", ret);
    exit(1);
   }
   if (allow) CHECK(ticket != 0);
   /* Deliberately retain active/HELD fixtures: no test-side forced destructor. */
  }
 }
}
static void open_without_fill(void)
{
 struct tb_guard *g = at_stage(S_OPEN);
 struct tb_guard_snapshot s = snapshot(g);
 uint64_t ticket = 0;
 CHECK(s.phase == TB_PHASE_GPU_READY && s.native_safe && s.gpu_safe);
 CHECK((s.cleanup_permissions & GPU_PERMS) == GPU_PERMS);
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == -EPERM);
 operation(g, TB_OP_GPU_FILL, TB_PHASE_GPU_READY, true, true);
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == 0);
 s = snapshot(g);
 CHECK(s.phase == TB_PHASE_CREATE_ATTEMPTED && !s.native_safe);
 CHECK(s.cleanup_permissions == 0);
}
static void local_stop_no_pair(void)
{
 struct tb_guard *g = at_stage(S_STOPPED);
 struct tb_guard_snapshot s = snapshot(g);
 uint64_t ticket = 0;
 CHECK(s.native_safe && s.gpu_safe && !s.pair_stop_proved);
 CHECK(s.cleanup_permissions == TB_CLEANUP_EPOCH_FDS);
 CHECK(tb_guard_begin(g, TB_OP_GPU_VERIFY, &ticket) == -EPERM);
 CHECK(tb_guard_begin(g, TB_OP_VISIBLE, &ticket) == -EPERM);
 CHECK(tb_guard_begin(g, TB_OP_GPU_FILL, &ticket) == -EPERM);
 CHECK(tb_guard_begin(g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
 CHECK(tb_guard_pair_stopped(g) == 0);
 s = snapshot(g);
 CHECK(s.pair_stop_proved && (s.cleanup_permissions & GPU_PERMS) == GPU_PERMS);
 CHECK(tb_guard_begin(g, TB_OP_GPU_VERIFY, &ticket) == -EPERM);
 operation(g, TB_OP_VISIBLE, TB_PHASE_DRAINED_SAFE, true, true);
 operation(g, TB_OP_GPU_VERIFY, TB_PHASE_VERIFIED, true, true);
}
static void pair_before_stop_refused(void)
{
 enum stage stages[] = {S_NEW, S_OPEN, S_FILLED, S_CREATED, S_STARTED, S_DONE, S_HELD};
 for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
  struct tb_guard *g = at_stage(stages[i]);
  CHECK(tb_guard_pair_stopped(g) < 0);
  CHECK(!snapshot(g).pair_stop_proved);
 }
}
static void new_epoch_clears_proof(void)
{
 struct tb_guard *g = at_stage(S_VERIFIED);
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == -EPERM);
 operation(g, TB_OP_GPU_FILL, TB_PHASE_GPU_READY, true, true);
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == 0);
 s = snapshot(g);
 CHECK(s.phase == TB_PHASE_CREATE_ATTEMPTED && !s.native_safe);
 CHECK(!s.pair_stop_proved && s.cleanup_permissions == 0);
 CHECK(tb_guard_end(g, ticket, TB_PHASE_SESSION_CREATED, false, true) == 0);
 operation(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, true);
 CHECK(tb_guard_pair_stopped(g) == 0);
 CHECK(tb_guard_begin(g, TB_OP_GPU_VERIFY, &ticket) == -EPERM);
}
static void provider_ready(void)
{
 struct tb_guard *g = NULL;
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 CHECK(tb_guard_new(TB_BACKING_EXISTING_PROVIDER, &g) == 0);
 CHECK(tb_guard_external_ready(g, TB_READY_NONE) < 0);
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == -EPERM);
 CHECK(tb_guard_external_ready(g, TB_READY_EXISTING_PROVIDER_REGISTERED) == 0);
 s = snapshot(g);
 CHECK(s.phase == TB_PHASE_EXTERNAL_READY && !s.gpu_applicable);
 CHECK(s.backing_mode == TB_BACKING_EXISTING_PROVIDER);
 CHECK(s.external_ready_proof == TB_READY_EXISTING_PROVIDER_REGISTERED);
 CHECK(s.gpu_safe && !(s.cleanup_permissions & (TB_CLEANUP_GPU_FREE | TB_CLEANUP_CONTEXT_DESTROY)));
 CHECK(tb_guard_begin(g, TB_OP_GPU_OPEN, &ticket) == -EPERM);
 CHECK(tb_guard_begin(g, TB_OP_GPU_FILL, &ticket) == -EPERM);
 operation(g, TB_OP_CREATE, TB_PHASE_SESSION_CREATED, false, true);
 operation(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, true);
 s = snapshot(g);
 CHECK(!s.pair_stop_proved && !s.gpu_applicable && s.native_safe);
 CHECK(s.cleanup_permissions & TB_CLEANUP_EPOCH_FDS);
 CHECK(s.cleanup_permissions & TB_CLEANUP_PEER_FD);
 CHECK(!(s.cleanup_permissions & (TB_CLEANUP_GPU_FREE | TB_CLEANUP_CONTEXT_DESTROY)));
 CHECK(tb_guard_begin(g, TB_OP_GPU_VERIFY, &ticket) == -EPERM);
 CHECK(tb_guard_begin(g, TB_OP_VISIBLE, &ticket) == -EPERM);
 g = at_stage(S_NEW);
 CHECK(tb_guard_external_ready(g, TB_READY_EXISTING_PROVIDER_REGISTERED) < 0);
 CHECK(snapshot(g).phase == TB_PHASE_NEW);
}
struct late {
 pthread_mutex_t lock;
 pthread_cond_t cond;
 struct tb_guard *g;
 bool begun, release;
 int ret;
};
static void *late_completion(void *opaque)
{
 struct late *l = opaque;
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(l->g, TB_OP_GPU_FILL, &ticket) == 0);
 CHECK(pthread_mutex_lock(&l->lock) == 0);
 l->begun = true;
 CHECK(pthread_cond_signal(&l->cond) == 0);
 while (!l->release) CHECK(pthread_cond_wait(&l->cond, &l->lock) == 0);
 CHECK(pthread_mutex_unlock(&l->lock) == 0);
 l->ret = tb_guard_end(l->g, ticket, TB_PHASE_GPU_READY, true, true);
 return NULL;
}
static void late_cuda(void)
{
 pthread_t worker;
 struct late l = {.lock = PTHREAD_MUTEX_INITIALIZER,
  .cond = PTHREAD_COND_INITIALIZER, .g = at_stage(S_OPEN)};
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 CHECK(pthread_create(&worker, NULL, late_completion, &l) == 0);
 CHECK(pthread_mutex_lock(&l.lock) == 0);
 while (!l.begun) CHECK(pthread_cond_wait(&l.cond, &l.lock) == 0);
 s = snapshot(l.g);
 CHECK(s.phase == TB_PHASE_GPU_BUSY && s.cleanup_permissions == 0);
 /* Latch while owner remains blocked: guard never holds its lock over work. */
 tb_guard_hold(l.g, TB_HOLD_DEADLINE);
 tb_guard_hold(l.g, TB_HOLD_SIGNAL);
 l.release = true;
 CHECK(pthread_cond_signal(&l.cond) == 0);
 CHECK(pthread_mutex_unlock(&l.lock) == 0);
 CHECK(pthread_join(worker, NULL) == 0);
 CHECK(l.ret == -ECANCELED);
 s = snapshot(l.g);
 CHECK(s.held && s.phase == TB_PHASE_HELD && s.cleanup_permissions == 0);
 CHECK((s.hold_reasons & (TB_HOLD_DEADLINE | TB_HOLD_SIGNAL)) ==
       (TB_HOLD_DEADLINE | TB_HOLD_SIGNAL));
 CHECK(tb_guard_begin(l.g, TB_OP_CREATE, &ticket) == -EPERM);
 CHECK(tb_guard_begin(l.g, TB_OP_START, &ticket) == -EPERM);
 CHECK(tb_guard_begin(l.g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
 CHECK(tb_guard_delete(l.g) == -EPERM);
 CHECK(pthread_cond_destroy(&l.cond) == 0);
 CHECK(pthread_mutex_destroy(&l.lock) == 0);
}
static void held_destructor(void)
{
 struct tb_guard *g = at_stage(S_PAIR);
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 tb_guard_hold(g, TB_HOLD_EPIPE);
 s = snapshot(g);
 CHECK(s.held && s.phase == TB_PHASE_HELD && s.cleanup_permissions == 0);
 for (int op = TB_OP_GPU_OPEN; op <= TB_OP_GPU_CLOSE; op++)
  CHECK(tb_guard_begin(g, (enum tb_operation)op, &ticket) == -EPERM);
 CHECK(tb_guard_delete(g) == -EPERM);
 CHECK(tb_guard_pair_stopped(g) < 0);
 tb_guard_hold(g, TB_HOLD_CANCEL);
 s = snapshot(g);
 CHECK(s.held && s.cleanup_permissions == 0);
 CHECK((s.hold_reasons & (TB_HOLD_EPIPE | TB_HOLD_CANCEL)) ==
       (TB_HOLD_EPIPE | TB_HOLD_CANCEL));
}
static void ticket_proof(void)
{
 struct tb_guard *g = at_stage(S_NEW);
 uint64_t ticket = 0, other = 0;
 CHECK(tb_guard_begin(g, TB_OP_GPU_OPEN, &ticket) == 0);
 CHECK(tb_guard_begin(g, TB_OP_GPU_OPEN, &other) < 0);
 CHECK(tb_guard_end(g, ticket + 1, TB_PHASE_GPU_READY, true, true) < 0);
 CHECK(snapshot(g).phase != TB_PHASE_GPU_READY);
 CHECK(snapshot(g).cleanup_permissions == 0);
 CHECK(tb_guard_end(g, ticket, TB_PHASE_VERIFIED, true, true) < 0);
 CHECK(snapshot(g).phase != TB_PHASE_VERIFIED);
}
static void unknown_gpu_not_safe(void)
{
 struct tb_guard *g = at_stage(S_FILLED);
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket, TB_PHASE_SESSION_CREATED, false, false) == 0);
 operation(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, false);
 CHECK(tb_guard_cleanup_permissions(g) == 0);
 CHECK(tb_guard_pair_stopped(g) == 0);
 CHECK(tb_guard_cleanup_permissions(g) == 0);
 CHECK(tb_guard_begin(g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
}
static void geometry(void)
{
 static const struct { uint64_t bytes; uint32_t depth; bool valid; } inputs[] = {
  {4096, 1, true}, {4096, 4, true}, {4096, 16, true},
  {65536, 1, true}, {65536, 4, true}, {262144, 1, true},
  {65536, 16, false}, {262144, 4, false}, {262144, 16, false},
  {262144, 3, true}, {65536, 15, true}
 };
 struct tb_geometry g;
 for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
  g = (struct tb_geometry){.allocation_bytes = UINT64_C(1048576),
   .group_bytes = inputs[i].bytes, .frame_size = 65536,
   .seg_len = inputs[i].bytes < 65536 ? (uint32_t)inputs[i].bytes : 65536,
   .depth = inputs[i].depth, .native_elems = (uint32_t)(inputs[i].bytes / 4096)};
  CHECK((tb_geometry_validate(&g) == 0) == inputs[i].valid);
 }
 g = (struct tb_geometry){.allocation_bytes = 65536, .group_bytes = 4096,
  .frame_size = 65536, .seg_len = 4096, .depth = 1, .native_elems = 1};
 CHECK(tb_geometry_validate(&g) == 0);
 g.group_bytes = 4095;
 CHECK(tb_geometry_validate(&g) < 0);
 g.group_bytes = 4096;
 g.depth = 0;
 CHECK(tb_geometry_validate(&g) < 0);
 g.depth = 1;
 g.native_elems = 65;
 CHECK(tb_geometry_validate(&g) < 0);
 g.native_elems = 1;
 g.allocation_bytes = TB_MAX_ALLOCATION + 1;
 CHECK(tb_geometry_validate(&g) < 0);
 g.allocation_bytes = 65536;
 g.group_bytes = UINT64_MAX;
 CHECK(tb_geometry_validate(&g) < 0);
}
static void unsafe_gpu_create_no_start(void)
{
 struct tb_guard *g = at_stage(S_FILLED);
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 unsigned int external_start_calls = 0;
 int ret;
 CHECK(tb_guard_begin(g, TB_OP_CREATE, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket, TB_PHASE_SESSION_CREATED, false, false) == 0);
 s = snapshot(g);
 CHECK(s.phase == TB_PHASE_SESSION_CREATED && !s.native_safe && !s.gpu_safe);
 CHECK(s.cleanup_permissions == 0);
 ret = tb_guard_begin(g, TB_OP_START, &ticket);
 if (!ret) external_start_calls++;
 CHECK(ret == -EPERM);
 CHECK(external_start_calls == 0);
 operation(g, TB_OP_STOP, TB_PHASE_DRAINED_SAFE, true, false);
 s = snapshot(g);
 CHECK(s.native_safe && !s.gpu_safe && s.cleanup_permissions == 0);
 CHECK(tb_guard_pair_stopped(g) == 0);
 s = snapshot(g);
 CHECK(s.pair_stop_proved && !s.gpu_safe && s.cleanup_permissions == 0);
 CHECK(tb_guard_begin(g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
 CHECK(external_start_calls == 0);
 /* Native completion cannot turn an already false GPU proof true, even
  * if the caller supplies true. Rejecting the end or preserving false are
  * both safe; granting any cleanup based on that value is not. */
 g = at_stage(S_FILLED);
 operation(g, TB_OP_CREATE, TB_PHASE_SESSION_CREATED, false, false);
 CHECK(tb_guard_begin(g, TB_OP_STOP, &ticket) == 0);
 (void)tb_guard_end(g, ticket, TB_PHASE_DRAINED_SAFE, true, true);
 s = snapshot(g);
 CHECK(!s.gpu_safe && s.cleanup_permissions == 0);
}
static void gpu_safe_prework_failure(bool open)
{
 struct tb_guard *g = at_stage(open ? S_NEW : S_OPEN);
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, open ? TB_OP_GPU_OPEN : TB_OP_GPU_FILL, &ticket) == 0);
 CHECK(tb_guard_end(g, ticket, TB_PHASE_FAILED_SAFE, true, true) == 0);
 s = snapshot(g);
 CHECK(s.phase == TB_PHASE_FAILED_SAFE && !s.held && s.native_safe && s.gpu_safe);
 CHECK((s.cleanup_permissions & (TB_CLEANUP_EPOCH_FDS | GPU_PERMS)) ==
       (TB_CLEANUP_EPOCH_FDS | GPU_PERMS));
 operation(g, TB_OP_EPOCH_CLOSE, TB_PHASE_FAILED_SAFE, true, true);
 operation(g, TB_OP_GPU_CLOSE, TB_PHASE_CLOSED, true, true);
 CHECK(tb_guard_delete(g) == 0);
}
static void unknown_gpu_safe_exit_refused(void)
{
 struct tb_guard *g = at_stage(S_OPEN);
 struct tb_guard_snapshot s;
 uint64_t ticket = 0;
 CHECK(tb_guard_begin(g, TB_OP_GPU_FILL, &ticket) == 0);
 tb_guard_hold(g, TB_HOLD_CUDA_UNKNOWN);
 CHECK(tb_guard_end(g, ticket, TB_PHASE_FAILED_SAFE, true, true) == -ECANCELED);
 s = snapshot(g);
 CHECK(s.held && s.phase == TB_PHASE_HELD && s.cleanup_permissions == 0);
 CHECK(s.hold_reasons & TB_HOLD_CUDA_UNKNOWN);
 CHECK(tb_guard_begin(g, TB_OP_GPU_CLOSE, &ticket) == -EPERM);
 CHECK(tb_guard_delete(g) == -EPERM);
}
static const char *const names[] = {
 "guard-operation-phase-table", "gpu-open-without-fill-no-create",
 "local-stop-no-pair-no-verify", "pair-before-local-stop-refused",
 "new-epoch-clears-pair-and-visibility", "existing-provider-ready-no-gpu-claim",
 "late-cuda-success-held", "held-destructor-refused", "ticket-and-next-proof-gates",
 "stop-native-safe-gpu-unknown-no-cleanup", "geometry-frozen-positive-negative-boundaries",
 "gpu-unsafe-created-no-start-stop-preserves-gpu-proof",
 "gpu-open-safe-prework-failure-exits-admission",
 "gpu-fill-safe-prework-failure-exits-admission",
 "unknown-gpu-cannot-use-safe-failure-exit"
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
 case 0: matrix(); break;
 case 1: open_without_fill(); break;
 case 2: local_stop_no_pair(); break;
 case 3: pair_before_stop_refused(); break;
 case 4: new_epoch_clears_proof(); break;
 case 5: provider_ready(); break;
 case 6: late_cuda(); break;
 case 7: held_destructor(); break;
 case 8: ticket_proof(); break;
 case 9: unknown_gpu_not_safe(); break;
 case 10: geometry(); break;
 case 11: unsafe_gpu_create_no_start(); break;
 case 12: gpu_safe_prework_failure(true); break;
 case 13: gpu_safe_prework_failure(false); break;
 case 14: unknown_gpu_safe_exit_refused(); break;
 default: CHECK(0);
 }
 printf("ok - %s\n", argv[1]);
 return 0;
}
