// SPDX-License-Identifier: GPL-2.0
/* Completion-driven NET stage (requirement P4): several native descriptors in
 * flight per batch, completion from the driver callback in any context, one
 * hand-off per batch, STOP/timeout abandonment with quarantine. Pure tracker
 * from io_uring/xdev_ext_peer_net_track.h; atomic read-modify-writes are
 * counted through XDEV_EXT_PEER_NET_RMW_HOOK and used to inject interleavings.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#if !__has_include("../../../../io_uring/xdev_ext_peer_net_track.h")
int main(void)
{
 puts("not ok 1 - asynchronous NET in-flight tracker (io_uring/xdev_ext_peer_net_track.h) missing: one descriptor in flight, worker waits synchronously");
 puts("not ok 2 - exactly-once batch hand-off from native completions missing");
 puts("not ok 3 - STOP/timeout abandonment of in-flight descriptors with quarantine missing");
 return 1;
}
#else
static _Thread_local int in_hook;
static _Thread_local unsigned long rmw;
static _Thread_local unsigned long inject_at;
static _Thread_local void (*inject)(void);
static void rmw_hook(void)
{
 rmw++;
 if (inject && !in_hook && rmw == inject_at) { in_hook = 1; inject(); in_hook = 0; }
}
#define XDEV_EXT_PEER_NET_RMW_HOOK() rmw_hook()
#include "../../../../io_uring/xdev_ext_peer_net_track.h"

static int failures;
#define CHECK(c, text) do { if (!(c)) { printf("not ok - %s (line %d)\n", text, __LINE__); failures++; } } while (0)
#define HANDOFF XDEV_EXT_PEER_NET_TRACK_HANDOFF
#define PENDING XDEV_EXT_PEER_NET_TRACK_PENDING
#define LATE XDEV_EXT_PEER_NET_TRACK_LATE

static struct xdev_ext_peer_net_track t;
static int abandon_won;
static void do_abandon(void) { abandon_won += xdev_ext_peer_net_track_abandon(&t, -ECANCELED); }

static void case_success(void)
{
 int before = failures, ret, i;
 bool seq = true;
 unsigned long r;
 CHECK(XDEV_EXT_PEER_NET_TRACK_MAX >= 16, "a batch keeps all its NET descriptors in flight");
 CHECK(xdev_ext_peer_net_track_init(&t, 0) == -EINVAL, "empty batch refused");
 CHECK(xdev_ext_peer_net_track_init(&t, XDEV_EXT_PEER_NET_TRACK_MAX + 1) == -EINVAL, "oversized batch refused");
 rmw = 0;
 CHECK(!xdev_ext_peer_net_track_init(&t, 16) && rmw == 0, "init uses no atomic read-modify-write");
 CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -EINPROGRESS, "no result while descriptors are in flight");
 for (i = 0; i < 15; i++) {
  r = rmw; ret = xdev_ext_peer_net_track_complete(&t, 0, true);
  CHECK(ret == PENDING, "non-last completion leaves the batch pending");
  CHECK(rmw - r <= 1, "a non-last successful completion costs at most one atomic RMW");
 }
 ret = xdev_ext_peer_net_track_complete(&t, 0, true);
 CHECK(ret == HANDOFF, "the last completion hands the batch off");
 printf("# 16-descriptor successful batch: %lu atomic RMWs (bound 17)\n", rmw);
 CHECK(rmw <= 17, "a successful 16-descriptor hand-off costs at most posted + 1 atomic RMWs");
 seq = true; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == 0 && !seq, "clean batch: success, reusable");
 CHECK(xdev_ext_peer_net_track_complete(&t, -EIO, false) == LATE, "a surplus completion is LATE");
 seq = true; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == 0 && !seq, "and changes nothing");
 CHECK(!xdev_ext_peer_net_track_abandon(&t, -ECANCELED), "abandon after hand-off loses");
 seq = true; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == 0 && !seq, "and changes nothing");
 if (failures == before) puts("ok 1 - one hand-off per batch after its last native completion, bounded atomic cost");
}

static void case_errors(void)
{
 int before = failures;
 bool seq;
 xdev_ext_peer_net_track_init(&t, 3);
 CHECK(xdev_ext_peer_net_track_complete(&t, -EIO, true) == PENDING, "error completion first");
 CHECK(xdev_ext_peer_net_track_complete(&t, -ENOLINK, true) == PENDING, "second error");
 CHECK(xdev_ext_peer_net_track_complete(&t, 0, true) == HANDOFF, "hand-off still after the last");
 seq = true; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -EIO && !seq, "first error wins; quiesced errors are reusable");
 xdev_ext_peer_net_track_init(&t, 2);
 xdev_ext_peer_net_track_complete(&t, 0, false);
 CHECK(xdev_ext_peer_net_track_complete(&t, 0, true) == HANDOFF, "hand-off with one unquiesced element");
 seq = false; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -EIO && seq, "zero status without quiescence fails closed and sequesters");
 xdev_ext_peer_net_track_init(&t, 2);
 xdev_ext_peer_net_track_complete(&t, 0, true);
 xdev_ext_peer_net_track_complete(&t, -ETIMEDOUT, false);
 seq = false; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -ETIMEDOUT && seq, "native error without quiescence sequesters with its status");
 if (failures == before) puts("ok 2 - first native error reported; any unquiesced element sequesters the batch");
}

static void case_stop(void)
{
 int before = failures, i;
 bool seq;
 xdev_ext_peer_net_track_init(&t, 8);
 for (i = 0; i < 3; i++) xdev_ext_peer_net_track_complete(&t, 0, true);
 CHECK(xdev_ext_peer_net_track_abandon(&t, -ECANCELED), "STOP with five descriptors in flight abandons the batch");
 seq = false; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -ECANCELED && seq, "abandoned batch is sequestered (quarantine)");
 for (i = 0; i < 5; i++) CHECK(xdev_ext_peer_net_track_complete(&t, 0, true) == LATE, "late native completions after STOP publish nothing");
 CHECK(!xdev_ext_peer_net_track_abandon(&t, -ETIMEDOUT), "second abandon loses");
 seq = false; CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -ECANCELED && seq, "result keeps the first abandon reason");
 CHECK(!xdev_ext_peer_net_track_expired(0, 0, 0) && !xdev_ext_peer_net_track_expired(29999, 0, 0) &&
       xdev_ext_peer_net_track_expired(30000, 0, 0), "a native wait allows 30 s without STOP");
 CHECK(!xdev_ext_peer_net_track_expired(1099, 0, 100) && xdev_ext_peer_net_track_expired(1100, 0, 100),
       "after STOP at most the stop grace");
 CHECK(XDEV_EXT_PEER_NET_TIMEOUT_MS == 30000 && XDEV_EXT_PEER_NET_STOP_GRACE_MS <= 1000 &&
       XDEV_EXT_PEER_NET_STOP_GRACE_MS < 5000, "stop grace keeps STOP inside the 5 s drain bound");
 CHECK(!xdev_ext_peer_net_track_expired(5, UINT64_MAX - 10, 0) && xdev_ext_peer_net_track_expired(5, UINT64_MAX - 10, UINT64_MAX - 2000),
       "clock wrap is handled with unsigned differences");
 if (failures == before) puts("ok 3 - STOP/timeout abandons in-flight descriptors exactly once, late completions are inert, grace < drain bound");
}

/* Abandon injected before every atomic step of every completion. */
static void case_interleavings(void)
{
 int before = failures, posted, k, i, handoffs;
 bool seq;
 for (posted = 1; posted <= 4; posted++)
  for (k = 1; k <= 3 * posted + 4; k++) {
   xdev_ext_peer_net_track_init(&t, (unsigned)posted);
   abandon_won = 0; handoffs = 0; rmw = 0; inject = do_abandon; inject_at = (unsigned long)k;
   for (i = 0; i < posted; i++) {
    int ret = xdev_ext_peer_net_track_complete(&t, 0, true);
    handoffs += ret == HANDOFF;
   }
   inject = NULL;
   if (rmw < (unsigned long)k) { abandon_won += xdev_ext_peer_net_track_abandon(&t, -ECANCELED); }
   CHECK(handoffs + abandon_won == 1, "exactly one owner: one hand-off or one winning abandon");
   seq = !abandon_won;
   if (handoffs) CHECK(xdev_ext_peer_net_track_result(&t, &seq) == 0 && !seq, "hand-off owner sees success");
   else CHECK(xdev_ext_peer_net_track_result(&t, &seq) == -ECANCELED && seq, "abandon owner sequesters");
  }
 if (failures == before) puts("ok 4 - abandon at every atomic step of the completions keeps a single owner");
}

#define THREADS 16
static pthread_barrier_t go;
static int outcome[THREADS + 1];
static void *completer(void *arg)
{
 int i = (int)(intptr_t)arg;
 pthread_barrier_wait(&go);
 outcome[i] = xdev_ext_peer_net_track_complete(&t, 0, true);
 return NULL;
}
static void *abandoner(void *arg)
{
 (void)arg;
 pthread_barrier_wait(&go);
 outcome[THREADS] = xdev_ext_peer_net_track_abandon(&t, -ECANCELED);
 return NULL;
}
static void case_threads(void)
{
 int before = failures, iter, i, owners;
 pthread_t th[THREADS + 1];
 for (iter = 0; iter < 2000 && failures == before; iter++) {
  xdev_ext_peer_net_track_init(&t, THREADS);
  pthread_barrier_init(&go, NULL, THREADS + 1 + (iter & 1));
  for (i = 0; i < THREADS; i++) pthread_create(&th[i], NULL, completer, (void *)(intptr_t)i);
  if (iter & 1) pthread_create(&th[THREADS], NULL, abandoner, NULL);
  pthread_barrier_wait(&go);
  for (i = 0; i < THREADS + (iter & 1); i++) pthread_join(th[i], NULL);
  pthread_barrier_destroy(&go);
  owners = 0;
  for (i = 0; i < THREADS; i++) owners += outcome[i] == HANDOFF;
  if (iter & 1) owners += outcome[THREADS];
  CHECK(owners == 1, "concurrent completions and abandon: exactly one owner");
 }
 if (failures == before) puts("ok 5 - 2000 concurrent rounds of 16 completions (with and without STOP) keep exactly-once hand-off");
}

int main(void)
{
 case_success();
 case_errors();
 case_stop();
 case_interleavings();
 case_threads();
 return failures ? 1 : 0;
}
#endif
