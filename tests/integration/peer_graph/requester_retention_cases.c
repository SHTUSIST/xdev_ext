/* SPDX-License-Identifier: GPL-2.0 */
#include "requester_retention_host.h"
#include <linux/xdev_ext_requester_retention.h>
#include RETENTION_CORE

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: FAIL %s\n", __func__, __LINE__, #c); exit(1); } } while (0)
#define MiB (1024ULL * 1024)
#define reserve xdev_ext_requester_retention_reserve
#define retain xdev_ext_requester_retention_retain
#define release xdev_ext_requester_retention_release
static struct xdev_ext_requester_retention_stats snap(struct pci_dev *p)
{
 struct xdev_ext_requester_retention_stats s;
 memset(&s, 0xa5, sizeof(s));
 xdev_ext_requester_retention_snapshot(p, &s);
 CHECK(s.global_limit == 64 * MiB);
 CHECK(s.global_reserved_bytes <= s.global_limit);
 CHECK(s.global_retained_bytes <= s.global_reserved_bytes);
 CHECK(s.retained_generations <= s.generations);
 return s;
}
static void balanced(void)
{
 struct pci_dev p = {0};
 for (int i = 0; i < 1000; i++) {
  struct xdev_ext_requester_retention *r = reserve(&p, 2, 4096);
  CHECK(!IS_ERR_OR_NULL(r));
  struct xdev_ext_requester_retention_stats s = snap(&p);
  CHECK(s.generations == 1 && s.reserved_bytes == 4096);
  release(r);
  s = snap(&p);
  CHECK(!s.generations && !s.retained_generations && !s.reserved_bytes && !s.retained_bytes);
  CHECK(!s.global_reserved_bytes && !s.global_retained_bytes);
 }
 CHECK(atomic_load(&p.refs) == 0);
}
static void per_device(void)
{
 struct pci_dev p = {0};
 struct xdev_ext_requester_retention *a = reserve(&p, 2, 100);
 struct xdev_ext_requester_retention *b = reserve(&p, 2, 200);
 CHECK(!IS_ERR_OR_NULL(a) && !IS_ERR_OR_NULL(b));
 CHECK(IS_ERR(reserve(&p, 2, 1)));
 struct xdev_ext_requester_retention_stats s = snap(&p);
 CHECK(s.generations == 2 && s.reserved_bytes == 300);
 release(a);
 a = reserve(&p, 2, 300);
 CHECK(!IS_ERR_OR_NULL(a));
 release(a); release(b);
 CHECK(snap(&p).global_reserved_bytes == 0);
}
static void retain_once(void)
{
 struct pci_dev p = {0};
 struct xdev_ext_requester_retention *r = reserve(&p, 2, 4096);
 CHECK(!IS_ERR_OR_NULL(r));
 retain(r, 1024); retain(r, 2048); retain(r, 1024);
 struct xdev_ext_requester_retention_stats s = snap(&p);
 CHECK(s.generations == 1 && s.retained_generations == 1);
 CHECK(s.reserved_bytes == 4096 && s.retained_bytes == 1024);
 CHECK(s.global_reserved_bytes == 4096 && s.global_retained_bytes == 1024);
}
static void retained_release(void)
{
 struct pci_dev p = {0};
 struct xdev_ext_requester_retention *r = reserve(&p, 1, 4096);
 CHECK(!IS_ERR_OR_NULL(r)); retain(r, 768); release(r); release(r);
 struct xdev_ext_requester_retention_stats s = snap(&p);
 CHECK(s.generations == 1 && s.retained_generations == 1);
 CHECK(s.reserved_bytes == 4096 && s.retained_bytes == 768);
 CHECK(IS_ERR(reserve(&p, 1, 1)));
 CHECK(atomic_load(&p.refs) > 0);
}
static void new_session(void)
{
 struct pci_dev p = {0};
 for (int session = 0; session < 4; session++) {
  struct xdev_ext_requester_retention *r = reserve(&p, 4, 4096);
  CHECK(!IS_ERR_OR_NULL(r)); retain(r, 64); release(r);
 }
 /* Dropping every driver-owned record variable does not reset core charges. */
 CHECK(IS_ERR(reserve(&p, 4, 4096)));
 struct xdev_ext_requester_retention_stats s = snap(&p);
 CHECK(s.generations == 4 && s.retained_generations == 4);
 CHECK(s.reserved_bytes == 16384 && s.retained_bytes == 256);
}
static void global_limit(void)
{
 struct pci_dev p = {0}, q = {0};
 struct xdev_ext_requester_retention *a = reserve(&p, 10, 32 * MiB);
 struct xdev_ext_requester_retention *b = reserve(&q, 10, 32 * MiB);
 CHECK(!IS_ERR_OR_NULL(a) && !IS_ERR_OR_NULL(b));
 CHECK(IS_ERR(reserve(&q, 10, 1)));
 CHECK(snap(&p).global_reserved_bytes == 64 * MiB);
 release(b);
 b = reserve(&q, 10, 32 * MiB);
 CHECK(!IS_ERR_OR_NULL(b));
 retain(a, 8 * MiB); release(a); release(b);
 struct xdev_ext_requester_retention_stats s = snap(&q);
 CHECK(s.global_reserved_bytes == 32 * MiB && s.global_retained_bytes == 8 * MiB);
 CHECK(IS_ERR(reserve(&q, 10, 32 * MiB + 1)));
}
static void overflow(void)
{
 struct pci_dev p = {0};
 CHECK(IS_ERR(reserve(&p, 1, UINT64_MAX)));
 CHECK(IS_ERR(reserve(&p, 1, 64 * MiB + 1)));
 CHECK(IS_ERR(reserve(&p, 0, 4096)));
 CHECK(IS_ERR(reserve(&p, 1, 0)));
 CHECK(!snap(&p).global_reserved_bytes);
 struct xdev_ext_requester_retention *a = reserve(&p, 2, 4096);
 CHECK(!IS_ERR_OR_NULL(a));
 CHECK(IS_ERR(reserve(&p, 2, UINT64_MAX - 4095)));
 CHECK(snap(&p).global_reserved_bytes == 4096);
 release(a);
}
static void distinct_devices(void)
{
 struct pci_dev p = {0}, q = {0};
 struct xdev_ext_requester_retention *a = reserve(&p, 1, 100);
 struct xdev_ext_requester_retention *b = reserve(&q, 1, 200);
 CHECK(!IS_ERR_OR_NULL(a) && !IS_ERR_OR_NULL(b));
 retain(a, 80);
 struct xdev_ext_requester_retention_stats ps = snap(&p), qs = snap(&q);
 CHECK(ps.generations == 1 && ps.reserved_bytes == 100 && ps.retained_bytes == 80);
 CHECK(qs.generations == 1 && qs.reserved_bytes == 200 && !qs.retained_bytes);
 CHECK(qs.global_reserved_bytes == 300 && qs.global_retained_bytes == 80);
 release(b);
 CHECK(!snap(&q).generations && snap(&p).generations == 1);
}
#define THREADS 64
struct race_arg { struct pci_dev *pdev; unsigned limit; u64 bytes; struct xdev_ext_requester_retention *r; };
static pthread_barrier_t gate;
static void *race_reserve(void *arg)
{
 struct race_arg *a = arg;
 pthread_barrier_wait(&gate);
 a->r = reserve(a->pdev, a->limit, a->bytes);
 return NULL;
}
static void race(int global)
{
 struct pci_dev devices[THREADS] = {0};
 pthread_t threads[THREADS]; struct race_arg args[THREADS];
 pthread_barrier_init(&gate, NULL, THREADS);
 for (int i = 0; i < THREADS; i++) {
  args[i] = (struct race_arg){ .pdev = &devices[global ? i : 0], .limit = global ? 1 : 7, .bytes = global ? 4 * MiB : 4096 };
  CHECK(!pthread_create(&threads[i], NULL, race_reserve, &args[i]));
 }
 unsigned successes = 0;
 for (int i = 0; i < THREADS; i++) { CHECK(!pthread_join(threads[i], NULL)); CHECK(args[i].r != NULL); successes += !IS_ERR(args[i].r); }
 CHECK(successes == (global ? 16 : 7));
 struct xdev_ext_requester_retention_stats s = snap(&devices[0]);
 CHECK(s.global_reserved_bytes == (global ? 64 * MiB : 7 * 4096));
 for (int i = 0; i < THREADS; i++) if (!IS_ERR(args[i].r)) release(args[i].r);
 CHECK(!snap(&devices[0]).global_reserved_bytes);
 pthread_barrier_destroy(&gate);
}
static void *race_retainer(void *arg)
{
 pthread_barrier_wait(&gate); retain(arg, 512); return NULL;
}
static void race_retain(void)
{
 struct pci_dev p = {0};
 struct xdev_ext_requester_retention *r = reserve(&p, 1, 4096);
 CHECK(!IS_ERR_OR_NULL(r)); pthread_t threads[THREADS];
 pthread_barrier_init(&gate, NULL, THREADS);
 for (int i = 0; i < THREADS; i++) CHECK(!pthread_create(&threads[i], NULL, race_retainer, r));
 for (int i = 0; i < THREADS; i++) CHECK(!pthread_join(threads[i], NULL));
 struct xdev_ext_requester_retention_stats s = snap(&p);
 CHECK(s.retained_generations == 1 && s.retained_bytes == 512 && s.global_retained_bytes == 512);
 pthread_barrier_destroy(&gate);
}
int main(int argc, char **argv)
{
 CHECK(argc == 2);
 if (!strcmp(argv[1], "balanced")) balanced();
 else if (!strcmp(argv[1], "per_device")) per_device();
 else if (!strcmp(argv[1], "retain_once")) retain_once();
 else if (!strcmp(argv[1], "retained_release")) retained_release();
 else if (!strcmp(argv[1], "new_session")) new_session();
 else if (!strcmp(argv[1], "global_limit")) global_limit();
 else if (!strcmp(argv[1], "overflow")) overflow();
 else if (!strcmp(argv[1], "distinct_devices")) distinct_devices();
 else if (!strcmp(argv[1], "race_device")) race(0);
 else if (!strcmp(argv[1], "race_global")) race(1);
 else if (!strcmp(argv[1], "race_retain")) race_retain();
 else CHECK(0);
 printf("PASS %s\n", argv[1]); return 0;
}
