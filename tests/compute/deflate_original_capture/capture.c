// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "linux/io_uring.h"
#include "linux/xdev_ext_mech.h"
#define FRAME 8192U
#define HEAD 128U
#define SEG 4096U
#define POOL (6U * FRAME)
#define BOUND 60000U
#define MUST(c) do { if (!(c)) { fprintf(stderr, "FAIL deflate-original line=%d expression=%s errno=%d\n", __LINE__, #c, errno); goto out; } } while (0)
struct observer {
 int fd;
 void *map;
 size_t len;
 struct xdev_ext_user_ring_hdr *h;
 struct xdev_ext_user_ready *r;
 struct xdev_ext_user_done *d;
 struct xdev_ext_user_slot *s;
};
static int mech(int fd, __u32 op, __u64 arg)
{
 struct io_uring_xdev_ext_mech r = {.op = op, .arg = arg};
 int n = syscall(__NR_io_uring_register, fd, IORING_REGISTER_XDEV_EXT_MECH, &r, 1);
 return n < 0 ? -errno : n;
}
static int span(__u64 off, size_t n, __u64 len)
{
 return off <= len && n <= len - off;
}
static int observer_open(int ring, struct observer *o)
{
 struct xdev_ext_mech_user_stage r = {.size = sizeof(r), .entries = 1, .eventfd = -1};
 if (mech(ring, XDEV_EXT_MECH_OP_USER_STAGE, (uintptr_t)&r)) return -1;
 o->fd = r.fd; o->len = r.off.mmap_size;
 if (!o->len || o->len > 1048576 || r.off.hdr % 8 || r.off.ready % 8 ||
     r.off.done % 8 || r.off.slots % 8 ||
     !span(r.off.hdr, sizeof(*o->h), o->len) ||
     !span(r.off.ready, sizeof(*o->r), o->len) ||
     !span(r.off.done, sizeof(*o->d), o->len) ||
     !span(r.off.slots, sizeof(*o->s), o->len)) return -1;
 o->map = mmap(NULL, o->len, PROT_READ | PROT_WRITE, MAP_SHARED, o->fd, 0);
 if (o->map == MAP_FAILED) { o->map = NULL; return -1; }
 o->h = (void *)((char *)o->map + r.off.hdr);
 o->r = (void *)((char *)o->map + r.off.ready);
 o->d = (void *)((char *)o->map + r.off.done);
 o->s = (void *)((char *)o->map + r.off.slots);
 return 0;
}
static void observer_close(struct observer *o)
{
 if (o->map) munmap(o->map, o->len);
 if (o->fd >= 0) close(o->fd);
}
/* The existing depth-one USER ring, with a correctness wait bound only. */
static int observe(struct observer *o, const unsigned char *pool, unsigned char *bytes,
                   unsigned capacity, unsigned *produced, unsigned char *allowed,
                   struct xdev_ext_user_ready *ready)
{
 unsigned i, count = 0;
 struct xdev_ext_user_frame f[XDEV_EXT_MECH_MAX_FRAMES];
 *produced = 0;
 for (i = 0; i < BOUND; i++) {
  __u32 prod = __atomic_load_n(&o->h->ready_prod, __ATOMIC_ACQUIRE);
  if (prod != o->h->ready_cons) break;
  if (__atomic_load_n(&o->h->kernel_flags, __ATOMIC_ACQUIRE) & XDEV_EXT_USER_K_STOPPED) return -1;
  usleep(1000);
 }
 if (i == BOUND || __atomic_load_n(&o->h->ready_prod, __ATOMIC_ACQUIRE) - o->h->ready_cons != 1) return -1;
 *ready = *o->r;
 if (ready->slot || !ready->ticket || !ready->nr_frames || ready->nr_frames > 2 ||
     __atomic_load_n(&o->s->ticket, __ATOMIC_ACQUIRE) != ready->ticket ||
     o->s->nr_frames != ready->nr_frames) return -1;
 for (i = 0; i < ready->nr_frames; i++) {
  f[i].umem_addr = __atomic_load_n(&o->s->f[i].umem_addr, __ATOMIC_RELAXED);
  f[i].data_off = __atomic_load_n(&o->s->f[i].data_off, __ATOMIC_RELAXED);
  f[i].data_len = __atomic_load_n(&o->s->f[i].data_len, __ATOMIC_RELAXED);
  f[i].capacity = __atomic_load_n(&o->s->f[i].capacity, __ATOMIC_RELAXED);
  f[i].out_len = __atomic_load_n(&o->s->f[i].out_len, __ATOMIC_RELAXED);
 }
 __atomic_thread_fence(__ATOMIC_ACQUIRE);
 if (__atomic_load_n(&o->s->ticket, __ATOMIC_RELAXED) != ready->ticket) return -1;
 for (i = 0; i < ready->nr_frames; i++) {
  unsigned n = f[i].data_len;
  __u64 start = f[i].umem_addr + f[i].data_off;
  if ((i && f[i].umem_addr != f[0].umem_addr + i * FRAME) ||
      f[i].umem_addr % FRAME || f[i].umem_addr < FRAME ||
      !span(f[i].umem_addr, FRAME, POOL) || f[i].data_off != HEAD ||
      !n || n > SEG || f[i].capacity != FRAME - HEAD ||
      f[i].out_len != n || count > capacity || n > capacity - count) return -1;
  printf("FRAME observed=%u umem_addr=%llu data_off=%u data_len=%u capacity=%u ticket=%llu batch=%llu\n",
         i, (unsigned long long)f[i].umem_addr, f[i].data_off, n, f[i].capacity,
         (unsigned long long)ready->ticket, (unsigned long long)ready->batch_id);
  memcpy(bytes + count, pool + start, n);
  count += n;
  *produced = count; /* Retain an observed prefix even if a later check fails. */
 }
 /* Capacity-exterior guards; compressor may legally touch unwritten capacity. */
 for (i = 0; i < ready->nr_frames; i++) {
  __u64 start = f[i].umem_addr + HEAD;
  if (allowed[start]) return -1; /* outputs must be disjoint */
  memset(allowed + start, 1, SEG);
 }
 /* The compressor reserves two frames even if only one is produced. */
 if (capacity == 2 * SEG && ready->nr_frames == 1) {
  __u64 next = f[0].umem_addr + FRAME + HEAD;
  if (!span(next, SEG, POOL) || allowed[next]) return -1;
  memset(allowed + next, 1, SEG);
 }
 __atomic_store_n(&o->h->ready_cons, o->h->ready_cons + 1, __ATOMIC_RELEASE);
 *produced = count;
 return 0;
}
static int release_observation(struct observer *o, const struct xdev_ext_user_ready *r)
{
 __u32 prod = o->h->done_prod;
 if (prod - __atomic_load_n(&o->h->done_cons, __ATOMIC_ACQUIRE) >= 1) return -1;
 *o->d = (struct xdev_ext_user_done){.ticket = r->ticket, .slot = r->slot};
 __atomic_store_n(&o->h->done_prod, prod + 1, __ATOMIC_RELEASE);
 return ioctl(o->fd, XDEV_EXT_USER_IOC_KICK, 0);
}
static int emit(const char *dir, const char *name, const unsigned char *p, unsigned n)
{
 char path[4096];
 int count = snprintf(path, sizeof(path), "%s/%s.bin", dir, name);
 FILE *f;
 if (!n) return -1;
 /* Console bytes survive guest poweroff even if the local artifact fails. */
 printf("BYTES %s len=%u hex=", name, n);
 for (unsigned i = 0; i < n; i++) printf("%02x", p[i]);
 putchar('\n');
 if (ferror(stdout) || count < 0 || (size_t)count >= sizeof(path)) return -1;
 f = fopen(path, "wbx");
 if (!f) return -1;
 if (fwrite(p, 1, n, f) != n) { fclose(f); return -1; }
 return fclose(f) ? -1 : 0;
}
/* Failure-only evidence: fixed six actual frames per initialized image. */
static void diagnostic_pool(const char *dir, const char *name, const char *kind,
                            const unsigned char *image)
{
 char artifact[96];
 for (unsigned f = 0; f < 6; f++) {
  snprintf(artifact, sizeof(artifact), "diag.%s.%s.f%u", name, kind, f);
  if (emit(dir, artifact, image + f * FRAME, FRAME))
   fprintf(stderr, "DIAGNOSTIC_FAILURE artifact=%s errno=%d\n", artifact, errno);
 }
}
static int one(int iaa, const unsigned char *input, const char *dir,
               unsigned char *compressed, unsigned *compressed_len)
{
 int ret = 1, ring = -1, token = -1, created = 0, pool_ready = 0, snapshot_ready = 0;
 int observed;
 unsigned char *pool = MAP_FAILED, *before = NULL, *compressed_pool = NULL, *allowed = NULL;
 unsigned char restored[SEG];
 unsigned restored_len = 0, comp_frames[6] = {0};
 struct observer first = {.fd = -1}, final = {.fd = -1};
 struct xdev_ext_user_ready a, b;
 struct io_uring_params p = {0};
 struct io_uring_xdev_ext_umem_reg reg = {.size = POOL, .frame_size = FRAME};
 struct xdev_ext_mech_create c = {.abi_version = XDEV_EXT_MECH_ABI_VERSION,
  .nr_stages = 4, .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1,
  .depth = 1, .eventfd = -1, .layout = {FRAME, HEAD, SEG, SEG}};
 __u32 index = 0;
 struct xdev_ext_mech_start start = {.nr_batches = 1, .flags = XDEV_EXT_MECH_START_F_USER_FRAMES,
  .nr_user_frames = 1, .user_frames = (uintptr_t)&index};
 struct xdev_ext_mech_stats st = {0};
 const char *name = iaa ? "iaa" : "cpu";
 char artifact[32];
 ring = syscall(__NR_io_uring_setup, 8, &p); MUST(ring >= 0);
 pool = mmap(NULL, POOL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); MUST(pool != MAP_FAILED);
 before = malloc(POOL); compressed_pool = malloc(POOL); allowed = calloc(1, POOL);
 MUST(before && compressed_pool && allowed);
 memset(pool, 0x97, POOL); memcpy(pool + HEAD, input, SEG); memcpy(before, pool, POOL);
 pool_ready = 1;
 reg.addr = (uintptr_t)pool;
 MUST(!syscall(__NR_io_uring_register, ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1));
 MUST(!observer_open(ring, &first)); MUST(!observer_open(ring, &final));
 token = eventfd(0, EFD_CLOEXEC); MUST(token >= 0);
 c.st[0] = (struct xdev_ext_mech_stage_uapi){
  .class_id = iaa ? XDEV_EXT_MECH_CLASS_IAA : XDEV_EXT_MECH_CLASS_CPU,
  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = iaa ? token : -1,
  .flags = iaa ? XDEV_EXT_IAA_F_SOFTWARE : 0,
  .arg0 = iaa ? 1 : XDEV_EXT_CPU_XFORM_DEFLATE, .arg1 = 2 * SEG};
 c.st[1] = (struct xdev_ext_mech_stage_uapi){.class_id = XDEV_EXT_MECH_CLASS_USER,
  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = first.fd, .arg0 = BOUND};
 c.st[2] = (struct xdev_ext_mech_stage_uapi){
  .class_id = iaa ? XDEV_EXT_MECH_CLASS_IAA : XDEV_EXT_MECH_CLASS_CPU,
  .direction = iaa ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
  .fd = iaa ? token : -1, .flags = iaa ? XDEV_EXT_IAA_F_SOFTWARE : 0,
  .arg0 = iaa ? 3 : XDEV_EXT_CPU_XFORM_INFLATE, .arg1 = SEG};
 c.st[3] = (struct xdev_ext_mech_stage_uapi){.class_id = XDEV_EXT_MECH_CLASS_USER,
  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = final.fd, .arg0 = BOUND};
 MUST(!mech(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c)); created = 1;
 start.session_id = c.session_id;
 MUST(!mech(ring, XDEV_EXT_MECH_OP_START, (uintptr_t)&start));
 observed = observe(&first, pool, compressed, 2 * SEG, compressed_len, allowed, &a);
 if (*compressed_len) {
  snprintf(artifact, sizeof(artifact), "%s.deflate", name);
  MUST(!emit(dir, artifact, compressed, *compressed_len));
 }
 MUST(!observed);
 MUST(*compressed_len && *compressed_len <= 2 * SEG);
 memcpy(compressed_pool, pool, POOL); snapshot_ready = 1;
 for (unsigned f = 1; f < 6; f++) comp_frames[f] = allowed[f * FRAME + HEAD];
 MUST(!memcmp(pool, before, FRAME));
 MUST(!release_observation(&first, &a));
 observed = observe(&final, pool, restored, SEG, &restored_len, allowed, &b);
 if (restored_len) {
  snprintf(artifact, sizeof(artifact), "%s.inflate", name);
  MUST(!emit(dir, artifact, restored, restored_len));
 }
 MUST(!observed);
 MUST(a.batch_id == b.batch_id && a.key == b.key && restored_len == SEG);
 MUST(!memcmp(restored, input, SEG)); MUST(!memcmp(pool, before, FRAME));
 /* Preserve every full compressed frame, including its original guards. */
 for (unsigned f = 1; f < 6; f++) {
  unsigned off = f * FRAME;
  if (comp_frames[f])
   MUST(!memcmp(pool + off, compressed_pool + off, FRAME));
 }
 for (unsigned i = 0; i < POOL; i++) if (!allowed[i]) MUST(pool[i] == before[i]);
 MUST(!release_observation(&final, &b));
 for (unsigned i = 0; i < BOUND; i++) {
  st = (struct xdev_ext_mech_stats){.session_id = c.session_id};
  MUST(!mech(ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&st));
  if (st.batches_done || st.batches_abort || st.sequestered || st.last_err) break;
  usleep(1000);
 }
 MUST(st.batches_done == 1 && !st.batches_abort && !st.rejects && !st.protocol_err &&
      !st.timeouts && !st.sequestered && !st.inflight && !st.last_err);
 for (unsigned i = 0; i < 4; i++) MUST(st.submitted[i] == 1 && st.completed[i] == 1);
 MUST(!mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id)); created = 0;
 MUST(!memcmp(pool, before, FRAME));
 for (unsigned i = 0; i < POOL; i++) if (!allowed[i]) MUST(pool[i] == before[i]);
 printf("CASE %s PASS compressed=%u restored=%u source_unchanged=1 compressed_source_unchanged=1 pool_guards=1 stages=1,1,1,1 stop=0\n", name, *compressed_len, restored_len);
 ret = 0;
out:
 if (ret && pool_ready) {
  diagnostic_pool(dir, name, "pool", pool);
  diagnostic_pool(dir, name, "initial", before);
  if (snapshot_ready) diagnostic_pool(dir, name, "compressed_snapshot", compressed_pool);
 }
 if (created && ring >= 0) {
  int stop = mech(ring, XDEV_EXT_MECH_OP_STOP, c.session_id);
  fprintf(stderr, "CLEANUP %s stop=%d\n", name, stop);
 }
 if (ring >= 0) close(ring);
 observer_close(&first); observer_close(&final);
 if (token >= 0) close(token);
 if (pool != MAP_FAILED) munmap(pool, POOL);
 free(before); free(compressed_pool); free(allowed);
 return ret;
}
int main(int argc, char **argv)
{
 struct bpf_object *obj = NULL;
 struct bpf_link *links[3] = {NULL, NULL, NULL};
 const char *maps[] = {"capture_cpu", "capture_iaa", "capture_user"};
 struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
 struct utsname u;
 unsigned char input[SEG], cpu[2 * SEG], iaa[2 * SEG];
 unsigned nc = 0, ni = 0;
 int ret = 1;
 setbuf(stdout, NULL);
 if (argc != 3 || !getenv("XDEV_EXT_DEFLATE_ORIGINAL_GUEST") ||
     strcmp(getenv("XDEV_EXT_DEFLATE_ORIGINAL_GUEST"), "1")) {
  fprintf(stderr, "usage: XDEV_EXT_DEFLATE_ORIGINAL_GUEST=1 %s PLANS_BPF_OBJECT NEW_OUTPUT_DIRECTORY\n", argv[0]); return 2;
 }
 MUST(!setrlimit(RLIMIT_MEMLOCK, &limit)); MUST(!uname(&u));
 printf("KERNEL sysname=%s release=%s version=%s machine=%s\n", u.sysname, u.release, u.version, u.machine);
 puts("PARAM CPU algorithm=deflate driver=deflate-generic type=0 mask=CRYPTO_ALG_ASYNC request_flags=0 xforms=8,9 capacities=8192,4096");
 puts("PARAM IAA software=1 algorithm=deflate driver=deflate-generic type=0 mask=0 request_flags=CRYPTO_TFM_REQ_MAY_BACKLOG directions=TO_DEVICE,FROM_DEVICE capacities=8192,4096");
 puts("PARAM deflate=locked-upstream-defaults level=Z_DEFAULT_COMPRESSION method=Z_DEFLATED windowBits=-11 memLevel=MAX_MEM_LEVEL strategy=Z_DEFAULT_STRATEGY timing=none");
 for (unsigned i = 0; i < SEG; i++) input[i] = ((i % 64) * 13 + 7) ^ (((i / 64) % 7) * 29);
 MUST(!emit(argv[2], "input", input, SEG));
 obj = bpf_object__open_file(argv[1], NULL); MUST(obj && !libbpf_get_error(obj));
 MUST(!bpf_object__load(obj));
 for (unsigned i = 0; i < 3; i++) {
  struct bpf_map *m = bpf_object__find_map_by_name(obj, maps[i]); MUST(m);
  links[i] = bpf_map__attach_struct_ops(m); MUST(links[i] && !libbpf_get_error(links[i]));
 }
 MUST(!one(0, input, argv[2], cpu, &nc));
 MUST(!one(1, input, argv[2], iaa, &ni));
 printf("COMPARISON cpu_len=%u iaa_len=%u compressed_equal=%u\n", nc, ni, nc == ni && !memcmp(cpu, iaa, nc));
 puts("XDEV_EXT_DEFLATE_ORIGINAL=PASS classes=CPU,IAA_SOFTWARE actual_kernel_transforms=1 exact_bytes=1 timing=none");
 ret = 0;
out:
 for (unsigned i = 0; i < 3; i++) if (links[i] && !libbpf_get_error(links[i])) bpf_link__destroy(links[i]);
 if (obj && !libbpf_get_error(obj)) bpf_object__close(obj);
 return ret;
}
