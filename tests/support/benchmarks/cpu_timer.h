/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_CPU_TIMER_H
#define XDEV_EVAL_CPU_TIMER_H
/* Endpoint retention only: no sampler and no clock reads. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "native_process.h"

struct cpu_timer_row { const char *metric; uint64_t key, start_ns, end_ns; };
struct cpu_timer {
 int enabled, failed, published;
 const char *clock;
 char token[256], run_id[256], domain[256], directory[4096];
 uint64_t start_ticks;
 pid_t pid;
 struct cpu_timer_row *rows;
 size_t capacity, count;
};
static inline int cpu_timer_scalar(char *out, size_t size, const char *value, int path)
{
 size_t n;
 if (!value || !(n = strnlen(value, size)) || n >= size || (path && value[0] != '/'))
  return -EINVAL;
 memcpy(out, value, n + 1);
 return 0;
}
static inline int cpu_timer_init(struct cpu_timer *t, const char *clock, size_t capacity)
{
 const char *owner = getenv("XDEV_EXT_EVAL_CPU_OWNER");
 char owner_path[4096];
 struct stat st;
 memset(t, 0, sizeof(*t));
 if (!owner) return 0;
 t->enabled = 1;
 t->failed = 1;
 if (!clock || (strcmp(clock, "CLOCK_MONOTONIC") && strcmp(clock, "CLOCK_MONOTONIC_RAW")) ||
     !capacity || capacity > 1048576U || capacity > (64U * 1024U * 1024U) / sizeof(*t->rows) ||
     cpu_timer_scalar(owner_path, sizeof(owner_path), owner, 1) ||
     cpu_timer_scalar(t->directory, sizeof(t->directory), getenv("XDEV_EXT_EVAL_CPU_JOURNAL_DIR"), 1) ||
     cpu_timer_scalar(t->token, sizeof(t->token), getenv("XDEV_EXT_EVAL_CPU_TOKEN"), 0) ||
     cpu_timer_scalar(t->run_id, sizeof(t->run_id), getenv("XDEV_EXT_EVAL_CPU_RUN_ID"), 0) ||
     cpu_timer_scalar(t->domain, sizeof(t->domain), getenv("XDEV_EXT_EVAL_CPU_CLOCK_DOMAIN"), 0) ||
     lstat(owner_path, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
     lstat(t->directory, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077) ||
     native_process_start_ticks(&t->start_ticks) || !t->start_ticks)
  return -EINVAL;
 t->rows = (struct cpu_timer_row *)calloc(capacity, sizeof(*t->rows));
 if (!t->rows) return -ENOMEM;
 /* Fault all storage before timed work; calloc alone may leave lazy pages. */
 { volatile unsigned char *p = (volatile unsigned char *)t->rows;
   size_t i; for (i = 0; i < capacity * sizeof(*t->rows); i += 4096) p[i] = 0;
   p[capacity * sizeof(*t->rows) - 1] = 0;
 }
 t->pid = getpid(); t->clock = clock; t->capacity = capacity; t->failed = 0;
 return 0;
}
static inline int cpu_timer_metric_valid(const char *metric)
{
 size_t i;
 if (!metric || !metric[0]) return 0;
 for (i = 1; i < 128; i++) if (!metric[i]) return 1;
 return 0;
}
static inline int cpu_timer_store(struct cpu_timer *t, const char *metric, uint64_t key,
                                  uint64_t start_ns, uint64_t end_ns)
{
 struct cpu_timer_row *r;
 if (!t->enabled) return 0;
 if (t->failed || t->published || t->count >= t->capacity || !cpu_timer_metric_valid(metric) || !start_ns || end_ns <= start_ns) {
  t->failed = 1; return -EINVAL;
 }
 r = &t->rows[t->count++];
 r->metric = metric; r->key = key; r->start_ns = start_ns; r->end_ns = end_ns;
 return 0;
}
static inline void cpu_timer_json(FILE *f, const char *s)
{
 const unsigned char *p = (const unsigned char *)s;
 fputc('"', f);
 for (; *p; p++) {
  if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
  else if (*p < 32 || *p >= 127) fprintf(f, "\\u%04x", (unsigned int)*p);
  else fputc(*p, f);
 }
 fputc('"', f);
}
static inline int cpu_timer_compare(const void *left, const void *right)
{
 const struct cpu_timer_row *a = (const struct cpu_timer_row *)left;
 const struct cpu_timer_row *b = (const struct cpu_timer_row *)right;
 int metric = strcmp(a->metric, b->metric);
 return metric ? metric : a->key < b->key ? -1 : a->key > b->key;
}
static inline int cpu_timer_publish(struct cpu_timer *t)
{
 char path[4352]; size_t i; int fd, bad; FILE *f;
 if (!t->enabled) return 0;
 if (t->failed || t->published || !t->count || getpid() != t->pid) return -EINVAL;
 qsort(t->rows, t->count, sizeof(*t->rows), cpu_timer_compare);
 for (i = 1; i < t->count; i++)
  if (!cpu_timer_compare(&t->rows[i-1], &t->rows[i])) {
   t->failed = 1; return -EINVAL;
  }
 if (snprintf(path, sizeof(path), "%s/cpu-%ld-%llu.jsonl", t->directory, (long)t->pid,
              (unsigned long long)t->start_ticks) >= (int)sizeof(path)) return -ENAMETOOLONG;
 fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
 if (fd < 0) return -errno;
 f = fdopen(fd, "w");
 if (!f) { bad = errno; close(fd); unlink(path); return -bad; }
 fputs("{\"kind\":\"cpu-timer-metadata\",\"schema\":1,\"token\":", f); cpu_timer_json(f,t->token);
 fputs(",\"run_id\":",f); cpu_timer_json(f,t->run_id);
 fprintf(f,",\"pid\":%ld,\"process_start_ticks\":%llu,\"clock\":",(long)t->pid,(unsigned long long)t->start_ticks);
 cpu_timer_json(f,t->clock); fputs(",\"clock_domain\":",f); cpu_timer_json(f,t->domain);
 fprintf(f,",\"rows\":%zu,\"complete\":true}\n",t->count);
 for (i=0;i<t->count;i++) {
  const struct cpu_timer_row *r=&t->rows[i];
  fputs("{\"kind\":\"cpu-timer-span\",\"metric\":",f); cpu_timer_json(f,r->metric);
  fprintf(f,",\"key\":%llu,\"start_ns\":%llu,\"end_ns\":%llu}\n",(unsigned long long)r->key,
          (unsigned long long)r->start_ns,(unsigned long long)r->end_ns);
 }
 bad = ferror(f); if (fclose(f)) bad = 1;
 if (bad) { unlink(path); t->failed=1; return -EIO; }
 t->published=1; return 0;
}
static inline void cpu_timer_destroy(struct cpu_timer *t)
{
 if (t->enabled) { free(t->rows); t->rows=NULL; t->capacity=t->count=0; }
}
#endif
