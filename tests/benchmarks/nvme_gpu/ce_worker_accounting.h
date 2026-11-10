/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CE_WORKER_ACCOUNTING_H
#define CE_WORKER_ACCOUNTING_H

/* Proc accounting is an outer guest-worker interval, never device time. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct cwa_identity {
 uint64_t session_id, start_ticks;
 int pid;
 char comm[16];
};
struct cwa_snapshot {
 struct cwa_identity id;
 uint64_t runtime_ns, run_delay_ns, pcount, read_begin_ns, read_end_ns;
};
struct cwa_delta { uint64_t runtime_ns, run_delay_ns, pcount; };

static inline int cwa_name(uint64_t sid, char comm[16])
{
 int n;
 if (!sid) return -EINVAL;
 n = snprintf(comm, 16, "xdev_ext_mech/%llu", (unsigned long long)sid);
 return n < 0 || n >= 16 ? -EOVERFLOW : 0;
}

static inline int cwa_uint(const char *s, size_t len, uint64_t *out)
{
 uint64_t value = 0;
 size_t i;
 if (!len) return -EINVAL;
 for (i = 0; i < len; i++) {
  unsigned int digit = (unsigned char)s[i] - '0';
  if (digit > 9) return -EINVAL;
  if (value > (UINT64_MAX - digit) / 10) return -EOVERFLOW;
  value = value * 10 + digit;
 }
 *out = value;
 return 0;
}

static inline int cwa_parse_schedstat(const char *s, size_t len,
                                      struct cwa_snapshot *out)
{
 uint64_t values[3];
 size_t pos = 0, begin;
 unsigned int i;
 int ret;
 if (memchr(s, 0, len)) return -EINVAL;
 for (i = 0; i < 3; i++) {
  while (pos < len && isspace((unsigned char)s[pos])) pos++;
  begin = pos;
  while (pos < len && !isspace((unsigned char)s[pos])) pos++;
  ret = cwa_uint(s + begin, pos - begin, &values[i]);
  if (ret) return ret;
 }
 while (pos < len && isspace((unsigned char)s[pos])) pos++;
 if (pos != len) return -EINVAL;
 out->runtime_ns = values[0]; out->run_delay_ns = values[1]; out->pcount = values[2];
 return 0;
}

/* EOF is required: no successful prefix parse after a short or bounded read. */
static inline int cwa_read(const char *root, int pid, const char *file,
                            char *buf, size_t cap, size_t *len)
{
 char path[4096], extra;
 size_t used = 0;
 ssize_t got;
 int fd, ret = 0, n = snprintf(path, sizeof(path), "%s/%d/%s", root, pid, file);
 if (n < 0 || (size_t)n >= sizeof(path)) return -ENAMETOOLONG;
 fd = open(path, O_RDONLY | O_CLOEXEC);
 if (fd < 0) return -errno;
 while (used < cap - 1) {
  got = read(fd, buf + used, cap - 1 - used);
  if (got < 0) { if (errno == EINTR) continue; ret = -errno; break; }
  if (!got) break;
  used += (size_t)got;
 }
 if (!ret && used == cap - 1) {
  do { got = read(fd, &extra, 1); } while (got < 0 && errno == EINTR);
  if (got != 0) ret = got < 0 ? -errno : -EOVERFLOW;
 }
 if (close(fd) && !ret) ret = -errno;
 if (!ret && (!used || memchr(buf, 0, used))) ret = -EINVAL;
 if (ret) return ret;
 buf[used] = 0; *len = used;
 return 0;
}

static inline int cwa_comm(const char *root, int pid, char comm[16])
{
 char buf[32]; size_t len;
 int ret = cwa_read(root, pid, "comm", buf, sizeof(buf), &len);
 if (ret) return ret;
 if (len < 2 || len > 16 || buf[len - 1] != '\n' || memchr(buf, '\n', len - 1))
  return -EINVAL;
 memcpy(comm, buf, len - 1); comm[len - 1] = 0;
 return 0;
}

static inline int cwa_stat(const char *s, size_t len, int pid, const char *comm,
                            uint64_t *ticks)
{
 const char *open_paren = strchr(s, '('), *end = s + len, *p, *q, *close_paren;
 uint64_t value; unsigned int field = 4;
 int ret;
 if (!open_paren || open_paren == s || open_paren[-1] != ' ') return -EINVAL;
 ret = cwa_uint(s, (size_t)(open_paren - s - 1), &value);
 if (ret) return ret;
 if (value != (uint64_t)pid) return -ESTALE;
 close_paren = strrchr(open_paren, ')');
 if (!close_paren || (size_t)(close_paren - open_paren - 1) != strlen(comm) ||
     memcmp(open_paren + 1, comm, strlen(comm))) return -ESTALE;
 p = close_paren + 1;
 if (end - p < 4 || p[0] != ' ' || !isalpha((unsigned char)p[1]) || p[2] != ' ')
  return -EINVAL;
 p += 3;
 while (p < end) {
  int negative;
  while (p < end && isspace((unsigned char)*p)) p++;
  if (p == end) break;
  q = p; while (q < end && !isspace((unsigned char)*q)) q++;
  negative = *p == '-';
  ret = cwa_uint(p + negative, (size_t)(q - p) - negative, &value);
  if (ret) return ret;
  if (field == 22) {
   if (negative || !value) return -EINVAL;
   *ticks = value;
  }
  field++; p = q;
 }
 return field > 22 ? 0 : -EINVAL;
}

static inline int cwa_identity_read(const char *root, int pid, const char *name,
                                     struct cwa_identity *id)
{
 char first[16] = {0}, last[16] = {0}, stat[4096];
 size_t len; uint64_t ticks = 0;
 int ret = cwa_comm(root, pid, first);
 if (ret) return ret;
 if (strcmp(first, name)) return -ESTALE;
 ret = cwa_read(root, pid, "stat", stat, sizeof(stat), &len);
 if (!ret) ret = cwa_stat(stat, len, pid, name, &ticks);
 if (!ret) ret = cwa_comm(root, pid, last);
 if (ret) return ret;
 if (strcmp(first, last)) return -ESTALE;
 id->pid = pid; id->start_ticks = ticks; memcpy(id->comm, first, sizeof(id->comm));
 return 0;
}

static inline int cwa_same(const struct cwa_identity *a, const struct cwa_identity *b)
{
 return a->pid == b->pid && a->session_id == b->session_id &&
        a->start_ticks == b->start_ticks && !strcmp(a->comm, b->comm);
}

static inline int cwa_discover(const char *root, uint64_t sid, struct cwa_identity *out)
{
 struct cwa_identity found = {.session_id = sid};
 char name[16], comm[16];
 struct dirent *entry; DIR *dir;
 int matches = 0, ret = cwa_name(sid, name);
 if (ret) return ret;
 dir = opendir(root); if (!dir) return -errno;
 for (;;) {
  uint64_t pid;
  errno = 0; entry = readdir(dir);
  if (!entry) { ret = errno ? -errno : 0; break; }
  if (cwa_uint(entry->d_name, strlen(entry->d_name), &pid) || !pid || pid > INT_MAX)
   continue;
  ret = cwa_comm(root, (int)pid, comm);
  if (ret == -ENOENT || ret == -ESRCH) continue; /* unrelated task exited */
  if (ret) break;
  if (strcmp(comm, name)) continue;
  if (++matches > 1) { ret = -EEXIST; break; }
  ret = cwa_identity_read(root, (int)pid, name, &found);
  if (ret) break;
 }
 if (closedir(dir) && !ret) ret = -errno;
 if (!ret && matches != 1) ret = -ENOENT;
 if (!ret) *out = found;
 return ret;
}

static inline int cwa_clock(uint64_t *out)
{
 struct timespec ts;
 if (clock_gettime(CLOCK_MONOTONIC, &ts)) return -errno;
 if (ts.tv_sec < 0 || (uint64_t)ts.tv_sec > (UINT64_MAX - (uint64_t)ts.tv_nsec) / 1000000000ULL)
  return -EOVERFLOW;
 *out = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
 return *out ? 0 : -EINVAL;
}

static inline int cwa_snapshot(const char *root, const struct cwa_identity *id,
                                struct cwa_snapshot *out)
{
 struct cwa_identity before = {.session_id=id->session_id}, after = {.session_id=id->session_id};
 struct cwa_snapshot sample = {.id=*id};
 char buf[128]; size_t len;
 int ret = cwa_clock(&sample.read_begin_ns);
 if (!ret) ret = cwa_identity_read(root, id->pid, id->comm, &before);
 if (!ret && !cwa_same(id, &before)) ret = -ESTALE;
 if (!ret) ret = cwa_read(root, id->pid, "schedstat", buf, sizeof(buf), &len);
 if (!ret) ret = cwa_parse_schedstat(buf, len, &sample);
 if (!ret) ret = cwa_identity_read(root, id->pid, id->comm, &after);
 if (!ret && !cwa_same(id, &after)) ret = -ESTALE;
 if (!ret) ret = cwa_clock(&sample.read_end_ns);
 if (!ret && sample.read_end_ns < sample.read_begin_ns) ret = -EINVAL;
 if (!ret) *out = sample;
 return ret;
}

static inline int cwa_delta(const struct cwa_snapshot *a, const struct cwa_snapshot *b,
                             struct cwa_delta *d)
{
 if (!cwa_same(&a->id, &b->id)) return -ESTALE;
 if (!a->read_begin_ns || a->read_end_ns < a->read_begin_ns ||
     b->read_begin_ns < a->read_end_ns || b->read_end_ns < b->read_begin_ns)
  return -EINVAL;
 if (b->runtime_ns < a->runtime_ns || b->run_delay_ns < a->run_delay_ns || b->pcount < a->pcount)
  return -ERANGE;
 d->runtime_ns = b->runtime_ns - a->runtime_ns;
 d->run_delay_ns = b->run_delay_ns - a->run_delay_ns;
 d->pcount = b->pcount - a->pcount;
 return d->runtime_ns || d->run_delay_ns || d->pcount ? 0 : -ENODATA;
}
#endif
