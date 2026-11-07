// SPDX-License-Identifier: GPL-2.0
/*
 * K-KV restore worker: a KV object stored as one LBA extent on host 1's NVMe
 * is restored over one Thunderbolt/USB4 cable into host 2's GPU memory.
 *
 *   serve         host 1: NVMe READ -> XDOMAIN TX in one session worker, frames
 *                 from a system-heap dma-buf ring; one START per request.
 *   restore       host 2: XDOMAIN RX into frames of a CUDA device allocation;
 *                 per restore one START of ordered destination frames, one
 *                 request to host 1, one wait for the final notification.
 *   local-verify  one host, correctness only: NVMe READ into a dma-buf pool
 *                 with host 2's ordered destination placement, then a CPU
 *                 check of every byte (pattern) and of every other byte
 *                 (poison).  No XDOMAIN, no timing claim.
 *
 * --dst ce-vmm (restore, local-verify) replaces the destination frames for a
 * GPU without GPUDirect RDMA: the receiving stage writes each group into a
 * recycled ring of host frames (the ring's XDEV_EXT UMEM) and a CE stage
 * (XDEV_EXT_CE_STAGE_F_TARGET_RANGE, program kv_ce_place.bpf.c) copies it with
 * the GPU copy engine into a CUDA VMM allocation exported as a POSIX fd and
 * attached to the CE device, at the same place the PEER layout would put it.
 * The CPU copies no payload byte on either path; local-verify checks the
 * whole allocation (pattern inside, poison outside) through CUDA afterwards.
 * The kernel currently admits a range-target CE stage only next to an NVMe
 * stage, so restore with ce-vmm is refused at CREATE until XDOMAIN is admitted.
 *
 * Each role creates its session once at start-up and talks the worker line
 * protocol of kv_protocol.py on stdin/stdout:
 *   -> KV_READY {json}            setup done (or KV_ERROR {json}, exit 1)
 *   <- GO run=ID ordinal=R object_slba=S bytes=B dst_frame0=D seed=X verify=0|1
 *   -> KV_RESULT {json}           one restore (restore, local-verify)
 *   <- QUIT                       -> KV_BYE {json}: STOP's result (the session's
 *                                    final error) and whether resources were released;
 *                                    exit 1 if retained or a release failed
 * serve reads RESTORE/DONE lines from host 2 over TCP and logs KV_SERVED.
 * Every role refuses a plan whose keys do not exceed every key it already
 * used.  --dry-run opens no device: it validates options and answers GO with
 * the plan only.  The restore latency is CLOCK_MONOTONIC from just before
 * host 2's START to the return of its final wait; host CPU accounting is the
 * orchestrator's (run.py, kv_cpu.py).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "../../../kernel/tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "../../../kernel/include/uapi/linux/xdev_ext_peer.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_cuda.h"
#include "../../../kernel/tools/include/xdev_ext_nv_p2p_ioctl.h"
#include "kv_plan.h"
#include "kv_ce_place.h"

#define LINE_MAX_BYTES	1024
#define VERIFY_CHUNK	(64ULL << 20)
#define POISON		0xA5

enum role { ROLE_SERVE = 1, ROLE_RESTORE, ROLE_LOCAL };
/* Destination of the received groups: GPU frames (PEER), a system-heap
 * dma-buf (local-verify), or host frames plus the GPU copy engine. */
enum dst { DST_NONE = 0, DST_PEER, DST_DMABUF, DST_CE };
static const char *const dst_names[] = { "none", "peer", "dmabuf", "ce-vmm" };

struct opts {
	enum role role;
	struct kv_window w;
	struct kv_geometry g;
	const char *nvme, *nvme_prog, *xdomain_prog, *xdomain_map, *service, *sysfs_root;
	const char *listen, *peer, *gpu_bdf, *gpu_node, *token, *ce_dev, *ce_prog;
	enum dst dst;
	uint64_t link_token, pool_bytes;
	int timeout_ms;
	bool dry_run;
};

struct prog {
	struct bpf_object *obj;
	struct bpf_link *link;
};

struct worker {
	struct opts o;
	struct xdev_ext_session *s;
	struct prog nvme, xd, ce;
	struct bpf_map *ce_target;	/* kv_ce_place.bpf.c .bss: struct kv_ce_target */
	struct xdev_ext_mech_cuda cuda;
	int ctl, allocation, dmabuf, gpu, lsock, sock, ce_fd;
	uint32_t ring_frames;		/* ce-vmm: host frames of the UMEM ring */
	uint64_t pool_frames, next_key, restores, prev_done, prev_ce;
	bool dirty;
};

static uint64_t now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static uint64_t cpu_us(void)
{
	struct rusage r;

	getrusage(RUSAGE_SELF, &r);
	return (uint64_t)(r.ru_utime.tv_sec + r.ru_stime.tv_sec) * 1000000ULL +
	       (uint64_t)(r.ru_utime.tv_usec + r.ru_stime.tv_usec);
}

/* JSON string literal of a short identifier (run ids, errors, paths). */
static void jstr(FILE *f, const char *s)
{
	fputc('"', f);
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		if (*p == '"' || *p == '\\')
			fprintf(f, "\\%c", *p);
		else if (*p < 32 || *p > 126)
			fprintf(f, "\\u%04x", *p);
		else
			fputc(*p, f);
	}
	fputc('"', f);
}

static void emit_error(const char *where, int err)
{
	printf("KV_ERROR {\"where\": ");
	jstr(stdout, where);
	printf(", \"error\": %d, \"strerror\": ", err);
	jstr(stdout, strerror(err < 0 ? -err : err));
	printf("}\n");
	fflush(stdout);
}

static int parse_u64(const char *s, uint64_t *v)
{
	unsigned long long n;
	char *end;

	if (!s || !*s || *s == '-')
		return -EINVAL;
	errno = 0;
	n = strtoull(s, &end, 0);
	if (errno || *end)
		return -EINVAL;
	*v = n;
	return 0;
}

static int parse_u32(const char *s, uint32_t *v)
{
	uint64_t n;

	if (parse_u64(s, &n) || n > UINT32_MAX)
		return -EINVAL;
	*v = (uint32_t)n;
	return 0;
}

/* ---- key=value lines ---------------------------------------------------- */

struct kv_line {
	char buf[LINE_MAX_BYTES];
	char *key[16], *val[16];
	unsigned n;
};

/* "WORD k=v k=v": the word is key[0] with val[0] NULL. */
static int line_split(struct kv_line *l, const char *text)
{
	char *save = NULL, *tok;
	size_t len = strlen(text);

	if (len >= sizeof(l->buf))
		return -E2BIG;
	memcpy(l->buf, text, len + 1);
	l->n = 0;
	for (tok = strtok_r(l->buf, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
		char *eq = strchr(tok, '=');

		if (l->n == 16)
			return -E2BIG;
		if (l->n && !eq)
			return -EINVAL;
		if (eq)
			*eq++ = 0;
		l->key[l->n] = tok;
		l->val[l->n++] = eq;
	}
	return l->n ? 0 : -EINVAL;
}

static const char *line_get(const struct kv_line *l, const char *key)
{
	for (unsigned i = 1; i < l->n; i++)
		if (!strcmp(l->key[i], key))
			return l->val[i];
	return NULL;
}

static int line_u64(const struct kv_line *l, const char *key, uint64_t *v)
{
	return parse_u64(line_get(l, key), v);
}

static int run_id_ok(const char *id)
{
	if (!id || !*id || strlen(id) > 64)
		return 0;
	for (const char *p = id; *p; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
		      *p == '-' || *p == '_' || *p == '.'))
			return 0;
	return 1;
}

/* ---- programs ----------------------------------------------------------- */

/* Load one struct_ops map as a PRIVATE instance; flags resolved through BTF. */
static int load_private(const char *path, const char *map_name, const char *type_name,
			struct prog *p)
{
	struct bpf_map *map, *m;
	const struct btf_type *t;
	struct btf *btf;
	size_t size = 0;
	void *value;
	int id, err;
	bool found = false;

	p->obj = bpf_object__open_file(path, NULL);
	err = (int)libbpf_get_error(p->obj);
	if (err) {
		p->obj = NULL;
		return err;
	}
	bpf_object__for_each_map(m, p->obj)
		if (bpf_map__type(m) == BPF_MAP_TYPE_STRUCT_OPS && strcmp(bpf_map__name(m), map_name))
			bpf_map__set_autocreate(m, false);
	map = bpf_object__find_map_by_name(p->obj, map_name);
	btf = bpf_object__btf(p->obj);
	if (!map || bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS || !btf)
		return -ENOENT;
	id = btf__find_by_name_kind(btf, type_name, BTF_KIND_STRUCT);
	if (id <= 0)
		return -ENOENT;
	t = btf__type_by_id(btf, id);
	value = bpf_map__initial_value(map, &size);
	if (!value || size != t->size)
		return -EPROTO;
	for (unsigned n = 0; n < btf_vlen(t); n++) {
		const struct btf_member *mb = btf_members(t) + n;
		unsigned bits = btf_member_bit_offset(t, n);
		uint32_t flags;

		if (strcmp(btf__name_by_offset(btf, mb->name_off), "flags"))
			continue;
		if (btf_member_bitfield_size(t, n) || (bits & 7) || bits / 8 + sizeof(flags) > size)
			return -EPROTO;
		memcpy(&flags, (char *)value + bits / 8, sizeof(flags));
		flags |= XDEV_EXT_MECH_OPS_F_PRIVATE;
		memcpy((char *)value + bits / 8, &flags, sizeof(flags));
		found = true;
	}
	if (!found)
		return -EPROTO;
	err = bpf_object__load(p->obj);
	if (err)
		return err;
	p->link = bpf_map__attach_struct_ops(map);
	err = (int)libbpf_get_error(p->link);
	if (err) {
		p->link = NULL;
		return err;
	}
	return 0;
}

static void prog_free(struct prog *p)
{
	if (p->link)
		bpf_link__destroy(p->link);
	if (p->obj)
		bpf_object__close(p->obj);
	p->link = NULL;
	p->obj = NULL;
}

static int prog_fd(const struct prog *p)
{
	return p->link ? bpf_link__fd(p->link) : -1;
}

/* ---- memory ------------------------------------------------------------- */

static int heap_alloc(uint64_t len)
{
	struct dma_heap_allocation_data a = { .len = len, .fd_flags = O_RDWR | O_CLOEXEC };
	int heap = open("/dev/dma_heap/system", O_RDONLY | O_CLOEXEC), ret;

	if (heap < 0)
		return -errno;
	ret = ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a) ? -errno : (int)a.fd;
	close(heap);
	return ret;
}

static int peer_register(int ctl, int fd, __u32 flags, uint64_t va, uint64_t len)
{
	struct xdev_ext_peer_register r = { .gpu_fd = fd, .flags = flags, .gpu_va = va, .len = len };
	int ret = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &r);

	return ret < 0 ? -errno : ret;
}

/* CPU access to the dma-buf between SYNC START/END. */
static int dmabuf_cpu(int buf, uint64_t len, bool write, int (*fn)(void *, uint64_t, void *),
		      void *arg)
{
	struct dma_buf_sync sync = { .flags = DMA_BUF_SYNC_START |
		(write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ) };
	void *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, buf, 0);
	int ret, end;

	if (map == MAP_FAILED)
		return -errno;
	ret = ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync) ? -errno : fn(map, len, arg);
	sync.flags = DMA_BUF_SYNC_END | (write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ);
	end = ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync) ? -errno : 0;
	munmap(map, len);
	return ret ? ret : end;
}

static int poison_fn(void *map, uint64_t len, void *arg)
{
	(void)arg;
	memset(map, POISON, len);
	return 0;
}

struct check {
	uint64_t seed, offset, bytes, first_bad, digest, outside_bad;
	int result;
};

/* Pattern inside [offset, offset+bytes), poison everywhere else. */
static int check_fn(void *map, uint64_t len, void *arg)
{
	struct check *c = arg;
	const uint8_t *p = map;

	c->result = kv_pattern_check(c->seed, 0, p + c->offset, c->bytes, &c->first_bad);
	c->digest = kv_fnv1a(KV_FNV_OFFSET, p + c->offset, c->bytes);
	c->outside_bad = UINT64_MAX;
	for (uint64_t i = 0; i < len; i++) {
		if (i == c->offset) {
			i += c->bytes - 1;
			continue;
		}
		if (p[i] != POISON) {
			c->outside_bad = i;
			break;
		}
	}
	return 0;
}

/* Device-memory readback through the session's CUDA context (untimed). */
static int cuda_verify(struct worker *wk, uint64_t offset, uint64_t bytes, uint64_t seed,
		       struct check *c)
{
	int (*dtoh)(void *, uint64_t, size_t);
	void *previous = NULL, *buf;
	int ret = 0;

	*(void **)&dtoh = dlsym(wk->cuda.lib, "cuMemcpyDtoH_v2");
	if (!dtoh)
		return -ENOSYS;
	buf = malloc(VERIFY_CHUNK);
	if (!buf)
		return -ENOMEM;
	c->result = 0;
	c->digest = KV_FNV_OFFSET;
	c->outside_bad = UINT64_MAX;
	if (wk->cuda.ctx_get(&previous) || wk->cuda.ctx_set(wk->cuda.ctx)) {
		free(buf);
		return -EIO;
	}
	for (uint64_t done = 0; done < bytes && !ret && !c->result; ) {
		size_t n = bytes - done < VERIFY_CHUNK ? (size_t)(bytes - done) : VERIFY_CHUNK;

		if (dtoh(buf, wk->cuda.va + offset + done, n)) {
			ret = -EIO;
			break;
		}
		c->result = kv_pattern_check(seed, done, buf, n, &c->first_bad);
		c->digest = kv_fnv1a(c->digest, buf, n);
		done += n;
	}
	if (wk->cuda.ctx_set(previous))
		ret = ret ? ret : -EIO;
	free(buf);
	return ret;
}

/* ce-vmm local-verify: one CUDA copy over the whole VMM allocation (untimed). */
static int cuda_whole(struct worker *wk, bool write, struct check *c)
{
	int (*htod)(uint64_t, const void *, size_t);
	int (*dtoh)(void *, uint64_t, size_t);
	void *previous = NULL;
	uint8_t *buf;
	int ret = 0;

	*(void **)&htod = dlsym(wk->cuda.lib, "cuMemcpyHtoD_v2");
	*(void **)&dtoh = dlsym(wk->cuda.lib, "cuMemcpyDtoH_v2");
	if (!htod || !dtoh)
		return -ENOSYS;
	buf = malloc(VERIFY_CHUNK);
	if (!buf)
		return -ENOMEM;
	if (write) {
		memset(buf, POISON, VERIFY_CHUNK);
	} else {
		c->result = 0;
		c->digest = KV_FNV_OFFSET;
		c->outside_bad = UINT64_MAX;
	}
	if (wk->cuda.ctx_get(&previous) || wk->cuda.ctx_set(wk->cuda.ctx)) {
		free(buf);
		return -EIO;
	}
	for (uint64_t at = 0; at < wk->cuda.vmm_bytes && !ret; ) {
		size_t n = wk->cuda.vmm_bytes - at < VERIFY_CHUNK ? (size_t)(wk->cuda.vmm_bytes - at)
								 : VERIFY_CHUNK;

		if (write) {
			ret = htod(wk->cuda.va + at, buf, n) ? -EIO : 0;
			at += n;
			continue;
		}
		if (dtoh(buf, wk->cuda.va + at, n)) {
			ret = -EIO;
			break;
		}
		for (size_t i = 0; i < n; i++) {
			uint64_t pos = at + i;
			bool inside = pos >= c->offset && pos - c->offset < c->bytes;

			if (!inside && buf[i] != POISON && c->outside_bad == UINT64_MAX)
				c->outside_bad = pos;
		}
		/* The pattern part of this chunk, in KV byte order. */
		if (at + n > c->offset && at < c->offset + c->bytes) {
			uint64_t lo = at > c->offset ? at : c->offset;
			uint64_t hi = at + n < c->offset + c->bytes ? at + n : c->offset + c->bytes;
			uint64_t bad = 0;

			if (!c->result && kv_pattern_check(c->seed, lo - c->offset, buf + (lo - at),
							   hi - lo, &bad)) {
				c->result = 1;
				c->first_bad = bad;
			}
			c->digest = kv_fnv1a(c->digest, buf + (lo - at), hi - lo);
		}
		at += n;
	}
	if (wk->cuda.ctx_set(previous))
		ret = ret ? ret : -EIO;
	free(buf);
	return ret;
}

/* ---- sockets ------------------------------------------------------------ */

static int split_addr(const char *spec, char *host, size_t cap, char *port, size_t pcap)
{
	const char *colon = strrchr(spec, ':');

	if (!colon || colon == spec || (size_t)(colon - spec) >= cap || strlen(colon + 1) >= pcap)
		return -EINVAL;
	memcpy(host, spec, colon - spec);
	host[colon - spec] = 0;
	strcpy(port, colon + 1);
	return 0;
}

static int tcp_open(const char *spec, bool listen_side, int timeout_ms)
{
	struct addrinfo hints = { .ai_socktype = SOCK_STREAM, .ai_flags = listen_side ? AI_PASSIVE : 0 };
	struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
	char host[256], port[16];
	struct addrinfo *res;
	int fd = -1, one = 1, ret;

	if (split_addr(spec, host, sizeof(host), port, sizeof(port)))
		return -EINVAL;
	ret = getaddrinfo(host, port, &hints, &res);
	if (ret)
		return -EHOSTUNREACH;
	fd = socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (listen_side) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		ret = bind(fd, res->ai_addr, res->ai_addrlen) || listen(fd, 1) ? -errno : 0;
	} else {
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		ret = connect(fd, res->ai_addr, res->ai_addrlen) ? -errno : 0;
	}
	if (ret) {
		close(fd);
		fd = -1;
	}
out:
	freeaddrinfo(res);
	return fd >= 0 ? fd : ret;
}

static int send_line(int fd, const char *text)
{
	size_t len = strlen(text), done = 0;

	while (done < len) {
		ssize_t n = send(fd, text + done, len - done, MSG_NOSIGNAL);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return n < 0 ? -errno : -EPIPE;
		done += (size_t)n;
	}
	return 0;
}

/* One '\n'-terminated line, byte by byte (lines are short and rare). */
static int recv_line(int fd, char *buf, size_t cap)
{
	size_t used = 0;

	while (used + 1 < cap) {
		ssize_t n = recv(fd, buf + used, 1, 0);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return n < 0 ? -errno : -ECONNRESET;
		if (buf[used] == '\n') {
			buf[used] = 0;
			return 0;
		}
		used++;
	}
	return -E2BIG;
}

/* ---- session ------------------------------------------------------------ */

static void stats_json(FILE *f, const struct xdev_ext_mech_stats *st)
{
	fprintf(f, "{\"done\": %llu, \"abort\": %llu, \"inflight\": %llu, \"sequestered\": %llu, "
		"\"rejects\": %llu, \"timeouts\": %llu, \"protocol_err\": %llu, \"published\": %llu, "
		"\"submitted\": [%llu, %llu], \"completed\": [%llu, %llu], \"last_err\": %d, "
		"\"state\": %u}",
		(unsigned long long)st->batches_done, (unsigned long long)st->batches_abort,
		(unsigned long long)st->inflight, (unsigned long long)st->sequestered,
		(unsigned long long)st->rejects, (unsigned long long)st->timeouts,
		(unsigned long long)st->protocol_err, (unsigned long long)st->published,
		(unsigned long long)st->submitted[0], (unsigned long long)st->submitted[1],
		(unsigned long long)st->completed[0], (unsigned long long)st->completed[1],
		st->last_err, st->state);
}

static int link_token(const struct opts *o, uint64_t *token)
{
	struct xdev_ext_link_snapshot snap;
	int ret;

	if (o->link_token) {
		*token = o->link_token;
	} else {
		ret = xdev_ext_link_read(o->sysfs_root, o->service, &snap);
		if (ret)
			return ret;
		*token = snap.token;
	}
	/* The link must be up now; CREATE rechecks under the kernel's locks. */
	return xdev_ext_link_discover(o->sysfs_root, *token, &snap);
}

static int create_session(struct worker *wk)
{
	struct xdev_ext_create_opts c = { .sz = sizeof(c) };
	struct xdev_ext_mech_create_report report;
	struct xdev_ext_peer_pool_opts pool = { .sz = sizeof(pool), .allocation_fd = wk->allocation };
	const struct opts *o = &wk->o;
	int fds[3] = { -1, -1, -1 }, nvme = -1, ret;
	uint64_t token = 0;
	__u32 xd = o->g.early ? XDEV_EXT_XDOMAIN_F_EARLY : 0, i = 0;

	if (o->dst == DST_CE) {
		struct xdev_ext_pool_opts umem = { .sz = sizeof(umem),
			.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .nr_frames = wk->ring_frames };

		ret = xdev_ext_session_open(&umem, &wk->s);
	} else {
		ret = xdev_ext_session_open_peer(&pool, &wk->s);
	}
	if (ret)
		return ret;
	c.group_bytes = o->g.group_bytes;
	c.depth = o->g.depth;
	kv_plan_layout(&o->g, &c.layout);
	if (o->role != ROLE_RESTORE) {
		nvme = open(o->nvme, O_RDONLY | O_CLOEXEC);
		if (nvme < 0)
			return -errno;
		c.st[i] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = nvme,
			.arg0 = o->w.slba, .arg1 = o->w.nlb };
		fds[i++] = prog_fd(&wk->nvme);
	}
	if (o->role != ROLE_LOCAL) {
		ret = link_token(o, &token);
		if (!ret)
			ret = xdev_ext_stage_xdomain(&c.st[i], wk->ctl, token,
				o->role == ROLE_SERVE ? XDEV_EXT_MECH_DIR_TO_DEVICE
						      : XDEV_EXT_MECH_DIR_FROM_DEVICE, xd);
		if (ret) {
			if (nvme >= 0)
				close(nvme);
			return ret;
		}
		c.st[i].arg1 = kv_plan_xdomain_arg1(&o->g);
		fds[i++] = prog_fd(&wk->xd);
	}
	if (o->dst == DST_CE) {
		/* The whole allocation is the window; the program picks each group's place. */
		c.st[i] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = wk->ce_fd,
			.flags = XDEV_EXT_CE_STAGE_F_TARGET_RANGE, .arg0 = wk->cuda.va,
			.arg1 = o->pool_bytes };
		fds[i++] = prog_fd(&wk->ce);
	}
	c.nr_stages = i;
	ret = xdev_ext_session_create_programs(wk->s, &c, fds, i, &report);
	/* The session keeps its own namespace reference after CREATE. */
	if (nvme >= 0)
		close(nvme);
	if (ret && report.size == sizeof(report))
		fprintf(stderr, "kv_restore: CREATE result=%d phase=%u failed_stage=%u cleanup=%u\n",
			report.result, report.phase, report.failed_stage, report.cleanup);
	return ret;
}

/* Pinned host pages of a dma-buf registration count against RLIMIT_MEMLOCK. */
static void raise_memlock(void)
{
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &lim) && !getrlimit(RLIMIT_MEMLOCK, &lim)) {
		lim.rlim_cur = lim.rlim_max;
		setrlimit(RLIMIT_MEMLOCK, &lim);
	}
}

static long long memlock_bytes(void)
{
	struct rlimit lim;

	if (getrlimit(RLIMIT_MEMLOCK, &lim))
		return -2;
	return lim.rlim_cur == RLIM_INFINITY ? -1 : (long long)lim.rlim_cur;
}

static int setup(struct worker *wk, const char **where)
{
	const struct opts *o = &wk->o;
	uint64_t len;
	int ret;

	wk->pool_frames = o->role == ROLE_SERVE ? (uint64_t)o->g.depth *
		(o->g.group_bytes / o->g.frame_bytes) : o->pool_bytes / o->g.frame_bytes;
	len = wk->pool_frames * o->g.frame_bytes;
	if (o->dst == DST_CE)
		wk->ring_frames = o->g.depth * (o->g.group_bytes / o->g.frame_bytes);
	if (o->dry_run)
		return 0;
	*where = "open /dev/xdev_ext_peer";
	wk->ctl = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
	if (wk->ctl < 0)
		return -errno;
	if (o->role != ROLE_RESTORE) {
		*where = "load NVMe program";
		ret = load_private(o->nvme_prog, "kv_nvme_ops", "xdev_ext_nvme_mech_ops", &wk->nvme);
		if (ret)
			return ret;
	}
	if (o->role != ROLE_LOCAL && o->xdomain_prog) {
		*where = "load XDOMAIN program";
		ret = load_private(o->xdomain_prog, o->xdomain_map, "xdev_ext_xdomain_mech_ops",
				   &wk->xd);
		if (ret)
			return ret;
	}
	if (o->dst == DST_CE) {
		struct xdev_ext_nv_ce_attach_memory attach = { 0 };
		size_t size = 0;

		*where = "load CE program";
		ret = load_private(o->ce_prog, "kv_ce_ops", "xdev_ext_ce_mech_ops", &wk->ce);
		if (ret)
			return ret;
		wk->ce_target = bpf_object__find_map_by_name(wk->ce.obj, ".bss");
		if (!wk->ce_target || !bpf_map__initial_value(wk->ce_target, &size) ||
		    size != sizeof(struct kv_ce_target))
			return -EPROTO;
		*where = "CUDA VMM allocation";
		ret = xdev_ext_mech_cuda_open_vmm(&wk->cuda, o->gpu_bdf, len);
		if (ret)
			return ret;
		*where = "open CE device";
		wk->ce_fd = open(o->ce_dev, O_RDWR | O_CLOEXEC);
		if (wk->ce_fd < 0)
			return -errno;
		/* CREATE claims the VRAM through this attached export. */
		*where = "attach CUDA export to the CE device";
		attach = (struct xdev_ext_nv_ce_attach_memory){ .mem_fd = wk->cuda.export_fd,
			.gpu_va = wk->cuda.va, .size = wk->cuda.vmm_bytes };
		if (xdev_ext_nv_ce_attach_memory(wk->ce_fd, &attach)) {
			ret = errno ? -errno : -EIO;
			fprintf(stderr, "kv_restore: CE attach status 0x%x\n", attach.status);
			return ret;
		}
	} else if (o->role == ROLE_RESTORE) {
		*where = "CUDA allocation";
		ret = xdev_ext_mech_cuda_open(&wk->cuda, o->gpu_bdf, len);
		if (ret)
			return ret;
		*where = "open GPU node";
		wk->gpu = open(o->gpu_node, O_RDWR | O_CLOEXEC);
		if (wk->gpu < 0)
			return -errno;
		*where = "register GPU memory";
		wk->allocation = peer_register(wk->ctl, wk->gpu, 0, wk->cuda.va, len);
	} else {
		*where = "system heap allocation";
		wk->dmabuf = heap_alloc(len);
		if (wk->dmabuf < 0)
			return wk->dmabuf;
		*where = "register dma-buf";
		wk->allocation = peer_register(wk->ctl, wk->dmabuf, XDEV_EXT_PEER_REGISTER_F_DMABUF,
					       0, len);
	}
	/* PEER and dma-buf register an allocation; ce-vmm attached its export above. */
	if (o->dst != DST_CE && wk->allocation < 0)
		return wk->allocation;
	*where = "CREATE";
	ret = create_session(wk);
	if (ret)
		return ret;
	if (o->role == ROLE_SERVE) {
		*where = "listen";
		wk->lsock = tcp_open(o->listen, true, o->timeout_ms);
		return wk->lsock < 0 ? wk->lsock : 0;
	}
	if (o->role == ROLE_RESTORE) {
		*where = "connect to host 1";
		wk->sock = tcp_open(o->peer, false, o->timeout_ms);
		return wk->sock < 0 ? wk->sock : 0;
	}
	return 0;
}

/* Plan one restore and claim its keys: they must exceed every key used. */
static int plan_claim(struct worker *wk, uint64_t ordinal, uint64_t slba, uint64_t bytes,
		      uint32_t dst0, struct kv_plan *p)
{
	struct kv_request r = { .object_slba = slba, .bytes = bytes, .ordinal = ordinal,
		.dst_frame0 = dst0,
		.pool_frames = wk->o.role == ROLE_SERVE ? 0 : wk->pool_frames,
		.host2_ring = wk->o.dst == DST_CE };
	int ret = kv_plan_make(&wk->o.w, &wk->o.g, &r, p);

	if (ret)
		return ret;
	if (p->first_seq < wk->next_key)
		return -EALREADY;
	return 0;
}

static int start_plan(struct worker *wk, const struct kv_plan *p, bool host1)
{
	struct xdev_ext_start_frames_opts so = { .sz = sizeof(so) };
	struct kv_start ks;
	uint32_t *idx;
	int ret;

	if (host1)
		kv_plan_host1_start(p, &ks);
	else
		kv_plan_host2_start(p, &ks);
	idx = calloc(ks.nr_frames, sizeof(*idx));
	if (!idx)
		return -ENOMEM;
	if (host1)
		kv_plan_host1_indices(p, idx);
	else
		kv_plan_host2_indices(p, idx);
	so.nr_batches = ks.nr_batches;
	so.first_seq = ks.first_seq;
	so.indices = idx;
	so.nr_indices = ks.nr_frames;
	so.flags = ks.recycle ? XDEV_EXT_MECH_START_F_RECYCLE : 0;
	ret = xdev_ext_session_start_frames(wk->s, &so);
	free(idx);
	if (!ret)
		wk->next_key = p->first_seq + p->groups;
	return ret;
}

/* Batches of this restore all finished without abort or sequestering; with
 * ce-vmm the copy engine stage (the last) completed exactly one command per group. */
static int outcome(struct worker *wk, const struct xdev_ext_mech_stats *st, uint64_t groups)
{
	const unsigned ce = 1;	/* [NVMe READ | XDOMAIN RX, CE] */
	int ret = 0;

	if (st->batches_done != wk->prev_done + groups || st->batches_abort || st->sequestered ||
	    st->inflight || st->last_err)
		ret = st->last_err ? st->last_err : -EIO;
	if (!ret && wk->o.dst == DST_CE &&
	    (st->completed[ce] != wk->prev_ce + groups || st->submitted[ce] != st->completed[ce]))
		ret = -EIO;
	wk->prev_done = st->batches_done;
	if (wk->o.dst == DST_CE)
		wk->prev_ce = st->completed[ce];
	return ret;
}

/* ce-vmm: the keys and place of this restore, read by kv_ce_place.bpf.c. */
static int ce_target(struct worker *wk, const struct kv_plan *p)
{
	struct kv_ce_target t = { .first_key = p->first_seq, .groups = p->groups,
		.dst_off = (uint64_t)p->host2_dst_frame0 * wk->o.g.frame_bytes };
	__u32 zero = 0;

	return bpf_map_update_elem(bpf_map__fd(wk->ce_target), &zero, &t, BPF_ANY) ? -errno : 0;
}

static const char *payload_path(const struct worker *wk)
{
	if (wk->o.dst == DST_CE)
		return wk->o.role == ROLE_LOCAL ? "nvme-read>host-frame>ce-h2d"
						: "xdomain-rx>host-frame>ce-h2d";
	return wk->o.dst == DST_DMABUF ? "nvme-read>dmabuf-frame" : "xdomain-rx>gpu-frame";
}

static void plan_json(FILE *f, const struct kv_plan *p)
{
	fprintf(f, "{\"groups\": %" PRIu64 ", \"slots\": %" PRIu64 ", \"slot0\": %" PRIu64
		", \"first_seq\": %" PRIu64 ", \"frames_per_group\": %u, \"host2_frames\": %" PRIu64
		", \"host2_dst_frame0\": %u, \"host1_recycle_frames\": %u, \"host2_ring\": %s"
		", \"host2_start_frames\": %u}",
		p->groups, p->slots, p->slot0, p->first_seq, p->frames_per_group, p->host2_frames,
		p->host2_dst_frame0, p->host1_recycle_frames, p->host2_ring ? "true" : "false",
		p->host2_start_frames);
}

/* GO for restore and local-verify. */
static void handle_go(struct worker *wk, const struct kv_line *l)
{
	const char *run = line_get(l, "run");
	uint64_t ordinal, slba, bytes, dst0, seed = 0, verify = 0, t0 = 0, t1 = 0, c0 = 0, c1 = 0;
	struct xdev_ext_mech_stats st = { 0 };
	struct check chk = { .result = 1, .outside_bad = UINT64_MAX };
	char line[LINE_MAX_BYTES], reply[LINE_MAX_BYTES] = "";
	/* Payload bytes this process copies with the CPU between t0 and t1.  No
	 * path below copies payload: the NIC/NVMe and the copy engine move it. */
	const uint64_t cpu_copy_bytes = 0;
	int ret, wait_err = 0, verify_err = 0;
	bool planned = false, started = false, good;
	struct kv_plan p;

	if (!run_id_ok(run) || line_u64(l, "ordinal", &ordinal) || line_u64(l, "object_slba", &slba) ||
	    line_u64(l, "bytes", &bytes) || line_u64(l, "dst_frame0", &dst0) || dst0 > UINT32_MAX ||
	    (line_get(l, "seed") && line_u64(l, "seed", &seed)) ||
	    (line_get(l, "verify") && (line_u64(l, "verify", &verify) || verify > 1))) {
		emit_error("GO arguments", -EINVAL);
		return;
	}
	ret = wk->dirty ? -ESTALE : plan_claim(wk, ordinal, slba, bytes, (uint32_t)dst0, &p);
	planned = !ret;
	if (ret)
		goto report;
	if (wk->o.dry_run) {
		wk->next_key = p.first_seq + p.groups;
		goto report;
	}
	if (wk->o.role == ROLE_LOCAL) {
		ret = wk->o.dst == DST_CE ? cuda_whole(wk, true, NULL)
			: dmabuf_cpu(wk->dmabuf, wk->pool_frames * wk->o.g.frame_bytes, true,
				     poison_fn, NULL);
		if (ret)
			goto report;
	}
	snprintf(line, sizeof(line), "RESTORE token=%s run=%s ordinal=%" PRIu64 " object_slba=%" PRIu64
		 " bytes=%" PRIu64 " first_seq=%" PRIu64 " groups=%" PRIu64 "\n", wk->o.token, run,
		 ordinal, slba, bytes, p.first_seq, p.groups);
	c0 = cpu_us();
	t0 = now_ns();
	ret = wk->o.dst == DST_CE ? ce_target(wk, &p) : 0;
	if (!ret)
		ret = start_plan(wk, &p, false);
	started = !ret;
	if (!ret && wk->o.role == ROLE_RESTORE)
		ret = send_line(wk->sock, line);
	if (!ret)
		wait_err = xdev_ext_session_wait(wk->s, wk->o.timeout_ms, &st);
	t1 = now_ns();
	c1 = cpu_us();
	if (ret || wait_err) {
		/* An unfinished START keeps its batches; this session takes no more. */
		wk->dirty = true;
		ret = ret ? ret : wait_err;
		goto report;
	}
	ret = outcome(wk, &st, p.groups);
	if (ret)
		wk->dirty = true;
	if (wk->o.role == ROLE_RESTORE) {
		int r = recv_line(wk->sock, reply, sizeof(reply));

		if (r && !ret)
			ret = r;
	}
	if (!ret && verify) {
		uint64_t off = (uint64_t)p.host2_dst_frame0 * wk->o.g.frame_bytes;

		chk = (struct check){ .seed = seed, .offset = off, .bytes = bytes,
				      .outside_bad = UINT64_MAX };
		if (wk->o.role == ROLE_LOCAL && wk->o.dst == DST_CE)
			verify_err = cuda_whole(wk, false, &chk);
		else if (wk->o.role == ROLE_LOCAL)
			verify_err = dmabuf_cpu(wk->dmabuf, wk->pool_frames * wk->o.g.frame_bytes,
						false, check_fn, &chk);
		else
			verify_err = cuda_verify(wk, off, bytes, seed, &chk);
	}
report:
	wk->restores++;
	good = !ret && !verify_err && (!verify || wk->o.dry_run ||
				      (!chk.result && chk.outside_bad == UINT64_MAX));
	printf("KV_RESULT {\"run\": ");
	jstr(stdout, run);
	printf(", \"role\": \"%s\", \"ok\": %s, \"error\": %d, \"dry_run\": %s, \"bytes\": %" PRIu64,
	       wk->o.role == ROLE_LOCAL ? "local-verify" : "restore", good ? "true" : "false",
	       ret ? ret : verify_err, wk->o.dry_run ? "true" : "false", good ? bytes : 0);
	printf(", \"dst\": \"%s\", \"payload_path\": \"%s\", \"cpu_copy_bytes\": %" PRIu64,
	       dst_names[wk->o.dst], payload_path(wk), cpu_copy_bytes);
	if (planned) {
		printf(", \"plan\": ");
		plan_json(stdout, &p);
	}
	printf(", \"started\": %s, \"t0_ns\": %" PRIu64 ", \"t1_ns\": %" PRIu64
	       ", \"latency_ns\": %" PRIu64 ", \"worker_cpu_us\": %" PRIu64 ", \"wait_err\": %d",
	       started ? "true" : "false", t0, t1, started ? t1 - t0 : 0, started ? c1 - c0 : 0,
	       wait_err);
	if (verify && !ret && !verify_err && !wk->o.dry_run)
		printf(", \"verified\": %s, \"first_bad\": %" PRId64 ", \"outside_bad\": %" PRId64
		       ", \"digest\": \"0x%016" PRIx64 "\"",
		       !chk.result && chk.outside_bad == UINT64_MAX ? "true" : "false",
		       chk.result ? (int64_t)chk.first_bad : -1,
		       chk.outside_bad == UINT64_MAX ? -1 : (int64_t)chk.outside_bad, chk.digest);
	else
		printf(", \"verified\": null");
	if (reply[0]) {
		printf(", \"host1\": ");
		jstr(stdout, reply);
	}
	if (started) {
		printf(", \"stats\": ");
		stats_json(stdout, &st);
	}
	printf("}\n");
	fflush(stdout);
}

/* RESTORE from host 2: same plan on this side, one START, one wait, DONE. */
static void serve_request(struct worker *wk, const char *text)
{
	uint64_t ordinal, slba, bytes, first, groups, t0, t1;
	struct xdev_ext_mech_stats st = { 0 };
	char reply[LINE_MAX_BYTES];
	const char *run, *token;
	struct kv_line l;
	struct kv_plan p;
	int ret;

	ret = line_split(&l, text);
	run = ret ? NULL : line_get(&l, "run");
	token = ret ? NULL : line_get(&l, "token");
	if (ret || strcmp(l.key[0], "RESTORE") || !run_id_ok(run) || !token ||
	    strcmp(token, wk->o.token) || line_u64(&l, "ordinal", &ordinal) ||
	    line_u64(&l, "object_slba", &slba) || line_u64(&l, "bytes", &bytes) ||
	    line_u64(&l, "first_seq", &first) || line_u64(&l, "groups", &groups)) {
		send_line(wk->sock, "DONE ok=0 err=-22\n");
		emit_error("RESTORE request", -EINVAL);
		return;
	}
	ret = wk->dirty ? -ESTALE : plan_claim(wk, ordinal, slba, bytes, 0, &p);
	/* Both hosts must derive the same keys from the same window. */
	if (!ret && (p.first_seq != first || p.groups != groups))
		ret = -EPROTO;
	t0 = now_ns();
	if (!ret)
		ret = start_plan(wk, &p, true);
	if (!ret) {
		ret = xdev_ext_session_wait(wk->s, wk->o.timeout_ms, &st);
		if (!ret)
			ret = outcome(wk, &st, p.groups);
		if (ret)
			wk->dirty = true;
	}
	t1 = now_ns();
	snprintf(reply, sizeof(reply), "DONE run=%s ok=%d err=%d wait_ns=%" PRIu64
		 " done=%llu abort=%llu sequestered=%llu last_err=%d\n", run, !ret, ret, t1 - t0,
		 (unsigned long long)st.batches_done, (unsigned long long)st.batches_abort,
		 (unsigned long long)st.sequestered, st.last_err);
	send_line(wk->sock, reply);
	printf("KV_SERVED {\"run\": ");
	jstr(stdout, run);
	printf(", \"ok\": %s, \"error\": %d, \"t0_ns\": %" PRIu64 ", \"t1_ns\": %" PRIu64
	       ", \"first_seq\": %" PRIu64 ", \"groups\": %" PRIu64 ", \"stats\": ",
	       ret ? "false" : "true", ret, t0, t1, first, groups);
	stats_json(stdout, &st);
	printf("}\n");
	fflush(stdout);
}

static int serve_loop(struct worker *wk)
{
	char buf[LINE_MAX_BYTES];

	for (;;) {
		struct pollfd pf[2] = { { .fd = 0, .events = POLLIN },
			{ .fd = wk->sock >= 0 ? wk->sock : wk->lsock, .events = POLLIN } };
		int n = poll(pf, wk->o.dry_run ? 1 : 2, -1);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (pf[0].revents) {
			if (!fgets(buf, sizeof(buf), stdin) || !strncmp(buf, "QUIT", 4))
				return 0;
			emit_error("serve takes only QUIT on stdin", -EINVAL);
			continue;
		}
		if (!pf[1].revents)
			continue;
		if (wk->sock < 0) {
			wk->sock = accept4(wk->lsock, NULL, NULL, SOCK_CLOEXEC);
			if (wk->sock < 0)
				return -errno;
			continue;
		}
		if (recv_line(wk->sock, buf, sizeof(buf))) {
			close(wk->sock);
			wk->sock = -1;
			continue;
		}
		serve_request(wk, buf);
	}
}

/* STOP's own result (the session's final error) is reported apart from the
 * release of this process's resources. */
static int teardown(struct worker *wk, bool *retained, int *stop_error)
{
	int ret = 0, r;

	*retained = false;
	*stop_error = 0;
	if (wk->s) {
		r = xdev_ext_session_stop(wk->s);
		if (r != -ENOTCONN)
			*stop_error = r;
		if (xdev_ext_session_close(wk->s)) {
			/* DMA ownership unknown: the session keeps every resource. */
			*retained = true;
			wk->s = NULL;
			return -EBUSY;
		}
		wk->s = NULL;
	}
	if (wk->sock >= 0)
		close(wk->sock);
	if (wk->lsock >= 0)
		close(wk->lsock);
	if (wk->allocation >= 0)
		close(wk->allocation);
	if (wk->dmabuf >= 0)
		close(wk->dmabuf);
	if (wk->gpu >= 0)
		close(wk->gpu);
	if (wk->ce_fd >= 0)
		close(wk->ce_fd);
	r = wk->cuda.lib ? xdev_ext_mech_cuda_close(&wk->cuda) : 0;
	if (r && !ret)
		ret = r;
	prog_free(&wk->ce);
	prog_free(&wk->xd);
	prog_free(&wk->nvme);
	if (wk->ctl >= 0)
		close(wk->ctl);
	return ret;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: kv_restore serve|restore|local-verify [--dry-run]\n"
		"  common: --window-slba N --window-nlb N --lba-bytes N --group-bytes N --frame-bytes N\n"
		"          --depth N --window N [--early] [--timeout-ms N] [--token T]\n"
		"  serve:  --nvme /dev/ngXnY --nvme-prog kv_nvme_read.bpf.o --listen HOST:PORT\n"
		"          (--service NAME [--sysfs-root DIR] | --link-token N)\n"
		"          [--xdomain-prog OBJ [--xdomain-map NAME]]\n"
		"  restore: --gpu-bdf BDF --gpu-node /dev/nvidiaN --pool-bytes N --peer HOST:PORT\n"
		"          (--service NAME [--sysfs-root DIR] | --link-token N) [--xdomain-prog OBJ]\n"
		"  local-verify: --nvme /dev/ngXnY --nvme-prog kv_nvme_read.bpf.o --pool-bytes N\n"
		"  --dst peer|dmabuf|ce-vmm: restore defaults to peer, local-verify to dmabuf;\n"
		"     ce-vmm: --gpu-bdf BDF --ce-dev /dev/nvidiaN --ce-prog kv_ce_place.bpf.o\n"
		"     --frame-bytes 4096, no --gpu-node; --pool-bytes sizes the CUDA VMM allocation\n");
}

static int parse(int argc, char **argv, struct opts *o)
{
	static const struct option lo[] = {
		{ "window-slba", 1, 0, 1 }, { "window-nlb", 1, 0, 2 }, { "lba-bytes", 1, 0, 3 },
		{ "group-bytes", 1, 0, 4 }, { "frame-bytes", 1, 0, 5 }, { "depth", 1, 0, 6 },
		{ "window", 1, 0, 7 }, { "early", 0, 0, 8 }, { "timeout-ms", 1, 0, 9 },
		{ "token", 1, 0, 10 }, { "nvme", 1, 0, 11 }, { "nvme-prog", 1, 0, 12 },
		{ "xdomain-prog", 1, 0, 13 }, { "xdomain-map", 1, 0, 14 }, { "service", 1, 0, 15 },
		{ "sysfs-root", 1, 0, 16 }, { "link-token", 1, 0, 17 }, { "listen", 1, 0, 18 },
		{ "peer", 1, 0, 19 }, { "gpu-bdf", 1, 0, 20 }, { "gpu-node", 1, 0, 21 },
		{ "pool-bytes", 1, 0, 22 }, { "dry-run", 0, 0, 23 }, { "dst", 1, 0, 24 },
		{ "ce-dev", 1, 0, 25 }, { "ce-prog", 1, 0, 26 }, { 0, 0, 0, 0 } };
	uint64_t timeout = 120000;
	int c, bad = 0;

	if (argc < 2)
		return -EINVAL;
	o->role = !strcmp(argv[1], "serve") ? ROLE_SERVE : !strcmp(argv[1], "restore") ? ROLE_RESTORE
		: !strcmp(argv[1], "local-verify") ? ROLE_LOCAL : 0;
	if (!o->role)
		return -EINVAL;
	o->sysfs_root = "/sys/bus/thunderbolt/devices";
	o->xdomain_map = "xdomain_peer_ops";
	o->token = "kv";
	optind = 2;
	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		switch (c) {
		case 1: bad |= parse_u64(optarg, &o->w.slba); break;
		case 2: bad |= parse_u64(optarg, &o->w.nlb); break;
		case 3: bad |= parse_u32(optarg, &o->w.lba_bytes); break;
		case 4: bad |= parse_u32(optarg, &o->g.group_bytes); break;
		case 5: bad |= parse_u32(optarg, &o->g.frame_bytes); break;
		case 6: bad |= parse_u32(optarg, &o->g.depth); break;
		case 7: bad |= parse_u32(optarg, &o->g.window); break;
		case 8: o->g.early = true; break;
		case 9: bad |= parse_u64(optarg, &timeout); break;
		case 10: o->token = optarg; break;
		case 11: o->nvme = optarg; break;
		case 12: o->nvme_prog = optarg; break;
		case 13: o->xdomain_prog = optarg; break;
		case 14: o->xdomain_map = optarg; break;
		case 15: o->service = optarg; break;
		case 16: o->sysfs_root = optarg; break;
		case 17: bad |= parse_u64(optarg, &o->link_token); break;
		case 18: o->listen = optarg; break;
		case 19: o->peer = optarg; break;
		case 20: o->gpu_bdf = optarg; break;
		case 21: o->gpu_node = optarg; break;
		case 22: bad |= parse_u64(optarg, &o->pool_bytes); break;
		case 23: o->dry_run = true; break;
		case 24:
			o->dst = !strcmp(optarg, "peer") ? DST_PEER : !strcmp(optarg, "dmabuf") ? DST_DMABUF
				: !strcmp(optarg, "ce-vmm") ? DST_CE : DST_NONE;
			bad |= o->dst == DST_NONE;
			break;
		case 25: o->ce_dev = optarg; break;
		case 26: o->ce_prog = optarg; break;
		default: return -EINVAL;
		}
	}
	if (bad || optind != argc || !timeout || timeout > INT32_MAX || !run_id_ok(o->token))
		return -EINVAL;
	o->timeout_ms = (int)timeout;
	if (kv_geometry_check(&o->g, o->w.lba_bytes) || !o->w.nlb)
		return -EINVAL;
	if (o->role != ROLE_RESTORE && (!o->nvme || !o->nvme_prog))
		return -EINVAL;
	if (o->role != ROLE_LOCAL && !o->link_token == !o->service)
		return -EINVAL;
	if (o->role == ROLE_SERVE && !o->listen)
		return -EINVAL;
	/* Destination: explicit, or each role's original one. */
	if (o->role == ROLE_SERVE ? o->dst != DST_NONE :
	    o->role == ROLE_RESTORE ? o->dst == DST_DMABUF : o->dst == DST_PEER)
		return -EINVAL;
	if (o->dst == DST_NONE && o->role != ROLE_SERVE)
		o->dst = o->role == ROLE_RESTORE ? DST_PEER : DST_DMABUF;
	if (o->dst == DST_CE ? !o->gpu_bdf || !o->ce_dev || !o->ce_prog || o->gpu_node ||
				  o->g.frame_bytes != XDEV_EXT_FRAME_SIZE
			     : o->ce_dev || o->ce_prog)
		return -EINVAL;
	if (o->role == ROLE_RESTORE && (!o->gpu_bdf || !o->peer ||
					(o->dst == DST_PEER && !o->gpu_node)))
		return -EINVAL;
	if (o->role != ROLE_SERVE && (!o->pool_bytes || o->pool_bytes % o->g.frame_bytes ||
				      o->pool_bytes / o->g.frame_bytes > UINT32_MAX))
		return -EINVAL;
	return 0;
}

int main(int argc, char **argv)
{
	struct worker wk = { .ctl = -1, .allocation = -1, .dmabuf = -1, .gpu = -1, .lsock = -1,
			     .sock = -1, .ce_fd = -1, .next_key = 1 };
	char buf[LINE_MAX_BYTES], where[96];
	const char *step = "options";
	bool retained = false;
	int ret, stop_error = 0;

	signal(SIGPIPE, SIG_IGN);
	ret = parse(argc, argv, &wk.o);
	if (ret) {
		usage();
		emit_error("arguments", ret);
		return 2;
	}
	if (!wk.o.dry_run)
		raise_memlock();
	ret = setup(&wk, &step);
	if (ret) {
		snprintf(where, sizeof(where), "setup: %s", step);
		emit_error(where, ret);
		teardown(&wk, &retained, &stop_error);
		return 1;
	}
	printf("KV_READY {\"role\": \"%s\", \"dry_run\": %s, \"session_id\": %llu, "
	       "\"pool_frames\": %" PRIu64 ", \"frame_bytes\": %u, \"group_bytes\": %u, "
	       "\"depth\": %u, \"window\": %u, \"early\": %s, \"private_xdomain\": %s, "
	       "\"memlock_bytes\": %lld, \"dst\": \"%s\", \"ring_frames\": %u}\n",
	       argv[1], wk.o.dry_run ? "true" : "false",
	       wk.s ? (unsigned long long)xdev_ext_session_id(wk.s) : 0ULL, wk.pool_frames,
	       wk.o.g.frame_bytes, wk.o.g.group_bytes, wk.o.g.depth, wk.o.g.window,
	       wk.o.g.early ? "true" : "false", wk.xd.link ? "true" : "false", memlock_bytes(),
	       dst_names[wk.o.dst], wk.ring_frames);
	fflush(stdout);
	if (wk.o.role == ROLE_SERVE) {
		ret = serve_loop(&wk);
	} else {
		while (fgets(buf, sizeof(buf), stdin)) {
			struct kv_line l;

			if (line_split(&l, buf)) {
				emit_error("protocol line", -EINVAL);
				continue;
			}
			if (!strcmp(l.key[0], "QUIT"))
				break;
			if (strcmp(l.key[0], "GO")) {
				emit_error("unknown command", -EINVAL);
				continue;
			}
			handle_go(&wk, &l);
		}
	}
	ret = teardown(&wk, &retained, &stop_error) ?: ret;
	printf("KV_BYE {\"error\": %d, \"stop_error\": %d, \"retained\": %s, \"restores\": %"
	       PRIu64 "}\n", ret, stop_error, retained ? "true" : "false", wk.restores);
	fflush(stdout);
	return retained || ret ? 1 : 0;
}
