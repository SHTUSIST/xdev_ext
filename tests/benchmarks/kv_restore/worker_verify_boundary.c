/* SPDX-License-Identifier: GPL-2.0 */
/* Host boundary test: real worker/index/mmap/dlopen verification, CPU storage.
 * Session execution, DMA-buf sync and CE map update are the external stand-ins.
 * No kernel, GPU or vLLM execution is represented by this fixture.
 */
#define main kv_restore_worker_main
#include "kv_restore.c"
#undef main

static const char *payload_file;
static int storage_fd;
static uint64_t completed_groups;
static bool break_guard;
static uint64_t ce_destination;

int __wrap_ioctl(int fd, unsigned long request, ...)
{
	(void)fd;
	if (request == DMA_BUF_IOCTL_SYNC)
		return 0;
	errno = ENOTTY;
	return -1;
}

int __wrap_xdev_ext_session_start_frames(struct xdev_ext_session *s,
					 const struct xdev_ext_start_frames_opts *o)
{
	unsigned char buf[4096];
	uint64_t off = ce_destination ? ce_destination : (uint64_t)o->indices[0] * 4096;
	int fd = open(payload_file, O_RDONLY);
	ssize_t n;

	(void)s;
	if (fd < 0)
		return -errno;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		if (pwrite(storage_fd, buf, (size_t)n, (off_t)off) != n)
			abort();
		off += (uint64_t)n;
	}
	close(fd);
	if (n < 0)
		return -EIO;
	if (break_guard && pwrite(storage_fd, "x", 1, 0) != 1)
		abort();
	completed_groups = o->nr_batches;
	return 0;
}

int __wrap_xdev_ext_session_wait(struct xdev_ext_session *s, int timeout_ms,
				 struct xdev_ext_mech_stats *st)
{
	(void)s; (void)timeout_ms;
	memset(st, 0, sizeof(*st));
	st->batches_done = completed_groups;
	st->submitted[1] = st->completed[1] = completed_groups;
	return 0;
}

int __wrap_bpf_map__fd(const struct bpf_map *map) { (void)map; return 7; }
int __wrap_bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
	const struct kv_ce_target *target = value;
	(void)fd; (void)key; (void)flags;
	ce_destination = target->dst_off;
	return 0;
}

int main(int argc, char **argv)
{
	struct worker wk = { 0 };
	struct queued q = { 0 };
	struct kv_line line;
	char command[512];
	const struct kv_index_entry *e;
	FILE *index;
	uint64_t len;
	unsigned char *map;
	int sv[2] = { -1, -1 };

	if (argc != 6)
		return 2;
	if (kv_fnv1a(KV_FNV_OFFSET, (const uint8_t *)"hello", 5) != 0xa430d84680aabd0bULL)
		return 9;
	index = fopen(argv[1], "re");
	if (!index || kv_index_load(index, &wk.index) || wk.index.n != 1)
		return 3;
	fclose(index);
	e = &wk.index.v[0];
	payload_file = argv[2];
	break_guard = !strcmp(argv[5], "guard");
	len = e->bytes + 2 * 4096;
	storage_fd = memfd_create("kv-verification-cpu-storage", MFD_CLOEXEC);
	if (storage_fd < 0 || ftruncate(storage_fd, (off_t)len))
		return 4;
	map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, storage_fd, 0);
	if (map == MAP_FAILED)
		return 5;
	memset(map, POISON, len);
	wk.o.role = ROLE_LOCAL;
	wk.o.dst = DST_DMABUF;
	wk.o.w = (struct kv_window){ .slba = 2048, .nlb = (64 << 20) / 512, .lba_bytes = 512 };
	wk.o.g = (struct kv_geometry){ .group_bytes = 131072, .frame_bytes = 4096,
		.depth = 4, .window = 4, .early = true };
	wk.o.timeout_ms = 1000;
	wk.o.token = "5";
	wk.dmabuf = storage_fd;
	wk.pool_frames = len / 4096;
	if (strcmp(argv[3], "dmabuf")) {
		wk.o.dst = DST_CE;
		wk.cuda.lib = dlopen(argv[4], RTLD_NOW | RTLD_LOCAL);
		if (!wk.cuda.lib)
			return 6;
		*(void **)&wk.cuda.ctx_get = dlsym(wk.cuda.lib, "cuCtxGetCurrent");
		*(void **)&wk.cuda.ctx_set = dlsym(wk.cuda.lib, "cuCtxSetCurrent");
		wk.cuda.va = (uintptr_t)map;
		wk.cuda.vmm_bytes = len;
		if (!strcmp(argv[3], "peer")) {
			wk.o.role = ROLE_RESTORE;
			wk.o.dst = DST_PEER;
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) || send_line(sv[1], "DONE run=verify ok=1 err=0\n"))
				return 7;
			wk.sock = sv[0];
		}
	}
	snprintf(command, sizeof(command), "GO run=verify ordinal=1 prefix=%s dst_frame0=1 seed=9 verify=1", e->hash);
	if (line_split(&line, command))
		return 8;
	handle_go(&wk, &line, &q, now_ns());
	if (wk.cuda.lib)
		dlclose(wk.cuda.lib);
	if (sv[0] >= 0) { close(sv[0]); close(sv[1]); }
	munmap(map, len); close(storage_fd); kv_index_free(&wk.index);
	return 0;
}
