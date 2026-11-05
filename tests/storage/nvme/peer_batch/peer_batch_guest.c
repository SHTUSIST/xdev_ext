// SPDX-License-Identifier: GPL-2.0
/* GUEST TEST ONLY: concurrent multi-page XDEV_EXT_PEER_NVME_BATCH requests
 * (42-PEER-BATCH, 42-RANDOM) between QEMU NVMe and a system-heap dma-buf
 * imported through /dev/xdev_ext_peer (XDEV_EXT_PEER_REGISTER_F_DMABUF).
 * No provider fixture, device stand-in or GPU is involved. Correctness only:
 * nothing measures time. The NVMe tracepoints are read only for command
 * counts, command lengths and the order of submissions and completions.
 *
 * Controllers: SRC (read source), DST (private destination), ERR (a private
 * image whose QEMU block backend fails reads of one sector). The pool P is
 * 6 MiB + 68 KiB, allocated while 1 MiB holes fragment free memory so that
 * its pages form several separate DMA runs; probe reads with the xdev_ext
 * native tracepoint give each page's device-visible address.
 * Phases, one boot (the host validator duplicates this plan, it does not
 * import it):
 *   A  1 MiB read as one command; three 1 MiB reads in one batch; a request
 *      across a DMA discontinuity and two page-tail requests
 *   B  40 random disjoint read targets, shuffled, two duplicate source LBAs
 *   C  1 MiB write and 32 random disjoint LBA write targets
 *   D  refusals: no command may reach any controller, nothing changes
 *   E  one accepted command fails on ERR: completed prefix, no resubmission,
 *      the allocation is retained (UNKNOWN): later batches refused, MEMLOCK
 *      charge and device attachment kept after close, re-import refused
 * P and the pool of E are dumped to DST with ordinary writes for the host.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "linux/xdev_ext_peer.h"

#define LBA 512U
#define PAGE 4096U
#define KIB 1024ULL
#define MIB (1024ULL * KIB)
#define SRC_BYTES (64ULL * MIB)
#define DST_BYTES (64ULL * MIB)
#define ERR_BYTES (4ULL * MIB)
#define SRC_LBAS (SRC_BYTES / LBA)
#define P_BYTES (6 * MIB + 68 * KIB)
#define Q_BYTES (1 * MIB)
#define HOLES 32
#define GUARD 0x6b
#define ERR_SECTOR 2368ULL
#define DUMP_A (16 * MIB)
#define DUMP_B (24 * MIB)
#define DUMP_Q (40 * MIB)
#define TRACE "/sys/kernel/tracing"
#define BUFINFO "/sys/kernel/debug/dma_buf/bufinfo"

static unsigned int checks;
#define CHECK(c, msg) do { if (!(c)) { \
	fprintf(stderr, "not ok %u - %s (errno=%d %s)\n", checks + 1, msg, errno, strerror(errno)); \
	printf("not ok %u - %s\n", ++checks, msg); exit(1); } printf("ok %u - %s\n", ++checks, msg); } while (0)

static const char *ctrl_name[3]; /* SRC, DST, ERR controller names, e.g. nvme0 */
enum { SRC, DST, ERR };
static unsigned char *src_image, *err_image, *dst_expect, *p_expect, *q_expect, *scratch;

static uint8_t pattern_p(uint64_t off) { return (uint8_t)(((off * 131 + 7) ^ (off >> 9)) & 0xff); }
static uint8_t pattern_w(uint64_t off) { return (uint8_t)(((off * 197 + 11) ^ (off >> 10) ^ 0xa5) & 0xff); }
static uint8_t pattern_q(uint64_t off) { return (uint8_t)(((off * 61 + 3) ^ 0x96) & 0xff); }
static uint64_t seed = 0x42ba7c4u;
static uint32_t rnd(void) { seed = seed * 6364136223846793005ULL + 1442695040888963407ULL; return (uint32_t)(seed >> 33); }

static void write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	CHECK(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text) && !close(fd), path);
}
static int open_ok(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);
	CHECK(fd >= 0, path);
	return fd;
}
static void read_all(int fd, void *buf, size_t n, off_t off)
{
	size_t got = 0;
	while (got < n) {
		ssize_t r = pread(fd, (char *)buf + got, n - got, off + got);
		CHECK(r > 0, "complete pread");
		got += r;
	}
}
static void write_all(int fd, const void *buf, size_t n, off_t off)
{
	size_t done = 0;
	while (done < n) {
		ssize_t r = pwrite(fd, (const char *)buf + done, n - done, off + done);
		CHECK(r > 0, "complete pwrite");
		done += r;
	}
}
/* Uncached read: no readahead may touch the failing sector of ERR. */
static void read_direct(int fd, void *buf, size_t n, off_t off)
{
	void *bounce = NULL;
	CHECK(!posix_memalign(&bounce, PAGE, n) && pread(fd, bounce, n, off) == (ssize_t)n, "complete O_DIRECT pread");
	memcpy(buf, bounce, n);
	free(bounce);
}
static uint64_t vmpin(void)
{
	FILE *f = fopen("/proc/self/status", "re");
	char line[256];
	unsigned long long kb = ULLONG_MAX;
	CHECK(f != NULL, "open /proc/self/status");
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "VmPin: %llu kB", &kb) == 1) break;
	fclose(f);
	CHECK(kb != ULLONG_MAX, "VmPin is reported");
	return kb * 1024;
}
static int heap_alloc(int heap, uint64_t len, unsigned long *ino)
{
	struct dma_heap_allocation_data a = {.len = len, .fd_flags = O_RDWR | O_CLOEXEC};
	struct stat st;
	if (ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &a) || fstat((int)a.fd, &st)) return -errno;
	if (ino) *ino = st.st_ino;
	return (int)a.fd;
}
/* CPU view of a dma-buf through its own mapping and DMA_BUF_IOCTL_SYNC. */
static void cpu_access(int buf, unsigned char *data, uint64_t len, bool write)
{
	struct dma_buf_sync sync = {.flags = DMA_BUF_SYNC_START | (write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ)};
	unsigned char *map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, buf, 0);
	CHECK(map != MAP_FAILED, "CPU mapping of the dma-buf");
	CHECK(!ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync), "DMA_BUF_IOCTL_SYNC start");
	if (write) memcpy(map, data, len); else memcpy(data, map, len);
	sync.flags = DMA_BUF_SYNC_END | (write ? DMA_BUF_SYNC_WRITE : DMA_BUF_SYNC_READ);
	CHECK(!ioctl(buf, DMA_BUF_IOCTL_SYNC, &sync), "DMA_BUF_IOCTL_SYNC end");
	CHECK(!munmap(map, len), "drop CPU mapping before device work");
}
static int reg(int ctl, int buf, uint64_t len, uint64_t *generation)
{
	struct xdev_ext_peer_register r = {.gpu_fd = buf, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF, .len = len};
	int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &r);
	if (fd < 0) return -errno;
	*generation = r.generation;
	return fd;
}
/* Attached devices of the buffer with inode ino; false when it is not listed. */
static bool bufinfo(unsigned long ino, char *attached, size_t size)
{
	static char text[1 << 17];
	char key[32], *line, *save = NULL, *field, *fsave;
	bool found = false, in_attached = false;
	ssize_t n, got = 0;
	int fd = open_ok(BUFINFO, O_RDONLY);
	while (got < (ssize_t)sizeof(text) - 1 && (n = read(fd, text + got, sizeof(text) - 1 - got)) > 0) got += n;
	close(fd);
	text[got] = 0;
	attached[0] = 0;
	snprintf(key, sizeof(key), "%08lu", ino);
	for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (!found) {
			unsigned int column = 0;
			char copy[512];
			if (line[0] == '\t') continue;
			snprintf(copy, sizeof(copy), "%s", line);
			for (field = strtok_r(copy, "\t", &fsave); field; field = strtok_r(NULL, "\t", &fsave))
				if (column++ == 5) { found = !strcmp(field, key); break; }
			continue;
		}
		if (!strcmp(line, "\tAttached Devices:")) { in_attached = true; continue; }
		if (!strncmp(line, "Total ", 6) || line[0] != '\t') break;
		if (in_attached) {
			if (attached[0]) strncat(attached, ",", size - strlen(attached) - 1);
			strncat(attached, line + 1, size - strlen(attached) - 1);
		}
	}
	return found;
}

/* NVMe tracepoints: submissions and completions of the I/O queues. */
struct trace_view { unsigned setups[3], completes[3], max_out, inversions; unsigned setup_lens[64]; uint64_t setup_slba[64]; unsigned nr_setup_list; };
static void trace_begin(void) { write_file(TRACE "/trace", ""); }
static int ctrl_of(const char *line)
{
	int i;
	for (i = 0; i < 3; i++) {
		char want[32];
		snprintf(want, sizeof(want), " %s: ", ctrl_name[i]);
		if (strstr(line, want)) return i;
	}
	return -1;
}
static void trace_end(struct trace_view *t, int only)
{
	static char text[1 << 22];
	struct { int ctrl, qid, cid; unsigned seq; } out[512];
	unsigned nr_out = 0, seq = 0, live[3] = {0, 0, 0};
	char *line, *save = NULL;
	ssize_t n, got = 0;
	int fd = open_ok(TRACE "/trace", O_RDONLY);
	memset(t, 0, sizeof(*t));
	while (got < (ssize_t)sizeof(text) - 1 && (n = read(fd, text + got, sizeof(text) - 1 - got)) > 0) got += n;
	close(fd);
	CHECK(got < (ssize_t)sizeof(text) - 1, "trace fits the reader");
	text[got] = 0;
	CHECK(!strstr(text, "LOST"), "no trace events lost");
	for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		bool setup = strstr(line, "nvme_setup_cmd: ") != NULL, done = strstr(line, "nvme_complete_rq: ") != NULL;
		int ctrl, qid, cid;
		const char *q;
		unsigned i;
		if (!setup && !done) continue;
		ctrl = ctrl_of(line);
		q = strstr(line, "qid=");
		if (ctrl < 0 || !q || sscanf(q, "qid=%d, cmdid=%d", &qid, &cid) != 2 || !qid) continue;
		if (setup) {
			const char *c = strstr(line, "slba=");
			unsigned long long slba = 0;
			unsigned len = 0;
			t->setups[ctrl]++;
			if (c && sscanf(c, "slba=%llu, len=%u", &slba, &len) == 2 && ctrl == only && t->nr_setup_list < 64) {
				t->setup_slba[t->nr_setup_list] = slba;
				t->setup_lens[t->nr_setup_list++] = len;
			}
			CHECK(nr_out < 512, "outstanding command table");
			out[nr_out].ctrl = ctrl; out[nr_out].qid = qid; out[nr_out].cid = cid; out[nr_out++].seq = seq++;
			if (ctrl == only && ++live[ctrl] > t->max_out) t->max_out = live[ctrl];
			else if (ctrl != only) live[ctrl]++;
		} else {
			unsigned oldest = UINT_MAX;
			t->completes[ctrl]++;
			for (i = 0; i < nr_out; i++) if (out[i].ctrl == ctrl && out[i].seq < oldest) oldest = out[i].seq;
			for (i = 0; i < nr_out; i++)
				if (out[i].ctrl == ctrl && out[i].qid == qid && out[i].cid == cid) {
					if (ctrl == only && out[i].seq != oldest) t->inversions++;
					live[ctrl]--;
					out[i] = out[--nr_out];
					break;
				}
		}
	}
}

static struct xdev_ext_peer_nvme_batch batch;
static void batch_init(int alloc, uint64_t gen, bool write, unsigned nr)
{
	memset(&batch, 0, sizeof(batch));
	batch.allocation_fd = alloc; batch.generation = gen; batch.nr = nr;
	batch.flags = write ? XDEV_EXT_PEER_NVME_F_WRITE : 0;
}
static void desc(unsigned i, uint64_t offset, uint64_t slba, uint32_t bytes)
{ batch.desc[i] = (struct xdev_ext_peer_nvme_desc){.offset = offset, .slba = slba, .bytes = bytes}; }
static void plan_line(const char *name)
{
	unsigned i;
	printf("PLAN case=%s write=%u nr=%u", name, batch.flags & 1, batch.nr);
	for (i = 0; i < batch.nr; i++)
		printf(" %llu:%llu:%u", (unsigned long long)batch.desc[i].offset,
		       (unsigned long long)batch.desc[i].slba, batch.desc[i].bytes);
	printf("\n");
}
/* Apply the batch's expected effect to an image of the pool or the disk. */
static void expect_read(unsigned char *pool, const unsigned char *disk, unsigned i)
{ memcpy(pool + batch.desc[i].offset, disk + batch.desc[i].slba * LBA, batch.desc[i].bytes); }
static void expect_write(unsigned char *disk, const unsigned char *pool, unsigned i)
{ memcpy(disk + batch.desc[i].slba * LBA, pool + batch.desc[i].offset, batch.desc[i].bytes); }
static int run(int ng)
{
	int ret = ioctl(ng, XDEV_EXT_PEER_NVME_BATCH, &batch);
	return ret < 0 ? -errno : ret;
}
static void refused(int ng, int expected, int ctrl_to_watch, const char *msg)
{
	struct trace_view t;
	int ret;
	plan_line(msg);
	trace_begin();
	ret = run(ng);
	trace_end(&t, ctrl_to_watch);
	printf("OBSERVE case=%s ret=%d completed=%u status=%d setups=%u,%u,%u\n", msg, ret, batch.completed,
	       batch.status, t.setups[SRC], t.setups[DST], t.setups[ERR]);
	CHECK(ret == expected && !batch.completed && batch.status == expected, msg);
	CHECK(!t.setups[SRC] && !t.setups[DST] && !t.setups[ERR], "refused batch: no command reached any controller");
}

/* Device-visible DMA address of every 4 KiB page of the pool: one probe read
 * per MiB with the xdev_ext native tracepoint, whose peer_dma_span events
 * carry each lease's address as the controller was given it. */
static void dma_layout(int ng, int alloc, uint64_t gen, uint64_t *dma)
{
	static char text[1 << 22];
	uint64_t off, pages = P_BYTES / PAGE, seen = 0, bad = 0;
	write_file(TRACE "/events/xdev_ext/native_event/enable", "1");
	for (off = 0; off < P_BYTES; off += MIB) {
		uint64_t len = P_BYTES - off < MIB ? P_BYTES - off : MIB;
		char *line, *save = NULL;
		ssize_t n, got = 0;
		int fd, ret;
		batch_init(alloc, gen, false, 1); desc(0, off, 0, (uint32_t)len);
		trace_begin(); ret = run(ng);
		CHECK(!ret && batch.completed == 1, "layout probe read of one MiB of the pool");
		fd = open_ok(TRACE "/trace", O_RDONLY);
		while (got < (ssize_t)sizeof(text) - 1 && (n = read(fd, text + got, sizeof(text) - 1 - got)) > 0) got += n;
		close(fd);
		text[got] = 0;
		CHECK(got < (ssize_t)sizeof(text) - 1 && !strstr(text, "LOST"), "layout probe trace complete");
		for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
			const char *b = strstr(line, " bytes="), *a = strstr(line, " aux="), *d = strstr(line, " native_user_data=");
			unsigned long long bytes = 0, aux = 0, addr = 0, k;
			if (!strstr(line, "phase=peer_dma_span ")) continue;
			if (!b || !a || !d || sscanf(b, " bytes=%llu", &bytes) != 1 || sscanf(a, " aux=%llu", &aux) != 1 ||
			    sscanf(d, " native_user_data=%llu", &addr) != 1 || aux + bytes > len || (aux % PAGE) ||
			    !bytes || (bytes % PAGE) || (addr % PAGE)) { bad++; continue; }
			for (k = 0; k < bytes; k += PAGE) { dma[(off + aux + k) / PAGE] = addr + k; seen++; }
		}
	}
	write_file(TRACE "/events/xdev_ext/native_event/enable", "0");
	CHECK(!bad && seen == pages, "every pool page has one device-visible DMA address");
}

int main(int argc, char **argv)
{
	int srcb, srcng, dstb, dstng, errb, errng, ctl, heap, holes[HOLES], pbuf, qbuf, palloc, qalloc, ret;
	uint64_t pgen, qgen, *dma, boundary = 0, i, vm0, vm1, vm2;
	unsigned long pino, qino;
	struct trace_view t;
	struct rlimit unlimited = {RLIM_INFINITY, RLIM_INFINITY};
	char attached[512];
	unsigned issued, runs;

	setbuf(stdout, NULL);
	puts("TAP version 13");
	if (argc != 10) {
		fprintf(stderr, "usage: %s SRC_BLOCK SRC_NG DST_BLOCK DST_NG ERR_BLOCK ERR_NG SRC_CTRL DST_CTRL ERR_CTRL\n", argv[0]);
		return 2;
	}
	CHECK(getenv("XDEV_EXT_PEER_BATCH_GUEST") && !strcmp(getenv("XDEV_EXT_PEER_BATCH_GUEST"), "1"), "guest-only opt-in");
	ctrl_name[SRC] = argv[7]; ctrl_name[DST] = argv[8]; ctrl_name[ERR] = argv[9];
	CHECK(!setrlimit(RLIMIT_MEMLOCK, &unlimited), "MEMLOCK limit lifted for the imports");
	srcb = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dstb = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	errb = open_ok(argv[5], O_RDONLY | O_DIRECT); errng = open_ok(argv[6], O_RDONLY);
	{
		uint64_t s, d, e;
		int lb;
		CHECK(!ioctl(srcb, BLKGETSIZE64, &s) && !ioctl(dstb, BLKGETSIZE64, &d) && !ioctl(errb, BLKGETSIZE64, &e) &&
		      s == SRC_BYTES && d == DST_BYTES && e == ERR_BYTES, "disk capacities equal the frozen plan");
		CHECK(!ioctl(srcb, BLKSSZGET, &lb) && lb == LBA && !ioctl(dstb, BLKSSZGET, &lb) && lb == LBA &&
		      !ioctl(errb, BLKSSZGET, &lb) && lb == LBA, "512-byte logical blocks");
	}
	{
		char path[128];
		unsigned kb = 0;
		FILE *f;
		snprintf(path, sizeof(path), "/sys/block/%sn1/queue/max_hw_sectors_kb", ctrl_name[SRC]);
		f = fopen(path, "re");
		CHECK(f && fscanf(f, "%u", &kb) == 1, "queue transfer limit readable");
		fclose(f);
		printf("OBSERVE case=queue max_hw_sectors_kb=%u\n", kb);
		CHECK(kb == 1024, "the controller takes exactly a 1 MiB command (QEMU mdts=8)");
	}
	src_image = malloc(SRC_BYTES); err_image = malloc(ERR_BYTES); dst_expect = malloc(DST_BYTES);
	p_expect = malloc(P_BYTES); q_expect = malloc(Q_BYTES); scratch = malloc(DST_BYTES);
	dma = calloc(P_BYTES / PAGE, sizeof(*dma));
	CHECK(src_image && err_image && dst_expect && p_expect && q_expect && scratch && dma, "verification buffers");
	read_all(srcb, src_image, SRC_BYTES, 0);
	read_all(dstb, dst_expect, DST_BYTES, 0);
	for (i = 0; i < DST_BYTES; i++) if (dst_expect[i] != GUARD) break;
	CHECK(i == DST_BYTES, "private destination starts as guard bytes");

	write_file(TRACE "/trace_clock", "global");
	write_file(TRACE "/buffer_size_kb", "16384");
	write_file(TRACE "/events/nvme/nvme_setup_cmd/enable", "1");
	write_file(TRACE "/events/nvme/nvme_complete_rq/enable", "1");
	write_file(TRACE "/tracing_on", "1");

	/* Fragment free memory with 1 MiB holes, then allocate the pool P. */
	heap = open_ok("/dev/dma_heap/system", O_RDWR);
	for (i = 0; i < HOLES; i++) {
		holes[i] = heap_alloc(heap, 1 * MIB, NULL);
		CHECK(holes[i] >= 0, "1 MiB fragmentation dma-buf");
	}
	for (i = 0; i < HOLES; i += 2) CHECK(!close(holes[i]), "free every other 1 MiB block");
	pbuf = heap_alloc(heap, P_BYTES, &pino);
	CHECK(pbuf >= 0, "system heap allocates the 6 MiB + 68 KiB pool");
	ctl = open_ok("/dev/xdev_ext_peer", O_RDWR);
	vm0 = vmpin();
	palloc = reg(ctl, pbuf, P_BYTES, &pgen);
	CHECK(palloc >= 0 && pgen, "REGISTER imports the pool dma-buf");
	vm1 = vmpin();
	CHECK(vm1 - vm0 == P_BYTES, "VmPin rises by exactly the pool while registered");
	dma_layout(srcng, palloc, pgen, dma);
	for (i = 1, runs = 1; i < P_BYTES / PAGE; i++) {
		if (dma[i] == dma[i - 1] + PAGE) continue;
		runs++;
		if (!boundary && i * PAGE >= 4 * MIB + 128 * KIB && i * PAGE <= P_BYTES - 64 * KIB) boundary = i * PAGE;
	}
	printf("OBSERVE case=pool dma_runs=%u boundary=%llu\n", runs, (unsigned long long)boundary);
	CHECK(boundary, "the pool has a DMA discontinuity inside the frozen window");
	for (i = 0; i < P_BYTES; i++) p_expect[i] = pattern_p(i);
	cpu_access(pbuf, p_expect, P_BYTES, true);

	/* A1: one 1 MiB read is one native command. */
	batch_init(palloc, pgen, false, 1); desc(0, 0, 4096, 1 << 20);
	plan_line("A1"); trace_begin(); ret = run(srcng); trace_end(&t, SRC);
	printf("OBSERVE case=A1 setups=%u lens=%u slba=%llu\n", t.setups[SRC], t.setup_lens[0], (unsigned long long)t.setup_slba[0]);
	CHECK(!ret && batch.completed == 1 && !batch.status, "1 MiB read completes");
	CHECK(t.setups[SRC] == 1 && t.completes[SRC] == 1 && t.setup_lens[0] == 2047 && t.setup_slba[0] == 4096,
	      "the 1 MiB request reached the controller as one 2048-LBA command");
	expect_read(p_expect, src_image, 0);
	/* A2: three 1 MiB reads in one batch, out of address order. */
	batch_init(palloc, pgen, false, 3);
	desc(0, 3 * MIB, 16384, 1 << 20); desc(1, 1 * MIB, 8192, 1 << 20); desc(2, 2 * MIB, 12288, 1 << 20);
	plan_line("A2"); trace_begin(); ret = run(srcng); trace_end(&t, SRC);
	printf("OBSERVE case=A2 setups=%u max_outstanding=%u completion_inversions=%u\n", t.setups[SRC], t.max_out, t.inversions);
	CHECK(!ret && batch.completed == 3 && !batch.status, "three 1 MiB reads complete");
	CHECK(t.setups[SRC] == 3 && t.setup_lens[0] == 2047 && t.setup_lens[1] == 2047 && t.setup_lens[2] == 2047,
	      "three 2048-LBA commands, one per request");
	CHECK(t.max_out >= 2, "commands of one batch were in flight together");
	for (i = 0; i < 3; i++) expect_read(p_expect, src_image, i);
	/* A3: across a DMA discontinuity, and page tails. */
	batch_init(palloc, pgen, false, 3);
	desc(0, boundary - 33280, 24576, 65536); desc(1, 4 * MIB + 1024, 24832, 3072); desc(2, 4 * MIB + 7680, 24840, 4096);
	plan_line("A3"); trace_begin(); ret = run(srcng); trace_end(&t, SRC);
	CHECK(!ret && batch.completed == 3 && !batch.status && t.setups[SRC] == 3,
	      "discontiguous and page-tail requests complete as three commands");
	for (i = 0; i < 3; i++) expect_read(p_expect, src_image, i);
	cpu_access(pbuf, scratch, P_BYTES, false);
	CHECK(!memcmp(scratch, p_expect, P_BYTES), "phase A: whole pool equals the plan, every other byte unchanged");
	write_all(dstb, scratch, P_BYTES, DUMP_A);

	/* B: 40 random disjoint read targets, shuffled, two duplicate source LBAs. */
	{
		unsigned slot[48], k;
		for (k = 0; k < 48; k++) slot[k] = k;
		for (k = 47; k > 0; k--) { unsigned j = rnd() % (k + 1), s = slot[k]; slot[k] = slot[j]; slot[j] = s; }
		batch_init(palloc, pgen, false, 40);
		for (k = 0; k < 40; k++) {
			uint32_t head = 512 * (rnd() % 64), bytes = 512 * (1 + rnd() % 192);
			uint64_t lba = rnd() % (SRC_LBAS - 256);
			desc(k, (uint64_t)slot[k] * 128 * KIB + head, lba, bytes);
		}
		batch.desc[7].slba = batch.desc[3].slba; batch.desc[23].slba = batch.desc[3].slba;
	}
	plan_line("B"); trace_begin(); ret = run(srcng); trace_end(&t, SRC);
	printf("OBSERVE case=B setups=%u max_outstanding=%u completion_inversions=%u\n", t.setups[SRC], t.max_out, t.inversions);
	CHECK(!ret && batch.completed == 40 && !batch.status && t.setups[SRC] == 40,
	      "40 random targets complete, one command each, none resubmitted");
	CHECK(t.max_out >= 2, "random batch commands were in flight together");
	for (i = 0; i < 40; i++) expect_read(p_expect, src_image, i);
	cpu_access(pbuf, scratch, P_BYTES, false);
	CHECK(!memcmp(scratch, p_expect, P_BYTES), "phase B: whole pool equals the plan (duplicate sources included)");
	write_all(dstb, scratch, P_BYTES, DUMP_B);

	/* C: writes from the pool, 1 MiB and 32 random disjoint LBA targets. */
	for (i = 0; i < P_BYTES; i++) p_expect[i] = pattern_w(i);
	cpu_access(pbuf, p_expect, P_BYTES, true);
	batch_init(palloc, pgen, true, 1); desc(0, 0, 0, 1 << 20);
	plan_line("C1"); trace_begin(); ret = run(dstng); trace_end(&t, DST);
	CHECK(!ret && batch.completed == 1 && t.setups[DST] == 1 && t.setup_lens[0] == 2047,
	      "1 MiB write is one 2048-LBA command");
	expect_write(dst_expect, p_expect, 0);
	{
		unsigned slot[32], k;
		for (k = 0; k < 32; k++) slot[k] = k;
		for (k = 31; k > 0; k--) { unsigned j = rnd() % (k + 1), s = slot[k]; slot[k] = slot[j]; slot[j] = s; }
		batch_init(palloc, pgen, true, 32);
		for (k = 0; k < 32; k++) {
			uint64_t lba = 4096 + (uint64_t)slot[k] * 768 + rnd() % 128;
			uint32_t bytes = 512 * (1 + rnd() % 512);
			uint64_t source = 512ULL * (rnd() % ((P_BYTES - 256 * KIB) / 512));
			desc(k, source, lba, bytes);
		}
	}
	plan_line("C2"); trace_begin(); ret = run(dstng); trace_end(&t, DST);
	printf("OBSERVE case=C2 setups=%u max_outstanding=%u completion_inversions=%u\n", t.setups[DST], t.max_out, t.inversions);
	CHECK(!ret && batch.completed == 32 && t.setups[DST] == 32, "32 random LBA write targets complete");
	for (i = 0; i < 32; i++) expect_write(dst_expect, p_expect, i);
	CHECK(!ioctl(dstb, BLKFLSBUF), "drop cached destination pages before readback");
	read_all(dstb, scratch, 14 * MIB, 0);
	CHECK(!memcmp(scratch, dst_expect, 14 * MIB), "phase C: destination write region equals the plan, guards kept");

	/* D: refusals before any device sees the batch. */
	batch_init(palloc, pgen, false, 4);
	desc(0, 0, 0, 4096); desc(1, 64 * KIB, 8, 4096); desc(2, 128 * KIB, 16, 4096); desc(3, 64 * KIB, 24, 4096);
	refused(srcng, -EINVAL, SRC, "D1-duplicate-target");
	batch_init(palloc, pgen, false, 6);
	for (i = 0; i < 6; i++) desc(i, i * 256 * KIB, i * 64, 65536);
	batch.desc[5].offset = 65536 - 512;
	refused(srcng, -EINVAL, SRC, "D2-overlap-last");
	batch_init(palloc, pgen, true, 2); desc(0, 0, 100, 8192); desc(1, 1 * MIB, 115, 1024);
	refused(dstng, -EINVAL, DST, "D3-write-lba-overlap");
	batch_init(palloc, pgen, false, 5);
	for (i = 0; i < 5; i++) desc(i, i * 512 * KIB, i * 128, 65536);
	batch.desc[4].offset = P_BYTES - 4096;
	refused(srcng, -ERANGE, SRC, "D4-target-past-pool");
	batch_init(palloc, pgen, false, 3);
	for (i = 0; i < 3; i++) desc(i, i * 512 * KIB, i * 128, 4096);
	batch.desc[2].slba = SRC_LBAS - 1; batch.desc[2].bytes = 1024;
	refused(srcng, -ERANGE, SRC, "D5-lba-past-namespace");
	batch_init(palloc, pgen, false, 2); desc(0, 0, 10, 4096); desc(1, UINT64_MAX - 4095, 20, 8192);
	refused(srcng, -EOVERFLOW, SRC, "D6-offset-wrap");
	batch_init(palloc, pgen, false, 2); desc(0, 0, 10, 4096); desc(1, 8192, UINT64_MAX - 7, 4096);
	refused(srcng, -ERANGE, SRC, "D7-lba-wrap");
	batch_init(palloc, pgen + 1, false, 1); desc(0, 0, 10, 4096);
	refused(srcng, -ESTALE, SRC, "D8-wrong-generation");
	batch_init(palloc, pgen, false, 2); desc(0, 0, 10, 4096); desc(1, 1 * MIB, 100, (1 << 20) + 4096);
	refused(srcng, -E2BIG, SRC, "D9-over-transfer-limit");
	cpu_access(pbuf, scratch, P_BYTES, false);
	CHECK(!memcmp(scratch, p_expect, P_BYTES), "phase D: the pool is unchanged by every refused batch");
	CHECK(!ioctl(dstb, BLKFLSBUF), "drop cached destination pages before readback");
	read_all(dstb, scratch, 14 * MIB, 0);
	CHECK(!memcmp(scratch, dst_expect, 14 * MIB), "phase D: the destination is unchanged by every refused batch");

	/* E: an accepted command fails on ERR; the allocation is retained. */
	qbuf = heap_alloc(heap, Q_BYTES, &qino);
	CHECK(qbuf >= 0, "system heap allocates the 1 MiB pool of phase E");
	for (i = 0; i < Q_BYTES; i++) q_expect[i] = pattern_q(i);
	cpu_access(qbuf, q_expect, Q_BYTES, true);
	vm0 = vmpin();
	qalloc = reg(ctl, qbuf, Q_BYTES, &qgen);
	CHECK(qalloc >= 0 && qgen, "REGISTER imports the phase E dma-buf");
	CHECK(vmpin() - vm0 == Q_BYTES, "VmPin rises by exactly the phase E pool");
	batch_init(qalloc, qgen, false, 6);
	for (i = 0; i < 6; i++) desc(i, i * 128 * KIB, 2048 + i * 128, 65536);
	plan_line("E1"); trace_begin(); ret = run(errng); trace_end(&t, ERR);
	{
		unsigned d2 = 0, k;
		for (k = 0; k < t.nr_setup_list; k++) d2 += t.setup_slba[k] == 2304;
		issued = t.setups[ERR];
		printf("OBSERVE case=E1 ret=%d completed=%u status=%d setups=%u d2_setups=%u completes=%u\n",
		       ret, batch.completed, batch.status, issued, d2, t.completes[ERR]);
		CHECK(ret > 0 && batch.status == ret && batch.completed == 2,
		      "native NVMe status of the failed command; completed is the two-request prefix");
		CHECK(d2 == 1 && issued >= 3 && issued <= 6 && t.completes[ERR] == issued,
		      "the failed command was issued once and never resubmitted; every issued command completed");
		for (k = 0; k < 6; k++) {
			if (k == 2 || k >= issued) continue;
			read_direct(errb, err_image, 65536, (off_t)(batch.desc[k].slba * LBA));
			memcpy(q_expect + batch.desc[k].offset, err_image, 65536);
		}
	}
	cpu_access(qbuf, scratch, Q_BYTES, false);
	memcpy(scratch + 2 * 128 * KIB, q_expect + 2 * 128 * KIB, 65536); /* the failed command's bytes are unspecified */
	CHECK(!memcmp(scratch, q_expect, Q_BYTES), "phase E: completed and later issued requests landed, others untouched");
	cpu_access(qbuf, scratch, Q_BYTES, false);
	write_all(dstb, scratch, Q_BYTES, DUMP_Q);
	batch_init(qalloc, qgen, false, 1); desc(0, 0, 0, 4096);
	refused(srcng, -ESTALE, SRC, "E2-quarantined-allocation");
	vm1 = vmpin();
	CHECK(!close(qalloc), "close the quarantined allocation fd");
	vm2 = vmpin();
	printf("OBSERVE case=E3 vmpin_before_close=%llu vmpin_after_close=%llu\n", (unsigned long long)vm1, (unsigned long long)vm2);
	CHECK(vm2 == vm1, "UNKNOWN DMA: the MEMLOCK charge is retained after the last fd closed");
	CHECK(bufinfo(qino, attached, sizeof(attached)) && attached[0], "UNKNOWN DMA: the requester attachment is retained");
	printf("OBSERVE case=E3 attached=%s\n", attached);
	CHECK(reg(ctl, qbuf, Q_BYTES, &qgen) == -EBUSY, "UNKNOWN DMA: the same dma-buf cannot be imported again");

	/* The normal path releases: close the pool's allocation fd. */
	vm1 = vmpin();
	CHECK(!close(palloc), "close the pool allocation fd");
	vm2 = vmpin();
	CHECK(vm1 - vm2 == P_BYTES, "the pool's MEMLOCK charge returns after its last fd closed");
	CHECK(bufinfo(pino, attached, sizeof(attached)) && !attached[0], "the pool has no requester attachment left");
	CHECK(!fsync(dstb), "flush the dumps");
	printf("1..%u\n", checks);
	printf("XDEV_EXT_PEER_BATCH=PASS phases=A,B,C,D,E pool=system-heap requesters=3 timing=none\n");
	return 0;
}
