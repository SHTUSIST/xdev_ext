// SPDX-License-Identifier: GPL-2.0
/* Guest-only correctness test, prototype for ASK.70. The dma-buf comes from
 * the upstream udmabuf driver, which registers no xdev_ext backing
 * descriptor. It is imported through /dev/xdev_ext_peer with the opt-in
 * XDEV_EXT_PEER_REGISTER_F_DMABUF_UNDESCRIBED and then read and written by
 * real QEMU NVMe PCI DMA through XDEV_EXT_PEER_NVME_BATCH. No timing.
 *
 * usage: undescribed_dma MODE SRC_NG DST_NG SRC_PCI DST_PCI
 *   MODE normal: DMA must land; MODE refuse: the guest booted with
 *   swiotlb=force, so every requester must be refused before any attach.
 *
 * Output is TAP. Each check has a fixed id; the host oracle requires the exact
 * id list for the mode, the plan line, and the destination image.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/dma-buf.h>
#include <linux/udmabuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "linux/xdev_ext_peer.h"

#define PAGE 4096u
#define PAGES 16u
#define EXPORT (PAGE * PAGES)
#define LBA 512u
#define RANGE_A 2048ULL /* reverse-order READ source, WRITE destination */
#define RANGE_B 4096ULL /* after the exporter fds are closed */
#define BUFINFO "/sys/kernel/debug/dma_buf/bufinfo"
#define FILL 0xee
#define BOTH (XDEV_EXT_PEER_REGISTER_F_DMABUF | XDEV_EXT_PEER_REGISTER_F_DMABUF_UNDESCRIBED)

static unsigned checks;
static bool failed;

static void check(bool ok, const char *id, int err)
{
	checks++;
	if (ok) {
		printf("ok %u - %s\n", checks, id);
	} else {
		printf("not ok %u - %s errno=%d (%s)\n", checks, id, err, strerror(err));
		failed = true;
	}
}

/* Same formula as validate.py: the sector number, then a pattern. */
static unsigned char source_byte(uint64_t sector, unsigned j)
{
	if (j < 8) return (unsigned char)(sector >> (8 * j));
	return (unsigned char)((sector * 131 + j * 7 + 0x3d) & 0xff);
}
static unsigned char pattern_byte(unsigned i)
{
	return (unsigned char)(((i * 29u) + 0x5au) ^ (i >> 12));
}

static uint64_t vmpin(void)
{
	FILE *f = fopen("/proc/self/status", "re");
	char line[256];
	unsigned long long kb = ULLONG_MAX;
	if (!f) return UINT64_MAX;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "VmPin: %llu kB", &kb) == 1) break;
	fclose(f);
	return kb == ULLONG_MAX ? UINT64_MAX : kb * 1024;
}

/* memfd -> udmabuf, the upstream exporter without a descriptor. */
static int make_udmabuf(int udmabuf, int *memfd, unsigned char **map, unsigned long *ino)
{
	struct udmabuf_create c = {.flags = UDMABUF_FLAGS_CLOEXEC, .offset = 0, .size = EXPORT};
	struct stat st;
	int buf;
	*memfd = memfd_create("xdev-ext-undescribed", MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (*memfd < 0 || ftruncate(*memfd, EXPORT) || fcntl(*memfd, F_ADD_SEALS, F_SEAL_SHRINK))
		return -errno;
	*map = mmap(NULL, EXPORT, PROT_READ | PROT_WRITE, MAP_SHARED, *memfd, 0);
	if (*map == MAP_FAILED) return -errno;
	memset(*map, FILL, EXPORT);
	c.memfd = (__u32)*memfd;
	buf = ioctl(udmabuf, UDMABUF_CREATE, &c);
	if (buf < 0) return -errno;
	if (fstat(buf, &st)) return -errno;
	*ino = st.st_ino;
	return buf;
}

static int reg(int ctl, int buf, __u32 flags, uint64_t *generation)
{
	struct xdev_ext_peer_register r = {.gpu_fd = buf, .flags = flags, .len = EXPORT};
	int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &r);
	if (fd < 0) return -errno;
	if (generation) *generation = r.generation;
	return fd;
}

static int nvme_batch(int ng, int alloc, uint64_t generation, bool write, uint64_t slba0,
		      bool reverse, unsigned *completed)
{
	struct xdev_ext_peer_nvme_batch b = {.allocation_fd = alloc, .generation = generation,
		.flags = write ? XDEV_EXT_PEER_NVME_F_WRITE : 0, .nr = PAGES};
	unsigned i;
	int ret;
	for (i = 0; i < PAGES; i++)
		b.desc[i] = (struct xdev_ext_peer_nvme_desc){.offset = (uint64_t)i * PAGE,
			.slba = slba0 + (uint64_t)(reverse ? PAGES - 1 - i : i) * (PAGE / LBA),
			.bytes = PAGE};
	ret = ioctl(ng, XDEV_EXT_PEER_NVME_BATCH, &b);
	*completed = b.completed;
	if (ret < 0) return -errno;
	return b.status;
}

/* 1 if the buffer with this inode is listed, 0 if not, -1 on error.
 * exporter and attached receive the exp_name column and attached devices. */
static int bufinfo(unsigned long ino, char *exporter, size_t esize, char *attached, size_t asize)
{
	static char text[1 << 16];
	char key[32], *line, *save = NULL;
	bool found = false, in_attached = false;
	ssize_t n = 0, got = 0;
	int fd = open(BUFINFO, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	while (got < (ssize_t)sizeof(text) - 1 && (n = read(fd, text + got, sizeof(text) - 1 - got)) > 0)
		got += n;
	close(fd);
	if (n < 0 || got >= (ssize_t)sizeof(text) - 1) return -1;
	text[got] = 0;
	attached[0] = exporter[0] = 0;
	snprintf(key, sizeof(key), "%08lu", ino);
	for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (!found) {
			/* size, flags, mode, count, exp_name, ino, name */
			char copy[512], *field, *fsave = NULL, *name = NULL;
			unsigned column = 0;
			if (line[0] == '\t') continue;
			snprintf(copy, sizeof(copy), "%s", line);
			for (field = strtok_r(copy, "\t", &fsave); field; field = strtok_r(NULL, "\t", &fsave)) {
				if (column == 4) name = field;
				if (column++ == 5) {
					found = !strcmp(field, key);
					if (found && name) snprintf(exporter, esize, "%s", name);
					break;
				}
			}
			continue;
		}
		if (!strcmp(line, "\tAttached Devices:")) { in_attached = true; continue; }
		if (!strncmp(line, "Total ", 6)) break;
		if (in_attached && line[0] == '\t') {
			if (attached[0]) strncat(attached, ",", asize - strlen(attached) - 1);
			strncat(attached, line + 1, asize - strlen(attached) - 1);
		}
	}
	return found;
}

/* Number of attached entries; *src and *dst say whether each function is one. */
static unsigned attachments(const char *attached, const char *src_pci, const char *dst_pci,
			    bool *src, bool *dst)
{
	char copy[256], *tok, *save = NULL;
	unsigned n = 0;
	*src = *dst = false;
	snprintf(copy, sizeof(copy), "%s", attached);
	for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		n++;
		*src |= !strcmp(tok, src_pci);
		*dst |= !strcmp(tok, dst_pci);
	}
	return n;
}

static bool released(unsigned long ino)
{
	char exporter[64], attached[256];
	unsigned tries;
	int present = 1;
	/* Release can finish on deferred work; wait only for the buffer itself. */
	for (tries = 0; tries < 6000 && (present = bufinfo(ino, exporter, sizeof(exporter),
			attached, sizeof(attached))) == 1; tries++)
		usleep(10000);
	return present == 0;
}

int main(int argc, char **argv)
{
	const char *mode, *src_pci, *dst_pci;
	char exporter[64], attached[256];
	unsigned char *map = MAP_FAILED, *expect;
	unsigned long ino = 0, ino2 = 0;
	uint64_t base = UINT64_MAX, generation = 0, gen2 = 0;
	unsigned completed, i, n;
	int ctl, udm, src, dst, memfd = -1, memfd2 = -1, buf, buf2, peer, peer2, ret, listed;
	bool refuse, has_src, has_dst;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 6) { fprintf(stderr, "usage: %s MODE SRC_NG DST_NG SRC_PCI DST_PCI\n", argv[0]); return 2; }
	mode = argv[1]; src_pci = argv[4]; dst_pci = argv[5];
	if (strcmp(mode, "normal") && strcmp(mode, "refuse")) { fprintf(stderr, "bad mode\n"); return 2; }
	refuse = !strcmp(mode, "refuse");
	printf("PLAN mode=%s export=%u pages=%u range_a=%llu range_b=%llu\n", mode, EXPORT, PAGES,
	       RANGE_A, RANGE_B);
	expect = malloc(EXPORT);
	if (!expect) return 2;

	ctl = open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC);
	check(ctl >= 0, "open-control", errno);
	udm = open("/dev/udmabuf", O_RDWR | O_CLOEXEC);
	check(udm >= 0, "open-udmabuf", errno);
	src = open(argv[2], O_RDWR | O_CLOEXEC);
	check(src >= 0, "open-source-namespace", errno);
	dst = open(argv[3], O_RDWR | O_CLOEXEC);
	check(dst >= 0, "open-destination-namespace", errno);
	if (failed) goto out;
	buf = make_udmabuf(udm, &memfd, &map, &ino);
	check(buf >= 0, "udmabuf-create", buf < 0 ? -buf : 0);
	if (buf < 0) goto out;
	listed = bufinfo(ino, exporter, sizeof(exporter), attached, sizeof(attached));
	printf("OBSERVE bufinfo exporter=%s attached=%s\n", exporter, attached[0] ? attached : "-");
	check(listed == 1 && !strcmp(exporter, "udmabuf") && !attached[0], "bufinfo-exporter-udmabuf", 0);
	base = vmpin();
	check(base != UINT64_MAX, "vmpin-baseline", 0);

	/* The default contract is unchanged on a real kernel. */
	ret = reg(ctl, buf, XDEV_EXT_PEER_REGISTER_F_DMABUF, NULL);
	check(ret == -EOPNOTSUPP, "default-register-refused", ret < 0 ? -ret : 0);
	if (ret >= 0) close(ret);
	ret = reg(ctl, buf, XDEV_EXT_PEER_REGISTER_F_DMABUF_UNDESCRIBED, NULL);
	check(ret == -EINVAL, "opt-in-alone-invalid", ret < 0 ? -ret : 0);
	if (ret >= 0) close(ret);
	ret = reg(ctl, buf, BOTH | 2u, NULL);
	check(ret == -EINVAL, "reserved-bit-invalid", ret < 0 ? -ret : 0);
	if (ret >= 0) close(ret);
	check(vmpin() == base, "refusals-charge-nothing", 0);

	peer = reg(ctl, buf, BOTH, &generation);
	check(peer >= 0 && generation, "undescribed-register", peer < 0 ? -peer : 0);
	if (peer < 0) goto out;
	check(fcntl(peer, F_GETFD) & FD_CLOEXEC, "allocation-fd-cloexec", errno);
	check(vmpin() == base + EXPORT, "whole-export-charged", 0);
	ret = reg(ctl, buf, BOTH, NULL);
	check(ret == -EBUSY, "duplicate-busy", ret < 0 ? -ret : 0);
	if (ret >= 0) close(ret);

	ret = nvme_batch(src, peer, generation, false, RANGE_A, true, &completed);
	printf("OBSERVE read status=%d completed=%u\n", ret, completed);
	if (!refuse) {
		check(ret == 0 && completed == PAGES, "batch-read", ret < 0 ? -ret : 0);
		for (i = 0; i < EXPORT; i++) {
			uint64_t page = i / PAGE, sector = RANGE_A + (PAGES - 1 - page) * (PAGE / LBA) +
				(i % PAGE) / LBA;
			expect[i] = source_byte(sector, i % LBA);
		}
		check(!memcmp(map, expect, EXPORT), "batch-read-bytes", 0);
	} else {
		check(ret == -EXDEV && completed == 0, "batch-read-refused", ret < 0 ? -ret : 0);
		memset(expect, FILL, EXPORT);
		check(!memcmp(map, expect, EXPORT), "region-untouched", 0);
	}
	listed = bufinfo(ino, exporter, sizeof(exporter), attached, sizeof(attached));
	printf("OBSERVE bufinfo after-read attached=%s\n", attached[0] ? attached : "-");
	n = attachments(attached, src_pci, dst_pci, &has_src, &has_dst);
	if (!refuse)
		check(listed == 1 && n == 1 && has_src, "source-function-attached", 0);
	else
		check(listed == 1 && n == 0, "refused-before-attach", 0);

	for (i = 0; i < EXPORT; i++) map[i] = pattern_byte(i);
	ret = nvme_batch(dst, peer, generation, true, RANGE_A, false, &completed);
	printf("OBSERVE write status=%d completed=%u\n", ret, completed);
	if (!refuse)
		check(ret == 0 && completed == PAGES, "batch-write", ret < 0 ? -ret : 0);
	else
		check(ret == -EXDEV && completed == 0, "batch-write-refused", ret < 0 ? -ret : 0);
	listed = bufinfo(ino, exporter, sizeof(exporter), attached, sizeof(attached));
	printf("OBSERVE bufinfo after-write attached=%s\n", attached[0] ? attached : "-");
	n = attachments(attached, src_pci, dst_pci, &has_src, &has_dst);
	if (!refuse)
		check(listed == 1 && n == 2 && has_src && has_dst, "one-attachment-per-function", 0);
	else
		check(listed == 1 && n == 0, "still-no-attachment", 0);

	/* The application drops every exporter-side handle; the importer's own
	 * buffer reference keeps the memory and its accounting. */
	ret = munmap(map, EXPORT);
	map = MAP_FAILED;
	ret |= close(memfd);
	memfd = -1;
	ret |= close(buf);
	check(!ret, "exporter-fds-closed", errno);
	check(vmpin() == base + EXPORT, "charge-kept-after-exporter-close", 0);
	if (!refuse) {
		ret = nvme_batch(src, peer, generation, false, RANGE_B, false, &completed);
		check(ret == 0 && completed == PAGES, "read-after-exporter-close", ret < 0 ? -ret : 0);
		ret = nvme_batch(dst, peer, generation, true, RANGE_B, false, &completed);
		check(ret == 0 && completed == PAGES, "write-after-exporter-close", ret < 0 ? -ret : 0);
	}
	check(!close(peer), "allocation-close", errno);
	check(vmpin() == base, "charge-returned", 0);
	check(released(ino), "buffer-released", 0);

	/* No identity or charge is left behind: a fresh import works and returns. */
	buf2 = make_udmabuf(udm, &memfd2, &map, &ino2);
	check(buf2 >= 0, "second-udmabuf-create", buf2 < 0 ? -buf2 : 0);
	if (buf2 < 0) goto out;
	peer2 = reg(ctl, buf2, BOTH, &gen2);
	check(peer2 >= 0 && gen2 && gen2 != generation, "second-register", peer2 < 0 ? -peer2 : 0);
	if (peer2 >= 0) close(peer2);
	munmap(map, EXPORT);
	map = MAP_FAILED;
	close(memfd2);
	close(buf2);
	check(vmpin() == base, "final-charge-baseline", 0);
	check(released(ino2), "second-buffer-released", 0);
out:
	if (map != MAP_FAILED) munmap(map, EXPORT);
	printf("1..%u\n", checks);
	printf("RESULT mode=%s checks=%u %s\n", mode, checks, failed ? "FAIL" : "PASS");
	return failed ? 1 : 0;
}
