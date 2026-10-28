// SPDX-License-Identifier: GPL-2.0
/* Real native NVMe ioctl and PCI DMA, guest-only host-RAM provider fixture. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include "linux/xdev_ext_peer.h"
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "sw_provider_uapi.h"

static unsigned int checks;
static unsigned int completed_reads, completed_writes;
#define CHECK(c, msg) do { if (!(c)) { \
	fprintf(stderr, "not ok %u - %s (errno=%d %s)\n", ++checks, msg, errno, strerror(errno)); \
	exit(1); } printf("ok %u - %s\n", ++checks, msg); } while (0)
static int open_ok(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);
	CHECK(fd >= 0, path);
	return fd;
}
static void read_all(int fd, void *buf, size_t bytes, off_t off)
{
	CHECK(pread(fd, buf, bytes, off) == (ssize_t)bytes, "complete pread");
}
static void write_all(int fd, const void *buf, size_t bytes, off_t off)
{
	CHECK(pwrite(fd, buf, bytes, off) == (ssize_t)bytes, "complete pwrite");
}
static struct peer_sw_stats stats(int fd)
{
	struct peer_sw_stats s = {};
	CHECK(!ioctl(fd, PEER_SW_STATS, &s), "provider lifetime counters");
	return s;
}
static int registration(int ctl, int provider, uint64_t *generation)
{
	struct xdev_ext_peer_register r = {
		.gpu_fd = provider, .gpu_va = PEER_SW_VA, .len = PEER_SW_BYTES,
	};
	int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &r);
	CHECK(fd >= 0 && r.generation, "REGISTER returns allocation fd and nonzero generation");
	*generation = r.generation;
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC, "allocation fd is CLOEXEC");
	return fd;
}
static struct xdev_ext_peer_nvme_batch batch(int alloc, uint64_t gen,
		unsigned int nr, uint64_t slba, int write)
{
	struct xdev_ext_peer_nvme_batch b = {
		.allocation_fd = alloc, .generation = gen, .nr = nr,
		.flags = write ? XDEV_EXT_PEER_NVME_F_WRITE : 0,
	};
	unsigned int i;
	for (i = 0; i < nr; i++) {
		b.desc[i].offset = i * 1024;
		b.desc[i].slba = slba + i * 2;
		b.desc[i].bytes = 1024;
	}
	return b;
}
static void refused(int ng, struct xdev_ext_peer_nvme_batch *b, int expected)
{
	int ret;
	errno = 0;
	ret = ioctl(ng, XDEV_EXT_PEER_NVME_BATCH, b);
	CHECK(ret == -1 && errno == expected && b->completed == 0,
	      "native ioctl refuses without completed commands");
}
static void native_batch(int ng, struct xdev_ext_peer_nvme_batch *b)
{
	int ret = ioctl(ng, XDEV_EXT_PEER_NVME_BATCH, b);
	if (ret) fprintf(stderr, "# native SGL failure: ret=%d errno=%d status=%d completed=%u; no retry/fallback\n",
		ret, errno, b->status, b->completed);
	CHECK(!ret && b->status == 0 && b->completed == b->nr,
	      "native SGL batch completes exact bounded prefix");
	if (b->flags & XDEV_EXT_PEER_NVME_F_WRITE) completed_writes += b->completed;
	else completed_reads += b->completed;
}
int main(int argc, char **argv)
{
	static const unsigned int groups[] = {32, 64, 64, 64, 33};
	unsigned char memory[PEER_SW_BYTES], expected[PEER_SW_BYTES];
	unsigned char *source, *source_after, *dest, *dest_after;
	uint64_t source_bytes, dest_bytes, gen, badgen, slba = 2048;
	unsigned int g, i, ordinal = 0;
	struct stat ss, ds;
	struct peer_sw_stats before, during, after;
	struct xdev_ext_peer_nvme_batch b;
	int src, srcng, dst, dstng, ctl, observer, provider, alloc, original, bad;
	setbuf(stdout, NULL);
	puts("TAP version 13\n# guest software provider: host RAM/CPU stand-in, real QEMU NVMe PCI DMA, native serial depth=1");
	if (argc != 5 && argc != 6) {
		fprintf(stderr, "usage: %s SOURCE_BLOCK SOURCE_NG PRIVATE_DEST_BLOCK PRIVATE_DEST_NG [SOURCE_SLBA]\n", argv[0]);
		return 2;
	}
	if (argc == 6) slba = strtoull(argv[5], NULL, 0);
	/* Fail closed on hosts: only run under the harness's explicit guest flag. */
	CHECK(getenv("XDEV_EXT_PEER_GUEST") && !strcmp(getenv("XDEV_EXT_PEER_GUEST"), "1"), "guest-only opt-in");
	observer = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
	before = stats(observer);
	CHECK(!before.live_pins && !before.live_maps, "isolated provider starts without pins or maps");
	ctl = open_ok("/dev/xdev_ext_peer", O_RDWR);
	src = open_ok(argv[1], O_RDONLY); srcng = open_ok(argv[2], O_RDONLY);
	dst = open_ok(argv[3], O_RDWR); dstng = open_ok(argv[4], O_RDWR);
	CHECK(!fstat(src, &ss) && !fstat(dst, &ds) && S_ISBLK(ss.st_mode) &&
	      S_ISBLK(ds.st_mode) && ss.st_rdev != ds.st_rdev, "distinct source and private destination block devices");
	CHECK(!ioctl(src, BLKGETSIZE64, &source_bytes) && !ioctl(dst, BLKGETSIZE64, &dest_bytes), "disk capacities");
	CHECK(source_bytes <= 128U * 1024 * 1024 && dest_bytes <= 128U * 1024 * 1024 &&
	      source_bytes >= slba * 512 + 257 * 1024 && dest_bytes >= 1024 * 1024 + 257 * 1024,
	      "bounded whole-disk comparison and 257 distinct descriptors fit");
	{
		int lb;
		CHECK(!ioctl(src, BLKSSZGET, &lb) && lb == 512 && !ioctl(dst, BLKSSZGET, &lb) && lb == 512,
		      "fixture requires 512-byte logical sectors");
	}
	source = malloc(source_bytes); source_after = malloc(source_bytes);
	dest = malloc(dest_bytes); dest_after = malloc(dest_bytes);
	CHECK(source && source_after && dest && dest_after, "whole-disk verification buffers");
	read_all(src, source, source_bytes, 0);
	memset(dest, 0x6b, dest_bytes); write_all(dst, dest, dest_bytes, 0);
	CHECK(!fsync(dst), "initialize private destination guards");
	provider = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
	original = registration(ctl, provider, &gen);
	alloc = dup(original); CHECK(alloc >= 0, "duplicate allocation authority");
	CHECK(!close(original), "close original allocation fd before native IO");
	b = batch(alloc, gen + 1, 1, slba, 0); refused(srcng, &b, ESTALE);
	CHECK(b.status == -ESTALE, "wrong generation returned in batch status");
	b = batch(alloc, gen, 1, slba, 0); b.desc[0].offset = PEER_SW_BYTES;
	refused(srcng, &b, ERANGE);
	b = batch(alloc, gen, 1, slba, 0); b.nr = 65; refused(srcng, &b, EINVAL);
	b = batch(alloc, gen, 1, slba, 1); refused(srcng, &b, EBADF);
	/* A later admission refusal preserves the exactly completed first prefix. */
	memset(expected, 0x5d, sizeof(expected)); write_all(provider, expected, sizeof(expected), 0);
	b = batch(alloc, gen, 2, slba, 0); b.desc[1].offset = PEER_SW_BYTES;
	errno = 0;
	CHECK(ioctl(srcng, XDEV_EXT_PEER_NVME_BATCH, &b) == -1 && errno == ERANGE &&
	      b.status == -ERANGE && b.completed == 1, "admission failure preserves exact completed native prefix");
	completed_reads += b.completed;
	memcpy(expected, source + slba * 512, 1024); read_all(provider, memory, sizeof(memory), 0);
	CHECK(!memcmp(memory, expected, sizeof(memory)), "failed-prefix read changes only the completed descriptor");
	/* Distinct open/allocation: reject unsupported provider map capability. */
	bad = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
	CHECK(!ioctl(bad, PEER_SW_REJECT_MAP), "configure unsupported software mapping capability");
	original = registration(ctl, bad, &badgen);
	CHECK(badgen != gen, "allocation generations are distinct");
	b = batch(original, badgen, 1, slba, 0); refused(srcng, &b, EOPNOTSUPP);
	CHECK(b.status == -EOPNOTSUPP, "unsupported map capability propagates without fallback");
	close(original); close(bad);
	{
		struct xdev_ext_peer_net_batch n = {.allocation_fd = alloc, .generation = gen,
			.ifindex = if_nametoindex("lo"), .nr = 1, .flags = 1};
		errno = 0;
		CHECK(ioctl(ctl, XDEV_EXT_PEER_NET_TX, &n) == -1 && errno == EOPNOTSUPP,
		      "RX request is rejected");
		n.flags = 0;
		CHECK(ioctl(ctl, XDEV_EXT_PEER_NET_TX, &n) == -1 && errno == EOPNOTSUPP,
		      "loopback without native peer capability is rejected");
	}
	/* Probe the complete 64KiB geometry as one actual native command too. */
	b = batch(alloc, gen, 1, slba, 0); b.desc[0].bytes = PEER_SW_BYTES;
	native_batch(srcng, &b); read_all(provider, memory, sizeof(memory), 0);
	CHECK(!memcmp(memory, source + slba * 512, sizeof(memory)), "single 64KiB native SGL span");
	for (g = 0; g < sizeof(groups) / sizeof(groups[0]); g++) {
		memset(expected, 0xa5, sizeof(expected)); write_all(provider, expected, sizeof(expected), 0);
		b = batch(alloc, gen, groups[g], slba + ordinal * 2, 0); native_batch(srcng, &b);
		memcpy(expected, source + slba * 512 + ordinal * 1024, groups[g] * 1024);
		read_all(provider, memory, sizeof(memory), 0);
		CHECK(!memcmp(memory, expected, sizeof(memory)), "NVMe read: all 65536 bytes including untouched allocation tail");
		ordinal += groups[g];
	}
	CHECK(ordinal == 257, "257 distinct source descriptors across five bounded groups");
	ordinal = 0;
	for (g = 0; g < sizeof(groups) / sizeof(groups[0]); g++) {
		for (i = 0; i < sizeof(memory); i++) memory[i] = (i * 29 + g * 71 + (i >> 8)) & 255;
		write_all(provider, memory, sizeof(memory), 0);
		memcpy(dest + 1024 * 1024 + ordinal * 1024, memory, groups[g] * 1024);
		b = batch(alloc, gen, groups[g], 2048 + ordinal * 2, 1);
		if (g == 4) {
			CHECK(!close(provider), "close original provider fd before final native batch");
			close(observer);
			errno = 0;
			CHECK(syscall(SYS_delete_module, "xdev_ext_peer_sw", O_NONBLOCK) == -1 && errno == EWOULDBLOCK,
			      "allocation authority alone prevents provider module unload");
			observer = open_ok("/dev/xdev_ext_peer_sw", O_RDWR);
		}
		native_batch(dstng, &b); ordinal += groups[g];
	}
	during = stats(observer);
	CHECK(during.live_pins == 1 && during.live_maps == 2 && during.maps - before.maps == 2,
	      "one live allocation, one cached real DMA mapping per NVMe PCI function");
	CHECK(during.pins - before.pins == 2 && during.unpins - before.unpins == 1,
	      "rejected capability allocation was unpinned exactly once");
	CHECK(ordinal == 257, "257 native write descriptors, no user continuation within batch");
	CHECK(!ioctl(src, BLKFLSBUF) && !ioctl(dst, BLKFLSBUF), "invalidate block cache before independent disk readback");
	read_all(src, source_after, source_bytes, 0); read_all(dst, dest_after, dest_bytes, 0);
	CHECK(!memcmp(source, source_after, source_bytes), "whole source disk unchanged");
	CHECK(!memcmp(dest, dest_after, dest_bytes), "whole destination disk matches payload and every guard byte");
	CHECK(!close(alloc), "close final allocation authority");
	after = stats(observer);
	CHECK(!after.live_maps && !after.live_pins && after.maps - before.maps == after.unmaps - before.unmaps &&
	      after.pins - before.pins == after.unpins - before.unpins,
	      "all successful pins/maps released exactly once");
	CHECK(after.opens - before.opens == after.closes - before.closes, "provider file refs released after original fd closure");
	CHECK(completed_reads == 259 && completed_writes == 257, "exact successful native descriptor counts including prefix and 64KiB probe");
	close(observer); close(ctl); close(src); close(srcng); close(dst); close(dstng);
	free(source); free(source_after); free(dest); free(dest_after);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_PEER_NATIVE=PASS reads=%u writes=%u groups=257 batches=5 max_desc=64 native_depth=1 source_whole_disk_unchanged=1 destination_whole_disk=1 allocation_guards=1 maps=%llu pins=%llu live_maps=%llu live_pins=%llu memory=host-RAM-standin\n",
	       completed_reads, completed_writes,
	       (unsigned long long)(during.maps-before.maps),
	       (unsigned long long)(during.pins-before.pins),
	       (unsigned long long)after.live_maps, (unsigned long long)after.live_pins);
	return 0;
}
