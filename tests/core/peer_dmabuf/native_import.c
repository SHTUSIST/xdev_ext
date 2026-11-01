// SPDX-License-Identifier: GPL-2.0
/* Real fd/ioctl acceptance only. No kernel shim and no native DMA request. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/xdev_ext_peer.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

enum { FAIL = 1, SETUP_ERROR = 2 };
static unsigned int passed;

static int report(int status, const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "%s: ", status == SETUP_ERROR ? "SETUP_ERROR" : "FAIL");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	return status;
}

static void pass(const char *name)
{
	printf("PASS case=%s\n", name);
	passed++;
}

static struct xdev_ext_peer_register registration(int source, uint64_t len)
{
	return (struct xdev_ext_peer_register) {
		.gpu_fd = source, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF,
		.len = len,
	};
}

static int expect_error(int ctl, struct xdev_ext_peer_register request,
			int want, const char *name)
{
	int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &request);
	int saved = errno;

	if (fd >= 0) {
		close(fd);
		return report(FAIL, "%s unexpectedly returned peer fd", name);
	}
	if (saved != want)
		return report(FAIL, "%s errno=%d (%s), expected=%d (%s)",
			      name, saved, strerror(saved), want, strerror(want));
	pass(name);
	return 0;
}

static int import_fd(int ctl, int source, uint64_t len, int *peer,
		     bool initial, const char *name)
{
	struct xdev_ext_peer_register request = registration(source, len);
	int flags, saved;

	*peer = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &request);
	saved = errno;
	if (*peer < 0) {
		int status = initial && (saved == EPERM || saved == EACCES ||
				saved == ENOMEM || saved == ENOTTY || saved == EOPNOTSUPP) ?
			SETUP_ERROR : FAIL;
		return report(status, "%s errno=%d (%s)%s", name, saved,
			      strerror(saved), initial ?
			      "; require importer/system-heap descriptor, CAP_SYS_RAWIO and no preexisting UID locked_vm charge" : "");
	}
	flags = fcntl(*peer, F_GETFD);
	if (flags < 0 || !(flags & FD_CLOEXEC) || !request.generation)
		return report(FAIL, "%s lacks live CLOEXEC fd or nonzero generation", name);
	printf("OBSERVE case=%s len=%" PRIu64 " generation=%" PRIu64 "\n",
	       name, len, (uint64_t)request.generation);
	pass(name);
	return 0;
}

static int pinned_bytes(uint64_t *bytes)
{
	FILE *status = fopen("/proc/self/status", "re");
	char line[256], unit[16];
	unsigned long long kb;

	if (!status)
		return report(SETUP_ERROR, "open /proc/self/status: %s", strerror(errno));
	while (fgets(line, sizeof(line), status)) {
		if (sscanf(line, "VmPin: %llu %15s", &kb, unit) == 2 &&
		    !strcmp(unit, "kB") && kb <= UINT64_MAX / 1024) {
			*bytes = kb * 1024;
			fclose(status);
			return 0;
		}
	}
	fclose(status);
	return report(SETUP_ERROR, "VmPin unavailable; cannot observe mm pinned_vm");
}

static int expect_pin(uint64_t want, const char *name)
{
	uint64_t got;
	int rc = pinned_bytes(&got);

	if (rc)
		return rc;
	if (got != want)
		return report(FAIL, "%s VmPin=%" PRIu64 ", expected=%" PRIu64,
			      name, got, want);
	printf("OBSERVE case=%s VmPin_bytes=%" PRIu64 "\n", name, got);
	pass(name);
	return 0;
}

static int allocate(int heap, uint64_t len)
{
	struct dma_heap_allocation_data data = {
		.len = len, .fd_flags = O_RDWR | O_CLOEXEC,
	};

	if (ioctl(heap, DMA_HEAP_IOCTL_ALLOC, &data) < 0) {
		report(SETUP_ERROR, "DMA_HEAP_IOCTL_ALLOC: %s", strerror(errno));
		return -1;
	}
	return data.fd;
}

/* CPU byte preservation is not evidence of a requester DMA mapping. */
static int cpu_bytes(int fd, size_t len, bool write)
{
	struct dma_buf_sync sync = {
		.flags = DMA_BUF_SYNC_START | (write ? DMA_BUF_SYNC_RW : DMA_BUF_SYNC_READ),
	};
	unsigned char *mapping;
	int rc = 0;
	size_t i;

	if (ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync) < 0)
		return report(SETUP_ERROR, "DMA_BUF_IOCTL_SYNC START: %s", strerror(errno));
	mapping = mmap(NULL, len, PROT_READ | (write ? PROT_WRITE : 0), MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED) {
		rc = report(SETUP_ERROR, "dma_buf mmap: %s", strerror(errno));
	} else {
		for (i = 0; i < len; i++) {
			unsigned char want = (unsigned char)(i * 37U + 11U);
			if (write)
				mapping[i] = want;
			else if (mapping[i] != want) {
				rc = report(FAIL, "CPU bytes offset=%zu got=%u want=%u",
					    i, mapping[i], want);
				break;
			}
		}
		if (munmap(mapping, len) && !rc)
			rc = report(SETUP_ERROR, "dma_buf munmap: %s", strerror(errno));
	}
	sync.flags = DMA_BUF_SYNC_END | (write ? DMA_BUF_SYNC_RW : DMA_BUF_SYNC_READ);
	if (ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync) < 0 && !rc)
		rc = report(SETUP_ERROR, "DMA_BUF_IOCTL_SYNC END: %s", strerror(errno));
	if (!rc)
		pass(write ? "cpu-initialize-whole-export" : "cpu-bytes-preserved");
	return rc;
}

static int negative_cases(int ctl, int source, uint64_t len)
{
	struct xdev_ext_peer_register r;
	int regular, rc;

#define BAD(field, value, name) do { \
	r = registration(source, len); r.field = (value); \
	rc = expect_error(ctl, r, EINVAL, name); if (rc) return rc; \
} while (0)
	BAD(flags, XDEV_EXT_PEER_REGISTER_F_DMABUF | 2U, "unknown-register-flags");
	BAD(generation, 1, "nonzero-input-generation");
	BAD(gpu_va, 4096, "nonzero-dmabuf-offset");
	BAD(len, 0, "zero-length");
	BAD(len, len - 1, "unaligned-length");
	BAD(len, len - 4096, "aligned-prefix-length");
	BAD(len, len + 4096, "aligned-oversize-length");
#undef BAD
	r = registration(-1, len);
	rc = expect_error(ctl, r, EBADF, "invalid-source-fd");
	if (rc)
		return rc;
	regular = memfd_create("dmabuf-native-non-export", MFD_CLOEXEC);
	if (regular < 0)
		return report(SETUP_ERROR, "memfd non-dma-buf: %s", strerror(errno));
	r = registration(regular, len);
	rc = expect_error(ctl, r, EINVAL, "regular-file-is-not-dmabuf");
	close(regular);
	return rc;
}

static int enabled_run(int ctl, int heap, size_t len)
{
	struct rlimit original, limit;
	uint64_t baseline;
	int a = -1, b = -1, alias = -1, peer = -1, duplicate = -1, rc = SETUP_ERROR;
	bool limited = false;

#define CHECK(expr) do { rc = (expr); if (rc) goto out; } while (0)
#define CLOSE(fd) do { if (close(fd)) { rc = report(SETUP_ERROR, "close: %s", strerror(errno)); (fd) = -1; goto out; } (fd) = -1; } while (0)
	if (getrlimit(RLIMIT_MEMLOCK, &original))
		return report(SETUP_ERROR, "getrlimit: %s", strerror(errno));
	if (original.rlim_max != RLIM_INFINITY && original.rlim_max < len)
		return report(SETUP_ERROR, "MEMLOCK hard limit is smaller than one export (%zu)", len);
	CHECK(pinned_bytes(&baseline));
	printf("OBSERVE export_bytes=%zu baseline_VmPin_bytes=%" PRIu64 " uid=%lu\n",
	       len, baseline, (unsigned long)getuid());
	a = allocate(heap, len);
	b = allocate(heap, len);
	if (a < 0 || b < 0) {
		rc = SETUP_ERROR;
		goto out;
	}
	CHECK(cpu_bytes(a, len, true));
	limit = original;
	limit.rlim_cur = len;
	if (setrlimit(RLIMIT_MEMLOCK, &limit)) {
		rc = report(SETUP_ERROR, "set finite MEMLOCK: %s", strerror(errno));
		goto out;
	}
	limited = true;
	CHECK(import_fd(ctl, a, len, &peer, true, "whole-export-import"));
	CHECK(expect_pin(baseline + len, "whole-export-charge"));
	CHECK(cpu_bytes(a, len, false));
	CHECK(negative_cases(ctl, a, len));
	CHECK(expect_error(ctl, registration(a, len), EBUSY, "duplicate-import"));
	alias = fcntl(a, F_DUPFD_CLOEXEC, 0);
	if (alias < 0) { rc = report(SETUP_ERROR, "dup source: %s", strerror(errno)); goto out; }
	CLOSE(a);
	CHECK(expect_error(ctl, registration(alias, len), EBUSY, "source-dup-same-identity"));
	duplicate = fcntl(peer, F_DUPFD_CLOEXEC, 0);
	if (duplicate < 0) { rc = report(SETUP_ERROR, "dup peer: %s", strerror(errno)); goto out; }
	CLOSE(peer);
	CHECK(expect_pin(baseline + len, "peer-dup-retains-charge"));
	CHECK(expect_error(ctl, registration(alias, len), EBUSY, "peer-dup-retains-identity"));
	CHECK(expect_error(ctl, registration(b, len), ENOMEM, "finite-quota-second-export-refused"));
	CLOSE(duplicate);
	CHECK(expect_pin(baseline, "final-peer-close-uncharge"));
	CHECK(import_fd(ctl, alias, len, &peer, false, "reimport-after-final-close"));
	CLOSE(alias); /* No source fd or mmap remains: only the peer owns export A. */
	CHECK(expect_pin(baseline + len, "all-source-fds-closed-charge-retained"));
	duplicate = fcntl(peer, F_DUPFD_CLOEXEC, 0);
	if (duplicate < 0) { rc = report(SETUP_ERROR, "dup source-less peer: %s", strerror(errno)); goto out; }
	CLOSE(peer);
	CHECK(expect_pin(baseline + len, "source-less-peer-dup-retains-charge"));
	CHECK(expect_error(ctl, registration(b, len), ENOMEM, "source-less-peer-retains-quota"));
	CLOSE(duplicate);
	CHECK(expect_pin(baseline, "source-less-final-close-uncharge"));
	CHECK(import_fd(ctl, b, len, &peer, false, "finite-quota-restored-after-close"));
	CHECK(expect_pin(baseline + len, "replacement-export-charge"));
	CLOSE(peer);
	CHECK(expect_pin(baseline, "replacement-close-uncharge"));
	limit.rlim_cur = 0;
	if (setrlimit(RLIMIT_MEMLOCK, &limit)) { rc = report(SETUP_ERROR, "set zero MEMLOCK: %s", strerror(errno)); goto out; }
	CHECK(expect_error(ctl, registration(b, len), ENOMEM, "zero-memlock-refused"));
	CHECK(expect_pin(baseline, "failed-import-no-charge"));
	limit.rlim_cur = len;
	if (setrlimit(RLIMIT_MEMLOCK, &limit)) { rc = report(SETUP_ERROR, "restore finite MEMLOCK: %s", strerror(errno)); goto out; }
	CHECK(import_fd(ctl, b, len, &peer, false, "zero-limit-failure-releases-identity"));
	CLOSE(peer);
	CHECK(expect_pin(baseline, "final-accounting-baseline"));
	rc = 0;
out:
	if (duplicate >= 0) close(duplicate);
	if (peer >= 0) close(peer);
	if (alias >= 0) close(alias);
	if (a >= 0) close(a);
	if (b >= 0) close(b);
	if (limited && setrlimit(RLIMIT_MEMLOCK, &original))
		rc = report(SETUP_ERROR, "restore original MEMLOCK: %s", strerror(errno));
	return rc;
#undef CLOSE
#undef CHECK
}

int main(int argc, char **argv)
{
	const char *heap_path = "/dev/dma_heap/system", *control = "/dev/xdev_ext_peer";
	bool expect_unsupported = false;
	long page;
	size_t len;
	int ctl, heap, source, rc, i;
	struct stat st;

	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			puts("Usage: native_import [--heap PATH] [--control PATH] [--expect-disabled]");
			puts("--expect-disabled (legacy name): observe that REGISTER returns EOPNOTSUPP;");
			puts("kernel configuration requires external evidence.");
			return 0;
		} else if (!strcmp(argv[i], "--expect-disabled")) {
			expect_unsupported = true;
		} else if (!strcmp(argv[i], "--heap") || !strcmp(argv[i], "--control")) {
			bool is_heap = !strcmp(argv[i], "--heap");
			if (++i == argc || !argv[i][0] || argv[i][0] == '-')
				return report(SETUP_ERROR, "missing device path");
			if (is_heap) heap_path = argv[i]; else control = argv[i];
		} else {
			return report(SETUP_ERROR, "unknown argument: %s", argv[i]);
		}
	}
	ctl = open(control, O_RDWR | O_CLOEXEC);
	if (ctl < 0)
		return report(SETUP_ERROR, "open %s: %s", control, strerror(errno));
	if (fstat(ctl, &st) || !S_ISCHR(st.st_mode)) {
		close(ctl);
		return report(SETUP_ERROR, "control must be a character device");
	}
	heap = open(heap_path, O_RDWR | O_CLOEXEC);
	if (heap < 0) { close(ctl); return report(SETUP_ERROR, "open %s: %s", heap_path, strerror(errno)); }
	if (fstat(heap, &st) || !S_ISCHR(st.st_mode)) {
		close(heap); close(ctl);
		return report(SETUP_ERROR, "heap must be a character device");
	}
	page = sysconf(_SC_PAGESIZE);
	if (page < 4096 || (page & 4095) || (unsigned long)page > SIZE_MAX / 3) {
		close(heap); close(ctl);
		return report(SETUP_ERROR, "unsupported system page size");
	}
	len = 3 * (size_t)page;
	if (expect_unsupported) {
		source = allocate(heap, len);
		if (source < 0) rc = SETUP_ERROR;
		else {
			struct xdev_ext_peer_register request = registration(source, len);
			int fd = ioctl(ctl, XDEV_EXT_PEER_REGISTER, &request);
			int saved = errno;
			if (fd >= 0) { close(fd); rc = report(FAIL, "expected REGISTER EOPNOTSUPP but received peer fd"); }
			else if (saved == EPERM || saved == EACCES || saved == ENOTTY)
				rc = report(SETUP_ERROR, "REGISTER refusal check errno=%d (%s)", saved, strerror(saved));
			else if (saved != EOPNOTSUPP)
				rc = report(FAIL, "REGISTER refusal check errno=%d, expected EOPNOTSUPP", saved);
			else { pass("register-returned-EOPNOTSUPP"); rc = 0; }
			close(source);
		}
	} else rc = enabled_run(ctl, heap, len);
	close(heap);
	close(ctl);
	if (!rc)
		printf("PASS scope=%s cases=%u; no CREATE/map/lease/native-DMA/INFO-query coverage\n",
		       expect_unsupported ? "register-EOPNOTSUPP-observation-only" : "native-system-heap-register-lifetime-memlock-cpu-bytes", passed);
	return rc;
}
