// SPDX-License-Identifier: GPL-2.0
/*
 * Database-style positional O_DIRECT workload for the transparent preload
 * front end (tools/io_uring_unified_preload.c).  The program is unaware of the
 * front end: it runs unchanged with or without LD_PRELOAD and prints one
 * deterministic summary line:
 *
 *   XDEV_EXT_DB_WORKLOAD_RESULT=PASS eligible_reads=N eligible_writes=N
 *     fallback_calls=N sha256=HEX eligible_read_errors=N
 *     eligible_write_errors=N cancelled_calls=N trace=HEX mode=M
 *     page_bytes=N dio_mem_align=N dio_offset_align=N
 *
 * eligible_* count the calls that satisfy every admission rule of the
 * "Transparent preload front end" contract in tools/README_unified_ops.md for
 * <file>, assuming XDEV_EXT_PRELOAD_PATHS names <file>.  Each eligible call is one
 * READ_COMPAT or WRITE_COMPAT request on a matching kernel, so the summed
 * XDEV_EXT_PRELOAD_REPORT read_count + read_errors equals eligible_reads, and
 * read_errors equals eligible_read_errors (writes likewise).  fallback_calls
 * counts every recorded call that fails at least one admission rule.  In full
 * mode with a reported DIO alignment that is exactly the 18 deliberate
 * non-qualifying calls (measured with offset alignment 512 and 4096, frames
 * 4096 and 8192); without STATX_DIOALIGN every recorded call is counted.  In
 * fallback-only mode no call is eligible.  cancelled_calls counts the pwrite
 * and the pwritev that a pending cancellation stops at entry.
 * trace digests the return value, errno and returned bytes of every counted
 * call, so two runs with the same summary line observed the same POSIX
 * results.
 *
 * <file> must be on a file system that accepts O_DIRECT, on a device whose
 * logical block is at most one page.  Exit status: 0 PASS; 1 a call or the
 * final file differed from the expected result; 2 usage or setup error; 4 the
 * O_DIRECT open failed with EINVAL (the file system rejects O_DIRECT).
 *
 * Build: gcc -O2 -pthread -o xdev_ext_preload_db_workload xdev_ext_preload_db_workload.c
 * The binary must stay dynamically linked for LD_PRELOAD to apply.
 */
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* Consume this checkout's UAPI, as the front end does. */
#include "../../../../include/uapi/linux/io_uring.h"
#define statx_timestamp xdev_ext_kernel_statx_timestamp
#define statx xdev_ext_kernel_statx
#include "../../../../include/uapi/linux/stat.h"
#undef statx
#undef statx_timestamp

#define WL_DEFAULT_FRAME 4096U
#define WL_MAX_FRAME (1U << 20)
#define WL_RANDOM_READS 48U
#define WL_DUP2_TARGET 200
#define WL_FD_SCAN_LIMIT 1024
#define WL_ERRNO_SENTINEL EDOM

/* File layout in pages; the page size equals the front end's frame size. */
enum {
	WL_DATA_FIRST = 0,
	WL_DATA_PAGES = 24,
	WL_THREAD_FIRST = 24,
	WL_THREADS = 4,
	WL_THREAD_PAGES = 6,
	WL_LOG_FIRST = 48,
	WL_LOG_PAGES = 12,
	WL_VECTOR_FIRST = 60,
	WL_SHARED_PAGE = 62,
	WL_LARGE_PAGE = 63,	/* two pages: 63 and 64 */
	WL_BUFFERED_PAGE = 65,
	WL_CANCEL_PAGE = 66,
	WL_SETFL_PAGE = 67,
	WL_PARTIAL_PAGE = 70,
	WL_EFBIG_PAGE = 71,
	WL_EOF_PAGE = 72,
	WL_PAGES = 74,
	WL_EOF_TAIL = 512,
};

enum wl_call {
	WL_CALL_PREAD = 1,
	WL_CALL_PREAD64,
	WL_CALL_PWRITE,
	WL_CALL_PWRITE64,
	WL_CALL_PREADV,
	WL_CALL_PREADV2,
	WL_CALL_PWRITEV,
	WL_CALL_PWRITEV2,
	WL_CALL_READ,
	WL_CALL_WRITE,
	WL_CALL_MMAP,
	WL_CALL_SEND,
	WL_CALL_APP_RING_READ,
};

struct sha256 {
	uint32_t h[8];
	uint64_t bytes;
	unsigned char block[64];
	size_t used;
};

struct wl_tally {
	uint64_t eligible_reads;
	uint64_t eligible_writes;
	uint64_t eligible_read_errors;
	uint64_t eligible_write_errors;
	uint64_t fallback_calls;
	uint64_t cancelled_calls;
};

struct wl_ctx {
	struct wl_tally tally;
	struct sha256 trace;
	unsigned char *buf;	/* three frame-aligned pages */
	unsigned char *expect;	/* one frame-aligned page */
};

struct wl_fd {
	int fd;
	bool target;	/* the allowlisted file */
	bool direct;	/* O_DIRECT currently set */
};

struct wl_config {
	const char *path;
	char outside[PATH_MAX];
	size_t page;
	bool dio_known;
	uint32_t mem_align;
	uint32_t offset_align;
	bool full;
};

static struct wl_config cfg;
static uint32_t page_version[WL_PAGES];
static size_t partial_bytes;	/* bytes of WL_PARTIAL_PAGE that landed */
static pthread_mutex_t fail_lock = PTHREAD_MUTEX_INITIALIZER;
static char fail_message[512];
static volatile sig_atomic_t alarm_deliveries;

/* ---- SHA-256 (FIPS 180-4) ---- */

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror32(uint32_t value, unsigned int bits)
{
	return (value >> bits) | (value << (32 - bits));
}

static void sha256_init(struct sha256 *s)
{
	static const uint32_t initial[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	memcpy(s->h, initial, sizeof(initial));
	s->bytes = 0;
	s->used = 0;
}

static void sha256_compress(struct sha256 *s, const unsigned char *p)
{
	uint32_t w[64];
	uint32_t v[8];
	unsigned int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	memcpy(v, s->h, sizeof(v));
	for (i = 0; i < 64; i++) {
		uint32_t big1 = ror32(v[4], 6) ^ ror32(v[4], 11) ^ ror32(v[4], 25);
		uint32_t choose = (v[4] & v[5]) ^ (~v[4] & v[6]);
		uint32_t t1 = v[7] + big1 + choose + sha256_k[i] + w[i];
		uint32_t big0 = ror32(v[0], 2) ^ ror32(v[0], 13) ^ ror32(v[0], 22);
		uint32_t major = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);

		v[7] = v[6];
		v[6] = v[5];
		v[5] = v[4];
		v[4] = v[3] + t1;
		v[3] = v[2];
		v[2] = v[1];
		v[1] = v[0];
		v[0] = t1 + big0 + major;
	}
	for (i = 0; i < 8; i++)
		s->h[i] += v[i];
}

static void sha256_update(struct sha256 *s, const void *data, size_t length)
{
	const unsigned char *p = data;

	s->bytes += length;
	while (length) {
		size_t take = sizeof(s->block) - s->used;

		if (take > length)
			take = length;
		memcpy(s->block + s->used, p, take);
		s->used += take;
		p += take;
		length -= take;
		if (s->used == sizeof(s->block)) {
			sha256_compress(s, s->block);
			s->used = 0;
		}
	}
}

static void sha256_final(struct sha256 *s, unsigned char digest[32])
{
	uint64_t bits = s->bytes * 8;
	unsigned char length[8];
	unsigned char pad = 0x80;
	unsigned char zero = 0;
	unsigned int i;

	for (i = 0; i < 8; i++)
		length[i] = (unsigned char)(bits >> (56 - 8 * i));
	sha256_update(s, &pad, 1);
	while (s->used != 56)
		sha256_update(s, &zero, 1);
	sha256_update(s, length, sizeof(length));
	for (i = 0; i < 8; i++) {
		digest[4 * i] = (unsigned char)(s->h[i] >> 24);
		digest[4 * i + 1] = (unsigned char)(s->h[i] >> 16);
		digest[4 * i + 2] = (unsigned char)(s->h[i] >> 8);
		digest[4 * i + 3] = (unsigned char)s->h[i];
	}
}

static void hex32(const unsigned char digest[32], char out[65])
{
	static const char digits[] = "0123456789abcdef";
	unsigned int i;

	for (i = 0; i < 32; i++) {
		out[2 * i] = digits[digest[i] >> 4];
		out[2 * i + 1] = digits[digest[i] & 15];
	}
	out[64] = '\0';
}

static bool sha256_known_answer(void)
{
	static const char expected[] =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	unsigned char digest[32];
	struct sha256 s;
	char text[65];

	sha256_init(&s);
	sha256_update(&s, "abc", 3);
	sha256_final(&s, digest);
	hex32(digest, text);
	return !strcmp(text, expected);
}

/* ---- failure reporting ---- */

static bool wl_fail(const char *format, ...)
{
	va_list args;

	pthread_mutex_lock(&fail_lock);
	if (!fail_message[0]) {
		va_start(args, format);
		vsnprintf(fail_message, sizeof(fail_message), format, args);
		va_end(args);
	}
	pthread_mutex_unlock(&fail_lock);
	return false;
}

#define WL_CHECK(cond, ...) do {					\
	if (!(cond))							\
		return wl_fail(__VA_ARGS__);				\
} while (0)

/* ---- admission rules (README "Transparent preload front end") ---- */

static bool wl_aligned(uint64_t value, uint32_t alignment)
{
	return alignment && !(value % alignment);
}

/* Rules 2-5 for a scalar call; rule 1 (opt-in) is the caller's environment. */
static bool wl_admitted(const struct wl_fd *f, const void *buffer, size_t count,
			int64_t offset)
{
	if (!f->target || !f->direct || !cfg.dio_known)
		return false;
	if (!buffer || !count || count > cfg.page || offset < 0)
		return false;
	return wl_aligned((uintptr_t)buffer, cfg.mem_align) &&
	       wl_aligned(count, cfg.mem_align) &&
	       wl_aligned(count, cfg.offset_align) &&
	       wl_aligned((uint64_t)offset, cfg.offset_align);
}

static bool wl_iov_admitted(const struct wl_fd *f, const struct iovec *iov,
			    int iovcnt, int64_t offset, int flags)
{
	size_t total = 0;
	int i;

	if (flags || !f->target || !f->direct || !cfg.dio_known || !iov ||
	    iovcnt <= 0 || iovcnt > IOV_MAX || offset < 0)
		return false;
	for (i = 0; i < iovcnt; i++) {
		if (!iov[i].iov_len)
			continue;
		if (!iov[i].iov_base ||
		    !wl_aligned((uintptr_t)iov[i].iov_base, cfg.mem_align) ||
		    !wl_aligned(iov[i].iov_len, cfg.mem_align) ||
		    !wl_aligned(iov[i].iov_len, cfg.offset_align) ||
		    iov[i].iov_len > cfg.page - total)
			return false;
		total += iov[i].iov_len;
	}
	return total && wl_aligned((uint64_t)offset, cfg.offset_align);
}

/* ---- trace and accounting ---- */

static void wl_put64(unsigned char *p, uint64_t value)
{
	unsigned int i;

	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)(value >> (8 * i));
}

static void wl_record(struct wl_ctx *ctx, enum wl_call call, size_t count,
		      int64_t offset, int64_t ret, int error,
		      const void *returned)
{
	unsigned char record[40];

	wl_put64(record, (uint64_t)call);
	wl_put64(record + 8, (uint64_t)count);
	wl_put64(record + 16, (uint64_t)offset);
	wl_put64(record + 24, (uint64_t)ret);
	wl_put64(record + 32, (uint64_t)(int64_t)error);
	sha256_update(&ctx->trace, record, sizeof(record));
	if (returned && ret > 0)
		sha256_update(&ctx->trace, returned, (size_t)ret);
}

static void wl_account(struct wl_ctx *ctx, bool eligible, bool write,
		       ssize_t ret)
{
	if (!eligible) {
		ctx->tally.fallback_calls++;
	} else if (write) {
		ctx->tally.eligible_writes++;
		if (ret < 0)
			ctx->tally.eligible_write_errors++;
	} else {
		ctx->tally.eligible_reads++;
		if (ret < 0)
			ctx->tally.eligible_read_errors++;
	}
}

static void wl_add_tally(struct wl_tally *to, const struct wl_tally *from)
{
	to->eligible_reads += from->eligible_reads;
	to->eligible_writes += from->eligible_writes;
	to->eligible_read_errors += from->eligible_read_errors;
	to->eligible_write_errors += from->eligible_write_errors;
	to->fallback_calls += from->fallback_calls;
	to->cancelled_calls += from->cancelled_calls;
}

/* A successful POSIX call leaves errno alone; the front end must as well. */
static bool wl_errno_ok(ssize_t ret, int error)
{
	WL_CHECK(ret < 0 || error == WL_ERRNO_SENTINEL,
		 "successful call changed errno to %d", error);
	return true;
}

/* The current cancellation state; pthread_setcancelstate leaves errno alone. */
static int wl_cancel_state(void)
{
	int state;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	pthread_setcancelstate(state, NULL);
	return state;
}

/* Every positional call returns with the caller's cancellation state. */
static void wl_cancel_state_kept(const char *call, int before)
{
	if (wl_cancel_state() != before)
		wl_fail("%s changed the caller's cancellation state", call);
}

static ssize_t wl_pread(struct wl_ctx *ctx, const struct wl_fd *f, void *buffer,
			size_t count, int64_t offset, bool use_64, int *error)
{
	bool eligible = wl_admitted(f, buffer, count, offset);
	int state = wl_cancel_state();
	ssize_t ret;

	errno = WL_ERRNO_SENTINEL;
	ret = use_64 ? pread64(f->fd, buffer, count, (off64_t)offset) :
		       pread(f->fd, buffer, count, (off_t)offset);
	*error = errno;
	wl_cancel_state_kept("pread", state);
	wl_account(ctx, eligible, false, ret);
	wl_record(ctx, use_64 ? WL_CALL_PREAD64 : WL_CALL_PREAD, count, offset,
		  ret, *error, buffer);
	return ret;
}

static ssize_t wl_pwrite(struct wl_ctx *ctx, const struct wl_fd *f,
			 const void *buffer, size_t count, int64_t offset,
			 bool use_64, int *error)
{
	bool eligible = wl_admitted(f, buffer, count, offset);
	int state = wl_cancel_state();
	ssize_t ret;

	errno = WL_ERRNO_SENTINEL;
	ret = use_64 ? pwrite64(f->fd, buffer, count, (off64_t)offset) :
		       pwrite(f->fd, buffer, count, (off_t)offset);
	*error = errno;
	wl_cancel_state_kept("pwrite", state);
	wl_account(ctx, eligible, true, ret);
	wl_record(ctx, use_64 ? WL_CALL_PWRITE64 : WL_CALL_PWRITE, count,
		  offset, ret, *error, NULL);
	return ret;
}

static ssize_t wl_pvec(struct wl_ctx *ctx, const struct wl_fd *f,
		       const struct iovec *iov, int iovcnt, int64_t offset,
		       bool write, bool use_v2, int flags, int *error)
{
	bool eligible = wl_iov_admitted(f, iov, iovcnt, offset, flags);
	int state = wl_cancel_state();
	enum wl_call call;
	ssize_t ret;
	int i;

	errno = WL_ERRNO_SENTINEL;
	if (write) {
		call = use_v2 ? WL_CALL_PWRITEV2 : WL_CALL_PWRITEV;
		ret = use_v2 ? pwritev2(f->fd, iov, iovcnt, (off_t)offset, flags) :
			       pwritev(f->fd, iov, iovcnt, (off_t)offset);
	} else {
		call = use_v2 ? WL_CALL_PREADV2 : WL_CALL_PREADV;
		ret = use_v2 ? preadv2(f->fd, iov, iovcnt, (off_t)offset, flags) :
			       preadv(f->fd, iov, iovcnt, (off_t)offset);
	}
	*error = errno;
	wl_cancel_state_kept(write ? "pwritev" : "preadv", state);
	wl_account(ctx, eligible, write, ret);
	wl_record(ctx, call, (size_t)iovcnt, offset, ret, *error, NULL);
	if (!write && ret > 0) {
		size_t left = (size_t)ret;

		for (i = 0; i < iovcnt && left; i++) {
			size_t take = iov[i].iov_len < left ? iov[i].iov_len : left;

			sha256_update(&ctx->trace, iov[i].iov_base, take);
			left -= take;
		}
	}
	return ret;
}

/* ---- deterministic page contents ---- */

static void wl_fill(unsigned char *buffer, size_t length, uint64_t page,
		    uint32_t version)
{
	uint64_t state = ((page + 1) * UINT64_C(0x9e3779b97f4a7c15)) ^
			 ((uint64_t)version << 32) ^ UINT64_C(0x55425244);
	size_t i;

	state |= 1;
	for (i = 0; i < length; i += sizeof(state)) {
		size_t take = length - i < sizeof(state) ? length - i :
							  sizeof(state);

		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		memcpy(buffer + i, &state, take);
	}
}

/* Expected bytes of one page of the final file image. */
static void wl_expected_page(unsigned char *buffer, unsigned int page)
{
	memset(buffer, 0, cfg.page);
	if (page_version[page])
		wl_fill(buffer, cfg.page, page, page_version[page]);
	if (page == WL_PARTIAL_PAGE && page_version[page])
		memset(buffer + partial_bytes, 0, cfg.page - partial_bytes);
}

static bool wl_verify_read(const void *buffer, ssize_t ret, size_t want,
			   unsigned int page, unsigned char *expect)
{
	WL_CHECK(ret == (ssize_t)want, "page %u read returned %zd, want %zu",
		 page, ret, want);
	wl_expected_page(expect, page);
	WL_CHECK(!memcmp(buffer, expect, want), "page %u content mismatch",
		 page);
	return true;
}

static off_t wl_offset(unsigned int page)
{
	return (off_t)page * (off_t)cfg.page;
}

/* Positional calls must not move the shared file offset. */
static bool wl_offset_is(int fd, off_t expected)
{
	off_t now = lseek(fd, 0, SEEK_CUR);

	WL_CHECK(now == expected, "file offset %jd, want %jd", (intmax_t)now,
		 (intmax_t)expected);
	return true;
}

static bool wl_write_page(struct wl_ctx *ctx, const struct wl_fd *f,
			  unsigned int page, uint32_t version, bool use_64)
{
	ssize_t ret;
	int error;

	wl_fill(ctx->buf, cfg.page, page, version);
	ret = wl_pwrite(ctx, f, ctx->buf, cfg.page, wl_offset(page), use_64,
			&error);
	WL_CHECK(ret == (ssize_t)cfg.page, "page %u write returned %zd errno %d",
		 page, ret, error);
	if (!wl_errno_ok(ret, error))
		return false;
	page_version[page] = version;
	return true;
}

static bool wl_read_page(struct wl_ctx *ctx, const struct wl_fd *f,
			 unsigned int page, bool use_64)
{
	ssize_t ret;
	int error;

	memset(ctx->buf, 0xee, cfg.page);
	ret = wl_pread(ctx, f, ctx->buf, cfg.page, wl_offset(page), use_64,
		       &error);
	if (!wl_errno_ok(ret, error))
		return false;
	return wl_verify_read(ctx->buf, ret, cfg.page, page, ctx->expect);
}

static int wl_retry_fsync(int fd, bool data_only)
{
	int ret;

	do {
		ret = data_only ? fdatasync(fd) : fsync(fd);
	} while (ret && errno == EINTR);
	return ret;
}

static bool wl_ctx_init(struct wl_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	sha256_init(&ctx->trace);
	if (posix_memalign((void **)&ctx->buf, cfg.page, 3 * cfg.page) ||
	    posix_memalign((void **)&ctx->expect, cfg.page, cfg.page))
		return wl_fail("posix_memalign failed");
	return true;
}

static void wl_ctx_destroy(struct wl_ctx *ctx)
{
	free(ctx->buf);
	free(ctx->expect);
	ctx->buf = NULL;
	ctx->expect = NULL;
}

static void wl_fold_digest(struct wl_ctx *into, struct sha256 *from)
{
	unsigned char digest[32];

	sha256_final(from, digest);
	sha256_update(&into->trace, digest, sizeof(digest));
}

static int wl_open_fd_count(void)
{
	int count = 0;
	int fd;

	for (fd = 0; fd < WL_FD_SCAN_LIMIT; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			count++;
	return count;
}

/* ---- phases ---- */

static bool wl_phase_sequential(struct wl_ctx *ctx, const struct wl_fd *f)
{
	unsigned int page;

	for (page = WL_DATA_FIRST; page < WL_DATA_FIRST + WL_DATA_PAGES; page++)
		if (!wl_write_page(ctx, f, page, 1, page & 1))
			return false;
	WL_CHECK(!wl_retry_fsync(f->fd, true), "fdatasync: %s", strerror(errno));
	return true;
}

static bool wl_phase_random_reads(struct wl_ctx *ctx, const struct wl_fd *f)
{
	uint32_t state = 0x2545f491;
	unsigned int i;

	for (i = 0; i < WL_RANDOM_READS; i++) {
		unsigned int page;

		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		page = WL_DATA_FIRST + state % WL_DATA_PAGES;
		if (!wl_read_page(ctx, f, page, i & 1))
			return false;
	}
	return true;
}

static bool wl_phase_overwrite(struct wl_ctx *ctx, const struct wl_fd *f)
{
	unsigned int page;

	for (page = WL_DATA_FIRST; page < WL_DATA_FIRST + WL_DATA_PAGES;
	     page += 3)
		if (!wl_write_page(ctx, f, page, 2, false))
			return false;
	for (page = WL_DATA_FIRST; page < WL_DATA_FIRST + WL_DATA_PAGES;
	     page += 3)
		if (!wl_read_page(ctx, f, page, true))
			return false;
	return true;
}

/* A write-ahead-log style region: O_DSYNC descriptor, increasing offsets. */
static bool wl_phase_log(struct wl_ctx *ctx, const struct wl_fd *f)
{
	struct wl_fd log = { .target = true, .direct = true };
	unsigned int record;

	log.fd = open(cfg.path, O_RDWR | O_DIRECT | O_DSYNC);
	WL_CHECK(log.fd >= 0, "open log descriptor: %s", strerror(errno));
	for (record = 0; record < WL_LOG_PAGES; record++) {
		if (!wl_write_page(ctx, &log, WL_LOG_FIRST + record, record + 1,
				   record & 1))
			goto fail;
		if ((record & 3) == 3 && wl_retry_fsync(log.fd, true)) {
			wl_fail("log fdatasync: %s", strerror(errno));
			goto fail;
		}
	}
	if (wl_retry_fsync(log.fd, false)) {
		wl_fail("log fsync: %s", strerror(errno));
		goto fail;
	}
	close(log.fd);
	for (record = 0; record < WL_LOG_PAGES; record++)
		if (!wl_read_page(ctx, f, WL_LOG_FIRST + record, false))
			return false;
	return true;
fail:
	close(log.fd);
	return false;
}

/*
 * Two half-page segments when each half meets the reported DIO alignment.
 * Otherwise (an offset alignment above half a page, as on a device with a
 * 4096-byte logical block, or no STATX_DIOALIGN) one full-page segment, which
 * every device with a logical block of at most one page accepts.
 */
static int wl_vector_segments(void)
{
	size_t half = cfg.page / 2;

	if (cfg.dio_known && wl_aligned(half, cfg.mem_align) &&
	    wl_aligned(half, cfg.offset_align))
		return 2;
	return 1;
}

static bool wl_phase_vectors(struct wl_ctx *ctx, const struct wl_fd *f)
{
	int segments = wl_vector_segments();
	size_t length = cfg.page / (size_t)segments;
	struct iovec iov[2] = {
		{ .iov_base = ctx->buf, .iov_len = length },
		{ .iov_base = ctx->buf + 2 * cfg.page, .iov_len = length },
	};
	unsigned int i;
	ssize_t ret;
	int error;
	int s;

	for (i = 0; i < 2; i++) {
		unsigned int page = WL_VECTOR_FIRST + i;

		wl_fill(ctx->expect, cfg.page, page, 1);
		for (s = 0; s < segments; s++)
			memcpy(iov[s].iov_base, ctx->expect + s * length,
			       length);
		ret = wl_pvec(ctx, f, iov, segments, wl_offset(page), true,
			      i == 1, 0, &error);
		WL_CHECK(ret == (ssize_t)cfg.page && error == WL_ERRNO_SENTINEL,
			 "vector write page %u returned %zd errno %d", page,
			 ret, error);
		page_version[page] = 1;
	}
	for (i = 0; i < 2; i++) {
		unsigned int page = WL_VECTOR_FIRST + i;

		for (s = 0; s < segments; s++)
			memset(iov[s].iov_base, 0, length);
		ret = wl_pvec(ctx, f, iov, segments, wl_offset(page), false,
			      i == 1, 0, &error);
		WL_CHECK(ret == (ssize_t)cfg.page && error == WL_ERRNO_SENTINEL,
			 "vector read page %u returned %zd errno %d", page, ret,
			 error);
		wl_expected_page(ctx->expect, page);
		for (s = 0; s < segments; s++)
			WL_CHECK(!memcmp(iov[s].iov_base,
					 ctx->expect + s * length, length),
				 "vector read page %u content mismatch", page);
	}
	return true;
}

struct wl_worker {
	const struct wl_fd *f;
	unsigned int first;
	struct wl_ctx ctx;
	bool ok;
};

static void *wl_worker_main(void *opaque)
{
	struct wl_worker *worker = opaque;
	struct wl_ctx *ctx = &worker->ctx;
	unsigned int i;

	worker->ok = false;
	for (i = 0; i < WL_THREAD_PAGES; i++)
		if (!wl_write_page(ctx, worker->f, worker->first + i, 1, i & 1))
			return NULL;
	for (i = 0; i < WL_THREAD_PAGES; i++)
		if (!wl_read_page(ctx, worker->f, worker->first + i, !(i & 1)))
			return NULL;
	for (i = 0; i < WL_THREAD_PAGES; i += 2)
		if (!wl_write_page(ctx, worker->f, worker->first + i, 3, false))
			return NULL;
	for (i = 0; i < WL_THREAD_PAGES; i += 2)
		if (!wl_read_page(ctx, worker->f, worker->first + i, false))
			return NULL;
	worker->ok = true;
	return NULL;
}

/* Each thread owns a disjoint page range and its own trace. */
static bool wl_phase_threads(struct wl_ctx *ctx, const struct wl_fd *f)
{
	struct wl_worker workers[WL_THREADS];
	pthread_t threads[WL_THREADS];
	unsigned int started = 0;
	unsigned int i;
	bool ok = true;

	for (i = 0; i < WL_THREADS; i++) {
		workers[i].f = f;
		workers[i].first = WL_THREAD_FIRST + i * WL_THREAD_PAGES;
		if (!wl_ctx_init(&workers[i].ctx)) {
			ok = false;
			break;
		}
		if (pthread_create(&threads[i], NULL, wl_worker_main,
				   &workers[i])) {
			wl_ctx_destroy(&workers[i].ctx);
			ok = wl_fail("pthread_create failed");
			break;
		}
		started++;
	}
	for (i = 0; i < started; i++) {
		if (pthread_join(threads[i], NULL) || !workers[i].ok)
			ok = false;
		wl_add_tally(&ctx->tally, &workers[i].ctx.tally);
		wl_fold_digest(ctx, &workers[i].ctx.trace);
		wl_ctx_destroy(&workers[i].ctx);
	}
	return ok;
}

struct wl_child_result {
	unsigned char digest[32];
	struct wl_tally tally;
	int ok;
	char message[sizeof(fail_message)];
};

static ssize_t wl_full_read(int fd, void *buffer, size_t length)
{
	size_t done = 0;

	while (done < length) {
		ssize_t ret = read(fd, (unsigned char *)buffer + done,
				   length - done);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret <= 0)
			return ret < 0 ? -1 : (ssize_t)done;
		done += (size_t)ret;
	}
	return (ssize_t)done;
}

static void wl_child(const struct wl_fd *f, int pipe_fd)
{
	struct wl_child_result result;
	struct wl_ctx ctx;
	unsigned int page;
	int ok = 0;

	memset(&result, 0, sizeof(result));
	if (wl_ctx_init(&ctx)) {
		ok = 1;
		for (page = WL_DATA_FIRST; ok && page < WL_THREAD_FIRST +
		     WL_THREADS * WL_THREAD_PAGES; page++)
			ok = wl_read_page(&ctx, f, page, page & 1);
		sha256_final(&ctx.trace, result.digest);
		result.tally = ctx.tally;
		wl_ctx_destroy(&ctx);
	}
	result.ok = ok && !fail_message[0];
	snprintf(result.message, sizeof(result.message), "%s", fail_message);
	if (write(pipe_fd, &result, sizeof(result)) != (ssize_t)sizeof(result))
		ok = 0;
	close(pipe_fd);
	/* exit(), not _exit(): the front end reports this process's ring. */
	exit(ok ? 0 : 1);
}

/* A forked child reads and verifies pages its parent wrote. */
static bool wl_phase_fork(struct wl_ctx *ctx, const struct wl_fd *f)
{
	struct wl_child_result result;
	int pipe_fds[2];
	pid_t child;
	pid_t waited;
	int status;

	WL_CHECK(!pipe(pipe_fds), "pipe: %s", strerror(errno));
	fflush(NULL);
	child = fork();
	if (child < 0) {
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return wl_fail("fork: %s", strerror(errno));
	}
	if (!child) {
		close(pipe_fds[0]);
		wl_child(f, pipe_fds[1]);
	}
	close(pipe_fds[1]);
	memset(&result, 0, sizeof(result));
	if (wl_full_read(pipe_fds[0], &result, sizeof(result)) !=
	    (ssize_t)sizeof(result))
		result.ok = 0;
	close(pipe_fds[0]);
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	WL_CHECK(waited == child && WIFEXITED(status) && !WEXITSTATUS(status) &&
		 result.ok, "forked child failed: %s", result.message);
	sha256_update(&ctx->trace, result.digest, sizeof(result.digest));
	wl_add_tally(&ctx->tally, &result.tally);
	return true;
}

static bool wl_outside_round_trip(struct wl_ctx *ctx)
{
	struct wl_fd outside = { .target = false, .direct = true };
	ssize_t ret;
	int error;

	outside.fd = open(cfg.outside, O_RDWR | O_CREAT | O_DIRECT, 0600);
	WL_CHECK(outside.fd >= 0, "open %s: %s", cfg.outside, strerror(errno));
	wl_fill(ctx->buf, cfg.page, 0, 7);
	ret = wl_pwrite(ctx, &outside, ctx->buf, cfg.page, 0, false, &error);
	if (ret == (ssize_t)cfg.page) {
		memset(ctx->buf, 0, cfg.page);
		ret = wl_pread(ctx, &outside, ctx->buf, cfg.page, 0, false,
			       &error);
		wl_fill(ctx->expect, cfg.page, 0, 7);
		if (ret != (ssize_t)cfg.page ||
		    memcmp(ctx->buf, ctx->expect, cfg.page))
			ret = -1;
	}
	close(outside.fd);
	WL_CHECK(ret == (ssize_t)cfg.page, "outside-allowlist round trip failed");
	return true;
}

/* dup, F_DUPFD_CLOEXEC, dup2, close and number reuse, access-mode errors. */
static bool wl_phase_descriptors(struct wl_ctx *ctx, const struct wl_fd *f)
{
	struct wl_fd copy = { .target = true, .direct = true };
	ssize_t ret;
	int error;

	copy.fd = dup(f->fd);
	WL_CHECK(copy.fd >= 0, "dup: %s", strerror(errno));
	if (!wl_read_page(ctx, &copy, 0, false))
		return false;
	close(copy.fd);

	copy.fd = fcntl(f->fd, F_DUPFD_CLOEXEC, 0);
	WL_CHECK(copy.fd >= 0, "F_DUPFD_CLOEXEC: %s", strerror(errno));
	if (!wl_write_page(ctx, &copy, 1, page_version[1], false))
		return false;
	close(copy.fd);

	WL_CHECK(fcntl(WL_DUP2_TARGET, F_GETFD) == -1, "fd %d already open",
		 WL_DUP2_TARGET);
	copy.fd = dup2(f->fd, WL_DUP2_TARGET);
	WL_CHECK(copy.fd == WL_DUP2_TARGET, "dup2: %s", strerror(errno));
	if (!wl_read_page(ctx, &copy, 2, true))
		return false;
	close(copy.fd);

	/* The closed numbers are reused for a file outside the allowlist. */
	if (!wl_outside_round_trip(ctx))
		return false;

	copy.fd = open(cfg.path, O_RDONLY | O_DIRECT);
	WL_CHECK(copy.fd >= 0, "open read-only: %s", strerror(errno));
	if (!wl_read_page(ctx, &copy, 3, false))
		goto fail;
	wl_fill(ctx->buf, cfg.page, 3, 99);
	ret = wl_pwrite(ctx, &copy, ctx->buf, cfg.page, wl_offset(3), false,
			&error);
	if (ret != -1 || error != EBADF) {
		wl_fail("pwrite on O_RDONLY returned %zd errno %d", ret, error);
		goto fail;
	}
	close(copy.fd);

	copy.fd = open(cfg.path, O_WRONLY | O_DIRECT);
	WL_CHECK(copy.fd >= 0, "open write-only: %s", strerror(errno));
	ret = wl_pread(ctx, &copy, ctx->buf, cfg.page, wl_offset(3), false,
		       &error);
	if (ret != -1 || error != EBADF) {
		wl_fail("pread on O_WRONLY returned %zd errno %d", ret, error);
		goto fail;
	}
	close(copy.fd);
	return true;
fail:
	close(copy.fd);
	return false;
}

/* Open buffered, then switch O_DIRECT on and off with F_SETFL. */
static bool wl_phase_setfl(struct wl_ctx *ctx)
{
	struct wl_fd toggled = { .target = true, .direct = false };
	int flags;

	toggled.fd = open(cfg.path, O_RDWR);
	WL_CHECK(toggled.fd >= 0, "open buffered: %s", strerror(errno));
	if (!wl_read_page(ctx, &toggled, 4, false))
		goto fail;
	flags = fcntl(toggled.fd, F_GETFL);
	if (flags < 0 || fcntl(toggled.fd, F_SETFL, flags | O_DIRECT)) {
		wl_fail("F_SETFL O_DIRECT: %s", strerror(errno));
		goto fail;
	}
	toggled.direct = true;
	if (!wl_read_page(ctx, &toggled, 4, true) ||
	    !wl_write_page(ctx, &toggled, WL_SETFL_PAGE, 1, false))
		goto fail;
	if (fcntl(toggled.fd, F_SETFL, flags & ~O_DIRECT)) {
		wl_fail("F_SETFL clear O_DIRECT: %s", strerror(errno));
		goto fail;
	}
	toggled.direct = false;
	if (!wl_read_page(ctx, &toggled, WL_SETFL_PAGE, false))
		goto fail;
	close(toggled.fd);
	return true;
fail:
	close(toggled.fd);
	return false;
}

struct wl_cancel {
	pthread_mutex_t lock;
	pthread_cond_t changed;
	bool ready;
	bool requested;
	bool returned;
	bool vectored;
	ssize_t result;
	int fd;
	const void *buffer;
	size_t count;
	off_t offset;
};

static void *wl_cancel_main(void *opaque)
{
	struct wl_cancel *state = opaque;
	struct iovec iov = {
		.iov_base = (void *)state->buffer,
		.iov_len = state->count,
	};
	int old;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
	pthread_mutex_lock(&state->lock);
	state->ready = true;
	pthread_cond_broadcast(&state->changed);
	while (!state->requested)
		pthread_cond_wait(&state->changed, &state->lock);
	pthread_mutex_unlock(&state->lock);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
	/* pwrite and pwritev are cancellation points: the request acts here. */
	if (state->vectored)
		state->result = pwritev(state->fd, &iov, 1, state->offset);
	else
		state->result = pwrite(state->fd, state->buffer, state->count,
				       state->offset);
	state->returned = true;
	return NULL;
}

static bool wl_cancel_at_entry(struct wl_ctx *ctx, const struct wl_fd *f,
			       bool vectored)
{
	struct wl_cancel state = {
		.lock = PTHREAD_MUTEX_INITIALIZER,
		.changed = PTHREAD_COND_INITIALIZER,
		.vectored = vectored,
		.fd = f->fd,
		.buffer = ctx->buf,
		.count = cfg.page,
		.offset = wl_offset(WL_CANCEL_PAGE),
	};
	const char *call = vectored ? "pwritev" : "pwrite";
	pthread_t thread;
	void *result = NULL;
	int before;
	int after;

	before = wl_open_fd_count();
	WL_CHECK(!pthread_create(&thread, NULL, wl_cancel_main, &state),
		 "pthread_create failed");
	pthread_mutex_lock(&state.lock);
	while (!state.ready)
		pthread_cond_wait(&state.changed, &state.lock);
	pthread_cancel(thread);
	state.requested = true;
	pthread_cond_broadcast(&state.changed);
	pthread_mutex_unlock(&state.lock);
	WL_CHECK(!pthread_join(thread, &result), "pthread_join failed");
	after = wl_open_fd_count();
	WL_CHECK(result == PTHREAD_CANCELED && !state.returned,
		 "pending cancellation did not act at %s entry", call);
	WL_CHECK(after == before, "cancelled %s left %d descriptor(s) open",
		 call, after - before);
	ctx->tally.cancelled_calls++;
	return true;
}

/*
 * A pending deferred cancellation acts at pwrite and pwritev entry, before
 * any I/O: the page keeps the bytes written before the cancelled calls.
 */
static bool wl_phase_cancel(struct wl_ctx *ctx, const struct wl_fd *f)
{
	if (!wl_write_page(ctx, f, WL_CANCEL_PAGE, 1, false))
		return false;
	wl_fill(ctx->buf, cfg.page, WL_CANCEL_PAGE, 9);
	if (!wl_cancel_at_entry(ctx, f, false) ||
	    !wl_cancel_at_entry(ctx, f, true))
		return false;
	return wl_read_page(ctx, f, WL_CANCEL_PAGE, false);
}

static bool wl_einval_or_success(ssize_t ret, int error, const char *what)
{
	WL_CHECK(ret >= 0 || error == EINVAL, "%s returned %zd errno %d", what,
		 ret, error);
	return true;
}

/* *created is false when io_uring_setup itself failed. */
static ssize_t wl_app_ring_read(int fd, void *buffer, unsigned int length,
				off_t offset, int *error, bool *created)
{
	struct io_uring_params params;
	struct io_uring_sqe *sqes = MAP_FAILED;
	struct io_uring_cqe *cqe;
	unsigned char *sq = MAP_FAILED;
	unsigned char *cq = MAP_FAILED;
	size_t sq_size = 0;
	size_t cq_size = 0;
	unsigned int *sq_head, *sq_tail, *sq_mask, *sq_array;
	unsigned int *cq_head, *cq_tail, *cq_mask;
	unsigned int tail;
	unsigned int index;
	ssize_t ret = -1;
	int ring;

	memset(&params, 0, sizeof(params));
	*created = false;
	ring = (int)syscall(__NR_io_uring_setup, 4, &params);
	if (ring < 0) {
		*error = errno;
		return -1;
	}
	*created = true;
	sq_size = params.sq_off.array + params.sq_entries * sizeof(unsigned int);
	cq_size = params.cq_off.cqes +
		  params.cq_entries * sizeof(struct io_uring_cqe);
	sq = mmap(NULL, sq_size, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
	cq = mmap(NULL, cq_size, PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING);
	sqes = mmap(NULL, params.sq_entries * sizeof(*sqes),
		    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring,
		    IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) {
		*error = errno;
		goto out;
	}
	sq_head = (unsigned int *)(sq + params.sq_off.head);
	sq_tail = (unsigned int *)(sq + params.sq_off.tail);
	sq_mask = (unsigned int *)(sq + params.sq_off.ring_mask);
	sq_array = (unsigned int *)(sq + params.sq_off.array);
	cq_head = (unsigned int *)(cq + params.cq_off.head);
	cq_tail = (unsigned int *)(cq + params.cq_off.tail);
	cq_mask = (unsigned int *)(cq + params.cq_off.ring_mask);
	tail = __atomic_load_n(sq_tail, __ATOMIC_RELAXED);
	index = tail & *sq_mask;
	memset(&sqes[index], 0, sizeof(sqes[index]));
	sqes[index].opcode = IORING_OP_READ;
	sqes[index].fd = fd;
	sqes[index].addr = (uintptr_t)buffer;
	sqes[index].len = length;
	sqes[index].off = (uint64_t)offset;
	sqes[index].user_data = 0x5542;
	sq_array[index] = index;
	__atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
	for (;;) {
		unsigned int head = __atomic_load_n(cq_head, __ATOMIC_RELAXED);
		unsigned int submit;

		if (head != __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) {
			cqe = (struct io_uring_cqe *)(cq + params.cq_off.cqes) +
			      (head & *cq_mask);
			if (cqe->res < 0) {
				*error = -cqe->res;
			} else {
				ret = cqe->res;
				*error = WL_ERRNO_SENTINEL;
			}
			__atomic_store_n(cq_head, head + 1, __ATOMIC_RELEASE);
			break;
		}
		submit = __atomic_load_n(sq_head, __ATOMIC_ACQUIRE) == tail ?
			 1 : 0;
		if (syscall(__NR_io_uring_enter, ring, submit, 1,
			    IORING_ENTER_GETEVENTS, NULL, 0) < 0 &&
		    errno != EINTR) {
			*error = errno;
			break;
		}
	}
out:
	if (sqes != MAP_FAILED)
		munmap(sqes, params.sq_entries * sizeof(*sqes));
	if (cq != MAP_FAILED)
		munmap(cq, cq_size);
	if (sq != MAP_FAILED)
		munmap(sq, sq_size);
	close(ring);
	return ret;
}

/* Calls outside the takeover surface; each must behave exactly like libc. */
static bool wl_phase_probes(struct wl_ctx *ctx, const struct wl_fd *f)
{
	struct wl_fd buffered = { .target = true, .direct = false };
	struct iovec iov;
	unsigned char *mapped;
	bool ring_created;
	int sockets[2];
	ssize_t ret;
	off_t position;
	int error;

	/* Shared-offset write() and read() advance the descriptor offset. */
	position = wl_offset(WL_SHARED_PAGE);
	WL_CHECK(lseek(f->fd, position, SEEK_SET) == position, "lseek failed");
	wl_fill(ctx->buf, cfg.page, WL_SHARED_PAGE, 1);
	errno = WL_ERRNO_SENTINEL;
	ret = write(f->fd, ctx->buf, cfg.page);
	error = errno;
	wl_account(ctx, false, true, ret);
	wl_record(ctx, WL_CALL_WRITE, cfg.page, position, ret, error, NULL);
	WL_CHECK(ret == (ssize_t)cfg.page, "write() returned %zd", ret);
	page_version[WL_SHARED_PAGE] = 1;
	if (!wl_offset_is(f->fd, position + (off_t)cfg.page))
		return false;
	WL_CHECK(lseek(f->fd, position, SEEK_SET) == position, "lseek failed");
	memset(ctx->buf, 0, cfg.page);
	errno = WL_ERRNO_SENTINEL;
	ret = read(f->fd, ctx->buf, cfg.page);
	error = errno;
	wl_account(ctx, false, false, ret);
	wl_record(ctx, WL_CALL_READ, cfg.page, position, ret, error, ctx->buf);
	if (!wl_verify_read(ctx->buf, ret, cfg.page, WL_SHARED_PAGE,
			    ctx->expect) ||
	    !wl_offset_is(f->fd, position + (off_t)cfg.page))
		return false;
	WL_CHECK(lseek(f->fd, 0, SEEK_SET) == 0, "lseek failed");

	/* A request larger than one frame. */
	wl_fill(ctx->buf, cfg.page, WL_LARGE_PAGE, 1);
	wl_fill(ctx->buf + cfg.page, cfg.page, WL_LARGE_PAGE + 1, 1);
	ret = wl_pwrite(ctx, f, ctx->buf, 2 * cfg.page, wl_offset(WL_LARGE_PAGE),
			false, &error);
	WL_CHECK(ret == (ssize_t)(2 * cfg.page), "two-frame pwrite returned %zd",
		 ret);
	page_version[WL_LARGE_PAGE] = 1;
	page_version[WL_LARGE_PAGE + 1] = 1;
	memset(ctx->buf, 0, 2 * cfg.page);
	ret = wl_pread(ctx, f, ctx->buf, 2 * cfg.page, wl_offset(WL_LARGE_PAGE),
		       true, &error);
	if (!wl_verify_read(ctx->buf, ret == (ssize_t)(2 * cfg.page) ?
			    (ssize_t)cfg.page : -1, cfg.page, WL_LARGE_PAGE,
			    ctx->expect) ||
	    !wl_verify_read(ctx->buf + cfg.page, (ssize_t)cfg.page, cfg.page,
			    WL_LARGE_PAGE + 1, ctx->expect))
		return false;

	/* Misaligned buffer, offset and length; and a zero-length request. */
	ret = wl_pread(ctx, f, ctx->buf + 1, cfg.page, 0, false, &error);
	if (!wl_einval_or_success(ret, error, "misaligned-buffer pread"))
		return false;
	ret = wl_pread(ctx, f, ctx->buf, cfg.page, 1, false, &error);
	if (!wl_einval_or_success(ret, error, "misaligned-offset pread"))
		return false;
	ret = wl_pread(ctx, f, ctx->buf, 100, 0, false, &error);
	if (!wl_einval_or_success(ret, error, "misaligned-length pread"))
		return false;
	ret = wl_pread(ctx, f, ctx->buf, 0, 0, false, &error);
	WL_CHECK(ret == 0 && error == WL_ERRNO_SENTINEL,
		 "zero-length pread returned %zd errno %d", ret, error);

	/* A descriptor to the same file without O_DIRECT. */
	buffered.fd = open(cfg.path, O_RDWR);
	WL_CHECK(buffered.fd >= 0, "open buffered: %s", strerror(errno));
	if (!wl_write_page(ctx, &buffered, WL_BUFFERED_PAGE, 5, false) ||
	    !wl_read_page(ctx, &buffered, WL_BUFFERED_PAGE, true)) {
		close(buffered.fd);
		return false;
	}
	close(buffered.fd);
	if (cfg.full && !wl_read_page(ctx, f, WL_BUFFERED_PAGE, false))
		return false;

	if (!cfg.full && !wl_outside_round_trip(ctx))
		return false;

	/* preadv2/pwritev2 with nonzero flags stay in libc. */
	wl_fill(ctx->buf, cfg.page, WL_VECTOR_FIRST + 1, 1);
	iov = (struct iovec) { .iov_base = ctx->buf, .iov_len = cfg.page };
	ret = wl_pvec(ctx, f, &iov, 1, wl_offset(WL_VECTOR_FIRST + 1), true,
		      true, RWF_DSYNC, &error);
	WL_CHECK(ret == (ssize_t)cfg.page, "pwritev2 RWF_DSYNC returned %zd",
		 ret);
	page_version[WL_VECTOR_FIRST + 1] = 1;

	/* mmap of the same file sees the O_DIRECT-written bytes. */
	WL_CHECK(!wl_retry_fsync(f->fd, false), "fsync: %s", strerror(errno));
	errno = WL_ERRNO_SENTINEL;
	mapped = mmap(NULL, cfg.page, PROT_READ, MAP_SHARED, f->fd, 0);
	error = errno;
	wl_account(ctx, false, false, mapped == MAP_FAILED ? -1 : 0);
	wl_record(ctx, WL_CALL_MMAP, cfg.page, 0, mapped == MAP_FAILED ? -1 : 0,
		  mapped == MAP_FAILED ? error : 0, NULL);
	WL_CHECK(mapped != MAP_FAILED, "mmap: %s", strerror(error));
	wl_expected_page(ctx->expect, 0);
	ret = memcmp(mapped, ctx->expect, cfg.page) ? -1 : 0;
	sha256_update(&ctx->trace, mapped, cfg.page);
	munmap(mapped, cfg.page);
	WL_CHECK(!ret, "mmap content mismatch");

	/* send() on a local datagram socket. */
	WL_CHECK(!socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets), "socketpair: %s",
		 strerror(errno));
	errno = WL_ERRNO_SENTINEL;
	ret = send(sockets[0], ctx->expect, 64, 0);
	error = errno;
	wl_account(ctx, false, true, ret);
	wl_record(ctx, WL_CALL_SEND, 64, 0, ret, error, NULL);
	if (ret == 64) {
		do {
			ret = recv(sockets[1], ctx->buf, 64, 0);
		} while (ret < 0 && errno == EINTR);
		if (ret != 64 || memcmp(ctx->buf, ctx->expect, 64))
			ret = -1;
	}
	close(sockets[0]);
	close(sockets[1]);
	WL_CHECK(ret == 64, "send/recv round trip failed");

	/*
	 * An application-managed io_uring READ on the allowlisted file.
	 * Where io_uring is unavailable (ENOSYS, or EPERM from
	 * kernel.io_uring_disabled or seccomp), the recorded setup errno is
	 * the result both runs compare.
	 */
	memset(ctx->buf, 0, cfg.page);
	ret = wl_app_ring_read(f->fd, ctx->buf, (unsigned int)cfg.page, 0,
			       &error, &ring_created);
	wl_account(ctx, false, false, ret);
	wl_record(ctx, WL_CALL_APP_RING_READ, cfg.page, 0, ret, error,
		  ctx->buf);
	if (!ring_created)
		return true;
	return wl_verify_read(ctx->buf, ret, cfg.page, 0, ctx->expect);
}

/* RLIMIT_FSIZE produces a deterministic partial write and then EFBIG. */
static bool wl_phase_partial(struct wl_ctx *ctx, const struct wl_fd *f)
{
	struct sigaction ignore = { .sa_handler = SIG_IGN };
	struct sigaction previous;
	struct rlimit original;
	struct rlimit limited;
	size_t partial;
	ssize_t ret;
	int error;
	bool ok = true;

	if (!cfg.dio_known)
		partial = cfg.page / 2;
	else if (cfg.offset_align < cfg.page)
		partial = (cfg.page / 2) / cfg.offset_align * cfg.offset_align;
	else
		partial = 0;
	if (!partial)
		return true;
	WL_CHECK(!getrlimit(RLIMIT_FSIZE, &original), "getrlimit failed");
	limited = original;
	limited.rlim_cur = (rlim_t)wl_offset(WL_PARTIAL_PAGE) + partial;
	if (original.rlim_max != RLIM_INFINITY &&
	    original.rlim_max < limited.rlim_cur)
		return true;
	sigemptyset(&ignore.sa_mask);
	WL_CHECK(!sigaction(SIGXFSZ, &ignore, &previous), "sigaction failed");
	WL_CHECK(!setrlimit(RLIMIT_FSIZE, &limited), "setrlimit failed");
	wl_fill(ctx->buf, cfg.page, WL_PARTIAL_PAGE, 1);
	ret = wl_pwrite(ctx, f, ctx->buf, cfg.page, wl_offset(WL_PARTIAL_PAGE),
			false, &error);
	if (ret == (ssize_t)partial && error == WL_ERRNO_SENTINEL) {
		page_version[WL_PARTIAL_PAGE] = 1;
		partial_bytes = partial;
	} else if (cfg.dio_known || ret != -1 || error != EINVAL) {
		ok = wl_fail("partial pwrite returned %zd errno %d, want %zu",
			     ret, error, partial);
	}
	ret = wl_pwrite(ctx, f, ctx->buf, cfg.page, wl_offset(WL_EFBIG_PAGE),
			true, &error);
	if (ok && (ret != -1 || error != EFBIG))
		ok = wl_fail("pwrite past RLIMIT_FSIZE returned %zd errno %d",
			     ret, error);
	if (setrlimit(RLIMIT_FSIZE, &original) ||
	    sigaction(SIGXFSZ, &previous, NULL))
		ok = wl_fail("restoring RLIMIT_FSIZE failed");
	return ok;
}

/* A read that crosses end of file is short; one past end of file reads 0. */
static bool wl_phase_eof(struct wl_ctx *ctx, const struct wl_fd *f)
{
	ssize_t ret;
	int error;

	WL_CHECK(!ftruncate(f->fd, wl_offset(WL_EOF_PAGE) + WL_EOF_TAIL),
		 "ftruncate: %s", strerror(errno));
	memset(ctx->buf, 0xee, cfg.page);
	ret = wl_pread(ctx, f, ctx->buf, cfg.page, wl_offset(WL_EOF_PAGE), false,
		       &error);
	if (!wl_errno_ok(ret, error) ||
	    !wl_verify_read(ctx->buf, ret, WL_EOF_TAIL, WL_EOF_PAGE,
			    ctx->expect))
		return false;
	ret = wl_pread(ctx, f, ctx->buf, cfg.page, wl_offset(WL_EOF_PAGE + 1),
		       true, &error);
	WL_CHECK(ret == 0 && error == WL_ERRNO_SENTINEL,
		 "read past end of file returned %zd errno %d", ret, error);
	return true;
}

/* Hash the final file through an independent buffered descriptor. */
static bool wl_hash_file(struct wl_ctx *ctx, char hex[65])
{
	unsigned char digest[32];
	struct sha256 file_hash;
	struct stat st;
	off_t size;
	unsigned int page;
	int fd;

	fd = open(cfg.path, O_RDONLY);
	WL_CHECK(fd >= 0, "open for hashing: %s", strerror(errno));
	if (fstat(fd, &st)) {
		close(fd);
		return wl_fail("fstat: %s", strerror(errno));
	}
	size = cfg.full ? wl_offset(WL_EOF_PAGE) + WL_EOF_TAIL : st.st_size;
	if (st.st_size != size) {
		close(fd);
		return wl_fail("file size %jd, want %jd", (intmax_t)st.st_size,
			       (intmax_t)size);
	}
	sha256_init(&file_hash);
	for (page = 0; (off_t)page * (off_t)cfg.page < size; page++) {
		size_t want = size - wl_offset(page) < (off_t)cfg.page ?
			      (size_t)(size - wl_offset(page)) : cfg.page;

		if (wl_full_read(fd, ctx->buf, want) != (ssize_t)want) {
			close(fd);
			return wl_fail("short read while hashing page %u", page);
		}
		if (page < WL_PAGES) {
			wl_expected_page(ctx->expect, page);
			if (memcmp(ctx->buf, ctx->expect, want)) {
				close(fd);
				return wl_fail("final image differs at page %u",
					       page);
			}
		}
		sha256_update(&file_hash, ctx->buf, want);
	}
	close(fd);
	sha256_final(&file_hash, digest);
	hex32(digest, hex);
	return true;
}

/* ---- configuration ---- */

static size_t wl_frame_size(void)
{
	const char *text = getenv("XDEV_EXT_PRELOAD_FRAME_SIZE");
	long system_page = sysconf(_SC_PAGESIZE);
	size_t frame = WL_DEFAULT_FRAME;

	/* Mirror the front end: invalid values keep the default. */
	if (system_page > 0 && (size_t)system_page > frame)
		frame = (size_t)system_page;
	if (text && *text) {
		unsigned long parsed;
		char *end = NULL;

		errno = 0;
		parsed = strtoul(text, &end, 0);
		if (!errno && end && !*end && system_page > 0 &&
		    parsed >= (unsigned long)system_page &&
		    parsed <= WL_MAX_FRAME && parsed &&
		    !(parsed & (parsed - 1)))
			frame = parsed;
	}
	return frame;
}

static void wl_query_dio_alignment(int fd)
{
	struct xdev_ext_kernel_statx stx;

	memset(&stx, 0, sizeof(stx));
	if (!syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC,
		     STATX_DIOALIGN, &stx) &&
	    (stx.stx_mask & STATX_DIOALIGN) && stx.stx_dio_mem_align &&
	    stx.stx_dio_offset_align) {
		cfg.dio_known = true;
		cfg.mem_align = stx.stx_dio_mem_align;
		cfg.offset_align = stx.stx_dio_offset_align;
	}
}

/* With the front end enabled, the allowlist must name exactly <file>. */
static int wl_check_allowlist(void)
{
	const char *enabled = getenv("XDEV_EXT_PRELOAD_ENABLED");
	const char *paths = getenv("XDEV_EXT_PRELOAD_PATHS");
	char *canonical_target;
	char *copy;
	char *cursor;
	char *token;
	bool found = false;
	bool outside = false;

	if (!enabled || strcmp(enabled, "1"))
		return 0;
	canonical_target = realpath(cfg.path, NULL);
	copy = paths ? strdup(paths) : NULL;
	if (!canonical_target || !copy) {
		free(canonical_target);
		free(copy);
		fprintf(stderr, "XDEV_EXT_PRELOAD_PATHS must name %s\n", cfg.path);
		return 2;
	}
	cursor = copy;
	while ((token = strsep(&cursor, ":")) != NULL) {
		char *canonical = *token == '/' ? realpath(token, NULL) : NULL;

		if (canonical && !strcmp(canonical, canonical_target))
			found = true;
		if (!strcmp(token, cfg.outside))
			outside = true;
		free(canonical);
	}
	free(copy);
	free(canonical_target);
	if (!found || outside) {
		fprintf(stderr,
			"XDEV_EXT_PRELOAD_PATHS must name %s and not %s\n",
			cfg.path, cfg.outside);
		return 2;
	}
	return 0;
}

static void wl_on_alarm(int signal_number)
{
	(void)signal_number;
	alarm_deliveries++;
}

/* SIGALRM without SA_RESTART interrupts the process throughout the run. */
static bool wl_timer(bool start)
{
	struct itimerval interval = {
		.it_interval = { .tv_usec = start ? 1000 : 0 },
		.it_value = { .tv_usec = start ? 1000 : 0 },
	};
	struct sigaction action = {
		.sa_handler = start ? wl_on_alarm : SIG_DFL,
	};

	sigemptyset(&action.sa_mask);
	if (!start && setitimer(ITIMER_REAL, &interval, NULL))
		return false;
	if (sigaction(SIGALRM, &action, NULL))
		return false;
	return !start || !setitimer(ITIMER_REAL, &interval, NULL);
}

static bool wl_run(struct wl_ctx *ctx, const struct wl_fd *f)
{
	if (!cfg.full) {
		struct wl_fd buffered = { .target = true, .direct = false };
		unsigned int page;

		buffered.fd = open(cfg.path, O_RDWR);
		WL_CHECK(buffered.fd >= 0, "open buffered: %s", strerror(errno));
		for (page = 0; page < 5; page++) {
			if (!wl_write_page(ctx, &buffered, page, 1, false)) {
				close(buffered.fd);
				return false;
			}
		}
		close(buffered.fd);
		return wl_phase_probes(ctx, f);
	}
	if (!wl_offset_is(f->fd, 0) ||
	    lseek(f->fd, wl_offset(7), SEEK_SET) != wl_offset(7))
		return wl_fail("lseek failed");
	if (!wl_phase_sequential(ctx, f) || !wl_phase_random_reads(ctx, f) ||
	    !wl_phase_overwrite(ctx, f) || !wl_phase_log(ctx, f) ||
	    !wl_phase_vectors(ctx, f) || !wl_offset_is(f->fd, wl_offset(7)))
		return false;
	if (!wl_phase_threads(ctx, f) || !wl_phase_fork(ctx, f) ||
	    !wl_phase_descriptors(ctx, f) || !wl_phase_setfl(ctx) ||
	    !wl_phase_cancel(ctx, f) || !wl_offset_is(f->fd, wl_offset(7)))
		return false;
	return wl_phase_probes(ctx, f) && wl_phase_partial(ctx, f) &&
	       wl_phase_eof(ctx, f) && wl_retry_fsync(f->fd, false) == 0;
}

int main(int argc, char **argv)
{
	unsigned char digest[32];
	struct wl_fd target = { .target = true, .direct = true };
	struct wl_ctx ctx;
	struct stat st;
	char file_hex[65];
	char trace_hex[65];
	bool ok;
	int ret;

	if (argc != 3 || (strcmp(argv[2], "full") &&
			  strcmp(argv[2], "fallback-only"))) {
		fprintf(stderr, "usage: %s <file> full|fallback-only\n",
			argv[0]);
		return 2;
	}
	cfg.path = argv[1];
	cfg.full = !strcmp(argv[2], "full");
	if (snprintf(cfg.outside, sizeof(cfg.outside), "%s.outside",
		     cfg.path) >= (int)sizeof(cfg.outside))
		return 2;
	unlink(cfg.outside);
	if (cfg.path[0] != '/' || stat(cfg.path, &st) || !S_ISREG(st.st_mode)) {
		fprintf(stderr, "%s must be an existing regular file named by an "
			"absolute path\n", cfg.path);
		return 2;
	}
	if (!sha256_known_answer()) {
		fprintf(stderr, "SHA-256 known-answer test failed\n");
		return 2;
	}
	ret = wl_check_allowlist();
	if (ret)
		return ret;
	cfg.page = wl_frame_size();
	target.fd = open(cfg.path, O_RDWR | O_DIRECT);
	if (target.fd < 0) {
		int open_errno = errno;

		fprintf(stderr, "O_DIRECT open of %s failed: %s\n", cfg.path,
			strerror(open_errno));
		return open_errno == EINVAL ? 4 : 2;
	}
	wl_query_dio_alignment(target.fd);
	if (cfg.dio_known && (cfg.page % cfg.mem_align ||
			      cfg.page % cfg.offset_align)) {
		fprintf(stderr, "page %zu is not a multiple of the DIO alignment "
			"%u/%u\n", cfg.page, cfg.mem_align, cfg.offset_align);
		return 2;
	}
	if (ftruncate(target.fd, 0) || !wl_ctx_init(&ctx) || !wl_timer(true)) {
		fprintf(stderr, "setup failed: %s\n", strerror(errno));
		return 2;
	}
	ok = wl_run(&ctx, &target) && !fail_message[0];
	/* Not in the summary: the delivery count depends on timing. */
	if (ok && cfg.full && !alarm_deliveries)
		ok = wl_fail("no SIGALRM was delivered during the run");
	if (!wl_timer(false))
		ok = wl_fail("stopping the interval timer failed");
	close(target.fd);
	if (ok)
		ok = wl_hash_file(&ctx, file_hex);
	unlink(cfg.outside);
	if (!ok) {
		printf("XDEV_EXT_DB_WORKLOAD_RESULT=FAIL mode=%s reason=\"%s\"\n",
		       argv[2], fail_message);
		wl_ctx_destroy(&ctx);
		return 1;
	}
	sha256_final(&ctx.trace, digest);
	hex32(digest, trace_hex);
	printf("XDEV_EXT_DB_WORKLOAD_RESULT=PASS eligible_reads=%" PRIu64
	       " eligible_writes=%" PRIu64 " fallback_calls=%" PRIu64
	       " sha256=%s eligible_read_errors=%" PRIu64
	       " eligible_write_errors=%" PRIu64 " cancelled_calls=%" PRIu64
	       " trace=%s mode=%s page_bytes=%zu dio_mem_align=%u"
	       " dio_offset_align=%u\n",
	       ctx.tally.eligible_reads, ctx.tally.eligible_writes,
	       ctx.tally.fallback_calls, file_hex,
	       ctx.tally.eligible_read_errors, ctx.tally.eligible_write_errors,
	       ctx.tally.cancelled_calls, trace_hex, argv[2], cfg.page,
	       cfg.mem_align, cfg.offset_align);
	wl_ctx_destroy(&ctx);
	return 0;
}
