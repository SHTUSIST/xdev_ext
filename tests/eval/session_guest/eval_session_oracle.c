// SPDX-License-Identifier: GPL-2.0
/*
 * eval_session_oracle - the user-space oracle and data preparer of the eval
 * session guest run (kernel/tools/testing/selftests/xdev_ext_integration/
 * xdev_ext_eval_session_guest.sh).  It shares no code with the arms it
 * checks: the payload formulas of tests/eval/nvme_gpu/nvme_gpu_core.h and
 * tests/eval/chains/chain_oracle.h are written out again here, SHA-256 is
 * implemented here, and every check reads the bytes back itself after the
 * arm exited.  Devices are read and written with O_DIRECT (a regular file
 * that refuses O_DIRECT is opened buffered, for the host tests); the CE
 * stand-in window /dev/xdev_ext_ce_sim is read with pread at its offset.
 *
 *   snapshot  --dev D --offset O --length L --out NEW_FILE
 *   restore   --dev D --offset O --snapshot FILE       write back, read back, compare
 *   compare   --dev D --offset O --snapshot FILE --skip-offset S --skip-length L
 *             compare every byte except [S,S+L) relative to the snapshot
 *   fill      --dev D --offset O --length L --byte B
 *   chain-source --dev D --offset O --group G --groups T --seed S [--compress]
 *   chain-ref --out NEW_FILE --group G --groups T --seed S [--text]
 *   chain-file --dev D --offset O --group G --groups T --seed S
 *   chain-ce  --ce DEV --va V --group G --slots N --groups T --seed S
 *   xg-slots  --ce DEV --va V --size Z --slots Q --seed S
 *   xg-file   --dev D --offset O --size Z --groups N --slots Q --seed S
 *   sha256    FILE
 *
 * Checks print one line "bytes=<n> sha256=<hex>" of the canonical bytes
 * they verified (the guest validator's canonical()); restore prints the
 * restored span.  Exit: 0 pass, 1 mismatch or I/O error, 2 usage.
 * Nothing here is timed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#define ALIGN		4096u
#define MAX_SPAN	(256u << 20)
#define CE_PRISTINE	0xa6	/* chain_bench's fill of a CE oracle window */
#define IAA_WBITS	11	/* the kernel's deflate-generic: -DEFLATE_DEF_WINBITS */

/* --- SHA-256 (FIPS 180-4) -------------------------------------------- */

struct sha {
	uint32_t h[8];
	uint64_t len;
	unsigned char buf[64];
	size_t fill;
};

static const uint32_t sha_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror(uint32_t x, int n)
{
	return x >> n | x << (32 - n);
}

static void sha_block(struct sha *s, const unsigned char *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (; i < 64; i++)
		w[i] = w[i - 16] + (ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ w[i - 15] >> 3) +
		       w[i - 7] + (ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ w[i - 2] >> 10);
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
	e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) +
			      sha_k[i] + w[i];
		uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));

		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha_init(struct sha *s)
{
	static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
					0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

	memset(s, 0, sizeof(*s));
	memcpy(s->h, iv, sizeof(iv));
}

static void sha_update(struct sha *s, const unsigned char *p, size_t n)
{
	s->len += n;
	while (n) {
		size_t take = 64 - s->fill < n ? 64 - s->fill : n;

		memcpy(s->buf + s->fill, p, take);
		s->fill += take;
		p += take;
		n -= take;
		if (s->fill == 64) {
			sha_block(s, s->buf);
			s->fill = 0;
		}
	}
}

static void sha_final(struct sha *s, char hex[65])
{
	uint64_t bits = s->len * 8;
	unsigned char pad = 0x80, len[8];
	int i;

	sha_update(s, &pad, 1);
	pad = 0;
	while (s->fill != 56)
		sha_update(s, &pad, 1);
	for (i = 0; i < 8; i++)
		len[i] = (unsigned char)(bits >> (56 - 8 * i));
	sha_update(s, len, 8);
	for (i = 0; i < 8; i++)
		snprintf(hex + 8 * i, 9, "%08" PRIx32, s->h[i]);
}

static void report(const unsigned char *data, size_t n)
{
	struct sha s;
	char hex[65];

	sha_init(&s);
	sha_update(&s, data, n);
	sha_final(&s, hex);
	printf("bytes=%zu sha256=%s\n", n, hex);
}

/* --- payloads, written out independently of the arms ------------------- */

static uint64_t splitmix_final(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ULL;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

/* nvme_gpu/gpu_nic window word @w of @seed (uint32 seeds, as the arms). */
static uint64_t xg_value(uint64_t w, uint32_t seed)
{
	return (w ^ splitmix_final(seed)) * 0x9e3779b97f4a7c15ULL;
}

static void put_le(unsigned char *p, uint64_t v)
{
	for (int i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (8 * i));
}

static uint64_t get_le(const unsigned char *p)
{
	uint64_t v = 0;

	for (int i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

static void xg_bytes(unsigned char *out, uint64_t offset, size_t n, uint32_t seed)
{
	for (size_t i = 0; i < n; i += 8)
		put_le(out + i, xg_value((offset + i) / 8, seed));
}

static uint64_t mix33(uint64_t x)
{
	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdULL;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ULL;
	return x ^ (x >> 33);
}

/* chains group @g: little-endian g, then the binary or text payload. */
static void chain_bytes(unsigned char *out, size_t n, uint64_t seed, uint64_t g, bool text)
{
	uint64_t base = seed ^ g * 0x9e3779b97f4a7c15ULL;

	for (size_t i = 0; i < n; i++) {
		if (i < 8)
			out[i] = (unsigned char)(g >> (8 * i));
		else if (text)
			out[i] = (unsigned char)('a' + (mix33(base ^ (i >> 6)) & 15));
		else
			out[i] = (unsigned char)(mix33(base ^ (i >> 3) * 0xc2b2ae3d27d4eb4fULL) >> (8 * (i & 7)));
	}
}

/* --- I/O ------------------------------------------------------------- */

static int open_dev(const char *path, int flags)
{
	int fd = open(path, flags | O_DIRECT | O_CLOEXEC);

	if (fd < 0 && errno == EINVAL)
		fd = open(path, flags | O_CLOEXEC);
	if (fd < 0)
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
	return fd;
}

static int full_io(int fd, bool write_, void *buf, size_t n, uint64_t off)
{
	size_t done = 0;

	while (done < n) {
		ssize_t k = write_ ? pwrite(fd, (char *)buf + done, n - done, (off_t)(off + done)) :
				     pread(fd, (char *)buf + done, n - done, (off_t)(off + done));

		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0) {
			fprintf(stderr, "%s at %" PRIu64 ": %s\n", write_ ? "write" : "read",
				off + done, k ? strerror(errno) : "end of device");
			return -1;
		}
		done += (size_t)k;
	}
	return 0;
}

static unsigned char *aligned(size_t n)
{
	void *p = NULL;

	if (posix_memalign(&p, ALIGN, n ? n : ALIGN))
		return NULL;
	return p;
}

static int read_span(const char *path, uint64_t off, size_t n, unsigned char *buf)
{
	int fd = open_dev(path, O_RDONLY), ret;

	if (fd < 0)
		return -1;
	ret = full_io(fd, false, buf, n, off);
	close(fd);
	return ret;
}

static int write_span(const char *path, uint64_t off, size_t n, unsigned char *buf)
{
	int fd = open_dev(path, O_WRONLY), ret;

	if (fd < 0)
		return -1;
	ret = full_io(fd, true, buf, n, off);
	if (!ret && fsync(fd)) {
		fprintf(stderr, "%s: fsync: %s\n", path, strerror(errno));
		ret = -1;
	}
	if (close(fd) && !ret)
		ret = -1;
	return ret;
}

/* A plain (non-O_DIRECT) read of a CE window: the stand-in is a char device. */
static int read_ce(const char *path, uint64_t va, size_t n, unsigned char *buf)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC), ret;

	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -1;
	}
	ret = full_io(fd, false, buf, n, va);
	close(fd);
	return ret;
}

static int write_new(const char *path, const unsigned char *buf, size_t n)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600), ret;

	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", path, strerror(errno));
		return -2;
	}
	ret = full_io(fd, true, (void *)buf, n, 0);
	if (close(fd) && !ret)
		ret = -1;
	return ret;
}

/* --- options ----------------------------------------------------------- */

struct opts {
	const char *dev, *ce, *out, *snapshot;
	uint64_t offset, length, va, group, groups, slots, size, seed, byte, skip_offset, skip_length;
	bool compress, text;
	unsigned int have;
};

enum { H_DEV = 1, H_CE = 2, H_OUT = 4, H_SNAP = 8, H_OFF = 16, H_LEN = 32, H_VA = 64,
       H_GROUP = 128, H_GROUPS = 256, H_SLOTS = 512, H_SIZE = 1024, H_SEED = 2048, H_BYTE = 4096, H_SKIP_OFF = 8192, H_SKIP_LEN = 16384 };

static bool number(const char *s, uint64_t *v)
{
	char *end;

	if (!*s || strspn(s, "0123456789") != strlen(s) || strlen(s) > 20)
		return false;
	errno = 0;
	*v = strtoull(s, &end, 10);
	return !errno && !*end;
}

static int parse(int argc, char **argv, struct opts *o)
{
	static const struct { const char *name; unsigned int bit; } table[] = {
		{ "--dev", H_DEV }, { "--ce", H_CE }, { "--out", H_OUT }, { "--snapshot", H_SNAP },
		{ "--offset", H_OFF }, { "--length", H_LEN }, { "--va", H_VA }, { "--group", H_GROUP },
		{ "--groups", H_GROUPS }, { "--slots", H_SLOTS }, { "--size", H_SIZE },
		{ "--seed", H_SEED }, { "--byte", H_BYTE },
		{ "--skip-offset", H_SKIP_OFF }, { "--skip-length", H_SKIP_LEN },
	};

	memset(o, 0, sizeof(*o));
	for (int i = 2; i < argc; i++) {
		unsigned int bit = 0;
		size_t k;

		if (!strcmp(argv[i], "--compress")) {
			o->compress = true;
			continue;
		}
		if (!strcmp(argv[i], "--text")) {
			o->text = true;
			continue;
		}
		for (k = 0; k < sizeof(table) / sizeof(table[0]); k++)
			if (!strcmp(argv[i], table[k].name))
				bit = table[k].bit;
		if (!bit || i + 1 >= argc || (o->have & bit))
			return -1;
		o->have |= bit;
		i++;
		switch (bit) {
		case H_DEV: o->dev = argv[i]; break;
		case H_CE: o->ce = argv[i]; break;
		case H_OUT: o->out = argv[i]; break;
		case H_SNAP: o->snapshot = argv[i]; break;
		default: {
			uint64_t v;

			if (!number(argv[i], &v))
				return -1;
			switch (bit) {
			case H_OFF: o->offset = v; break;
			case H_LEN: o->length = v; break;
			case H_VA: o->va = v; break;
			case H_GROUP: o->group = v; break;
			case H_GROUPS: o->groups = v; break;
			case H_SLOTS: o->slots = v; break;
			case H_SIZE: o->size = v; break;
			case H_SEED: o->seed = v; break;
			case H_BYTE: o->byte = v; break;
			case H_SKIP_OFF: o->skip_offset = v; break;
			case H_SKIP_LEN: o->skip_length = v; break;
			}
		}
		}
	}
	return 0;
}

static bool need(const struct opts *o, unsigned int bits)
{
	return (o->have & bits) == bits && !(o->have & ~bits);
}

static bool span_ok(uint64_t off, uint64_t len)
{
	return !(off % ALIGN) && len && !(len % ALIGN) && len <= MAX_SPAN;
}

/* --- commands ---------------------------------------------------------- */

static int cmd_snapshot(const struct opts *o)
{
	unsigned char *buf;
	int ret;

	if (!need(o, H_DEV | H_OFF | H_LEN | H_OUT) || !span_ok(o->offset, o->length))
		return 2;
	if (!access(o->out, F_OK))
		return fprintf(stderr, "%s exists\n", o->out), 2;
	buf = aligned(o->length);
	if (!buf)
		return 1;
	ret = read_span(o->dev, o->offset, o->length, buf);
	if (!ret)
		ret = write_new(o->out, buf, o->length);
	free(buf);
	return ret == -2 ? 2 : ret ? 1 : 0;
}

static int cmd_restore(const struct opts *o)
{
	unsigned char *want = NULL, *got = NULL;
	struct stat st;
	int fd, ret = 1;

	if (!need(o, H_DEV | H_OFF | H_SNAP))
		return 2;
	fd = open(o->snapshot, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
	    !span_ok(o->offset, (uint64_t)st.st_size)) {
		if (fd >= 0)
			close(fd);
		return 2;
	}
	want = aligned((size_t)st.st_size);
	got = aligned((size_t)st.st_size);
	if (want && got && !full_io(fd, false, want, (size_t)st.st_size, 0) &&
	    !write_span(o->dev, o->offset, (size_t)st.st_size, want) &&
	    !read_span(o->dev, o->offset, (size_t)st.st_size, got)) {
		if (memcmp(want, got, (size_t)st.st_size)) {
			fprintf(stderr, "restored span reads back differently\n");
		} else {
			report(got, (size_t)st.st_size);
			ret = 0;
		}
	}
	close(fd);
	free(want);
	free(got);
	return ret;
}

/* Check untouched bytes independently, including guards after the active span. */
static int cmd_compare(const struct opts *o)
{
	struct stat st;
	unsigned char *want = NULL, *got = NULL;
	int fd, ret = 1;
	size_t n;

	if (!need(o, H_DEV | H_OFF | H_SNAP | H_SKIP_OFF | H_SKIP_LEN))
		return 2;
	fd = open(o->snapshot, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 1;
	if (fstat(fd, &st) || !S_ISREG(st.st_mode) ||
	    !span_ok(o->offset, (uint64_t)st.st_size) ||
	    o->skip_offset > (uint64_t)st.st_size ||
	    o->skip_length > (uint64_t)st.st_size - o->skip_offset) {
		close(fd);
		return 2;
	}
	n = (size_t)st.st_size;
	want = aligned(n);
	got = aligned(n);
	if (want && got && !full_io(fd, false, want, n, 0) &&
	    !read_span(o->dev, o->offset, n, got)) {
		ret = 0;
		for (size_t i = 0; i < n; i++) {
			if (i >= o->skip_offset && i - o->skip_offset < o->skip_length)
				continue;
			if (want[i] != got[i]) {
				fprintf(stderr, "guard byte %zu differs on %s\n", i, o->dev);
				ret = 1;
				break;
			}
		}
	}
	close(fd);
	free(want);
	free(got);
	return ret;
}

static int cmd_fill(const struct opts *o)
{
	unsigned char *buf;
	int ret;

	if (!need(o, H_DEV | H_OFF | H_LEN | H_BYTE) || !span_ok(o->offset, o->length) || o->byte > 255)
		return 2;
	buf = aligned(o->length);
	if (!buf)
		return 1;
	memset(buf, (int)o->byte, o->length);
	ret = write_span(o->dev, o->offset, o->length, buf);
	free(buf);
	return ret ? 1 : 0;
}

static bool chain_shape_ok(const struct opts *o)
{
	return o->group >= 512 && !(o->group % 512) && o->group <= (4u << 20) && o->groups &&
	       o->groups <= MAX_SPAN / o->group;
}

static int cmd_chain_source(const struct opts *o)
{
	size_t total;
	unsigned char *buf, *plain;
	int ret = 0;

	if (!need(o, H_DEV | H_OFF | H_GROUP | H_GROUPS | H_SEED) || !chain_shape_ok(o) ||
	    !span_ok(o->offset, o->group * o->groups))
		return 2;
	total = o->group * o->groups;
	buf = aligned(total);
	plain = malloc(o->group);
	if (!buf || !plain)
		return 1;
	memset(buf, 0, total);
	for (uint64_t g = 0; g < o->groups && !ret; g++) {
		unsigned char *slot = buf + g * o->group;

		if (!o->compress) {
			chain_bytes(slot, o->group, o->seed, g, false);
			continue;
		}
		/* Raw DEFLATE, 2 KiB window, zero-padded to the slot (run.py's compressed_record). */
		z_stream z;

		memset(&z, 0, sizeof(z));
		chain_bytes(plain, o->group, o->seed, g, true);
		if (deflateInit2(&z, 9, Z_DEFLATED, -IAA_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
			ret = 1;
		z.next_in = plain;
		z.avail_in = (uInt)o->group;
		z.next_out = slot;
		z.avail_out = (uInt)o->group;
		if (!ret && deflate(&z, Z_FINISH) != Z_STREAM_END) {
			fprintf(stderr, "group %" PRIu64 " does not compress into its slot\n", g);
			ret = 1;
		}
		deflateEnd(&z);
	}
	if (!ret)
		ret = write_span(o->dev, o->offset, total, buf) ? 1 : 0;
	free(buf);
	free(plain);
	return ret;
}

static int cmd_chain_ref(const struct opts *o)
{
	size_t total;
	unsigned char *buf;
	int ret;

	if (!need(o, H_OUT | H_GROUP | H_GROUPS | H_SEED) || !chain_shape_ok(o))
		return 2;
	total = o->group * o->groups;
	buf = malloc(total);
	if (!buf)
		return 1;
	for (uint64_t g = 0; g < o->groups; g++)
		chain_bytes(buf + g * o->group, o->group, o->seed, g, o->text);
	ret = write_new(o->out, buf, total);
	free(buf);
	return ret == -2 ? 2 : ret ? 1 : 0;
}

static int cmd_chain_file(const struct opts *o)
{
	size_t total;
	unsigned char *got, *want;
	int ret = 1;

	if (!need(o, H_DEV | H_OFF | H_GROUP | H_GROUPS | H_SEED) || !chain_shape_ok(o) ||
	    !span_ok(o->offset, o->group * o->groups))
		return 2;
	total = o->group * o->groups;
	got = aligned(total);
	want = malloc(o->group);
	if (got && want && !read_span(o->dev, o->offset, total, got)) {
		ret = 0;
		for (uint64_t g = 0; g < o->groups && !ret; g++) {
			chain_bytes(want, o->group, o->seed, g, false);
			if (memcmp(got + g * o->group, want, o->group)) {
				fprintf(stderr, "destination group %" PRIu64 " differs\n", g);
				ret = 1;
			}
		}
		if (!ret)
			report(got, total);
	}
	free(got);
	free(want);
	return ret;
}

static int cmd_chain_ce(const struct opts *o)
{
	unsigned char *win, *want, *seen, *newest = NULL;
	size_t bytes;
	int ret = 1;

	if (!need(o, H_CE | H_VA | H_GROUP | H_SLOTS | H_GROUPS | H_SEED) || !chain_shape_ok(o) ||
	    !o->slots || o->slots > 1024)
		return 2;
	bytes = o->slots * o->group;
	win = malloc(bytes);
	want = malloc(o->group);
	seen = calloc(o->groups, 1);
	if (win && want && seen && !read_ce(o->ce, o->va, bytes, win)) {
		ret = 0;
		for (uint64_t s = 0; s < o->slots && !ret; s++) {
			unsigned char *slot = win + s * o->group;
			uint64_t g = get_le(slot);
			size_t i;

			for (i = 0; i < o->group && slot[i] == CE_PRISTINE; i++)
				;
			if (i == o->group)
				continue;	/* never written */
			if (g >= o->groups || seen[g]++) {
				fprintf(stderr, "slot %" PRIu64 " holds group %" PRIu64 " (%s)\n", s, g,
					g >= o->groups ? "outside the campaign" : "twice");
				ret = 1;
				break;
			}
			chain_bytes(want, o->group, o->seed, g, true);
			if (memcmp(slot, want, o->group)) {
				fprintf(stderr, "slot %" PRIu64 " is not a whole image of group %" PRIu64 "\n", s, g);
				ret = 1;
			}
			if (g == o->groups - 1)
				newest = slot;
		}
		if (!ret && !newest) {
			fprintf(stderr, "the newest group %" PRIu64 " is in no slot\n", o->groups - 1);
			ret = 1;
		}
		if (!ret)
			report(newest, o->group);
	}
	free(win);
	free(want);
	free(seen);
	return ret;
}

/*
 * Which block of the @nblocks-block window a @size-byte image holds: its
 * first word names its position; the whole image must then match.
 */
static int identify(const unsigned char *img, uint64_t size, uint64_t nblocks, uint32_t seed,
		    unsigned char *scratch, uint64_t *block)
{
	uint64_t inv = 0x9e3779b97f4a7c15ULL, w;

	for (int i = 0; i < 6; i++)
		inv *= 2 - 0x9e3779b97f4a7c15ULL * inv;
	w = (get_le(img) * inv) ^ splitmix_final(seed);
	if (w % (size / 8) || w / (size / 8) >= nblocks)
		return -1;
	*block = w / (size / 8);
	xg_bytes(scratch, *block * size, size, seed);
	return memcmp(img, scratch, size) ? -1 : 0;
}

/* Reorder @n images of @size bytes by block; every block 0..n-1 exactly once. */
static int canonical_blocks(const unsigned char *images, uint64_t n, uint64_t size,
			    uint32_t seed, const char *what)
{
	unsigned char *out = malloc(n * size), *scratch = malloc(size), *seen = calloc(n, 1);
	int ret = 0;

	if (!out || !scratch || !seen)
		ret = 1;
	for (uint64_t i = 0; i < n && !ret; i++) {
		uint64_t b;

		if (identify(images + i * size, size, n, seed, scratch, &b)) {
			fprintf(stderr, "%s %" PRIu64 " is not a whole block image of the window\n", what, i);
			ret = 1;
		} else if (seen[b]++) {
			fprintf(stderr, "%s %" PRIu64 " repeats block %" PRIu64 "\n", what, i, b);
			ret = 1;
		} else {
			memcpy(out + b * size, images + i * size, size);
		}
	}
	if (!ret)
		report(out, n * size);
	free(out);
	free(scratch);
	free(seen);
	return ret;
}

static bool xg_shape_ok(uint64_t size, uint64_t slots)
{
	return size >= 4096 && !(size % 4096) && size <= (4u << 20) && slots && slots <= 64 &&
	       slots * size <= MAX_SPAN;
}

static int cmd_xg_slots(const struct opts *o)
{
	unsigned char *win;
	int ret = 1;

	if (!need(o, H_CE | H_VA | H_SIZE | H_SLOTS | H_SEED) || !xg_shape_ok(o->size, o->slots) ||
	    o->seed > UINT32_MAX)
		return 2;
	win = malloc(o->slots * o->size);
	if (win && !read_ce(o->ce, o->va, o->slots * o->size, win))
		ret = canonical_blocks(win, o->slots, o->size, (uint32_t)o->seed, "device slot");
	free(win);
	return ret;
}

static int cmd_xg_file(const struct opts *o)
{
	unsigned char *buf;
	int ret = 1;

	/* window/size == qd: every slot image lands in exactly one file group. */
	if (!need(o, H_DEV | H_OFF | H_SIZE | H_GROUPS | H_SLOTS | H_SEED) ||
	    !xg_shape_ok(o->size, o->slots) || o->groups != o->slots || o->seed > UINT32_MAX ||
	    !span_ok(o->offset, o->size * o->groups))
		return 2;
	buf = aligned(o->size * o->groups);
	if (buf && !read_span(o->dev, o->offset, o->size * o->groups, buf))
		ret = canonical_blocks(buf, o->groups, o->size, (uint32_t)o->seed, "file group");
	free(buf);
	return ret;
}

static int cmd_sha256(int argc, char **argv)
{
	unsigned char chunk[65536];
	struct sha s;
	uint64_t total;
	char hex[65];
	ssize_t n;
	int fd;

	if (argc != 3)
		return 2;
	fd = open(argv[2], O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 1;
	sha_init(&s);
	while ((n = read(fd, chunk, sizeof(chunk))) > 0)
		sha_update(&s, chunk, (size_t)n);
	close(fd);
	if (n < 0)
		return 1;
	total = s.len;
	sha_final(&s, hex);
	printf("bytes=%" PRIu64 " sha256=%s\n", total, hex);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct { const char *name; int (*fn)(const struct opts *); } cmds[] = {
		{ "compare", cmd_compare }, { "snapshot", cmd_snapshot }, { "restore", cmd_restore }, { "fill", cmd_fill },
		{ "chain-source", cmd_chain_source }, { "chain-ref", cmd_chain_ref },
		{ "chain-file", cmd_chain_file }, { "chain-ce", cmd_chain_ce },
		{ "xg-slots", cmd_xg_slots }, { "xg-file", cmd_xg_file },
	};
	struct opts o;

	if (argc >= 2 && !strcmp(argv[1], "sha256"))
		return cmd_sha256(argc, argv);
	for (size_t i = 0; argc >= 2 && i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		if (strcmp(argv[1], cmds[i].name))
			continue;
		if (parse(argc, argv, &o)) {
			fprintf(stderr, "eval_session_oracle %s: bad options\n", argv[1]);
			return 2;
		}
		return cmds[i].fn(&o);
	}
	fprintf(stderr, "usage: eval_session_oracle snapshot|restore|fill|chain-source|chain-ref|"
		"chain-file|chain-ce|xg-slots|xg-file|sha256 ...\n");
	return 2;
}
