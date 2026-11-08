/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KV_RESTORE_INDEX_H
#define KV_RESTORE_INDEX_H
/*
 * The K-KV prefix index as the C worker reads it (same file kv_layout.py
 * writes; test_plan_crosscheck.py compares the two parsers):
 *
 *   xdev-kv-index 1                         (legacy raw/pattern indexes)
 *   xdev-kv-index 2 dtype=bfloat16          (typed producer indexes)
 *   prefix HASH object=NAME slba=N offset=N bytes=N tokens=N [fnv1a=0xN]
 *
 * HASH is kv_layout.prefix_hashes()'s 64 lowercase hex digits; slba is the
 * object's first LBA, offset the byte offset of the prefix in the object,
 * bytes its length, fnv1a the FNV-1a 64 of the prefix bytes.  The checks
 * against a manifest (object exists, whole vLLM blocks, inside the extent)
 * are kv_layout.py's when it writes or loads the file; this parser checks the
 * syntax, repeats and the LBA arithmetic of the restore request. The worker
 * treats HASH as opaque; the connector separately requires typed v2 and
 * recomputes its dtype-specific domain before selecting an entry.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KV_INDEX_HEADER		"xdev-kv-index 1"
#define KV_INDEX_MAX_ENTRIES	(1u << 20)
#define KV_INDEX_LINE_MAX	512

struct kv_index_entry {
	char hash[65];
	char object[129];
	uint64_t slba, offset, bytes, tokens, fnv1a;
	bool has_fnv1a;
};

struct kv_index {
	struct kv_index_entry *v;
	size_t n;
};

/* Decimal or 0x hex, no sign; what kv_layout.py writes and accepts. */
static inline int kv_index_number(const char *s, uint64_t *out)
{
	int base = 10;
	uint64_t v = 0;

	if (s[0] == '0' && s[1] == 'x') {
		base = 16;
		s += 2;
	}
	if (!*s)
		return -EINVAL;
	for (; *s; s++) {
		int d = *s >= '0' && *s <= '9' ? *s - '0'
			: base == 16 && *s >= 'a' && *s <= 'f' ? *s - 'a' + 10
			: base == 16 && *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : -1;

		if (d < 0 || v > (UINT64_MAX - (uint64_t)d) / (uint64_t)base)
			return -EINVAL;
		v = v * (uint64_t)base + (uint64_t)d;
	}
	*out = v;
	return 0;
}

static inline bool kv_index_hash_ok(const char *h)
{
	size_t i;

	for (i = 0; h[i]; i++)
		if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f')))
			return false;
	return i == 64;
}

/* 0: an entry in @e; 1: blank or comment line; -EINVAL: malformed. */
static inline int kv_index_parse_line(const char *text, struct kv_index_entry *e)
{
	char buf[KV_INDEX_LINE_MAX], *save = NULL, *tok;
	unsigned seen = 0;
	size_t len = strlen(text);

	if (len >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, text, len + 1);
	tok = strtok_r(buf, " \t\r\n", &save);
	if (!tok || tok[0] == '#')
		return 1;
	memset(e, 0, sizeof(*e));
	if (strcmp(tok, "prefix"))
		return -EINVAL;
	tok = strtok_r(NULL, " \t\r\n", &save);
	if (!tok || !kv_index_hash_ok(tok))
		return -EINVAL;
	memcpy(e->hash, tok, 65);
	while ((tok = strtok_r(NULL, " \t\r\n", &save))) {
		static const char *const keys[] = { "object", "slba", "offset", "bytes", "tokens",
						    "fnv1a" };
		uint64_t *nums[] = { NULL, &e->slba, &e->offset, &e->bytes, &e->tokens, &e->fnv1a };
		char *eq = strchr(tok, '=');
		unsigned k;

		if (!eq)
			return -EINVAL;
		*eq++ = 0;
		for (k = 0; k < 6 && strcmp(tok, keys[k]); k++)
			;
		if (k == 6 || seen & (1u << k))
			return -EINVAL;
		seen |= 1u << k;
		if (!k) {
			size_t n = strlen(eq);

			if (!n || n >= sizeof(e->object))
				return -EINVAL;
			memcpy(e->object, eq, n + 1);
		} else if (kv_index_number(eq, nums[k])) {
			return -EINVAL;
		}
	}
	if ((seen & 0x1f) != 0x1f || !e->tokens || !e->bytes)
		return -EINVAL;
	e->has_fnv1a = seen & (1u << 5);
	return 0;
}

static inline void kv_index_free(struct kv_index *ix)
{
	free(ix->v);
	ix->v = NULL;
	ix->n = 0;
}

static inline const struct kv_index_entry *kv_index_find(const struct kv_index *ix,
							  const char *hash)
{
	for (size_t i = 0; i < ix->n; i++)
		if (!strcmp(ix->v[i].hash, hash))
			return &ix->v[i];
	return NULL;
}

/* The whole file or nothing: header first, no repeated prefix. */
static inline int kv_index_load(FILE *f, struct kv_index *ix)
{
	char line[KV_INDEX_LINE_MAX + 2];
	size_t cap = 0;
	int ret = 0;

	ix->v = NULL;
	ix->n = 0;
	if (!fgets(line, sizeof(line), f))
		return -EINVAL;
	line[strcspn(line, "\r\n")] = 0;
	if (strcmp(line, KV_INDEX_HEADER) && strcmp(line, "xdev-kv-index 2 dtype=bfloat16") &&
	    strcmp(line, "xdev-kv-index 2 dtype=float16") &&
	    strcmp(line, "xdev-kv-index 2 dtype=float32") && strcmp(line, "xdev-kv-index 2 dtype=uint8"))
		return -EINVAL;
	while (!ret && fgets(line, sizeof(line), f)) {
		struct kv_index_entry e;
		int r = kv_index_parse_line(line, &e);

		if (r == 1)
			continue;
		if (r) {
			ret = r;
		} else if (kv_index_find(ix, e.hash)) {
			ret = -EEXIST;
		} else if (ix->n == KV_INDEX_MAX_ENTRIES) {
			ret = -E2BIG;
		} else {
			if (ix->n == cap) {
				size_t ncap = cap ? cap * 2 : 64;
				struct kv_index_entry *v = realloc(ix->v, ncap * sizeof(*v));

				if (!v) {
					ret = -ENOMEM;
					break;
				}
				ix->v = v;
				cap = ncap;
			}
			ix->v[ix->n++] = e;
		}
	}
	if (!ret && ferror(f))
		ret = -EIO;
	if (ret)
		kv_index_free(ix);
	return ret;
}

/* The restore request (object_slba, bytes) for an entry. */
static inline int kv_index_resolve(const struct kv_index_entry *e, uint32_t lba_bytes,
				   uint64_t *slba, uint64_t *bytes)
{
	if (!lba_bytes || e->offset % lba_bytes || e->slba > UINT64_MAX - e->offset / lba_bytes)
		return -EINVAL;
	*slba = e->slba + e->offset / lba_bytes;
	*bytes = e->bytes;
	return 0;
}

#endif /* KV_RESTORE_INDEX_H */
