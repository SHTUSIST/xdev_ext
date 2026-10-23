/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_JSON_H
#define CHAIN_JSON_H

/*
 * A strict JSON subset for benchmark specs: objects, arrays, strings,
 * unsigned decimal integers and true/false.  Anything else (null,
 * negative or fractional numbers, \u escapes, duplicate keys, trailing
 * bytes) is an error, so a spec either means exactly one thing or is
 * refused.  Nodes and string bytes live in the fixed arrays of the
 * document; nothing is allocated.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CJ_MAX_NODES	512
#define CJ_MAX_STRBUF	16384
#define CJ_MAX_DEPTH	8

enum cj_type { CJ_BOOL = 1, CJ_UINT, CJ_STRING, CJ_ARRAY, CJ_OBJECT };

struct cj_node {
	enum cj_type type;
	bool b;
	uint64_t u;
	const char *s;		/* CJ_STRING, NUL-terminated */
	const char *key;	/* member name inside an object, else NULL */
	int child;		/* first element/member, -1 if none */
	int next;		/* next sibling, -1 if none */
	unsigned int count;	/* elements/members */
};

struct cj_doc {
	struct cj_node n[CJ_MAX_NODES];
	int nr;
	char str[CJ_MAX_STRBUF];
	size_t used;
	const char *err;
	size_t err_off;
};

struct cj_in {
	const char *p, *end, *start;
	struct cj_doc *d;
};

static inline int cj_fail(struct cj_in *in, const char *why)
{
	if (!in->d->err) {
		in->d->err = why;
		in->d->err_off = (size_t)(in->p - in->start);
	}
	return -1;
}

static inline void cj_ws(struct cj_in *in)
{
	while (in->p < in->end && (*in->p == ' ' || *in->p == '\t' ||
				   *in->p == '\n' || *in->p == '\r'))
		in->p++;
}

static inline int cj_node(struct cj_in *in, enum cj_type t)
{
	struct cj_doc *d = in->d;

	if (d->nr >= CJ_MAX_NODES)
		return cj_fail(in, "too many JSON nodes");
	d->n[d->nr] = (struct cj_node){ .type = t, .child = -1, .next = -1 };
	return d->nr++;
}

/* A string token at in->p (the opening quote) into the string arena. */
static inline const char *cj_string(struct cj_in *in)
{
	struct cj_doc *d = in->d;
	char *out = d->str + d->used;
	size_t room = sizeof(d->str) - d->used;
	size_t len = 0;

	in->p++;
	for (;;) {
		char c;

		if (in->p >= in->end) {
			cj_fail(in, "unterminated string");
			return NULL;
		}
		c = *in->p++;
		if (c == '"')
			break;
		if ((unsigned char)c < 0x20) {
			cj_fail(in, "control character in string");
			return NULL;
		}
		if (c == '\\') {
			if (in->p >= in->end) {
				cj_fail(in, "unterminated escape");
				return NULL;
			}
			c = *in->p++;
			switch (c) {
			case '"': case '\\': case '/':
				break;
			case 'n':
				c = '\n';
				break;
			case 't':
				c = '\t';
				break;
			default:
				cj_fail(in, "unsupported string escape");
				return NULL;
			}
		}
		if (len + 1 >= room) {
			cj_fail(in, "string arena exhausted");
			return NULL;
		}
		out[len++] = c;
	}
	out[len] = '\0';
	d->used += len + 1;
	return out;
}

static inline int cj_value(struct cj_in *in, int depth);

static inline int cj_container(struct cj_in *in, int depth, bool object)
{
	char close = object ? '}' : ']';
	int self = cj_node(in, object ? CJ_OBJECT : CJ_ARRAY), last = -1;

	if (self < 0)
		return -1;
	if (depth >= CJ_MAX_DEPTH)
		return cj_fail(in, "JSON nesting too deep");
	in->p++;
	cj_ws(in);
	if (in->p < in->end && *in->p == close) {
		in->p++;
		return self;
	}
	for (;;) {
		const char *key = NULL;
		int v;

		cj_ws(in);
		if (object) {
			int m;

			if (in->p >= in->end || *in->p != '"')
				return cj_fail(in, "object member name expected");
			key = cj_string(in);
			if (!key)
				return -1;
			for (m = in->d->n[self].child; m >= 0; m = in->d->n[m].next)
				if (!strcmp(in->d->n[m].key, key))
					return cj_fail(in, "duplicate object member");
			cj_ws(in);
			if (in->p >= in->end || *in->p != ':')
				return cj_fail(in, "':' expected");
			in->p++;
		}
		v = cj_value(in, depth + 1);
		if (v < 0)
			return -1;
		in->d->n[v].key = key;
		if (last < 0)
			in->d->n[self].child = v;
		else
			in->d->n[last].next = v;
		last = v;
		in->d->n[self].count++;
		cj_ws(in);
		if (in->p < in->end && *in->p == ',') {
			in->p++;
			continue;
		}
		if (in->p < in->end && *in->p == close) {
			in->p++;
			return self;
		}
		return cj_fail(in, object ? "',' or '}' expected" :
					    "',' or ']' expected");
	}
}

static inline int cj_value(struct cj_in *in, int depth)
{
	int v;

	cj_ws(in);
	if (in->p >= in->end)
		return cj_fail(in, "value expected");
	switch (*in->p) {
	case '{':
		return cj_container(in, depth, true);
	case '[':
		return cj_container(in, depth, false);
	case '"': {
		const char *s;

		v = cj_node(in, CJ_STRING);
		if (v < 0)
			return -1;
		s = cj_string(in);
		if (!s)
			return -1;
		in->d->n[v].s = s;
		return v;
	}
	case 't':
	case 'f': {
		bool t = *in->p == 't';
		const char *word = t ? "true" : "false";
		size_t len = strlen(word);

		if ((size_t)(in->end - in->p) < len || memcmp(in->p, word, len))
			return cj_fail(in, "invalid literal");
		in->p += len;
		v = cj_node(in, CJ_BOOL);
		if (v >= 0)
			in->d->n[v].b = t;
		return v;
	}
	default:
		break;
	}
	if (*in->p >= '0' && *in->p <= '9') {
		uint64_t x = 0;
		const char *first = in->p;

		while (in->p < in->end && *in->p >= '0' && *in->p <= '9') {
			unsigned int digit = (unsigned int)(*in->p - '0');

			if (x > (UINT64_MAX - digit) / 10)
				return cj_fail(in, "integer overflow");
			x = x * 10 + digit;
			in->p++;
		}
		if (*first == '0' && in->p - first > 1)
			return cj_fail(in, "leading zero");
		if (in->p < in->end && (*in->p == '.' || *in->p == 'e' ||
					*in->p == 'E'))
			return cj_fail(in, "only unsigned integers are accepted");
		v = cj_node(in, CJ_UINT);
		if (v >= 0)
			in->d->n[v].u = x;
		return v;
	}
	return cj_fail(in, "unsupported JSON value");
}

/* The root object of @len bytes at @text, or -1 with d->err set. */
static inline int cj_parse(struct cj_doc *d, const char *text, size_t len)
{
	struct cj_in in = { .p = text, .end = text + len, .start = text, .d = d };
	int root;

	memset(d, 0, sizeof(*d));
	cj_ws(&in);
	if (in.p >= in.end || *in.p != '{')
		return cj_fail(&in, "root must be an object");
	root = cj_value(&in, 0);
	if (root < 0)
		return -1;
	cj_ws(&in);
	if (in.p != in.end)
		return cj_fail(&in, "trailing bytes after the root object");
	return root;
}

static inline int cj_get(const struct cj_doc *d, int obj, const char *key)
{
	int m;

	if (obj < 0 || d->n[obj].type != CJ_OBJECT)
		return -1;
	for (m = d->n[obj].child; m >= 0; m = d->n[m].next)
		if (!strcmp(d->n[m].key, key))
			return m;
	return -1;
}

/* NULL when every member of @obj is in the NULL-terminated @allowed. */
static inline const char *cj_unknown(const struct cj_doc *d, int obj,
				     const char *const *allowed)
{
	int m;

	for (m = d->n[obj].child; m >= 0; m = d->n[m].next) {
		const char *const *a;

		for (a = allowed; *a; a++)
			if (!strcmp(*a, d->n[m].key))
				break;
		if (!*a)
			return d->n[m].key;
	}
	return NULL;
}

/* 0 found, 1 absent (value untouched), -1 wrong type. */
static inline int cj_u64(const struct cj_doc *d, int obj, const char *key,
			 uint64_t *v)
{
	int m = cj_get(d, obj, key);

	if (m < 0)
		return 1;
	if (d->n[m].type != CJ_UINT)
		return -1;
	*v = d->n[m].u;
	return 0;
}

static inline int cj_bool(const struct cj_doc *d, int obj, const char *key,
			  bool *v)
{
	int m = cj_get(d, obj, key);

	if (m < 0)
		return 1;
	if (d->n[m].type != CJ_BOOL)
		return -1;
	*v = d->n[m].b;
	return 0;
}

/* Copies into @buf of @size; -1 also when it does not fit. */
static inline int cj_str(const struct cj_doc *d, int obj, const char *key,
			 char *buf, size_t size)
{
	int m = cj_get(d, obj, key);
	size_t len;

	if (m < 0)
		return 1;
	if (d->n[m].type != CJ_STRING)
		return -1;
	len = strlen(d->n[m].s);
	if (len >= size)
		return -1;
	memcpy(buf, d->n[m].s, len + 1);
	return 0;
}

/*
 * @s as a JSON string literal, for result lines (run.py reads them with
 * Python's json): quote, backslash and control bytes escaped.
 */
static inline void cj_write_str(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		if (*s == '"' || *s == '\\')
			fprintf(f, "\\%c", *s);
		else if ((unsigned char)*s < 0x20)
			fprintf(f, "\\u%04x", (unsigned char)*s);
		else
			fputc(*s, f);
	}
	fputc('"', f);
}

#endif /* CHAIN_JSON_H */
