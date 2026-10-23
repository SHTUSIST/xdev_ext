/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_SPEC_H
#define CHAIN_SPEC_H

/*
 * Pure part of chain_bench: the JSON spec, its validation, the named chain
 * catalog and the stage/pool layout a session is created with.  Nothing
 * here opens a device; tests/eval/chains/test_chain_spec.c covers it on the
 * host.
 *
 * A spec lists up to XDEV_EXT_MECH_MAX_STAGES stages explicitly.  "chain"
 * names the expected class/direction sequence and the spec is refused when
 * the list does not match it; "custom" accepts any list that the kernel's
 * CREATE rules (xdev_ext_mech_create_check, xdev_ext_mech_transform_reserve)
 * can admit and this runtime can drive.  Refusals of a missing capability
 * start with "unsupported:", malformed specs with "invalid:".
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "chain_json.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

#define CHAIN_SCHEMA		"xdev-chain-spec-v1"
#define CHAIN_PATH_MAX		256
#define CHAIN_MAX_PLANS		4
#define CHAIN_MAX_SETS		4
#define CHAIN_MAX_DEPTH		64	/* XDEV_EXT_MECH_MAX_DEPTH */
#define CHAIN_MAX_BATCHES	(1U << 24)
#define CHAIN_XSK_FRAMES	4096U	/* AF_XDP pool chunks, as xdev_ext_mech_ctl */
#define CHAIN_IAA_MAX		131072U	/* CRYPTO_ACOMP_DST_MAX */

enum chain_class { CH_NVME = 1, CH_CE, CH_AFXDP, CH_IAA };
enum chain_dir { CH_TO = 1, CH_FROM };
enum chain_arm { CH_SESSION = 1, CH_STAGED };
enum chain_mode { CH_CORRECTNESS = 1, CH_TIMING };
enum chain_start { CH_START_BATCH = 1, CH_START_RUN };
enum chain_load { CH_LOAD_CLOSED = 1, CH_LOAD_SUSTAINED };
enum chain_plan_kind { CH_PLAN_BPF = 1, CH_PLAN_DEFAULT };
enum chain_xsk_mode { CH_XSK_ZC = 1, CH_XSK_COPY };
enum chain_oracle_kind { CH_ORACLE_NONE = 1, CH_ORACLE_FILE, CH_ORACLE_CE };
enum chain_gpu { CH_GPU_NONE = 1, CH_GPU_CUDA, CH_GPU_CE_SIM };

struct chain_stage {
	enum chain_class cls;
	enum chain_dir dir;
	char dev[CHAIN_PATH_MAX];	/* NVMe ng char device; IAA lifetime token */
	char block[CHAIN_PATH_MAX];	/* NVMe block device (staged arm) */
	char ifname[16];		/* AF_XDP, IFNAMSIZ */
	uint64_t slba, nlb;		/* NVMe window */
	uint32_t queue;			/* AF_XDP queue */
	bool software;			/* IAA: deflate-generic instead of deflate-iaa */
	uint32_t capacity;		/* IAA: destination bytes per batch */
	uint32_t expect;		/* IAA: produced bytes every batch must have, 0 any */
};

struct chain_plan {
	char obj[CHAIN_PATH_MAX];
	char map[64];
	unsigned int nr_sets;
	char set_name[CHAIN_MAX_SETS][64];
	uint64_t set_value[CHAIN_MAX_SETS];
};

struct chain_spec {
	char chain[32];
	enum chain_arm arm;
	enum chain_mode mode;
	enum chain_start start_per;
	enum chain_load load;		/* closed: window by window; sustained: one run */
	enum chain_plan_kind plan;
	enum chain_xsk_mode xsk_mode;
	uint32_t group_bytes, depth, burst;
	uint64_t batches, warmup, timeout_ms, seed;
	/* io_uring UMEM pool, for chains without an AF_XDP stage */
	uint32_t frame_size, hdr_room, pool_frames;
	bool hugepage;
	/* one device window shared by every CE stage */
	char ce_dev[CHAIN_PATH_MAX];
	uint64_t ce_va, ce_len;
	bool ce_native;
	char ce_bdf[32];		/* staged arm with CUDA */
	struct xdev_ext_mech_peer peer;
	uint64_t nxp_session;
	unsigned int nr_plans, nr_stages;
	struct chain_plan plans[CHAIN_MAX_PLANS];
	struct chain_stage st[XDEV_EXT_MECH_MAX_STAGES];
	enum chain_oracle_kind oracle;
	char oracle_path[CHAIN_PATH_MAX];	/* FILE: readback device or file */
	char reference[CHAIN_PATH_MAX];		/* expected bytes */
	uint64_t oracle_offset;
	bool every_window;			/* CE: check after each window */
	enum chain_gpu gpu;			/* staged arm GPU leg */
	char iaa_counts_pin[CHAIN_PATH_MAX];	/* chain_counts of a system-wide plan */
	char out[CHAIN_PATH_MAX];
};

/* One named chain: its stage sequence, or a refusal when it cannot exist. */
struct chain_catalog {
	const char *name;
	unsigned int nr;
	enum chain_class cls[XDEV_EXT_MECH_MAX_STAGES];
	enum chain_dir dir[XDEV_EXT_MECH_MAX_STAGES];
	const char *refusal;	/* non-NULL: never runs */
	bool staged;		/* the staged arm implements it */
	bool staged_timing;	/* ... and may be timed */
};

#define CHAIN_REFUSE_CRC \
	"unsupported: in-frame transform not implemented (no mechanism class " \
	"claims a frame, rewrites it in place and republishes it; the BPF " \
	"frame view is read-only)"
#define CHAIN_REFUSE_NIC_IAA \
	"unsupported: one session cannot hold AF_XDP RX and an IAA transform: " \
	"AF_XDP stages need the socket UMEM pool and IAA destination leases " \
	"need the io_uring UMEM pool"
#define CHAIN_REFUSE_DEFAULT_PLAN \
	"unsupported: no mechanism class registers default_build, so a build " \
	"returning XDEV_EXT_MECH_BUILD_DEFAULT aborts with -EOPNOTSUPP"

static const struct chain_catalog chain_catalog[] = {
	{ "nvme-nic", 2, { CH_NVME, CH_AFXDP }, { CH_FROM, CH_TO },
	  NULL, true, true },
	{ "nic-nvme", 2, { CH_AFXDP, CH_NVME }, { CH_FROM, CH_TO },
	  NULL, true, true },
	{ "nvme-gpu-nic", 4, { CH_NVME, CH_CE, CH_CE, CH_AFXDP },
	  { CH_FROM, CH_TO, CH_FROM, CH_TO }, NULL, true, true },
	{ "nic-gpu-nvme", 4, { CH_AFXDP, CH_CE, CH_CE, CH_NVME },
	  { CH_FROM, CH_TO, CH_FROM, CH_TO }, NULL, true, true },
	{ "nvme-iaa-gpu", 3, { CH_NVME, CH_IAA, CH_CE },
	  { CH_FROM, CH_FROM, CH_TO }, NULL, true, false },
	{ "nic-iaa-gpu", 3, { CH_AFXDP, CH_IAA, CH_CE },
	  { CH_FROM, CH_FROM, CH_TO }, CHAIN_REFUSE_NIC_IAA, false, false },
	{ "nvme-crc-nic", 0, { 0 }, { 0 }, CHAIN_REFUSE_CRC, false, false },
};

static inline const struct chain_catalog *chain_find(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(chain_catalog) / sizeof(chain_catalog[0]); i++)
		if (!strcmp(chain_catalog[i].name, name))
			return &chain_catalog[i];
	return NULL;
}

static inline bool chain_has(const struct chain_spec *s, enum chain_class c)
{
	unsigned int i;

	for (i = 0; i < s->nr_stages; i++)
		if (s->st[i].cls == c)
			return true;
	return false;
}

/* AF_XDP RX first: the session is driven by received packets, not START. */
static inline bool chain_rx_first(const struct chain_spec *s)
{
	return s->nr_stages && s->st[0].cls == CH_AFXDP && s->st[0].dir == CH_FROM;
}

/* Windows (one START, one terminal wake each) of the measured part. */
static inline uint64_t chain_windows(const struct chain_spec *s)
{
	if (s->load == CH_LOAD_SUSTAINED)
		return 1;
	return s->start_per == CH_START_RUN ? 1 : s->batches / s->burst;
}

/* Records (burst batches each) of the whole campaign, warmup included. */
static inline uint64_t chain_records(const struct chain_spec *s)
{
	return (s->warmup + s->batches) / s->burst;
}

/* The most batches one START asks for. */
static inline uint64_t chain_start_batches(const struct chain_spec *s)
{
	if (s->load == CH_LOAD_SUSTAINED)
		return s->warmup + s->batches;
	if (s->start_per == CH_START_BATCH)
		return s->burst;		/* warmup windows are bursts too */
	return s->warmup > s->batches ? s->warmup : s->batches;
}

static inline uint64_t chain_window_batches(const struct chain_spec *s)
{
	return s->start_per == CH_START_RUN ? s->batches : s->burst;
}

/* --- parsing ------------------------------------------------------------ */

struct chain_err {
	char msg[256];
};

static inline int chain_bad(struct chain_err *e, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static inline int chain_bad(struct chain_err *e, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
	va_end(ap);
	return -1;
}

static inline int chain_enum(const struct cj_doc *d, int obj, const char *key,
			     const char *const *names, const int *values,
			     int dflt, int *out, struct chain_err *e)
{
	char buf[32];
	int r = cj_str(d, obj, key, buf, sizeof(buf));
	unsigned int i;

	if (r > 0) {
		if (dflt < 0)
			return chain_bad(e, "invalid: missing %s", key);
		*out = dflt;
		return 0;
	}
	if (r < 0)
		return chain_bad(e, "invalid: %s must be a short string", key);
	for (i = 0; names[i]; i++)
		if (!strcmp(names[i], buf)) {
			*out = values[i];
			return 0;
		}
	return chain_bad(e, "invalid: %s=%s", key, buf);
}

#define CHAIN_ENUM(d, obj, key, dflt, out, e, ...) ({			\
	static const char *const n_[] = { __VA_ARGS__, NULL };		\
	static const int v_[] = { 1, 2, 3, 4 };				\
	int x_ = 0, r_ = chain_enum(d, obj, key, n_, v_, dflt, &x_, e);	\
	if (!r_)							\
		*(out) = x_;						\
	r_;								\
})

static inline int chain_u64(const struct cj_doc *d, int obj, const char *key,
			    uint64_t dflt, bool required, uint64_t lo,
			    uint64_t hi, uint64_t *out, struct chain_err *e)
{
	uint64_t v = dflt;
	int r = cj_u64(d, obj, key, &v);

	if (r < 0)
		return chain_bad(e, "invalid: %s must be an unsigned integer", key);
	if (r > 0 && required)
		return chain_bad(e, "invalid: missing %s", key);
	if (v < lo || v > hi)
		return chain_bad(e, "invalid: %s=%llu outside [%llu, %llu]", key,
				 (unsigned long long)v, (unsigned long long)lo,
				 (unsigned long long)hi);
	*out = v;
	return 0;
}

static inline int chain_u32(const struct cj_doc *d, int obj, const char *key,
			    uint32_t dflt, bool required, uint32_t lo,
			    uint32_t hi, uint32_t *out, struct chain_err *e)
{
	uint64_t v = 0;

	if (chain_u64(d, obj, key, dflt, required, lo, hi, &v, e))
		return -1;
	*out = (uint32_t)v;
	return 0;
}

static inline int chain_path(const struct cj_doc *d, int obj, const char *key,
			     bool required, char *buf, size_t size,
			     struct chain_err *e)
{
	int r = cj_str(d, obj, key, buf, size);

	if (r < 0)
		return chain_bad(e, "invalid: %s must be a string shorter than %zu",
				 key, size);
	if (r > 0 && required)
		return chain_bad(e, "invalid: missing %s", key);
	if (!r && !buf[0])
		return chain_bad(e, "invalid: empty %s", key);
	return 0;
}

static inline int chain_ipv4(const char *s, __be32 *ip)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		return -1;
	*ip = (__be32)a.s_addr;
	return 0;
}

static inline int chain_parse_peer(const struct cj_doc *d, int obj,
				   struct chain_spec *s, struct chain_err *e)
{
	static const char *const keys[] = { "local_mac", "peer_mac", "local_ip",
		"peer_ip", "local_port", "peer_port", "session", NULL };
	char buf[32];
	uint32_t port;
	const char *bad = cj_unknown(d, obj, keys);

	if (bad)
		return chain_bad(e, "invalid: unknown peer member %s", bad);
	if (cj_str(d, obj, "local_mac", buf, sizeof(buf)) ||
	    xdev_ext_mech_ctl_parse_mac(buf, s->peer.local_mac))
		return chain_bad(e, "invalid: peer.local_mac");
	if (cj_str(d, obj, "peer_mac", buf, sizeof(buf)) ||
	    xdev_ext_mech_ctl_parse_mac(buf, s->peer.peer_mac))
		return chain_bad(e, "invalid: peer.peer_mac");
	if (cj_str(d, obj, "local_ip", buf, sizeof(buf)) ||
	    chain_ipv4(buf, &s->peer.local_ip))
		return chain_bad(e, "invalid: peer.local_ip");
	if (cj_str(d, obj, "peer_ip", buf, sizeof(buf)) ||
	    chain_ipv4(buf, &s->peer.peer_ip))
		return chain_bad(e, "invalid: peer.peer_ip");
	if (chain_u32(d, obj, "local_port", 0, true, 1, 65535, &port, e))
		return -1;
	s->peer.local_port = (__be16)htons((uint16_t)port);
	if (chain_u32(d, obj, "peer_port", 0, true, 1, 65535, &port, e))
		return -1;
	s->peer.peer_port = (__be16)htons((uint16_t)port);
	return chain_u64(d, obj, "session", 0, true, 1, UINT64_MAX,
			 &s->nxp_session, e);
}

static inline int chain_parse_plans(const struct cj_doc *d, int arr,
				    struct chain_spec *s, struct chain_err *e)
{
	static const char *const keys[] = { "obj", "map", "set", NULL };
	int p;

	if (d->n[arr].type != CJ_ARRAY)
		return chain_bad(e, "invalid: plans must be an array");
	if (d->n[arr].count > CHAIN_MAX_PLANS)
		return chain_bad(e, "invalid: at most %u plans", CHAIN_MAX_PLANS);
	for (p = d->n[arr].child; p >= 0; p = d->n[p].next) {
		struct chain_plan *pl = &s->plans[s->nr_plans++];
		const char *bad;
		int set, m;

		if (d->n[p].type != CJ_OBJECT)
			return chain_bad(e, "invalid: a plan must be an object");
		bad = cj_unknown(d, p, keys);
		if (bad)
			return chain_bad(e, "invalid: unknown plan member %s", bad);
		if (chain_path(d, p, "obj", true, pl->obj, sizeof(pl->obj), e) ||
		    chain_path(d, p, "map", true, pl->map, sizeof(pl->map), e))
			return -1;
		set = cj_get(d, p, "set");
		if (set < 0)
			continue;
		if (d->n[set].type != CJ_OBJECT || d->n[set].count > CHAIN_MAX_SETS)
			return chain_bad(e, "invalid: plan set must be an object of at most %u globals",
					 CHAIN_MAX_SETS);
		for (m = d->n[set].child; m >= 0; m = d->n[m].next) {
			char name[72];
			__u64 v;

			if (d->n[m].type != CJ_UINT ||
			    strlen(d->n[m].key) >= sizeof(pl->set_name[0]))
				return chain_bad(e, "invalid: plan global %s", d->n[m].key);
			snprintf(name, sizeof(name), "%s=0", d->n[m].key);
			if (xdev_ext_mech_ctl_parse_set(name, pl->set_name[pl->nr_sets],
						   sizeof(pl->set_name[0]), &v))
				return chain_bad(e, "invalid: plan global name %s",
						 d->n[m].key);
			pl->set_value[pl->nr_sets++] = d->n[m].u;
		}
	}
	return 0;
}

static inline int chain_parse_stage(const struct cj_doc *d, int o,
				    struct chain_stage *st, struct chain_err *e)
{
	static const char *const keys[] = { "class", "dir", "dev", "block",
		"ifname", "slba", "nlb", "queue", "software", "capacity",
		"expect", NULL };
	const char *bad = cj_unknown(d, o, keys);
	int cls, dir;

	if (bad)
		return chain_bad(e, "invalid: unknown stage member %s", bad);
	if (CHAIN_ENUM(d, o, "class", -1, &cls, e, "nvme", "ce", "afxdp", "iaa") ||
	    CHAIN_ENUM(d, o, "dir", -1, &dir, e, "to", "from"))
		return -1;
	st->cls = (enum chain_class)cls;
	st->dir = (enum chain_dir)dir;
	switch (st->cls) {
	case CH_NVME:
		if (chain_path(d, o, "dev", false, st->dev, sizeof(st->dev), e) ||
		    chain_path(d, o, "block", false, st->block, sizeof(st->block), e) ||
		    chain_u64(d, o, "slba", 0, true, 0, UINT64_MAX, &st->slba, e) ||
		    chain_u64(d, o, "nlb", 0, true, 1, UINT64_MAX, &st->nlb, e))
			return -1;
		if (!st->dev[0] && !st->block[0])
			return chain_bad(e, "invalid: an NVMe stage needs dev or block");
		break;
	case CH_AFXDP:
		if (chain_path(d, o, "ifname", true, st->ifname, sizeof(st->ifname), e) ||
		    chain_u32(d, o, "queue", 0, false, 0, 4095, &st->queue, e))
			return -1;
		break;
	case CH_IAA:
		if (cj_bool(d, o, "software", &st->software) < 0)
			return chain_bad(e, "invalid: software must be a boolean");
		if (chain_path(d, o, "dev", false, st->dev, sizeof(st->dev), e) ||
		    chain_u32(d, o, "capacity", 0, true, 1, 1U << 21, &st->capacity, e) ||
		    chain_u32(d, o, "expect", 0, false, 0, 1U << 21, &st->expect, e))
			return -1;
		if (st->expect > st->capacity)
			return chain_bad(e, "invalid: IAA expect exceeds capacity");
		if (!st->dev[0])
			snprintf(st->dev, sizeof(st->dev), "/dev/null");
		break;
	case CH_CE:
		break;
	}
	return 0;
}

static inline int chain_parse_oracle(const struct cj_doc *d, int o,
				     struct chain_spec *s, struct chain_err *e)
{
	static const char *const keys[] = { "kind", "path", "reference",
		"offset", "every_window", NULL };
	const char *bad = cj_unknown(d, o, keys);
	int kind;

	if (bad)
		return chain_bad(e, "invalid: unknown oracle member %s", bad);
	if (CHAIN_ENUM(d, o, "kind", -1, &kind, e, "none", "file", "ce-window"))
		return -1;
	s->oracle = (enum chain_oracle_kind)kind;
	if (s->oracle == CH_ORACLE_NONE)
		return 0;
	if (cj_bool(d, o, "every_window", &s->every_window) < 0)
		return chain_bad(e, "invalid: every_window must be a boolean");
	if (chain_path(d, o, "reference", true, s->reference,
		       sizeof(s->reference), e) ||
	    chain_u64(d, o, "offset", 0, false, 0, UINT64_MAX >> 1,
		      &s->oracle_offset, e))
		return -1;
	if (s->oracle == CH_ORACLE_FILE)
		return chain_path(d, o, "path", true, s->oracle_path,
				  sizeof(s->oracle_path), e);
	return 0;
}

/* Fill @s from the JSON text; the semantic checks are chain_validate(). */
static inline int chain_parse(const char *text, size_t len, struct chain_spec *s,
			      struct chain_err *e)
{
	static const char *const keys[] = { "schema", "chain", "arm", "mode",
		"group_bytes", "batches", "warmup", "burst", "depth",
		"start_per", "plan", "afxdp_mode", "timeout_ms", "seed", "pool",
		"ce", "peer", "plans", "stages", "oracle", "staged_gpu", "out",
		"load", "iaa_counts_pin", NULL };
	static const char *const pool_keys[] = { "frame_size", "hdr_room",
		"frames", "hugepage", NULL };
	static const char *const ce_keys[] = { "dev", "va", "len", "alloc",
		"bdf", NULL };
	static struct cj_doc doc;
	char schema[32];
	const char *bad;
	int root, o, x, m;

	memset(s, 0, sizeof(*s));
	root = cj_parse(&doc, text, len);
	if (root < 0)
		return chain_bad(e, "invalid: JSON at byte %zu: %s", doc.err_off,
				 doc.err);
	bad = cj_unknown(&doc, root, keys);
	if (bad)
		return chain_bad(e, "invalid: unknown member %s", bad);
	if (cj_str(&doc, root, "schema", schema, sizeof(schema)) ||
	    strcmp(schema, CHAIN_SCHEMA))
		return chain_bad(e, "invalid: schema must be %s", CHAIN_SCHEMA);
	if (chain_path(&doc, root, "chain", true, s->chain, sizeof(s->chain), e) ||
	    CHAIN_ENUM(&doc, root, "arm", -1, &x, e, "session", "staged"))
		return -1;
	s->arm = (enum chain_arm)x;
	if (CHAIN_ENUM(&doc, root, "mode", -1, &x, e, "correctness", "timing"))
		return -1;
	s->mode = (enum chain_mode)x;
	if (CHAIN_ENUM(&doc, root, "start_per", CH_START_BATCH, &x, e, "batch", "run"))
		return -1;
	s->start_per = (enum chain_start)x;
	if (CHAIN_ENUM(&doc, root, "load", CH_LOAD_CLOSED, &x, e, "closed", "sustained"))
		return -1;
	s->load = (enum chain_load)x;
	if (CHAIN_ENUM(&doc, root, "plan", CH_PLAN_BPF, &x, e, "bpf", "default"))
		return -1;
	s->plan = (enum chain_plan_kind)x;
	if (CHAIN_ENUM(&doc, root, "afxdp_mode", CH_XSK_ZC, &x, e, "zc", "copy"))
		return -1;
	s->xsk_mode = (enum chain_xsk_mode)x;
	if (CHAIN_ENUM(&doc, root, "staged_gpu", CH_GPU_NONE, &x, e, "none", "cuda",
		       "ce-sim"))
		return -1;
	s->gpu = (enum chain_gpu)x;
	if (chain_u32(&doc, root, "group_bytes", 0, true, 1, 1U << 30,
		      &s->group_bytes, e) ||
	    chain_u64(&doc, root, "batches", 0, true, 1, CHAIN_MAX_BATCHES,
		      &s->batches, e) ||
	    chain_u64(&doc, root, "warmup", 0, false, 0, CHAIN_MAX_BATCHES,
		      &s->warmup, e) ||
	    chain_u32(&doc, root, "burst", 1, false, 1, CHAIN_MAX_BATCHES,
		      &s->burst, e) ||
	    chain_u32(&doc, root, "depth", 0, true, 1, CHAIN_MAX_DEPTH,
		      &s->depth, e) ||
	    chain_u64(&doc, root, "timeout_ms", 30000, false, 1, 3600000,
		      &s->timeout_ms, e) ||
	    chain_u64(&doc, root, "seed", 1, false, 0, UINT64_MAX, &s->seed, e) ||
	    chain_path(&doc, root, "out", false, s->out, sizeof(s->out), e) ||
	    chain_path(&doc, root, "iaa_counts_pin", false, s->iaa_counts_pin,
		       sizeof(s->iaa_counts_pin), e))
		return -1;
	s->frame_size = 4096;
	s->oracle = CH_ORACLE_NONE;
	o = cj_get(&doc, root, "pool");
	if (o >= 0) {
		if (doc.n[o].type != CJ_OBJECT)
			return chain_bad(e, "invalid: pool must be an object");
		bad = cj_unknown(&doc, o, pool_keys);
		if (bad)
			return chain_bad(e, "invalid: unknown pool member %s", bad);
		if (chain_u32(&doc, o, "frame_size", 4096, false, 512, 1U << 21,
			      &s->frame_size, e) ||
		    chain_u32(&doc, o, "hdr_room", 0, false, 0, 1U << 20,
			      &s->hdr_room, e) ||
		    chain_u32(&doc, o, "frames", 0, false, 0, 1U << 24,
			      &s->pool_frames, e))
			return -1;
		if (cj_bool(&doc, o, "hugepage", &s->hugepage) < 0)
			return chain_bad(e, "invalid: hugepage must be a boolean");
	}
	o = cj_get(&doc, root, "ce");
	if (o >= 0) {
		char alloc[16] = "given";

		if (doc.n[o].type != CJ_OBJECT)
			return chain_bad(e, "invalid: ce must be an object");
		bad = cj_unknown(&doc, o, ce_keys);
		if (bad)
			return chain_bad(e, "invalid: unknown ce member %s", bad);
		if (chain_path(&doc, o, "dev", false, s->ce_dev, sizeof(s->ce_dev), e) ||
		    chain_path(&doc, o, "bdf", false, s->ce_bdf, sizeof(s->ce_bdf), e) ||
		    chain_u64(&doc, o, "va", 0, false, 0, UINT64_MAX, &s->ce_va, e) ||
		    chain_u64(&doc, o, "len", 0, true, 1, UINT64_MAX >> 1, &s->ce_len, e))
			return -1;
		if (cj_str(&doc, o, "alloc", alloc, sizeof(alloc)) < 0 ||
		    (strcmp(alloc, "given") && strcmp(alloc, "native")))
			return chain_bad(e, "invalid: ce.alloc must be given or native");
		s->ce_native = !strcmp(alloc, "native");
	}
	o = cj_get(&doc, root, "peer");
	if (o >= 0 && (doc.n[o].type != CJ_OBJECT || chain_parse_peer(&doc, o, s, e)))
		return e->msg[0] ? -1 : chain_bad(e, "invalid: peer must be an object");
	o = cj_get(&doc, root, "plans");
	if (o >= 0 && chain_parse_plans(&doc, o, s, e))
		return -1;
	o = cj_get(&doc, root, "oracle");
	if (o >= 0) {
		if (doc.n[o].type != CJ_OBJECT)
			return chain_bad(e, "invalid: oracle must be an object");
		if (chain_parse_oracle(&doc, o, s, e))
			return -1;
	}
	o = cj_get(&doc, root, "stages");
	if (o < 0 || doc.n[o].type != CJ_ARRAY || !doc.n[o].count)
		return chain_bad(e, "invalid: stages must be a non-empty array");
	if (doc.n[o].count > XDEV_EXT_MECH_MAX_STAGES)
		return chain_bad(e, "invalid: at most %u stages",
				 XDEV_EXT_MECH_MAX_STAGES);
	for (m = doc.n[o].child; m >= 0; m = doc.n[m].next) {
		if (doc.n[m].type != CJ_OBJECT)
			return chain_bad(e, "invalid: a stage must be an object");
		if (chain_parse_stage(&doc, m, &s->st[s->nr_stages++], e))
			return -1;
	}
	return 0;
}

/* --- validation ------------------------------------------------------- */

/*
 * The checks this runtime and the kernel's CREATE impose, in the order a
 * reader needs them: capability refusals first, so an impossible chain is
 * never reported as a malformed one.  0, or -1 with e->msg.
 */
static inline int chain_validate(const struct chain_spec *s, struct chain_err *e)
{
	const struct chain_catalog *c = strcmp(s->chain, "custom") ?
					chain_find(s->chain) : NULL;
	unsigned int i, ce = 0;
	bool xsk = chain_has(s, CH_AFXDP), iaa = chain_has(s, CH_IAA);

	if (strcmp(s->chain, "custom") && !c)
		return chain_bad(e, "invalid: unknown chain %s", s->chain);
	if (c && c->refusal)
		return chain_bad(e, "%s", c->refusal);
	if (s->plan == CH_PLAN_DEFAULT)
		return chain_bad(e, "%s", CHAIN_REFUSE_DEFAULT_PLAN);
	if (c) {
		if (s->nr_stages != c->nr)
			return chain_bad(e, "invalid: chain %s has %u stages, spec lists %u",
					 c->name, c->nr, s->nr_stages);
		for (i = 0; i < c->nr; i++)
			if (s->st[i].cls != c->cls[i] || s->st[i].dir != c->dir[i])
				return chain_bad(e, "invalid: stage %u does not match chain %s",
						 i, c->name);
	}
	if (s->arm == CH_STAGED && (!c || !c->staged))
		return chain_bad(e, "unsupported: the staged arm has no %s composition",
				 s->chain);
	if (s->arm == CH_STAGED && s->mode == CH_TIMING && !c->staged_timing)
		return chain_bad(e, "unsupported: staged %s has no device decompressor "
				 "(user-space IAA via QPL/accel-config is not implemented); "
				 "only its CPU-zlib correctness run exists", s->chain);
	if (xsk && iaa)
		return chain_bad(e, "%s", CHAIN_REFUSE_NIC_IAA);
	if (!((s->st[0].cls == CH_NVME && s->st[0].dir == CH_FROM) ||
	      chain_rx_first(s)))
		return chain_bad(e, "unsupported: stage 0 must be an NVMe READ or AF_XDP RX");
	for (i = 0; i < s->nr_stages; i++) {
		const struct chain_stage *st = &s->st[i];

		if (i && st->cls == CH_AFXDP && st->dir == CH_FROM)
			return chain_bad(e, "invalid: AF_XDP RX must be stage 0");
		if (i && st->cls == CH_NVME && st->dir == CH_FROM)
			return chain_bad(e, "invalid: an NVMe READ must be stage 0");
		if (i + 1 < s->nr_stages && st->cls == CH_AFXDP && st->dir == CH_TO)
			return chain_bad(e, "invalid: AF_XDP TX must be the last stage");
		if (st->cls == CH_NVME && s->arm == CH_SESSION && !st->dev[0])
			return chain_bad(e, "invalid: session NVMe stage %u needs dev (ngXnY)", i);
		if (st->cls == CH_NVME && s->arm == CH_STAGED && !st->block[0])
			return chain_bad(e, "invalid: staged NVMe stage %u needs block", i);
		if (st->cls == CH_IAA && st->dir == CH_FROM && st->expect == 0 &&
		    s->oracle != CH_ORACLE_NONE)
			return chain_bad(e, "invalid: an IAA decompress stage checked by an oracle needs expect");
		/* xdev_ext_iaa_bind (arg1) and xdev_ext_iaa_validate (src_len). */
		if (st->cls == CH_IAA &&
		    (st->capacity > CHAIN_IAA_MAX || s->group_bytes > CHAIN_IAA_MAX))
			return chain_bad(e, "unsupported: IAA stage %u: deflate takes at most "
					 "CRYPTO_ACOMP_DST_MAX = %u bytes of source and of destination "
					 "per batch (group_bytes %u, capacity %u); split a larger "
					 "record into a burst of groups", i, CHAIN_IAA_MAX,
					 s->group_bytes, st->capacity);
		if (st->cls == CH_IAA && st->software && s->mode == CH_TIMING)
			return chain_bad(e, "unsupported: IAA stage %u uses deflate-generic, a CPU "
					 "stand-in; timing needs deflate-iaa", i);
		if (st->cls == CH_IAA && st->capacity > s->group_bytes &&
		    i + 1 < s->nr_stages && s->st[i + 1].cls == CH_CE)
			return chain_bad(e, "unsupported: CE copies stay inside one group_bytes window "
					 "slot, so IAA output above group_bytes (%u > %u) cannot reach the GPU",
					 st->capacity, s->group_bytes);
		ce += st->cls == CH_CE;
	}
	if (s->nr_stages < 2 && chain_rx_first(s))
		return chain_bad(e, "invalid: AF_XDP RX feeds at least one more stage");
	if (ce && s->arm == CH_SESSION && !s->ce_dev[0])
		return chain_bad(e, "invalid: CE stages need ce.dev");
	if (ce && s->arm == CH_SESSION &&
	    !xdev_ext_mech_ctl_ce_window_ok(s->depth, s->group_bytes, s->ce_len))
		return chain_bad(e, "invalid: ce.len must hold depth x group_bytes window slots");
	if (ce && s->arm == CH_STAGED && s->gpu == CH_GPU_NONE)
		return chain_bad(e, "unsupported: staged GPU leg needs staged_gpu cuda or ce-sim");
	if (s->arm == CH_STAGED && s->gpu == CH_GPU_CE_SIM && !s->ce_dev[0])
		return chain_bad(e, "invalid: staged_gpu ce-sim needs ce.dev");
	if (s->arm == CH_STAGED && s->gpu == CH_GPU_CUDA && !s->ce_bdf[0])
		return chain_bad(e, "invalid: staged_gpu cuda needs ce.bdf");
	if (xsk && !s->nxp_session)
		return chain_bad(e, "invalid: NIC stages need peer");
	if (s->start_per == CH_START_BATCH &&
	    (s->batches % s->burst || s->warmup % s->burst))
		return chain_bad(e, "invalid: batches and warmup must be multiples of burst");
	if (chain_rx_first(s) && s->start_per == CH_START_RUN)
		return chain_bad(e, "invalid: an AF_XDP RX chain has no START; use start_per batch");
	if (s->load == CH_LOAD_SUSTAINED && s->start_per == CH_START_RUN)
		return chain_bad(e, "invalid: start_per run is a closed-load option; the sustained "
				 "load issues one START for the whole campaign");
	if (s->load == CH_LOAD_SUSTAINED && s->every_window)
		return chain_bad(e, "invalid: every_window needs the closed load (no window "
				 "boundaries in a sustained run)");
	if (s->mode == CH_TIMING && s->every_window)
		return chain_bad(e, "invalid: every_window checks bytes between windows; correctness mode only");
	if (s->oracle == CH_ORACLE_CE && (!ce || s->st[s->nr_stages - 1].cls != CH_CE))
		return chain_bad(e, "invalid: a ce-window oracle needs a final CE stage");
	if (s->oracle == CH_ORACLE_CE && s->every_window && s->burst != 1)
		return chain_bad(e, "invalid: every_window needs burst 1 (a slot may be reused inside a window)");
	if (s->mode == CH_TIMING && s->xsk_mode == CH_XSK_COPY && !xsk)
		return chain_bad(e, "invalid: afxdp_mode copy without an AF_XDP stage");
	if (s->mode == CH_TIMING && ce && strstr(s->ce_dev, "xdev_ext_ce_sim"))
		return chain_bad(e, "unsupported: the CE simulator is a CPU memcpy stand-in; "
				 "timing needs a physical GPU");
	if (s->mode == CH_TIMING && s->gpu == CH_GPU_CE_SIM)
		return chain_bad(e, "unsupported: staged_gpu ce-sim is a CPU stand-in; "
				 "timing needs a physical GPU");
	return 0;
}

/* --- layout ------------------------------------------------------------- */

/*
 * io_uring UMEM pool of a chain without AF_XDP: per batch @src frames at
 * [0, depth * src); every IAA stage reserves depth * ceil(capacity /
 * seg_len) destination frames after that, its first frame in iaa_first[].
 */
struct chain_iou_plan {
	struct xdev_ext_mech_layout l;
	uint32_t src_frames;		/* frames per source batch */
	uint32_t lend_frames;		/* frames one START lends */
	uint32_t pool_frames;
	uint32_t iaa_first[XDEV_EXT_MECH_MAX_STAGES];
};

static inline int chain_iou_layout(const struct chain_spec *s,
				   struct chain_iou_plan *p, struct chain_err *e)
{
	uint64_t next, lend;
	unsigned int i;
	int nr;

	memset(p, 0, sizeof(*p));
	if (s->frame_size & (s->frame_size - 1))
		return chain_bad(e, "invalid: pool.frame_size must be a power of two");
	if (s->hdr_room % 8 || s->hdr_room >= s->frame_size)
		return chain_bad(e, "invalid: pool.hdr_room must be 8-byte aligned and below frame_size");
	p->l = (struct xdev_ext_mech_layout){
		.frame_size = s->frame_size, .hdr_room = s->hdr_room,
		.seg_len = s->frame_size - s->hdr_room, .group_bytes = s->group_bytes,
	};
	nr = xdev_ext_mech_layout_frames(&p->l);
	if (nr < 0)
		return chain_bad(e, "invalid: group_bytes %u needs more than %u frames of %u bytes",
				 s->group_bytes, XDEV_EXT_MECH_MAX_FRAMES, p->l.seg_len);
	p->src_frames = (uint32_t)nr;
	lend = chain_start_batches(s);
	if (lend > s->depth)
		lend = s->depth;
	p->lend_frames = (uint32_t)lend * p->src_frames;
	next = (uint64_t)s->depth * p->src_frames;
	for (i = 0; i < s->nr_stages; i++) {
		uint64_t dst;

		if (s->st[i].cls != CH_IAA)
			continue;
		dst = (s->st[i].capacity + p->l.seg_len - 1) / p->l.seg_len;
		if (dst > XDEV_EXT_MECH_MAX_FRAMES)
			return chain_bad(e, "invalid: IAA capacity needs more than %u frames",
					 XDEV_EXT_MECH_MAX_FRAMES);
		p->iaa_first[i] = (uint32_t)next;
		next += (uint64_t)s->depth * dst;
	}
	if (s->pool_frames && s->pool_frames < next)
		return chain_bad(e, "invalid: pool.frames %u below the %llu frames this chain needs",
				 s->pool_frames, (unsigned long long)next);
	if (s->pool_frames)
		next = s->pool_frames;
	if (next * s->frame_size > (1ULL << 36))
		return chain_bad(e, "invalid: pool above 64 GiB");
	p->pool_frames = (uint32_t)next;
	return 0;
}

/* NVMe window: every batch of the run has its own group of LBAs. */
static inline int chain_nvme_window_ok(const struct chain_stage *st,
				       uint32_t lba_bytes, uint32_t group_bytes,
				       uint64_t batches)
{
	uint64_t lbas;

	if (!lba_bytes || group_bytes % lba_bytes)
		return -EINVAL;
	lbas = group_bytes / lba_bytes;
	return batches > st->nlb / lbas ? -ERANGE : 0;
}

/*
 * The CREATE stage list.  fds[i] is stage i's opened device (NVMe ng, CE
 * device, IAA token); AF_XDP stages take @xsk_fd.  @ce_va is the window the
 * CE stages share; @iaa_first the IAA destination frames of chain_iou_layout.
 */
static inline void chain_stage_uapi(const struct chain_spec *s, const int *fds,
				    int xsk_fd, uint64_t ce_va,
				    const uint32_t *iaa_first,
				    struct xdev_ext_mech_stage_uapi *out)
{
	unsigned int i;

	memset(out, 0, XDEV_EXT_MECH_MAX_STAGES * sizeof(*out));
	for (i = 0; i < s->nr_stages; i++) {
		const struct chain_stage *st = &s->st[i];
		struct xdev_ext_mech_stage_uapi *u = &out[i];

		u->direction = st->dir == CH_TO ? XDEV_EXT_MECH_DIR_TO_DEVICE :
						  XDEV_EXT_MECH_DIR_FROM_DEVICE;
		u->fd = fds[i];
		switch (st->cls) {
		case CH_NVME:
			u->class_id = XDEV_EXT_MECH_CLASS_NVME;
			u->arg0 = st->slba;
			u->arg1 = st->nlb;
			break;
		case CH_CE:
			u->class_id = XDEV_EXT_MECH_CLASS_CE;
			u->arg0 = ce_va;
			u->arg1 = s->ce_len;
			break;
		case CH_AFXDP:
			u->class_id = XDEV_EXT_MECH_CLASS_AFXDP;
			u->fd = xsk_fd;
			break;
		case CH_IAA:
			u->class_id = XDEV_EXT_MECH_CLASS_IAA;
			u->flags = st->software ? XDEV_EXT_IAA_F_SOFTWARE : 0;
			u->arg0 = iaa_first[i];
			u->arg1 = st->capacity;
			break;
		}
	}
}

#endif /* CHAIN_SPEC_H */
