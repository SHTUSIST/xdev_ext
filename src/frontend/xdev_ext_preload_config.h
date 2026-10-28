/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_CONFIG_H
#define XDEV_EXT_PRELOAD_CONFIG_H

/*
 * Configuration snapshot for io_uring_unified_preload.c.  The constructor
 * parses the environment once, through a view that tests replace, and the
 * front end never reads it again.  Nothing here performs I/O: resolving
 * XDEV_EXT_PRELOAD_PATHS into the allowlist belongs to the export layer and runs
 * right after the parse.
 *
 * Fail-closed rules:
 *  - Without a master switch (XDEV_EXT_PRELOAD_ENABLED=1,
 *    XDEV_EXT_PRELOAD_SOCKET_ENABLED=1 or a non-empty XDEV_EXT_PRELOAD_RX) no other
 *    variable is read, so a stray knob cannot affect an inert process.
 *  - With one, every knob added for the transparent front end must be spelled
 *    exactly.  Anything else returns -EINVAL with error_var naming it, and the
 *    whole configuration is inert.
 *  - The switches that predate this parser keep their lenient spellings:
 *    anything but "1" is off, and an unusable XDEV_EXT_PRELOAD_FRAME_SIZE means
 *    the default.
 *  - A variable that is set but empty reads as unset.
 */
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "xdev_ext_preload_config_backend.h"

#define XDEV_EXT_PRELOAD_DEFAULT_FRAME_SIZE 4096U
#define XDEV_EXT_PRELOAD_MAX_FRAME_SIZE (1U << 20)
#define XDEV_EXT_CFG_MAX_RX_FLOWS 8U
#define XDEV_EXT_CFG_IFNAMSIZ 16U
#define XDEV_EXT_CFG_DEFAULT_RX_FRAMES 1024U
#define XDEV_EXT_CFG_MIN_RX_FRAMES 64U
#define XDEV_EXT_CFG_MAX_RX_FRAMES 16384U

/* get() returns the value of name or NULL; the parser copies what it keeps. */
struct xdev_ext_env_view {
	const char *(*get)(const struct xdev_ext_env_view *view, const char *name);
	const void *opaque;
	long page_size;
};

struct xdev_ext_allow_entry {
	char *path;
	dev_t dev;
	ino_t ino;
};

enum xdev_ext_cfg_rx_mode {
	XDEV_EXT_CFG_RX_MODE_AUTO,	/* driver mode, then skb mode */
	XDEV_EXT_CFG_RX_MODE_DRV,
	XDEV_EXT_CFG_RX_MODE_SKB,
};

enum xdev_ext_cfg_rx_fork {
	XDEV_EXT_CFG_RX_FORK_RELEASE,	/* new datagrams go back to the kernel */
	XDEV_EXT_CFG_RX_FORK_KEEP,		/* the parent keeps the fast path */
};

enum xdev_ext_cfg_write_sink {
	XDEV_EXT_CFG_WRITE_SINK_AUTO,
	XDEV_EXT_CFG_WRITE_SINK_PASSTHRU,	/* XDEV_EXT_CFG_SPELLING_SINK_PASSTHRU */
	XDEV_EXT_CFG_WRITE_SINK_UNIFIED,	/* direct sub-operations (phase two) */
	XDEV_EXT_CFG_WRITE_SINK_COMPAT,
	XDEV_EXT_CFG_WRITE_SINK_LIBC,
};

enum xdev_ext_cfg_iopath {
	XDEV_EXT_CFG_IOPATH_DEFAULT,		/* not given: the build's default */
	XDEV_EXT_CFG_IOPATH_DIRECT,
	XDEV_EXT_CFG_IOPATH_COMPAT,
};

enum xdev_ext_cfg_identity {
	XDEV_EXT_CFG_IDENTITY_PER_CALL,
	XDEV_EXT_CFG_IDENTITY_LIFECYCLE,
};

enum xdev_ext_cfg_bdev_cache {
	XDEV_EXT_CFG_BDEV_COHERENT,
	XDEV_EXT_CFG_BDEV_EXCLUSIVE,
};

/* One XDEV_EXT_PRELOAD_RX item: <interface>/<queue>/<a.b.c.d>:<port>. */
struct xdev_ext_cfg_rx_flow {
	char ifname[XDEV_EXT_CFG_IFNAMSIZ];
	uint32_t queue;
	struct in_addr addr;		/* network byte order */
	uint16_t port;			/* host byte order */
};

struct xdev_ext_config {
	/* Switches that predate the snapshot; unchanged meaning. */
	bool enabled;			/* file takeover; cleared if no path resolves */
	bool socket_enabled;
	bool report;
	size_t frame_size;
	char *paths;			/* owned copy of XDEV_EXT_PRELOAD_PATHS */
	struct xdev_ext_allow_entry *allow;	/* filled by the export layer */
	size_t nr_allow;

	/*
	 * armed: at least one takeover path is configured.  error and
	 * error_var hold the first reason the snapshot is not as requested;
	 * with armed set it is a note about a lenient switch, not a failure.
	 */
	bool armed;
	bool verbose;
	bool require_armed;
	int error;
	const char *error_var;		/* static string, NULL when error is 0 */

	unsigned int rx_nflows;
	struct xdev_ext_cfg_rx_flow rx_flows[XDEV_EXT_CFG_MAX_RX_FLOWS];
	uint32_t rx_frames;
	enum xdev_ext_cfg_rx_mode rx_mode;
	enum xdev_ext_cfg_rx_fork rx_fork;
	enum xdev_ext_cfg_write_sink write_sink;
	enum xdev_ext_cfg_iopath iopath;
	enum xdev_ext_cfg_identity identity;
	enum xdev_ext_cfg_bdev_cache bdev_cache;

	/* Read only by builds with XDEV_EXT_PRELOAD_TEST_HOOKS. */
	char *test_sysfs_root;
	char *test_ns_map_path;
	uint32_t test_ns_map_nsid;
	uint8_t test_ns_map_lba_shift;
};

struct xdev_ext_cfg_choice {
	const char *spelling;
	int value;
};

static inline const char *xdev_ext_cfg_get(const struct xdev_ext_env_view *env,
				      const char *name)
{
	const char *value = env->get(env, name);

	return value && *value ? value : NULL;
}

static inline bool xdev_ext_cfg_is_one(const char *value)
{
	return value && !strcmp(value, "1");
}

/* Canonical decimal only: no sign, blank or leading zero. */
static inline bool xdev_ext_cfg_parse_u32(const char *text, size_t length,
				     uint32_t max, uint32_t *out)
{
	uint64_t value = 0;

	if (!length || (length > 1 && text[0] == '0'))
		return false;
	for (size_t i = 0; i < length; i++) {
		if (text[i] < '0' || text[i] > '9')
			return false;
		value = value * 10 + (uint64_t)(text[i] - '0');
		if (value > max)
			return false;
	}
	*out = (uint32_t)value;
	return true;
}

static inline bool xdev_ext_cfg_parse_ipv4(const char *text, size_t length,
				      struct in_addr *out)
{
	uint32_t octet[4];
	unsigned int count = 0;
	size_t start = 0;

	for (size_t i = 0; i <= length; i++) {
		if (i < length && text[i] != '.')
			continue;
		if (count == 4 ||
		    !xdev_ext_cfg_parse_u32(text + start, i - start, 255,
				       &octet[count]))
			return false;
		count++;
		start = i + 1;
	}
	if (count != 4)
		return false;
	out->s_addr = htonl(octet[0] << 24 | octet[1] << 16 | octet[2] << 8 |
			    octet[3]);
	return true;
}

/*
 * The kernel's dev_valid_name() also allows non-ASCII bytes; refusing them
 * here only means such an interface is never taken over.
 */
static inline bool xdev_ext_cfg_valid_ifname(const char *text, size_t length)
{
	if (!length || length >= XDEV_EXT_CFG_IFNAMSIZ)
		return false;
	if ((length == 1 && text[0] == '.') ||
	    (length == 2 && text[0] == '.' && text[1] == '.'))
		return false;
	for (size_t i = 0; i < length; i++) {
		unsigned char c = (unsigned char)text[i];

		if (c <= ' ' || c >= 0x7f || c == '/' || c == ':')
			return false;
	}
	return true;
}

static inline bool xdev_ext_cfg_parse_flow(const char *item, size_t length,
				      struct xdev_ext_cfg_rx_flow *flow)
{
	const char *end = item + length;
	const char *slash1 = memchr(item, '/', length);
	const char *slash2;
	const char *colon = NULL;
	uint32_t port;

	if (!slash1)
		return false;
	slash2 = memchr(slash1 + 1, '/', (size_t)(end - slash1 - 1));
	if (!slash2)
		return false;
	for (const char *p = end; p > slash2 + 1; p--) {
		if (p[-1] == ':') {
			colon = p - 1;
			break;
		}
	}
	memset(flow, 0, sizeof(*flow));
	if (!colon ||
	    !xdev_ext_cfg_valid_ifname(item, (size_t)(slash1 - item)) ||
	    !xdev_ext_cfg_parse_u32(slash1 + 1, (size_t)(slash2 - slash1 - 1),
			       UINT32_MAX, &flow->queue) ||
	    !xdev_ext_cfg_parse_ipv4(slash2 + 1, (size_t)(colon - slash2 - 1),
				&flow->addr) ||
	    !xdev_ext_cfg_parse_u32(colon + 1, (size_t)(end - colon - 1), 65535,
			       &port) || !port)
		return false;
	/* The flow filter matches one destination address. */
	if (flow->addr.s_addr == htonl(INADDR_ANY))
		return false;
	memcpy(flow->ifname, item, (size_t)(slash1 - item));
	flow->port = (uint16_t)port;
	return true;
}

static inline int xdev_ext_cfg_parse_flows(const char *text, struct xdev_ext_config *cfg)
{
	const char *item = text;

	for (;;) {
		const char *comma = strchr(item, ',');
		size_t length = comma ? (size_t)(comma - item) : strlen(item);
		struct xdev_ext_cfg_rx_flow flow;

		if (cfg->rx_nflows == XDEV_EXT_CFG_MAX_RX_FLOWS ||
		    !xdev_ext_cfg_parse_flow(item, length, &flow))
			return -EINVAL;
		/* A bound address and port must select exactly one flow. */
		for (unsigned int i = 0; i < cfg->rx_nflows; i++) {
			if (cfg->rx_flows[i].addr.s_addr == flow.addr.s_addr &&
			    cfg->rx_flows[i].port == flow.port)
				return -EINVAL;
		}
		cfg->rx_flows[cfg->rx_nflows++] = flow;
		if (!comma)
			return 0;
		item = comma + 1;
	}
}

/* Unset keeps *value; a spelling outside choices is -EINVAL. */
static inline int xdev_ext_cfg_choose(const struct xdev_ext_env_view *env,
				 const char *var,
				 const struct xdev_ext_cfg_choice *choices,
				 size_t count, int *value)
{
	const char *text = xdev_ext_cfg_get(env, var);

	if (!text)
		return 0;
	for (size_t i = 0; i < count; i++) {
		if (!strcmp(text, choices[i].spelling)) {
			*value = choices[i].value;
			return 0;
		}
	}
	return -EINVAL;
}

static inline int xdev_ext_cfg_flag(const struct xdev_ext_env_view *env, const char *var,
			       bool *flag)
{
	static const struct xdev_ext_cfg_choice flags[] = {
		{ "0", 0 },
		{ "1", 1 },
	};
	int value = *flag;
	int ret;

	ret = xdev_ext_cfg_choose(env, var, flags, sizeof(flags) / sizeof(flags[0]),
			     &value);
	*flag = value;
	return ret;
}

/* The existing XDEV_EXT_PRELOAD_FRAME_SIZE rule, kept silent on bad values. */
static inline size_t xdev_ext_cfg_frame_size(const char *text, long page_size,
					size_t fallback)
{
	unsigned long parsed;
	char *end = NULL;
	int saved_errno = errno;

	if (!text)
		return fallback;
	errno = 0;
	parsed = strtoul(text, &end, 0);
	if (errno || !end || *end || page_size <= 0 ||
	    parsed < (unsigned long)page_size ||
	    parsed > XDEV_EXT_PRELOAD_MAX_FRAME_SIZE || (parsed & (parsed - 1)))
		parsed = fallback;
	errno = saved_errno;
	return parsed;
}

static inline void xdev_ext_cfg_free_owned(struct xdev_ext_config *cfg)
{
	for (size_t i = 0; i < cfg->nr_allow; i++)
		free(cfg->allow[i].path);
	free(cfg->allow);
	free(cfg->paths);
	free(cfg->test_sysfs_root);
	free(cfg->test_ns_map_path);
	cfg->allow = NULL;
	cfg->nr_allow = 0;
	cfg->paths = NULL;
	cfg->test_sysfs_root = NULL;
	cfg->test_ns_map_path = NULL;
}

static inline void xdev_ext_preload_config_update_armed(struct xdev_ext_config *cfg)
{
	cfg->armed = cfg->enabled || cfg->socket_enabled || cfg->rx_nflows;
}

/* Record a reason without changing what is armed; the first one wins. */
static inline void xdev_ext_preload_config_note(struct xdev_ext_config *cfg, int error,
					   const char *var)
{
	if (cfg->error)
		return;
	cfg->error = error;
	cfg->error_var = var;
}

/*
 * Make the whole snapshot inert and record why.  The output switches
 * (report, verbose, require_armed) survive so that the reason is printed.
 */
static inline void xdev_ext_preload_config_disarm(struct xdev_ext_config *cfg, int error,
					     const char *var)
{
	xdev_ext_cfg_free_owned(cfg);
	cfg->enabled = false;
	cfg->socket_enabled = false;
	cfg->rx_nflows = 0;
	cfg->armed = false;
	cfg->error = error;
	cfg->error_var = var;
}

static inline int xdev_ext_cfg_fail(struct xdev_ext_config *cfg, int error,
			       const char *var)
{
	xdev_ext_preload_config_disarm(cfg, error, var);
	return error;
}

#ifdef XDEV_EXT_PRELOAD_TEST_HOOKS
/* <absolute regular file>:<nsid>:<lba_shift>; the path may contain ':'. */
static inline int xdev_ext_cfg_parse_ns_map(const char *text, struct xdev_ext_config *cfg)
{
	const char *shift = strrchr(text, ':');
	const char *nsid = NULL;
	uint32_t value;

	if (!shift)
		return -EINVAL;
	for (const char *p = shift; p > text; p--) {
		if (p[-1] == ':') {
			nsid = p - 1;
			break;
		}
	}
	if (!nsid || nsid == text || text[0] != '/' ||
	    !xdev_ext_cfg_parse_u32(nsid + 1, (size_t)(shift - nsid - 1),
			       UINT32_MAX - 1, &cfg->test_ns_map_nsid) ||
	    !cfg->test_ns_map_nsid ||
	    !xdev_ext_cfg_parse_u32(shift + 1, strlen(shift + 1), 12, &value) ||
	    value < 9)
		return -EINVAL;
	cfg->test_ns_map_lba_shift = (uint8_t)value;
	cfg->test_ns_map_path = strndup(text, (size_t)(nsid - text));
	return cfg->test_ns_map_path ? 0 : -ENOMEM;
}

static inline int xdev_ext_cfg_parse_test_hooks(const struct xdev_ext_env_view *env,
					   struct xdev_ext_config *cfg)
{
	const char *root = xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_TEST_SYSFS_ROOT");
	const char *map = xdev_ext_cfg_get(env, XDEV_EXT_CFG_VAR_TEST_NS_MAP);
	int ret;

	if (root) {
		if (root[0] != '/')
			return xdev_ext_cfg_fail(cfg, -EINVAL,
					    "XDEV_EXT_PRELOAD_TEST_SYSFS_ROOT");
		cfg->test_sysfs_root = strdup(root);
		if (!cfg->test_sysfs_root)
			return xdev_ext_cfg_fail(cfg, -ENOMEM,
					    "XDEV_EXT_PRELOAD_TEST_SYSFS_ROOT");
	}
	if (map) {
		ret = xdev_ext_cfg_parse_ns_map(map, cfg);
		if (ret)
			return xdev_ext_cfg_fail(cfg, ret, XDEV_EXT_CFG_VAR_TEST_NS_MAP);
	}
	return 0;
}
#endif

/*
 * Fill *cfg from env.  *cfg must be zeroed or released; the snapshot owns
 * copies of every string it keeps.  Returns 0 (also for an inert process)
 * or the negative errno that made the snapshot inert.
 */
static inline int xdev_ext_preload_config_parse(const struct xdev_ext_env_view *env,
					   struct xdev_ext_config *cfg)
{
	static const struct xdev_ext_cfg_choice rx_modes[] = {
		{ "auto", XDEV_EXT_CFG_RX_MODE_AUTO },
		{ "drv", XDEV_EXT_CFG_RX_MODE_DRV },
		{ "skb", XDEV_EXT_CFG_RX_MODE_SKB },
	};
	static const struct xdev_ext_cfg_choice rx_forks[] = {
		{ "release", XDEV_EXT_CFG_RX_FORK_RELEASE },
		{ "keep", XDEV_EXT_CFG_RX_FORK_KEEP },
	};
	static const struct xdev_ext_cfg_choice write_sinks[] = {
		{ "auto", XDEV_EXT_CFG_WRITE_SINK_AUTO },
		{ XDEV_EXT_CFG_SPELLING_SINK_PASSTHRU, XDEV_EXT_CFG_WRITE_SINK_PASSTHRU },
		{ "unified", XDEV_EXT_CFG_WRITE_SINK_UNIFIED },
		{ "compat", XDEV_EXT_CFG_WRITE_SINK_COMPAT },
		{ "libc", XDEV_EXT_CFG_WRITE_SINK_LIBC },
	};
	static const struct xdev_ext_cfg_choice iopaths[] = {
		{ "direct", XDEV_EXT_CFG_IOPATH_DIRECT },
		{ "compat", XDEV_EXT_CFG_IOPATH_COMPAT },
	};
	static const struct xdev_ext_cfg_choice identities[] = {
		{ "per-call", XDEV_EXT_CFG_IDENTITY_PER_CALL },
		{ "lifecycle", XDEV_EXT_CFG_IDENTITY_LIFECYCLE },
	};
	static const struct xdev_ext_cfg_choice caches[] = {
		{ "coherent", XDEV_EXT_CFG_BDEV_COHERENT },
		{ "exclusive", XDEV_EXT_CFG_BDEV_EXCLUSIVE },
	};
#define XDEV_EXT_CFG_CHOOSE(var, table, field) do {				\
	int _value = (int)cfg->field;					\
									\
	if (xdev_ext_cfg_choose(env, var, table,				\
			   sizeof(table) / sizeof(table[0]), &_value))	\
		return xdev_ext_cfg_fail(cfg, -EINVAL, var);			\
	cfg->field = _value;						\
} while (0)
	const char *rx;
	const char *text;
	uint32_t frames;
	int verbose_ret;
	int require_ret;

	memset(cfg, 0, sizeof(*cfg));
	cfg->frame_size = XDEV_EXT_PRELOAD_DEFAULT_FRAME_SIZE;
	if (env->page_size > 0 && (size_t)env->page_size > cfg->frame_size)
		cfg->frame_size = (size_t)env->page_size;
	cfg->rx_frames = XDEV_EXT_CFG_DEFAULT_RX_FRAMES;

	cfg->enabled = xdev_ext_cfg_is_one(xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_ENABLED"));
	cfg->socket_enabled =
		xdev_ext_cfg_is_one(xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED"));
	rx = xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_RX");
	if (!cfg->enabled && !cfg->socket_enabled && !rx)
		return 0;

	/* Output switches first, so that any later error is reported. */
	cfg->report = xdev_ext_cfg_is_one(xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_REPORT"));
	verbose_ret = xdev_ext_cfg_flag(env, "XDEV_EXT_PRELOAD_VERBOSE", &cfg->verbose);
	require_ret = xdev_ext_cfg_flag(env, "XDEV_EXT_PRELOAD_REQUIRE_ARMED",
				   &cfg->require_armed);
	if (verbose_ret)
		return xdev_ext_cfg_fail(cfg, verbose_ret, "XDEV_EXT_PRELOAD_VERBOSE");
	if (require_ret)
		return xdev_ext_cfg_fail(cfg, require_ret,
				    "XDEV_EXT_PRELOAD_REQUIRE_ARMED");

	cfg->frame_size =
		xdev_ext_cfg_frame_size(xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_FRAME_SIZE"),
				   env->page_size, cfg->frame_size);
	if (rx && xdev_ext_cfg_parse_flows(rx, cfg))
		return xdev_ext_cfg_fail(cfg, -EINVAL, "XDEV_EXT_PRELOAD_RX");
	text = xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_RX_FRAMES");
	if (text) {
		if (!xdev_ext_cfg_parse_u32(text, strlen(text),
				       XDEV_EXT_CFG_MAX_RX_FRAMES, &frames) ||
		    frames < XDEV_EXT_CFG_MIN_RX_FRAMES || (frames & (frames - 1)))
			return xdev_ext_cfg_fail(cfg, -EINVAL,
					    "XDEV_EXT_PRELOAD_RX_FRAMES");
		cfg->rx_frames = frames;
	}
	XDEV_EXT_CFG_CHOOSE(XDEV_EXT_CFG_VAR_RX_ATTACH_MODE, rx_modes, rx_mode);
	XDEV_EXT_CFG_CHOOSE("XDEV_EXT_PRELOAD_RX_FORK", rx_forks, rx_fork);
	XDEV_EXT_CFG_CHOOSE("XDEV_EXT_PRELOAD_WRITE_SINK", write_sinks, write_sink);
	XDEV_EXT_CFG_CHOOSE("XDEV_EXT_PRELOAD_IOPATH", iopaths, iopath);
	XDEV_EXT_CFG_CHOOSE("XDEV_EXT_PRELOAD_IDENTITY", identities, identity);
	XDEV_EXT_CFG_CHOOSE("XDEV_EXT_PRELOAD_BDEV_CACHE", caches, bdev_cache);
#undef XDEV_EXT_CFG_CHOOSE
#ifdef XDEV_EXT_PRELOAD_TEST_HOOKS
	if (xdev_ext_cfg_parse_test_hooks(env, cfg))
		return cfg->error;
#endif

	if (cfg->enabled) {
		text = xdev_ext_cfg_get(env, "XDEV_EXT_PRELOAD_PATHS");
		if (!text) {
			cfg->enabled = false;
			xdev_ext_preload_config_note(cfg, -ENOENT,
						"XDEV_EXT_PRELOAD_PATHS");
		} else {
			cfg->paths = strdup(text);
			if (!cfg->paths)
				return xdev_ext_cfg_fail(cfg, -ENOMEM,
						    "XDEV_EXT_PRELOAD_PATHS");
		}
	}
	xdev_ext_preload_config_update_armed(cfg);
	return 0;
}

static inline void xdev_ext_preload_config_release(struct xdev_ext_config *cfg)
{
	xdev_ext_cfg_free_owned(cfg);
}

/* XDEV_EXT_PRELOAD_REQUIRE_ARMED=1: a run that takes nothing over must not pass. */
static inline bool xdev_ext_preload_config_must_abort(const struct xdev_ext_config *cfg)
{
	return cfg->require_armed && (cfg->error || !cfg->armed);
}

/* One XDEV_EXT_PRELOAD_CONFIG line; -ENOSPC when buf is too small. */
static inline int xdev_ext_preload_config_format(const struct xdev_ext_config *cfg,
					    char *buf, size_t size)
{
	char number[16];
	const char *error;
	int length;

	switch (-cfg->error) {
	case 0:
		error = "none";
		break;
	case EINVAL:
		error = "EINVAL";
		break;
	case ENOENT:
		error = "ENOENT";
		break;
	case ENOMEM:
		error = "ENOMEM";
		break;
	default:
		snprintf(number, sizeof(number), "%d", -cfg->error);
		error = number;
		break;
	}
	length = snprintf(buf, size, "XDEV_EXT_PRELOAD_CONFIG state=%s error=%s "
			  "var=%s\n", cfg->armed ? "armed" : "inert", error,
			  cfg->error_var ? cfg->error_var : "none");
	if (length < 0 || (size_t)length >= size)
		return -ENOSPC;
	return length;
}

#endif /* XDEV_EXT_PRELOAD_CONFIG_H */
