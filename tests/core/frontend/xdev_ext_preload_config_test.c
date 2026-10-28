// SPDX-License-Identifier: GPL-2.0
/*
 * The front end snapshots its configuration once, in a constructor.  The
 * parser is pure: it reads the environment through an injected view, so every
 * accepted and rejected spelling is checked here without touching the real
 * environment.  When run_tests exports XDEV_EXT_PRELOAD_TEST_DIR, the built front
 * end is also loaded into a child process to check the XDEV_EXT_PRELOAD_CONFIG
 * line and the XDEV_EXT_PRELOAD_REQUIRE_ARMED abort.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "xdev_ext_preload_config.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr) do {                                           \
	checks++;                                                          \
	if (!(expr)) {                                                     \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",       \
			__FILE__, __LINE__, #expr);                           \
		failures++;                                               \
	}                                                                  \
} while (0)

#define EXPECT_EQ(actual, expected) do {                                \
	long long _actual = (long long)(actual);                          \
	long long _expected = (long long)(expected);                      \
	checks++;                                                          \
	if (_actual != _expected) {                                       \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",       \
			__FILE__, __LINE__, #actual, _actual, _expected);      \
		failures++;                                               \
	}                                                                  \
} while (0)

#define EXPECT_STR(actual, expected) do {                               \
	const char *_actual = (actual);                                   \
	const char *_expected = (expected);                               \
	checks++;                                                          \
	if (!_actual || !_expected ? _actual != _expected :              \
	    strcmp(_actual, _expected)) {                                  \
		fprintf(stderr, "%s:%d: %s=\"%s\", expected \"%s\"\n",   \
			__FILE__, __LINE__, #actual,                          \
			_actual ? _actual : "(null)",                         \
			_expected ? _expected : "(null)");                    \
		failures++;                                               \
	}                                                                  \
} while (0)

#define FAKE_ENV_MAX 24

struct fake_env {
	unsigned int count;
	const char *name[FAKE_ENV_MAX];
	const char *value[FAKE_ENV_MAX];
};

static const char *fake_get(const struct xdev_ext_env_view *view, const char *name)
{
	const struct fake_env *env = view->opaque;

	for (unsigned int i = 0; i < env->count; i++) {
		if (!strcmp(env->name[i], name))
			return env->value[i];
	}
	return NULL;
}

static void env_set(struct fake_env *env, const char *name, const char *value)
{
	for (unsigned int i = 0; i < env->count; i++) {
		if (!strcmp(env->name[i], name)) {
			env->value[i] = value;
			return;
		}
	}
	if (env->count == FAKE_ENV_MAX)
		abort();
	env->name[env->count] = name;
	env->value[env->count++] = value;
}

static int parse(const struct fake_env *env, struct xdev_ext_config *cfg)
{
	struct xdev_ext_env_view view = {
		.get = fake_get,
		.opaque = env,
		.page_size = 4096,
	};

	memset(cfg, 0, sizeof(*cfg));
	return xdev_ext_preload_config_parse(&view, cfg);
}

static uint32_t ipv4(const char *text)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, text, &addr) != 1)
		abort();
	return addr.s_addr;
}

static void expect_defaults(const struct xdev_ext_config *cfg)
{
	EXPECT_EQ(cfg->frame_size, 4096);
	EXPECT_EQ(cfg->rx_frames, 1024);
	EXPECT_EQ(cfg->rx_mode, XDEV_EXT_CFG_RX_MODE_AUTO);
	EXPECT_EQ(cfg->rx_fork, XDEV_EXT_CFG_RX_FORK_RELEASE);
	EXPECT_EQ(cfg->write_sink, XDEV_EXT_CFG_WRITE_SINK_AUTO);
	EXPECT_EQ(cfg->iopath, XDEV_EXT_CFG_IOPATH_DEFAULT);
	EXPECT_EQ(cfg->identity, XDEV_EXT_CFG_IDENTITY_PER_CALL);
	EXPECT_EQ(cfg->bdev_cache, XDEV_EXT_CFG_BDEV_COHERENT);
	EXPECT_TRUE(!cfg->require_armed);
	EXPECT_TRUE(!cfg->verbose);
}

static void expect_inert(const struct xdev_ext_config *cfg)
{
	EXPECT_TRUE(!cfg->armed);
	EXPECT_TRUE(!cfg->enabled);
	EXPECT_TRUE(!cfg->socket_enabled);
	EXPECT_EQ(cfg->rx_nflows, 0);
	EXPECT_TRUE(cfg->paths == NULL);
}

/* Without a master switch nothing else is read, not even to reject it. */
static void test_inert_without_master_switch(void)
{
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	EXPECT_EQ(parse(&env, &cfg), 0);
	expect_inert(&cfg);
	EXPECT_EQ(cfg.error, 0);
	EXPECT_TRUE(cfg.error_var == NULL);
	expect_defaults(&cfg);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_RX_FRAMES", "7");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_XDP_MODE", "bogus");
	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", "bogus");
	env_set(&env, "XDEV_EXT_PRELOAD_REQUIRE_ARMED", "yes");
	env_set(&env, "XDEV_EXT_PRELOAD_VERBOSE", "yes");
	env_set(&env, "XDEV_EXT_PRELOAD_REPORT", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_PATHS", "/tmp");
	EXPECT_EQ(parse(&env, &cfg), 0);
	expect_inert(&cfg);
	EXPECT_EQ(cfg.error, 0);
	EXPECT_TRUE(cfg.error_var == NULL);
	EXPECT_TRUE(!cfg.report);
	expect_defaults(&cfg);
	xdev_ext_preload_config_release(&cfg);

	/* Only the exact spelling "1" engages an existing master switch. */
	env_set(&env, "XDEV_EXT_PRELOAD_ENABLED", "0");
	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "yes");
	env_set(&env, "XDEV_EXT_PRELOAD_RX", "");
	EXPECT_EQ(parse(&env, &cfg), 0);
	expect_inert(&cfg);
	EXPECT_EQ(cfg.error, 0);
	xdev_ext_preload_config_release(&cfg);
}

static void test_rx_flow_is_parsed(void)
{
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	env_set(&env, "XDEV_EXT_PRELOAD_RX", "ubrrx/0/192.0.2.2:12345");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(cfg.armed);
	EXPECT_EQ(cfg.error, 0);
	EXPECT_TRUE(!cfg.enabled);
	EXPECT_TRUE(!cfg.socket_enabled);
	EXPECT_EQ(cfg.rx_nflows, 1);
	EXPECT_STR(cfg.rx_flows[0].ifname, "ubrrx");
	EXPECT_EQ(cfg.rx_flows[0].queue, 0);
	EXPECT_EQ(cfg.rx_flows[0].addr.s_addr, ipv4("192.0.2.2"));
	EXPECT_EQ(cfg.rx_flows[0].port, 12345);
	expect_defaults(&cfg);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_RX",
		"a/1/10.0.0.1:1,b-2.x_y@/4294967295/255.255.255.254:65535");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(cfg.armed);
	EXPECT_EQ(cfg.rx_nflows, 2);
	EXPECT_STR(cfg.rx_flows[0].ifname, "a");
	EXPECT_EQ(cfg.rx_flows[0].queue, 1);
	EXPECT_EQ(cfg.rx_flows[0].addr.s_addr, ipv4("10.0.0.1"));
	EXPECT_EQ(cfg.rx_flows[0].port, 1);
	EXPECT_STR(cfg.rx_flows[1].ifname, "b-2.x_y@");
	EXPECT_EQ(cfg.rx_flows[1].queue, 4294967295U);
	EXPECT_EQ(cfg.rx_flows[1].addr.s_addr, ipv4("255.255.255.254"));
	EXPECT_EQ(cfg.rx_flows[1].port, 65535);
	xdev_ext_preload_config_release(&cfg);

	/* Eight flows fit; IFNAMSIZ - 1 characters fit. */
	env_set(&env, "XDEV_EXT_PRELOAD_RX",
		"i0/0/10.0.0.1:1,i1/0/10.0.0.1:2,i2/0/10.0.0.1:3,"
		"i3/0/10.0.0.1:4,i4/0/10.0.0.1:5,i5/0/10.0.0.1:6,"
		"i6/0/10.0.0.1:7,abcdefghijklmno/7/10.0.0.1:8");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.rx_nflows, 8);
	EXPECT_STR(cfg.rx_flows[7].ifname, "abcdefghijklmno");
	EXPECT_EQ(cfg.rx_flows[7].queue, 7);
	EXPECT_EQ(cfg.rx_flows[7].port, 8);
	xdev_ext_preload_config_release(&cfg);
}

static void expect_rejected(struct fake_env *env, const char *name,
			    const char *value, const char *line)
{
	struct xdev_ext_config cfg;
	int ret;

	env_set(env, name, value);
	ret = parse(env, &cfg);
	if (ret != -EINVAL || !cfg.error_var || strcmp(cfg.error_var, name))
		fprintf(stderr, "%s:%s=\"%s\": ret=%d var=%s\n", line, name,
			value, ret, cfg.error_var ? cfg.error_var : "(null)");
	EXPECT_EQ(ret, -EINVAL);
	EXPECT_EQ(cfg.error, -EINVAL);
	EXPECT_STR(cfg.error_var, name);
	expect_inert(&cfg);
	xdev_ext_preload_config_release(&cfg);
}

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)
#define EXPECT_REJECTED(env, name, value) \
	expect_rejected(env, name, value, __FILE__ ":" STRINGIFY(__LINE__))

static void test_rx_flow_is_validated(void)
{
	static const char *const bad[] = {
		"ubrrx/0/192.0.2.2",		/* no port */
		"ubrrx/0/192.0.2.2:",		/* empty port */
		"ubrrx/0/192.0.2.2:0",		/* port 0 */
		"ubrrx/0/192.0.2.2:65536",
		"ubrrx/0/192.0.2.2:+1",
		"ubrrx/0/192.0.2.2: 1",
		"ubrrx/0/192.0.2.2:01",
		"ubrrx/0/192.0.2.2:1x",
		"ubrrx/0/192.0.2.2:1/x",
		"ubrrx//192.0.2.2:1",		/* empty queue */
		"ubrrx/01/192.0.2.2:1",
		"ubrrx/-1/192.0.2.2:1",
		"ubrrx/4294967296/192.0.2.2:1",
		"ubrrx/0x1/192.0.2.2:1",
		"/0/192.0.2.2:1",		/* empty interface */
		"abcdefghijklmnop/0/192.0.2.2:1", /* IFNAMSIZ characters */
		"./0/192.0.2.2:1",
		"../0/192.0.2.2:1",
		"xdev_ext rx/0/192.0.2.2:1",
		"xdev_ext\trx/0/192.0.2.2:1",
		"xdev_ext:rx/0/192.0.2.2:1",
		"ubrrx/0/192.0.2.256:1",
		"ubrrx/0/192.0.2:1",
		"ubrrx/0/192.0.2.2.1:1",
		"ubrrx/0/192.0.2.02:1",
		"ubrrx/0/192.0..2:1",
		"ubrrx/0/0.0.0.0:1",		/* a filter needs one address */
		"ubrrx/0/[::1]:1",
		"ubrrx/0:1",
		"ubrrx",
		"a/0/10.0.0.1:1,",		/* empty item */
		",a/0/10.0.0.1:1",
		"a/0/10.0.0.1:1,,b/0/10.0.0.2:1",
		"a/0/10.0.0.1:1,b/1/10.0.0.1:1", /* same address and port */
		"i0/0/10.0.0.1:1,i1/0/10.0.0.1:2,i2/0/10.0.0.1:3,"
		"i3/0/10.0.0.1:4,i4/0/10.0.0.1:5,i5/0/10.0.0.1:6,"
		"i6/0/10.0.0.1:7,i7/0/10.0.0.1:8,i8/0/10.0.0.1:9",
	};

	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		struct fake_env env = { 0 };

		env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
		EXPECT_REJECTED(&env, "XDEV_EXT_PRELOAD_RX", bad[i]);
	}
}

struct knob_case {
	const char *name;
	const char *value;
};

/* Every new knob, valid spellings first, then rejected ones. */
static void test_new_knobs_are_validated(void)
{
	static const struct knob_case bad[] = {
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "7" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "32" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "100" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "32768" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "01024" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "0x400" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "-1024" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "+1024" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", " 1024" },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "1024 " },
		{ "XDEV_EXT_PRELOAD_RX_FRAMES", "18446744073709551616" },
		{ "XDEV_EXT_PRELOAD_RX_XDP_MODE", "native" },
		{ "XDEV_EXT_PRELOAD_RX_XDP_MODE", "AUTO" },
		{ "XDEV_EXT_PRELOAD_RX_XDP_MODE", "drv " },
		{ "XDEV_EXT_PRELOAD_RX_FORK", "Keep" },
		{ "XDEV_EXT_PRELOAD_RX_FORK", "release2" },
		{ "XDEV_EXT_PRELOAD_WRITE_SINK", "nvme" },
		{ "XDEV_EXT_PRELOAD_WRITE_SINK", "nvme-pt,libc" },
		{ "XDEV_EXT_PRELOAD_IOPATH", "unified" },
		{ "XDEV_EXT_PRELOAD_IDENTITY", "percall" },
		{ "XDEV_EXT_PRELOAD_BDEV_CACHE", "none" },
		{ "XDEV_EXT_PRELOAD_REQUIRE_ARMED", "yes" },
		{ "XDEV_EXT_PRELOAD_REQUIRE_ARMED", "2" },
		{ "XDEV_EXT_PRELOAD_VERBOSE", "true" },
	};
	static const char *const masters[][2] = {
		{ "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1" },
		{ "XDEV_EXT_PRELOAD_ENABLED", "1" },
		{ "XDEV_EXT_PRELOAD_RX", "ubrrx/0/192.0.2.2:12345" },
	};

	for (size_t m = 0; m < sizeof(masters) / sizeof(masters[0]); m++) {
		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			struct fake_env env = { 0 };

			env_set(&env, masters[m][0], masters[m][1]);
			env_set(&env, "XDEV_EXT_PRELOAD_PATHS", "/tmp");
			EXPECT_REJECTED(&env, bad[i].name, bad[i].value);
		}
	}
}

static void test_new_knob_values(void)
{
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_FRAMES", "64");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_XDP_MODE", "drv");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_FORK", "keep");
	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", "nvme-pt");
	env_set(&env, "XDEV_EXT_PRELOAD_IOPATH", "direct");
	env_set(&env, "XDEV_EXT_PRELOAD_IDENTITY", "lifecycle");
	env_set(&env, "XDEV_EXT_PRELOAD_BDEV_CACHE", "exclusive");
	env_set(&env, "XDEV_EXT_PRELOAD_REQUIRE_ARMED", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_VERBOSE", "1");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(cfg.armed);
	EXPECT_TRUE(cfg.socket_enabled);
	EXPECT_EQ(cfg.rx_frames, 64);
	EXPECT_EQ(cfg.rx_mode, XDEV_EXT_CFG_RX_MODE_DRV);
	EXPECT_EQ(cfg.rx_fork, XDEV_EXT_CFG_RX_FORK_KEEP);
	EXPECT_EQ(cfg.write_sink, XDEV_EXT_CFG_WRITE_SINK_PASSTHRU);
	EXPECT_EQ(cfg.iopath, XDEV_EXT_CFG_IOPATH_DIRECT);
	EXPECT_EQ(cfg.identity, XDEV_EXT_CFG_IDENTITY_LIFECYCLE);
	EXPECT_EQ(cfg.bdev_cache, XDEV_EXT_CFG_BDEV_EXCLUSIVE);
	EXPECT_TRUE(cfg.require_armed);
	EXPECT_TRUE(cfg.verbose);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_RX_FRAMES", "16384");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_XDP_MODE", "skb");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_FORK", "release");
	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", "unified");
	env_set(&env, "XDEV_EXT_PRELOAD_IOPATH", "compat");
	env_set(&env, "XDEV_EXT_PRELOAD_IDENTITY", "per-call");
	env_set(&env, "XDEV_EXT_PRELOAD_BDEV_CACHE", "coherent");
	env_set(&env, "XDEV_EXT_PRELOAD_REQUIRE_ARMED", "0");
	env_set(&env, "XDEV_EXT_PRELOAD_VERBOSE", "0");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.rx_frames, 16384);
	EXPECT_EQ(cfg.rx_mode, XDEV_EXT_CFG_RX_MODE_SKB);
	EXPECT_EQ(cfg.rx_fork, XDEV_EXT_CFG_RX_FORK_RELEASE);
	EXPECT_EQ(cfg.write_sink, XDEV_EXT_CFG_WRITE_SINK_UNIFIED);
	EXPECT_EQ(cfg.iopath, XDEV_EXT_CFG_IOPATH_COMPAT);
	EXPECT_EQ(cfg.identity, XDEV_EXT_CFG_IDENTITY_PER_CALL);
	EXPECT_EQ(cfg.bdev_cache, XDEV_EXT_CFG_BDEV_COHERENT);
	EXPECT_TRUE(!cfg.require_armed);
	EXPECT_TRUE(!cfg.verbose);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_RX_XDP_MODE", "auto");
	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", "compat");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.rx_mode, XDEV_EXT_CFG_RX_MODE_AUTO);
	EXPECT_EQ(cfg.write_sink, XDEV_EXT_CFG_WRITE_SINK_COMPAT);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", "libc");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.write_sink, XDEV_EXT_CFG_WRITE_SINK_LIBC);
	xdev_ext_preload_config_release(&cfg);

	/* A set-but-empty knob keeps its default, like an unset one. */
	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", "");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_FRAMES", "");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.write_sink, XDEV_EXT_CFG_WRITE_SINK_AUTO);
	EXPECT_EQ(cfg.rx_frames, 1024);
	xdev_ext_preload_config_release(&cfg);
}

/* The switches that predate this parser keep their lenient spellings. */
static void test_existing_switches(void)
{
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	/* File takeover without XDEV_EXT_PRELOAD_PATHS stays off, with a note. */
	env_set(&env, "XDEV_EXT_PRELOAD_ENABLED", "1");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(!cfg.enabled);
	EXPECT_TRUE(!cfg.armed);
	EXPECT_EQ(cfg.error, -ENOENT);
	EXPECT_STR(cfg.error_var, "XDEV_EXT_PRELOAD_PATHS");
	xdev_ext_preload_config_release(&cfg);
	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(!cfg.enabled);
	EXPECT_TRUE(cfg.socket_enabled);
	EXPECT_TRUE(cfg.armed);
	EXPECT_EQ(cfg.error, -ENOENT);
	xdev_ext_preload_config_release(&cfg);
	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "0");

	env_set(&env, "XDEV_EXT_PRELOAD_PATHS", "/a/b:relative::/c");
	env_set(&env, "XDEV_EXT_PRELOAD_REPORT", "yes");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(cfg.enabled);
	EXPECT_TRUE(cfg.armed);
	EXPECT_TRUE(!cfg.socket_enabled);
	EXPECT_TRUE(!cfg.report);
	EXPECT_STR(cfg.paths, "/a/b:relative::/c");
	EXPECT_TRUE(cfg.allow == NULL);
	EXPECT_EQ(cfg.nr_allow, 0);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_REPORT", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(cfg.report);
	EXPECT_TRUE(cfg.socket_enabled);
	EXPECT_TRUE(cfg.enabled);
	xdev_ext_preload_config_release(&cfg);

	/* An invalid new knob makes the whole configuration inert. */
	env_set(&env, "XDEV_EXT_PRELOAD_IDENTITY", "never");
	EXPECT_EQ(parse(&env, &cfg), -EINVAL);
	expect_inert(&cfg);
	EXPECT_TRUE(cfg.report);	/* still prints the CONFIG line */
	xdev_ext_preload_config_release(&cfg);
}

/* XDEV_EXT_PRELOAD_FRAME_SIZE keeps its silent fallback to the default. */
static void test_frame_size_keeps_silent_default(void)
{
	static const char *const ignored[] = {
		"3", "2048", "12288", "2097152", "abc", "4096k", "-4096", "",
	};
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
	for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++) {
		env_set(&env, "XDEV_EXT_PRELOAD_FRAME_SIZE", ignored[i]);
		EXPECT_EQ(parse(&env, &cfg), 0);
		EXPECT_EQ(cfg.error, 0);
		EXPECT_TRUE(cfg.armed);
		EXPECT_EQ(cfg.frame_size, 4096);
		xdev_ext_preload_config_release(&cfg);
	}
	env_set(&env, "XDEV_EXT_PRELOAD_FRAME_SIZE", "8192");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.frame_size, 8192);
	xdev_ext_preload_config_release(&cfg);
	env_set(&env, "XDEV_EXT_PRELOAD_FRAME_SIZE", "0x100000");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_EQ(cfg.frame_size, 1U << 20);
	xdev_ext_preload_config_release(&cfg);
}

/* The parser copies what it keeps; later changes to the view do not leak in. */
static void test_snapshot_is_a_copy(void)
{
	char rx[] = "ubrrx/3/192.0.2.2:12345";
	char paths[] = "/srv/a:/srv/b";
	char sink[] = "libc";
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	env_set(&env, "XDEV_EXT_PRELOAD_ENABLED", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_PATHS", paths);
	env_set(&env, "XDEV_EXT_PRELOAD_RX", rx);
	env_set(&env, "XDEV_EXT_PRELOAD_WRITE_SINK", sink);
	EXPECT_EQ(parse(&env, &cfg), 0);
	memset(rx, 'x', sizeof(rx) - 1);
	memset(paths, 'y', sizeof(paths) - 1);
	memcpy(sink, "bad", sizeof("bad"));
	env_set(&env, "XDEV_EXT_PRELOAD_ENABLED", "0");
	EXPECT_TRUE(cfg.enabled);
	EXPECT_STR(cfg.paths, "/srv/a:/srv/b");
	EXPECT_EQ(cfg.rx_nflows, 1);
	EXPECT_STR(cfg.rx_flows[0].ifname, "ubrrx");
	EXPECT_EQ(cfg.rx_flows[0].queue, 3);
	EXPECT_EQ(cfg.write_sink, XDEV_EXT_CFG_WRITE_SINK_LIBC);
	xdev_ext_preload_config_release(&cfg);
}

static void test_test_hook_knobs(void)
{
	static const struct knob_case bad[] = {
		{ "XDEV_EXT_PRELOAD_TEST_SYSFS_ROOT", "relative/sys" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f:1" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "f:1:9" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f::9" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f:0:9" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f:4294967295:9" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f:1:8" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f:1:13" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/f:01:9" },
		{ "XDEV_EXT_PRELOAD_TEST_NVME_MAP", ":1:9" },
	};
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;

	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_TEST_SYSFS_ROOT", "/tmp/fake-sys");
	env_set(&env, "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/srv/ns:a.img:4294967294:12");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_STR(cfg.test_sysfs_root, "/tmp/fake-sys");
	EXPECT_STR(cfg.test_ns_map_path, "/srv/ns:a.img");
	EXPECT_EQ(cfg.test_ns_map_nsid, 4294967294U);
	EXPECT_EQ(cfg.test_ns_map_lba_shift, 12);
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_TEST_NVME_MAP", "/srv/ns.img:1:9");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_STR(cfg.test_ns_map_path, "/srv/ns.img");
	EXPECT_EQ(cfg.test_ns_map_nsid, 1);
	EXPECT_EQ(cfg.test_ns_map_lba_shift, 9);
	xdev_ext_preload_config_release(&cfg);

	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		struct fake_env one = { 0 };

		env_set(&one, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
		EXPECT_REJECTED(&one, bad[i].name, bad[i].value);
	}
}

static void test_config_line(void)
{
	struct fake_env env = { 0 };
	struct xdev_ext_config cfg;
	char line[160];

	env_set(&env, "XDEV_EXT_PRELOAD_SOCKET_ENABLED", "1");
	EXPECT_EQ(parse(&env, &cfg), 0);
	EXPECT_TRUE(xdev_ext_preload_config_format(&cfg, line, sizeof(line)) > 0);
	EXPECT_STR(line, "XDEV_EXT_PRELOAD_CONFIG state=armed error=none var=none\n");
	EXPECT_TRUE(!xdev_ext_preload_config_must_abort(&cfg));
	xdev_ext_preload_config_release(&cfg);

	env_set(&env, "XDEV_EXT_PRELOAD_REQUIRE_ARMED", "1");
	env_set(&env, "XDEV_EXT_PRELOAD_RX_FRAMES", "7");
	EXPECT_EQ(parse(&env, &cfg), -EINVAL);
	EXPECT_TRUE(cfg.require_armed);
	EXPECT_TRUE(xdev_ext_preload_config_must_abort(&cfg));
	EXPECT_TRUE(xdev_ext_preload_config_format(&cfg, line, sizeof(line)) > 0);
	EXPECT_STR(line, "XDEV_EXT_PRELOAD_CONFIG state=inert error=EINVAL "
			 "var=XDEV_EXT_PRELOAD_RX_FRAMES\n");
	xdev_ext_preload_config_release(&cfg);

	/* A disarmed-after-parse configuration still names its reason. */
	env_set(&env, "XDEV_EXT_PRELOAD_RX_FRAMES", "1024");
	EXPECT_EQ(parse(&env, &cfg), 0);
	xdev_ext_preload_config_disarm(&cfg, -ENOENT, "XDEV_EXT_PRELOAD_PATHS");
	EXPECT_TRUE(!cfg.armed);
	EXPECT_TRUE(xdev_ext_preload_config_must_abort(&cfg));
	EXPECT_TRUE(xdev_ext_preload_config_format(&cfg, line, sizeof(line)) > 0);
	EXPECT_STR(line, "XDEV_EXT_PRELOAD_CONFIG state=inert error=ENOENT "
			 "var=XDEV_EXT_PRELOAD_PATHS\n");
	EXPECT_TRUE(xdev_ext_preload_config_format(&cfg, line, 8) < 0);
	xdev_ext_preload_config_release(&cfg);
}

/* ---- the built front end, loaded into a child of this program ---- */

struct child_result {
	int status;
	char err[512];
};

static bool run_child(const char *front_end, char *const extra[],
		      struct child_result *result)
{
	char preload[PATH_MAX + 16];
	char *envp[16];
	char *argv[] = { "xdev_ext_preload_config_test", "--noop", NULL };
	unsigned int n = 0;
	size_t used = 0;
	int pipe_fds[2];
	pid_t child;

	memset(result, 0, sizeof(*result));
	snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", front_end);
	envp[n++] = preload;
	for (unsigned int i = 0; extra[i]; i++)
		envp[n++] = extra[i];
	envp[n] = NULL;
	if (pipe2(pipe_fds, O_CLOEXEC))
		return false;
	child = fork();
	if (child < 0)
		return false;
	if (!child) {
		/* The abort cases must not leave core files behind. */
		struct rlimit no_core = { 0, 0 };

		setrlimit(RLIMIT_CORE, &no_core);
		dup2(pipe_fds[1], STDERR_FILENO);
		execve("/proc/self/exe", argv, envp);
		_exit(127);
	}
	close(pipe_fds[1]);
	while (used < sizeof(result->err) - 1) {
		size_t room = sizeof(result->err) - 1 - used;
		ssize_t got = read(pipe_fds[0], &result->err[used], room);

		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0 || (size_t)got > room)
			break;
		used += (size_t)got;
	}
	close(pipe_fds[0]);
	while (waitpid(child, &result->status, 0) < 0) {
		if (errno != EINTR)
			return false;
	}
	return true;
}

#define CHILD_ENV(...) ((char *[]){ __VA_ARGS__, NULL })

static void expect_child(const char *front_end, char *const extra[],
			 int exit_code, int signal_number, const char *err)
{
	struct child_result result;

	EXPECT_TRUE(run_child(front_end, extra, &result));
	if (signal_number) {
		EXPECT_TRUE(WIFSIGNALED(result.status));
		EXPECT_EQ(WIFSIGNALED(result.status) ?
			  WTERMSIG(result.status) : -1, signal_number);
	} else {
		EXPECT_TRUE(WIFEXITED(result.status));
		EXPECT_EQ(WIFEXITED(result.status) ?
			  WEXITSTATUS(result.status) : -1, exit_code);
	}
	EXPECT_STR(result.err, err);
}

static void test_front_end_constructor(void)
{
	const char *dir = getenv("XDEV_EXT_PRELOAD_TEST_DIR");
	char front_end[PATH_MAX];
	char target[PATH_MAX];
	char paths[PATH_MAX + 32];
	int fd;

	if (!dir) {
		printf("# front end constructor checks skipped: "
		       "XDEV_EXT_PRELOAD_TEST_DIR is not set\n");
		return;
	}
	snprintf(front_end, sizeof(front_end), "%s/libio_uring_unified.so",
		 dir);
	EXPECT_EQ(access(front_end, R_OK), 0);
	snprintf(target, sizeof(target), "%s/.xdev_ext-config-test.XXXXXX", dir);
	fd = mkstemp(target);
	EXPECT_TRUE(fd >= 0);
	if (fd < 0)
		return;
	close(fd);
	snprintf(paths, sizeof(paths), "XDEV_EXT_PRELOAD_PATHS=%s", target);

	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_REPORT=1"), 0, 0, "");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_REQUIRE_ARMED=1",
					  "XDEV_EXT_PRELOAD_RX_FRAMES=7"), 0, 0, "");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_ENABLED=1", paths,
					  "XDEV_EXT_PRELOAD_REPORT=1"), 0, 0,
		     "XDEV_EXT_PRELOAD_CONFIG state=armed error=none var=none\n");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_ENABLED=1", paths), 0, 0,
		     "");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_SOCKET_ENABLED=1",
					  "XDEV_EXT_PRELOAD_RX_FRAMES=7",
					  "XDEV_EXT_PRELOAD_REPORT=1"), 0, 0,
		     "XDEV_EXT_PRELOAD_CONFIG state=inert error=EINVAL "
		     "var=XDEV_EXT_PRELOAD_RX_FRAMES\n");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_SOCKET_ENABLED=1",
					  "XDEV_EXT_PRELOAD_RX_FRAMES=7",
					  "XDEV_EXT_PRELOAD_VERBOSE=1"), 0, 0,
		     "XDEV_EXT_PRELOAD_CONFIG state=inert error=EINVAL "
		     "var=XDEV_EXT_PRELOAD_RX_FRAMES\n");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_SOCKET_ENABLED=1",
					  "XDEV_EXT_PRELOAD_RX_FRAMES=7"), 0, 0, "");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_SOCKET_ENABLED=1",
					  "XDEV_EXT_PRELOAD_RX_FRAMES=7",
					  "XDEV_EXT_PRELOAD_REQUIRE_ARMED=1"),
		     0, SIGABRT,
		     "XDEV_EXT_PRELOAD_CONFIG state=inert error=EINVAL "
		     "var=XDEV_EXT_PRELOAD_RX_FRAMES\n");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_SOCKET_ENABLED=1",
					  "XDEV_EXT_PRELOAD_REQUIRE_ARMED=1"),
		     0, 0, "");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_ENABLED=1",
					  "XDEV_EXT_PRELOAD_PATHS=/nonexistent/xdev_ext",
					  "XDEV_EXT_PRELOAD_REQUIRE_ARMED=1"),
		     0, SIGABRT,
		     "XDEV_EXT_PRELOAD_CONFIG state=inert error=ENOENT "
		     "var=XDEV_EXT_PRELOAD_PATHS\n");
	expect_child(front_end, CHILD_ENV("XDEV_EXT_PRELOAD_ENABLED=1",
					  "XDEV_EXT_PRELOAD_PATHS=/nonexistent/xdev_ext",
					  "XDEV_EXT_PRELOAD_SOCKET_ENABLED=1",
					  "XDEV_EXT_PRELOAD_VERBOSE=1"), 0, 0,
		     "XDEV_EXT_PRELOAD_CONFIG state=armed error=ENOENT "
		     "var=XDEV_EXT_PRELOAD_PATHS\n");
	unlink(target);
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--noop"))
		return EXIT_SUCCESS;

	test_inert_without_master_switch();
	test_rx_flow_is_parsed();
	test_rx_flow_is_validated();
	test_new_knobs_are_validated();
	test_new_knob_values();
	test_existing_switches();
	test_frame_size_keeps_silent_default();
	test_snapshot_is_a_copy();
	test_test_hook_knobs();
	test_config_line();
	test_front_end_constructor();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u config checks failed\n", failures,
			checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u config checks\n", checks);
	return EXIT_SUCCESS;
}
