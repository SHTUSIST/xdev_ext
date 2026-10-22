// SPDX-License-Identifier: GPL-2.0
/*
 * Unit test for the NVMe passthrough write sink.  The namespace probe runs on
 * a fake sysfs and /dev tree in a temporary directory; every ioctl, fstat and
 * cache call goes through injected operations, so nothing here touches a real
 * NVMe device.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include "xdev_ext_preload_sink.h"
#include "xdev_ext_preload_sink_nvme_pt.h"

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

#define EXPECT_U64(actual, expected) do {                               \
	unsigned long long _actual = (unsigned long long)(actual);        \
	unsigned long long _expected = (unsigned long long)(expected);    \
	checks++;                                                          \
	if (_actual != _expected) {                                       \
		fprintf(stderr, "%s:%d: %s=%#llx, expected %#llx\n",     \
			__FILE__, __LINE__, #actual, _actual, _expected);      \
		failures++;                                               \
	}                                                                  \
} while (0)

#define EXPECT_STR(actual, expected) do {                               \
	const char *_actual = (actual);                                   \
	const char *_expected = (expected);                               \
	checks++;                                                          \
	if (!_actual || strcmp(_actual, _expected)) {                     \
		fprintf(stderr, "%s:%d: %s=\"%s\",\n\texpected \"%s\"\n", \
			__FILE__, __LINE__, #actual,                          \
			_actual ? _actual : "(null)", _expected);              \
		failures++;                                               \
	}                                                                  \
} while (0)

/* Paths here are short; a truncated one is a broken test, not a result. */
#define XSNPRINTF(buf, ...) do {                                        \
	int _n = snprintf(buf, sizeof(buf), __VA_ARGS__);                 \
	if (_n < 0 || (size_t)_n >= sizeof(buf)) {                        \
		fprintf(stderr, "%s:%d: truncated\n", __FILE__, __LINE__);\
		exit(EXIT_FAILURE);                                         \
	}                                                                  \
} while (0)

/* ---------------------------------------------------------------------- */
/* Fake system: sysfs and /dev under a temporary root, injected operations */

#define FAKE_NODES 16
#define FAKE_FDS 1024
#define FAKE_LOG 32
#define FAKE_LOG_LEN 96

#define CTRL_DIR "devices/pci0000:00/0000:00:04.0/nvme/nvme1"
#define CTRL2_DIR "devices/pci0000:00/0000:00:05.0/nvme/nvme2"
#define SUBSYS_DIR "devices/virtual/nvme-subsystem/nvme-subsys3"

#define NS_LBAS (1ULL << 36)
#define NS_NSID 7U
#define NG_MAJOR 242U
#define BLK_MAJOR 259U

struct fake_node {
	char name[32];
	mode_t type;
	dev_t rdev;
	ino_t ino;
	uint32_t nsid;
};

struct fake {
	char root[PATH_MAX];
	char sysfs[PATH_MAX];
	char dev[PATH_MAX];
	struct fake_node nodes[FAKE_NODES];
	unsigned int nnodes;
	int fd_node[FAKE_FDS];
	unsigned int opens;
	unsigned int closes;
	char log[FAKE_LOG][FAKE_LOG_LEN];
	unsigned int nlog;
	char joined[FAKE_LOG * FAKE_LOG_LEN];
	bool sys_admin;
	int getfl;
	int fstat_ret;
	uint64_t blk_bytes;
	uint8_t identify[XDEV_EXT_NVME_PT_IDENTIFY_LEN];
	int identify_ret;
	int sync_ret;
	int fadvise_ret;
	bool make_private;
	int private_ret;
	struct nvme_passthru_cmd last_admin;
	unsigned int admin_calls;
};

static struct fake fk;

static const char *fake_fd_name(int fd)
{
	if (fd < 0 || fd >= FAKE_FDS || fk.fd_node[fd] < 0)
		return "?";
	return fk.nodes[fk.fd_node[fd]].name;
}

static void fake_log(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
static void fake_log(const char *fmt, ...)
{
	va_list ap;

	if (fk.nlog >= FAKE_LOG)
		return;
	va_start(ap, fmt);
	vsnprintf(fk.log[fk.nlog++], FAKE_LOG_LEN, fmt, ap);
	va_end(ap);
}

static void fake_log_clear(void)
{
	fk.nlog = 0;
}

static const char *fake_log_joined(void)
{
	size_t used = 0;

	fk.joined[0] = '\0';
	for (unsigned int i = 0; i < fk.nlog; i++) {
		int n = snprintf(fk.joined + used, sizeof(fk.joined) - used,
				 "%s%s", i ? ";" : "", fk.log[i]);

		if (n < 0 || (size_t)n >= sizeof(fk.joined) - used)
			break;
		used += (size_t)n;
	}
	return fk.joined;
}

static int fake_node_index(const char *name)
{
	for (unsigned int i = 0; i < fk.nnodes; i++)
		if (!strcmp(fk.nodes[i].name, name))
			return (int)i;
	return -1;
}

static void fake_add_node(const char *name, mode_t type, unsigned int major_nr,
			  unsigned int minor_nr, ino_t ino, uint32_t nsid)
{
	struct fake_node *node = &fk.nodes[fk.nnodes++];

	XSNPRINTF(node->name, "%s", name);
	node->type = type;
	node->rdev = makedev(major_nr, minor_nr);
	node->ino = ino;
	node->nsid = nsid;
}

static void fake_track(int fd, const char *path)
{
	const char *base = strrchr(path, '/');
	size_t dev_len = strlen(fk.dev);

	if (fd < 0 || fd >= FAKE_FDS)
		return;
	fk.fd_node[fd] = -1;
	if (!strncmp(path, fk.dev, dev_len) && path[dev_len] == '/' && base)
		fk.fd_node[fd] = fake_node_index(base + 1);
}

static int fake_open(void *opaque, const char *path, int flags)
{
	int fd;

	(void)opaque;
	fd = open(path, flags & ~O_DIRECT);
	if (fd < 0)
		return -errno;
	fk.opens++;
	fake_track(fd, path);
	if (fk.fd_node[fd] >= 0)
		fake_log("open %s %s", fake_fd_name(fd),
			 (flags & O_ACCMODE) == O_RDWR ? "rw" : "ro");
	return fd;
}

static int fake_close(void *opaque, int fd)
{
	(void)opaque;
	if (fd >= 0 && fd < FAKE_FDS && fk.fd_node[fd] >= 0)
		fake_log("close %s", fake_fd_name(fd));
	if (fd >= 0 && fd < FAKE_FDS)
		fk.fd_node[fd] = -1;
	fk.closes++;
	return close(fd) ? -errno : 0;
}

static ssize_t fake_read(void *opaque, int fd, void *buf, size_t count)
{
	ssize_t ret;

	(void)opaque;
	ret = read(fd, buf, count);
	return ret < 0 ? -errno : ret;
}

static int fake_fstat(void *opaque, int fd, struct stat *st)
{
	const struct fake_node *node;

	(void)opaque;
	if (fd < 0 || fd >= FAKE_FDS || fk.fd_node[fd] < 0)
		return -EBADF;
	node = &fk.nodes[fk.fd_node[fd]];
	fake_log("fstat %s", node->name);
	if (fk.fstat_ret)
		return fk.fstat_ret;
	memset(st, 0, sizeof(*st));
	st->st_mode = node->type | 0600;
	st->st_rdev = node->rdev;
	st->st_ino = node->ino;
	st->st_dev = makedev(0, 5);
	return 0;
}

static int fake_getfl(void *opaque, int fd)
{
	(void)opaque;
	(void)fd;
	return fk.getfl;
}

static int fake_ioctl(void *opaque, int fd, unsigned long request, void *arg)
{
	const struct fake_node *node;
	struct nvme_passthru_cmd *cmd = arg;

	(void)opaque;
	if (fd < 0 || fd >= FAKE_FDS || fk.fd_node[fd] < 0)
		return -EBADF;
	node = &fk.nodes[fk.fd_node[fd]];
	if (request == NVME_IOCTL_ID) {
		fake_log("ioctl %s id", node->name);
		return node->nsid ? (int)node->nsid : -ENOTTY;
	}
	if (request == NVME_IOCTL_ADMIN_CMD) {
		fake_log("ioctl %s identify", node->name);
		fk.admin_calls++;
		fk.last_admin = *cmd;
		if (!S_ISCHR(node->type) || cmd->opcode != 0x06 ||
		    cmd->nsid != node->nsid || cmd->cdw10 != 0 ||
		    cmd->data_len != XDEV_EXT_NVME_PT_IDENTIFY_LEN || !cmd->addr)
			return -EINVAL;
		if (fk.identify_ret)
			return fk.identify_ret;
		memcpy((void *)(uintptr_t)cmd->addr, fk.identify,
		       sizeof(fk.identify));
		return 0;
	}
	if (request == BLKGETSIZE64) {
		fake_log("ioctl %s size", node->name);
		if (!S_ISBLK(node->type))
			return -ENOTTY;
		*(uint64_t *)arg = fk.blk_bytes;
		return 0;
	}
	return -ENOTTY;
}

static int fake_sync_range(void *opaque, int fd, int64_t offset,
			   int64_t count, unsigned int flags)
{
	(void)opaque;
	fake_log("sync %s %lld %lld %u", fake_fd_name(fd), (long long)offset,
		 (long long)count, flags);
	return fk.sync_ret;
}

static int fake_fadvise(void *opaque, int fd, int64_t offset, int64_t count,
			int advice)
{
	(void)opaque;
	fake_log("fadvise %s %lld %lld %d", fake_fd_name(fd),
		 (long long)offset, (long long)count, advice);
	return fk.fadvise_ret;
}

static bool fake_has_sys_admin(void *opaque)
{
	(void)opaque;
	return fk.sys_admin;
}

static int fake_make_private(void *opaque, int fd)
{
	int moved;

	(void)opaque;
	if (fk.private_ret)
		return fk.private_ret;
	moved = fcntl(fd, F_DUPFD_CLOEXEC, 200);
	if (moved < 0 || moved >= FAKE_FDS)
		return -EMFILE;
	fk.fd_node[moved] = fk.fd_node[fd];
	fk.fd_node[fd] = -1;
	fake_log("private %s", fake_fd_name(moved));
	close(fd);
	return moved;
}

static struct xdev_ext_nvme_pt_env fake_env(bool exclusive)
{
	return (struct xdev_ext_nvme_pt_env) {
		.sysfs_root = fk.sysfs,
		.dev_root = fk.dev,
		.exclusive = exclusive,
		.page_size = 4096,
		.opaque = &fk,
		.open = fake_open,
		.close = fake_close,
		.read = fake_read,
		.fstat = fake_fstat,
		.getfl = fake_getfl,
		.ioctl = fake_ioctl,
		.sync_range = fake_sync_range,
		.fadvise = fake_fadvise,
		.has_sys_admin = fake_has_sys_admin,
		.make_private = fk.make_private ? fake_make_private : NULL,
	};
}

static void put_file(const char *rel, const char *content)
{
	char path[PATH_MAX];
	char *slash;
	FILE *file;

	XSNPRINTF(path, "%s/%s", fk.root, rel);
	for (slash = strchr(path + strlen(fk.root) + 1, '/'); slash;
	     slash = strchr(slash + 1, '/')) {
		*slash = '\0';
		(void)mkdir(path, 0755);
		*slash = '/';
	}
	file = fopen(path, "w");
	if (!file) {
		perror(path);
		exit(EXIT_FAILURE);
	}
	fputs(content, file);
	fclose(file);
}

static void remove_file(const char *rel)
{
	char path[PATH_MAX];

	XSNPRINTF(path, "%s/%s", fk.root, rel);
	(void)unlink(path);
}

static void put_link(const char *rel, const char *target)
{
	char path[PATH_MAX];

	put_file("sys/dev/block/.keep", "");
	XSNPRINTF(path, "%s/%s", fk.root, rel);
	if (symlink(target, path)) {
		perror(path);
		exit(EXIT_FAILURE);
	}
}

static void put_namespace_attrs(const char *dir)
{
	char rel[PATH_MAX];

	XSNPRINTF(rel, "sys/%s/csi", dir);
	put_file(rel, "0\n");
	XSNPRINTF(rel, "sys/%s/ro", dir);
	put_file(rel, "0\n");
	XSNPRINTF(rel, "sys/%s/queue/logical_block_size", dir);
	put_file(rel, "512\n");
	XSNPRINTF(rel, "sys/%s/queue/max_hw_sectors_kb", dir);
	put_file(rel, "128\n");
	XSNPRINTF(rel, "sys/%s/queue/max_segments", dir);
	put_file(rel, "33\n");
	XSNPRINTF(rel, "sys/%s/queue/dma_alignment", dir);
	put_file(rel, "3\n");
}

static void put_le(uint8_t *bytes, size_t offset, uint64_t value,
		   unsigned int width)
{
	for (unsigned int i = 0; i < width; i++)
		bytes[offset + i] = (uint8_t)(value >> (8 * i));
}

static void identify_reset(void)
{
	memset(fk.identify, 0, sizeof(fk.identify));
	put_le(fk.identify, 0, NS_LBAS, 8);	/* NSZE */
	put_le(fk.identify, 8, NS_LBAS, 8);	/* NCAP */
	fk.identify[25] = 1;			/* NLBAF: two formats */
	fk.identify[26] = 0;			/* FLBAS: format 0 */
	fk.identify[29] = 0;			/* DPS: no PI */
	put_le(fk.identify, 128, 0, 2);		/* LBAF0 MS */
	fk.identify[130] = 9;			/* LBAF0 LBADS */
	put_le(fk.identify, 132, 8, 2);		/* LBAF1 MS */
	fk.identify[134] = 12;			/* LBAF1 LBADS */
}

static void fake_defaults(void)
{
	fk.sys_admin = true;
	fk.getfl = O_RDWR | O_DIRECT;
	fk.fstat_ret = 0;
	fk.blk_bytes = NS_LBAS << 9;
	fk.identify_ret = 0;
	fk.sync_ret = 0;
	fk.fadvise_ret = 0;
	fk.make_private = false;
	fk.private_ret = 0;
	identify_reset();
	fake_log_clear();
}

static void fake_setup(void)
{
	const char *tmp = getenv("TMPDIR");

	memset(&fk, 0, sizeof(fk));
	for (unsigned int i = 0; i < FAKE_FDS; i++)
		fk.fd_node[i] = -1;
	XSNPRINTF(fk.root, "%s/xdev_ext_nvme_pt_test.XXXXXX",
		 tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(fk.root)) {
		perror("mkdtemp");
		exit(EXIT_FAILURE);
	}
	XSNPRINTF(fk.sysfs, "%s/sys", fk.root);
	XSNPRINTF(fk.dev, "%s/dev", fk.root);

	/* Whole namespace nvme1n1 on controller nvme1, generic node ng1n1. */
	put_namespace_attrs(CTRL_DIR "/nvme1n1");
	put_file("sys/" CTRL_DIR "/ng1n1/dev", "242:1\n");
	put_link("sys/dev/block/259:1", "../../" CTRL_DIR "/nvme1n1");
	/* Its first partition. */
	put_namespace_attrs(CTRL_DIR "/nvme1n1/nvme1n1p1");
	put_file("sys/" CTRL_DIR "/nvme1n1/nvme1n1p1/partition", "1\n");
	put_link("sys/dev/block/259:2", "../../" CTRL_DIR "/nvme1n1/nvme1n1p1");
	/* A second namespace whose generic node answers another nsid. */
	put_namespace_attrs(CTRL_DIR "/nvme1n2");
	put_file("sys/" CTRL_DIR "/ng1n2/dev", "242:2\n");
	put_link("sys/dev/block/259:3", "../../" CTRL_DIR "/nvme1n2");
	/* A native multipath head under the subsystem. */
	put_namespace_attrs(SUBSYS_DIR "/nvme3n1");
	put_file("sys/" SUBSYS_DIR "/ng3n1/dev", "242:3\n");
	put_link("sys/dev/block/259:4", "../../" SUBSYS_DIR "/nvme3n1");
	/*
	 * nvme_core.multipath=Y names a private namespace after the subsystem
	 * instance (nvme0n1) while its generic node keeps the controller
	 * instance (ng2n1).
	 */
	put_namespace_attrs(CTRL2_DIR "/nvme0n1");
	put_file("sys/" CTRL2_DIR "/ng2n1/dev", "242:5\n");
	put_link("sys/dev/block/259:5", "../../" CTRL2_DIR "/nvme0n1");

	put_file("dev/nvme1n1", "");
	put_file("dev/nvme1n1p1", "");
	put_file("dev/nvme1n2", "");
	put_file("dev/nvme3n1", "");
	put_file("dev/nvme0n1", "");
	put_file("dev/ng1n1", "");
	put_file("dev/ng1n2", "");
	put_file("dev/ng3n1", "");
	put_file("dev/ng2n1", "");
	fake_add_node("nvme1n1", S_IFBLK, BLK_MAJOR, 1, 1001, NS_NSID);
	fake_add_node("nvme1n1p1", S_IFBLK, BLK_MAJOR, 2, 1002, NS_NSID);
	fake_add_node("nvme1n2", S_IFBLK, BLK_MAJOR, 3, 1003, 8);
	fake_add_node("nvme3n1", S_IFBLK, BLK_MAJOR, 4, 1004, 1);
	fake_add_node("nvme0n1", S_IFBLK, BLK_MAJOR, 5, 1005, NS_NSID);
	fake_add_node("ng1n1", S_IFCHR, NG_MAJOR, 1, 2001, NS_NSID);
	fake_add_node("ng1n2", S_IFCHR, NG_MAJOR, 2, 2002, 9);
	fake_add_node("ng3n1", S_IFCHR, NG_MAJOR, 3, 2003, 1);
	fake_add_node("ng2n1", S_IFCHR, NG_MAJOR, 5, 2005, NS_NSID);
	fake_defaults();
}

static int remove_entry(const char *path, const struct stat *st, int type,
			struct FTW *ftw)
{
	(void)st;
	(void)type;
	(void)ftw;
	return remove(path);
}

static void fake_teardown(void)
{
	(void)nftw(fk.root, remove_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* Open a fake device node as the application would, outside the counters. */
static int app_open(const char *name, struct stat *st)
{
	char path[PATH_MAX];
	int fd;

	XSNPRINTF(path, "%s/%s", fk.dev, name);
	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		exit(EXIT_FAILURE);
	}
	fake_track(fd, path);
	if (fake_fstat(NULL, fd, st)) {
		fprintf(stderr, "fake fstat failed for %s\n", name);
		exit(EXIT_FAILURE);
	}
	return fd;
}

static void app_close(int fd)
{
	fk.fd_node[fd] = -1;
	close(fd);
}

static int probe_name(const char *name, bool exclusive,
		      struct xdev_ext_nvme_pt_env *env, struct xdev_ext_nvme_pt_ns **ns,
		      enum xdev_ext_nvme_pt_stage *stage, int *app_fd)
{
	char path[PATH_MAX];
	struct stat st;
	int fd;
	int ret;

	*env = fake_env(exclusive);
	fd = app_open(name, &st);
	XSNPRINTF(path, "%s/%s", fk.dev, name);
	fake_log_clear();
	*ns = NULL;
	*stage = XDEV_EXT_NVME_PT_STAGE_OK;
	ret = xdev_ext_nvme_pt_probe(env, fd, &st, path, ns, stage);
	if (app_fd)
		*app_fd = fd;
	else
		app_close(fd);
	return ret;
}

/* Expect one rejected probe and no descriptor left behind. */
static void expect_rejected(const char *name, enum xdev_ext_nvme_pt_stage expected,
			    int line)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = (struct xdev_ext_nvme_pt_ns *)1;
	enum xdev_ext_nvme_pt_stage stage;
	unsigned int opens = fk.opens;
	unsigned int closes = fk.closes;
	int ret;

	ret = probe_name(name, false, &env, &ns, &stage, NULL);
	checks += 4;
	if (ret >= 0 || ns || stage != expected ||
	    fk.opens - opens != fk.closes - closes) {
		fprintf(stderr,
			"%s:%d: probe %s: ret=%d ns=%p stage=%s expected %s, "
			"opens=%u closes=%u\n",
			__FILE__, line, name, ret, (void *)ns,
			xdev_ext_nvme_pt_stage_name(stage),
			xdev_ext_nvme_pt_stage_name(expected), fk.opens - opens,
			fk.closes - closes);
		failures++;
	}
}

#define EXPECT_REJECTED(name, stage) expect_rejected(name, stage, __LINE__)

/* ---------------------------------------------------------------------- */
/* Pure helpers                                                           */

static void test_layout_parse(void)
{
	struct xdev_ext_nvme_pt_layout layout;

	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout(
			  "/sys/devices/pci0000:00/0000:00:04.0/nvme/nvme1/nvme1n1",
			  &layout), XDEV_EXT_NVME_PT_STAGE_OK);
	EXPECT_EQ(layout.ctrl_instance, 1);
	EXPECT_EQ(layout.disk_instance, 1);
	EXPECT_EQ(layout.head_instance, 1);
	EXPECT_EQ(layout.ctrl_dir_len,
		  strlen("/sys/devices/pci0000:00/0000:00:04.0/nvme/nvme1"));

	/* core.c names the disk after the subsystem under multipath=Y. */
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/nvme/nvme2/nvme0n13", &layout),
		  XDEV_EXT_NVME_PT_STAGE_OK);
	EXPECT_EQ(layout.ctrl_instance, 2);
	EXPECT_EQ(layout.disk_instance, 0);
	EXPECT_EQ(layout.head_instance, 13);

	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout(
			  "/sys/devices/virtual/nvme-subsystem/nvme-subsys3/nvme3n1",
			  &layout), XDEV_EXT_NVME_PT_STAGE_MULTIPATH);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/nvme/nvme1/nvme1c1n1", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/nvme/nvme1/nvme1n1/nvme1n1p1",
					   &layout), XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/virtio1/block/vda", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/virtio/nvme1/nvme1n1", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("nvme1/nvme1n1", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/nvme/nvme1/nvme1n", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout("/s/nvme/nvmeX/nvme1n1", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout(
			  "/s/nvme/nvme1/nvme1n99999999999", &layout),
		  XDEV_EXT_NVME_PT_STAGE_LAYOUT);
	EXPECT_EQ(xdev_ext_nvme_pt_parse_layout(NULL, &layout),
		  XDEV_EXT_NVME_PT_STAGE_ARGS);
}

static void test_identify_decode(void)
{
	struct xdev_ext_nvme_pt_id_ns id;

	identify_reset();
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), 0);
	EXPECT_U64(id.nsze, NS_LBAS);
	EXPECT_U64(id.ncap, NS_LBAS);
	EXPECT_EQ(id.lba_shift, 9);
	EXPECT_EQ(id.ms, 0);
	EXPECT_EQ(id.pi_type, 0);
	EXPECT_EQ(id.lbaf_index, 0);
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, 4095, &id),
		  -EINVAL);

	/* Metadata per LBA: the kernel admission refuses it. */
	fk.identify[26] = 1;
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), -EOPNOTSUPP);
	EXPECT_EQ(id.ms, 8);
	/* Protection information. */
	identify_reset();
	fk.identify[29] = 1;
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), -EOPNOTSUPP);
	/* Not allocated. */
	identify_reset();
	put_le(fk.identify, 8, 0, 8);
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), -ENXIO);
	/* LBA data size below 512 bytes. */
	identify_reset();
	fk.identify[130] = 8;
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), -EINVAL);
	/* Format index beyond NLBAF. */
	identify_reset();
	fk.identify[26] = 2;
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), -EINVAL);
	/* FLBAS bits 6:5 extend the format index (nvme_lbaf_index()). */
	identify_reset();
	fk.identify[25] = 16;
	fk.identify[26] = 0x20;
	fk.identify[128 + 4 * 16 + 2] = 12;
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), 0);
	EXPECT_EQ(id.lbaf_index, 16);
	EXPECT_EQ(id.lba_shift, 12);
	/* NSZE << LBADS must fit in 64 bits. */
	identify_reset();
	put_le(fk.identify, 0, UINT64_MAX >> 8, 8);
	EXPECT_EQ(xdev_ext_nvme_pt_decode_identify(fk.identify, sizeof(fk.identify),
					      &id), -EOVERFLOW);
	identify_reset();
}

static void test_max_bytes(void)
{
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(9, 128, 33, 4096), 131072);
	/* Segment count binds: worst case one page per segment. */
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(9, 128, 17, 4096), 65536);
	/* NLB is a 16-bit 0-based field. */
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(9, 1U << 20, 1U << 20, 4096),
		  65536U << 9);
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(12, 1ULL << 32, 1ULL << 40, 4096),
		  65536U << 12);
	/* 32-bit data_len, rounded down to whole blocks. */
	EXPECT_U64(xdev_ext_nvme_pt_max_bytes(16, 1ULL << 40, 1ULL << 40, 4096),
		   0xffff0000U);
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(12, 6, 100, 4096), 4096);
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(9, 0, 33, 4096), 0);
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(9, 128, 1, 4096), 0);
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(9, 128, 33, 0), 0);
	EXPECT_EQ(xdev_ext_nvme_pt_max_bytes(8, 128, 33, 4096), 0);
}

static void test_capable_sys_admin_matches_proc(void)
{
	char line[256];
	unsigned long long effective = 0;
	bool found = false;
	FILE *status = fopen("/proc/self/status", "r");

	if (!status)
		return;
	while (fgets(line, sizeof(line), status))
		if (sscanf(line, "CapEff: %llx", &effective) == 1)
			found = true;
	fclose(status);
	EXPECT_TRUE(found);
	EXPECT_EQ(xdev_ext_nvme_pt_capable_sys_admin(),
		  !!(effective & (1ULL << XDEV_EXT_NVME_PT_CAP_SYS_ADMIN)));
}

/* ---------------------------------------------------------------------- */
/* Namespace probe                                                        */

static void test_probe_whole_namespace(void)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	unsigned int opens = fk.opens;
	unsigned int closes = fk.closes;
	int anchor;

	fake_defaults();
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	EXPECT_EQ(stage, XDEV_EXT_NVME_PT_STAGE_OK);
	EXPECT_TRUE(ns != NULL);
	if (!ns)
		return;
	EXPECT_STR(fake_log_joined(),
		   "open ng1n1 rw;fstat ng1n1;ioctl nvme1n1 id;ioctl ng1n1 id;"
		   "ioctl ng1n1 identify;ioctl nvme1n1 size");
	EXPECT_EQ(fk.opens - opens, fk.closes - closes + 1);
	anchor = ns->anchor_fd;
	EXPECT_TRUE(anchor >= 0);
	EXPECT_STR(fake_fd_name(anchor), "ng1n1");
	EXPECT_U64(ns->ng_rdev, makedev(NG_MAJOR, 1));
	EXPECT_EQ(ns->ng_ino, 2001);
	EXPECT_EQ(ns->nsid, NS_NSID);
	EXPECT_EQ(ns->lba_shift, 9);
	EXPECT_U64(ns->capacity_lbas, NS_LBAS);
	EXPECT_EQ(ns->max_bytes, 131072);
	EXPECT_EQ(ns->dma_align_mask, 3);
	EXPECT_U64(ns->bdev_rdev, makedev(BLK_MAJOR, 1));
	EXPECT_EQ(ns->bdev_ino, 1001);
	EXPECT_U64(ns->bdev_dev, makedev(0, 5));
	EXPECT_EQ(ns->bdev_type, S_IFBLK);
	EXPECT_STR(ns->name, "nvme1n1");
	EXPECT_TRUE(!ns->exclusive);
	EXPECT_U64(ns->written_lo, UINT64_MAX);
	EXPECT_U64(ns->written_hi, 0);
	EXPECT_TRUE(ns->env == &env);
	/* Identify Namespace, CNS 0, one 4 KiB page. */
	EXPECT_EQ(fk.last_admin.opcode, 0x06);
	EXPECT_EQ(fk.last_admin.flags, 0);
	EXPECT_EQ(fk.last_admin.nsid, NS_NSID);
	EXPECT_EQ(fk.last_admin.cdw10, 0);
	EXPECT_EQ(fk.last_admin.data_len, 4096);
	EXPECT_EQ(fk.last_admin.metadata_len, 0);
	EXPECT_TRUE(fk.last_admin.addr != 0);

	fake_log_clear();
	xdev_ext_nvme_pt_destroy(ns);
	EXPECT_STR(fake_log_joined(), "close ng1n1");
	EXPECT_EQ(fk.opens - opens, fk.closes - closes);
}

static void test_probe_derives_generic_node_from_controller(void)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;

	fake_defaults();
	EXPECT_EQ(probe_name("nvme0n1", false, &env, &ns, &stage, NULL), 0);
	EXPECT_TRUE(ns != NULL);
	if (!ns)
		return;
	EXPECT_STR(ns->name, "nvme0n1");
	EXPECT_STR(fake_fd_name(ns->anchor_fd), "ng2n1");
	EXPECT_U64(ns->ng_rdev, makedev(NG_MAJOR, 5));
	xdev_ext_nvme_pt_destroy(ns);
}

static void test_probe_moves_anchor_out_of_view(void)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	unsigned int opens = fk.opens;
	unsigned int closes = fk.closes;

	fake_defaults();
	fk.make_private = true;
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	EXPECT_TRUE(ns != NULL);
	if (ns) {
		EXPECT_TRUE(ns->anchor_fd >= 200);
		EXPECT_STR(fake_fd_name(ns->anchor_fd), "ng1n1");
		EXPECT_STR(fk.log[fk.nlog - 1], "private ng1n1");
		xdev_ext_nvme_pt_destroy(ns);
	}
	/* fake_make_private closed the original number itself. */
	EXPECT_EQ(fk.opens - opens, fk.closes - closes);

	opens = fk.opens;
	closes = fk.closes;
	fk.private_ret = -EMFILE;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_PRIVATE);
	EXPECT_EQ(fk.opens - opens, fk.closes - closes);
	fake_defaults();
}

static void test_probe_rejections(void)
{
	char ng_dev[PATH_MAX];
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	struct stat st;
	int fd;

	fake_defaults();
	EXPECT_REJECTED("nvme1n1p1", XDEV_EXT_NVME_PT_STAGE_PARTITION);
	EXPECT_REJECTED("nvme3n1", XDEV_EXT_NVME_PT_STAGE_MULTIPATH);
	/* Generic node answers a different namespace id. */
	EXPECT_REJECTED("nvme1n2", XDEV_EXT_NVME_PT_STAGE_NSID);

	/* Device number with no sysfs entry. */
	fk.nodes[fake_node_index("nvme1n1")].rdev = makedev(BLK_MAJOR, 99);
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_SYSFS);
	fk.nodes[fake_node_index("nvme1n1")].rdev = makedev(BLK_MAJOR, 1);

	/* Not a block device, and a block device opened read-only. */
	env = fake_env(false);
	fd = app_open("nvme1n1", &st);
	st.st_mode = S_IFREG | 0600;
	ns = NULL;
	EXPECT_EQ(xdev_ext_nvme_pt_probe(&env, fd, &st, "x", &ns, &stage),
		  -ENOTBLK);
	EXPECT_EQ(stage, XDEV_EXT_NVME_PT_STAGE_ARGS);
	EXPECT_TRUE(ns == NULL);
	EXPECT_EQ(xdev_ext_nvme_pt_probe(&env, fd, NULL, "x", &ns, &stage),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_nvme_pt_probe(NULL, fd, &st, "x", &ns, &stage),
		  -EINVAL);
	app_close(fd);
	fk.getfl = O_RDONLY | O_DIRECT;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ACCESS);
	fk.getfl = -EBADF;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ACCESS);
	fake_defaults();

	/* Namespace attributes: command set, read-only, missing csi. */
	put_file("sys/" CTRL_DIR "/nvme1n1/csi", "2\n");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ATTRS);
	remove_file("sys/" CTRL_DIR "/nvme1n1/csi");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ATTRS);
	put_file("sys/" CTRL_DIR "/nvme1n1/csi", "0\n");
	put_file("sys/" CTRL_DIR "/nvme1n1/ro", "1\n");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ATTRS);
	put_file("sys/" CTRL_DIR "/nvme1n1/ro", "0\n");

	/* Generic node: sysfs names another device, or /dev lacks it. */
	put_file("sys/" CTRL_DIR "/ng1n1/dev", "242:9\n");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ANCHOR);
	put_file("sys/" CTRL_DIR "/ng1n1/dev", "242:1\n");
	XSNPRINTF(ng_dev, "%s/ng1n1", fk.dev);
	(void)unlink(ng_dev);
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ANCHOR);
	put_file("dev/ng1n1", "");
	fk.nodes[fake_node_index("ng1n1")].type = S_IFBLK;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_ANCHOR);
	fk.nodes[fake_node_index("ng1n1")].type = S_IFCHR;

	/* The block device itself does not answer NVME_IOCTL_ID. */
	fk.nodes[fake_node_index("nvme1n1")].nsid = 0;
	fk.nodes[fake_node_index("ng1n1")].nsid = 0;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_NSID);
	fk.nodes[fake_node_index("nvme1n1")].nsid = NS_NSID;
	fk.nodes[fake_node_index("ng1n1")].nsid = NS_NSID;

	/* Identify fails, returns an NVMe status, or shows metadata. */
	fk.identify_ret = -EACCES;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_IDENTIFY);
	fk.identify_ret = 0x4002;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_IDENTIFY);
	fk.identify_ret = 0;
	fk.identify[26] = 1;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_FORMAT);
	identify_reset();
	fk.identify[29] = 2;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_FORMAT);
	identify_reset();

	/* Block layer capacity or logical block size disagree. */
	fk.blk_bytes = (NS_LBAS << 9) - 512;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_CAPACITY);
	fk.blk_bytes = NS_LBAS << 9;
	put_file("sys/" CTRL_DIR "/nvme1n1/queue/logical_block_size",
		 "4096\n");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_CAPACITY);
	put_file("sys/" CTRL_DIR "/nvme1n1/queue/logical_block_size", "512\n");

	/* Request limits must be readable. */
	remove_file("sys/" CTRL_DIR "/nvme1n1/queue/max_segments");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_LIMITS);
	put_file("sys/" CTRL_DIR "/nvme1n1/queue/max_segments", "33\n");
	put_file("sys/" CTRL_DIR "/nvme1n1/queue/max_hw_sectors_kb", "zz\n");
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_LIMITS);
	put_file("sys/" CTRL_DIR "/nvme1n1/queue/max_hw_sectors_kb", "128\n");

	/* Unprivileged: the effects log cannot be read to prove CSUPP. */
	fk.sys_admin = false;
	EXPECT_REJECTED("nvme1n1", XDEV_EXT_NVME_PT_STAGE_PRIVILEGE);
	fake_defaults();

	/* Missing dma_alignment falls back to the LBA size mask. */
	remove_file("sys/" CTRL_DIR "/nvme1n1/queue/dma_alignment");
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	EXPECT_TRUE(ns != NULL);
	if (ns) {
		EXPECT_EQ(ns->dma_align_mask, 511);
		xdev_ext_nvme_pt_destroy(ns);
	}
	put_file("sys/" CTRL_DIR "/nvme1n1/queue/dma_alignment", "3\n");
}

/* ---------------------------------------------------------------------- */
/* Eligibility, identity, SQE and CQE                                     */

static struct xdev_ext_io make_io(const void *buf, size_t count, int64_t offset,
			     int fd)
{
	return (struct xdev_ext_io) {
		.buf = buf,
		.count = count,
		.offset = offset,
		.app_fd = fd,
		.write = true,
	};
}

#define BUF ((const void *)(uintptr_t)0x100000)

static void test_eligibility_matrix(void)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	const int dio = O_RDWR | O_DIRECT;
	const int64_t capacity = (int64_t)(NS_LBAS << 9);
	struct xdev_ext_io io;

	fake_defaults();
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	if (!ns)
		return;
	io = make_io(BUF, 4096, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_ELIGIBLE);
	/* O_DIRECT, and no synchronous or append semantics. */
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, O_RDWR, &io),
		  XDEV_EXT_NVME_PT_INELIGIBLE);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio | O_DSYNC, &io),
		  XDEV_EXT_NVME_PT_SYNC_FLAGS);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio | O_SYNC, &io),
		  XDEV_EXT_NVME_PT_SYNC_FLAGS);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio | O_APPEND, &io),
		  XDEV_EXT_NVME_PT_SYNC_FLAGS);
	/* 0 < count <= max_bytes. */
	io = make_io(BUF, 0, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	io = make_io(BUF, 131072, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_ELIGIBLE);
	io = make_io(BUF, 131072 + 512, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	/* offset >= 0. */
	io = make_io(BUF, 4096, -512, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	/* Offset and length in whole logical blocks. */
	io = make_io(BUF, 4096, 8192 + 256, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	io = make_io(BUF, 4096 + 256, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	/* offset + count <= capacity, without overflow. */
	io = make_io(BUF, 4096, capacity - 4096, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_ELIGIBLE);
	io = make_io(BUF, 4096, capacity - 512, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	io = make_io(BUF, 4096, INT64_MAX & ~(int64_t)511, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	/* Buffer present and aligned to the queue's DMA mask. */
	io = make_io(NULL, 4096, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	io = make_io((const void *)(uintptr_t)0x100002, 4096, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	io = make_io((const void *)(uintptr_t)0x100004, 4096, 8192, 3);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_ELIGIBLE);
	/* The sink serves writes only. */
	io = make_io(BUF, 4096, 8192, 3);
	io.write = false;
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, &io), XDEV_EXT_NVME_PT_INELIGIBLE);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(ns, dio, NULL), XDEV_EXT_NVME_PT_INELIGIBLE);
	EXPECT_EQ(xdev_ext_nvme_pt_classify(NULL, dio, &io),
		  XDEV_EXT_NVME_PT_INELIGIBLE);
	xdev_ext_nvme_pt_destroy(ns);
}

static void test_identity(void)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	struct stat st;

	fake_defaults();
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	if (!ns)
		return;
	memset(&st, 0, sizeof(st));
	st.st_mode = S_IFBLK | 0660;
	st.st_rdev = makedev(BLK_MAJOR, 1);
	st.st_ino = 1001;
	st.st_dev = makedev(0, 5);
	EXPECT_TRUE(xdev_ext_nvme_pt_identity_matches(ns, &st));
	st.st_rdev = makedev(BLK_MAJOR, 3);
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, &st));
	st.st_rdev = makedev(BLK_MAJOR, 1);
	st.st_ino = 1003;
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, &st));
	st.st_ino = 1001;
	st.st_dev = makedev(0, 6);
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, &st));
	st.st_dev = makedev(0, 5);
	st.st_mode = S_IFREG | 0600;
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, &st));
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, NULL));
	/* The type is the one recorded at registration, never zero. */
	ns->bdev_type = S_IFREG;
	EXPECT_TRUE(xdev_ext_nvme_pt_identity_matches(ns, &st));
	st.st_mode = S_IFBLK | 0600;
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, &st));
	ns->bdev_type = 0;
	st.st_mode = 0;
	EXPECT_TRUE(!xdev_ext_nvme_pt_identity_matches(ns, &st));
	xdev_ext_nvme_pt_destroy(ns);
}

/*
 * The expected 128-byte SQE is written out field by field at fixed offsets,
 * so a layout or constant change in either UAPI header shows up here.
 */
static void test_sqe_bytes(void)
{
	const uint64_t slba = (1ULL << 32) + 7;
	const uint64_t user_data = 0x0000beef00000009ULL;
	const uintptr_t buf = (uintptr_t)0x00007f1234567000ULL;
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	struct xdev_ext_nvme_pt_sqe sqe;
	uint8_t expect[128];

	/* Constants the encoding depends on, checked by value. */
	EXPECT_EQ(sizeof(struct xdev_ext_nvme_pt_sqe), 128);
	EXPECT_EQ(sizeof(struct nvme_uring_cmd), 72);
	EXPECT_EQ(IORING_OP_URING_CMD, 46);
	EXPECT_EQ(IOSQE_FIXED_FILE, 1);
	EXPECT_U64(NVME_URING_CMD_IO, 0xc0484e80U);
	EXPECT_EQ(NVME_URING_CMD_F_XDEV_EXT, 1);

	fake_defaults();
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	if (!ns)
		return;
	memset(&sqe, 0xa5, sizeof(sqe));
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&sqe, ns, 3, (const void *)buf, 8192,
					 (int64_t)(slba << 9), user_data), 0);

	memset(expect, 0, sizeof(expect));
	expect[0] = 46;				/* opcode: URING_CMD */
	expect[1] = 1;				/* flags: IOSQE_FIXED_FILE */
	put_le(expect, 2, 0, 2);		/* ioprio */
	put_le(expect, 4, 3, 4);		/* fd: fixed-file slot */
	put_le(expect, 8, 0xc0484e80U, 4);	/* cmd_op: NVME_URING_CMD_IO */
	put_le(expect, 12, 0, 4);		/* __pad1 */
	put_le(expect, 16, 0, 8);		/* addr */
	put_le(expect, 24, 0, 4);		/* len */
	put_le(expect, 28, 0, 4);		/* uring_cmd_flags: not FIXED */
	put_le(expect, 32, user_data, 8);	/* user_data */
	put_le(expect, 40, 0, 2);		/* buf_index */
	put_le(expect, 42, 0, 2);		/* personality */
	put_le(expect, 44, 0, 4);		/* file_index */
	/* struct nvme_uring_cmd at offset 48 */
	expect[48] = 0x01;			/* opcode: NVM Write */
	expect[49] = 0;				/* flags */
	put_le(expect, 50, 0, 2);		/* rsvd1 */
	put_le(expect, 52, NS_NSID, 4);		/* nsid */
	put_le(expect, 56, 0, 4);		/* cdw2 */
	put_le(expect, 60, 0, 4);		/* cdw3 */
	put_le(expect, 64, 0, 8);		/* metadata */
	put_le(expect, 72, buf, 8);		/* addr: caller's buffer */
	put_le(expect, 80, 0, 4);		/* metadata_len */
	put_le(expect, 84, 8192, 4);		/* data_len */
	put_le(expect, 88, (uint32_t)slba, 4);	/* cdw10: SLBA low */
	put_le(expect, 92, slba >> 32, 4);	/* cdw11: SLBA high */
	put_le(expect, 96, 8192 / 512 - 1, 4);	/* cdw12: NLB 0-based */
	put_le(expect, 100, 0, 4);		/* cdw13 */
	put_le(expect, 104, 0, 4);		/* cdw14 */
	put_le(expect, 108, 0, 4);		/* cdw15 */
	put_le(expect, 112, 0, 4);		/* timeout_ms */
	put_le(expect, 116, 1, 4);		/* rsvd2: F_XDEV_EXT */
	/* 120..127: rest of the 80-byte command area, zero */
	for (unsigned int i = 0; i < sizeof(expect); i++) {
		checks++;
		if (sqe.bytes[i] != expect[i]) {
			fprintf(stderr,
				"%s:%d: SQE byte %u = %#04x, expected %#04x\n",
				__FILE__, __LINE__, i, sqe.bytes[i],
				expect[i]);
			failures++;
		}
	}

	/* Geometry the encoder refuses on its own. */
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&sqe, ns, 3, (const void *)buf, 0, 0,
					 user_data), -EINVAL);
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&sqe, ns, 3, (const void *)buf, 4096,
					 256, user_data), -EINVAL);
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&sqe, ns, 3, (const void *)buf,
					 65536U * 512U + 512U, 0, user_data),
		  -EINVAL);
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&sqe, ns, XDEV_EXT_NVME_PT_SLOTS,
					 (const void *)buf, 4096, 0,
					 user_data), -EINVAL);
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&sqe, ns, 3, NULL, 4096, 0,
					 user_data), -EINVAL);
	xdev_ext_nvme_pt_destroy(ns);
}

static void test_cqe_mapping(void)
{
	enum xdev_ext_nvme_pt_cqe_class cls;

	EXPECT_EQ(xdev_ext_nvme_pt_map_cqe(0, 8192, &cls), 8192);
	EXPECT_EQ(cls, XDEV_EXT_NVME_PT_CQE_OK);
	EXPECT_EQ(xdev_ext_nvme_pt_map_cqe(-EPERM, 8192, &cls), -EPERM);
	EXPECT_EQ(cls, XDEV_EXT_NVME_PT_CQE_POLICY_DENIED);
	EXPECT_EQ(xdev_ext_nvme_pt_map_cqe(-EIO, 8192, &cls), -EIO);
	EXPECT_EQ(cls, XDEV_EXT_NVME_PT_CQE_ERRNO);
	EXPECT_EQ(xdev_ext_nvme_pt_map_cqe(-EOPNOTSUPP, 8192, &cls), -EOPNOTSUPP);
	EXPECT_EQ(cls, XDEV_EXT_NVME_PT_CQE_ERRNO);
	/* A positive result is an NVMe status: no short write exists. */
	EXPECT_EQ(xdev_ext_nvme_pt_map_cqe(0x281, 8192, &cls), -EIO);
	EXPECT_EQ(cls, XDEV_EXT_NVME_PT_CQE_DEVICE_STATUS);
	EXPECT_EQ(xdev_ext_nvme_pt_map_cqe(4096, 8192, &cls), -EIO);
	EXPECT_EQ(cls, XDEV_EXT_NVME_PT_CQE_DEVICE_STATUS);
}

/* ---------------------------------------------------------------------- */
/* Execution: the call sequence and the cache-coherence decisions          */

struct fake_ring {
	int ready_ret;
	int submit_ret;
	bool publish;
	int cqe_res;
	unsigned int submits;
	struct xdev_ext_nvme_pt_sqe last;
};

static int fake_ring_ready(void *opaque, uint32_t slot)
{
	struct fake_ring *ring = opaque;

	fake_log("ready %u", slot);
	return ring->ready_ret;
}

static int fake_ring_submit(void *opaque, const struct xdev_ext_nvme_pt_sqe *sqe,
			    int *cqe_res, bool *published)
{
	struct fake_ring *ring = opaque;

	fake_log("submit");
	ring->submits++;
	ring->last = *sqe;
	*published = ring->publish;
	*cqe_res = ring->cqe_res;
	return ring->submit_ret;
}

static struct xdev_ext_nvme_pt_ring fake_ring_ops(struct fake_ring *ring)
{
	return (struct xdev_ext_nvme_pt_ring) {
		.opaque = ring,
		.ready = fake_ring_ready,
		.submit_and_wait = fake_ring_submit,
	};
}

struct exec_case {
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns;
	struct fake_ring ring;
	struct xdev_ext_nvme_pt_ring ops;
	struct xdev_ext_io io;
	struct xdev_ext_nvme_pt_call call;
	int app_fd;
};

static bool exec_setup(struct exec_case *c, bool exclusive)
{
	enum xdev_ext_nvme_pt_stage stage;

	memset(c, 0, sizeof(*c));
	fake_defaults();
	if (probe_name("nvme1n1", exclusive, &c->env, &c->ns, &stage,
		       &c->app_fd) || !c->ns) {
		fprintf(stderr, "%s:%d: probe failed\n", __FILE__, __LINE__);
		failures++;
		return false;
	}
	c->ring = (struct fake_ring) { .publish = true };
	c->ops = fake_ring_ops(&c->ring);
	c->io = make_io(BUF, 8192, 4096, c->app_fd);
	c->call = (struct xdev_ext_nvme_pt_call) {
		.io = &c->io,
		.status_flags = O_RDWR | O_DIRECT,
		.slot = 3,
		.user_data = 0x42,
	};
	fake_log_clear();
	return true;
}

static void exec_teardown(struct exec_case *c)
{
	xdev_ext_nvme_pt_destroy(c->ns);
	app_close(c->app_fd);
}

static int exec_run(struct exec_case *c, ssize_t *result, bool *published)
{
	*result = 12345;
	*published = true;
	return xdev_ext_nvme_pt_execute(c->ns, &c->call, &c->ops, result,
				   published);
}

static void test_execute_coherent(void)
{
	struct xdev_ext_nvme_pt_sqe direct = { 0 };
	struct exec_case c;
	ssize_t result;
	bool published;

	/* Success: write back, publish, wait, drop the cached range. */
	if (!exec_setup(&c, false))
		return;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_STR(fake_log_joined(),
		   "fstat nvme1n1;ready 3;sync nvme1n1 4096 8192 7;submit;"
		   "fadvise nvme1n1 4096 8192 4");
	EXPECT_EQ(result, 8192);
	EXPECT_TRUE(published);
	EXPECT_EQ(c.ring.submits, 1);
	EXPECT_EQ(xdev_ext_nvme_pt_encode_sqe(&direct, c.ns, 3, BUF, 8192, 4096,
					 0x42), 0);
	EXPECT_TRUE(!memcmp(&direct, &c.ring.last, sizeof(direct)));
	EXPECT_EQ(c.ns->ctr.takeover, 1);
	EXPECT_EQ(c.ns->ctr.takeover_bytes, 8192);
	EXPECT_EQ(c.ns->ctr.errors, 0);
	/* coherent mode does not track a written range. */
	EXPECT_U64(c.ns->written_lo, UINT64_MAX);

	/* The pre-write write-back fails: nothing is published. */
	fake_log_clear();
	fk.sync_ret = -EIO;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_STR(fake_log_joined(),
		   "fstat nvme1n1;ready 3;sync nvme1n1 4096 8192 7");
	EXPECT_TRUE(!published);
	EXPECT_EQ(c.ring.submits, 1);
	EXPECT_EQ(c.ns->ctr.fallback_presync, 1);
	fk.sync_ret = 0;

	/* Invalidation failure after a completed write is only counted. */
	fake_log_clear();
	fk.fadvise_ret = -EINVAL;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_EQ(result, 8192);
	EXPECT_EQ(c.ns->ctr.invalidate_errors, 1);
	EXPECT_EQ(c.ns->ctr.takeover, 2);
	fk.fadvise_ret = 0;
	exec_teardown(&c);
}

/*
 * posix_fadvise(POSIX_FADV_DONTNEED) keeps a page the range covers only in
 * part (mm/fadvise.c), while the block layer's O_DIRECT write invalidates
 * every page it touches (kiocb_invalidate_post_direct_write()).  A stale
 * cached page would survive a served sub-page write, so coherent mode hands
 * those writes to libc; exclusive mode keeps no cache to go stale.
 */
static void test_execute_coherent_sub_page(void)
{
	struct exec_case c;
	ssize_t result;
	bool published;

	if (!exec_setup(&c, false))
		return;
	EXPECT_EQ(c.ns->page_mask, 4095);
	c.io = make_io(BUF, 512, 512, c.app_fd);
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_STR(fake_log_joined(), "");
	EXPECT_TRUE(!published);
	EXPECT_EQ(c.ring.submits, 0);
	EXPECT_EQ(c.ns->ctr.fallback_ineligible, 1);
	/* A partial last page, and a partial first page. */
	c.io = make_io(BUF, 4096 + 512, 8192, c.app_fd);
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	c.io = make_io(BUF, 3584, 512, c.app_fd);
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_EQ(c.ns->ctr.fallback_ineligible, 3);
	EXPECT_EQ(c.ns->ctr.takeover, 0);
	EXPECT_EQ(c.ring.submits, 0);
	/* Whole pages are served and dropped as before. */
	fake_log_clear();
	c.io = make_io(BUF, 4096, 4096, c.app_fd);
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_STR(fake_log_joined(),
		   "fstat nvme1n1;ready 3;sync nvme1n1 4096 4096 7;submit;"
		   "fadvise nvme1n1 4096 4096 4");
	EXPECT_EQ(result, 4096);
	exec_teardown(&c);

	if (!exec_setup(&c, true))
		return;
	c.io = make_io(BUF, 512, 512, c.app_fd);
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_EQ(result, 512);
	EXPECT_EQ(c.ns->ctr.fallback_ineligible, 0);
	exec_teardown(&c);

	/* The page mask needs a power-of-two page size. */
	{
		struct xdev_ext_nvme_pt_env env = fake_env(false);
		struct xdev_ext_nvme_pt_ns *ns = NULL;
		enum xdev_ext_nvme_pt_stage stage;
		unsigned int opens, closes;
		char path[PATH_MAX];
		struct stat st;
		int fd;

		fake_defaults();
		env.page_size = 3072;
		fd = app_open("nvme1n1", &st);
		XSNPRINTF(path, "%s/%s", fk.dev, "nvme1n1");
		opens = fk.opens;
		closes = fk.closes;
		EXPECT_TRUE(xdev_ext_nvme_pt_probe(&env, fd, &st, path, &ns,
					      &stage) < 0);
		EXPECT_EQ(stage, XDEV_EXT_NVME_PT_STAGE_LIMITS);
		EXPECT_TRUE(ns == NULL);
		EXPECT_EQ(fk.opens - opens, fk.closes - closes);
		app_close(fd);
	}
}

static void test_execute_fallbacks(void)
{
	struct exec_case c;
	ssize_t result;
	bool published;

	if (!exec_setup(&c, false))
		return;
	/* Ineligible: no system call at all. */
	c.call.status_flags = O_RDWR;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_STR(fake_log_joined(), "");
	EXPECT_TRUE(!published);
	EXPECT_EQ(c.ns->ctr.fallback_ineligible, 1);
	c.call.status_flags = O_RDWR | O_DIRECT | O_DSYNC;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_EQ(c.ns->ctr.fallback_sync_flags, 1);
	c.call.status_flags = O_RDWR | O_DIRECT;

	/* The descriptor now names another object. */
	fake_log_clear();
	fk.nodes[fake_node_index("nvme1n1")].ino = 4242;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_STR(fake_log_joined(), "fstat nvme1n1");
	EXPECT_EQ(c.ns->ctr.fallback_identity, 1);
	fk.nodes[fake_node_index("nvme1n1")].ino = 1001;
	fk.fstat_ret = -EBADF;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_EQ(c.ns->ctr.fallback_identity, 2);
	fk.fstat_ret = 0;

	/* This thread has no usable ring or slot. */
	fake_log_clear();
	c.ring.ready_ret = -ENOSYS;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_STR(fake_log_joined(), "fstat nvme1n1;ready 3");
	EXPECT_EQ(c.ns->ctr.fallback_ineligible, 2);
	c.ring.ready_ret = 0;

	/* The ring refuses the entry before publishing it. */
	fake_log_clear();
	c.ring.publish = false;
	c.ring.submit_ret = -EBUSY;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_FALLBACK);
	EXPECT_TRUE(!published);
	EXPECT_EQ(c.ns->ctr.fallback_ineligible, 3);
	EXPECT_EQ(c.ns->ctr.takeover, 0);
	EXPECT_EQ(c.ns->ctr.fallback_presync, 0);
	exec_teardown(&c);
}

static void test_execute_errors_after_publish(void)
{
	struct exec_case c;
	ssize_t result;
	bool published;

	if (!exec_setup(&c, false))
		return;
	/* Policy denial: served with -EPERM, no invalidation. */
	c.ring.cqe_res = -EPERM;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_STR(fake_log_joined(),
		   "fstat nvme1n1;ready 3;sync nvme1n1 4096 8192 7;submit");
	EXPECT_EQ(result, -EPERM);
	EXPECT_TRUE(published);
	EXPECT_EQ(c.ns->ctr.errors, 1);
	EXPECT_EQ(c.ns->ctr.policy_denied, 1);
	/* NVMe status. */
	c.ring.cqe_res = 0x281;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_EQ(result, -EIO);
	EXPECT_EQ(c.ns->ctr.device_status_errors, 1);
	EXPECT_EQ(c.ns->ctr.errors, 2);
	/* Ring failure after publication: never handed to libc. */
	fake_log_clear();
	c.ring.cqe_res = 0;
	c.ring.submit_ret = -EIO;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_EQ(result, -EIO);
	EXPECT_TRUE(published);
	EXPECT_EQ(c.ns->ctr.errors, 3);
	EXPECT_STR(fake_log_joined(),
		   "fstat nvme1n1;ready 3;sync nvme1n1 4096 8192 7;submit");
	EXPECT_EQ(c.ns->ctr.takeover, 3);
	EXPECT_EQ(c.ns->ctr.takeover_bytes, 0);
	exec_teardown(&c);
}

static void test_execute_exclusive(void)
{
	char expected[256];
	struct exec_case c;
	ssize_t result;
	bool published;
	unsigned int opens;
	unsigned int closes;

	/* Registration writes back and drops the whole device once. */
	{
		struct xdev_ext_nvme_pt_env env;
		struct xdev_ext_nvme_pt_ns *ns = NULL;
		enum xdev_ext_nvme_pt_stage stage;

		fake_defaults();
		EXPECT_EQ(probe_name("nvme1n1", true, &env, &ns, &stage, NULL),
			  0);
		EXPECT_STR(fake_log_joined(),
			   "open ng1n1 rw;fstat ng1n1;ioctl nvme1n1 id;"
			   "ioctl ng1n1 id;ioctl ng1n1 identify;"
			   "ioctl nvme1n1 size;sync nvme1n1 0 0 7;"
			   "fadvise nvme1n1 0 0 4");
		EXPECT_TRUE(ns && ns->exclusive);
		if (ns)
			xdev_ext_nvme_pt_destroy(ns);
	}

	if (!exec_setup(&c, true))
		return;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_STR(fake_log_joined(), "fstat nvme1n1;ready 3;submit");
	EXPECT_EQ(result, 8192);
	EXPECT_U64(c.ns->written_lo, 4096);
	EXPECT_U64(c.ns->written_hi, 4096 + 8192);
	c.io.offset = 1 << 20;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_U64(c.ns->written_lo, 4096);
	EXPECT_U64(c.ns->written_hi, (1 << 20) + 8192);
	/* A failed write does not widen the range. */
	c.io.offset = 1 << 22;
	c.ring.cqe_res = -EIO;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	EXPECT_U64(c.ns->written_hi, (1 << 20) + 8192);

	/* Teardown drops what was written, once, through a fresh open. */
	fake_log_clear();
	opens = fk.opens;
	closes = fk.closes;
	xdev_ext_nvme_pt_teardown(c.ns);
	snprintf(expected, sizeof(expected),
		 "open nvme1n1 ro;fstat nvme1n1;fadvise nvme1n1 4096 %d 4;"
		 "close nvme1n1", (1 << 20) + 8192 - 4096);
	EXPECT_STR(fake_log_joined(), expected);
	EXPECT_EQ(fk.opens - opens, fk.closes - closes);
	fake_log_clear();
	xdev_ext_nvme_pt_teardown(c.ns);
	EXPECT_STR(fake_log_joined(), "");
	EXPECT_EQ(c.ns->ctr.invalidate_errors, 0);
	exec_teardown(&c);

	/* A teardown that cannot reach the device is counted. */
	if (!exec_setup(&c, true))
		return;
	EXPECT_EQ(exec_run(&c, &result, &published), XDEV_EXT_SINK_SERVED);
	fk.nodes[fake_node_index("nvme1n1")].rdev = makedev(BLK_MAJOR, 77);
	xdev_ext_nvme_pt_teardown(c.ns);
	EXPECT_EQ(c.ns->ctr.invalidate_errors, 1);
	fk.nodes[fake_node_index("nvme1n1")].rdev = makedev(BLK_MAJOR, 1);
	exec_teardown(&c);

	/* Registration-time write-back failure refuses the registration. */
	fake_defaults();
	fk.sync_ret = -EIO;
	{
		struct xdev_ext_nvme_pt_env env;
		struct xdev_ext_nvme_pt_ns *ns = NULL;
		enum xdev_ext_nvme_pt_stage stage;

		opens = fk.opens;
		closes = fk.closes;
		EXPECT_EQ(probe_name("nvme1n1", true, &env, &ns, &stage, NULL),
			  -EIO);
		EXPECT_EQ(stage, XDEV_EXT_NVME_PT_STAGE_CACHE);
		EXPECT_TRUE(ns == NULL);
		EXPECT_EQ(fk.opens - opens, fk.closes - closes);
	}
	fake_defaults();
}

/* ---------------------------------------------------------------------- */
/* Report line and the sink-interface adaptors                            */

static void test_report_line(void)
{
	struct xdev_ext_nvme_pt_env env;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	enum xdev_ext_nvme_pt_stage stage;
	char line[XDEV_EXT_NVME_PT_REPORT_MAX];

	fake_defaults();
	EXPECT_EQ(probe_name("nvme1n1", false, &env, &ns, &stage, NULL), 0);
	if (!ns)
		return;
	ns->ctr = (struct xdev_ext_nvme_pt_counters) {
		.takeover = 4,
		.takeover_bytes = 32768,
		.errors = 3,
		.policy_denied = 1,
		.device_status_errors = 2,
		.fallback_ineligible = 5,
		.fallback_vector = 6,
		.fallback_sync_flags = 7,
		.fallback_identity = 8,
		.fallback_presync = 9,
		.invalidate_errors = 10,
	};
	EXPECT_TRUE(xdev_ext_nvme_pt_format_report(ns, 4242, line, sizeof(line)) >
		    0);
	EXPECT_STR(line,
		   "XDEV_EXT_PRELOAD_WRITE_REPORT pid=4242 sink=nvme-pt "
		   "device=nvme1n1 nsid=7 lba_bytes=512 takeover=4 "
		   "takeover_bytes=32768 errors=3 policy_denied=1 "
		   "device_status_errors=2 fallback_ineligible=5 "
		   "fallback_vector=6 fallback_sync_flags=7 "
		   "fallback_identity=8 fallback_presync=9 "
		   "invalidate_errors=10 cache=coherent\n");
	ns->exclusive = true;
	EXPECT_TRUE(xdev_ext_nvme_pt_format_report(ns, 1, line, sizeof(line)) > 0);
	EXPECT_TRUE(strstr(line, " cache=exclusive\n") != NULL);
	EXPECT_EQ(xdev_ext_nvme_pt_format_report(ns, 1, line, 16), -ENOSPC);
	xdev_ext_nvme_pt_destroy(ns);
}

static void test_sink_adaptors(void)
{
	static const struct xdev_ext_sink_ops sink = {
		.name = XDEV_EXT_NVME_PT_NAME,
		.probe = xdev_ext_nvme_pt_sink_probe,
		.destroy = xdev_ext_nvme_pt_sink_destroy,
		.report = xdev_ext_nvme_pt_sink_report,
	};
	static const struct xdev_ext_source_ops source = { .name = "test" };
	struct xdev_ext_nvme_pt_env env;
	char line[XDEV_EXT_NVME_PT_REPORT_MAX];
	char expected[64];
	void *backend = (void *)1;
	struct stat st;
	int pipefd[2];
	ssize_t n;
	int fd;

	EXPECT_STR(sink.name, "nvme-pt");
	EXPECT_STR(source.name, "test");
	fake_defaults();
	xdev_ext_nvme_pt_use_env(NULL);
	fd = app_open("nvme1n1", &st);
	EXPECT_EQ(sink.probe(fd, &st, "x", &backend), -ENODEV);
	EXPECT_TRUE(backend == NULL);

	env = fake_env(false);
	xdev_ext_nvme_pt_use_env(&env);
	EXPECT_EQ(sink.probe(fd, &st, "x", &backend), 0);
	EXPECT_TRUE(backend != NULL);
	app_close(fd);
	if (!backend)
		return;

	EXPECT_EQ(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC), 0);
	sink.report(backend, pipefd[1]);
	n = read(pipefd[0], line, sizeof(line) - 1);
	EXPECT_TRUE(n > 0);
	line[n > 0 ? n : 0] = '\0';
	snprintf(expected, sizeof(expected),
		 "XDEV_EXT_PRELOAD_WRITE_REPORT pid=%d sink=nvme-pt ",
		 (int)getpid());
	EXPECT_TRUE(!strncmp(line, expected, strlen(expected)));
	/* A registration reports exactly once. */
	sink.report(backend, pipefd[1]);
	EXPECT_EQ(read(pipefd[0], line, sizeof(line)), -1);
	close(pipefd[0]);
	close(pipefd[1]);

	fake_log_clear();
	sink.destroy(backend);
	EXPECT_STR(fake_log_joined(), "close ng1n1");
	sink.destroy(NULL);
	xdev_ext_nvme_pt_use_env(NULL);
}

int main(void)
{
	fake_setup();
	test_layout_parse();
	test_identify_decode();
	test_max_bytes();
	test_capable_sys_admin_matches_proc();
	test_probe_whole_namespace();
	test_probe_derives_generic_node_from_controller();
	test_probe_moves_anchor_out_of_view();
	test_probe_rejections();
	test_eligibility_matrix();
	test_identity();
	test_sqe_bytes();
	test_cqe_mapping();
	test_execute_coherent();
	test_execute_coherent_sub_page();
	test_execute_fallbacks();
	test_execute_errors_after_publish();
	test_execute_exclusive();
	test_report_line();
	test_sink_adaptors();
	fake_teardown();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u nvme-pt sink checks failed\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u nvme-pt sink checks\n", checks);
	return EXIT_SUCCESS;
}
