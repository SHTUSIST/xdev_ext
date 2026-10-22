// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "../../../include/xdev_ext_gpu_identity.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(expected, actual) do {                                      \
	long long expected_ = (long long)(expected);                           \
	long long actual_ = (long long)(actual);                               \
	checks++;                                                               \
	if (expected_ != actual_) {                                             \
		fprintf(stderr, "%s:%d expected %lld got %lld\n", __FILE__,    \
			__LINE__, expected_, actual_);                              \
		failures++;                                                       \
	}                                                                       \
} while (0)

#define EXPECT_STREQ(expected, actual) do {                                  \
	checks++;                                                               \
	if (strcmp((expected), (actual))) {                                     \
		fprintf(stderr, "%s:%d expected '%s' got '%s'\n", __FILE__,   \
			__LINE__, (expected), (actual));                           \
		failures++;                                                       \
	}                                                                       \
} while (0)

struct fake_identity_fs {
	dev_t opened_rdev;
	dev_t expected_rdev;
	const char *requested;
	const char *requested_real;
	const char *direct_sysfs_real;
	struct xdev_ext_gpu_identity_candidate candidates[4];
	size_t candidate_count;
	unsigned int load_calls;
};

static int fake_fstat(void *opaque, int fd, struct stat *st)
{
	struct fake_identity_fs *fs = opaque;

	(void)fd;
	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFCHR | 0600;
	st->st_rdev = fs->opened_rdev;
	return 0;
}

static int fake_realpath(void *opaque, const char *path, char *resolved,
			 size_t resolved_size)
{
	struct fake_identity_fs *fs = opaque;
	const char *result = NULL;

	if (!strcmp(path, fs->requested))
		result = fs->requested_real;
	else if (!strncmp(path, "/dev/nvidia", strlen("/dev/nvidia")))
		result = path;
	else if (!strncmp(path, "/sys/dev/char/", strlen("/sys/dev/char/"))) {
		if (!fs->direct_sysfs_real)
			return -ENOENT;
		result = fs->direct_sysfs_real;
	}
	if (!result)
		return -ENOENT;
	if (strlen(result) >= resolved_size)
		return -ENAMETOOLONG;
	strcpy(resolved, result);
	return 0;
}

static int fake_stat(void *opaque, const char *path, struct stat *st)
{
	struct fake_identity_fs *fs = opaque;

	if (strncmp(path, "/dev/nvidia", strlen("/dev/nvidia")))
		return -ENOENT;
	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFCHR | 0600;
	st->st_rdev = fs->expected_rdev;
	return 0;
}

static int fake_load_candidates(void *opaque,
				struct xdev_ext_gpu_identity_candidate *candidates,
				size_t capacity, size_t *count)
{
	struct fake_identity_fs *fs = opaque;

	fs->load_calls++;
	if (fs->candidate_count > capacity)
		return -E2BIG;
	memcpy(candidates, fs->candidates,
	       fs->candidate_count * sizeof(*candidates));
	*count = fs->candidate_count;
	return 0;
}

static const struct xdev_ext_gpu_identity_ops fake_ops = {
	.fstat_fd = fake_fstat,
	.realpath_path = fake_realpath,
	.stat_path = fake_stat,
	.load_candidates = fake_load_candidates,
};

static struct fake_identity_fs fake_default(void)
{
	struct fake_identity_fs fs = {
		.opened_rdev = makedev(195, 0),
		.expected_rdev = makedev(195, 0),
		.requested = "/dev/nvidia0",
		.requested_real = "/dev/nvidia0",
	};

	return fs;
}

static void test_pci_bdf_parser_requires_canonical_width(void)
{
	EXPECT_EQ(1, xdev_ext_gpu_identity_is_pci_bdf("0000:8a:00.0"));
	EXPECT_EQ(1, xdev_ext_gpu_identity_is_pci_bdf("ABCD:EF:1F.7"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("00000:8a:00.0"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("000:8a:00.0"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("0000:08a:00.0"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("0000:8a:000.0"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("0000:8a:00.00"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("0000:8a:20.0"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("0000:8a:00.8"));
	EXPECT_EQ(0, xdev_ext_gpu_identity_is_pci_bdf("0000:8a:00.0tail"));
}

static void test_missing_char_sysfs_uses_unique_driver_candidate(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	strcpy(fs.candidates[0].bdf, "0000:8a:00.0");
	fs.candidates[0].minor = 0;
	strcpy(fs.candidates[1].bdf, "0000:9b:00.0");
	fs.candidates[1].minor = 1;
	fs.candidate_count = 2;
	EXPECT_EQ(0, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							 "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("0000:8a:00.0", bdf);
	EXPECT_EQ(1, fs.load_calls);
}

static void test_duplicate_minor_fails_closed(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	strcpy(fs.candidates[0].bdf, "0000:8a:00.0");
	fs.candidates[0].minor = 0;
	strcpy(fs.candidates[1].bdf, "0000:8b:00.0");
	fs.candidates[1].minor = 0;
	fs.candidate_count = 2;
	EXPECT_EQ(-EEXIST, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							       "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("", bdf);
}

static void test_no_matching_minor_fails_closed(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	strcpy(fs.candidates[0].bdf, "0000:8a:00.0");
	fs.candidates[0].minor = 1;
	fs.candidate_count = 1;
	EXPECT_EQ(-ENODEV, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							       "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("", bdf);
}

static void test_unterminated_candidate_fails_closed(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	memset(fs.candidates[0].bdf, 'a', sizeof(fs.candidates[0].bdf));
	fs.candidates[0].minor = 0;
	fs.candidate_count = 1;
	EXPECT_EQ(-EPROTO, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							       "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("", bdf);
}

static void test_direct_char_sysfs_skips_fallback(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	fs.direct_sysfs_real =
		"/sys/devices/pci0000:89/0000:89:02.0/0000:8a:00.0";
	EXPECT_EQ(0, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							 "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("0000:8a:00.0", bdf);
	EXPECT_EQ(0, fs.load_calls);
}

static void test_malformed_direct_char_sysfs_fails_closed(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	fs.direct_sysfs_real = "/sys/devices/virtual/nvidia/nvidia0";
	EXPECT_EQ(-EPROTO, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							       "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("", bdf);
	EXPECT_EQ(0, fs.load_calls);
}

static void test_noncanonical_direct_char_sysfs_fails_closed(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	fs.direct_sysfs_real =
		"/sys/devices/pci0000:89/0000:89:02.0/00000:8a:00.0";
	EXPECT_EQ(-EPROTO, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
						       "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("", bdf);
	EXPECT_EQ(0, fs.load_calls);
}

static void test_noncanonical_fallback_candidate_fails_closed(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	strcpy(fs.candidates[0].bdf, "00000:8a:00.0");
	fs.candidates[0].minor = 0;
	fs.candidate_count = 1;
	EXPECT_EQ(-EPROTO, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
						       "/dev/nvidia0", 0, bdf));
	EXPECT_STREQ("", bdf);
}

static void test_node_identity_mismatch_fails_before_fallback(void)
{
	struct fake_identity_fs fs = fake_default();
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };

	fs.requested = "/tmp/gpu";
	fs.requested_real = "/dev/nvidia1";
	EXPECT_EQ(-EXDEV, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							      "/tmp/gpu", 0, bdf));
	EXPECT_EQ(0, fs.load_calls);
	EXPECT_EQ(-EXDEV, xdev_ext_gpu_identity_from_opened_with(&fake_ops, &fs, 7,
							      "/tmp/gpu",
							      1, bdf));
}

int main(void)
{
	test_pci_bdf_parser_requires_canonical_width();
	test_missing_char_sysfs_uses_unique_driver_candidate();
	test_duplicate_minor_fails_closed();
	test_no_matching_minor_fails_closed();
	test_unterminated_candidate_fails_closed();
	test_direct_char_sysfs_skips_fallback();
	test_malformed_direct_char_sysfs_fails_closed();
	test_noncanonical_direct_char_sysfs_fails_closed();
	test_noncanonical_fallback_candidate_fails_closed();
	test_node_identity_mismatch_fails_before_fallback();
	printf("xdev_ext_gpu_identity: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
