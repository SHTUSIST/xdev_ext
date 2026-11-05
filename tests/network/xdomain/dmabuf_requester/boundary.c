// SPDX-License-Identifier: GPL-2.0
/*
 * Host stand-ins: a one-pool session object (the core owns the real one), an
 * fd table for the REGISTER ioctl, anonymous inode files, user copies and DMA
 * topology answers.  The DMA-BUF exporter itself is tests/core/peer_dmabuf's
 * kernel_shim.c (fake attachment, pin, map and SG table).
 */
#include "kernel_shim.h"
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_peer_dmabuf.h>
#include "boundary.h"

struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
static struct xdev_ext_mech_session session;
#define FIXTURE_FDS 16
static struct file *fds[FIXTURE_FDS];
static bool reserved[FIXTURE_FDS];
bool fixture_dma_iommu = true;

struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{
	assert(s == &session);
	return &s->pool;
}
struct xdev_ext_mech_session *fixture_session(void) { return &session; }
struct xdev_ext_mech_pool *fixture_pool(void) { return &session.pool; }

int pci_p2pdma_distance(struct pci_dev *provider, struct device *client, bool verbose)
{
	(void)provider; (void)client; (void)verbose;
	fprintf(stderr, "unexpected topology query for ownerless host RAM\n");
	abort();
}
bool use_dma_iommu(struct device *dev) { (void)dev; return fixture_dma_iommu; }
const void *get_dma_ops(struct device *dev) { (void)dev; return NULL; }
int misc_register(struct miscdevice *misc) { (void)misc; return 0; }
long xdev_ext_peer_net_ioctl(unsigned long arg) { (void)arg; return -ENOTTY; }

#define FIXTURE_FILES 64
static struct file *anon_files[FIXTURE_FILES];
static unsigned nr_anon_files;
struct file *anon_inode_getfile(const char *name, const struct file_operations *fops,
				void *priv, int flags)
{
	struct file *f = calloc(1, sizeof(*f));
	(void)name; (void)flags;
	assert(f && nr_anon_files < FIXTURE_FILES);
	*f = (struct file){.f_op = fops, .refs = 1, .private_data = priv};
	anon_files[nr_anon_files++] = f;
	return f;
}
int get_unused_fd_flags(unsigned flags)
{
	(void)flags;
	for (int fd = 3; fd < FIXTURE_FDS; fd++)
		if (!fds[fd] && !reserved[fd] && fd != 7) { reserved[fd] = true; return fd; }
	return -EMFILE;
}
void put_unused_fd(int fd) { assert(reserved[fd] && !fds[fd]); reserved[fd] = false; }
void fd_install(int fd, struct file *file) { assert(reserved[fd] && !fds[fd]); fds[fd] = file; }
struct file *fget(int fd)
{
	if (fd < 0 || fd >= FIXTURE_FDS || !fds[fd]) return NULL;
	get_file(fds[fd]);
	return fds[fd];
}
struct file *fixture_fget(int fd) { return fd >= 0 && fd < FIXTURE_FDS ? fds[fd] : NULL; }
unsigned fixture_live_fds(void)
{
	unsigned n = 0;
	for (int fd = 0; fd < FIXTURE_FDS; fd++) n += fds[fd] != NULL;
	return n;
}
unsigned long copy_from_user(void *to, const void *from, unsigned long n) { memcpy(to, from, n); return 0; }
unsigned long copy_to_user(void *to, const void *from, unsigned long n) { memcpy(to, from, n); return 0; }

void fixture_reset(const struct dma_buf_ops *exporter)
{
	test_env_init(exporter);
	memset(&session, 0, sizeof(session));
	memset(fds, 0, sizeof(fds));
	memset(reserved, 0, sizeof(reserved));
	fixture_dma_iommu = true;
}

/* Teardown in kernel order: the session releases its pool (authority), then
 * the process closes the allocation fd; then every charge must be returned. */
void fixture_finish(struct file **allocation)
{
	if (session.pool.ops) {
		session.pool.ops->release(&session.pool);
		memset(&session.pool, 0, sizeof(session.pool));
	}
	for (int fd = 0; fd < FIXTURE_FDS; fd++) {
		struct file *f = fds[fd];
		if (!f) continue;
		fds[fd] = NULL;
		reserved[fd] = false;
		fput(f);
	}
	if (allocation) *allocation = NULL;
	/* Every anonymous file must have been closed by its last reference. */
	for (unsigned i = 0; i < nr_anon_files; i++) {
		assert(anon_files[i]->refs == 0);
		free(anon_files[i]);
	}
	nr_anon_files = 0;
	assert(fixture_system_heap_unregister() == 0);
	assert(atomic_long_read(&env.user.locked_vm) == 0);
	assert(atomic64_read(&env.mm.pinned_vm) == 0);
	assert(env.attaches == env.detaches && env.pins == env.unpins && env.maps == env.unmaps);
	assert(env.live_allocs == 0);
}
