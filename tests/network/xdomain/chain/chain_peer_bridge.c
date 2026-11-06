// SPDX-License-Identifier: GPL-2.0
/*
 * --pool dmabuf: host 1's frames are a system-heap DMA-BUF registered through
 * the real REGISTER ioctl, and its requester binds and leases are the real
 * requester, peer region core, DMA-BUF importer and peer fd unit (compiled in
 * this unit's kernel_shim universe, as tests/network/xdomain/dmabuf_requester
 * does).  The NVMe and NHI functions of the other units are not this
 * universe's pci_dev, so each gets a twin here: a trusted, coherent,
 * unbounced requester whose exporter attachment uses a window the chain
 * chooses.  Only pointers cross; the twin is what the real code sees.
 */
#include "kernel_shim.h"
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_peer_dmabuf.h>
#include <linux/xdev_ext_requester.h>
#include <uapi/linux/xdev_ext_peer.h>

/* Real functions of this universe, renamed at compile time by run.py. */
int chain_real_requester_bind(struct xdev_ext_requester *, struct xdev_ext_mech_stage *,
			      struct pci_dev *, u32);
void chain_real_requester_unbind(struct xdev_ext_requester *);
int chain_real_peer_file_acquire(struct file *, struct pci_dev *, u64, u64, u32,
				 enum dma_data_direction, struct xdev_ext_peer_fd_lease *);
void chain_real_peer_fd_release(struct xdev_ext_peer_fd_lease *, bool);
long fixture_ctl_ioctl(unsigned int cmd, void *arg);
struct file *fixture_control_file(void);
int fixture_system_heap_register(void);
const struct dma_buf_ops *fixture_system_heap_ops(void);

/* Kernel services the real units reach (same roles as dmabuf_requester/boundary.c). */
int pci_p2pdma_distance(struct pci_dev *provider, struct device *client, bool verbose)
{ (void)provider; (void)client; (void)verbose; abort(); }
bool use_dma_iommu(struct device *dev) { (void)dev; return true; }
const void *get_dma_ops(struct device *dev) { (void)dev; return NULL; }
int misc_register(struct miscdevice *misc) { (void)misc; return 0; }
long xdev_ext_peer_net_ioctl(unsigned long arg) { (void)arg; return -ENOTTY; }
#define BRIDGE_FILES 64
/* File objects allocated by this OS boundary, not the chain's NVMe file
 * layout. An authority has no chain fd, but its actual shim refs still own it. */
static struct file *bridge_files[BRIDGE_FILES];
struct file *anon_inode_getfile(const char *name, const struct file_operations *fops,
				void *priv, int flags)
{
	struct file *f = calloc(1, sizeof(*f));
	(void)name; (void)flags;
	assert(f);
	*f = (struct file){ .f_op = fops, .refs = 1, .private_data = priv };
	for (unsigned i = 0; i < BRIDGE_FILES; i++)
		if (!bridge_files[i]) {
			bridge_files[i] = f;
			return f;
		}
	abort();
}
bool chain_bridge_owns_file(const void *pointer)
{
	if (pointer == fixture_control_file())
		return true;
	for (unsigned i = 0; i < BRIDGE_FILES; i++)
		if (bridge_files[i] && bridge_files[i] == pointer)
			return true;
	return false;
}
void chain_bridge_file_get(struct file *file)
{
	assert(chain_bridge_owns_file(file));
	get_file(file);
}
void chain_bridge_file_put(struct file *file)
{
	assert(chain_bridge_owns_file(file));
	/* The shim checks refs and invokes the real production release callback.
	 * Only the anonymous file storage itself belongs to this OS boundary. */
	fput(file);
	if (file->refs)
		return;
	for (unsigned i = 0; i < BRIDGE_FILES; i++)
		if (bridge_files[i] == file) {
			bridge_files[i] = NULL;
			free(file);
			return;
		}
}
#define BRIDGE_FDS 8
static struct file *bridge_fds[BRIDGE_FDS];
static bool bridge_reserved[BRIDGE_FDS];
int get_unused_fd_flags(unsigned flags)
{
	(void)flags;
	for (int fd = 3; fd < BRIDGE_FDS; fd++)
		if (!bridge_fds[fd] && !bridge_reserved[fd] && fd != 7) { bridge_reserved[fd] = true; return fd; }
	return -EMFILE;
}
void put_unused_fd(int fd) { bridge_reserved[fd] = false; }
void fd_install(int fd, struct file *file) { bridge_fds[fd] = file; }
/* fget(): the chain's descriptor table (only the non-DMA-BUF REGISTER path reaches it). */
unsigned long copy_from_user(void *to, const void *from, unsigned long n) { memcpy(to, from, n); return 0; }
unsigned long copy_to_user(void *to, const void *from, unsigned long n) { memcpy(to, from, n); return 0; }

static struct io_tlb_mem no_bounce = { .force_bounce = false };
#define BRIDGE_TWINS 4
static struct { const void *original; struct pci_dev twin; } twins[BRIDGE_TWINS];
static unsigned nr_twins;

/* The fake exporter (kernel_shim.c) copies env.sg into each new attachment. */
int chain_bridge_setup(u64 bytes)
{
	test_env_init(fixture_system_heap_ops());
	env.buf.size = bytes;
	env.limit = bytes; /* MEMLOCK budget: exactly this export */
	return fixture_system_heap_register();
}
struct file *chain_bridge_register(u64 bytes, u64 *generation)
{
	struct xdev_ext_peer_register reg = { .gpu_fd = 7, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF,
		.len = bytes };
	long fd = fixture_ctl_ioctl(XDEV_EXT_PEER_REGISTER, &reg);

	if (fd < 0)
		return NULL;
	*generation = reg.generation;
	return bridge_fds[fd];
}
struct file *chain_bridge_control(void) { return fixture_control_file(); }
void *chain_bridge_twin(const void *original, u32 id)
{
	for (unsigned i = 0; i < nr_twins; i++)
		if (twins[i].original == original || &twins[i].twin == original)
			return &twins[i].twin;
	assert(nr_twins < BRIDGE_TWINS);
	twins[nr_twins].original = original;
	twins[nr_twins].twin = (struct pci_dev){ .dev = { .dma_coherent = true, .dma_io_tlb_mem = &no_bounce },
		.id = id };
	return &twins[nr_twins++].twin;
}
const void *chain_bridge_original(const void *pointer)
{
	for (unsigned i = 0; i < nr_twins; i++)
		if (twins[i].original == pointer || &twins[i].twin == pointer)
			return twins[i].original;
	return NULL;
}
void chain_bridge_window(u64 first, u32 first_len, u64 second, u32 second_len)
{
	env.sg[0] = (struct scatterlist){ .dma_address = first, .dma_length = first_len,
		.length = first_len, .next = &env.sg[1] };
	env.sg[1] = (struct scatterlist){ .dma_address = second, .dma_length = second_len,
		.length = second_len };
}
int chain_bridge_requester_bind(struct xdev_ext_requester *rq, struct xdev_ext_mech_stage *st, void *twin)
{ return chain_real_requester_bind(rq, st, twin, 0); }
void chain_bridge_requester_unbind(struct xdev_ext_requester *rq) { chain_real_requester_unbind(rq); }
int chain_bridge_acquire(struct file *f, void *twin, u64 generation, u64 offset, u32 len,
			 enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h)
{ return chain_real_peer_file_acquire(f, twin, generation, offset, len, dir, h); }
void chain_bridge_release(struct xdev_ext_peer_fd_lease *h, bool quiesced)
{ chain_real_peer_fd_release(h, quiesced); }
bool chain_bridge_owns_twin(const void *pointer)
{
	for (unsigned i = 0; i < nr_twins; i++)
		if (&twins[i].twin == pointer)
			return true;
	return false;
}
