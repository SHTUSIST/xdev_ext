/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel facilities beyond tests/core/peer_dmabuf/kernel_shim.h that the real
 * requester, PEER pool and peer fd code reach, plus the fixture entry points
 * used by cases.c.  No production algorithm is restated here.
 */
#ifndef DMABUF_REQUESTER_BOUNDARY_H
#define DMABUF_REQUESTER_BOUNDARY_H

#define CAP_SYS_ADMIN 21
#define try_cmpxchg(p, o, n) __atomic_compare_exchange_n(p, o, n, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define O_RDWR 02
#define O_CLOEXEC 02000000
#define MISC_DYNAMIC_MINOR 255
#define compat_ptr_ioctl NULL
#define late_initcall(fn) \
	static int (*const fixture_initcall_##fn)(void) __attribute__((unused)) = fn
static inline int pci_domain_nr(struct pci_bus *bus) { (void)bus; return 0; }
/* System-heap backing has no BAR owner, so topology distance is never asked. */
int pci_p2pdma_distance(struct pci_dev *provider, struct device *client, bool verbose);
bool use_dma_iommu(struct device *dev);
const void *get_dma_ops(struct device *dev);
struct miscdevice { int minor; const char *name; unsigned mode;
	const struct file_operations *fops; };
int misc_register(struct miscdevice *misc);
struct file *anon_inode_getfile(const char *name, const struct file_operations *fops,
				void *priv, int flags);
int get_unused_fd_flags(unsigned flags);
void put_unused_fd(int fd);
void fd_install(int fd, struct file *file);
struct file *fget(int fd);
unsigned long copy_from_user(void *to, const void *from, unsigned long n);
unsigned long copy_to_user(void *to, const void *from, unsigned long n);
long xdev_ext_peer_net_ioctl(unsigned long arg);
/* The requester unit's host-page (IOU_UMEM) mapping is compiled, never
 * reached: every pool of this test is PEER. */
typedef struct { bool held; } spinlock_t;
#define DEFINE_SPINLOCK(n) spinlock_t n = { false }
#define spin_lock_irqsave(l, f) do { (f) = 0; assert(!(l)->held); (l)->held = true; } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(f); assert((l)->held); (l)->held = false; } while (0)
#define smp_mb__before_atomic() atomic_thread_fence(memory_order_seq_cst)
#define DMA_ATTR_SKIP_CPU_SYNC (1UL << 5)
struct page;
dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size,
			      enum dma_data_direction dir, unsigned long attrs);
void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
			  enum dma_data_direction dir, unsigned long attrs);
int dma_mapping_error(struct device *dev, dma_addr_t addr);
void dma_sync_single_for_device(struct device *dev, dma_addr_t addr, size_t size,
				enum dma_data_direction dir);
void dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr, size_t size,
			     enum dma_data_direction dir);

/* Fixture entry points (boundary.c, fd_unit.c, heap_unit.c). */
struct xdev_ext_mech_session;
struct xdev_ext_mech_pool;
void fixture_reset(const struct dma_buf_ops *exporter);
int fixture_system_heap_register(void);
int fixture_system_heap_unregister(void);
const struct dma_buf_ops *fixture_system_heap_ops(void);
const struct dma_buf_ops *fixture_other_exporter_ops(void);
long fixture_ctl_ioctl(unsigned int cmd, void *arg);
bool fixture_is_control(struct file *file);
struct file *fixture_control_file(void);
struct file *fixture_fget(int fd);
unsigned fixture_live_fds(void);
struct xdev_ext_mech_session *fixture_session(void);
struct xdev_ext_mech_pool *fixture_pool(void);
void fixture_finish(struct file **allocation);
extern bool fixture_dma_iommu;
#endif
