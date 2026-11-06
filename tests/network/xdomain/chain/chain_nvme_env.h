/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Block layer, PCI device, file and NVMe protocol declarations reached by the
 * NVMe class (drivers/nvme/host/xdev_ext_mech_nvme.c) and the storage family
 * (io_uring/family/xdev_ext_storfam*.c), all compiled unchanged.  Objects
 * below are the namespace/controller/request environment; the controller
 * itself is chain_nvme_glue.c, which acts only on submitted commands.
 */
#ifndef CHAIN_NVME_ENV_H
#define CHAIN_NVME_ENV_H
#define CONFIG_XDEV_EXT_MECH_ZEROCOPY 1
#define CONFIG_BLOCK 1
#define SECTOR_SHIFT 9
#define SZ_4K 4096U
#define BIO_MAX_INLINE_VECS 256U
#define FMODE_READ 0x1U
#define FMODE_WRITE 0x2U
#define BLK_MQ_REQ_NOWAIT (1U << 0)
#define REQ_OP_READ 0U
#define REQ_OP_WRITE 1U
#define REQ_OP_DRV_IN 34U
#define REQ_OP_DRV_OUT 35U
#define REQ_POLLED (1U << 21)
#define REQ_FAILFAST_MASK (7U << 8)
#define BLK_FEAT_POLL (1U << 2)
#define NVME_REQ_CANCELLED (1U << 0)
#define NVME_REQ_USERCMD (1U << 1)
#define NVME_REQ_XDEV_EXT_ZC (1U << 4)
#define NVME_REQ_XDEV_EXT_PEER (1U << 5)
#define NVME_CMD_SGL_METABUF (1U << 6)
#define NVME_SGL_FMT_DATA_DESC 0x00
#define NVME_SGL_FMT_LAST_SEG_DESC 0x03
#define NVME_CTRL_PAGE_SHIFT 12
#define NVME_CTRL_PAGE_SIZE (1U << NVME_CTRL_PAGE_SHIFT)
#define module_param_cb(...)
#define MODULE_PARM_DESC(...)
#define cpu_to_le16(v) ((__u16)(v))
#define cpu_to_le32(v) ((__u32)(v))
#define cpu_to_le64(v) ((__u64)(v))
#define le16_to_cpu(v) ((__u16)(v))
#define le32_to_cpu(v) ((__u32)(v))
#define le64_to_cpu(v) ((__u64)(v))
#define capable(c) (true)
#define CAP_SYS_RAWIO 17
#define pr_warn_ratelimited(...) ((void)0)
typedef u32 blk_opf_t;
typedef u8 blk_status_t;
typedef u64 sector_t;
typedef unsigned int fmode_t;
enum nvme_opcode { nvme_cmd_flush = 0x00, nvme_cmd_write = 0x01, nvme_cmd_read = 0x02 };
enum nvme_ctrl_state { NVME_CTRL_NEW, NVME_CTRL_LIVE };
enum { NVME_NS_READY = 1, NVME_NS_REMOVING = 2 };
enum rq_end_io_ret { RQ_END_IO_NONE, RQ_END_IO_FREE };

struct device { bool is_pci; unsigned endpoint; const char *name; };
struct pci_dev { struct device dev; unsigned endpoint, refs; const char *name; };
#define to_pci_dev(d) container_of(d, struct pci_dev, dev)
#define dev_is_pci(d) ((d)->is_pci)
static inline const char *pci_name(const struct pci_dev *p) { return p->name; }

struct cdev { int unused; };
struct inode { struct cdev *i_cdev; };
struct io_uring_cmd;
struct file_operations {
	struct module *owner;
	int (*release)(struct inode *, struct file *);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
};
struct file { const struct file_operations *f_op; struct inode *inode; fmode_t f_mode;
	void *private_data; unsigned endpoint; };
static inline struct inode *file_inode(const struct file *f) { return f->inode; }

/*
 * LBA window handles (NVME_IOCTL_XDEV_EXT_WINDOW, nvme_xdev_ext_window_ioctl)
 * are outside this composition: no case issues one, and a stage file here is
 * always the namespace file itself, so the class's window target/admit checks
 * see a non-handle file.  The file and fd services only that ioctl uses must
 * therefore never run; tests/storage/nvme/window_handle covers the handle.
 */
#ifndef O_RDONLY
#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif
static inline unsigned long copy_from_user(void *to, const void __user *from, unsigned long n)
{ (void)to; (void)from; (void)n; abort(); }
static inline struct file *get_file(struct file *f) { (void)f; abort(); }
static inline struct file *anon_inode_getfile(const char *name, const struct file_operations *fops,
					      void *priv, int flags)
{ (void)name; (void)fops; (void)priv; (void)flags; abort(); }
static inline int get_unused_fd_flags(unsigned flags) { (void)flags; abort(); }
static inline void put_unused_fd(int fd) { (void)fd; abort(); }
static inline void fd_install(int fd, struct file *file) { (void)fd; (void)file; abort(); }

struct bio_vec { struct page *bv_page; unsigned bv_len, bv_offset; };
struct bvec_iter { sector_t bi_sector; unsigned bi_size; };
struct block_device;
struct bio { struct bvec_iter bi_iter; unsigned short bi_vcnt, bi_max_vecs; blk_opf_t bi_opf;
	struct bio_vec *bi_io_vec; struct bio_vec bi_inline_vecs[]; };
struct queue_limits { unsigned max_hw_sectors, max_segments, max_segment_size, virt_boundary_mask,
	dma_alignment, features; };
enum hctx_type { HCTX_TYPE_DEFAULT, HCTX_TYPE_READ, HCTX_TYPE_POLL, HCTX_MAX_TYPES };
struct blk_mq_queue_map { unsigned nr_queues; };
struct blk_mq_tag_set { unsigned nr_maps; struct blk_mq_queue_map map[HCTX_MAX_TYPES]; };
struct request_queue { struct queue_limits limits; struct blk_mq_tag_set *tag_set; };
struct gendisk { sector_t capacity; bool ro; u64 diskseq; struct request_queue *queue; };
struct blk_mq_hw_ctx { unsigned queue_num; };
struct nvme_sgl_desc { __le64 addr; __le32 length; __u8 rsvd[3]; __u8 type; };
union nvme_data_ptr { struct { __le64 prp1, prp2; }; struct nvme_sgl_desc sgl; };
struct nvme_rw_command { __u8 opcode, flags; __u16 command_id; __le32 nsid; __le32 cdw2[2];
	__le64 metadata; union nvme_data_ptr dptr; __le64 slba; __le16 length, control;
	__le32 dsmgmt, reftag; __le16 lbat, lbatm; };
struct nvme_common_command { __u8 opcode, flags; __u16 command_id; __le32 nsid; __le32 cdw2[2];
	__le64 metadata; union nvme_data_ptr dptr; __le32 cdw10, cdw11, cdw12, cdw13, cdw14, cdw15; };
struct nvme_command { union { struct nvme_rw_command rw; struct nvme_common_command common; }; };
union nvme_result { __le16 u16; __le32 u32; __le64 u64; };
struct nvme_xdev_ext_peer_trace;
struct nvme_request { struct nvme_command *cmd; union nvme_result result; u8 genctr, retries,
	flags; u16 status; struct nvme_xdev_ext_peer_trace *peer_trace; };
struct request {
	struct request_queue *q;
	struct blk_mq_hw_ctx *mq_hctx;
	blk_opf_t cmd_flags;
	unsigned int __data_len;
	struct bio *bio;
	enum rq_end_io_ret (*end_io)(struct request *, blk_status_t);
	void *end_io_data;
	struct nvme_request nreq;
	struct nvme_command cmd_storage;
	unsigned slot;
	bool allocated, executed;
};
#define nvme_req(r) (&(r)->nreq)
static inline unsigned int blk_rq_bytes(const struct request *r) { return r->__data_len; }
static inline int blk_status_to_errno(blk_status_t s) { return s ? -EIO : 0; }
static inline unsigned queue_max_hw_sectors(const struct request_queue *q) { return q->limits.max_hw_sectors; }
static inline unsigned short queue_max_segments(const struct request_queue *q) { return q->limits.max_segments; }
static inline unsigned queue_max_segment_size(const struct request_queue *q) { return q->limits.max_segment_size; }
static inline unsigned long queue_virt_boundary(const struct request_queue *q) { return q->limits.virt_boundary_mask; }
static inline unsigned blk_lim_dma_alignment_and_pad(const struct queue_limits *l) { return l->dma_alignment; }
static inline sector_t get_capacity(const struct gendisk *d) { return d->capacity; }
static inline bool get_disk_ro(const struct gendisk *d) { return d->ro; }
static inline bool blk_rq_is_poll(const struct request *r) { return r->cmd_flags & REQ_POLLED; }
static inline bool test_bit(unsigned bit, const unsigned long *p) { return (*p >> bit) & 1; }
struct request *blk_mq_alloc_request(struct request_queue *q, blk_opf_t opf, unsigned flags);
void blk_mq_free_request(struct request *rq);
void blk_execute_rq_nowait(struct request *rq, bool at_head);
int blk_mq_poll_hw_queue(struct request_queue *q, unsigned queue_num, void *iob);
void bio_init(struct bio *bio, struct block_device *bdev, struct bio_vec *table,
	      unsigned short max_vecs, blk_opf_t opf);
void bio_uninit(struct bio *bio);
struct bio *bio_kmalloc(unsigned short nr_vecs, gfp_t gfp);
int bio_add_page(struct bio *bio, struct page *page, unsigned len, unsigned off);
int blk_rq_append_bio(struct request *rq, struct bio *bio);
void *dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *dma, gfp_t gfp);
void dma_free_coherent(struct device *dev, size_t size, void *cpu, dma_addr_t dma);
struct page *alloc_page(gfp_t gfp);
void __free_page(struct page *page);
#endif
