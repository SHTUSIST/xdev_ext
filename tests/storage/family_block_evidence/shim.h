/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel facade for run.py's translation unit, after the shared peer shim.
 * Only names the actual sources use: blk-mq request and bio stand-ins, the
 * mechanism session/stage/batch accessors, PCI config reads and the native
 * completion publication, each observable by cases.c. No rule lives here.
 */
#include <linux/types.h>
struct inode;
#define list_for_each_entry_safe(p,n,h,m) for (p=container_of((h)->next,__typeof__(*p),m), \
	n=container_of(p->m.next,__typeof__(*p),m); &p->m!=(h); \
	p=n,n=container_of(n->m.next,__typeof__(*n),m))
typedef uint64_t dma_addr_t;
typedef int blk_status_t;
typedef unsigned int blk_opf_t;
typedef struct { int counter; } atomic_t;
#define PAGE_SIZE 4096U
#define BIO_MAX_INLINE_VECS 4U
#define kcalloc(n, s, f) calloc(n, s)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define WRITE_ONCE(x, v) ((x) = (v))
#define READ_ONCE(x) (x)
#define le64_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le16(x) (x)
static unsigned fixture_warnings;
#define WARN_ON_ONCE(c) ({ bool w__ = !!(c); if (w__) { fixture_warnings++; \
	fprintf(stderr, "WARN_ON_ONCE %s:%d\n", __FILE__, __LINE__); } w__; })
#define MAX_ERRNO 4095
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-MAX_ERRNO)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define ERR_CAST(p) ((void *)(p))

struct page;
struct block_device;
struct request_queue;
struct nvme_ns;
struct nvme_ns_head;
struct gendisk;
struct xdev_ext_mech_stage_uapi;
struct xdev_ext_requester_host;
struct xdev_ext_stor_completion;
struct xdev_ext_mech_layout;
struct xdev_ext_stor_stage;
struct xdev_ext_stor_io;
struct xdev_ext_stor_peer_resources;
struct nvme_xdev_ext_identity { int fixture_unused; };

/* bio: initialized by the slot owner, uninitialized exactly once. */
struct bio { int initialized; };
static unsigned fixture_bio_uninits;
static inline struct bio *bio_kmalloc(unsigned short nr, unsigned int gfp)
{ (void)nr; (void)gfp; return calloc(1, sizeof(struct bio)); }
static inline void bio_uninit(struct bio *bio) { fixture_bio_uninits++; bio->initialized = 0; }

/* Mechanism session, stage and batch: only the fields the sources read. */
struct xdev_ext_mech_pool { __u32 kind; };
struct xdev_ext_mech_session {
	struct xdev_ext_mech_pool pool;
	const struct xdev_ext_mech_layout *layout;
	__u32 depth;
};
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; void *priv; bool poll; };
struct xdev_ext_mech_batch {
	void *priv;
	__u32 bytes;
	__u64 ticket;
	unsigned publishes;
	int published_status;
	bool published_uncertain;
};
static inline struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ return &s->pool; }
static inline const struct xdev_ext_mech_layout *
xdev_ext_mech_session_layout(const struct xdev_ext_mech_session *s) { return s->layout; }
static inline __u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session *s) { return s->depth; }
static inline void *xdev_ext_mech_batch_priv(const struct xdev_ext_mech_batch *b) { return b->priv; }
static inline __u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch *b) { return b->bytes; }
static inline __u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch *b) { return b->ticket; }
static inline int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, __u64 ticket)
{ return ticket == b->ticket ? 0 : -ESTALE; }
static inline void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b, __u64 ticket,
							  int status, bool uncertain)
{ (void)ticket; b->publishes++; b->published_status = status; b->published_uncertain = uncertain; }
static inline void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b, __u64 t, int s)
{ (void)b; (void)t; (void)s; }
static inline void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b, __u64 cookie,
						     __u64 slba, __u32 bytes, __u32 op)
{ (void)b; (void)cookie; (void)slba; (void)bytes; (void)op; }

/* NVMe request: blk-mq PDU is the nvme_request the driver reads. */
struct nvme_xdev_ext_peer_trace;
struct nvme_command {
	struct { __u8 opcode; __u8 flags; __u16 command_id; __u32 nsid; __u64 slba; __u16 length; } rw;
};
union nvme_result { __u64 u64; };
struct nvme_request {
	struct nvme_command *cmd;
	union nvme_result result;
	__u8 flags;
	__u16 status;
	struct nvme_xdev_ext_peer_trace *peer_trace;
};
enum rq_end_io_ret { RQ_END_IO_NONE, RQ_END_IO_FREE };
struct request;
typedef enum rq_end_io_ret (rq_end_io_fn)(struct request *, blk_status_t);
struct request {
	rq_end_io_fn *end_io;
	void *end_io_data;
	struct bio *bio;
	unsigned int data_len;	/* blk_rq_bytes(): bytes not yet completed */
	blk_opf_t cmd_flags;
	struct nvme_request pdu;
};
#define nvme_req(r) (&(r)->pdu)
#define blk_rq_bytes(r) ((r)->data_len)
#define blk_status_to_errno(e) ((e) ? -EIO : 0)
static void fixture_dispatch(struct request *req);
static inline void blk_execute_rq_nowait(struct request *req, bool at_head)
{ (void)at_head; fixture_dispatch(req); }
static inline void xdev_ext_stor_block_poll_arm(bool poll, struct request *req,
						struct xdev_ext_stor_completion *done)
{ (void)poll; (void)req; (void)done; }

/* nvme-pci: the controller instance and its function's config space. */
struct device { struct pci_dev *pdev; };
#define to_pci_dev(d) ((d)->pdev)
struct nvme_dev { struct device *dev; struct xdev_ext_peer_requester *peer_requester; };
#define PCI_COMMAND 0x04
#define PCI_COMMAND_MASTER 0x4
static __u16 fixture_command_word;	/* read back after pci_disable_device() */
static int fixture_config_error;
static inline int pci_read_config_word(struct pci_dev *pdev, int where, __u16 *value)
{ (void)pdev; (void)where; *value = fixture_command_word; return fixture_config_error; }

/* Native trace events are disabled: observation only, never a rule. */
struct xdev_ext_native_event {
	const char *phase, *origin;
	__u32 class_id, aux, sequence;
	__u64 cookie, bytes, ticket, native_user_data;
	bool accepted;
	int status;
};
static inline bool trace_native_event_enabled(void) { return false; }
static inline void trace_native_event(const struct xdev_ext_native_event *e) { (void)e; }
