/* SPDX-License-Identifier: GPL-2.0 */
/* Native API shim for executing the unmodified production submit function. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLK_MQ_REQ_NOWAIT (1U << 0)
#define GFP_KERNEL 0
#define NVME_REQ_USERCMD (1U << 0)
#define NVME_REQ_XDEV_EXT_ZC (1U << 1)
#define cpu_to_le32(v) (v)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define atomic_read(p) (*(p))
#define nvme_req(r) (&(r)->nvme)

struct nvme_xdev_ext_mech_slot;
struct nvme_xdev_ext_mech_batch {
 struct nvme_xdev_ext_mech_slot *slot;
	bool validated;
	uint64_t batch_id;
	unsigned char sqe[64];
};
struct xdev_ext_mech_batch { struct nvme_xdev_ext_mech_batch priv; };
struct nvme_ns { void *queue; };
struct nvme_xdev_ext_mech_stage {
	int dead;
	struct { uint32_t nsid; } identity;
	struct nvme_ns *ns;
};
struct xdev_ext_mech_stage { struct nvme_xdev_ext_mech_stage *priv; void *s; };
#define XDEV_EXT_MECH_POOL_PEER 3
struct xdev_ext_mech_pool { unsigned int kind; };
static struct xdev_ext_mech_pool host_pool = { .kind = 2 };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(void *session)
{ (void)session; return &host_pool; }
/* The GPU branch has an independent actual-function test. This host-only
 * NOWAIT fixture must never divert to it or report a synthetic completion. */
static int nvme_xdev_ext_peer_submit(struct xdev_ext_mech_stage *st,
                                    struct xdev_ext_mech_batch *b)
{ (void)st; (void)b; abort(); }
struct nvme_command {
	struct { unsigned char opcode; uint32_t nsid; } rw;
	struct { uint32_t cdw10, cdw11, cdw12; } common;
};
enum rq_end_io_ret { RQ_END_IO_FREE };
struct request {
	struct { unsigned int flags; } nvme;
	enum rq_end_io_ret (*end_io)(struct request *, int);
	void *end_io_data;
};
struct nvme_xdev_ext_mech_completion { struct xdev_ext_mech_batch *b; uint64_t ticket; };
struct nvme_xdev_ext_mech_slot { struct nvme_xdev_ext_mech_completion done; };
/* Pool mechanics have a separate production-behavior test; this fixture
 * supplies one ready metadata lease and tests native NOWAIT tag admission. */
static struct nvme_xdev_ext_mech_slot ready_slot;
static struct nvme_xdev_ext_mech_slot *nvme_xdev_ext_class_slot_get(struct xdev_ext_mech_stage *st,
                                                       struct nvme_xdev_ext_mech_batch *bp)
{ (void)st;bp->slot=&ready_slot;return &ready_slot; }
static void nvme_xdev_ext_class_slot_put(struct xdev_ext_mech_stage *st,struct nvme_xdev_ext_mech_batch *bp)
{ (void)st;bp->slot=NULL; }

static const char *mode;
static unsigned int alloc_flags;
static int tag_calls, simulated_block, done_allocs, maps, handoffs, completions;
static struct request native_request;

static struct nvme_xdev_ext_mech_batch *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b)
{ return &b->priv; }
static uint64_t xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b)
{ (void)b; return 7; }
static uint64_t xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b)
{ (void)b; return 0x100000001ULL; }
static int nvme_xdev_ext_class_recheck(struct xdev_ext_mech_stage *st)
{ (void)st; return 0; }
static uint32_t nvme_xdev_ext_sqe_dw(const unsigned char *sqe, unsigned int dw)
{ (void)sqe; (void)dw; return 0; }
static int nvme_req_op(struct nvme_command *cmd)
{ (void)cmd; return 0; }

static struct request *blk_mq_alloc_request(void *queue, int op, unsigned int flags)
{
	(void)queue;
	(void)op;
	tag_calls++;
	alloc_flags = flags;
	if (!strcmp(mode, "full")) {
		if (flags & BLK_MQ_REQ_NOWAIT)
			return ERR_PTR(-EWOULDBLOCK);
		/* Model the forbidden wait deterministically, without hanging tests. */
		simulated_block++;
		return ERR_PTR(-ETIMEDOUT);
	}
	if (!strcmp(mode, "nodev"))
		return ERR_PTR(-ENODEV);
	return &native_request;
}

static void nvme_init_request(struct request *req, struct nvme_command *cmd)
{ (void)req; (void)cmd; }
static void blk_mq_free_request(struct request *req)
{ (void)req; }
static int nvme_xdev_ext_class_map(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			    struct request *req, struct nvme_xdev_ext_mech_batch *bp)
{ (void)st; (void)b; (void)req; (void)bp; maps++; return 0; }
static enum rq_end_io_ret nvme_xdev_ext_class_end_io(struct request *req, int err)
{
 (void)req;
	(void)err;
	completions++;

	return RQ_END_IO_FREE;
}
static void blk_execute_rq_nowait(struct request *req, bool at_head)
{
	(void)at_head;
	handoffs++;
	req->end_io(req, 0);
}

/* PRODUCTION_SUBMIT */

int main(int argc, char **argv)
{
	struct nvme_ns ns = {0};
	struct nvme_xdev_ext_mech_stage priv = { .ns = &ns };
	struct xdev_ext_mech_stage st = { .priv = &priv };
	struct xdev_ext_mech_batch b = { .priv = { .validated = true, .batch_id = 7 } };
	int rc;

	mode = argc > 1 ? argv[1] : "success";
	rc = nvme_xdev_ext_class_submit(&st, &b);
	printf("rc=%d flags=%u tag_calls=%d blocked=%d done_allocs=%d "
	       "maps=%d handoffs=%d completions=%d\n", rc, alloc_flags,
	       tag_calls, simulated_block, done_allocs, maps, handoffs, completions);
	return 0;
}
