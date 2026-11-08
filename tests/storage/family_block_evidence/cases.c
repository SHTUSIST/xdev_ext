// SPDX-License-Identifier: GPL-2.0
/*
 * A host-page NVMe command whose outcome is UNKNOWN keeps its slot. The slot
 * goes back to the stage's pool once a verified reset of the controller that
 * received the command proves its DMA stopped: the reset began after the
 * command was prepared for the SQ, whether the reset itself caused the
 * UNKNOWN outcome or came later. A command prepared after the reset began,
 * or sent to another controller, stays retained. run.py prepends the actual
 * sources; the case plays blk-mq dispatch and the controller's completions.
 */
static unsigned checks;
#define CHECK(c, msg) do { \
	if (!(c)) { printf("not ok %u - %s (line %d)\n", ++checks, msg, __LINE__); exit(1); } \
	printf("ok %u - %s\n", ++checks, msg); } while (0)

#define SC_ABORT_SQ_DELETION 0x0008	/* QEMU and controllers deleting an SQ */
#define SC_HOST_ABORTED 0x0371		/* nvme_cancel_request() */
#define BYTES 4096U

static struct pci_dev dst_fn = { .refs = 1 }, src_fn = { .refs = 1 };
static struct device dst_device = { .pdev = &dst_fn }, src_device = { .pdev = &src_fn };
static struct nvme_dev dst = { .dev = &dst_device }, src = { .dev = &src_device };

/* blk_execute_rq_nowait(): the controller whose queue prepares the request
 * now, or NULL to hold it back (a later dispatch() or never). */
static struct nvme_dev *queue_owner;
static void fixture_dispatch(struct request *req)
{
	if (queue_owner)
		nvme_pci_peer_note_submit(queue_owner, req);
}
static void dispatch(struct nvme_dev *d, struct request *req) { nvme_pci_peer_note_submit(d, req); }

struct fixture {
	struct xdev_ext_mech_layout layout;
	struct xdev_ext_mech_session s;
	struct xdev_ext_mech_stage st;
	struct nvme_xdev_ext_mech_stage member;
};
struct cmd {
	struct xdev_ext_mech_batch b;
	struct nvme_xdev_ext_mech_batch bp;
	struct xdev_ext_stor_command command;
	struct xdev_ext_stor_io *io;
	struct request req;
};

static void stage_up(struct fixture *f, const struct xdev_ext_stor_dev_ops *ops, u32 depth)
{
	memset(f, 0, sizeof(*f));
	f->layout.seg_len = BYTES;
	f->layout.group_bytes = BYTES;
	f->layout.frame_size = BYTES;
	f->s.pool.kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	f->s.layout = &f->layout;
	f->s.depth = depth;
	f->st.s = &f->s;
	f->st.priv = &f->member;
	f->member.family.st = &f->st;
	f->member.family.dev = ops;
	f->member.family.member = &f->member;
	assert(!xdev_ext_storfam_host_resources_init(&f->member.family));
}
static bool stage_down(struct fixture *f) { return xdev_ext_storfam_host_resources_free(&f->member.family); }

/* The family's host submission: a slot, its completion context, the request
 * built over the slot's bio, then the member's posting. */
static void post(struct fixture *f, struct cmd *c, struct nvme_dev *queue, u64 ticket)
{
	memset(c, 0, sizeof(*c));
	c->b.priv = &c->bp;
	c->b.bytes = BYTES;
	c->b.ticket = ticket;
	c->io = xdev_ext_storfam_host_get(&f->member.family, &c->bp.family);
	assert(!IS_ERR(c->io));
	c->io->done.b = &c->b;
	c->io->done.ticket = ticket;
	c->io->bio->initialized = 1;
	c->io->bio_live = true;
	c->bp.family.bio = c->io->bio;
	c->req.bio = c->io->bio;
	c->req.data_len = BYTES;
	c->req.pdu.flags = NVME_REQ_USERCMD;	/* request_init() of a host command */
	queue_owner = queue;
	nvme_xdev_ext_member_post(&f->member, &c->req, c->io, &c->b, &c->command, false);
	queue_owner = NULL;
}
/* The controller ends the command; residual bytes were not transferred. */
static void complete(struct cmd *c, u16 status, u32 residual, bool cancelled)
{
	c->req.pdu.status = status;
	c->req.data_len = residual;
	if (cancelled)
		c->req.pdu.flags |= NVME_REQ_CANCELLED;
	c->req.end_io(&c->req, 0);
}
/* The worker consumes the completion (xdev_ext_storfam_consume, host branch). */
static void consume(struct fixture *f, struct cmd *c) { xdev_ext_storfam_host_put(&f->member.family, &c->bp.family); }
static int evidence(struct fixture *f) { return xdev_ext_storfam_evidence(&f->member.family); }
static int release(struct fixture *f) { return xdev_ext_storfam_evidence_release(&f->member.family); }
static void drain(void) { while (host_run_pending_work()) { } }
static u64 reset_begin(struct nvme_dev *d) { return nvme_pci_peer_quiesce_begin(d); }
/* nvme_dev_disable() after CC.EN=0 completed: BME read back clear proves the stop. */
static void reset_end(struct nvme_dev *d, u64 epoch)
{
	fixture_command_word = 0;
	nvme_pci_peer_quiesce_end(d, epoch, true);
	drain();
}
static void proven_reset(struct nvme_dev *d) { reset_end(d, reset_begin(d)); }

static void case_reset_causes_the_outcome(void)
{
	struct fixture f;
	struct cmd a, next;
	unsigned uninits;
	u64 k;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	k = reset_begin(&dst);
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	CHECK(a.b.publishes == 1 && a.b.published_uncertain,
	      "a write aborted by SQ deletion with residual bytes is an UNKNOWN outcome");
	consume(&f, &a);
	CHECK(a.io->runtime.busy, "its host slot is retained");
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "while the reset that aborted it has not proven the stop, the slot waits");
	CHECK(release(&f) == -EBUSY && a.io->runtime.busy && a.io->bio_live,
	      "no release before the proof");
	reset_end(&dst, k);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED,
	      "the reset's DMA-stop proof covers a command prepared before the reset began");
	uninits = fixture_bio_uninits;
	CHECK(release(&f) == 0 && !a.io->runtime.busy && !a.io->bio_live &&
	      fixture_bio_uninits == uninits + 1,
	      "the slot goes back to the stage's pool and its bio is uninitialized once");
	post(&f, &next, &dst, 2);
	CHECK(next.io == a.io, "the next command takes the released slot");
	complete(&next, 0, BYTES, false);
	consume(&f, &next);
	CHECK(!next.io->runtime.busy && stage_down(&f), "a definite completion returns it again");
}

static void case_outcome_after_the_proof(void)
{
	struct fixture f;
	struct cmd a;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	proven_reset(&dst);
	complete(&a, SC_HOST_ABORTED, BYTES, true);
	consume(&f, &a);
	CHECK(a.b.published_uncertain && a.io->runtime.busy,
	      "a command cancelled after the reset with residual bytes is retained");
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED && release(&f) == 0 &&
	      !a.io->runtime.busy && stage_down(&f),
	      "the proof already recorded covers it: released at once");
}

static void case_outcome_before_a_later_reset(void)
{
	struct fixture f;
	struct cmd a;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	complete(&a, 0x0281, BYTES, false);	/* media error status, residual */
	consume(&f, &a);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING && release(&f) == -EBUSY,
	      "an UNKNOWN outcome without any reset stays retained");
	proven_reset(&dst);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED && release(&f) == 0 &&
	      !a.io->runtime.busy && stage_down(&f),
	      "a later proven reset of the same controller releases it");
}

static void case_prepared_after_the_reset_began_stays(void)
{
	struct fixture f;
	struct cmd a;
	u64 k;

	stage_up(&f, &actual_member_ops, 1);
	k = reset_begin(&dst);
	post(&f, &a, NULL, 1);		/* queued while the reset quiesces the queues */
	reset_end(&dst, k);
	dispatch(&dst, &a.req);		/* prepared once the queues run again */
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &a);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "a reset that began before the command was prepared does not cover it");
	CHECK(release(&f) == -EBUSY && a.io->runtime.busy && a.io->bio_live,
	      "so its slot stays retained");
	proven_reset(&dst);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED && release(&f) == 0 && stage_down(&f),
	      "only a reset that began after its preparation releases it");
}

static void case_other_controller_stays(void)
{
	struct fixture f;
	struct cmd a;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &a);
	proven_reset(&src);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING && release(&f) == -EBUSY &&
	      a.io->runtime.busy, "a proven reset of another controller does not cover it");
	proven_reset(&dst);
	CHECK(release(&f) == 0 && stage_down(&f), "its own controller's proof does");
}

static void case_unproven_resets_prove_nothing(void)
{
	struct fixture f;
	struct cmd a;
	u64 k;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &a);
	k = reset_begin(&dst);
	fixture_command_word = PCI_COMMAND_MASTER;
	nvme_pci_peer_quiesce_end(&dst, k, true);
	drain();
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "Bus Master Enable read back set proves nothing");
	k = reset_begin(&dst);
	fixture_command_word = 0;
	nvme_pci_peer_quiesce_end(&dst, k, false);
	drain();
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "a shutdown, dead controller or failed disable proves nothing");
	k = reset_begin(&dst);
	fixture_config_error = -EIO;
	nvme_pci_peer_quiesce_end(&dst, k, true);
	fixture_config_error = 0;
	drain();
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING && release(&f) == -EBUSY,
	      "an error response to the config read proves nothing");
	proven_reset(&dst);
	CHECK(release(&f) == 0 && stage_down(&f), "a verified reset still releases it");
}

static void case_never_prepared_has_no_evidence(void)
{
	struct fixture f;
	struct cmd a;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, NULL, 1);
	complete(&a, 0, BYTES / 2, false);	/* failed before any queue prepared it */
	consume(&f, &a);
	proven_reset(&dst);
	CHECK(a.b.published_uncertain && evidence(&f) == XDEV_EXT_PEER_EVIDENCE_NEVER &&
	      release(&f) == -EBUSY && a.io->runtime.busy,
	      "a command no controller recorded can never be proven stopped");
	CHECK(!stage_down(&f) && fixture_warnings, "and the stage cannot free the retained slot");
	fixture_warnings = 0;
}

static void case_one_pending_slot_holds_the_stage(void)
{
	struct fixture f;
	struct cmd a, b;
	u64 k;

	stage_up(&f, &actual_member_ops, 2);
	post(&f, &a, &dst, 1);
	k = reset_begin(&dst);
	post(&f, &b, NULL, 2);
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &a);
	reset_end(&dst, k);
	dispatch(&dst, &b.req);
	complete(&b, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &b);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "one covered and one uncovered slot: the stage reports the uncovered one");
	CHECK(release(&f) == -EBUSY && a.io->runtime.busy && b.io->runtime.busy,
	      "and returns neither, not even the covered one");
	proven_reset(&dst);
	CHECK(release(&f) == 0 && !a.io->runtime.busy && !b.io->runtime.busy && stage_down(&f),
	      "a reset covering both returns both");
}

static void case_member_without_evidence(void)
{
	struct xdev_ext_stor_dev_ops ops = actual_member_ops;
	struct fixture f;
	struct cmd a;

	ops.peer_evidence = NULL;
	stage_up(&f, &ops, 1);
	post(&f, &a, &dst, 1);
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &a);
	proven_reset(&dst);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_NEVER && release(&f) == -EBUSY,
	      "a member that reports no evidence keeps its retained slots for good");
	CHECK(!stage_down(&f), "and the stage keeps them");
	fixture_warnings = 0;
}

static void case_definite_outcomes_need_no_proof(void)
{
	struct fixture f;
	struct cmd a;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	complete(&a, 0, BYTES, false);	/* block layer keeps the full length for end_io */
	consume(&f, &a);
	CHECK(!a.b.published_uncertain && !a.io->runtime.busy &&
	      evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED,
	      "a full successful completion returns its slot at consumption");
	post(&f, &a, &dst, 2);
	complete(&a, SC_HOST_ABORTED, 0, true);	/* nothing left to transfer */
	CHECK(!a.b.published_uncertain, "an error with no residual bytes is definite");
	/* A ZOMBIE session's consumption keeps even a definite slot. */
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED && release(&f) == 0 &&
	      !a.io->runtime.busy && stage_down(&f),
	      "a slot kept after a definite completion needs no proof and is returned");
}

static void case_request_reuse_records_nothing(void)
{
	struct fixture f;
	struct cmd a;
	u64 k;

	stage_up(&f, &actual_member_ops, 1);
	post(&f, &a, &dst, 1);
	complete(&a, SC_ABORT_SQ_DELETION, BYTES, false);
	consume(&f, &a);
	CHECK(!a.req.pdu.peer_trace &&
	      !(a.req.pdu.flags & ~(NVME_REQ_USERCMD | NVME_REQ_CANCELLED | NVME_REQ_XDEV_EXT_ZC)),
	      "end_io leaves no record reference on the request");
	k = reset_begin(&dst);
	a.req.pdu.flags = NVME_REQ_USERCMD;	/* the request object serves another command */
	dispatch(&dst, &a.req);
	reset_end(&dst, k);
	CHECK(evidence(&f) == XDEV_EXT_PEER_EVIDENCE_COVERED && release(&f) == 0 && stage_down(&f),
	      "a later preparation of the reused request does not move the retained slot's epoch");
}

int main(void)
{
	setbuf(stdout, NULL);
	puts("TAP version 13");
	dst.peer_requester = xdev_ext_peer_requester_register(&dst_fn);
	src.peer_requester = xdev_ext_peer_requester_register(&src_fn);
	assert(dst.peer_requester && src.peer_requester);
	case_reset_causes_the_outcome();
	case_outcome_after_the_proof();
	case_outcome_before_a_later_reset();
	case_prepared_after_the_reset_began_stays();
	case_other_controller_stays();
	case_unproven_resets_prove_nothing();
	case_never_prepared_has_no_evidence();
	case_one_pending_slot_holds_the_stage();
	case_member_without_evidence();
	case_definite_outcomes_need_no_proof();
	case_request_reuse_records_nothing();
	xdev_ext_peer_requester_unregister(src.peer_requester);
	xdev_ext_peer_requester_unregister(dst.peer_requester);
	CHECK(!fixture_warnings, "no unexpected warning");
	printf("1..%u\n", checks);
	return 0;
}
