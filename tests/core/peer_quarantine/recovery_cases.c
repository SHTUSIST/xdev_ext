// SPDX-License-Identifier: GPL-2.0
/*
 * Recovery after an UNKNOWN peer-DMA outcome, against the actual region core
 * and the actual allocation-fd close.  run.py prepends both sources.  The
 * provider is a counter fixture: no device, no DMA, no IOMMU.  A "proof" here
 * is only the software call a requester driver makes after its own DMA-stop
 * evidence; whether a given driver event is such evidence is tested with the
 * driver, not here.
 */
static unsigned checks;
#define CHECK(c, msg) do { \
	if (!(c)) { printf("not ok %u - %s (line %d)\n", ++checks, msg, __LINE__); exit(1); } \
	printf("ok %u - %s\n", ++checks, msg); } while (0)

static int pins, unpins, maps, unmaps, fail_unmap, fail_unpin;
static int fx_pin(struct file *f, u64 va, u64 len, void **out)
{ (void)f; (void)va; (void)len; pins++; *out = &pins; return 0; }
static int fx_unpin(void *a) { (void)a; unpins++; return fail_unpin ? -EIO : 0; }
static u64 fx_addresses[] = { 0x100000, 0x110000 };
static int fx_map(void *a, struct pci_dev *peer, struct xdev_ext_peer_dma *d)
{
	(void)a; maps++;
	*d = (struct xdev_ext_peer_dma){ .private = peer, .addresses = fx_addresses,
					 .entries = 2, .page_shift = 16 };
	return 0;
}
static int fx_unmap(void *a, struct pci_dev *peer, struct xdev_ext_peer_dma *d)
{ (void)a; (void)peer; (void)d; unmaps++; return fail_unmap ? -EIO : 0; }

static struct file_operations gpu_fops;
static struct module provider_owner = { .refs = 1 };
static const struct xdev_ext_peer_provider_ops fx_ops = {
	.owner = &provider_owner, .fops = &gpu_fops, .pin = fx_pin, .unpin = fx_unpin,
	.map = fx_map, .unmap = fx_unmap,
};
static struct file gpu = { .f_op = &gpu_fops, .refs = 1 };
static struct pci_dev nvme_a = { .refs = 1 }, nvme_b = { .refs = 1 };

/* One user allocation fd as REGISTER builds it, with its per-peer map cache. */
struct owner {
	struct file file;
	struct xdev_ext_peer_fd *fd;
	struct xdev_ext_peer_region *region;
	u64 generation;
};
struct counts { int pins, unpins, maps, unmaps, gpu, module, a, b; };
static struct counts now(void)
{
	return (struct counts){ pins, unpins, maps, unmaps, gpu.refs, provider_owner.refs,
				nvme_a.refs, nvme_b.refs };
}
static bool same(struct counts x, struct counts y) { return !memcmp(&x, &y, sizeof(x)); }
/* Provider-side resources only, when a test itself registers requesters. */
static bool same_provider(struct counts x, struct counts y)
{
	return x.pins == y.pins && x.unpins == y.unpins && x.maps == y.maps &&
	       x.unmaps == y.unmaps && x.gpu == y.gpu && x.module == y.module;
}

static void owner_open(struct owner *o)
{
	o->fd = calloc(1, sizeof(*o->fd));
	assert(o->fd);
	mutex_init(&o->fd->lock); INIT_LIST_HEAD(&o->fd->maps);
	assert(!xdev_ext_peer_pin(&gpu, 0x20000, 0x20000, &o->region));
	o->fd->region = o->region;
	o->generation = xdev_ext_peer_generation(o->region);
	o->file = (struct file){ .refs = 1, .private_data = o->fd };
}
static struct xdev_ext_peer_mapping *owner_map(struct owner *o, struct pci_dev *peer)
{
	struct xdev_ext_peer_fd_map *m = calloc(1, sizeof(*m));
	assert(m && !xdev_ext_peer_map(o->region, peer, DMA_BIDIRECTIONAL, &m->mapping));
	m->peer = peer; list_add_tail(&m->node, &o->fd->maps);
	return m->mapping;
}
static void lease(struct owner *o, struct xdev_ext_peer_mapping *m, struct xdev_ext_peer_lease *l)
{
	*l = (struct xdev_ext_peer_lease){0};
	assert(!xdev_ext_peer_acquire(m, o->generation, 0, 64, DMA_FROM_DEVICE, l));
}
static int unknown(struct xdev_ext_peer_lease *l, struct xdev_ext_peer_requester *rq, u64 epoch,
		   bool *quiesced)
{ return xdev_ext_peer_release_unknown(l, l->ticket, rq, epoch, quiesced); }
/* The real file release of the allocation fd. */
static void owner_close(struct owner *o) { assert(!xdev_ext_peer_fd_close(NULL, &o->file)); }
static int drain(void) { int n = 0; while (host_run_pending_work()) n++; return n; }
static u64 proven_reset(struct xdev_ext_peer_requester *rq)
{
	u64 k = xdev_ext_peer_requester_begin(rq);
	xdev_ext_peer_requester_quiesced(rq, k);
	return k;
}

static void case_no_evidence_keeps_everything(void)
{
	struct counts base = now(), held;
	struct xdev_ext_peer_requester *rq = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	bool q = true;

	CHECK(rq, "a requester driver instance registers");
	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	CHECK(!unknown(&l, rq, xdev_ext_peer_requester_epoch(rq), &q) && !q,
	      "UNKNOWN release without evidence retires the lease but not its resources");
	CHECK(xdev_ext_peer_unmap(m) == -EIO && xdev_ext_peer_unpin(o.region) == -EIO,
	      "owner cannot unmap or unpin an UNKNOWN region");
	held = now();
	owner_close(&o); drain();
	CHECK(same(held, now()), "closing the owner keeps GPU file, provider module, PCI refs and mapping");
	xdev_ext_peer_requester_begin(rq); drain();
	CHECK(same(held, now()), "an epoch that began but was never proven releases nothing");
	CHECK(unmaps == base.unmaps && unpins == base.unpins, "provider never saw unmap or unpin");
}

static void case_proof_must_postdate_submission(void)
{
	struct xdev_ext_peer_requester *rq = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	struct counts base, held; u64 k; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	base = now();
	k = xdev_ext_peer_requester_begin(rq);
	/* Submitted after epoch k began, as when dispatch resumed in a new epoch. */
	CHECK(!unknown(&l, rq, xdev_ext_peer_requester_epoch(rq), &q) && !q,
	      "UNKNOWN submitted inside an already begun epoch is held");
	xdev_ext_peer_requester_quiesced(rq, k); drain();
	CHECK(xdev_ext_peer_unmap(m) == -EIO, "proof of the epoch the command was submitted in is not evidence");
	held = now();
	proven_reset(rq); drain();
	CHECK(same(held, now()), "recovery itself never calls the provider while the owner is open");
	CHECK(xdev_ext_peer_acquire(m, o.generation, 0, 64, DMA_FROM_DEVICE, &l) == -ESTALE,
	      "recovered region admits no new lease");
	{
		u64 len, gen; struct xdev_ext_peer_mapping *other;
		CHECK(xdev_ext_peer_info(o.region, &len, &gen, false) == -ESTALE &&
		      xdev_ext_peer_map(o.region, &nvme_b, DMA_BIDIRECTIONAL, &other) == -ESTALE,
		      "recovered region stays invalid for claims and new mappings");
	}
	owner_close(&o); drain();
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1,
	      "a later proven epoch lets the owner close unmap and unpin exactly once");
	CHECK(gpu.refs == base.gpu - 1 && provider_owner.refs == base.module - 1 && nvme_a.refs == base.a - 1,
	      "GPU file, provider module and mapping PCI refs are dropped");
	xdev_ext_peer_requester_unregister(rq);
}

static void case_orphan_torn_down_once(void)
{
	struct counts base = now(), held, after; /* before the requester's own ref */
	struct xdev_ext_peer_requester *rq = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	u64 s; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	s = xdev_ext_peer_requester_epoch(rq);
	CHECK(!unknown(&l, rq, s, &q) && !q, "UNKNOWN before any reset");
	owner_close(&o); drain(); held = now();
	CHECK(held.unmaps == base.unmaps && held.unpins == base.unpins && held.gpu == base.gpu + 1,
	      "orphaned UNKNOWN region is held after the owner closed");
	proven_reset(rq);
	CHECK(drain() >= 1, "a proof schedules recovery work");
	after = now();
	CHECK(after.unmaps == base.unmaps + 1 && after.unpins == base.unpins + 1 &&
	      after.gpu == base.gpu && after.module == base.module,
	      "covered orphan is unmapped, unpinned and its file/module refs dropped exactly once");
	proven_reset(rq); xdev_ext_peer_requester_quiesced(rq, xdev_ext_peer_requester_epoch(rq)); drain();
	CHECK(same(after, now()), "duplicate and later proofs change nothing");
	xdev_ext_peer_requester_unregister(rq);
	CHECK(nvme_a.refs == base.a, "requester and mapping PCI refs are back to the start");
}

static void case_late_completion_is_quiesced(void)
{
	struct xdev_ext_peer_requester *rq = xdev_ext_peer_requester_register(&nvme_a);
	struct counts base = now();
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l, again;
	u64 s; bool q = false;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	s = xdev_ext_peer_requester_epoch(rq);
	proven_reset(rq); drain();
	/* The completion (e.g. cancellation by that reset) is seen after the proof. */
	CHECK(!unknown(&l, rq, s, &q) && q, "UNKNOWN whose submission precedes a proven epoch is quiesced");
	lease(&o, m, &again);
	CHECK(again.mapping == m, "region stays usable after a covered completion");
	CHECK(!xdev_ext_peer_release(&again, again.ticket, true), "ordinary release");
	owner_close(&o); drain();
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1 && gpu.refs == base.gpu,
	      "owner close releases normally");
	xdev_ext_peer_requester_unregister(rq);
}

static void case_other_instance_is_not_evidence(void)
{
	struct xdev_ext_peer_requester *a1 = xdev_ext_peer_requester_register(&nvme_a);
	struct xdev_ext_peer_requester *b = xdev_ext_peer_requester_register(&nvme_b), *a2;
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	struct counts held; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	CHECK(!unknown(&l, a1, xdev_ext_peer_requester_epoch(a1), &q) && !q, "UNKNOWN bound to controller A");
	owner_close(&o); drain(); held = now();
	proven_reset(b); proven_reset(b); drain();
	CHECK(same(held, now()), "a proven reset of another controller is not evidence");
	xdev_ext_peer_requester_unregister(a1);
	a2 = xdev_ext_peer_requester_register(&nvme_a);
	CHECK(a2 && a2 != a1, "a rebound driver gets a new requester instance");
	proven_reset(a2); proven_reset(a2); drain();
	CHECK(same_provider(held, now()), "a new driver instance on the same function is not evidence for the old one");
	xdev_ext_peer_requester_unregister(a2); xdev_ext_peer_requester_unregister(b);
	CHECK(same_provider(held, now()), "unregistering requesters leaves the held region intact");
}

static void case_permanent_causes(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct xdev_ext_peer_requester *b = xdev_ext_peer_requester_register(&nvme_b);
	struct owner o1, o2, o3, o4; struct xdev_ext_peer_mapping *m;
	struct xdev_ext_peer_lease l, l2; struct counts held; bool q = true;

	owner_open(&o1); m = owner_map(&o1, &nvme_a); lease(&o1, m, &l);
	CHECK(!unknown(&l, b, xdev_ext_peer_requester_epoch(b), &q) && !q,
	      "UNKNOWN bound to a requester that is not the mapping's PCI function");
	owner_open(&o2); m = owner_map(&o2, &nvme_a); lease(&o2, m, &l);
	CHECK(!unknown(&l, a, XDEV_EXT_PEER_EPOCH_NONE, &q) && !q, "UNKNOWN without a submission epoch");
	owner_open(&o3); m = owner_map(&o3, &nvme_a); lease(&o3, m, &l);
	CHECK(!unknown(&l, NULL, 0, &q) && !q, "UNKNOWN without a requester");
	owner_open(&o4); m = owner_map(&o4, &nvme_a); lease(&o4, m, &l); lease(&o4, m, &l2);
	CHECK(!xdev_ext_peer_release(&l, l.ticket, false), "legacy UNKNOWN release of one lease");
	CHECK(!unknown(&l2, a, xdev_ext_peer_requester_epoch(a), &q) && !q, "bound UNKNOWN of another lease");
	owner_close(&o1); owner_close(&o2); owner_close(&o3); owner_close(&o4); drain();
	held = now();
	proven_reset(a); proven_reset(b); proven_reset(a); proven_reset(b); drain();
	CHECK(same(held, now()), "mismatched, epoch-less, requester-less and legacy UNKNOWN stay held for good");
	held = now();
	xdev_ext_peer_requester_unregister(a); xdev_ext_peer_requester_unregister(b);
	CHECK(nvme_a.refs == held.a - 1 && nvme_b.refs == held.b - 1,
	      "regions held for good keep no requester instance alive");
}

static void case_record_is_bound_to_one_instance(void)
{
	struct xdev_ext_peer_requester *a1 = xdev_ext_peer_requester_register(&nvme_a), *a2;
	struct owner o; struct xdev_ext_peer_mapping *m;
	struct xdev_ext_peer_lease l1, l2; struct counts held; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l1); lease(&o, m, &l2);
	proven_reset(a1); proven_reset(a1);
	CHECK(!unknown(&l1, a1, xdev_ext_peer_requester_epoch(a1), &q) && !q, "UNKNOWN received by instance 1");
	a2 = xdev_ext_peer_requester_register(&nvme_a);
	CHECK(!unknown(&l2, a2, xdev_ext_peer_requester_epoch(a2), &q) && !q,
	      "UNKNOWN of the same mapping reported by instance 2");
	owner_close(&o); drain(); held = now();
	proven_reset(a1); proven_reset(a1); proven_reset(a2); drain();
	CHECK(same(held, now()), "epochs of two instances never combine: the region is held for good");
	xdev_ext_peer_requester_unregister(a1); xdev_ext_peer_requester_unregister(a2);
}

static void case_later_command_raises_the_record(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m;
	struct xdev_ext_peer_lease l1, l2; struct counts base, held;
	u64 s1, s2, k; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l1); lease(&o, m, &l2);
	base = now();
	s1 = xdev_ext_peer_requester_epoch(a);
	k = xdev_ext_peer_requester_begin(a);
	s2 = xdev_ext_peer_requester_epoch(a);
	CHECK(!unknown(&l1, a, s1, &q) && !q && !unknown(&l2, a, s2, &q) && !q,
	      "two UNKNOWN commands of one controller, the second in a later epoch");
	owner_close(&o); drain(); held = now();
	xdev_ext_peer_requester_quiesced(a, k); drain();
	CHECK(same(held, now()), "a proof covering only the earlier command keeps the region");
	proven_reset(a); drain();
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1, "covering the later command releases it");
	xdev_ext_peer_requester_unregister(a);
}

static void case_every_record_must_be_covered(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct xdev_ext_peer_requester *b = xdev_ext_peer_requester_register(&nvme_b);
	struct owner o; struct xdev_ext_peer_mapping *ma, *mb;
	struct xdev_ext_peer_lease l1, l2, lb; struct counts base, held;
	u64 s1, s2, k; bool q = true;

	owner_open(&o); ma = owner_map(&o, &nvme_a); mb = owner_map(&o, &nvme_b);
	lease(&o, ma, &l1); lease(&o, ma, &l2); lease(&o, mb, &lb);
	base = now();
	s1 = xdev_ext_peer_requester_epoch(a);
	k = xdev_ext_peer_requester_begin(a); /* begun, not proven */
	s2 = xdev_ext_peer_requester_epoch(a);
	CHECK(s2 > s1, "epochs advance when a reset begins");
	CHECK(!unknown(&l1, a, s1, &q) && !q && !unknown(&l2, a, s2, &q) && !q,
	      "two UNKNOWN commands of controller A from different epochs");
	CHECK(!unknown(&lb, b, xdev_ext_peer_requester_epoch(b), &q) && !q, "one UNKNOWN command of controller B");
	owner_close(&o); drain(); held = now();
	xdev_ext_peer_requester_quiesced(a, k); drain();
	CHECK(same(held, now()), "proof covering only the older command of A keeps the region");
	proven_reset(a); drain();
	CHECK(same(held, now()), "A fully covered but B not: region still held");
	xdev_ext_peer_requester_quiesced(b, 7); drain();
	CHECK(same(held, now()), "a proof for an epoch B never began is ignored");
	proven_reset(b); drain();
	CHECK(unmaps == base.unmaps + 2 && unpins == base.unpins + 1 && gpu.refs == base.gpu - 1,
	      "both mappings unmapped and the allocation unpinned once both requesters proved");
	xdev_ext_peer_requester_unregister(a); xdev_ext_peer_requester_unregister(b);
}

static void case_stale_and_duplicate_releases(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	struct counts base; bool q = true; u64 s;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	base = now(); s = xdev_ext_peer_requester_epoch(a);
	CHECK(xdev_ext_peer_release_unknown(&l, l.ticket + 1, a, s, &q) == -ESTALE,
	      "UNKNOWN release with a stale ticket is refused");
	CHECK(xdev_ext_peer_unmap(m) == -EBUSY, "the lease is still active after a refused release");
	CHECK(!unknown(&l, a, s, &q) && !q, "matching UNKNOWN release");
	CHECK(unknown(&l, a, s, &q) == -EINVAL, "a duplicate notification of the same lease is refused");
	proven_reset(a); drain(); drain();
	owner_close(&o); drain();
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1, "duplicates did not unbalance release");
	xdev_ext_peer_requester_unregister(a);
}

static void case_teardown_failure_is_permanent(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	struct counts held; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	CHECK(!unknown(&l, a, xdev_ext_peer_requester_epoch(a), &q) && !q, "UNKNOWN");
	owner_close(&o); drain();
	held = now();
	fail_unmap = 1; proven_reset(a); drain(); fail_unmap = 0;
	CHECK(unmaps == held.unmaps + 1 && unpins == held.unpins && gpu.refs == held.gpu &&
	      provider_owner.refs == held.module,
	      "failed provider unmap during recovery is not followed by unpin or ref drops");
	held = now();
	proven_reset(a); drain();
	CHECK(same(held, now()), "a region whose recovery unmap failed is held for good");
	xdev_ext_peer_requester_unregister(a);
}

/* fd close saw the unmap refused, recovery then ran before it called orphan. */
static void case_orphan_after_concurrent_recovery(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	struct counts base; bool q = true;

	owner_open(&o); m = owner_map(&o, &nvme_a); owner_map(&o, &nvme_a); lease(&o, m, &l);
	base = now();
	CHECK(!unknown(&l, a, xdev_ext_peer_requester_epoch(a), &q) && !q, "UNKNOWN on a mapping with two cache borrowers");
	xdev_ext_peer_invalidate(o.region);
	CHECK(xdev_ext_peer_unmap(m) == -EIO, "owner's unmap is refused while quarantined");
	proven_reset(a); drain();
	xdev_ext_peer_orphan(o.region);
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1 && gpu.refs == base.gpu - 1,
	      "orphan after recovery tears down at once, the mapping unmapped once despite two borrowers");
	{
		struct xdev_ext_peer_fd_map *f, *n;
		list_for_each_entry_safe(f, n, &o.fd->maps, node) { list_del(&f->node); free(f); }
		free(o.fd);
	}
	xdev_ext_peer_requester_unregister(a);
}

static void case_no_requester_api_is_inert(void)
{
	CHECK(xdev_ext_peer_requester_epoch(NULL) == XDEV_EXT_PEER_EPOCH_NONE &&
	      !xdev_ext_peer_requester_begin(NULL), "a driver without a requester record has no epochs");
	xdev_ext_peer_requester_quiesced(NULL, 1); xdev_ext_peer_requester_unregister(NULL);
	CHECK(!drain(), "proof without a requester schedules nothing");
}

/* What a retained command's requester and epoch can still prove. */
static void case_evidence_of_a_retained_command(void)
{
	struct xdev_ext_peer_requester *rq = xdev_ext_peer_requester_register(&nvme_a);
	u64 e = xdev_ext_peer_requester_epoch(rq), k;

	CHECK(xdev_ext_peer_requester_evidence(NULL, 0) == XDEV_EXT_PEER_EVIDENCE_NEVER &&
	      xdev_ext_peer_requester_evidence(rq, XDEV_EXT_PEER_EPOCH_NONE) == XDEV_EXT_PEER_EVIDENCE_NEVER,
	      "no requester or no submission epoch: nothing can ever prove the command stopped");
	CHECK(xdev_ext_peer_requester_evidence(rq, e) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "a bound command waits for its requester's proof");
	xdev_ext_peer_requester_begin(rq);
	CHECK(xdev_ext_peer_requester_evidence(rq, e) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "a begun but unproven epoch is not evidence");
	k = proven_reset(rq); drain();
	CHECK(xdev_ext_peer_requester_evidence(rq, e) == XDEV_EXT_PEER_EVIDENCE_COVERED &&
	      xdev_ext_peer_requester_evidence(rq, k) == XDEV_EXT_PEER_EVIDENCE_PENDING,
	      "a proven later epoch covers it; the proven epoch itself does not");
	xdev_ext_peer_requester_unregister(rq);
}

static unsigned watch_calls;
static int watch_drainable = 1;
static struct xdev_ext_peer_region *watch_region;
static void watch_fn(struct xdev_ext_peer_recovery_watch *w)
{
	(void)w;
	watch_calls++;
	if (watch_region)
		watch_drainable = xdev_ext_peer_drainable(watch_region);
}
static struct xdev_ext_peer_recovery_watch watch = { .recovered = watch_fn };

/* Watchers run after each recovery pass, once the covered regions left quarantine. */
static void case_watchers_follow_each_pass(void)
{
	struct xdev_ext_peer_requester *rq = xdev_ext_peer_requester_register(&nvme_a);
	struct owner o; struct xdev_ext_peer_mapping *m; struct xdev_ext_peer_lease l;
	bool q = true;

	xdev_ext_peer_recovery_watch(&watch);
	owner_open(&o); m = owner_map(&o, &nvme_a); lease(&o, m, &l);
	assert(!unknown(&l, rq, xdev_ext_peer_requester_epoch(rq), &q) && !q);
	watch_region = o.region;
	xdev_ext_peer_requester_begin(rq); drain();
	CHECK(!watch_calls, "no pass, no watcher call, without a proof");
	proven_reset(rq); drain();
	CHECK(watch_calls == 1 && !watch_drainable,
	      "the proof's pass calls each watcher once, after the region left quarantine");
	xdev_ext_peer_recovery_unwatch(&watch);
	watch_region = NULL;
	proven_reset(rq); drain();
	CHECK(watch_calls == 1, "a removed watcher is not called");
	owner_close(&o); drain();
	xdev_ext_peer_requester_unregister(rq);
}

/* The storage family's UNKNOWN retirement of one native command's leases. */
static void fd_lease(struct owner *o, struct xdev_ext_peer_mapping *m, struct xdev_ext_peer_fd_lease *h)
{
	lease(o, m, &h->lease);
	get_file(&o->file); h->file = &o->file;
}
static void case_storage_unknown_command(void)
{
	struct xdev_ext_peer_requester *a = xdev_ext_peer_requester_register(&nvme_a);
	struct xdev_ext_peer_requester *b = xdev_ext_peer_requester_register(&nvme_b);
	struct xdev_ext_peer_fd_lease h[2];
	struct owner o; struct xdev_ext_peer_mapping *m;
	struct counts base;
	u64 e;

	memset(h, 0, sizeof(h));
	owner_open(&o); m = owner_map(&o, &nvme_a);
	fd_lease(&o, m, &h[0]); fd_lease(&o, m, &h[1]);
	base = now();
	e = xdev_ext_peer_requester_epoch(a);
	CHECK(!xdev_ext_stor_leases_retire_unknown(h, 2, a, e),
	      "an UNKNOWN command without a later proof is not quiesced");
	CHECK(!h[0].file && !h[0].lease.mapping && !h[1].file && !h[1].lease.mapping &&
	      o.file.refs == 1, "every lease handle of the command is retired");
	CHECK(xdev_ext_peer_unmap(m) == -EIO && same(base, now()), "its region is held");
	proven_reset(b); drain();
	CHECK(xdev_ext_peer_unmap(m) == -EIO, "another controller's proven reset holds it");
	proven_reset(a); drain();
	owner_close(&o); drain();
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1,
	      "its own controller's proven reset releases it at owner close");

	/* Cancelled inside an already proven reset: quiesced at once. */
	owner_open(&o); m = owner_map(&o, &nvme_a); fd_lease(&o, m, &h[0]);
	e = xdev_ext_peer_requester_epoch(a);
	proven_reset(a); drain();
	base = now();
	CHECK(xdev_ext_stor_leases_retire_unknown(h, 1, a, e) && !h[0].file,
	      "a command already covered by a proven reset is quiesced");
	owner_close(&o); drain();
	CHECK(unmaps == base.unmaps + 1 && unpins == base.unpins + 1,
	      "and its region releases at owner close without another reset");

	/* A covered epoch of another PCI function does not cover this mapping. */
	owner_open(&o); m = owner_map(&o, &nvme_a); fd_lease(&o, m, &h[0]);
	e = xdev_ext_peer_requester_epoch(b);
	proven_reset(b); drain();
	CHECK(!xdev_ext_stor_leases_retire_unknown(h, 1, b, e) && !h[0].file &&
	      xdev_ext_peer_drainable(o.region) == -EIO,
	      "a lease mapped for one controller is not quiesced by another controller's proof");

	/* A command's own resources (its SGL list) follow the command, not its leases. */
	e = xdev_ext_peer_requester_epoch(a);
	CHECK(!xdev_ext_stor_leases_retire_unknown(NULL, 0, a, e) &&
	      xdev_ext_stor_leases_retire_unknown(NULL, 0, a, e - 1),
	      "a command without leases is quiesced only when its epoch is covered");

	/* Never submitted to a queue: no epoch binds it. */
	owner_open(&o); m = owner_map(&o, &nvme_a); fd_lease(&o, m, &h[0]);
	CHECK(!xdev_ext_stor_leases_retire_unknown(h, 1, a, XDEV_EXT_PEER_EPOCH_NONE) && !h[0].file,
	      "an unbound UNKNOWN command retires its leases");
	proven_reset(a); drain();
	CHECK(xdev_ext_peer_unmap(m) == -EIO && xdev_ext_peer_drainable(o.region) == -EIO,
	      "and no proof ever releases its region");
	xdev_ext_peer_requester_unregister(b);
	xdev_ext_peer_requester_unregister(a);
}

int main(void)
{
	setbuf(stdout, NULL);
	puts("TAP version 13");
	assert(!xdev_ext_peer_provider_register(&fx_ops));
	case_no_requester_api_is_inert();
	case_no_evidence_keeps_everything();
	case_proof_must_postdate_submission();
	case_orphan_torn_down_once();
	case_late_completion_is_quiesced();
	case_other_instance_is_not_evidence();
	case_permanent_causes();
	case_record_is_bound_to_one_instance();
	case_later_command_raises_the_record();
	case_every_record_must_be_covered();
	case_stale_and_duplicate_releases();
	case_teardown_failure_is_permanent();
	case_orphan_after_concurrent_recovery();
	case_evidence_of_a_retained_command();
	case_watchers_follow_each_pass();
	case_storage_unknown_command();
	printf("1..%u\n", checks);
	return 0;
}
