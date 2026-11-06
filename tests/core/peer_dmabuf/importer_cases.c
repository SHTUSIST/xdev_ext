// SPDX-License-Identifier: GPL-2.0
/* Expectations are literal consequences of dmabuf-contract.md, not derived
 * from production internals. Cases use public region/lease APIs only. */
#include "kernel_shim.h"
#ifdef SHIM_CONTRACT_ONLY
#include "contract.h"
#else
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_peer_dmabuf.h>
#include <uapi/linux/xdev_ext_mech.h>
#endif
#include "fd_boundary.h"

static const struct dma_buf_ops trusted_ops;
static const struct dma_buf_ops other_ops;
static struct xdev_ext_peer_dmabuf_desc_ops descriptor;
static struct pci_dev requester;

static int host_describe(struct dma_buf *b, struct pci_dev *p,
			 struct xdev_ext_peer_backing *out)
{
	(void)p;
	assert(b->ops == &trusted_ops);
	/* Descriptor callbacks run outside the registry lock but with a live
	 * descriptor reference. The real unregister entry tests both properties. */
	assert(xdev_ext_peer_dmabuf_desc_unregister(&descriptor) == -EBUSY);
	*out = (struct xdev_ext_peer_backing){.owner = NULL,
		.flags = XDEV_EXT_PEER_BACKING_STRUCT_PAGE | XDEV_EXT_PEER_BACKING_HOST_SYSTEM};
	return 0;
}

static void setup(void)
{
	test_env_init(&trusted_ops);
	descriptor = (struct xdev_ext_peer_dmabuf_desc_ops){.owner = &env.descriptor,
		.ops = &trusted_ops, .describe = host_describe};
	requester = (struct pci_dev){.dev = {.dma_coherent = true}, .id = 1};
	assert(xdev_ext_peer_dmabuf_desc_register(&descriptor) == 0);
}

static void finish(void)
{
	assert(xdev_ext_peer_dmabuf_desc_unregister(&descriptor) == 0);
	assert(env.descriptor.refs == 0);
	assert(env.user.refs == 1 && env.mm.refs == 1);
	assert(atomic_long_read(&env.user.locked_vm) == 0);
	assert(atomic64_read(&env.mm.pinned_vm) == 0);
	assert(env.file.refs == 0 && env.exporter.refs == 0);
	assert(requester.refs == 0 && env.live_allocs == 0);
	assert(env.detaches == env.attaches - ((env.attach_error && env.attaches) ? 1U : 0U));
	assert(env.unpins == env.pins - ((env.pin_error && env.pins) ? 1U : 0U));
	assert(env.unmaps == env.maps - ((env.map_error && env.maps) ? 1U : 0U));
}

static struct xdev_ext_peer_region *import(void)
{
	struct xdev_ext_peer_region *r = NULL;
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == 0 && r);
	assert(atomic_long_read(&env.user.locked_vm) == 3);
	assert(atomic64_read(&env.mm.pinned_vm) == 3);
	assert(env.user.refs == 2 && env.mm.refs == 2);
	assert(env.file.refs == 2 && env.descriptor.refs == 1);
	return r;
}

static void geometry_bad(struct sg_table *table, u64 len)
{
	u64 *addresses = (void *)0x1;
	u32 entries = 99;
	assert(xdev_ext_peer_dmabuf_geometry(table, len, &addresses, &entries) < 0);
	assert(addresses == NULL && entries == 0);
}

static void geometry_overflow(struct sg_table *table, u64 len)
{
	u64 *addresses = (void *)0x1;
	u32 entries = 99;
	assert(xdev_ext_peer_dmabuf_geometry(table, len, &addresses, &entries) == -EOVERFLOW);
	assert(addresses == NULL && entries == 0);
}

static void geometry_case(void)
{
	u64 *addresses = NULL;
	u32 entries = 0;
	struct sg_table table;
	struct scatterlist huge[4097];
	test_env_init(&trusted_ops);
	table = (struct sg_table){.sgl = env.sg, .nents = 2, .orig_nents = 2};
	assert(xdev_ext_peer_dmabuf_geometry(&table, 12288, &addresses, &entries) == 0);
	assert(entries == 3 && addresses[0] == 0x10000 && addresses[1] == 0x11000 && addresses[2] == 0x90000);
	kvfree(addresses);
	env.sg[0].dma_address = 0;
	assert(xdev_ext_peer_dmabuf_geometry(&table, 12288, &addresses, &entries) == 0);
	assert(entries == 3 && addresses[0] == 0 && addresses[1] == 4096);
	kvfree(addresses);
	geometry_bad(&table, 8192);
	geometry_bad(&table, 16384);
	table.nents = 0;
	geometry_bad(&table, 12288);
	table.nents = 2;
	env.sg[0].dma_length = 0;
	geometry_bad(&table, 12288);
	env.sg[0].dma_length = 8192;
	env.sg[0].dma_address = 4095;
	geometry_bad(&table, 12288);
	env.sg[0].dma_address = 0;
	env.sg[0].dma_length = 8191;
	geometry_bad(&table, 12288);
	env.sg[0].dma_length = 8192;
	env.sg[0].dma_address = UINT64_MAX - 4095;
	geometry_overflow(&table, 12288);
	for (unsigned i = 0; i < ARRAY_SIZE(huge); i++)
		huge[i] = (struct scatterlist){.dma_address = 0,
			.dma_length = 0xfffff000U,
			.next = i + 1 < ARRAY_SIZE(huge) ? &huge[i+1] : NULL};
	table = (struct sg_table){.sgl = huge, .nents = ARRAY_SIZE(huge), .orig_nents = ARRAY_SIZE(huge)};
	geometry_overflow(&table, UINT64_C(4097) * 0xfffff000U);
	assert(env.live_allocs == 0);
	puts("geometry: discontiguous/zero addresses, exact coverage and malformed extents");
}

static void normal_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL, *same = NULL;
	struct xdev_ext_peer_lease lease = {0};
	struct xdev_ext_peer_backing back;
	u64 len, gen;
	setup();
	r = import();
	assert(xdev_ext_peer_dmabuf_desc_unregister(&descriptor) == -EBUSY);
	assert(env.attaches == 0 && env.pins == 0 && env.maps == 0);
	assert(xdev_ext_peer_info(r, &len, &gen, true) == 0 && len == 12288 && gen);
	assert(xdev_ext_peer_describe(r, &requester, &back) == 0);
	assert(back.owner == NULL && back.flags == (XDEV_EXT_PEER_BACKING_STRUCT_PAGE | XDEV_EXT_PEER_BACKING_HOST_SYSTEM));
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0 && m);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &same) == 0 && same == m);
	assert(env.attaches == 1 && env.pins == 1 && env.maps == 1);
	assert(xdev_ext_peer_acquire(m, gen, 8209, 32, DMA_TO_DEVICE, &lease) == 0);
	assert(lease.dma_address == 0x90011 && lease.len == 32);
	assert(xdev_ext_peer_unmap(m) == -EBUSY && env.unmaps == 0);
	assert(xdev_ext_peer_release(&lease, lease.ticket, true) == 0);
	assert(xdev_ext_peer_unmap(m) == 0 && env.unmaps == 0);
	assert(xdev_ext_peer_unmap(same) == 0);
	assert(env.unmaps == 1 && env.unpins == 1 && env.detaches == 1);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("normal: real region/lease geometry, one requester mapping, balanced refs");
}

static void reject_import_case(void)
{
	struct xdev_ext_peer_region *r = NULL;
	struct xdev_ext_peer_dmabuf_desc_ops second;
	setup();
	second = descriptor;
	assert(xdev_ext_peer_dmabuf_desc_register(&second) == -EEXIST);
	assert(xdev_ext_peer_dmabuf_desc_register(NULL) == -EINVAL);
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 0, &r) == -EINVAL && !r);
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 4096, &r) == -EINVAL && !r);
	env.buf.size = 12289;
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12289, &r) == -EINVAL && !r);
	env.buf.size = 12288;
	env.buf.ops = &other_ops;
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == -EOPNOTSUPP && !r);
	env.buf.ops = &trusted_ops;
	env.descriptor.dying = true;
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == -ENODEV && !r);
	assert(env.file.refs == 1 && env.user.refs == 1 && env.mm.refs == 1);
	assert(atomic_long_read(&env.user.locked_vm) == 0);
	env.descriptor.dying = false;
	dma_buf_put(&env.buf);
	finish();
	puts("identity: exact ops, validation, dying descriptor, failure retains caller ref");
}

static void accounting_case(void)
{
	struct xdev_ext_peer_region *r = NULL;
	setup();
	env.limit = 2 * PAGE_SIZE;
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == -ENOMEM && !r);
	assert(env.file.refs == 1 && atomic_long_read(&env.user.locked_vm) == 0);
	env.limit = RLIM_INFINITY;
	r = import();
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	/* A synthetic near-overflow counter tests accounting arithmetic only;
	 * it is not evidence that this many physical pages exist or are pinned. */
	setup();
	env.limit = RLIM_INFINITY;
	atomic_long_set(&env.user.locked_vm, -2L);
	r = NULL;
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == -EOVERFLOW && !r);
	assert(atomic_long_read(&env.user.locked_vm) == -2L);
	atomic_long_set(&env.user.locked_vm, 0);
	dma_buf_put(&env.buf);
	finish();
	puts("accounting: whole export, finite/infinite limits, checked counter overflow");
}

static void failure_case(void)
{
	for (unsigned edge = 0; edge < 7; edge++) {
		struct xdev_ext_peer_region *r;
		struct xdev_ext_peer_mapping *m = NULL;
		setup();
		r = import();
		if (edge == 0) env.attach_error = -EIO;
		if (edge == 1) env.pin_error = -ENOMEM;
		if (edge == 2) env.map_error = -EIO;
		if (edge == 3) env.wait_error = -EINTR;
		if (edge == 4) env.sg[1].dma_length = 0;
		if (edge == 5) env.move_on_pin = true;
		if (edge == 6) env.move_on_map = true;
		assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) < 0 && !m);
		/* No fixed implementation order is assumed after a stale callback.
		 * Every successful external acquisition must unwind exactly once. */
		assert(env.detaches == env.attaches - (env.attach_error ? 1U : 0U));
		assert(env.unpins == env.pins - (env.pin_error ? 1U : 0U));
		assert(env.unmaps == env.maps - (env.map_error ? 1U : 0U));
		assert(xdev_ext_peer_unpin(r) == 0);
		finish();
	}
	puts("unwind: attach/pin/map/readiness/geometry/move failures never publish a lease");
}

static void stale_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL, *other = NULL;
	struct xdev_ext_peer_lease owned = {0}, new_lease = {0};
	struct xdev_ext_peer_backing back;
	u64 gen, len;
	setup();
	r = import();
	gen = xdev_ext_peer_generation(r);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	assert(xdev_ext_peer_acquire(m, gen, 0, 32, DMA_FROM_DEVICE, &owned) == 0);
	assert(xdev_ext_peer_drainable(r) == -EBUSY);
	dma_resv_lock(&env.resv, NULL);
	test_notify(env.last_attach);
	dma_resv_unlock(&env.resv);
	assert(xdev_ext_peer_info(r, &len, &gen, false) == -ESTALE);
	assert(xdev_ext_peer_describe(r, &requester, &back) == -ESTALE);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &other) == -ESTALE && !other);
	assert(xdev_ext_peer_acquire(m, gen, 4096, 32, DMA_TO_DEVICE, &new_lease) == -ESTALE);
	assert(env.unmaps == 0 && env.unpins == 0 && env.detaches == 0);
	assert(xdev_ext_peer_release(&owned, owned.ticket + 1, true) == -ESTALE);
	assert(xdev_ext_peer_release(&owned, owned.ticket, true) == 0);
	assert(xdev_ext_peer_drainable(r) == 0);
	assert(xdev_ext_peer_info(r, &len, &gen, true) == -ESTALE);
	assert(xdev_ext_peer_unmap(m) == 0);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("stale: atomic callback refuses all new operations, preserves accepted DMA");
}

static void unknown_case(void)
{
	struct xdev_ext_peer_region *r, *duplicate = NULL;
	struct xdev_ext_peer_mapping *m = NULL;
	struct xdev_ext_peer_lease owned = {0};
	setup();
	r = import();
	get_dma_buf(&env.buf);
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &duplicate) == -EBUSY && !duplicate);
	dma_buf_put(&env.buf);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	assert(xdev_ext_peer_acquire(m, xdev_ext_peer_generation(r), 0, 32, DMA_FROM_DEVICE, &owned) == 0);
	assert(xdev_ext_peer_release(&owned, owned.ticket, false) == 0);
	assert(xdev_ext_peer_drainable(r) == -EIO);
	assert(xdev_ext_peer_unmap(m) == -EIO);
	assert(xdev_ext_peer_unpin(r) == -EIO);
	assert(env.unmaps == 0 && env.unpins == 0 && env.detaches == 0);
	assert(env.file.refs == 2 && env.descriptor.refs == 1 && env.exporter.refs == 1);
	assert(env.user.refs == 2 && env.mm.refs == 2 && requester.refs == 1);
	assert(atomic_long_read(&env.user.locked_vm) == 3 && atomic64_read(&env.mm.pinned_vm) == 3);
	assert(xdev_ext_peer_dmabuf_desc_unregister(&descriptor) == -EBUSY);
	get_dma_buf(&env.buf);
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &duplicate) == -EBUSY && !duplicate);
	dma_buf_put(&env.buf);
	/* Deliberately exit with retained kernel resources. Freeing them in a
	 * test helper would erase the exact contract this case verifies. */
	puts("unknown: maps, budget, owner and descriptor remain permanently retained");
}

static void host_guards_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL;
	struct xdev_ext_peer_backing back;
	setup();
	r = import();
	requester.dev.dma_coherent = false;
	assert(xdev_ext_peer_describe(r, &requester, &back) == -EOPNOTSUPP);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EOPNOTSUPP && !m);
	assert(env.maps == 0 && env.attaches == 0);
	requester.dev.dma_coherent = true;
	env.needs_sync_address = 0x90000;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EOPNOTSUPP && !m);
	assert(env.unmaps == 1 && env.unpins == 1 && env.detaches == 1);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	setup();
	r = import();
	env.buf.size = 16384;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -ESTALE && !m);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("host guards: noncoherent, second-extent bounce and changed size fail closed");
}

static void requester_bound_case(void)
{
	struct pci_dev peers[65] = {0};
	struct xdev_ext_peer_mapping *maps[64] = {0}, *same = NULL, *extra = NULL;
	struct xdev_ext_peer_region *r;
	setup();
	r = import();
	for (unsigned i = 0; i < ARRAY_SIZE(peers); i++) {
		peers[i].dev.dma_coherent = true;
		peers[i].id = i;
	}
	for (unsigned i = 0; i < 64; i++)
		assert(xdev_ext_peer_map(r, &peers[i], DMA_BIDIRECTIONAL, &maps[i]) == 0);
	assert(xdev_ext_peer_map(r, &peers[0], DMA_BIDIRECTIONAL, &same) == 0 && same == maps[0]);
	assert(xdev_ext_peer_map(r, &peers[64], DMA_BIDIRECTIONAL, &extra) == -ENOSPC && !extra);
	assert(env.attaches == 64 && env.pins == 64 && env.maps == 64);
	assert(xdev_ext_peer_unmap(same) == 0);
	for (unsigned i = 0; i < 64; i++) assert(xdev_ext_peer_unmap(maps[i]) == 0);
	assert(xdev_ext_peer_unpin(r) == 0);
	for (unsigned i = 0; i < ARRAY_SIZE(peers); i++) assert(peers[i].refs == 0);
	finish();
	puts("requester bound: cached mapping reused, 65th distinct attachment rejected");
}

static void allocation_case(void)
{
	struct xdev_ext_peer_region *r = NULL;
	struct xdev_ext_peer_mapping *m = NULL;
	unsigned import_allocations, map_allocations;
	setup();
	env.alloc_calls = 0;
	r = import();
	import_allocations = env.alloc_calls;
	env.alloc_calls = 0;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	map_allocations = env.alloc_calls;
	assert(xdev_ext_peer_unmap(m) == 0 && xdev_ext_peer_unpin(r) == 0);
	finish();
	assert(import_allocations && map_allocations);
	for (unsigned at = 1; at <= import_allocations; at++) {
		setup();
		env.alloc_calls = 0;
		env.fail_alloc = at;
		r = NULL;
		assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == -ENOMEM && !r);
		assert(env.file.refs == 1 && env.user.refs == 1 && env.mm.refs == 1);
		assert(atomic_long_read(&env.user.locked_vm) == 0);
		env.fail_alloc = 0;
		dma_buf_put(&env.buf);
		finish();
	}
	for (unsigned at = 1; at <= map_allocations; at++) {
		setup();
		r = import();
		env.alloc_calls = 0;
		env.fail_alloc = at;
		m = NULL;
		assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -ENOMEM && !m);
		env.fail_alloc = 0;
		assert(xdev_ext_peer_unpin(r) == 0);
		finish();
	}
	puts("allocation: each actual import/map allocation failure unwinds owned refs");
}

static void registration_owner_case(void)
{
	struct xdev_ext_peer_region *r;
	struct user_struct recipient = {.refs = 1};
	struct mm_struct recipient_mm = {.refs = 1};
	setup();
	r = import();
	/* Control can pass to another process; existing charge must stay with
	 * the registering identity. This substitutes only current credentials. */
	test_current_user = &recipient;
	env.task.mm = &recipient_mm;
	assert(xdev_ext_peer_unpin(r) == 0);
	assert(recipient.refs == 1 && recipient_mm.refs == 1);
	assert(atomic_long_read(&recipient.locked_vm) == 0);
	assert(atomic64_read(&recipient_mm.pinned_vm) == 0);
	finish();
	puts("registration owner: recipient credentials do not move or erase charge");
}

static void close_case(bool active, bool unknown)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL;
	struct xdev_ext_peer_lease lease = {0};
	struct test_authority_handle *h;
	setup();
	r = import();
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	if (active || unknown)
		assert(xdev_ext_peer_acquire(m, xdev_ext_peer_generation(r), 0, 32,
					    DMA_FROM_DEVICE, &lease) == 0);
	if (unknown) assert(xdev_ext_peer_release(&lease, lease.ticket, false) == 0);
	dma_resv_lock(&env.resv, NULL);
	test_notify(env.last_attach);
	dma_resv_unlock(&env.resv);
	h = test_authority_setup(r, m, &requester);
	if (!active && !unknown) {
		assert(xdev_ext_peer_drainable(r) == 0);
		assert(test_authority_close(h));
		test_authority_destroy_closed(h);
		finish();
		puts("actual authority close: stale idle region releases its original ref and pin budget");
	} else {
		assert(xdev_ext_peer_drainable(r) == (unknown ? -EIO : -EBUSY));
		assert(!test_authority_close(h));
		assert(env.file.refs == 2 && env.descriptor.refs == 1);
		assert(atomic_long_read(&env.user.locked_vm) == 3);
		assert(env.unmaps == 0 && env.unpins == 0 && env.detaches == 0);
		puts("actual authority close: active or unknown region preserves original ref and budget");
	}
}

/* Plan-review D8. An exporter that registered no descriptor may be imported
 * only when the caller opts in. xdev_ext then knows
 * nothing about the backing: each requester device gets the exporter's own
 * mapping for that device, bounce/sync/untrusted/noncoherent requesters are
 * refused, and the backing is reported as UNDESCRIBED, never as host RAM. */
static const struct dma_buf_ops undescribed_ops;
#define UNDESCRIBED XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED

static struct xdev_ext_peer_region *import_undescribed(void)
{
	struct xdev_ext_peer_region *r = NULL;
	env.buf.ops = &undescribed_ops;
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &r) == 0 && r);
	assert(atomic_long_read(&env.user.locked_vm) == 3);
	assert(atomic64_read(&env.mm.pinned_vm) == 3);
	assert(env.user.refs == 2 && env.mm.refs == 2);
	/* No descriptor is involved, so none is referenced. */
	assert(env.file.refs == 2 && env.descriptor.refs == 0);
	return r;
}

static void undescribed_import_case(void)
{
	struct xdev_ext_peer_region *r = NULL, *duplicate = NULL;
	struct xdev_ext_peer_mapping *m = NULL, *same = NULL, *m2 = NULL;
	struct xdev_ext_peer_lease first = {0}, second_lease = {0};
	struct xdev_ext_peer_backing back;
	struct dma_buf_attachment *first_attach;
	struct pci_dev second = {.dev = {.dma_coherent = true, .dma_base = 0x4000000}, .id = 2};
	u64 len, gen;
	setup();
	env.buf.ops = &undescribed_ops;
	/* The default contract is unchanged: no descriptor and no opt-in refuses. */
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &r) == -EOPNOTSUPP && !r);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, 0, &r) == -EOPNOTSUPP && !r);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, 1U << 1, &r) == -EINVAL && !r);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, ~0U, &r) == -EINVAL && !r);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 4096, UNDESCRIBED, &r) == -EINVAL && !r);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, NULL) == -EINVAL);
	assert(env.file.refs == 1 && env.user.refs == 1 && env.mm.refs == 1);
	assert(atomic_long_read(&env.user.locked_vm) == 0);
	r = import_undescribed();
	/* Identity exclusion covers both paths. */
	get_dma_buf(&env.buf);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &duplicate) == -EBUSY && !duplicate);
	assert(xdev_ext_peer_dmabuf_import(&env.buf, 12288, &duplicate) == -EBUSY && !duplicate);
	dma_buf_put(&env.buf);
	assert(atomic_long_read(&env.user.locked_vm) == 3);
	/* Registry operations for other exporters are unaffected by this import. */
	assert(xdev_ext_peer_dmabuf_desc_unregister(&descriptor) == 0);
	assert(xdev_ext_peer_dmabuf_desc_register(&descriptor) == 0);
	assert(env.attaches == 0 && env.pins == 0 && env.maps == 0);
	assert(xdev_ext_peer_info(r, &len, &gen, true) == 0 && len == 12288 && gen);
	assert(xdev_ext_peer_describe(r, &requester, &back) == 0);
	assert(back.owner == NULL && back.flags == XDEV_EXT_PEER_BACKING_UNDESCRIBED);
	assert(env.attaches == 0);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0 && m);
	first_attach = env.last_attach;
	assert(first_attach && first_attach->dev == &requester.dev);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &same) == 0 && same == m);
	assert(env.attaches == 1 && env.pins == 1 && env.maps == 1 && env.unbounced_checks == 1);
	/* A second device gets its own attachment and its own exporter mapping. */
	assert(xdev_ext_peer_map(r, &second, DMA_BIDIRECTIONAL, &m2) == 0 && m2 && m2 != m);
	assert(env.last_attach != first_attach && env.last_attach->dev == &second.dev);
	assert(env.attaches == 2 && env.pins == 2 && env.maps == 2 && env.unbounced_checks == 2);
	assert(xdev_ext_peer_acquire(m, gen, 8209, 32, DMA_TO_DEVICE, &first) == 0);
	assert(first.dma_address == 0x90011 && first.len == 32);
	assert(xdev_ext_peer_acquire(m2, gen, 8209, 32, DMA_FROM_DEVICE, &second_lease) == 0);
	assert(second_lease.dma_address == 0x4000000 + 0x90011);
	assert(xdev_ext_peer_unmap(m) == -EBUSY && env.unmaps == 0);
	assert(xdev_ext_peer_release(&first, first.ticket, true) == 0);
	assert(xdev_ext_peer_release(&second_lease, second_lease.ticket, true) == 0);
	assert(xdev_ext_peer_unmap(m) == 0 && env.unmaps == 0);
	assert(xdev_ext_peer_unmap(same) == 0 && xdev_ext_peer_unmap(m2) == 0);
	assert(env.unmaps == 2 && env.unpins == 2 && env.detaches == 2);
	assert(xdev_ext_peer_unpin(r) == 0);
	assert(second.refs == 0);
	finish();
	/* The opt-in never downgrades an exporter that does describe itself. */
	setup();
	r = NULL;
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &r) == 0 && r);
	assert(env.descriptor.refs == 1);
	assert(xdev_ext_peer_describe(r, &requester, &back) == 0);
	assert(back.flags == (XDEV_EXT_PEER_BACKING_STRUCT_PAGE | XDEV_EXT_PEER_BACKING_HOST_SYSTEM));
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	/* A dying descriptor is not bypassed by falling back to the generic path. */
	setup();
	r = NULL;
	env.descriptor.dying = true;
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &r) == -ENODEV && !r);
	assert(env.file.refs == 1 && atomic_long_read(&env.user.locked_vm) == 0);
	env.descriptor.dying = false;
	dma_buf_put(&env.buf);
	finish();
	puts("undescribed import: opt-in only, per-device attach and addresses, UNDESCRIBED backing");
}

static void undescribed_guards_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL;
	struct xdev_ext_peer_backing back;
	struct io_tlb_mem bounce = {.force_bounce = true};
	setup();
	r = import_undescribed();
	requester.untrusted = 1;
	assert(xdev_ext_peer_describe(r, &requester, &back) == -EXDEV);
	assert(back.owner == NULL && back.flags == 0);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EXDEV && !m);
	requester.untrusted = 0;
	requester.dev.dma_io_tlb_mem = &bounce;
	assert(xdev_ext_peer_describe(r, &requester, &back) == -EXDEV && back.flags == 0);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EXDEV && !m);
	requester.dev.dma_io_tlb_mem = NULL;
	requester.dev.dma_coherent = false;
	assert(xdev_ext_peer_describe(r, &requester, &back) == -EOPNOTSUPP && back.flags == 0);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EOPNOTSUPP && !m);
	/* These refusals happen before the exporter is ever asked to attach. */
	assert(env.attaches == 0 && env.maps == 0);
	requester.dev.dma_coherent = true;
	/* An extent that needs CPU sync for this device is refused after map. */
	env.needs_sync_address = 0x90000;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EOPNOTSUPP && !m);
	assert(env.attaches == 1 && env.unmaps == 1 && env.unpins == 1 && env.detaches == 1);
	env.needs_sync_address = UINT64_MAX;
	/* A bounced mapping (dma-direct sets no SG flag) is refused after map. */
	env.bounced = true;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EXDEV && !m);
	assert(env.attaches == 2 && env.unmaps == 2 && env.unpins == 2 && env.detaches == 2);
	env.bounced = false;
	/* Refused requesters leave the region usable for a suitable one. */
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0 && m);
	assert(xdev_ext_peer_unmap(m) == 0);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	setup();
	r = import_undescribed();
	env.buf.size = 16384;
	m = NULL;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -ESTALE && !m);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("undescribed guards: untrusted, forced bounce, noncoherent, sync, bounce and size fail closed");
}

static void undescribed_move_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL, *other = NULL;
	struct xdev_ext_peer_lease owned = {0}, fresh = {0};
	struct xdev_ext_peer_backing back;
	u64 gen, len;
	setup();
	r = import_undescribed();
	gen = xdev_ext_peer_generation(r);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	assert(xdev_ext_peer_acquire(m, gen, 0, 32, DMA_FROM_DEVICE, &owned) == 0);
	dma_resv_lock(&env.resv, NULL);
	test_notify(env.last_attach);
	dma_resv_unlock(&env.resv);
	/* No new use of any frame after the exporter moved the buffer. */
	assert(xdev_ext_peer_info(r, &len, &gen, false) == -ESTALE);
	assert(xdev_ext_peer_describe(r, &requester, &back) == -ESTALE);
	assert(xdev_ext_peer_acquire(m, gen, 4096, 32, DMA_TO_DEVICE, &fresh) == -ESTALE);
	/* The accepted request keeps its mapping until it completes. */
	assert(env.unmaps == 0 && env.unpins == 0 && env.detaches == 0);
	assert(xdev_ext_peer_release(&owned, owned.ticket, true) == 0);
	assert(xdev_ext_peer_drainable(r) == 0);
	assert(xdev_ext_peer_unmap(m) == 0);
	/* Re-mapping does not make the moved region reusable. */
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &other) == -ESTALE && !other);
	assert(env.attaches == 1 && env.maps == 1);
	assert(xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("undescribed move: no new lease or mapping after move_notify, accepted DMA drains");
}

static void undescribed_unknown_case(void)
{
	struct xdev_ext_peer_region *r, *duplicate = NULL;
	struct xdev_ext_peer_mapping *m = NULL, *m2 = NULL, *other = NULL;
	struct xdev_ext_peer_lease owned = {0}, held = {0};
	struct pci_dev second = {.dev = {.dma_coherent = true, .dma_base = 0x4000000}, .id = 2};
	u64 gen;
	setup();
	r = import_undescribed();
	gen = xdev_ext_peer_generation(r);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	assert(xdev_ext_peer_map(r, &second, DMA_BIDIRECTIONAL, &m2) == 0);
	assert(xdev_ext_peer_acquire(m, gen, 0, 32, DMA_FROM_DEVICE, &owned) == 0);
	assert(xdev_ext_peer_acquire(m2, gen, 4096, 32, DMA_TO_DEVICE, &held) == 0);
	dma_resv_lock(&env.resv, NULL);
	test_notify(env.last_attach);
	dma_resv_unlock(&env.resv);
	assert(xdev_ext_peer_release(&owned, owned.ticket, true) == 0);
	assert(xdev_ext_peer_drainable(r) == -EBUSY);
	/* The second device's DMA could not be proven stopped. */
	assert(xdev_ext_peer_release(&held, held.ticket, false) == 0);
	assert(xdev_ext_peer_drainable(r) == -EIO);
	assert(xdev_ext_peer_unmap(m) == -EIO && xdev_ext_peer_unmap(m2) == -EIO);
	assert(xdev_ext_peer_unpin(r) == -EIO);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &other) == -ESTALE && !other);
	assert(env.unmaps == 0 && env.unpins == 0 && env.detaches == 0);
	assert(env.file.refs == 2 && env.exporter.refs == 1 && env.descriptor.refs == 0);
	assert(env.user.refs == 2 && env.mm.refs == 2 && requester.refs == 1 && second.refs == 1);
	assert(atomic_long_read(&env.user.locked_vm) == 3 && atomic64_read(&env.mm.pinned_vm) == 3);
	get_dma_buf(&env.buf);
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &duplicate) == -EBUSY && !duplicate);
	dma_buf_put(&env.buf);
	/* Deliberately exit with retained kernel resources (see unknown_case). */
	puts("undescribed unknown: moved region with unproven DMA retains maps, budget and owner");
}

static void undescribed_allocation_case(void)
{
	struct xdev_ext_peer_region *r = NULL;
	struct xdev_ext_peer_mapping *m = NULL;
	unsigned import_allocations, map_allocations;
	setup();
	env.alloc_calls = 0;
	r = import_undescribed();
	import_allocations = env.alloc_calls;
	env.alloc_calls = 0;
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	map_allocations = env.alloc_calls;
	assert(xdev_ext_peer_unmap(m) == 0 && xdev_ext_peer_unpin(r) == 0);
	finish();
	assert(import_allocations && map_allocations);
	for (unsigned at = 1; at <= import_allocations; at++) {
		setup();
		env.buf.ops = &undescribed_ops;
		env.alloc_calls = 0;
		env.fail_alloc = at;
		r = NULL;
		assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &r) == -ENOMEM && !r);
		assert(env.file.refs == 1 && env.user.refs == 1 && env.mm.refs == 1);
		assert(atomic_long_read(&env.user.locked_vm) == 0);
		env.fail_alloc = 0;
		/* The failed import released its identity: a retry succeeds. */
		assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &r) == 0 && r);
		assert(xdev_ext_peer_unpin(r) == 0);
		finish();
	}
	for (unsigned at = 1; at <= map_allocations; at++) {
		setup();
		r = import_undescribed();
		env.alloc_calls = 0;
		env.fail_alloc = at;
		m = NULL;
		assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -ENOMEM && !m);
		env.fail_alloc = 0;
		assert(xdev_ext_peer_unpin(r) == 0);
		finish();
	}
	puts("undescribed allocation: each import/map allocation failure unwinds owned refs");
}

/* The application closes its exporter fd right after import, then the
 * importer session dies (its authority fd is closed by the actual close code). */
static void close_undescribed_case(bool active, bool unknown)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL;
	struct xdev_ext_peer_lease lease = {0};
	struct test_authority_handle *h;
	setup();
	get_dma_buf(&env.buf); /* the application's own exporter fd */
	r = NULL;
	env.buf.ops = &undescribed_ops;
	assert(xdev_ext_peer_dmabuf_import_flags(&env.buf, 12288, UNDESCRIBED, &r) == 0 && r);
	dma_buf_put(&env.buf); /* exporter fd closed */
	assert(env.file.refs == 2 && env.exporter.refs == 1);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	if (active || unknown)
		assert(xdev_ext_peer_acquire(m, xdev_ext_peer_generation(r), 0, 32,
					    DMA_FROM_DEVICE, &lease) == 0);
	if (unknown) assert(xdev_ext_peer_release(&lease, lease.ticket, false) == 0);
	h = test_authority_setup(r, m, &requester);
	if (!active && !unknown) {
		assert(xdev_ext_peer_drainable(r) == 0);
		assert(test_authority_close(h));
		test_authority_destroy_closed(h);
		finish();
		puts("undescribed close: exporter fd and session gone, idle region releases everything");
	} else {
		assert(xdev_ext_peer_drainable(r) == (unknown ? -EIO : -EBUSY));
		assert(!test_authority_close(h));
		assert(env.file.refs == 2 && env.exporter.refs == 1 && env.descriptor.refs == 0);
		assert(atomic_long_read(&env.user.locked_vm) == 3);
		assert(env.unmaps == 0 && env.unpins == 0 && env.detaches == 0);
		puts("undescribed close: active or unknown region keeps the buffer, mapping and budget");
	}
}

/* Implicit synchronization (include/linux/dma-buf.h, IMPLICIT SYNCHRONIZATION
 * and DYNAMIC IMPORTER RULES). An undescribed exporter, or another importer of
 * the same buffer, may order its accesses with fences in the buffer's
 * reservation object. xdev_ext adds no fence for its own device access, so it
 * must never begin a device access that such a fence orders after another
 * access: a device read waits for writers (dma_resv_usage_rw(false), which
 * includes KERNEL fences), a device write waits for readers and writers
 * (dma_resv_usage_rw(true)); BOOKKEEP fences take no part in implicit sync.
 * The lease path cannot sleep on a fence, so such a lease is refused with
 * -EBUSY and nothing else changes; the caller retries after the fence. */
static void fenced_lease_refused(struct xdev_ext_peer_mapping *m, u64 gen, u64 offset,
				 enum dma_data_direction dir, enum dma_resv_usage usage)
{
	struct xdev_ext_peer_lease probe = {0};
	unsigned before = env.fence_tests;
	assert(xdev_ext_peer_acquire(m, gen, offset, 32, dir, &probe) == -EBUSY);
	assert(env.fence_tests > before && env.fence_last_usage == usage);
	/* A refused lease owns nothing. */
	assert(!probe.mapping && !probe.next && !probe.ticket && !probe.dma_address && !probe.len);
}

static void fenced_lease_granted(struct xdev_ext_peer_mapping *m, u64 gen, u64 offset,
				 enum dma_data_direction dir)
{
	struct xdev_ext_peer_lease lease = {0};
	assert(xdev_ext_peer_acquire(m, gen, offset, 32, dir, &lease) == 0 && lease.mapping == m);
	assert(xdev_ext_peer_release(&lease, lease.ticket, true) == 0);
}

static void undescribed_fences_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL;
	struct xdev_ext_peer_lease accepted = {0}, probe = {0};
	struct xdev_ext_peer_backing back;
	u64 gen, len, info_gen;
	setup();
	r = import_undescribed();
	gen = xdev_ext_peer_generation(r);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	/* An implicit-sync writer is still running. */
	env.fence_pending[DMA_RESV_USAGE_WRITE] = 1;
	fenced_lease_refused(m, gen, 0, DMA_TO_DEVICE, DMA_RESV_USAGE_WRITE);
	fenced_lease_refused(m, gen, 4096, DMA_FROM_DEVICE, DMA_RESV_USAGE_READ);
	/* The refusal is transient: nothing is active, stale or quarantined. */
	assert(xdev_ext_peer_drainable(r) == 0);
	assert(xdev_ext_peer_info(r, &len, &info_gen, true) == 0 && info_gen == gen);
	assert(xdev_ext_peer_describe(r, &requester, &back) == 0 &&
	       back.flags == XDEV_EXT_PEER_BACKING_UNDESCRIBED);
	/* Argument and generation errors are still reported as before (the lease
	 * split shrinks on -ERANGE); only an otherwise valid lease is refused. */
	assert(xdev_ext_peer_acquire(m, gen, 4090, 32, DMA_TO_DEVICE, &probe) == -ERANGE);
	assert(xdev_ext_peer_acquire(m, gen + 1, 0, 32, DMA_TO_DEVICE, &probe) == -ESTALE);
	assert(xdev_ext_peer_acquire(m, gen, 0, 32, DMA_BIDIRECTIONAL, &probe) == -EINVAL);
	assert(!probe.mapping && !probe.ticket);
	/* The writer signals: device reads and writes start. */
	env.fence_pending[DMA_RESV_USAGE_WRITE] = 0;
	fenced_lease_granted(m, gen, 0, DMA_TO_DEVICE);
	fenced_lease_granted(m, gen, 4096, DMA_FROM_DEVICE);
	/* An implicit-sync reader: device reads start, device writes wait. */
	env.fence_pending[DMA_RESV_USAGE_READ] = 1;
	fenced_lease_granted(m, gen, 0, DMA_TO_DEVICE);
	fenced_lease_refused(m, gen, 4096, DMA_FROM_DEVICE, DMA_RESV_USAGE_READ);
	env.fence_pending[DMA_RESV_USAGE_READ] = 0;
	/* Kernel memory-management fences order every device access. */
	env.fence_pending[DMA_RESV_USAGE_KERNEL] = 1;
	fenced_lease_refused(m, gen, 0, DMA_TO_DEVICE, DMA_RESV_USAGE_WRITE);
	fenced_lease_refused(m, gen, 4096, DMA_FROM_DEVICE, DMA_RESV_USAGE_READ);
	env.fence_pending[DMA_RESV_USAGE_KERNEL] = 0;
	/* Fences that take no part in implicit sync refuse nothing. */
	env.fence_pending[DMA_RESV_USAGE_BOOKKEEP] = 1;
	fenced_lease_granted(m, gen, 0, DMA_TO_DEVICE);
	fenced_lease_granted(m, gen, 4096, DMA_FROM_DEVICE);
	env.fence_pending[DMA_RESV_USAGE_BOOKKEEP] = 0;
	/* A lease accepted before a fence arrives keeps its mapping; the fence
	 * only refuses new device accesses. */
	assert(xdev_ext_peer_acquire(m, gen, 8192, 32, DMA_TO_DEVICE, &accepted) == 0);
	env.fence_pending[DMA_RESV_USAGE_WRITE] = 1;
	assert(xdev_ext_peer_drainable(r) == -EBUSY);
	assert(xdev_ext_peer_unmap(m) == -EBUSY && env.unmaps == 0);
	assert(xdev_ext_peer_release(&accepted, accepted.ticket, true) == 0);
	assert(xdev_ext_peer_drainable(r) == 0);
	/* Permanent states keep their own error ahead of the transient one. */
	dma_resv_lock(&env.resv, NULL);
	test_notify(env.last_attach);
	dma_resv_unlock(&env.resv);
	assert(xdev_ext_peer_acquire(m, gen, 0, 32, DMA_TO_DEVICE, &probe) == -ESTALE);
	env.fence_pending[DMA_RESV_USAGE_WRITE] = 0;
	assert(xdev_ext_peer_unmap(m) == 0 && xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("undescribed fences: a lease that an implicit-sync fence orders is refused, never raced");
}

/* Scope: described exporters (system heap, NVIDIA) keep the contract in which
 * the application orders implicit-sync users itself; this case pins that the
 * fence rule above is not applied to them (a deliberate decision, see the
 * undescribed import notes). */
static void described_fences_case(void)
{
	struct xdev_ext_peer_region *r;
	struct xdev_ext_peer_mapping *m = NULL;
	u64 gen;
	setup();
	r = import();
	gen = xdev_ext_peer_generation(r);
	assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == 0);
	env.fence_pending[DMA_RESV_USAGE_WRITE] = 1;
	fenced_lease_granted(m, gen, 0, DMA_TO_DEVICE);
	fenced_lease_granted(m, gen, 4096, DMA_FROM_DEVICE);
	env.fence_pending[DMA_RESV_USAGE_WRITE] = 0;
	assert(xdev_ext_peer_unmap(m) == 0 && xdev_ext_peer_unpin(r) == 0);
	finish();
	puts("described fences: described exporters keep the application-ordered contract");
}

/* XDEV_EXT_PEER_BACKING_UNDESCRIBED is the importer's own report for an
 * exporter that registered no descriptor: requester admission then admits the
 * frame on the terms that the lease-time fence rule above protects. A
 * registered descriptor keeps the application-ordered contract and is never
 * fenced (described_fences), so a descriptor reporting UNDESCRIBED, alone or
 * with other bits, is refused before any requester attachment exists. */
static u32 claimed_backing;

static int claims_undescribed_describe(struct dma_buf *b, struct pci_dev *p,
				       struct xdev_ext_peer_backing *out)
{
	(void)p;
	assert(b->ops == &trusted_ops);
	*out = (struct xdev_ext_peer_backing){.owner = NULL, .flags = claimed_backing};
	return 0;
}

static void described_claims_undescribed_case(void)
{
	const u32 claims[] = {XDEV_EXT_PEER_BACKING_UNDESCRIBED,
		XDEV_EXT_PEER_BACKING_UNDESCRIBED | XDEV_EXT_PEER_BACKING_STRUCT_PAGE};
	for (unsigned i = 0; i < ARRAY_SIZE(claims); i++) {
		struct xdev_ext_peer_region *r;
		struct xdev_ext_peer_mapping *m = NULL;
		struct xdev_ext_peer_backing back;
		setup();
		descriptor.describe = claims_undescribed_describe;
		claimed_backing = claims[i];
		r = import();
		assert(xdev_ext_peer_describe(r, &requester, &back) == -EOPNOTSUPP);
		assert(back.owner == NULL && back.flags == 0);
		assert(xdev_ext_peer_map(r, &requester, DMA_BIDIRECTIONAL, &m) == -EOPNOTSUPP && !m);
		assert(env.attaches == 0 && env.pins == 0 && env.maps == 0);
		assert(xdev_ext_peer_unpin(r) == 0);
		finish();
	}
	puts("described claims undescribed: a descriptor cannot report UNDESCRIBED");
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	if (!strcmp(argv[1], "geometry")) geometry_case();
	else if (!strcmp(argv[1], "normal")) normal_case();
	else if (!strcmp(argv[1], "identity")) reject_import_case();
	else if (!strcmp(argv[1], "accounting")) accounting_case();
	else if (!strcmp(argv[1], "unwind")) failure_case();
	else if (!strcmp(argv[1], "stale")) stale_case();
	else if (!strcmp(argv[1], "unknown")) unknown_case();
	else if (!strcmp(argv[1], "host_guards")) host_guards_case();
	else if (!strcmp(argv[1], "requester_bound")) requester_bound_case();
	else if (!strcmp(argv[1], "allocation")) allocation_case();
	else if (!strcmp(argv[1], "registration_owner")) registration_owner_case();
	else if (!strcmp(argv[1], "close_stale_idle")) close_case(false, false);
	else if (!strcmp(argv[1], "close_stale_active")) close_case(true, false);
	else if (!strcmp(argv[1], "close_unknown")) close_case(false, true);
	else if (!strcmp(argv[1], "undescribed_import")) undescribed_import_case();
	else if (!strcmp(argv[1], "undescribed_guards")) undescribed_guards_case();
	else if (!strcmp(argv[1], "undescribed_move")) undescribed_move_case();
	else if (!strcmp(argv[1], "undescribed_unknown")) undescribed_unknown_case();
	else if (!strcmp(argv[1], "undescribed_allocation")) undescribed_allocation_case();
	else if (!strcmp(argv[1], "close_undescribed_idle")) close_undescribed_case(false, false);
	else if (!strcmp(argv[1], "close_undescribed_active")) close_undescribed_case(true, false);
	else if (!strcmp(argv[1], "close_undescribed_unknown")) close_undescribed_case(false, true);
	else if (!strcmp(argv[1], "undescribed_fences")) undescribed_fences_case();
	else if (!strcmp(argv[1], "described_fences")) described_fences_case();
	else if (!strcmp(argv[1], "described_claims_undescribed")) described_claims_undescribed_case();
	else return 2;
	return 0;
}
