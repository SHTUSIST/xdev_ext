/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Environment of the composite: the existing XDOMAIN stack environment
 * (stack_boundary.c with the real NHI adapter, included below) minus its
 * core-session stand-ins, which the real core unit now provides.  Added here:
 *  - a PEER lease provider with one DMA window per requester device and
 *    per-page permuted addresses (no contiguity across pages is implied);
 *  - device memory of each endpoint and the only byte movement in the test:
 *    the NVMe controller model and the Thunderbolt link copy bytes between
 *    that memory and the DMA addresses named by real descriptors, and only
 *    inside a live lease of the accessing device in the right direction;
 *  - stage files, pool claim, requester bind (recording stand-in; the real
 *    requester bind is tests/network/xdomain/dmabuf_requester);
 *  - BPF invocation of the reference programs with the core's context rules;
 *  - one deterministic scheduler over world work, core kthread work, NHI
 *    descriptor completion/delivery and NVMe completion.
 */
#define STACK_INTERNAL
struct xdev_ext_mech_session;
struct xdev_ext_mech_pool;
static unsigned long long chain_real_session_id(struct xdev_ext_mech_session *s);
static unsigned long long chain_real_pool_generation(struct xdev_ext_mech_session *s);
static void chain_link_payload(unsigned from, unsigned long long tx_dma, unsigned to,
			       unsigned long long rx_dma, unsigned len);
struct tb_ring;
struct ring_frame;
struct xdev_ext_net_elem;
static void chain_note_data_post(struct tb_ring *r, struct ring_frame *f, struct xdev_ext_net_elem *el);
#define xdev_ext_peer_file_acquire stackfake_peer_file_acquire
#define xdev_ext_peer_fd_release stackfake_peer_fd_release
#define xdev_ext_peer_mech_pool_file stackfake_peer_mech_pool_file
#define xdev_ext_peer_mech_pool_generation stackfake_peer_mech_pool_generation
#define xdev_ext_peer_control_file stackfake_peer_control_file
#define xdev_ext_requester_bind stackfake_requester_bind
#define xdev_ext_requester_unbind stackfake_requester_unbind
#define xdev_ext_mech_session_pool stackfake_session_pool
#define xdev_ext_mech_session_layout stackfake_session_layout
#define xdev_ext_mech_session_depth stackfake_session_depth
#define xdev_ext_mech_session_id stackfake_session_id
#define xdev_ext_mech_session_state stackfake_session_state
#define xdev_ext_mech_session_admits stackfake_session_admits
#define xdev_ext_mech_session_stop_started_ns stackfake_session_stop_started_ns
#define xdev_ext_mech_stage_stop stackfake_stage_stop
#define xdev_ext_mech_batch_priv stackfake_batch_priv
#define xdev_ext_mech_batch_cookie stackfake_batch_cookie
#define xdev_ext_mech_batch_nr_frames stackfake_batch_nr_frames
#define xdev_ext_mech_batch_key stackfake_batch_key
#define xdev_ext_mech_batch_ticket stackfake_batch_ticket
#define xdev_ext_mech_batch_frame stackfake_batch_frame
#define xdev_ext_mech_batch_completion_claim stackfake_completion_claim
#define xdev_ext_mech_batch_completion_publish stackfake_completion_publish
#define xdev_ext_mech_stage_kick stackfake_stage_kick
#define xdev_ext_mech_stage_dead stackfake_stage_dead
#define xdev_ext_mech_stage_native_get stackfake_native_get
#define xdev_ext_mech_stage_native_put stackfake_native_put
#define xdev_ext_mech_count stackfake_count
#define xdev_ext_mech_class_register stackfake_class_register
#define xdev_ext_mech_class_unregister stackfake_class_unregister
#define xdev_ext_mech_trace_xdomain_enabled stackfake_trace_xdomain_enabled
#define xdev_ext_mech_trace_xdomain stackfake_trace_xdomain
#define xdev_ext_mech_trace_native_submit stackfake_trace_native_submit
#define xdev_ext_mech_trace_native_complete stackfake_trace_native_complete
#define xdev_ext_mech_stage_has_member stackfake_stage_has_member
#define xdev_ext_mech_call stackfake_call
#define stack_record_dispatch stackfake_record_dispatch
#define stack_endpoint_stage stackfake_endpoint_stage
#include "stack_boundary.c"
#undef xdev_ext_peer_file_acquire
#undef xdev_ext_peer_fd_release
#undef xdev_ext_peer_mech_pool_file
#undef xdev_ext_peer_mech_pool_generation
#undef xdev_ext_peer_control_file
#undef xdev_ext_requester_bind
#undef xdev_ext_requester_unbind
#undef xdev_ext_mech_session_pool
#undef xdev_ext_mech_session_layout
#undef xdev_ext_mech_session_depth
#undef xdev_ext_mech_session_id
#undef xdev_ext_mech_session_state
#undef xdev_ext_mech_session_admits
#undef xdev_ext_mech_session_stop_started_ns
#undef xdev_ext_mech_stage_stop
#undef xdev_ext_mech_batch_priv
#undef xdev_ext_mech_batch_cookie
#undef xdev_ext_mech_batch_nr_frames
#undef xdev_ext_mech_batch_key
#undef xdev_ext_mech_batch_ticket
#undef xdev_ext_mech_batch_frame
#undef xdev_ext_mech_batch_completion_claim
#undef xdev_ext_mech_batch_completion_publish
#undef xdev_ext_mech_stage_kick
#undef xdev_ext_mech_stage_dead
#undef xdev_ext_mech_stage_native_get
#undef xdev_ext_mech_stage_native_put
#undef xdev_ext_mech_count
#undef xdev_ext_mech_class_register
#undef xdev_ext_mech_class_unregister
#undef xdev_ext_mech_trace_xdomain_enabled
#undef xdev_ext_mech_trace_xdomain
#undef xdev_ext_mech_trace_native_submit
#undef xdev_ext_mech_trace_native_complete
#undef xdev_ext_mech_stage_has_member
#undef xdev_ext_mech_call
#undef stack_record_dispatch
#undef stack_endpoint_stage
#include "chain_api.h"
#include "chain_core_api.h"
#ifdef CHAIN_REAL_PEER
#define CHAIN_STUB(name) chain_stub_##name
#else
#define CHAIN_STUB(name) name
#endif

/* Real definitions in other units (core, peer pool, XDOMAIN class). */
struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s);
u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session *s);
u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch *b);
u64 xdev_ext_mech_batch_key(const struct xdev_ext_mech_batch *b);
u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch *b);
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *pool);
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *pool);
void xdev_ext_xd_class_ctl(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg *m);
int xdev_ext_xd_class_register(void);
int stack_x6_call(struct xdev_ext_mech_stage *, const struct xdev_ext_mech_call_args *, s32 *);
int chain_x6_program_call(struct xdev_ext_mech_stage *stage, const struct xdev_ext_mech_call_args *args,
			  const struct xdev_ext_mech_ctx *ctx,
			  s32 (*fn)(void *, const struct xdev_ext_mech_ctx *), s32 *result);
s32 nvme_s0_build(void *, const struct xdev_ext_mech_ctx *);
s32 nvme_s0_complete(void *, const struct xdev_ext_mech_ctx *);

static unsigned long long chain_real_session_id(struct xdev_ext_mech_session *s)
{ return xdev_ext_mech_session_id(s); }
static unsigned long long chain_real_pool_generation(struct xdev_ext_mech_session *s)
{ return xdev_ext_peer_mech_pool_generation(xdev_ext_mech_session_pool(s)); }

/* ---- allocation used by the core and NVMe units ---------------------- */
void *chain_kzalloc(size_t n) { return calloc(1, n ? n : 1); }
void chain_kfree(const void *p) { free((void *)p); }
unsigned long long chain_now_ns(void) { return world->now; }

/* ---- event record ---------------------------------------------------- */
#define CHAIN_EVENTS 100000
static struct chain_event *chain_events;
static size_t chain_nevents;
void chain_record(struct chain_event e)
{
	assert(chain_events && chain_nevents < CHAIN_EVENTS);
	e.id = chain_nevents + 1;
	e.now_ns = world ? world->now : 0;
	chain_events[chain_nevents++] = e;
	if (getenv("CHAIN_TRACE"))
		fprintf(stderr, "CEV %llu t=%llu kind=%u ep=%u worker=%u stage=%u member=%u type=%u addr=%llx len=%llu group=%llu off=%llu status=%d\n",
			(unsigned long long)e.id, (unsigned long long)e.now_ns, e.kind, e.endpoint, e.worker, e.stage,
			e.member, e.control_type, (unsigned long long)e.address, (unsigned long long)e.length,
			(unsigned long long)e.group, (unsigned long long)e.offset, e.status);
}
size_t chain_event_count(void) { return chain_nevents; }
const struct chain_event *chain_event_get(size_t i) { return i < chain_nevents ? &chain_events[i] : NULL; }
void chain_observe_worker(unsigned worker, const void *fn, bool begin)
{
	if (begin)
		chain_record((struct chain_event){ .kind = CHAIN_EV_WORKER, .worker = worker,
			.address = (uintptr_t)fn });
}

/* ---- sessions, files and descriptors ---------------------------------- */
static struct xdev_ext_mech_session *chain_sessions[CHAIN_ENDPOINTS];
static int chain_creating = -1;
static int session_endpoint(const struct xdev_ext_mech_session *s)
{
	for (unsigned e = 0; e < CHAIN_ENDPOINTS; e++)
		if (chain_sessions[e] == s)
			return e;
	assert(chain_creating >= 0); /* only during the session's own CREATE */
	return chain_creating;
}
int stack_endpoint_stage(const struct xdev_ext_mech_stage *stage)
{
	return session_endpoint(stage->s);
}
void stack_record_dispatch(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg *m)
{
	stack_record((struct stack_event){ .kind = STACK_EV_DISPATCH, .endpoint = stack_endpoint_stage(st),
		.session_id = chain_real_session_id(st->s), .group = m->group, .seq = m->data_seq,
		.control = 1, .control_type = m->type, .length = m->total_len });
	chain_record((struct chain_event){ .kind = CHAIN_EV_CTL_RX, .endpoint = stack_endpoint_stage(st),
		.control_type = m->type, .group = m->group, .worker = chain_core_current_worker(),
		.session = chain_real_session_id(st->s) });
	xdev_ext_xd_class_ctl(st, m);
}
void xdev_ext_xd_class_ctl_v2(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg_v2 *m);
void chain_record_dispatch_v2(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg_v2 *m);
void chain_record_dispatch_v2(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg_v2 *m)
{
	chain_record((struct chain_event){ .kind = CHAIN_EV_CTL_RX, .endpoint = stack_endpoint_stage(st),
		.control_type = m->type, .group = m->group, .worker = chain_core_current_worker(),
		.session = chain_real_session_id(st->s), .member = 2 });
	xdev_ext_xd_class_ctl_v2(st, m);
}
unsigned chain_worker_of(struct xdev_ext_mech_session *s) { return chain_session_worker_id(s); }
/* The real X4 posted one data-ring frame; called from native_post. */
static void chain_note_data_post(struct tb_ring *r, struct ring_frame *f, struct xdev_ext_net_elem *el)
{
	chain_record((struct chain_event){ .kind = r->is_tx ? CHAIN_EV_DATA_TX_POST : CHAIN_EV_DATA_RX_POST,
		.endpoint = ring_info(r)->endpoint, .address = f->buffer_phy, .length = el->len,
		.group = el->slot->group, .worker = chain_core_current_worker(),
		.session = chain_real_session_id(el->slot->ns->st->s), .stage = el->slot->ns->st->index });
}

enum chain_file_kind { CHAIN_FILE_CONTROL = 1, CHAIN_FILE_ALLOCATION, CHAIN_FILE_AUTHORITY, CHAIN_FILE_FOREIGN };
struct chain_fd { void *file; unsigned kind, endpoint, refs; };
#define CHAIN_FDS 32
static struct chain_fd chain_fds[CHAIN_FDS];
static struct file chain_control[CHAIN_ENDPOINTS], chain_allocation[CHAIN_ENDPOINTS],
		   chain_authority[CHAIN_ENDPOINTS];
static u64 chain_generation[CHAIN_ENDPOINTS] = { 0x47, 0x59 };
static int chain_install(void *file, unsigned kind, unsigned endpoint)
{
	for (int fd = 3; fd < CHAIN_FDS; fd++)
		if (!chain_fds[fd].file) {
			chain_fds[fd] = (struct chain_fd){ file, kind, endpoint, 1 };
			return fd;
		}
	abort();
}
static struct chain_fd *chain_fd_of(const void *file)
{
	for (int fd = 0; fd < CHAIN_FDS; fd++)
		if (chain_fds[fd].file == file)
			return &chain_fds[fd];
	return NULL;
}
struct file *fget(int fd)
{
	if (fd < 0 || fd >= CHAIN_FDS || !chain_fds[fd].file)
		return NULL;
	chain_fds[fd].refs++;
	return chain_fds[fd].file;
}
void fput(struct file *f)
{
	struct chain_fd *d = chain_fd_of(f);

	assert(d && d->refs);
	d->refs--;
}
bool CHAIN_STUB(xdev_ext_peer_control_file)(struct file *file)
{
	struct chain_fd *d = chain_fd_of(file);
	return d && d->kind == CHAIN_FILE_CONTROL;
}
/* REGISTER already sealed a whole-export region: claiming its allocation
 * fd yields the authority the pool keeps. */
struct file *CHAIN_STUB(xdev_ext_peer_file_claim)(struct file *file, u64 *len, u64 *generation)
{
	struct chain_fd *d = chain_fd_of(file);
	unsigned e;

	if (!d || d->kind != CHAIN_FILE_ALLOCATION)
		return ERR_PTR(-EINVAL);
	e = d->endpoint;
	*len = world->cfg.nr_frames * (u64)world->cfg.frame_size;
	*generation = chain_generation[e];
	if (!chain_fd_of(&chain_authority[e]))
		chain_install(&chain_authority[e], CHAIN_FILE_AUTHORITY, e);
	else
		chain_fd_of(&chain_authority[e])->refs++;
	return &chain_authority[e];
}

/* ---- devices, windows, memory and leases ------------------------------ */
struct chain_device { const void *device; unsigned endpoint; enum chain_device_kind kind; u64 base; };
static struct chain_device chain_devices[8];
static unsigned chain_ndevices;
static u8 *chain_memory[CHAIN_ENDPOINTS];
static size_t chain_memory_bytes;
void chain_register_device(const void *device, unsigned endpoint, enum chain_device_kind kind)
{
	static const u64 bases[CHAIN_ENDPOINTS][3] = {
		{ 0, 0x3c00000000ULL, 0x7a00000000ULL }, { 0, 0x4d00000000ULL, 0x8b00000000ULL } };
	assert(chain_ndevices < ARRAY_SIZE(chain_devices) && endpoint < CHAIN_ENDPOINTS);
	chain_devices[chain_ndevices++] = (struct chain_device){ device, endpoint, kind,
		bases[endpoint][kind] };
}
static struct chain_device *chain_device_of(const void *device)
{
	for (unsigned i = 0; i < chain_ndevices; i++)
		if (chain_devices[i].device == device)
			return &chain_devices[i];
	return NULL;
}
static u32 chain_pages(void) { return (u32)(chain_memory_bytes / CHAIN_PAGE); }
/* Page p of the endpoint's export appears at window page pages-1-p. */
static bool chain_dmabuf_endpoint(unsigned endpoint)
{
#ifdef CHAIN_REAL_PEER
	return endpoint == 0;
#else
	(void)endpoint;
	return false;
#endif
}
static u64 chain_window_page(const struct chain_device *d, u64 page)
{
	u64 half = chain_pages() / 2;
	if (chain_dmabuf_endpoint(d->endpoint))
		return page < half ? half + page : page - half;
	return chain_pages() - 1 - page;
}
static u64 chain_page_dma(const struct chain_device *d, u64 offset)
{
	return d->base + chain_window_page(d, offset / CHAIN_PAGE) * CHAIN_PAGE + offset % CHAIN_PAGE;
}
uint64_t chain_device_dma(unsigned endpoint, enum chain_device_kind kind, uint64_t offset)
{
	for (unsigned i = 0; i < chain_ndevices; i++)
		if (chain_devices[i].endpoint == endpoint && chain_devices[i].kind == kind)
			return chain_page_dma(&chain_devices[i], offset);
	abort();
}
uint8_t *chain_frame_memory(unsigned endpoint, size_t *bytes)
{
	*bytes = chain_memory_bytes;
	return chain_memory[endpoint];
}

struct chain_lease {
	const struct chain_device *dev;
	u64 offset, ticket;
	u32 len;
	enum dma_data_direction dir;
	bool live, retained;
};
#define CHAIN_LEASES 20000
static struct chain_lease *chain_leases;
static unsigned chain_nleases;
static u64 chain_ticket;
unsigned chain_lease_violations;

static bool chain_overlap(u64 a, u32 alen, u64 b, u32 blen) { return a < b + blen && b < a + alen; }
int CHAIN_STUB(xdev_ext_peer_file_acquire)(struct file *file, struct pci_dev *peer, u64 generation, u64 offset,
			       u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h)
{
	struct chain_fd *auth = chain_fd_of(file);
	struct chain_device *dev = chain_device_of(peer);
	struct chain_lease *l;

	if (!h || h->file || h->lease.mapping)
		return -EINVAL;
	if (!auth || auth->kind != CHAIN_FILE_AUTHORITY || !dev || dev->endpoint != auth->endpoint)
		return -EINVAL;
	if (generation != chain_generation[dev->endpoint] || (dir != DMA_TO_DEVICE && dir != DMA_FROM_DEVICE))
		return -ESTALE;
	/* A 4 KiB provider page bounds one lease, as the DMA-BUF importer does. */
	if (!len || offset >= chain_memory_bytes || len > chain_memory_bytes - offset ||
	    offset % CHAIN_PAGE + len > CHAIN_PAGE)
		return -ERANGE;
	/* Reuse safety at the provider: a device may not write bytes another
	 * live lease still covers, and nothing may be leased over retained bytes. */
	for (unsigned i = 0; i < chain_nleases; i++) {
		struct chain_lease *o = &chain_leases[i];
		if (o->dev->endpoint != dev->endpoint || !chain_overlap(o->offset, o->len, offset, len))
			continue;
		if (o->retained || (o->live && (dir == DMA_FROM_DEVICE || o->dir == DMA_FROM_DEVICE))) {
			chain_lease_violations++;
			fprintf(stderr, "CHAIN_LEASE_VIOLATION ep=%u off=%llu len=%u against live=%d retained=%d\n",
				dev->endpoint, (unsigned long long)offset, len, o->live, o->retained);
		}
	}
	assert(chain_nleases < CHAIN_LEASES);
	l = &chain_leases[chain_nleases++];
	*l = (struct chain_lease){ dev, offset, ++chain_ticket, len, dir, true, false };
	h->lease.mapping = (struct xdev_ext_peer_mapping *)l;
	h->lease.ticket = l->ticket;
	h->lease.dma_address = chain_page_dma(dev, offset);
	h->lease.len = len;
	h->file = file;
	auth->refs++;
	chain_record((struct chain_event){ .kind = CHAIN_EV_LEASE, .endpoint = dev->endpoint,
		.device = peer, .offset = offset, .length = len, .address = h->lease.dma_address,
		.member = dir, .worker = chain_core_current_worker() });
	return 0;
}
void CHAIN_STUB(xdev_ext_peer_fd_release)(struct xdev_ext_peer_fd_lease *h, bool quiesced)
{
	struct chain_lease *l;

	if (!h || !h->file)
		return;
	l = (struct chain_lease *)h->lease.mapping;
	assert(l >= chain_leases && l < chain_leases + chain_nleases && l->live && l->ticket == h->lease.ticket);
	l->live = false;
	l->retained = !quiesced;
	chain_record((struct chain_event){ .kind = CHAIN_EV_RELEASE, .endpoint = l->dev->endpoint,
		.device = l->dev->device, .offset = l->offset, .length = l->len, .quiesced = quiesced,
		.worker = chain_core_current_worker() });
	fput(h->file);
	memset(h, 0, sizeof(*h));
}
/* LEASE_SPLIT */

static int chain_dma_page(const struct chain_device *dev, uint64_t dma, u8 *buf, uint32_t len,
			  bool device_writes);
/* One device access may span pages that are contiguous in its own window
 * (an SGL data block over two leased pages); each page is checked alone. */
int chain_dma_access(const void *device, uint64_t dma, void *buf, uint32_t len, bool device_writes)
{
	const struct chain_device *dev = chain_device_of(device);
	u8 *bytes = buf;

	while (len) {
		uint32_t chunk = min_t(uint32_t, len, CHAIN_PAGE - dma % CHAIN_PAGE);
		int ret = chain_dma_page(dev, dma, bytes, chunk, device_writes);
		if (ret)
			return ret;
		dma += chunk;
		bytes += chunk;
		len -= chunk;
	}
	return 0;
}
static int chain_dma_page(const struct chain_device *dev, uint64_t dma, u8 *buf, uint32_t len,
			  bool device_writes)
{
	u64 window_page, page, offset;

	if (!dev || dma < dev->base || dma >= dev->base + (u64)chain_pages() * CHAIN_PAGE ||
	    dma % CHAIN_PAGE + len > CHAIN_PAGE)
		goto fault;
	window_page = (dma - dev->base) / CHAIN_PAGE;
	for (page = 0; page < chain_pages() && chain_window_page(dev, page) != window_page; page++)
		;
	offset = page * CHAIN_PAGE + dma % CHAIN_PAGE;
	/* The device reaches only bytes it holds a live lease for, in that direction. */
	for (unsigned i = chain_nleases; i; i--) {
		const struct chain_lease *l = &chain_leases[i - 1];
		if (l->dev != dev || !l->live || offset < l->offset || offset + len > l->offset + l->len)
			continue;
		if (l->dir != (device_writes ? DMA_FROM_DEVICE : DMA_TO_DEVICE))
			goto fault;
		if (device_writes)
			memcpy(chain_memory[dev->endpoint] + offset, buf, len);
		else
			memcpy(buf, chain_memory[dev->endpoint] + offset, len);
		return 0;
	}
fault:
	chain_lease_violations++;
	fprintf(stderr, "CHAIN_DMA_FAULT device=%p dma=%llx len=%u write=%d\n",
		dev ? dev->device : NULL, (unsigned long long)dma, len, device_writes);
	return -EFAULT;
}

/* Called by the real-NHI adapter when the link delivers one data frame. */
static void chain_link_payload(unsigned from, unsigned long long tx_dma, unsigned to,
			       unsigned long long rx_dma, unsigned len)
{
	u8 bounce[CHAIN_PAGE];
	int status;

	assert(len <= CHAIN_PAGE);
	status = chain_dma_access(&world->side[from].pci, tx_dma, bounce, len, false);
	if (!status)
		status = chain_dma_access(&world->side[to].pci, rx_dma, bounce, len, true);
	chain_record((struct chain_event){ .kind = CHAIN_EV_DATA_DELIVER, .endpoint = from,
		.address = tx_dma, .offset = rx_dma, .length = len, .status = status });
}

/* Recording requester bind; the stage keeps its own device as requester. */
int CHAIN_STUB(xdev_ext_requester_bind)(struct xdev_ext_requester *rq, struct xdev_ext_mech_stage *st,
			    struct pci_dev *pdev, u32 flags)
{
	struct chain_device *dev = chain_device_of(pdev);
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);

	(void)flags;
	if (!dev || (int)dev->endpoint != session_endpoint(st->s) || rq->pdev)
		return -EXDEV;
	rq->pdev = pdev;
	rq->authority = xdev_ext_peer_mech_pool_file(pool);
	rq->generation = xdev_ext_peer_mech_pool_generation(pool);
	rq->adm = (struct xdev_ext_admission){ .reachability = XDEV_EXT_CAP_HOST_DMA_MAPPED,
		.backing = XDEV_EXT_PEER_BACKING_HOST_SYSTEM | XDEV_EXT_PEER_BACKING_STRUCT_PAGE,
		.distance = -1 };
	st->caps.reachability = XDEV_EXT_CAP_HOST_DMA_MAPPED;
	st->caps.backing = rq->adm.backing;
	st->caps.requester_mapping = XDEV_EXT_CAP_ESTABLISHED;
	chain_record((struct chain_event){ .kind = CHAIN_EV_LEASE, .endpoint = dev->endpoint,
		.device = pdev, .stage = st->index, .member = 99 });
	return 0;
}
void CHAIN_STUB(xdev_ext_requester_unbind)(struct xdev_ext_requester *rq) { rq->pdev = NULL; }

#ifdef CHAIN_REAL_PEER
/* Host 1 (endpoint 0): real REGISTER/claim/requester bind/leases on a
 * system-heap DMA-BUF (chain_peer_bridge.c); host 2 keeps the provider above. */
int chain_bridge_setup(u64 bytes);
struct file *chain_bridge_register(u64 bytes, u64 *generation);
struct file *chain_bridge_control(void);
void *chain_bridge_twin(const void *original, u32 id);
const void *chain_bridge_original(const void *pointer);
bool chain_bridge_owns_twin(const void *pointer);
void chain_bridge_window(u64 first, u32 first_len, u64 second, u32 second_len);
int chain_bridge_requester_bind(struct xdev_ext_requester *rq, struct xdev_ext_mech_stage *st, void *twin);
void chain_bridge_requester_unbind(struct xdev_ext_requester *rq);
int chain_bridge_acquire(struct file *f, void *twin, u64 generation, u64 offset, u32 len,
			 enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h);
void chain_bridge_release(struct xdev_ext_peer_fd_lease *h, bool quiesced);
struct file *chain_real_peer_file_claim(struct file *, u64 *, u64 *);
bool chain_real_peer_control_file(struct file *);
static struct file *chain_real_allocation, *chain_real_control;
static struct { struct xdev_ext_peer_fd_lease *h; u64 ticket; unsigned lease; } chain_real_leases[4096];
static unsigned chain_nreal;

bool xdev_ext_peer_control_file(struct file *file)
{
	return file == chain_real_control ? chain_real_peer_control_file(file) :
	       chain_stub_xdev_ext_peer_control_file(file);
}
struct file *xdev_ext_peer_file_claim(struct file *file, u64 *len, u64 *generation)
{
	return file == chain_real_allocation ? chain_real_peer_file_claim(file, len, generation) :
	       chain_stub_xdev_ext_peer_file_claim(file, len, generation);
}
int xdev_ext_requester_bind(struct xdev_ext_requester *rq, struct xdev_ext_mech_stage *st,
			    struct pci_dev *pdev, u32 flags)
{
	struct chain_device *dev = chain_device_of(pdev);
	u64 half = chain_pages() / 2;
	int ret;

	if (!dev || dev->endpoint != 0 || session_endpoint(st->s) != 0)
		return chain_stub_xdev_ext_requester_bind(rq, st, pdev, flags);
	chain_bridge_window(dev->base + half * CHAIN_PAGE, (u32)(half * CHAIN_PAGE),
			    dev->base, (u32)((chain_pages() - half) * CHAIN_PAGE));
	ret = chain_bridge_requester_bind(rq, st, chain_bridge_twin(pdev, dev->kind));
	if (!ret)
		chain_record((struct chain_event){ .kind = CHAIN_EV_LEASE, .endpoint = 0, .device = pdev,
			.stage = st->index, .member = 99, .address = rq->adm.backing,
			.length = st->caps.reachability, .offset = rq->adm.refused });
	return ret;
}
void xdev_ext_requester_unbind(struct xdev_ext_requester *rq)
{
	if (chain_bridge_owns_twin(rq->pdev))
		chain_bridge_requester_unbind(rq);
	else
		chain_stub_xdev_ext_requester_unbind(rq);
}
int xdev_ext_peer_file_acquire(struct file *file, struct pci_dev *peer, u64 generation, u64 offset,
			       u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h)
{
	const void *original = chain_bridge_original(peer) ? chain_bridge_original(peer) : peer;
	struct chain_device *dev = chain_device_of(original);
	int ret;

	if (chain_fd_of(file))
		return chain_stub_xdev_ext_peer_file_acquire(file, peer, generation, offset, len, dir, h);
	if (!dev || dev->endpoint != 0)
		return -EINVAL;
	ret = chain_bridge_acquire(file, chain_bridge_twin(original, dev->kind), generation, offset, len, dir, h);
	if (ret)
		return ret;
	assert(chain_nleases < CHAIN_LEASES && chain_nreal < ARRAY_SIZE(chain_real_leases));
	for (unsigned i = 0; i < chain_nleases; i++) {
		struct chain_lease *o = &chain_leases[i];
		if (o->dev->endpoint == 0 && chain_overlap(o->offset, o->len, offset, len) &&
		    (o->retained || (o->live && (dir == DMA_FROM_DEVICE || o->dir == DMA_FROM_DEVICE)))) {
			chain_lease_violations++;
			fprintf(stderr, "CHAIN_LEASE_VIOLATION ep=0 off=%llu len=%u\n", (unsigned long long)offset, len);
		}
	}
	chain_leases[chain_nleases] = (struct chain_lease){ dev, offset, h->lease.ticket, len, dir, true, false };
	chain_real_leases[chain_nreal++] = (typeof(chain_real_leases[0])){ h, h->lease.ticket, chain_nleases++ };
	if (h->lease.dma_address != chain_page_dma(dev, offset))
		chain_lease_violations++; /* the importer's address must be this device's attachment */
	chain_record((struct chain_event){ .kind = CHAIN_EV_LEASE, .endpoint = 0, .device = original,
		.offset = offset, .length = len, .address = h->lease.dma_address, .member = dir,
		.worker = chain_core_current_worker() });
	return 0;
}
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool quiesced)
{
	if (!h || !h->file)
		return;
	if (chain_fd_of(h->file)) {
		chain_stub_xdev_ext_peer_fd_release(h, quiesced);
		return;
	}
	for (unsigned i = chain_nreal; i; i--)
		if (chain_real_leases[i - 1].h == h && chain_real_leases[i - 1].ticket == h->lease.ticket) {
			struct chain_lease *l = &chain_leases[chain_real_leases[i - 1].lease];
			assert(l->live);
			l->live = false;
			l->retained = !quiesced;
			chain_record((struct chain_event){ .kind = CHAIN_EV_RELEASE, .endpoint = 0,
				.device = l->dev->device, .offset = l->offset, .length = l->len,
				.quiesced = quiesced, .worker = chain_core_current_worker() });
			chain_real_leases[i - 1].h = NULL;
			chain_bridge_release(h, quiesced);
			return;
		}
	abort(); /* a real lease this fixture never saw */
}
#endif

/* ---- BPF invocation of the reference programs ------------------------- */
struct xdev_ext_mech_ctx chain_program_ctx(struct xdev_ext_mech_stage *st,
					   const struct xdev_ext_mech_call_args *a);
struct xdev_ext_mech_ctx chain_program_ctx(struct xdev_ext_mech_stage *st,
					   const struct xdev_ext_mech_call_args *a)
{
	/* The context xdev_ext_mech_invoke() builds from the core target. */
	struct xdev_ext_mech_ctx c = { 0 };
	u64 batch = a->b ? xdev_ext_mech_batch_id(a->b) : a->batch_id;

	c.base = *a->base;
	c.base.event = a->member == XDEV_EXT_MECH_MEMBER_COMPLETE ? XDEV_EXT_BINDING_EVENT_COMPLETE :
		       XDEV_EXT_BINDING_EVENT_DISPATCH;
	c.base.request_id = batch;
	c.base.chain_id = chain_real_session_id(st->s);
	if (a->b) {
		c.base.src_offset = xdev_ext_mech_batch_key(a->b);
		c.base.length = xdev_ext_mech_batch_bytes(a->b);
	}
	c.mech_abi_version = st->cls->decl->mech_abi_version;
	c.member = a->member;
	c.class_id = st->class_id;
	c.callsite = a->callsite;
	c.nr_frames = a->nr_frames;
	c.session_id = chain_real_session_id(st->s);
	c.batch_id = batch;
	return c;
}
unsigned chain_program_context_violations;
int xdev_ext_mech_call(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_call_args *a,
		       s32 *ret, struct xdev_ext_mech_hold_intent *hold)
{
	struct xdev_ext_mech_ctx ctx;

	(void)hold;
	/* Programs run in process context only: never with a fixture-observed
	 * lock held or inside a native completion callback. */
	if (stack_spins || stack_mutexes || world->in_callback) {
		chain_program_context_violations++;
		fprintf(stderr, "CHAIN_PROGRAM_CONTEXT spins=%u mutexes=%u callback=%d\n",
			stack_spins, stack_mutexes, world->in_callback);
	}
	chain_record((struct chain_event){ .kind = CHAIN_EV_PROGRAM, .endpoint = stack_endpoint_stage(st),
		.stage = st->index, .member = a->member, .control_type = a->callsite,
		.worker = chain_core_current_worker(), .group = a->b ? xdev_ext_mech_batch_key(a->b) : 0 });
	if (st->class_id == XDEV_EXT_MECH_CLASS_XDOMAIN)
		return stack_x6_call(st, a, ret);
	if (st->class_id != XDEV_EXT_MECH_CLASS_NVME)
		abort();
	if (a->member == XDEV_EXT_MECH_MEMBER_PREPARE)
		return -ENOENT; /* nvme_s0 has no prepare member */
	ctx = chain_program_ctx(st, a);
	return chain_x6_program_call(st, a, &ctx, a->member == XDEV_EXT_MECH_MEMBER_BUILD ?
				     nvme_s0_build : nvme_s0_complete, ret);
}
bool xdev_ext_mech_stage_has_member(const struct xdev_ext_mech_stage *st, u32 member)
{
	if (member == XDEV_EXT_MECH_MEMBER_BUILD || member == XDEV_EXT_MECH_MEMBER_COMPLETE)
		return true;
	return member == XDEV_EXT_MECH_MEMBER_PREPARE && st->class_id == XDEV_EXT_MECH_CLASS_XDOMAIN;
}

/* ---- world, sessions and START ---------------------------------------- */
static struct chain_link_config chain_cfg;
static int chain_nvme_fd[CHAIN_ENDPOINTS];
int chain_world(const struct chain_link_config *cfg)
{
	struct stack_config sc;
	struct stack_world *w = NULL;
	int ret;

	memset(&sc, 0, sizeof(sc));
	sc.local_inc[0] = 101; sc.local_inc[1] = 203;
	sc.generation[0] = chain_generation[0]; sc.generation[1] = chain_generation[1];
	sc.depth = cfg->depth; sc.nr_frames = cfg->nr_frames; sc.frame_size = cfg->frame_size;
	sc.native_elems = cfg->group_bytes / cfg->frame_size; sc.channels = 1;
	chain_cfg = *cfg;
	chain_events = calloc(CHAIN_EVENTS, sizeof(*chain_events));
	chain_leases = calloc(CHAIN_LEASES, sizeof(*chain_leases));
	assert(chain_events && chain_leases);
	ret = stack_new(&sc, &w);
	if (ret)
		return ret;
	chain_memory_bytes = (size_t)cfg->nr_frames * cfg->frame_size;
	for (unsigned e = 0; e < CHAIN_ENDPOINTS; e++) {
		void *file;
		chain_memory[e] = calloc(1, chain_memory_bytes);
		assert(chain_memory[e]);
		chain_register_device(&w->side[e].pci, e, CHAIN_DEV_NHI);
		chain_nvme_create(e, 9, 2048, e == 1, &file);
		chain_nvme_fd[e] = chain_install(file, CHAIN_FILE_FOREIGN, e);
		chain_install(&chain_control[e], CHAIN_FILE_CONTROL, e);
		chain_install(&chain_allocation[e], CHAIN_FILE_ALLOCATION, e);
	}
#ifdef CHAIN_REAL_PEER
	ret = chain_bridge_setup(chain_memory_bytes);
	if (ret)
		return ret;
	chain_real_allocation = chain_bridge_register(chain_memory_bytes, &chain_generation[0]);
	chain_real_control = chain_bridge_control();
	if (!chain_real_allocation || !chain_real_control)
		return -EIO;
	chain_install(chain_real_allocation, CHAIN_FILE_FOREIGN, 0);
	chain_install(chain_real_control, CHAIN_FILE_FOREIGN, 0);
#endif
	chain_nvme_init_class();
	ret = stack_probe(w, 0);
	if (!ret)
		ret = stack_probe(w, 1);
	if (!ret)
		ret = stack_pump(w, 100000, 1000000);
	return ret;
}
uint64_t chain_link_token(unsigned endpoint) { return link(endpoint)->token; }
static int chain_fd_for(void *file)
{
	for (int fd = 0; fd < CHAIN_FDS; fd++)
		if (chain_fds[fd].file == file)
			return fd;
	abort();
}
static struct xdev_ext_mech_session *chain_create(unsigned endpoint, const struct xdev_ext_mech_create *c,
						 int *err)
{
	struct xdev_ext_mech_session *s;

	chain_creating = (int)endpoint;
	s = chain_session_create(c, err);
	chain_creating = -1;
	if (!*err)
		chain_sessions[endpoint] = s;
	return s;
}
static void *chain_host1_allocation(void)
{
#ifdef CHAIN_REAL_PEER
	return chain_real_allocation;
#else
	return &chain_allocation[0];
#endif
}
static void *chain_host1_control(void)
{
#ifdef CHAIN_REAL_PEER
	return chain_real_control;
#else
	return &chain_control[0];
#endif
}
/* Host 1: stage 0 NVMe READ of the LBA window, stage 1 XDOMAIN TX. */
struct xdev_ext_mech_session *chain_tx_session(int *err, uint64_t token_override)
{
	struct xdev_ext_mech_create c = {
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = chain_fd_for(chain_host1_allocation()),
		.layout = { .frame_size = chain_cfg.frame_size, .seg_len = chain_cfg.frame_size,
			    .group_bytes = chain_cfg.group_bytes },
		.depth = chain_cfg.depth, .eventfd = -1,
		.st = {
			{ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE,
			  .fd = chain_nvme_fd[0], .arg0 = 256, .arg1 = 256 },
			{ .class_id = XDEV_EXT_MECH_CLASS_XDOMAIN, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
			  .fd = chain_fd_for(chain_host1_control()),
			  .arg0 = token_override ? token_override : chain_link_token(0), .arg1 = 0,
			  .flags = chain_cfg.early ? XDEV_EXT_XDOMAIN_F_EARLY : 0 },
		},
	};
	return chain_create(0, &c, err);
}
/* Host 2: stage 0 XDOMAIN RX into its frames, stage 1 NVMe WRITE of them. */
struct xdev_ext_mech_session *chain_rx_session(int *err)
{
	struct xdev_ext_mech_create c = {
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = chain_fd_for(&chain_allocation[1]),
		.layout = { .frame_size = chain_cfg.frame_size, .seg_len = chain_cfg.frame_size,
			    .group_bytes = chain_cfg.group_bytes },
		.depth = chain_cfg.depth, .eventfd = -1,
		.st = {
			{ .class_id = XDEV_EXT_MECH_CLASS_XDOMAIN, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE,
			  .fd = chain_fd_for(&chain_control[1]), .arg0 = chain_link_token(1), .arg1 = 0,
			  .flags = chain_cfg.early ? XDEV_EXT_XDOMAIN_F_EARLY : 0 },
			{ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
			  .fd = chain_nvme_fd[1], .arg0 = 512, .arg1 = 256 },
		},
	};
	return chain_create(1, &c, err);
}
int chain_start(struct xdev_ext_mech_session *s, uint64_t batches, uint64_t first_seq)
{
	chain_record((struct chain_event){ .kind = CHAIN_EV_START, .endpoint = session_endpoint(s),
		.length = batches, .group = first_seq });
	return chain_session_start(s, batches, first_seq);
}

/* ---- holds and injected wire duplicates ------------------------------- */
void chain_hold_tx_completions(unsigned endpoint, bool hold) { world->hold_callbacks[endpoint] = hold; }
void chain_hold_ack(unsigned endpoint, bool hold)
{
	world->hold_controls[endpoint] = hold;
	world->hold_control_type[endpoint] = hold ? XDEV_EXT_XD_ACK : 0;
	if (!hold)
		for (unsigned i = 0; i < world->nn; i++)
			if (ring_info(world->n[i].r)->endpoint == endpoint)
				world->n[i].held = false;
}
/* Deliver again the bytes of the nth control message of @type that
 * @from_endpoint sent, into a posted control RX descriptor of the peer:
 * the real NHI completes it and real X4/X5 dispatch the duplicate. */
int chain_inject_stale_control(unsigned from_endpoint, unsigned type, uint64_t nth)
{
	struct native *tx = NULL, *rx = NULL;
	uint64_t seen = 0;

	for (unsigned i = 0; i < world->nn && !tx; i++) {
		struct native *n = &world->n[i];
		if (ring_info(n->r)->control && ring_info(n->r)->is_tx &&
		    ring_info(n->r)->endpoint == from_endpoint && n->raw_len > 5 && n->raw[5] == type &&
		    n->delivered && ++seen == nth)
			tx = n;
	}
	if (!tx)
		return -ENOENT;
	for (unsigned i = 0; i < world->nn && !rx; i++) {
		struct native *n = &world->n[i];
		if (native_live(n) && ring_info(n->r)->control && !ring_info(n->r)->is_tx &&
		    ring_info(n->r)->endpoint != from_endpoint && !n->delivered &&
		    stack_nhi_visible(n->r, n->f))
			rx = n;
	}
	if (!rx)
		return -EAGAIN;
	memcpy((void *)(uintptr_t)rx->f->buffer_phy, tx->raw, tx->raw_len);
	memcpy(rx->raw, tx->raw, tx->raw_len);
	rx->raw_len = tx->raw_len;
	rx->completion_len = tx->raw_len;
	rx->completion_sof = tx->f->sof;
	rx->completion_eof = tx->f->eof;
	rx->delivered = true;
	chain_record((struct chain_event){ .kind = CHAIN_EV_INJECT, .endpoint = 1 - from_endpoint,
		.control_type = type, .length = tx->raw_len });
	return 0;
}

/* ---- observation helpers for the assertions --------------------------- */
unsigned chain_control_tx_count(unsigned endpoint, unsigned type)
{
	unsigned n = 0;
	for (size_t i = 0; i < world->logs; i++)
		n += world->log[i].kind == STACK_EV_CONTROL_TX && world->log[i].endpoint == endpoint &&
		     world->log[i].control_type == type;
	return n;
}
unsigned chain_data_tx_done(unsigned endpoint)
{
	unsigned n = 0;
	for (size_t i = 0; i < world->logs; i++)
		n += world->log[i].kind == STACK_EV_DATA_CALLBACK && world->log[i].endpoint == endpoint &&
		     world->log[i].direction == 1 && !world->log[i].status;
	return n;
}
const void *chain_device(unsigned endpoint, enum chain_device_kind kind)
{
	for (unsigned i = 0; i < chain_ndevices; i++)
		if (chain_devices[i].endpoint == endpoint && chain_devices[i].kind == kind)
			return chain_devices[i].device;
	return NULL;
}
unsigned chain_violations(void) { return chain_lease_violations + chain_program_context_violations; }
unsigned chain_live_leases(unsigned endpoint, enum chain_device_kind kind, uint64_t offset, uint32_t len)
{
	unsigned n = 0;
	for (unsigned i = 0; i < chain_nleases; i++) {
		const struct chain_lease *l = &chain_leases[i];
		n += l->live && l->dev->endpoint == endpoint && l->dev->kind == kind &&
		     chain_overlap(l->offset, l->len, offset, len);
	}
	return n;
}
/* The requester the bind recorded for this stage (event written at bind). */
const void *chain_stage_requester(struct xdev_ext_mech_session *s, unsigned stage)
{
	int endpoint = session_endpoint(s);
	for (size_t i = 0; i < chain_nevents; i++)
		if (chain_events[i].kind == CHAIN_EV_LEASE && chain_events[i].member == 99 &&
		    (int)chain_events[i].endpoint == endpoint && chain_events[i].stage == stage)
			return chain_events[i].device;
	return NULL;
}

bool chain_real_peer_mode(void)
{
#ifdef CHAIN_REAL_PEER
	return true;
#else
	return false;
#endif
}
/* What the real requester bind recorded for host 1's stage (DMA-BUF mode). */
bool chain_stage_admission(struct xdev_ext_mech_session *s, unsigned stage, uint32_t *backing,
			   uint32_t *reachability, uint32_t *refused)
{
	int endpoint = session_endpoint(s);
	for (size_t i = 0; i < chain_nevents; i++)
		if (chain_events[i].kind == CHAIN_EV_LEASE && chain_events[i].member == 99 &&
		    (int)chain_events[i].endpoint == endpoint && chain_events[i].stage == stage) {
			*backing = (uint32_t)chain_events[i].address;
			*reachability = (uint32_t)chain_events[i].length;
			*refused = (uint32_t)chain_events[i].offset;
			return true;
		}
	return false;
}

/* ---- one deterministic scheduler ------------------------------------- */
static bool chain_world_work(void)
{
	struct work_struct *work = NULL;
	unsigned index = 0;

	for (unsigned i = 0; i < world->nwork; i++)
		if (world->work[i]->pending && world->work[i]->due <= world->now) {
			work = world->work[i];
			index = i;
			break;
		}
	if (!work)
		return false;
	for (unsigned endpoint = 0; endpoint < 2; endpoint++) {
		struct xdev_ext_xd_link *xl;
		if (!world->side[endpoint].probed || world->side[endpoint].removed)
			continue;
		xl = link(endpoint);
		if (work == &xl->login_work.work || work == &xl->connect_work ||
		    work == &xl->down_work || work == &xl->probe_work.work)
			world->active = endpoint;
	}
	work->pending = false;
	world->nwork--;
	memmove(&world->work[index], &world->work[index + 1], (world->nwork - index) * sizeof(world->work[0]));
	work->fn(work);
	return true;
}
int chain_pump(unsigned budget, uint64_t advance_ns)
{
	unsigned used = 0;

	world->now += advance_ns;
	jiffies = nsecs_to_jiffies(world->now);
	for (;;) {
		bool ran = false;

		if (used == budget)
			return -ELOOP;
		if (chain_world_work())
			ran = true;
		else if (chain_core_run_one())
			ran = true;
		else if (native_ready()) {
			assert(one_native());
			ran = true;
		} else if (chain_nvme_ready()) {
			chain_nvme_complete_one();
			ran = true;
		}
		if (!ran)
			return 0;
		used++;
	}
}
