// SPDX-License-Identifier: GPL-2.0
/*
 * Zero-copy AF_XDP TX wakeup custody against a driver whose link goes down.
 *
 * production.c.inc and production_journal.h hold the verbatim production
 * bodies the pool_dma adapter extracts (submit, kernel source peek/batch,
 * completion, cancellation, stop, the wakeup helper); wakeup_extra.c.inc adds
 * xsk_xdev_ext_mech_link_up() (netdev notifier side), xsk_mech_zc_rewake()
 * (session worker side) and xsk_rel_wakeup().  Only the device and the session
 * worker kick are simulated, with the early returns of the pinned drivers:
 *   igb  igb_xsk_wakeup(): -ENETDOWN when down, -EINVAL without XDP, else 0;
 *        igb_xmit_zc() returns before peeking without carrier.
 *   ice  ice_xsk_wakeup(): -ENETDOWN when down or without carrier, -EINVAL
 *        without XDP; ice_xmit_zc() returns before peeking without carrier.
 *   mlx5 mlx5e_xsk_wakeup(): -ENETDOWN without an active XDP program.
 */
#define XDEV_EXT_TEST_LINK_STATE 1
#include "os_boundary.h"
static bool link_running = true, link_carrier = true;
static bool netif_running(const struct net_device *d) { (void)d; return link_running; }
static bool netif_carrier_ok(const struct net_device *d) { (void)d; return link_carrier; }
/* Session core boundary: the worker kick and STOP admission. */
static int kicks;
static bool session_admits = true;
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st)
{
	(void)st;
	REQUIRE("kick_outside_provider_lock", !lock_depth);
	kicks++;
	ev("K ");
}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s)
{
	(void)s;
	return session_admits;
}
#ifndef smp_load_acquire
#define smp_load_acquire(p) (*(p))
#endif
static void boundary_raw(struct xsk_buff_pool *, u64);
static dma_addr_t xp_raw_get_dma(struct xsk_buff_pool *, u64);
static void xp_dma_sync_for_device(struct xsk_buff_pool *, dma_addr_t, size_t);
#include "production.c.inc"
#include "wakeup_extra.c.inc"

static struct xsk_xdev_ext_mech_provider p;
static struct xsk_xdev_ext_mech_stage xst;
static struct xsk_xdev_ext_mech_tx_batch tb;
static struct xdev_ext_mech_stage st;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_pool pool;
static struct xdev_ext_mech_batch batch;
static struct xdp_sock xs;
static struct xdp_umem umem;
static struct xsk_buff_pool xp;
static struct xsk_mech_zc_slot slots[8];
static struct xdp_desc descs[8];
static struct xdp_buff_xsk heads[3];
static struct xsk_dma_map shared_map;
static struct device nic = {17};
static void *pages[3];
static dma_addr_t maps[3] = {0x100000, 0x300000, 0x500000};
static u8 chunks[3][4096];
static u64 tags[3];

enum { DRV_IGB, DRV_ICE, DRV_MLX5 };
static int drv_kind, drv_wakes, drv_taken;
static bool drv_xdp;

static int fake_wakeup(struct net_device *dev, u32 q, u32 flags)
{
	(void)dev;
	REQUIRE("wakeup_socket_lock", mutex_depth == 1 && lock_depth == 0 && q == 7 &&
		flags == XDP_WAKEUP_TX);
	drv_wakes++;
	ev("W ");
	if (!link_running || (drv_kind == DRV_ICE && !link_carrier))
		return -ENETDOWN;
	if (!drv_xdp)
		return drv_kind == DRV_MLX5 ? -ENETDOWN : -EINVAL;
	/* NAPI: the transmit routine leaves the source alone without carrier. */
	if (link_carrier)
		drv_taken += xsk_tx_peek_release_desc_batch(&xp, 8);
	return 0;
}
static const struct net_device_ops nops = {fake_wakeup};
static struct net_device netdev = {&nops};
static const u8 packet_prefix[42] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0,
	0x45, 0, 0, 0x2c, 0x12, 0x34, 0, 0, 0x40, 0x11, 0xaa, 0xbb, 0xc0, 0, 2, 1, 0xc6, 0x33, 0x64, 2,
	0x12, 0x34, 0x56, 0x78, 0, 0x18, 0xcc, 0xdd};

static void reset(const char *name, int kind)
{
	case_name = name;
	lock_depth = mutex_depth = lock_epoch = 0;
	event_n = 0;
	events[0] = 0;
	callbacks = complete_status = dead_status = count_ops = count_bytes = 0;
	seq_callbacks = cancel_callbacks = 0;
	sync_dev_n = sync_cpu_n = raw_n = trace_n = wakeup_n = peek_on_wakeup = wakeup_result = 0;
	memset(check_epoch, 0, sizeof(check_epoch));
	memset(&p, 0, sizeof(p));
	memset(&xst, 0, sizeof(xst));
	memset(&tb, 0, sizeof(tb));
	memset(&xs, 0, sizeof(xs));
	memset(&xp, 0, sizeof(xp));
	memset(&pool, 0, sizeof(pool));
	memset(&batch, 0, sizeof(batch));
	memset(slots, 0, sizeof(slots));
	memset(tags, 0, sizeof(tags));
	drv_kind = kind;
	drv_xdp = true;
	drv_wakes = drv_taken = kicks = 0;
	session_admits = true;
	link_running = link_carrier = true;
	xp.dev = &nic;
	xp.dma_pages = malloc(sizeof(maps));
	memcpy(xp.dma_pages, maps, sizeof(maps));
	xp.dma_pages_cnt = 3;
	xp.chunk_size = 4096;
	xp.heads_cnt = 3;
	xp.umem = &umem;
	xp.heads = heads;
	xp.addrs = &chunks[0][0];
	umem.npgs = umem.chunks = 3;
	umem.size = 12288;
	umem.pgs = pages;
	INIT_LIST_HEAD(&umem.xsk_dma_list);
	INIT_LIST_HEAD(&shared_map.list);
	shared_map.netdev = &netdev;
	shared_map.users = 2;
	xp.netdev = &netdev;
	list_add_tail(&shared_map.list, &umem.xsk_dma_list);
	xp.tx_descs_capacity = 8;
	xp.tx_descs = descs;
	xp.xdev_ext_mech_tx = &p;
	INIT_LIST_HEAD(&xp.xsk_tx_list);
	xs.pool = &xp;
	xs.umem = &umem;
	xs.dev = &netdev;
	xs.queue_id = 7;
	xs.state = XSK_BOUND;
	xs.zc = true;
	xs.xdev_ext_mech_tx = &st;
	p.xs = &xs;
	p.xp = &xp;
	p.zc = true;
	p.slots = slots;
	p.ring.capacity = 8;
	p.ring.native_head = p.ring.native_tail = XSK_MECH_ZC_NONE;
	pool.ops = &xsk_xdev_ext_mech_pool_ops;
	pool.priv = &p;
	pool.pages = pages;
	pool.frame_size = 4096;
	pool.nr_frames = 3;
	session.pool = &pool;
	st.s = &session;
	st.priv = &xst;
	xst.xs = &xs;
	xst.tx_staged = &batch;
	xst.tx_staged_id = 77;
	xst.tx_n = 3;
	batch.s = &session;
	batch.nr_frames = 3;
	batch.id = 77;
	batch.ticket = 91;
	batch.priv = &tb;
	tb.ticket = 91;
	for (u32 i = 0; i < 3; i++) {
		memset(chunks[i], 0x31 + i, sizeof(chunks[i]));
		memcpy(chunks[i] + 22, packet_prefix, 42);
		batch.f[i] = (struct xdev_ext_mech_frame){.kaddr = chunks[i], .umem_addr = (u64)i * 4096,
			.index = i, .data_off = 64, .data_len = 16, .pool_priv = &heads[i]};
		xst.tx_desc[i] = (struct xdp_desc){(u64)i * 4096 + 22, 58, 0};
		xst.tx_pkt[i] = chunks[i] + 22;
		xst.tx_tag[i] = &tags[i];
	}
	observed_provider = &p;
	observed_stage = &xst;
}

/*
 * xsk_notifier() runs the hook under RCU only (the netdev instance lock may be
 * held); it may flag the provider and kick the worker but never wake.
 */
static void link_up(void)
{
	int before = drv_wakes;

	REQUIRE("notifier_holds_no_socket_mutex", !mutex_depth && !lock_depth);
	xsk_xdev_ext_mech_link_up(&xs);
	REQUIRE("notifier_never_wakes_the_driver", drv_wakes == before && !mutex_depth);
}

/* The session worker's ->progress pass after the kick. */
static void worker(void)
{
	REQUIRE("worker_holds_no_lock", !mutex_depth && !lock_depth);
	xsk_mech_zc_rewake(&st);
	REQUIRE("worker_releases_locks", !mutex_depth && !lock_depth);
}

static int probe(void)
{
	int err;

	mutex_lock(&xs.mutex);
	err = xsk_mech_zc_wake(&xs);
	mutex_unlock(&xs.mutex);
	return err;
}

/* The measured igb stall: the wakeup is taken, the source is not. */
static void igb_dropped_wakeup_is_repeated_at_link_up(void)
{
	reset("igb_carrier_down", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("dropped_wakeup_keeps_source", drv_wakes == 1 && drv_taken == 0 &&
	      p.ring.prod == 3 && p.ring.issued == 0 && !p.stopped && !dead_status && !callbacks);
	link_carrier = true;
	link_up();
	CHECK("link_up_kicks_worker", kicks == 1 && drv_wakes == 1);
	worker();
	CHECK("link_up_wakes_once", drv_wakes == 2);
	CHECK("link_up_drains_source", drv_taken == 3 && p.ring.issued == 3 && !p.stopped &&
	      !dead_status);
	worker();
	CHECK("rewake_consumed", drv_wakes == 2);
	xsk_tx_completed(&xp, 3);
	CHECK("link_up_batch_completes", callbacks == 1 && complete_status == 0 && p.ring.cons == 3 &&
	      !seq_callbacks && !cancel_callbacks);
	link_up();
	worker();
	CHECK("drained_source_no_wakeup", drv_wakes == 2 && kicks == 1);
}

/* ice refuses the wakeup outright while the carrier is down. */
static void ice_link_down_refusal_waits_for_link_up(void)
{
	reset("ice_carrier_down", DRV_ICE);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("link_down_refusal_is_not_fatal", drv_wakes == 1 && !p.stopped && !dead_status &&
	      !callbacks && !cancel_callbacks && !seq_callbacks);
	CHECK("link_down_refusal_keeps_source", p.ring.prod == 3 && p.ring.issued == 0 &&
	      !p.ring.fatal && tags[0] == 77 && tags[2] == 77);
	link_carrier = true;
	link_up();
	worker();
	CHECK("link_up_drains_source", drv_wakes == 2 && drv_taken == 3 && p.ring.issued == 3);
	xsk_tx_completed(&xp, 3);
	CHECK("link_up_batch_completes", callbacks == 1 && complete_status == 0 && !cancel_callbacks);
}

/* A down interface: igb/ixgbe/igc/virtio_net report -ENETDOWN, NETDEV_UP returns. */
static void interface_down_refusal_waits_for_link_up(void)
{
	reset("igb_interface_down", DRV_IGB);
	link_running = link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("down_interface_is_not_fatal", !p.stopped && !dead_status && !callbacks &&
	      p.ring.prod == 3 && p.ring.issued == 0);
	link_running = link_carrier = true;
	link_up();
	worker();
	CHECK("interface_up_drains_source", drv_wakes == 2 && drv_taken == 3);
}

/* Configuration refusals with the link up stay fatal, as before. */
static void configuration_refusal_stays_fatal(void)
{
	reset("igb_no_xdp", DRV_IGB);
	drv_xdp = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("no_xdp_is_fatal", p.stopped && dead_status == -EINVAL);
	CHECK("no_xdp_untaken_suffix_cancelled", callbacks == 1 && cancel_callbacks == 1 &&
	      !seq_callbacks && p.ring.native_count == 0);

	reset("mlx5_xdp_inactive", DRV_MLX5);
	drv_xdp = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("enetdown_with_link_up_is_fatal", p.stopped && dead_status == -ENETDOWN &&
	      callbacks == 1 && cancel_callbacks == 1);
}

/* CREATE probes the still-empty source: refusal iff a configuration fault. */
static void create_probe_refuses_only_configuration_faults(void)
{
	reset("probe_igb_no_xdp", DRV_IGB);
	drv_xdp = false;
	CHECK("probe_igb_no_xdp_refused", probe() == -EINVAL && drv_wakes == 1);
	reset("probe_mlx5_no_xdp", DRV_MLX5);
	drv_xdp = false;
	CHECK("probe_mlx5_no_xdp_refused", probe() == -ENETDOWN);
	reset("probe_ice_link_down", DRV_ICE);
	link_carrier = false;
	CHECK("probe_link_down_accepted", probe() == 0);
	reset("probe_igb_ready", DRV_IGB);
	CHECK("probe_ready_accepted", probe() == 0 && drv_taken == 0 && p.ring.prod == 0);
	reset("probe_interface_down", DRV_IGB);
	link_running = false;
	CHECK("probe_interface_down_accepted", probe() == 0);
}

/* The link-up hook asks for a wakeup only for descriptors still in a live source. */
static void link_up_wakes_only_waiting_live_sources(void)
{
	reset("link_up_empty", DRV_IGB);
	link_up();
	worker();
	CHECK("empty_source_no_wakeup", drv_wakes == 0 && !kicks && !dead_status);

	reset("link_up_already_taken", DRV_IGB);
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("taken_at_submit", drv_taken == 3 && drv_wakes == 1);
	link_up();
	worker();
	CHECK("taken_source_no_wakeup", drv_wakes == 1 && !kicks);

	reset("link_up_stopped", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	p.stopped = true;
	link_up();
	worker();
	CHECK("stopped_source_no_wakeup", drv_wakes == 1 && !kicks && !dead_status);

	reset("link_up_dead_stage", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	xst.dead = true;
	link_up();
	worker();
	CHECK("dead_stage_no_wakeup", drv_wakes == 1);

	reset("link_up_copy_mode", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	xs.zc = false;
	link_up();
	worker();
	CHECK("copy_mode_no_wakeup", drv_wakes == 1 && !kicks);

	reset("link_up_unbound", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	link_up();
	xs.state = 0;
	worker();
	CHECK("unbound_no_wakeup", drv_wakes == 1);

	reset("link_up_stopping", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	link_up();
	session_admits = false;
	worker();
	CHECK("stopping_session_no_wakeup", drv_wakes == 1 && !dead_status);
	session_admits = true;
	worker();
	CHECK("stopping_request_dropped", drv_wakes == 1);

	reset("link_up_no_stage", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	xs.xdev_ext_mech_tx = NULL;
	link_up();
	CHECK("no_stage_no_kick", !kicks);
}

/* A reliable receiver's ACK controls share the source but the socket has no TX stage. */
static void receiver_controls_are_woken_at_link_up(void)
{
	reset("receiver_controls", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("controls_wait", p.ring.prod == 3 && p.ring.issued == 0);
	xs.xdev_ext_mech_tx = NULL;
	xs.xdev_ext_mech_rx = &st;
	link_carrier = true;
	link_up();
	CHECK("receiver_link_up_kicks_worker", kicks == 1);
	worker();
	CHECK("receiver_controls_drained", drv_wakes == 2 && drv_taken == 3 && p.ring.issued == 3);
}

/* A refusal the link no longer explains stops the stage at link up. */
static void link_up_configuration_refusal_stops_stage(void)
{
	reset("link_up_xdp_removed", DRV_IGB);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	link_carrier = true;
	drv_xdp = false;
	link_up();
	worker();
	CHECK("link_up_refusal_stops_stage", drv_wakes == 2 && dead_status == -EINVAL && p.stopped);
	CHECK("link_up_refusal_cancels_untaken", callbacks == 1 && cancel_callbacks == 1 &&
	      !seq_callbacks && p.ring.native_count == 0);
}

/* The reliable transport's wakeup follows the same rule. */
static void reliable_wakeup_follows_link_rule(void)
{
	reset("reliable_ice_carrier_down", DRV_ICE);
	link_carrier = false;
	CHECK("submit_accepted", xsk_xdev_ext_mech_submit(&st, &batch) == 0);
	CHECK("reliable_setup", p.ring.prod == 3 && !p.stopped && !dead_status);
	xsk_rel_wakeup(&st);
	CHECK("reliable_link_down_not_fatal", drv_wakes == 2 && !p.stopped && !dead_status &&
	      !callbacks && p.ring.prod == 3 && p.ring.issued == 0);
	link_carrier = true;
	drv_xdp = false;
	xsk_rel_wakeup(&st);
	CHECK("reliable_configuration_fatal", drv_wakes == 3 && p.stopped && dead_status == -EINVAL &&
	      cancel_callbacks == 1);
}

/* The deferral rule itself. */
static void deferral_rule(void)
{
	case_name = "deferral_rule";
	CHECK("down_not_running", xsk_mech_zc_wake_deferred(-ENETDOWN, false, true));
	CHECK("down_no_carrier", xsk_mech_zc_wake_deferred(-ENETDOWN, true, false));
	CHECK("down_with_link_up", !xsk_mech_zc_wake_deferred(-ENETDOWN, true, true));
	CHECK("einval_never", !xsk_mech_zc_wake_deferred(-EINVAL, false, false));
	CHECK("enxio_never", !xsk_mech_zc_wake_deferred(-ENXIO, false, false));
	CHECK("eagain_never", !xsk_mech_zc_wake_deferred(-EAGAIN, false, false));
	CHECK("success_never", !xsk_mech_zc_wake_deferred(0, false, false));
}

int main(void)
{
	deferral_rule();
	igb_dropped_wakeup_is_repeated_at_link_up();
	ice_link_down_refusal_waits_for_link_up();
	interface_down_refusal_waits_for_link_up();
	configuration_refusal_stays_fatal();
	create_probe_refuses_only_configuration_faults();
	link_up_wakes_only_waiting_live_sources();
	receiver_controls_are_woken_at_link_up();
	link_up_configuration_refusal_stops_stage();
	reliable_wakeup_follows_link_rule();
	printf("RESULT assertions_failed=%d\n", failures);
	return failures ? 1 : 0;
}
