/* SPDX-License-Identifier: GPL-2.0 */
/* Recorder of the kernel services the requester unit calls; read by cases.c. */
#ifndef REQUESTER_HOST_BOUNDARY_H
#define REQUESTER_HOST_BOUNDARY_H

enum rh_kind { RH_MAP = 1, RH_UNMAP, RH_SYNC_DEVICE, RH_SYNC_CPU, RH_DESCRIBE, RH_PREMAP };
struct rh_event {
	enum rh_kind kind;
	const struct device *dev;
	const struct page *page;
	dma_addr_t addr;
	size_t offset, size;
	int dir;
	unsigned long attrs;
};
#define RH_EVENTS 4096
extern struct rh_event rh_log[RH_EVENTS];
extern unsigned rh_events;
/* 1-based ordinal of the dma_map_page_attrs() call that fails; 0: none fails. */
extern unsigned rh_fail_map_at;
extern unsigned rh_live_allocs;

/* The address a device sees for byte @offset of page @index: one window per
 * device, pages at reversed positions, so no contiguity is implied. */
dma_addr_t rh_window(const struct device *dev, unsigned index, size_t offset);
void rh_reset(void);
unsigned rh_count(enum rh_kind kind);

/* Run @fn once, right after the @n-th shared read of the unit from now
 * (n >= 1), as another CPU could at that point; rh_scheduled_runs counts the
 * scheduled actions that ran. */
void rh_schedule_after_reads(unsigned n, void (*fn)(void));
extern unsigned rh_scheduled_runs;

/* Fixture session: the core keeps its session private; the requester reads
 * only its pool through xdev_ext_mech_session_pool(). */
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
/* PEER fixture: describe reports a BAR owner, premap succeeds. */
extern struct pci_dev rh_gpu;
#endif
