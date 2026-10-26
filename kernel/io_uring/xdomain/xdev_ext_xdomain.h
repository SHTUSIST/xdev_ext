/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_XDOMAIN_H
#define _XDEV_EXT_XDOMAIN_H
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/thunderbolt.h>
#include <linux/uuid.h>
#include <linux/workqueue.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_netfam.h>
#include "xdev_ext_xdomain_core.h"

struct xdev_ext_xd_link;
struct xdev_ext_xd_ctl_allocation;
struct xdev_ext_xd_rings;
/* One bound XDOMAIN stage on one channel and direction (the family "link"). */
struct xdev_ext_xd_ep {
	struct xdev_ext_xd_link *xl;
	struct xdev_ext_mech_stage *st;
	u32 chan;
	bool rx;
	bool detached;		/* a link down took it off chan[]; set under ep_mutex and lock */
};
struct xdev_ext_xd_ctl_frame {
	struct ring_frame frame;
	struct xdev_ext_xd_link *xl;
	u8 *buf;
	u32 index;
};
struct xdev_ext_xd_chan {
	struct tb_ring *tx, *rx;		/* data rings */
	int out_hopid, in_hopid;		/* our TX path; the peer's TX path we receive */
	bool paths;				/* tb_xdomain_enable_paths() succeeded */
	u64 announced, consumed;		/* elements announced (TX) / consumed (RX) since link up; lock */
	struct xdev_ext_xd_ep *ep[2];		/* [0] TX stage, [1] RX stage; under ep_mutex */
};
struct xdev_ext_xd_link {
	struct kref ref;
	struct list_head node;			/* xdev_ext_xd_links, under xdev_ext_xd_links_lock */
	struct tb_service *svc;			/* valid until remove returns */
	struct tb_xdomain *xd;			/* valid until remove; NULL afterwards */
	struct pci_dev *nhi_pdev;		/* pci_dev_get() at probe, put with the last reference */
	u64 route, token;			/* token never reused */
	uuid_t local_uuid, remote_uuid;		/* copies taken at probe */
	spinlock_t lock;			/* up, closing flags, local/remote_inc, chan counters,
						 * control TX buffers, posting, down_err/down_local_inc */
	struct mutex ctl_mutex;			/* login state, accepted/response_inc, rings, paths */
	struct mutex ep_mutex;			/* chan[].ep, control dispatch, dead notifications */
	bool up, going_away, suspended, gone, nhi_gone;
	bool logged_in, remote_logged_in, e2e;
	u64 local_inc, remote_inc, response_inc, accepted_inc;
	int down_err;				/* first error for down_local_inc; lock */
	u64 down_local_inc;			/* incarnation that queued down_work; lock */
	u32 channels, login_retries;		/* login_retries counts sent requests; ctl_mutex */
	atomic_t command_id;
	struct xdev_ext_xd_login remote_login;	/* last valid LOGIN from the peer; lock */
	struct tb_ring *ctl_tx, *ctl_rx;
	int ctl_out_hopid, ctl_in_hopid;
	bool ctl_paths;
	struct xdev_ext_xd_rings *rings;
	/* X4 owns per-allocation custody and preallocated quarantine records. */
	struct xdev_ext_xd_ctl_allocation *ctl_rx_alloc, *ctl_tx_alloc;
	u8 *ctl_rx_buf, *ctl_tx_buf;
	dma_addr_t ctl_rx_dma, ctl_tx_dma;
	struct xdev_ext_xd_ctl_frame ctl_rx_frames[XDEV_EXT_XD_CTL_RING];
	struct xdev_ext_xd_ctl_frame ctl_tx_frames[XDEV_EXT_XD_CTL_RING];
	unsigned long ctl_tx_free[BITS_TO_LONGS(XDEV_EXT_XD_CTL_RING)];
	u64 ctl_dropped;			/* messages refused by xdev_ext_xd_msg_for_us() or decode */
	struct xdev_ext_xd_chan chan[XDEV_EXT_XD_MAX_CHANNELS];
	struct delayed_work login_work;
	struct work_struct connect_work, down_work;
};
struct xdev_ext_xd_link *xdev_ext_xd_link_get(u64 token);
void xdev_ext_xd_link_put(struct xdev_ext_xd_link *xl);
void xdev_ext_xd_link_down(struct xdev_ext_xd_link *xl, int err);
void xdev_ext_xd_link_fail(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_ep *ep, int err);
/* xdev_ext_xdomain_ring.c */
int  xdev_ext_xd_rings_alloc(struct xdev_ext_xd_link *xl);
int  xdev_ext_xd_rings_start(struct xdev_ext_xd_link *xl);
void xdev_ext_xd_rings_stop(struct xdev_ext_xd_link *xl);
void xdev_ext_xd_rings_free(struct xdev_ext_xd_link *xl);
int  xdev_ext_xd_paths_enable(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_login *peer);
void xdev_ext_xd_paths_disable(struct xdev_ext_xd_link *xl);
int  xdev_ext_xd_msg_send(struct xdev_ext_xd_link *xl, const struct xdev_ext_xd_ep *ep, u32 chan,
			  struct xdev_ext_xd_msg *m);
int  xdev_ext_xd_seq_consume(struct xdev_ext_xd_link *xl, u32 chan, u64 data_seq, u32 count);
u32  xdev_ext_xd_crc(u32 crc, const void *p, size_t len);
extern const struct xdev_ext_net_dev_ops xdev_ext_xd_dev_ops;
/* xdev_ext_xdomain_class.c */
void xdev_ext_xd_class_ctl(struct xdev_ext_mech_stage *st, const struct xdev_ext_xd_msg *m);
int  xdev_ext_xd_class_register(void);
void xdev_ext_xd_class_unregister(void);
#endif
