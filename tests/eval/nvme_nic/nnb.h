/* SPDX-License-Identifier: GPL-2.0 */
/* NVMe<->NIC eval producer: configuration, trial and arm interfaces. */
#ifndef NNB_H
#define NNB_H

#include <stdint.h>
#include <sys/types.h>
#include "nnb_wire.h"

enum { NNB_OK = 0, NNB_FAIL = 1, NNB_USAGE = 2, NNB_CAPABILITY = 4 };

#define NNB_MAX_QD		128U
#define NNB_SESSION_MAX_DEPTH	64U	/* XDEV_EXT_MECH_MAX_DEPTH */
#define NNB_MAX_ARMS		4U

struct nnb_cfg {
	int reverse;			/* 0: NVMe -> NIC, 1: NIC -> NVMe */
	int correctness;		/* no timing fields are emitted */
	int direct;			/* O_DIRECT for posix/uring arms */
	uint32_t size, qd, units, pairs, warmup, mtu, lba, queue, rate_mbps;
	uint64_t window_bytes, slba, nlb, seed, run_id, session_base, order_seed;
	const char *source, *ng, *ifname, *bpf_object;
	const char *local_ip, *peer_ip, *local_mac, *peer_mac, *control_ip;
	uint16_t local_port, peer_port, control_port;
	unsigned nr_arms;
	const char *arms[NNB_MAX_ARMS];
};

/* Work and evidence counters of one trial; zero fields are not applicable. */
struct nnb_counts {
	uint64_t read_ops, read_bytes, write_ops, write_bytes;
	uint64_t send_calls, send_bytes, datagrams, recv_calls;
	uint64_t cqes, notifs, zc_copied, splice_calls;
	uint64_t batches;		/* session batches completed in this trial */
};

struct nnb_trial {
	uint64_t trial, first_gen, groups, units;
	uint32_t bursts, burst_units;	/* reverse: units per GO */
	int integrity;
	uint64_t t_start, t_release;	/* CLOCK_MONOTONIC_RAW ns */
	/*
	 * Per-unit completion times, preallocated before the trial (NULL for the
	 * session arm, which has no per-unit completion in user space).  Forward:
	 * unit read issued .. its last send locally complete.  Reverse: first
	 * datagram of the unit seen by the producer .. its NVMe write complete.
	 */
	uint64_t *lat_start, *lat_done;
	struct nnb_counts counts;
};

/* One latency stamp of unit @u; two clock reads per unit, no per-byte work. */
static inline void nnb_stamp(uint64_t *v, uint64_t u, uint64_t now)
{
	if (v)
		v[u] = now;
}

struct nnb_arm;

struct nnb_arm_ops {
	const char *name;
	int (*setup)(struct nnb_arm *a);
	int (*run)(struct nnb_arm *a, struct nnb_trial *t);
	void (*teardown)(struct nnb_arm *a);
};

struct nnb_arm {
	const struct nnb_arm_ops *ops;
	const struct nnb_cfg *c;
	const struct nnb_geom *g;
	unsigned index;
	uint64_t wire_session, next_gen;
	uint16_t port;			/* this arm's local UDP port */
	int ctl;			/* control connection to the peer */
	uint32_t effective_qd, session_depth;
	uint64_t inflight_bytes;	/* payload bytes this arm keeps in flight at most */
	int xsk_zerocopy;		/* session: XDP_OPTIONS_ZEROCOPY, else -1 */
	int registrations;
	void *priv;
	char diag[160];
};

uint64_t nnb_now(void);
uint64_t nnb_unit_offset(const struct nnb_arm *a, const struct nnb_trial *t, uint64_t u);
uint64_t nnb_unit_gen(const struct nnb_trial *t, const struct nnb_geom *g, uint64_t u);
int nnb_udp_socket(const struct nnb_arm *a, int connect_peer, int gso);
void *nnb_alloc(size_t bytes);
int nnb_rev_go(struct nnb_arm *a, const struct nnb_trial *t, uint32_t burst);
int nnb_rev_sent(struct nnb_arm *a, const struct nnb_trial *t, uint32_t burst);
int nnb_fill_headers(const struct nnb_geom *g, unsigned char *hdrs, uint64_t session);
void nnb_set_unit_gen(const struct nnb_geom *g, unsigned char *hdrs, uint64_t gen0);
#define nnb_diag(a, ...) snprintf((a)->diag, sizeof((a)->diag), __VA_ARGS__)

extern const struct nnb_arm_ops nnb_posix_ops, nnb_splice_ops, nnb_uring_ops, nnb_session_ops;

#endif
