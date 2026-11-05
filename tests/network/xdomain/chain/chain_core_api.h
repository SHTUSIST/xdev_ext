/* SPDX-License-Identifier: GPL-2.0 */
/* Entry points of the extracted core unit, and what it needs from the
 * deterministic host scheduler (chain_boundary.c). Types stay opaque here. */
#ifndef CHAIN_CORE_API_H
#define CHAIN_CORE_API_H
struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_pool;
struct xdev_ext_mech_create;

unsigned long long chain_now_ns(void);
void chain_observe_worker(unsigned worker, const void *fn, bool begin);

struct xdev_ext_mech_session *chain_session_create(const struct xdev_ext_mech_create *c, int *err);
int chain_session_start(struct xdev_ext_mech_session *s, __u64 nr_batches, __u64 first_seq);
int chain_session_stop(struct xdev_ext_mech_session *s, int err);
unsigned chain_session_worker_id(struct xdev_ext_mech_session *s);
bool chain_core_ready(void);
unsigned long long chain_core_next_due(void);
unsigned chain_core_run_one(void);
unsigned chain_core_current_worker(void);

__u32 chain_frame_custody(struct xdev_ext_mech_session *s, __u32 index);
__u32 chain_frame_phase(struct xdev_ext_mech_session *s, __u32 index);
__u32 chain_pool_frames(struct xdev_ext_mech_session *s);
__u32 chain_frame_state_free(void); /* XDEV_EXT_MECH_F_K_FREE: kernel partition, free */
__u64 chain_session_done(struct xdev_ext_mech_session *s);
__u64 chain_session_aborted(struct xdev_ext_mech_session *s);
__u64 chain_session_counter(struct xdev_ext_mech_session *s, __u32 c);
__u64 chain_stage_submitted(struct xdev_ext_mech_session *s, __u32 i);
__u64 chain_stage_completed(struct xdev_ext_mech_session *s, __u32 i);
int chain_session_last_err(struct xdev_ext_mech_session *s);
__u32 chain_session_inflight(struct xdev_ext_mech_session *s);
__u32 chain_session_state(struct xdev_ext_mech_session *s);
__u64 chain_session_start_left(struct xdev_ext_mech_session *s);
struct xdev_ext_mech_stage *chain_session_stage(struct xdev_ext_mech_session *s, __u32 i);
struct xdev_ext_mech_pool *chain_session_pool_of(struct xdev_ext_mech_session *s);
__u32 chain_batch_stage_index(const struct xdev_ext_mech_batch *b);
__u64 chain_batch_id(const struct xdev_ext_mech_batch *b);
__u32 chain_batch_frame_index(const struct xdev_ext_mech_batch *b, __u32 pos);
__u32 chain_batch_frames(const struct xdev_ext_mech_batch *b);
struct xdev_ext_mech_session *chain_batch_session(const struct xdev_ext_mech_batch *b);
#endif
