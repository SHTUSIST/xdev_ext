/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_CHECK_CONTRACT_H
#define XDEV_EXT_CHECK_CONTRACT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define TB_CHECK_VERSION 1U
#define TB_MAX_GROUPS 10000U
#define TB_MAX_SPANS 64U
#define TB_NATIVE_TILE 4096U
#define TB_GPU_ALIGN 65536U
#define TB_MAX_JSON (1024U * 1024U)
#define TB_MAX_ALLOCATION (1024ULL * 1024ULL * 1024ULL)

enum tb_phase {
 TB_PHASE_NEW, TB_PHASE_GPU_BUSY, TB_PHASE_GPU_READY, TB_PHASE_EXTERNAL_READY,
 TB_PHASE_CREATE_ATTEMPTED, TB_PHASE_SESSION_CREATED,
 TB_PHASE_START_ACCEPTED, TB_PHASE_TRANSPORT_DONE,
 TB_PHASE_DRAINED_SAFE, TB_PHASE_VERIFYING, TB_PHASE_VERIFIED,
 TB_PHASE_CLOSED, TB_PHASE_FAILED_SAFE, TB_PHASE_HELD
};
enum tb_epoch_fate {
 TB_EPOCH_EMPTY, TB_EPOCH_CREATE_ATTEMPTED, TB_EPOCH_ACTIVE,
 TB_EPOCH_SAFE, TB_EPOCH_FAILED_SAFE, TB_EPOCH_HELD
};
enum tb_backing_mode { TB_BACKING_GPU, TB_BACKING_EXISTING_PROVIDER };
enum tb_ready_proof { TB_READY_NONE, TB_READY_EXISTING_PROVIDER_REGISTERED };
enum tb_cleanup_permission {
 TB_CLEANUP_NONE = 0,
 TB_CLEANUP_EPOCH_FDS = 1U << 0,
 TB_CLEANUP_PEER_FD = 1U << 1,
 TB_CLEANUP_GPU_FREE = 1U << 2,
 TB_CLEANUP_CONTEXT_DESTROY = 1U << 3
};
enum tb_hold_reason {
 TB_HOLD_CANCEL = 1U << 0, TB_HOLD_SIGNAL = 1U << 1,
 TB_HOLD_EOF = 1U << 2, TB_HOLD_EPIPE = 1U << 3,
 TB_HOLD_DEADLINE = 1U << 4, TB_HOLD_CUDA_UNKNOWN = 1U << 5,
 TB_HOLD_CREATE_UNKNOWN = 1U << 6, TB_HOLD_STOP_UNKNOWN = 1U << 7,
 TB_HOLD_PROTOCOL = 1U << 8
};
enum tb_operation {
 TB_OP_GPU_OPEN, TB_OP_GPU_FILL, TB_OP_CREATE, TB_OP_START,
 TB_OP_WAIT, TB_OP_STOP, TB_OP_VISIBLE, TB_OP_GPU_VERIFY,
 TB_OP_EPOCH_CLOSE, TB_OP_GPU_CLOSE, TB_OP_CONTROL = 10
};
struct tb_guard;
struct tb_guard_snapshot {
 uint32_t size, version;
 enum tb_phase phase;
 uint32_t hold_reasons, cleanup_permissions;
 uint64_t operation_ticket;
 enum tb_backing_mode backing_mode;
 enum tb_ready_proof external_ready_proof;
 bool held, native_safe, gpu_safe, gpu_applicable, pair_stop_proved;
};
struct tb_span { uint64_t allocation_off, data_off, len; };
enum tb_expect_kind { TB_EXPECT_PAYLOAD = 1, TB_EXPECT_GUARD = 2 };
struct tb_verify_extent {
 uint64_t dst_off, src_off, len, seed;
 uint32_t kind, reserved;
};
struct tb_verify_result {
 uint64_t bytes, mismatches, first_bad, launch_cookie;
};
/* first_bad == UINT64_MAX only when every expected byte matched. */
struct tb_geometry {
 uint64_t allocation_bytes, group_bytes;
 uint32_t frame_size, seg_len, depth, native_elems;
};
int tb_geometry_validate(const struct tb_geometry *);
int tb_guard_new(enum tb_backing_mode, struct tb_guard **);
int tb_guard_external_ready(struct tb_guard *, enum tb_ready_proof);
void tb_guard_snapshot(const struct tb_guard *, struct tb_guard_snapshot *);
int tb_guard_begin(struct tb_guard *, enum tb_operation, uint64_t *ticket);
int tb_guard_end(struct tb_guard *, uint64_t ticket, enum tb_phase next,
                 bool native_safe, bool gpu_safe);
void tb_guard_hold(struct tb_guard *, uint32_t reason);
/* Called by owner only after two same-run successful STOP receipts. */
int tb_guard_pair_stopped(struct tb_guard *);
uint32_t tb_guard_cleanup_permissions(const struct tb_guard *);
int tb_guard_delete(struct tb_guard *); /* HELD => -EPERM, no destructor */

#ifdef __cplusplus
}
#endif
#endif /* XDEV_EXT_CHECK_CONTRACT_H */
