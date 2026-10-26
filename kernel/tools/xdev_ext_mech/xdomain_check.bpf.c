// SPDX-License-Identifier: GPL-2.0
/* Private bounded observer; the included reference remains the only policy. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "../../../tests/eval/xdomain/observer_contract.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tb_xd_observer_config);
} xd_check_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TB_XD_OBSERVER_MAX_GROUPS);
	__type(key, __u32);
	__type(value, struct tb_xd_observer_record);
} xd_check_rec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tb_xd_observer_errors);
} xd_check_err SEC(".maps");

#define XD_OBS_BUSY 0x80000000U
#define XD_OBS_U32_MAX (~(__u32)0)
#define XD_OBS_U64_MAX (~(__u64)0)
#define XD_OBS_PIN(field) \
	_Static_assert(__builtin_offsetof(struct tb_xd_observer_cqe, field) == \
		       __builtin_offsetof(struct xdev_ext_xdomain_mech_cqe, field), \
		       "CQE offset " #field)
XD_OBS_PIN(status);
XD_OBS_PIN(outcome);
XD_OBS_PIN(remote);
XD_OBS_PIN(elems_done);
XD_OBS_PIN(group);
XD_OBS_PIN(bytes);
XD_OBS_PIN(crc_errors);
XD_OBS_PIN(rsvd);
XD_OBS_PIN(tag);
_Static_assert(sizeof(struct tb_xd_observer_cqe) ==
	       sizeof(struct xdev_ext_xdomain_mech_cqe), "CQE size");

static __always_inline int
xd_obs_error(struct tb_xd_observer_errors *errors,
	     struct tb_xd_observer_record *record, __u32 bits)
{
	__u64 old;
	__u32 i;

	if (record)
		__sync_fetch_and_or(&record->error_bits, bits);
	if (!errors)
		return -1;
	__sync_fetch_and_or(&errors->error_bits, (__u64)bits);
	/* Contention itself may saturate the counter, but can never wrap it. */
	for (i = 0; i < 4; i++) {
		old = errors->observations_lost;
		if (old == XD_OBS_U64_MAX)
			return -1;
		if (__sync_val_compare_and_swap(&errors->observations_lost,
					       old, old + 1) == old)
			return -1;
	}
	__sync_fetch_and_or(&errors->error_bits, (__u64)TB_XD_OBS_ERR_OVERFLOW);
	__sync_lock_test_and_set(&errors->observations_lost, XD_OBS_U64_MAX);
	return -1;
}

static __always_inline struct tb_xd_observer_record *
xd_obs_record(const struct xdev_ext_mech_ctx *ctx,
	      struct tb_xd_observer_config *cfg,
	      struct tb_xd_observer_errors *errors)
{
	struct tb_xd_observer_record *record;
	__u64 ordinal;
	__u32 index;

	if (!cfg || cfg->size != sizeof(*cfg) ||
	    cfg->version != TB_XD_OBSERVER_VERSION || !cfg->session_id ||
	    !cfg->groups || cfg->groups > TB_XD_OBSERVER_MAX_GROUPS ||
	    cfg->first_seq > XD_OBS_U64_MAX - (cfg->groups - 1) ||
	    !cfg->allocation_bytes || cfg->stage >= 4 ||
	    (cfg->direction != XDEV_EXT_MP_DIR_TO_DEVICE &&
	     cfg->direction != XDEV_EXT_MP_DIR_FROM_DEVICE)) {
		xd_obs_error(errors, 0, TB_XD_OBS_ERR_CONFIG);
		return 0;
	}
	if (ctx->base.src_offset < cfg->first_seq) {
		xd_obs_error(errors, 0, TB_XD_OBS_ERR_KEY);
		return 0;
	}
	ordinal = ctx->base.src_offset - cfg->first_seq;
	if (ordinal >= cfg->groups || ordinal >= TB_XD_OBSERVER_MAX_GROUPS) {
		xd_obs_error(errors, 0, TB_XD_OBS_ERR_KEY);
		return 0;
	}
	index = ordinal;
	record = bpf_map_lookup_elem(&xd_check_rec, &index);
	if (!record) {
		xd_obs_error(errors, 0, TB_XD_OBS_ERR_KEY);
		return 0;
	}
	if (ctx->session_id != cfg->session_id ||
	    ctx->base.current_stage != cfg->stage ||
	    ctx->base.direction != cfg->direction) {
		xd_obs_error(errors, record, TB_XD_OBS_ERR_CONFIG);
		return 0;
	}
	if (!errors) {
		xd_obs_error(0, record, TB_XD_OBS_ERR_CONFIG);
		return 0;
	}
	if (errors->error_bits || record->error_bits) {
		xd_obs_error(errors, record,
			     (__u32)errors->error_bits | record->error_bits);
		return 0;
	}
	return record;
}

static __always_inline int
xd_obs_identity(const struct xdev_ext_mech_ctx *ctx,
		const struct tb_xd_observer_config *cfg,
		const struct tb_xd_observer_record *record)
{
	return record->size == sizeof(*record) &&
	       record->version == TB_XD_OBSERVER_VERSION &&
	       record->session_id == ctx->session_id &&
	       record->batch_id == ctx->batch_id &&
	       record->key == ctx->base.src_offset &&
	       record->epoch == cfg->epoch &&
	       record->direction == ctx->base.direction;
}

static __always_inline int
xd_obs_build(const struct xdev_ext_mech_ctx *ctx,
	     const struct xdev_ext_xdomain_mech_info *info)
{
	struct tb_xd_observer_config *cfg;
	struct tb_xd_observer_errors *errors;
	struct tb_xd_observer_record *record;
	struct xdev_ext_xdomain_desc *desc;
	__u32 zero = 0, i, j, previous, bits = 0;
	__u64 off, available;

	cfg = bpf_map_lookup_elem(&xd_check_cfg, &zero);
	errors = bpf_map_lookup_elem(&xd_check_err, &zero);
	record = xd_obs_record(ctx, cfg, errors);
	if (!record)
		return -1;
	previous = __sync_val_compare_and_swap(&record->cqe_seen, 0, XD_OBS_BUSY);
	if (previous)
		return xd_obs_error(errors, record, previous == 1 ?
			TB_XD_OBS_ERR_BUILD_AFTER_CQE : TB_XD_OBS_ERR_OVERFLOW);
	if (record->build_attempts && (!xd_obs_identity(ctx, cfg, record) ||
	    record->generation != info->generation ||
	    record->local_inc != info->local_inc || record->remote_inc != info->remote_inc)) {
		bits = TB_XD_OBS_ERR_IDENTITY;
		goto fail;
	}
	if (record->build_attempts == XD_OBS_U32_MAX) {
		bits = TB_XD_OBS_ERR_OVERFLOW;
		goto fail;
	}
	if (!info->nr_frames || info->nr_frames > XDEV_EXT_MP_MAX_FRAMES ||
	    info->nr_frames > TB_XD_OBSERVER_MAX_SPANS ||
	    info->direction != cfg->direction) {
		bits = TB_XD_OBS_ERR_PLAN;
		goto fail;
	}
	for (i = 0; i < XDEV_EXT_MP_MAX_FRAMES; i++) {
		if (i >= info->nr_frames)
			break;
		desc = (void *)bpf_xdev_ext_desc(ctx, i, sizeof(*desc));
		if (!desc || desc->frame_pos >= info->nr_frames ||
		    desc->frame_pos >= XDEV_EXT_MP_MAX_FRAMES || !desc->len) {
			bits = TB_XD_OBS_ERR_PLAN;
			goto fail;
		}
		off = info->f[desc->frame_pos].umem_addr;
		if (off > cfg->allocation_bytes) {
			bits = TB_XD_OBS_ERR_PLAN;
			goto fail;
		}
		available = cfg->allocation_bytes - off;
		if (desc->frame_off > available || desc->len > available - desc->frame_off) {
			bits = TB_XD_OBS_ERR_PLAN;
			goto fail;
		}
		record->spans[i].allocation_off = off;
		record->spans[i].data_off = desc->frame_off;
		record->spans[i].len = desc->len;
		if (!i)
			for (j = 0; j < 24; j++)
				record->tag[j] = desc->tag[j];
	}
	/* A smaller retry must not leave a stale plan suffix behind. */
	for (i = 0; i < TB_XD_OBSERVER_MAX_SPANS; i++) {
		if (i < info->nr_frames)
			continue;
		record->spans[i].allocation_off = 0;
		record->spans[i].data_off = 0;
		record->spans[i].len = 0;
	}
	record->size = sizeof(*record);
	record->version = TB_XD_OBSERVER_VERSION;
	record->session_id = ctx->session_id;
	record->batch_id = ctx->batch_id;
	record->key = ctx->base.src_offset;
	record->epoch = cfg->epoch;
	record->generation = info->generation;
	record->local_inc = info->local_inc;
	record->remote_inc = info->remote_inc;
	record->direction = info->direction;
	record->channel = info->channel;
	record->nr_spans = info->nr_frames;
	record->build_attempts++;
	__sync_val_compare_and_swap(&record->cqe_seen, XD_OBS_BUSY, 0);
	bits = (__u32)errors->error_bits | record->error_bits;
	return bits ? xd_obs_error(errors, record, bits) : 0;
fail:
	xd_obs_error(errors, record, bits);
	__sync_val_compare_and_swap(&record->cqe_seen, XD_OBS_BUSY, 0);
	return -1;
}

static __always_inline int
xd_obs_cqe(const struct xdev_ext_mech_ctx *ctx,
	   const struct xdev_ext_xdomain_mech_cqe *cqe)
{
	struct tb_xd_observer_config *cfg;
	struct tb_xd_observer_errors *errors;
	struct tb_xd_observer_record *record;
	__u32 zero = 0, previous, i, bits;

	cfg = bpf_map_lookup_elem(&xd_check_cfg, &zero);
	errors = bpf_map_lookup_elem(&xd_check_err, &zero);
	record = xd_obs_record(ctx, cfg, errors);
	if (!record)
		return -1;
	previous = __sync_val_compare_and_swap(&record->cqe_seen, 0, XD_OBS_BUSY);
	if (previous)
		return xd_obs_error(errors, record, previous == 1 ?
			TB_XD_OBS_ERR_DUP_CQE : TB_XD_OBS_ERR_OVERFLOW);
	if (!record->build_attempts) {
		bits = TB_XD_OBS_ERR_MISSING_BUILD;
		goto fail;
	}
	if (!xd_obs_identity(ctx, cfg, record)) {
		bits = TB_XD_OBS_ERR_IDENTITY;
		goto fail;
	}
	record->completion.status = cqe->status;
	record->completion.outcome = cqe->outcome;
	record->completion.remote = cqe->remote;
	record->completion.elems_done = cqe->elems_done;
	record->completion.group = cqe->group;
	record->completion.bytes = cqe->bytes;
	record->completion.crc_errors = cqe->crc_errors;
	record->completion.rsvd = cqe->rsvd;
	for (i = 0; i < 24; i++)
		record->completion.tag[i] = cqe->tag[i];
	__sync_val_compare_and_swap(&record->cqe_seen, XD_OBS_BUSY, 1);
	bits = (__u32)errors->error_bits | record->error_bits;
	return bits ? xd_obs_error(errors, record, bits) : 0;
fail:
	xd_obs_error(errors, record, bits);
	__sync_val_compare_and_swap(&record->cqe_seen, XD_OBS_BUSY, 0);
	return -1;
}

#define XDEV_EXT_XDOMAIN_OBSERVE_BUILD(ctx, info) xd_obs_build(ctx, info)
#define XDEV_EXT_XDOMAIN_OBSERVE_CQE(ctx, cqe) xd_obs_cqe(ctx, cqe)
#include "xdomain_peer.bpf.c"
