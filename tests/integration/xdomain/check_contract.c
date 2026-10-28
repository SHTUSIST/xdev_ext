/* SPDX-License-Identifier: GPL-2.0 */
#include "check_contract.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct tb_guard {
 pthread_mutex_t lock;
 enum tb_phase phase, prior;
 enum tb_backing_mode mode;
 enum tb_ready_proof ready;
 enum tb_operation operation;
 uint64_t ticket;
 uint32_t reasons;
 bool busy, held, native_safe, gpu_safe, filled, visible, ever_create, pair;
 bool prior_gpu_safe, prior_native_safe, prior_ever_create, prior_pair, prior_visible;
};

static uint32_t permissions(const struct tb_guard *g)
{
 uint32_t p = 0;
 if (g->held || g->busy || !g->native_safe || !g->gpu_safe)
  return 0;
 if (g->phase == TB_PHASE_NEW || g->phase == TB_PHASE_EXTERNAL_READY ||
     g->phase == TB_PHASE_GPU_READY || g->phase == TB_PHASE_DRAINED_SAFE ||
     g->phase == TB_PHASE_VERIFIED || g->phase == TB_PHASE_FAILED_SAFE ||
     g->phase == TB_PHASE_CLOSED)
  p = TB_CLEANUP_EPOCH_FDS;
 if (!p || g->phase == TB_PHASE_NEW || g->phase == TB_PHASE_CLOSED)
  return p;
 if (g->mode == TB_BACKING_EXISTING_PROVIDER)
  return p | TB_CLEANUP_PEER_FD;
 if (!g->ever_create || g->pair)
  p |= TB_CLEANUP_PEER_FD | TB_CLEANUP_GPU_FREE | TB_CLEANUP_CONTEXT_DESTROY;
 return p;
}

int tb_geometry_validate(const struct tb_geometry *v)
{
 uint64_t frames, elems;
 if (!v || !v->allocation_bytes || v->allocation_bytes > TB_MAX_ALLOCATION ||
     v->allocation_bytes % TB_GPU_ALIGN || v->frame_size != TB_GPU_ALIGN ||
     !v->group_bytes || v->group_bytes > v->allocation_bytes ||
     v->group_bytes % TB_NATIVE_TILE || !v->depth || !v->seg_len ||
     v->seg_len != (v->group_bytes < TB_GPU_ALIGN ? v->group_bytes : TB_GPU_ALIGN))
  return -EINVAL;
 frames = (v->group_bytes + v->seg_len - 1) / v->seg_len;
 if (frames > 32 || frames > UINT64_MAX / v->depth ||
     frames * v->depth > v->allocation_bytes / v->frame_size)
  return -EINVAL;
 elems = v->group_bytes / TB_NATIVE_TILE;
 if (!elems || elems > TB_MAX_SPANS || v->native_elems != elems ||
     (uint64_t)v->depth * elems > 255)
  return -EINVAL;
 return 0;
}

int tb_guard_new(enum tb_backing_mode mode, struct tb_guard **out)
{
 struct tb_guard *g;
 int rc;
 if (!out || (mode != TB_BACKING_GPU && mode != TB_BACKING_EXISTING_PROVIDER))
  return -EINVAL;
 *out = NULL;
 g = calloc(1, sizeof(*g));
 if (!g)
  return -ENOMEM;
 rc = pthread_mutex_init(&g->lock, NULL);
 if (rc) { free(g); return -rc; }
 g->mode = mode;
 g->phase = TB_PHASE_NEW;
 g->native_safe = g->gpu_safe = true;
 *out = g;
 return 0;
}

int tb_guard_external_ready(struct tb_guard *g, enum tb_ready_proof proof)
{
 int rc = -EPERM;
 if (!g) return -EINVAL;
 pthread_mutex_lock(&g->lock);
 if (!g->held && !g->busy && g->phase == TB_PHASE_NEW &&
     g->mode == TB_BACKING_EXISTING_PROVIDER &&
     proof == TB_READY_EXISTING_PROVIDER_REGISTERED) {
  g->ready = proof;
  g->phase = TB_PHASE_EXTERNAL_READY;
  rc = 0;
 }
 pthread_mutex_unlock(&g->lock);
 return rc;
}

void tb_guard_snapshot(const struct tb_guard *guard, struct tb_guard_snapshot *out)
{
 struct tb_guard *g = (struct tb_guard *)guard;
 if (!out) return;
 memset(out, 0, sizeof(*out));
 out->size = sizeof(*out); out->version = TB_CHECK_VERSION;
 if (!g) return;
 pthread_mutex_lock(&g->lock);
 out->phase = g->phase; out->hold_reasons = g->reasons;
 out->cleanup_permissions = permissions(g); out->operation_ticket = g->ticket;
 out->backing_mode = g->mode; out->external_ready_proof = g->ready;
 out->held = g->held; out->native_safe = g->native_safe;
 out->gpu_safe = g->gpu_safe; out->gpu_applicable = g->mode == TB_BACKING_GPU;
 out->pair_stop_proved = g->pair;
 pthread_mutex_unlock(&g->lock);
}

static bool allowed(const struct tb_guard *g, enum tb_operation op)
{
 enum tb_phase p = g->phase;
 bool gpu = g->mode == TB_BACKING_GPU;
 switch (op) {
 case TB_OP_GPU_OPEN: return gpu && p == TB_PHASE_NEW;
 case TB_OP_GPU_FILL:
  return gpu && (p == TB_PHASE_GPU_READY || p == TB_PHASE_VERIFIED ||
                 (p == TB_PHASE_DRAINED_SAFE && g->pair));
 case TB_OP_CREATE:
  return g->gpu_safe && ((gpu && p == TB_PHASE_GPU_READY && g->filled &&
          (!g->ever_create || g->pair)) ||
         (!gpu && p == TB_PHASE_EXTERNAL_READY && g->ready != TB_READY_NONE));
 case TB_OP_START: return p == TB_PHASE_SESSION_CREATED && g->gpu_safe;
 case TB_OP_WAIT: return p == TB_PHASE_START_ACCEPTED;
 case TB_OP_STOP:
  return p == TB_PHASE_SESSION_CREATED || p == TB_PHASE_START_ACCEPTED ||
         p == TB_PHASE_TRANSPORT_DONE;
 case TB_OP_VISIBLE: return gpu && p == TB_PHASE_DRAINED_SAFE && g->pair;
 case TB_OP_GPU_VERIFY:
  return gpu && p == TB_PHASE_DRAINED_SAFE && g->pair && g->visible;
 case TB_OP_EPOCH_CLOSE:
  return (p == TB_PHASE_NEW || p == TB_PHASE_FAILED_SAFE ||
          (!g->ever_create && (p == TB_PHASE_GPU_READY || p == TB_PHASE_EXTERNAL_READY)) ||
          p == TB_PHASE_DRAINED_SAFE || p == TB_PHASE_VERIFIED) &&
         (permissions(g) & TB_CLEANUP_EPOCH_FDS);
 case TB_OP_GPU_CLOSE:
  return gpu && (p == TB_PHASE_GPU_READY || p == TB_PHASE_FAILED_SAFE ||
                 p == TB_PHASE_DRAINED_SAFE || p == TB_PHASE_VERIFIED) &&
         (permissions(g) & TB_CLEANUP_GPU_FREE);
 case TB_OP_CONTROL:
  return (gpu && p == TB_PHASE_GPU_READY && g->filled && g->gpu_safe) ||
         (!gpu && p == TB_PHASE_EXTERNAL_READY &&
          g->ready == TB_READY_EXISTING_PROVIDER_REGISTERED) ||
         p == TB_PHASE_SESSION_CREATED ||
         ((p == TB_PHASE_DRAINED_SAFE || p == TB_PHASE_VERIFIED) &&
          g->pair && g->native_safe && g->gpu_safe);
 }
 return false;
}

int tb_guard_begin(struct tb_guard *g, enum tb_operation op, uint64_t *ticket)
{
 int rc = -EPERM;
 if (!g || !ticket) return -EINVAL;
 pthread_mutex_lock(&g->lock);
 if (!g->held && !g->busy && allowed(g, op) && g->ticket != UINT64_MAX) {
  g->prior = g->phase; g->operation = op; g->busy = true;
  g->prior_gpu_safe = g->gpu_safe; g->prior_native_safe = g->native_safe;
  g->prior_ever_create = g->ever_create; g->prior_pair = g->pair;
  g->prior_visible = g->visible;
  *ticket = ++g->ticket;
  if (op == TB_OP_CREATE) {
   g->ever_create = true; g->pair = g->visible = false;
   g->native_safe = false; g->phase = TB_PHASE_CREATE_ATTEMPTED;
  } else if (op == TB_OP_GPU_OPEN || op == TB_OP_GPU_FILL || op == TB_OP_VISIBLE) {
   g->phase = TB_PHASE_GPU_BUSY; g->gpu_safe = false;
  } else if (op == TB_OP_GPU_VERIFY) {
   g->phase = TB_PHASE_VERIFYING; g->gpu_safe = false;
  }
  rc = 0;
 }
 pthread_mutex_unlock(&g->lock);
 return rc;
}

int tb_guard_end(struct tb_guard *g, uint64_t ticket, enum tb_phase next,
                 bool native_safe, bool gpu_safe)
{
 bool valid = false;
 int rc = -EINVAL;
 if (!g) return -EINVAL;
 pthread_mutex_lock(&g->lock);
 if (g->held) { rc = -ECANCELED; goto out; }
 if (!g->busy || ticket != g->ticket) goto out;
 switch (g->operation) {
 case TB_OP_GPU_OPEN: case TB_OP_GPU_FILL:
  valid = (next == TB_PHASE_GPU_READY ||
           (next == TB_PHASE_FAILED_SAFE && g->prior_native_safe && g->prior_gpu_safe)) &&
          native_safe && gpu_safe; break;
 case TB_OP_CREATE:
  valid = (next == TB_PHASE_SESSION_CREATED && !native_safe) ||
          (next == TB_PHASE_FAILED_SAFE && native_safe && g->prior_native_safe &&
           gpu_safe == g->prior_gpu_safe); break;
 case TB_OP_START:
  valid = (next == TB_PHASE_START_ACCEPTED || next == g->prior) &&
          !native_safe && gpu_safe; break;
 case TB_OP_WAIT:
  valid = (next == TB_PHASE_TRANSPORT_DONE || next == g->prior) &&
          !native_safe && gpu_safe; break;
 case TB_OP_STOP:
  valid = next == TB_PHASE_DRAINED_SAFE && native_safe; break;
 case TB_OP_VISIBLE:
  valid = next == TB_PHASE_DRAINED_SAFE && native_safe && gpu_safe; break;
 case TB_OP_GPU_VERIFY:
  valid = next == TB_PHASE_VERIFIED && native_safe && gpu_safe; break;
 case TB_OP_EPOCH_CLOSE:
  valid = next == g->prior && native_safe && gpu_safe; break;
 case TB_OP_GPU_CLOSE:
  valid = next == TB_PHASE_CLOSED && native_safe && gpu_safe; break;
 case TB_OP_CONTROL:
  valid = next == g->prior && native_safe == g->prior_native_safe &&
          gpu_safe == g->prior_gpu_safe; break;
 }
 if (!valid) goto out;
 g->phase = next; g->native_safe = native_safe;
 if (g->operation == TB_OP_CREATE && next == TB_PHASE_FAILED_SAFE) {
  /* The owner reports that no CREATE syscall was issued. */
  g->ever_create = g->prior_ever_create;
  g->pair = g->prior_pair; g->visible = g->prior_visible;
 }
 /* Native receipts cannot manufacture GPU completion evidence. */
 if (g->operation == TB_OP_GPU_OPEN || g->operation == TB_OP_GPU_FILL ||
     g->operation == TB_OP_VISIBLE || g->operation == TB_OP_GPU_VERIFY)
  g->gpu_safe = gpu_safe;
 else
  g->gpu_safe = g->gpu_safe && gpu_safe;
 g->busy = false;
 if (g->operation == TB_OP_GPU_FILL && next == TB_PHASE_GPU_READY) g->filled = true;
 if (g->operation == TB_OP_VISIBLE) g->visible = true;
 rc = 0;
 out:
 pthread_mutex_unlock(&g->lock);
 return rc;
}

void tb_guard_hold(struct tb_guard *g, uint32_t reason)
{
 if (!g) return;
 pthread_mutex_lock(&g->lock);
 g->held = true; g->reasons |= reason; g->phase = TB_PHASE_HELD;
 pthread_mutex_unlock(&g->lock);
}

int tb_guard_pair_stopped(struct tb_guard *g)
{
 int rc = -EPERM;
 if (!g) return -EINVAL;
 pthread_mutex_lock(&g->lock);
 if (!g->held && !g->busy && g->phase == TB_PHASE_DRAINED_SAFE && g->native_safe) {
  g->pair = true; rc = 0;
 }
 pthread_mutex_unlock(&g->lock);
 return rc;
}
uint32_t tb_guard_cleanup_permissions(const struct tb_guard *g)
{
 struct tb_guard_snapshot s;
 tb_guard_snapshot(g, &s);
 return s.cleanup_permissions;
}
int tb_guard_delete(struct tb_guard *g)
{
 bool permitted;
 if (!g) return -EINVAL;
 pthread_mutex_lock(&g->lock);
 permitted = !g->held && !g->busy && g->native_safe && g->gpu_safe;
 pthread_mutex_unlock(&g->lock);
 if (!permitted) return -EPERM;
 pthread_mutex_destroy(&g->lock); free(g);
 return 0;
}
