/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_CE_ASYNC_H_
#define _NV_XDEV_EXT_CE_ASYNC_H_
#include "nv-xdev_ext-gpu-policy.h"
#include "nv-xdev_ext-ce-classify.h"

/* Caller serializes all operations; tickets and channel tokens are distinct. */
enum nv_xdev_ext_ce_async_state { NV_XDEV_EXT_CE_ASYNC_FREE,
    NV_XDEV_EXT_CE_ASYNC_RESERVED, NV_XDEV_EXT_CE_ASYNC_PENDING,
    NV_XDEV_EXT_CE_ASYNC_QUARANTINED };
struct nv_xdev_ext_ce_async_slot {
    nv_xdev_ext_gpu_u64 ticket, token, bytes;
    void *cookie;
    unsigned int state;
};
struct nv_xdev_ext_ce_async_pool {
    struct nv_xdev_ext_ce_async_slot *slots;
    unsigned int capacity, stopping, quarantined;
};
struct nv_xdev_ext_ce_async_completion {
    nv_xdev_ext_gpu_u64 ticket, token, bytes;
    void *cookie;
};
static inline int nv_xdev_ext_ce_async_init(struct nv_xdev_ext_ce_async_pool *p,
    struct nv_xdev_ext_ce_async_slot *s, unsigned int n)
{
    unsigned int i;
    if (!p || !s || !n) return -EINVAL;
    p->slots = s; p->capacity = n; p->stopping = 0; p->quarantined = 0;
    for (i = 0; i < n; i++) {
        s[i].ticket = s[i].token = s[i].bytes = 0;
        s[i].cookie = 0; s[i].state = NV_XDEV_EXT_CE_ASYNC_FREE;
    }
    return 0;
}
static inline int nv_xdev_ext_ce_async_reserve(struct nv_xdev_ext_ce_async_pool *p,
    nv_xdev_ext_gpu_u64 ticket, void *cookie, nv_xdev_ext_gpu_u64 bytes,
    struct nv_xdev_ext_ce_async_slot **out)
{
    unsigned int i;
    if (!p || !out || !p->slots) return -EINVAL;
    *out = 0;
    if (p->stopping || p->quarantined) return -ESHUTDOWN;
    for (i = 0; i < p->capacity; i++) {
        struct nv_xdev_ext_ce_async_slot *s = &p->slots[i];
        if (s->state != NV_XDEV_EXT_CE_ASYNC_FREE) continue;
        s->ticket = ticket; s->token = 0; s->bytes = bytes; s->cookie = cookie;
        s->state = NV_XDEV_EXT_CE_ASYNC_RESERVED; *out = s;
        return 0;
    }
    return -EAGAIN;
}
static inline enum nv_xdev_ext_ce_outcome nv_xdev_ext_ce_async_submitted(
    struct nv_xdev_ext_ce_async_pool *p, struct nv_xdev_ext_ce_async_slot *s,
    int status, int issued, nv_xdev_ext_gpu_u64 token)
{
    if (status == 0 && token != 0) {
        s->token = token; s->state = NV_XDEV_EXT_CE_ASYNC_PENDING;
        return NV_XDEV_EXT_CE_OK;
    }
    /* A successful call without a token cannot prove DMA quiescence. */
    if (issued || status == 0) {
        s->state = NV_XDEV_EXT_CE_ASYNC_QUARANTINED;
        p->quarantined = p->stopping = 1;
        return NV_XDEV_EXT_CE_AMBIGUOUS;
    }
    s->state = NV_XDEV_EXT_CE_ASYNC_FREE;
    return NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED;
}
static inline int nv_xdev_ext_ce_async_ready(struct nv_xdev_ext_ce_async_pool *p,
    struct nv_xdev_ext_ce_async_slot *s, nv_xdev_ext_gpu_u64 watermark,
    struct nv_xdev_ext_ce_async_completion *c)
{
    /* A verified watermark may retire older work even after another slot
     * was quarantined. The quarantined slot itself remains unreleasable.
     */
    if (!p || !s || !c ||
        s->state != NV_XDEV_EXT_CE_ASYNC_PENDING || watermark < s->token) return 0;
    c->ticket = s->ticket; c->token = s->token;
    c->bytes = s->bytes; c->cookie = s->cookie;
    s->state = NV_XDEV_EXT_CE_ASYNC_FREE;
    return 1;
}
static inline void nv_xdev_ext_ce_async_stop(struct nv_xdev_ext_ce_async_pool *p)
{ p->stopping = 1; }
static inline int nv_xdev_ext_ce_async_can_release(const struct nv_xdev_ext_ce_async_pool *p)
{
    unsigned int i;
    if (!p || p->quarantined) return 0;
    for (i = 0; i < p->capacity; i++)
        if (p->slots[i].state != NV_XDEV_EXT_CE_ASYNC_FREE) return 0;
    return 1;
}
#endif
