/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_PEER_NET_TRACK_H
#define _XDEV_EXT_PEER_NET_TRACK_H
#ifdef __KERNEL__
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/types.h>
typedef atomic_t xdev_ext_net_atomic;
#define xdev_ext_net_read(p) atomic_read_acquire(p)
#define xdev_ext_net_set(p, v) atomic_set_release(p, v)
#else
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
typedef int xdev_ext_net_atomic;
#define xdev_ext_net_read(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define xdev_ext_net_set(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)
#endif
#ifndef XDEV_EXT_PEER_NET_RMW_HOOK
#define XDEV_EXT_PEER_NET_RMW_HOOK() do { } while (0)
#endif
#define XDEV_EXT_PEER_NET_TRACK_MAX 16U
#define XDEV_EXT_PEER_NET_TIMEOUT_MS 30000U
#define XDEV_EXT_PEER_NET_STOP_GRACE_MS 1000U
enum xdev_ext_peer_net_track_ret {
 XDEV_EXT_PEER_NET_TRACK_PENDING,
 XDEV_EXT_PEER_NET_TRACK_HANDOFF,
 XDEV_EXT_PEER_NET_TRACK_LATE,
};
struct xdev_ext_peer_net_track {
 xdev_ext_net_atomic pending, owner, status, uncertain;
 int abandon_error;
};
static inline int xdev_ext_net_cas(xdev_ext_net_atomic *p, int old, int new)
{
 XDEV_EXT_PEER_NET_RMW_HOOK();
#ifdef __KERNEL__
 return atomic_cmpxchg(p, old, new);
#else
 __atomic_compare_exchange_n(p, &old, new, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
 return old;
#endif
}
static inline int xdev_ext_net_dec(xdev_ext_net_atomic *p)
{
 XDEV_EXT_PEER_NET_RMW_HOOK();
#ifdef __KERNEL__
 return atomic_dec_return(p);
#else
 return __atomic_sub_fetch(p, 1, __ATOMIC_ACQ_REL);
#endif
}
static inline int xdev_ext_peer_net_track_init_max(struct xdev_ext_peer_net_track *t,
                                                  unsigned int posted, unsigned int max)
{
 if (!t || !posted || posted > max) return -EINVAL;
 xdev_ext_net_set(&t->pending, posted);
 xdev_ext_net_set(&t->owner, 0);
 xdev_ext_net_set(&t->status, 0);
 xdev_ext_net_set(&t->uncertain, 0);
 t->abandon_error = 0;
 return 0;
}
static inline int xdev_ext_peer_net_track_init(struct xdev_ext_peer_net_track *t,
                                              unsigned int posted)
{
 return xdev_ext_peer_net_track_init_max(t, posted, XDEV_EXT_PEER_NET_TRACK_MAX);
}
/* Driver promises exactly one callback per element. The decrement is the
 * release of that callback's record; the last decrement acquires all records.
 * owner arbitrates only the last callback against the worker's abandonment.
 */
static inline int xdev_ext_peer_net_track_complete(struct xdev_ext_peer_net_track *t,
                                                  int status, bool quiesced)
{
 if (xdev_ext_net_read(&t->owner) || xdev_ext_net_read(&t->pending) <= 0)
  return XDEV_EXT_PEER_NET_TRACK_LATE;
 if (status) xdev_ext_net_cas(&t->status, 0, status);
 if (!quiesced) xdev_ext_net_set(&t->uncertain, 1);
 if (xdev_ext_net_dec(&t->pending))
  return xdev_ext_net_read(&t->owner) ? XDEV_EXT_PEER_NET_TRACK_LATE :
                                       XDEV_EXT_PEER_NET_TRACK_PENDING;
 return !xdev_ext_net_cas(&t->owner, 0, 1) ? XDEV_EXT_PEER_NET_TRACK_HANDOFF :
                                          XDEV_EXT_PEER_NET_TRACK_LATE;
}
static inline bool xdev_ext_peer_net_track_abandon(struct xdev_ext_peer_net_track *t, int err)
{
 if (xdev_ext_net_cas(&t->owner, 0, 2)) return false;
 t->abandon_error = err;
 xdev_ext_net_set(&t->owner, 3);
 return true;
}
static inline int xdev_ext_peer_net_track_result(const struct xdev_ext_peer_net_track *t,
                                                bool *sequester)
{
 int owner = xdev_ext_net_read(&t->owner), status;
 *sequester = false;
 if (owner == 3) { *sequester = true; return t->abandon_error; }
 if (owner != 1) return -EINPROGRESS;
 *sequester = xdev_ext_net_read(&t->uncertain) != 0;
 status = xdev_ext_net_read(&t->status);
 return status ? status : *sequester ? -EIO : 0;
}
static inline bool xdev_ext_peer_net_track_expired(unsigned long long now_ms,
 unsigned long long posted_ms, unsigned long long stop_ms)
{
 return now_ms - posted_ms >= XDEV_EXT_PEER_NET_TIMEOUT_MS ||
        (stop_ms && now_ms - stop_ms >= XDEV_EXT_PEER_NET_STOP_GRACE_MS);
}
#endif
