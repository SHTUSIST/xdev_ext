/* SPDX-License-Identifier: GPL-2.0 */
/* Test-only observation boundaries; the atomic operations still execute. */
#ifndef PEER_WAIT_HOOKS_H
#define PEER_WAIT_HOOKS_H
#include <stdatomic.h>
void peer_wait_after_load(const void *p);
void peer_wait_after_arm(const void *p);
void peer_wait_after_fence(void);
#define __atomic_load_n(p, order) ({ __auto_type wait_v_ = __atomic_load_n((p), (order)); peer_wait_after_load((p)); wait_v_; })
#define __atomic_or_fetch(p, v, order) ({ __auto_type wait_v_ = __atomic_or_fetch((p), (v), (order)); peer_wait_after_arm((p)); wait_v_; })
#define __atomic_fetch_or(p, v, order) ({ __auto_type wait_v_ = __atomic_fetch_or((p), (v), (order)); peer_wait_after_arm((p)); wait_v_; })
#define __atomic_thread_fence(order) do { __atomic_thread_fence(order); peer_wait_after_fence(); } while (0)
#endif
