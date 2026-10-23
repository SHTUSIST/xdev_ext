/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace stand-in for the three kernel primitives that
 * io_uring/xdev_ext_mech_lifecycle.h uses under __KERNEL__.  Each one keeps
 * the kernel ordering (acquire load, release store, fully ordered
 * compare-and-exchange that updates *old on failure) and reports the access
 * to the model checker: before it, so the checker can switch actors at that
 * point, and after a write, so it can check the word that was written.
 */
#ifndef XDEV_EXT_LIFE_MODEL_SHIM_ATOMIC_H
#define XDEV_EXT_LIFE_MODEL_SHIM_ATOMIC_H

#include <stdbool.h>

enum { LIFE_MODEL_LOAD, LIFE_MODEL_STORE, LIFE_MODEL_CAS };

void life_model_before(const volatile void *p, int kind);
void life_model_after(const volatile void *p, int kind, bool wrote);

#define smp_load_acquire(p) ({						\
	life_model_before((p), LIFE_MODEL_LOAD);			\
	__atomic_load_n((p), __ATOMIC_ACQUIRE);				\
})

#define smp_store_release(p, v) do {					\
	life_model_before((p), LIFE_MODEL_STORE);			\
	__atomic_store_n((p), (v), __ATOMIC_RELEASE);			\
	life_model_after((p), LIFE_MODEL_STORE, true);			\
} while (0)

#define try_cmpxchg(p, old, v) ({					\
	bool __life_ok;							\
	life_model_before((p), LIFE_MODEL_CAS);				\
	__life_ok = __atomic_compare_exchange_n((p), (old), (v), false,	\
						__ATOMIC_ACQ_REL,	\
						__ATOMIC_ACQUIRE);	\
	life_model_after((p), LIFE_MODEL_CAS, __life_ok);		\
	__life_ok;							\
})

#endif
