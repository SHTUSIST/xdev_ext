// SPDX-License-Identifier: GPL-2.0
/* Run the same requirements against either lifecycle API.  The legacy adapter
 * only translates call signatures: it never repairs the production behavior.
 * This keeps a runnable behavioral RED in addition to the new API absence RED.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#define __KERNEL__
#include "io_uring/xdev_ext_mech_lifecycle.h"
#undef __KERNEL__

static const volatile void *watched;
static unsigned int writes, attempts, invalid_states;

void life_model_before(const volatile void *p, int kind)
{
	if (p == watched && kind == LIFE_MODEL_CAS)
		attempts++;
}

void life_model_after(const volatile void *p, int kind, bool wrote)
{
	(void)kind;
	if (p == watched && wrote) {
		__u64 value = __atomic_load_n((const __u64 *)p, __ATOMIC_ACQUIRE);
		writes++;
#ifdef XDEV_EXT_MECH_LIFE_REFS
		invalid_states += (value & XDEV_EXT_MECH_L_STATE_MASK) > 3;
#else
		invalid_states += (value & XDEV_EXT_MECH_L_MASK) > 3;
#endif
	}
}

#ifdef XDEV_EXT_MECH_LIFE_REFS
static __u64 generation(struct xdev_ext_mech_life *l)
{ return xdev_ext_mech_life_gen(l); }
static int producer(struct xdev_ext_mech_life *l, bool from_ready, __u64 *claim)
{ (void)from_ready; return xdev_ext_mech_life_claim(l, 0, claim); }
static int publish(struct xdev_ext_mech_life *l, __u64 claim)
{ return xdev_ext_mech_life_publish(l, claim, 1, 64); }
static int consumer(struct xdev_ext_mech_life *l, __u64 *claim)
{ return xdev_ext_mech_life_acquire(l, 1, 0, claim); }
static int complete(struct xdev_ext_mech_life *l, __u64 claim)
{ return xdev_ext_mech_life_put(l, claim); }
#else
#define XDEV_EXT_MECH_LIFE_LEGACY_ADAPTER 1
#ifdef XDEV_EXT_MECH_LIFE_LEGACY_ADAPTER
/* XDEV_EXT_MECH_LIFE_LEGACY adapter: retained only to execute the old header. */
static __u64 generation(struct xdev_ext_mech_life *l)
{ return xdev_ext_mech_life_token(l); }
static int producer(struct xdev_ext_mech_life *l, bool from_ready, __u64 *claim)
{ return xdev_ext_mech_life_begin_produce(l, from_ready, claim); }
static int publish(struct xdev_ext_mech_life *l, __u64 claim)
{ return xdev_ext_mech_life_publish(l, claim, 64); }
static int consumer(struct xdev_ext_mech_life *l, __u64 *claim)
{ return xdev_ext_mech_life_begin_consume(l, claim); }
static int complete(struct xdev_ext_mech_life *l, __u64 claim)
{ return xdev_ext_mech_life_complete_consume(l, claim); }
#endif /* XDEV_EXT_MECH_LIFE_LEGACY_ADAPTER */
#endif

static int failures, number;
static void check(bool ok, const char *name)
{
	printf("%s %d - %s\n", ok ? "ok" : "not ok", ++number, name);
	failures += !ok;
}

int main(void)
{
	struct xdev_ext_mech_life l;
	__u64 p, c, gen;
	int ret;

	puts("TAP version 13\n1..7");
	xdev_ext_mech_life_init(&l);
	gen = generation(&l);
	ret = producer(&l, false, &p);
	check(!ret && generation(&l) == gen, "L5 producer claim preserves generation");
	watched = &l.ctrl;
	ret = publish(&l, p);
	watched = NULL;
	check(!ret && writes == 1 && attempts == 1,
	      "L1 publication makes one atomic word update");
	check(!ret && !invalid_states, "L1 every observed data-plane state is one of four");
	gen = generation(&l);
	ret = consumer(&l, &c);
	check(!ret && generation(&l) == gen, "L5 consumer claim preserves generation");
	gen = generation(&l);
	ret = complete(&l, c);
	check(ret >= 0 && xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_FREE,
	      "L2 last consumer completion recycles to FREE");
	check(ret >= 0 && generation(&l) == gen + 1,
	      "L5 last consumer completion increments generation");
	xdev_ext_mech_life_init(&l);
	ret = producer(&l, false, &p);
	if (!ret)
		ret = publish(&l, p);
	check(!ret && producer(&l, true, &p) == -EBUSY &&
	      xdev_ext_mech_life_phase(&l) == XDEV_EXT_MECH_L_READY,
	      "L4 producer cannot overwrite a READY publication");
	return failures ? 1 : 0;
}
