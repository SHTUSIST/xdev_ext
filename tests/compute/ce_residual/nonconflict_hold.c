/* SPDX-License-Identifier: GPL-2.0 */
/* Additive check: a retained cleanup hold excludes only configured overlap. */
#define main frozen_main
#include "harness.c"
#undef main

static void retained_nonconflict(bool different_ops)
{
 struct fixture a, b;
 struct xdev_ext_mech_batch bb;
 int before;
 case_name = different_ops ? "held-different-ops-positive" : "held-adjacent-range-positive";
 reset();
 init(&a, 0);
 init(&b, different_ops);
 batch_init(&bb, 1, 0);
 CHECK(!bind_stage(&a, 0, 4096), "A binds exact [4096,4352)");
 CHECK(!bind_stage(&b, 0, different_ops ? 4096 : 4352), "B binds independent configured range");
 unregion_errno = -EIO;
 CHECK(xdev_ext_mech_unbind_checked(&a.s) == -EIO, "A retains region on cleanup refusal");
 expect_holds(&a.st[0], 1, "A retained cleanup owns hold");
 before = native_calls;
 CHECK(!submit(&b.st[0], &bb), "nonconflicting B admitted despite A hold");
 CHECK(native_calls == before + 1, "nonconflicting B native command executes once");
 finish(&b.st[0], &bb, false);
 unregion_errno = 0;
 CHECK(!xdev_ext_mech_unbind_checked(&a.s), "A eventually cleans up");
 CHECK(!xdev_ext_mech_unbind_checked(&b.s), "B cleans up");
 CHECK(module_a.refs == 0 && module_b.refs == 0, "pins balanced after independent use");
}

int main(void)
{
 setvbuf(stdout, NULL, _IONBF, 0);
 retained_nonconflict(false);
 retained_nonconflict(true);
 printf("checks=%d failures=%d\n", checks, failures);
 return failures ? 1 : 0;
}
