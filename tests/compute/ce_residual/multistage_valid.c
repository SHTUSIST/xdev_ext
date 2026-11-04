/* SPDX-License-Identifier: GPL-2.0 */
/* Additive control: v3 harness/assertions remain frozen and unmodified. */
#define main frozen_main
#include "harness.c"
#undef main

int main(void)
{
 struct fixture a, b;
 struct xdev_ext_mech_batch bb;
 int before;
 setvbuf(stdout, NULL, _IONBF, 0);
 case_name = "valid-bind-multistage-cleanup";
 reset();
 init(&a, 0);
 init(&b, 0);
 batch_init(&bb, 1, 0);
 CHECK(!bind_stage(&a, 0, 4096), "successful A stage0 bind");
 CHECK(!bind_stage(&a, 1, 4160), "successful A stage1 bind");
 CHECK(!bind_stage(&b, 0, 4096), "successful B bind");
 expect_holds(&a.st[0], 0, "no transient hold after both binds");
 /* Controlled direct class cleanup reentry tests two stage contributions.
  * Core checked-unbind normally stops on the first refusal. */
 unregion_errno = -EIO;
 CHECK(xdev_ext_ce_unbind(&a.st[0]) == -EIO, "stage0 cleanup refusal");
 CHECK(xdev_ext_ce_unbind(&a.st[1]) == -EIO, "stage1 cleanup refusal");
 expect_holds(&a.st[0], 2, "each valid bound stage contributes one hold");
 CHECK(xdev_ext_ce_unbind(&a.st[0]) == -EIO, "stage0 refusal retry");
 expect_holds(&a.st[0], 2, "retry preserves exact two holds");
 CHECK(unhost_calls == 2, "successful host unmaps not repeated");
 CHECK(module_a.refs == 3 && module_a.puts == 0, "all three stage pins retained");
 after_block(&b.st[0], &bb);
 if (((struct xdev_ext_ce_cookie *)bb.cookie)->state == XDEV_EXT_CE_CK_ARMED)
  finish(&b.st[0], &bb, false);
 unregion_errno = 0;
 CHECK(!xdev_ext_ce_unbind(&a.st[0]), "stage0 releases region");
 expect_holds(&a.st[1], 1, "stage1 hold survives stage0 detach");
 CHECK(module_a.refs == 2 && module_a.puts == 1, "only stage0 module pin released");
 xdev_ext_ce_mark_dead(&a.st[1]);
 before = native_calls;
 after_block(&b.st[0], &bb);
 CHECK(native_calls == before, "mark dead preserves native exclusion");
 if (((struct xdev_ext_ce_cookie *)bb.cookie)->state == XDEV_EXT_CE_CK_ARMED)
  finish(&b.st[0], &bb, false);
 CHECK(!xdev_ext_ce_unbind(&a.st[1]), "last valid-bound stage releases region");
 CHECK(!submit(&b.st[0], &bb), "B admitted after final A cleanup");
 finish(&b.st[0], &bb, false);
 CHECK(!xdev_ext_mech_unbind_checked(&b.s), "B cleans up");
 CHECK(module_a.refs == 0 && module_a.puts == 3, "one pin put per original stage");
 CHECK(list_empty(&xdev_ext_ce_lease_groups), "all groups gone");
 printf("checks=%d failures=%d\n", checks, failures);
 return failures ? 1 : 0;
}
