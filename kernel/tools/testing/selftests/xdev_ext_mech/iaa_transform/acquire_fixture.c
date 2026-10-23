/* SPDX-License-Identifier: GPL-2.0 */
/* L11: source acquisition is counted and generation changes only on recycle. */
/* Boundary shims only. No acquisition policy is implemented in this fixture. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "io_uring/xdev_ext_mech_step.h"
typedef __u32 u32;
typedef __u64 u64;
#define BIT(n) (1U << (n))
static bool warn_once(bool condition) { return condition; }
#define WARN_ON_ONCE(x) warn_once(!!(x))
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U << 2)
struct xdev_ext_mech_class_ops { u32 flags; };
struct xdev_ext_mech_stage { u32 class_id, direction, index; const struct xdev_ext_mech_class_ops *cls; };
struct xdev_ext_mech_session { u32 nr_stages;struct xdev_ext_mech_stage_uapi plan[1];struct xdev_ext_mech_stage st[1]; struct xdev_ext_mech_life *life; };
struct xdev_ext_mech_frame { u32 index, data_len; };
struct xdev_ext_mech_batch {
 struct {u32 stage;} bs;
 u32 nr_frames, life_active;
 u64 life_token[2];
 u32 life_previous[2];
 bool producing, fifo_accepted;
 struct xdev_ext_mech_frame f[2];
};
/* xdev_ext_mech_life_undo */
/* xdev_ext_mech_batch_acquire */
static int check(bool ok, const char *message) {
 if (ok) return 0;
 fprintf(stderr, "FAIL: %s\n", message);
 return 1;
}
int main(int argc, char **argv) {
 assert(argc == 2);
 bool short_source=!strcmp(argv[1],"short_source");
 bool short_second=!strcmp(argv[1],"short_second");
 bool busy_second=!strcmp(argv[1],"busy_second");
 bool saturated=!strcmp(argv[1],"saturated");
 bool ordinary=!strcmp(argv[1],"ordinary_producer");
 struct xdev_ext_mech_life life[2] = {0};
 const struct xdev_ext_mech_class_ops ops={.flags=ordinary?0:XDEV_EXT_MECH_CLASS_F_TRANSFORM};
 struct xdev_ext_mech_session s = {.st={{.class_id=ordinary?XDEV_EXT_MECH_CLASS_CE:XDEV_EXT_MECH_CLASS_IAA,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.cls=&ops}},.life=life};
 struct xdev_ext_mech_batch b = {.nr_frames=1,.f={{.index=0,.data_len=1024},{.index=1,.data_len=1024}}};
 s.nr_stages=1;s.plan[0]=(struct xdev_ext_mech_stage_uapi){.class_id=ordinary?XDEV_EXT_MECH_CLASS_CE:XDEV_EXT_MECH_CLASS_IAA,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};
 u64 token;
 if(!ordinary){
 assert(!xdev_ext_mech_life_claim(&life[0],0,&token));
 assert(!xdev_ext_mech_life_publish(&life[0],token,1,short_source?1000:1024));
 }
 if (!strcmp(argv[1],"to_device"))s.st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
 if (short_second || busy_second) {
  b.nr_frames=2;
  if(short_second) {
   assert(!xdev_ext_mech_life_claim(&life[1],0,&token));
   assert(!xdev_ext_mech_life_publish(&life[1],token,1,1000));
  }
 }
 if(saturated)life[0].ctrl=xdev_ext_mech_life_word(XDEV_EXT_MECH_L_GEN_MAX,XDEV_EXT_MECH_L_READY,1,0,0);
 u64 before=life[0].ctrl;
 int ret=xdev_ext_mech_batch_acquire(&s,&b);
 if (short_source || short_second || busy_second) {
  int expected=(short_source||short_second)?-ENODATA:-EBUSY;
  return check(ret == expected,"transform accepted invalid source or returned wrong errno") |
   check(xdev_ext_mech_life_phase(&life[0]) == XDEV_EXT_MECH_L_READY,"rejected transform changed first source phase") |
   check(!b.life_active,"rejected transform retained active source mask") |
   check(life[0].valid_len == 1024 || short_source,"rejected transform changed valid_len") |
   check(life[0].ctrl >= before,"source generation went backwards during rollback");
 }
 if(ordinary)
  return check(!ret && xdev_ext_mech_life_phase(&life[0])==XDEV_EXT_MECH_L_IO_PENDING,
   "transform flag changed ordinary FROM_DEVICE producer acquisition");
 if(saturated)assert(xdev_ext_mech_life_gen(&life[0])==XDEV_EXT_MECH_L_GEN_MAX);
 int bad=check(ret == 0,"valid source was refused") |
  check(xdev_ext_mech_life_phase(&life[0]) == XDEV_EXT_MECH_L_OUT_PENDING,"IAA source was acquired as producer instead of read-only consumer") |
  check(life[0].valid_len==1024,"source valid_len changed during read acquisition");
 if(!bad) {
  xdev_ext_mech_life_undo(&s,&b);
  bad |= check(xdev_ext_mech_life_phase(&life[0])==XDEV_EXT_MECH_L_READY && !b.life_active,
   "preaccept rollback did not restore source READY");
 }
 return bad;
}
