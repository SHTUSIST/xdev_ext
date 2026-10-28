/* SPDX-License-Identifier: GPL-2.0 */
/* Test-only metadata adapters. No checked-apply or protocol state machine here. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <linux/if_xdp.h>
#include "@MECH@"
#include "@PROG@"

#define SEC(s)
#define BPF_PROG(name, ...) name(void *ctx, __VA_ARGS__)
struct xdev_ext_xdomain_mech_ops {
 __u32 abi_version, flags;
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *);
 __s32 (*build)(const struct xdev_ext_mech_ctx *);
 __s32 (*complete)(const struct xdev_ext_mech_ctx *);
};
_Static_assert(sizeof(struct xdev_ext_xdomain_proto_info) == 256, "info size");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info, tag) == 200, "tag offset");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_info, reserved) == 224, "reserved offset");
_Static_assert(sizeof(struct xdev_ext_xdomain_proto_verdict) == 64, "verdict size");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_verdict, event_id) == 16, "event id offset");
_Static_assert(offsetof(struct xdev_ext_xdomain_proto_verdict, status) == 48, "status offset");
_Static_assert(sizeof(struct xdev_ext_xdomain_desc) == 64, "descriptor size");
_Static_assert(sizeof(struct xdev_ext_xdomain_mech_cqe) == 64, "CQE size");
_Static_assert(sizeof(struct xdev_ext_mech_stage_caps) == 64, "stage caps size");
_Static_assert(XDEV_EXT_MECH_SITE_WORKER == 0, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_RX_GENERIC == 1, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_RX_NATIVE == 2, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_URING_CMD == 3, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_CREATE == 4, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_RX_HOLD_RESULT == 5, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_WORKER_SELECT == 6, "existing site");
_Static_assert(XDEV_EXT_MECH_SITE_WORKER_PROTOCOL == 7, "additive protocol site");
@MIRROR_ASSERTIONS@

static struct xdev_ext_xdomain_mech_info build_info;
static struct xdev_ext_xdomain_desc descriptors[XDEV_EXT_MECH_MAX_FRAMES];
static struct xdev_ext_xdomain_mech_cqe final_cqe;
static struct xdev_ext_xdomain_proto_info snapshot;
static struct xdev_ext_xdomain_proto_verdict recorded;
static unsigned info_calls, verdict_calls, generic_calls, cqe_calls;
static int no_build_info, no_cqe, no_desc_at = -1, info_error, verdict_error;

static int all_zero(const void *p, size_t len)
{
 const unsigned char *b = p;
 for (size_t i = 0; i < len; i++) if (b[i]) return 0;
 return 1;
}
static void *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, __u32 n)
{
 generic_calls++;
 /* A protocol event has no generic metadata/backing, even before RX submit. */
 assert(ctx->callsite != XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 assert(n == sizeof(build_info));
 return no_build_info ? NULL : &build_info;
}
static void *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 i, __u32 n)
{
 generic_calls++;
 assert(ctx->callsite != XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 assert(i < XDEV_EXT_MECH_MAX_FRAMES && n == sizeof(descriptors[0]));
 return (int)i == no_desc_at ? NULL : &descriptors[i];
}
static void *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 i, __u32 n)
{
 cqe_calls++;
 /* Never return or manufacture a final CQE in the protocol branch. */
 assert(ctx->callsite == XDEV_EXT_MECH_SITE_WORKER);
 assert(!i && n == sizeof(final_cqe));
 return no_cqe ? NULL : &final_cqe;
}
static int bpf_xdev_ext_xdomain_info(const struct xdev_ext_mech_ctx *ctx, void *out, __u32 n)
{
 info_calls++;
 assert(ctx->callsite == XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 assert(!ctx->batch_id && !ctx->nr_frames && !ctx->desc_cap && !ctx->base.length);
 assert(n == 256 && all_zero(out, n)); /* initialized writable local output */
 if (info_error) return info_error;
 memcpy(out, &snapshot, n);
 return 0;
}
static int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *ctx,
                                     const void *in, __u32 n)
{
 verdict_calls++;
 assert(ctx->callsite == XDEV_EXT_MECH_SITE_WORKER_PROTOCOL);
 assert(n == 64 && verdict_calls == 1);
 if (verdict_error) return verdict_error;
 memcpy(&recorded, in, n); /* owned copy, never retain a BPF pointer */
 return 0;
}


/* Ordinary v1 invocation storage exposed to the versioned reference policy.
 * Actual private kfunc identity/validation is tested independently. */
static int bpf_xdev_ext_xdomain_info_v2(const struct xdev_ext_mech_ctx *ctx,void *out,__u32 size)
{
 struct xdev_ext_xdomain_proto_info base={0};
 struct xdev_ext_xdomain_proto_info_v2 *info=out;
 int ret;
 if(!out||size!=sizeof(*info))return -EINVAL;
 ret=bpf_xdev_ext_xdomain_info(ctx,&base,sizeof(base));
 if(ret)return ret;
 if(base.size!=sizeof(base)||base.version!=XDEV_EXT_XDOMAIN_PROTO_VERSION)return -EINVAL;
 memset(out,0,size);info->base=base;
 info->base.size=sizeof(*info);info->base.version=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION;
 return 0;
}
static int bpf_xdev_ext_xdomain_verdict_v2(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size)
{
 struct xdev_ext_xdomain_proto_verdict verdict;
 if(!in||size!=sizeof(verdict))return -EINVAL;
 memcpy(&verdict,in,size);
 if(verdict.size!=size||verdict.version!=XDEV_EXT_XDOMAIN_PROTO_V2_VERSION||
    verdict.action>XDEV_EXT_XDP_ACT_CANCEL_ARMED)return -EINVAL;
 verdict.version=XDEV_EXT_XDOMAIN_PROTO_VERSION;
 return bpf_xdev_ext_xdomain_verdict(ctx,&verdict,size);
}

@BPF_SOURCE@

#define UP (XDEV_EXT_XDP_F_LINK_UP | XDEV_EXT_XDP_F_ADMITS)
#define KNOWN (XDEV_EXT_XDP_F_LOCAL_KNOWN | XDEV_EXT_XDP_F_LOCAL_QUIESCED)
#define POSTED XDEV_EXT_XDP_F_NATIVE_POSTED
#define PENDING XDEV_EXT_XDP_F_NATIVE_PENDING
/* Frozen RDV numbers from the requirements: IDLE=0 ARMED=1 ANNOUNCED=2 POSTED=3.
 * No alternate event/action numeric table: every action/event below is UAPI. */
struct policy_case {
 const char *name;
 __u32 event, direction, state, remote, facts;
 __u64 now, hard, policy;
 __u32 posted_groups, ctl_room;
 __s32 local_status, chain_status;
 __u64 group, credit, msg_credit;
 __u32 expected_action;
 __u64 expected_wake, expected_credit;
 __s32 expected_status;
};
/* Explicit input/expected matrix. Every expected action is hand-selected from
 * 4.7b/4.7d. No expected value calls a production predicate or transition rule.
 * Time unit is ns. Ordinary now=1s, default bounded wake=1.020s.
 * Root clarified default WAIT=min(saturating(now+20ms), future policy/hard).
 * FAIL_LINK default=-ENOLINK for link/dead stage, -ETIMEDOUT for expiry. */
static const struct policy_case cases[] = {
 {"submit credit", XDEV_EXT_XDP_EV_TX_SUBMIT,1,0,0,UP,1000000000,0,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_TX_ANNOUNCE,0,0,0},
 {"submit no credit", XDEV_EXT_XDP_EV_TX_SUBMIT,1,0,0,UP,1000000000,0,0,0,1,0,0,9,9,9,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"RTS enqueue no room pre-accept", XDEV_EXT_XDP_EV_TX_SUBMIT,1,0,0,UP,1000000000,0,0,0,0,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"WAIT saturates near u64 max", XDEV_EXT_XDP_EV_TX_SUBMIT,1,0,0,UP,18446744073699551615ULL,0,0,0,1,0,0,9,9,9,XDEV_EXT_XDP_ACT_WAIT,18446744073709551615ULL,0,0},
 {"RX submit", XDEV_EXT_XDP_EV_RX_SUBMIT,2,0,0,UP,1000000000,0,0,0,1,0,0,0,16,16,XDEV_EXT_XDP_ACT_RX_ARM,0,0,0},
 {"RTS armed free", XDEV_EXT_XDP_EV_RTS,2,1,0,UP,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_RX_POST,0,0,0},
 {"RTS no armed batch", XDEV_EXT_XDP_EV_RTS,2,0,0,UP,1000000000,31000000000,0,0,1,0,0,0,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"RTS occupied posted/reservation token", XDEV_EXT_XDP_EV_RTS,2,1,0,UP,1000000000,31000000000,0,1,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"canceled pre-batch RTS", XDEV_EXT_XDP_EV_CANCEL,2,0,0,UP|XDEV_EXT_XDP_F_RTS_CANCELED,1000000000,31000000000,0,0,1,-ECANCELED,0,0,16,16,XDEV_EXT_XDP_ACT_REJECT_RTS,0,0,-ECANCELED},
 {"stopping queued RTS", XDEV_EXT_XDP_EV_RTS,2,0,0,UP|XDEV_EXT_XDP_F_STOPPING,1000000000,31000000000,0,0,1,-ECANCELED,0,0,16,16,XDEV_EXT_XDP_ACT_REJECT_RTS,0,0,-ECANCELED},
 {"CTS", XDEV_EXT_XDP_EV_CTS,1,2,0,UP|XDEV_EXT_XDP_F_CTS_RECEIVED,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_TX_POST,0,0,0},
 {"CTS after withdrawal", XDEV_EXT_XDP_EV_CTS,1,2,0,UP|XDEV_EXT_XDP_F_CTS_RECEIVED|XDEV_EXT_XDP_F_WITHDRAWN,1000000000,2000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_TX_POST,0,0,0},
 {"HELD uses normalized msg_credit", XDEV_EXT_XDP_EV_HELD,1,3,0,UP|POSTED|PENDING,1000000000,31000000000,0,0,1,0,0,9,16,12,XDEV_EXT_XDP_ACT_ACCEPT_HELD,0,12,0},
 {"ACK pending uses normalized msg_credit", XDEV_EXT_XDP_EV_ACK,1,3,0,UP|POSTED|PENDING,1000000000,31000000000,0,0,1,0,0,9,12,16,XDEV_EXT_XDP_ACT_ACCEPT_ACK,0,16,0},
 {"FAIL native pending", XDEV_EXT_XDP_EV_FAIL,1,3,0,UP|POSTED|PENDING,1000000000,31000000000,0,0,1,-EIO,0,9,12,16,XDEV_EXT_XDP_ACT_ACCEPT_FAIL,0,16,0},
 {"pre-CTS FAIL zero credit", XDEV_EXT_XDP_EV_FAIL,1,2,0,UP,1000000000,31000000000,0,0,1,-ECANCELED,0,9,16,0,XDEV_EXT_XDP_ACT_ACCEPT_FAIL,0,0,0},
 {"TX local no ACK", XDEV_EXT_XDP_EV_LOCAL,1,3,0,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"WAIT clips earlier policy deadline", XDEV_EXT_XDP_EV_LOCAL,1,3,0,UP|POSTED|KNOWN,1000000000,1015000000,1010000000,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1010000000,0,0},
 {"WAIT clips earlier hard deadline", XDEV_EXT_XDP_EV_LOCAL,1,3,0,UP|POSTED|KNOWN,1000000000,1005000000,1010000000,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1005000000,0,0},
 {"TX known ACKED", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_ACKED,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,0},
 {"TX remote FAILED canonical", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_FAILED,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,-EREMOTEIO},
 {"TX remote LOST canonical", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_LOST,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,-ENOLINK},
 {"TX local error wins remote LOST", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_LOST,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,-EIO},
 {"TX native pending cannot publish ACKED success", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_ACKED,UP|POSTED|PENDING|XDEV_EXT_XDP_F_LOCAL_KNOWN,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"TX error canonical", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_ACKED,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,-EIO},
 {"RX local success is not remote ACK", XDEV_EXT_XDP_EV_LOCAL,2,3,0,UP|POSTED|KNOWN,1000000000,31000000000,0,1,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,0},
 {"RX local error", XDEV_EXT_XDP_EV_LOCAL,2,3,0,UP|POSTED|KNOWN|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,1,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_SEND_FAIL,0,16,-EIO},
 {"successful final CHAIN_END", XDEV_EXT_XDP_EV_CHAIN_END,2,3,0,UP|KNOWN|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_SEND_ACK,0,16,0},
 {"failed final CHAIN_END", XDEV_EXT_XDP_EV_CHAIN_END,2,3,0,UP|KNOWN|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,1,0,-EIO,9,16,16,XDEV_EXT_XDP_ACT_SEND_FAIL,0,16,-EIO},
 {"sequestered final disposition", XDEV_EXT_XDP_EV_CHAIN_END,2,3,0,UP|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_CHAIN_SEQUESTERED|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,1,0,-EIO,9,16,16,XDEV_EXT_XDP_ACT_SEND_FAIL,0,16,-EIO},
 {"RX successful POST_RESULT", XDEV_EXT_XDP_EV_POST_RESULT,2,3,0,UP|POSTED|PENDING|XDEV_EXT_XDP_F_CTS_OWED,1000000000,31000000000,0,1,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_SEND_CTS,0,16,0},
 {"posted repeated CANCEL", XDEV_EXT_XDP_EV_CANCEL,2,3,0,UP|POSTED|PENDING|XDEV_EXT_XDP_F_CTS_OWED,1000000000,31000000000,0,1,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_SEND_CTS,0,16,0},
 {"owed CTS", XDEV_EXT_XDP_EV_REPLY_DUE,2,3,0,UP|POSTED|PENDING|XDEV_EXT_XDP_F_CTS_OWED,1000000000,31000000000,0,1,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_SEND_CTS,0,16,0},
 {"CTS control backpressure", XDEV_EXT_XDP_EV_REPLY_DUE,2,3,0,UP|POSTED|PENDING|XDEV_EXT_XDP_F_CTS_OWED,1000000000,31000000000,0,1,0,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"owed ACK control backpressure", XDEV_EXT_XDP_EV_REPLY_DUE,2,3,0,UP|KNOWN|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,0,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"owed FAIL control backpressure", XDEV_EXT_XDP_EV_REPLY_DUE,2,3,0,UP|KNOWN|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,0,0,-EIO,9,16,16,XDEV_EXT_XDP_ACT_WAIT,1020000000,0,0},
 {"owed ACK room restored", XDEV_EXT_XDP_EV_REPLY_DUE,2,3,0,UP|KNOWN|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_SEND_ACK,0,16,0},
 {"owed FAIL room restored", XDEV_EXT_XDP_EV_REPLY_DUE,2,3,0,UP|KNOWN|XDEV_EXT_XDP_F_CHAIN_DONE|XDEV_EXT_XDP_F_FINAL_OWED,1000000000,31000000000,0,0,1,0,-EIO,9,16,16,XDEV_EXT_XDP_ACT_SEND_FAIL,0,16,-EIO},
 {"announce 15s minus 1ns", XDEV_EXT_XDP_EV_TIMER,1,2,0,UP,15999999999,16000000000,16000000000,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,16000000000,0,0},
 {"policy due before later safety deadline", XDEV_EXT_XDP_EV_TIMER,1,2,0,UP,16000000000,31000000000,16000000000,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WITHDRAW,0,0,0},
 {"announce exact 15s", XDEV_EXT_XDP_EV_TIMER,1,2,0,UP,16000000000,16000000000,16000000000,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WITHDRAW,0,0,0},
 {"withdraw answer 1s minus 1ns", XDEV_EXT_XDP_EV_TIMER,1,2,0,UP|XDEV_EXT_XDP_F_WITHDRAWN,16999999999,17000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,17000000000,0,0},
 {"withdraw answer exact 1s", XDEV_EXT_XDP_EV_TIMER,1,2,0,UP|XDEV_EXT_XDP_F_WITHDRAWN,17000000000,17000000000,0,0,1,-ETIMEDOUT,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ETIMEDOUT},
 {"posted deadline minus 1ns", XDEV_EXT_XDP_EV_TIMER,1,3,0,UP|POSTED|PENDING,30999999999,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_WAIT,31000000000,0,0},
 {"posted deadline exact", XDEV_EXT_XDP_EV_TIMER,1,3,0,UP|POSTED|PENDING,31000000000,31000000000,0,0,1,-ETIMEDOUT,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ETIMEDOUT},
 {"STOP armed", XDEV_EXT_XDP_EV_STOP,2,1,0,UP|XDEV_EXT_XDP_F_STOPPING,1000000000,2000000000,0,0,1,-ECANCELED,0,0,16,16,XDEV_EXT_XDP_ACT_CANCEL_ARMED,0,0,-ECANCELED},
 {"armed deadline exact", XDEV_EXT_XDP_EV_TIMER,2,1,0,UP,2000000000,2000000000,0,0,1,-ETIMEDOUT,0,0,16,16,XDEV_EXT_XDP_ACT_CANCEL_ARMED,0,0,-ETIMEDOUT},
 {"STOP live committed CTS", XDEV_EXT_XDP_EV_CTS,1,2,0,UP|XDEV_EXT_XDP_F_STOPPING|XDEV_EXT_XDP_F_CTS_RECEIVED,1000000000,2000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_TX_POST,0,0,0},
 {"STOP dead committed CTS", XDEV_EXT_XDP_EV_CTS,1,2,0,UP|XDEV_EXT_XDP_F_STOPPING|XDEV_EXT_XDP_F_STAGE_DEAD|XDEV_EXT_XDP_F_CTS_RECEIVED,1000000000,2000000000,0,0,1,-ESHUTDOWN,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ENOLINK},
 {"STOP grace exact", XDEV_EXT_XDP_EV_TIMER,1,3,0,UP|POSTED|PENDING|XDEV_EXT_XDP_F_STOPPING,2000000000,2000000000,0,0,1,-ETIMEDOUT,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ETIMEDOUT},
 {"LINK_DOWN", XDEV_EXT_XDP_EV_LINK_DOWN,1,3,0,POSTED|PENDING,1000000000,31000000000,0,0,1,-ENOLINK,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ENOLINK},
 {"duplicate without obligation", XDEV_EXT_XDP_EV_DUPLICATE,1,0,0,UP,1000000000,0,0,0,1,0,0,0,16,16,XDEV_EXT_XDP_ACT_IGNORE,0,0,0},
 {"duplicate CTS after posted", XDEV_EXT_XDP_EV_DUPLICATE,1,3,0,UP|POSTED|PENDING,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_IGNORE,0,0,0},
 {"duplicate ACK terminal", XDEV_EXT_XDP_EV_DUPLICATE,1,3,XDEV_EXT_NET_REMOTE_ACKED,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,0,0,9,16,16,XDEV_EXT_XDP_ACT_IGNORE,0,0,0},
 /* X6-S1: a local error does not resolve the peer's posted commitment.
  * Publication follows terminal remote facts, retaining the local error. */
 {"TX LOCAL error remote NONE terminates commitment", XDEV_EXT_XDP_EV_LOCAL,1,3,XDEV_EXT_NET_REMOTE_NONE,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ENOLINK},
 {"TX LOCAL error remote HELD terminates commitment", XDEV_EXT_XDP_EV_LOCAL,1,3,XDEV_EXT_NET_REMOTE_HELD,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ENOLINK},
 {"TX READY error remote NONE terminates commitment", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_NONE,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ENOLINK},
 {"TX READY error remote HELD terminates commitment", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_HELD,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_FAIL_LINK,0,0,-ENOLINK},
 {"TX LOCAL error wins after remote LOST", XDEV_EXT_XDP_EV_LOCAL,1,3,XDEV_EXT_NET_REMOTE_LOST,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,-EIO},
 {"TX READY error wins after remote FAILED", XDEV_EXT_XDP_EV_READY,1,3,XDEV_EXT_NET_REMOTE_FAILED,UP|POSTED|KNOWN,1000000000,31000000000,0,0,1,-EIO,0,9,16,16,XDEV_EXT_XDP_ACT_PUBLISH,0,0,-EIO},
};
static unsigned tap;
static void ok(const char *name) { printf("ok %u - %s\n", ++tap, name); }
static void reset_calls(void)
{
 info_calls=verdict_calls=generic_calls=cqe_calls=0;
 info_error=verdict_error=0;
 memset(&recorded, 0, sizeof(recorded));
}
static struct xdev_ext_mech_ctx protocol_ctx(void)
{
 struct xdev_ext_mech_ctx c={0};
 c.class_id=XDEV_EXT_MECH_CLASS_XDOMAIN;
 c.member=XDEV_EXT_MECH_MEMBER_COMPLETE;
 c.callsite=XDEV_EXT_MECH_SITE_WORKER_PROTOCOL;
 c.session_id=37;
 return c;
}
static void matrix(void)
{
 for (size_t n=0; n<sizeof(cases)/sizeof(cases[0]); n++) {
  const struct policy_case *p=&cases[n];
  struct xdev_ext_xdomain_proto_verdict got, expected={0};
  struct xdev_ext_mech_ctx ctx=protocol_ctx();
  memset(&snapshot,0,sizeof(snapshot));
  snapshot.size=256; snapshot.version=1; snapshot.event=p->event;
  snapshot.direction=p->direction; snapshot.event_id=101; snapshot.epoch=203;
  snapshot.pool_generation=7; snapshot.local_inc=11; snapshot.remote_inc=13;
  snapshot.stream=17; snapshot.group=p->group; snapshot.now_ns=p->now;
  snapshot.hard_deadline_ns=p->hard; snapshot.policy_deadline_ns=p->policy;
  snapshot.base_group=9; snapshot.next_group=9; snapshot.credit=p->credit;
  snapshot.msg_credit=p->msg_credit; snapshot.data_seq=5; snapshot.expected_seq=5;
  snapshot.state=p->state; snapshot.remote=p->remote; snapshot.facts=p->facts;
  snapshot.total_len=131072; snapshot.count=32; snapshot.want_len=131072;
  snapshot.want_count=32; snapshot.posted_groups=p->posted_groups;
  snapshot.local_status=p->local_status; snapshot.chain_status=p->chain_status;
  snapshot.ctl_room=p->ctl_room;
  expected.size=64; expected.version=1; expected.event_id=101; expected.epoch=203;
  expected.action=p->expected_action; expected.wake_ns=p->expected_wake;
  expected.credit=p->expected_credit; expected.status=p->expected_status;
  struct xdev_ext_xdomain_proto_info before=snapshot;
  memset(&got,0xa5,sizeof(got)); /* choose must initialize every verdict byte */
  int rc=xdomain_peer_choose(&snapshot,&got);
  if (rc || memcmp(&got,&expected,64)) {
   fprintf(stderr,"row %s: ret=%d action=%u/%u wake=%llu/%llu credit=%llu/%llu status=%d/%d\n",
    p->name,rc,got.action,expected.action,(unsigned long long)got.wake_ns,
    (unsigned long long)expected.wake_ns,(unsigned long long)got.credit,
    (unsigned long long)expected.credit,got.status,expected.status);
   assert(0);
  }
  assert(!memcmp(&snapshot,&before,sizeof(snapshot)));
  reset_calls();
  assert(xdomain_peer_complete(NULL,&ctx)==0);
  assert(info_calls==1 && verdict_calls==1 && !generic_calls && !cqe_calls);
  assert(!memcmp(&recorded,&expected,64));
  assert(!memcmp(&snapshot,&before,sizeof(snapshot)));
  ok(p->name);
 }
}
static void error_paths(void)
{
 struct xdev_ext_mech_ctx ctx=protocol_ctx();
 memset(&snapshot,0,sizeof(snapshot));
 snapshot.size=256; snapshot.version=1; snapshot.event_id=101; snapshot.epoch=203;
 snapshot.pool_generation=7; snapshot.local_inc=11; snapshot.remote_inc=13;
 snapshot.stream=17; snapshot.now_ns=1000000000; snapshot.credit=16;
 snapshot.ctl_room=1;
 snapshot.event=XDEV_EXT_XDP_EV_RX_SUBMIT; snapshot.direction=2;
 snapshot.state=0; snapshot.group=0; snapshot.facts=UP;
 reset_calls(); info_error=-EIO;
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
 assert(info_calls==1 && !verdict_calls && !generic_calls && !cqe_calls);
 reset_calls(); verdict_error=-EIO;
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
 assert(info_calls==1 && verdict_calls==1 && all_zero(&recorded,64));
 assert(!generic_calls && !cqe_calls);
 ok("private copy/verdict failures abort without a final CQE or retry intent");
 const unsigned bad_events[]={0,18,0xffffffffU};
 for (size_t n=0;n<sizeof(bad_events)/sizeof(bad_events[0]);n++) {
  snapshot.event=bad_events[n]; reset_calls();
  assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
  assert(info_calls==1 && !verdict_calls && !generic_calls && !cqe_calls);
 }
 snapshot.event=XDEV_EXT_XDP_EV_RX_SUBMIT;
 const unsigned bad_sizes[]={0,255,257};
 for(size_t n=0;n<sizeof(bad_sizes)/sizeof(bad_sizes[0]);n++) {
  snapshot.size=bad_sizes[n]; reset_calls();
  assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
  assert(info_calls==1 && !verdict_calls && !generic_calls && !cqe_calls);
 }
 snapshot.size=256; snapshot.version=2; reset_calls();
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT && !verdict_calls);
 ok("unknown event and invalid info shape record no intent");
}
static void build_tests(void)
{
 struct xdev_ext_mech_ctx ctx={0};
 const unsigned char key[8]={1,2,3,4,5,6,7,8};
 ctx.base.src_offset=0x0102030405060708ULL;
 ctx.base.direction=1; ctx.base.length=131072; ctx.nr_frames=2; ctx.desc_cap=2;
 memset(&build_info,0,sizeof(build_info)); memset(descriptors,0,sizeof(descriptors));
 build_info.direction=1; build_info.nr_frames=2; build_info.next_group=39;
 build_info.f[0].data_len=65536; build_info.f[1].data_off=4096;
 build_info.f[1].data_len=65536;
 assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 struct xdev_ext_xdomain_desc expected[2]={0};
 expected[0].len=65536; expected[0].group=39; memcpy(expected[0].tag,key,8);
 expected[1].frame_pos=1; expected[1].frame_off=4096; expected[1].len=65536;
 assert(!memcmp(descriptors,expected,sizeof(expected)));
 assert(all_zero(&descriptors[2],sizeof(descriptors)-sizeof(expected)));
 ok("TX two 65536-byte spans, exact group, big-endian key, zero unused fields");
 memset(descriptors,0,sizeof(descriptors)); build_info.direction=2;
 ctx.base.direction=2;
 expected[0].group=0; memset(expected[0].tag,0,sizeof(expected[0].tag));
 assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 assert(!memcmp(descriptors,expected,sizeof(expected)));
 ok("RX plans have zero group and opaque tag");
 memset(descriptors,0,sizeof(descriptors));
 build_info.nr_frames=XDEV_EXT_MECH_MAX_FRAMES; ctx.desc_cap=XDEV_EXT_MECH_MAX_FRAMES;
 for(unsigned i=0;i<XDEV_EXT_MECH_MAX_FRAMES;i++) {
  build_info.f[i].data_off=0; build_info.f[i].data_len=4096;
 }
 assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_SUBMIT);
 for(unsigned i=0;i<XDEV_EXT_MECH_MAX_FRAMES;i++) {
  struct xdev_ext_xdomain_desc d={.frame_pos=i,.len=4096};
  assert(!memcmp(&descriptors[i],&d,sizeof(d)));
 }
 ok("maximum allowed number of RX spans remains representable");
 build_info.nr_frames=2; build_info.f[0].data_len=65536;
 build_info.f[1].data_off=4096; build_info.f[1].data_len=65536;
 no_build_info=1; assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT); no_build_info=0;
 no_desc_at=1; assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT); no_desc_at=-1;
 build_info.f[1].data_off=4097;
 assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT); build_info.f[1].data_off=4096;
 build_info.f[1].data_len=0;
 assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT); build_info.f[1].data_len=65536;
 build_info.nr_frames=0; assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT);
 build_info.nr_frames=XDEV_EXT_MECH_MAX_FRAMES+1;
 assert(xdomain_peer_build(NULL,&ctx)==XDEV_EXT_MP_BUILD_ABORT);
 ok("unavailable metadata/descriptor, misalignment, zero span and invalid frame count abort");
}
static void completion_tests(void)
{
 struct xdev_ext_mech_ctx ctx={0};
 ctx.callsite=XDEV_EXT_MECH_SITE_WORKER; ctx.base.direction=1; ctx.base.length=131072;
 memset(&final_cqe,0,sizeof(final_cqe));
 final_cqe.bytes=131072; final_cqe.remote=XDEV_EXT_NET_REMOTE_ACKED;
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_NEXT);
 for(unsigned remote=0;remote<=4;remote++) {
  final_cqe.remote=remote;
  assert(xdomain_peer_complete(NULL,&ctx)==(remote==2 ? XDEV_EXT_MP_NEXT : XDEV_EXT_MP_ABORT));
 }
 final_cqe.remote=XDEV_EXT_NET_REMOTE_ACKED;
 final_cqe.status=-EIO; assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT); final_cqe.status=0;
 final_cqe.status=1; assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT); final_cqe.status=0;
 for(unsigned outcome=1;outcome<=4;outcome++) {
  final_cqe.outcome=outcome; assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
 }
 final_cqe.outcome=0; final_cqe.bytes=131071;
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
 final_cqe.bytes=131073; assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
 final_cqe.bytes=131072; no_cqe=1;
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT); no_cqe=0;
 ctx.base.direction=2; final_cqe.remote=0;
 assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_NEXT);
 for(unsigned site=1;site<=6;site++) {
  ctx.callsite=site; reset_calls();
  assert(xdomain_peer_complete(NULL,&ctx)==XDEV_EXT_MP_ABORT);
  assert(!info_calls && !verdict_calls && !cqe_calls);
 }
 ok("only full successful WORKER CQE advances; TX additionally requires remote ACKED");
}
int main(void)
{
 puts("TAP version 13");
 build_tests(); completion_tests(); matrix(); error_paths();
 printf("1..%u\n",tap);
 return 0;
}
