// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmlinux.h"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
static unsigned crc_calls, hold_calls;
static struct { __u64 key; __u32 pos, off, len; } hold;
static struct { struct xdev_ext_mech_ctx ctx; const void *info; size_t info_size; __u8 *frames[32];
 __u32 frame_size; struct xdp_desc *desc; __u32 desc_cap; const void *cqe; size_t cqe_size; } M;
static __u32 sw_crc32c(__u32 crc, const void *buf, size_t len)
{
 const __u8 *p = buf; int k;
 while (len--) { crc ^= *p++; for (k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1))); }
 return crc;
}
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, const size_t n)
{ (void)c; return n == M.info_size ? (__u8 *)M.info : NULL; }
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{ (void)c; return n == sizeof(struct xdp_desc) && slot < M.desc_cap ? (__u8 *)&M.desc[slot] : NULL; }
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{ (void)c; return !slot && n == M.cqe_size ? (__u8 *)M.cqe : NULL; }
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{ (void)c; return pos < 32 && M.frames[pos] && off + n <= M.frame_size ? M.frames[pos] + off : NULL; }
__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, __u32 len, __u32 seed)
{ (void)c; crc_calls++; return sw_crc32c(seed, M.frames[pos] + off, len); }
__u32 bpf_xdev_ext_crc32c(const void *buf, __u32 n, __u32 seed) { crc_calls++; return sw_crc32c(seed, buf, n); }
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *c, const size_t n) { (void)c; (void)n; return NULL; }
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{ (void)c; return pos < 32 && M.frames[pos] && off + n <= M.frame_size ? M.frames[pos] + off : NULL; }
int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *c, __u64 key, __u32 pos, __u32 off, __u32 len)
{ (void)c; hold_calls++; hold.key = key; hold.pos = pos; hold.off = off; hold.len = len; return 0; }

/* These mocks record the new authority boundary. Returning -ERANGE is a
 * provider refusal, not a reference implementation of protocol rules. */
static unsigned view_calls, data_calls, control_calls;
int bpf_xdev_ext_rel_rx_view(const struct xdev_ext_mech_ctx *c, __u64 g, void *v, __u32 n)
{ (void)c; (void)g; (void)v; (void)n; view_calls++; return -ERANGE; }
int bpf_xdev_ext_rel_rx_data(const struct xdev_ext_mech_ctx *c, __u64 g, __u32 i, __u32 a, __u32 v)
{ (void)c; (void)g; (void)i; (void)a; (void)v; data_calls++; return -ERANGE; }
int bpf_xdev_ext_rel_rx_control(const struct xdev_ext_mech_ctx *c, __u64 g, __u32 a, __u64 cr, __u32 t)
{ (void)c; (void)g; (void)a; (void)cr; (void)t; control_calls++; return -ERANGE; }
int bpf_xdev_ext_rel_policy(const struct xdev_ext_mech_ctx *c, void *p, __u32 n)
{ (void)c; (void)p; (void)n; return -ERANGE; }
__u8 *bpf_xdev_ext_rel_tx_view(const struct xdev_ext_mech_ctx *c,const size_t n)
{ (void)c; (void)n; return NULL; }
#include PROGRAM
static unsigned checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); } } while (0)
int main(int argc, char **argv)
{
 __u8 chunk[4096] = {0};
 struct xdev_ext_afxdp_reliable_info info = {0};
 struct xdev_ext_rel_msg m = {.session=9, .group=1, .attempt=1};
 __u32 crc;
 int rc;
 if (argc != 2) return 2;
 info.base.l = (struct xdev_ext_mech_layout){.frame_size=4096, .hdr_room=384, .seg_len=512, .group_bytes=1024};
 info.base.nr_frames=1; info.wire_session=9;
 if (!strcmp(argv[1], "control")) {
  m.type=XDEV_EXT_REL_ACK; m.credit=5;
 } else {
  m.type=XDEV_EXT_REL_DATA; m.total_len=1024; m.count=2; m.payload_len=512;
 }
 EXPECT(!xdev_ext_rel_wire_encode(chunk+42, &m));
 crc=sw_crc32c(sw_crc32c(~0U,chunk+42,64),chunk+106,m.payload_len);
 xdev_ext_rel_put(chunk+98,crc^~0U,4);
 info.base.f[0]=(struct xdev_ext_mech_frame_info){.data_off=0,.data_len=106+m.payload_len};
 M.info=&info; M.info_size=sizeof(info); M.frame_size=4096; M.frames[0]=chunk;
 M.ctx.member=XDEV_EXT_MECH_MEMBER_COMPLETE; M.ctx.callsite=XDEV_EXT_MECH_SITE_RX_NATIVE;
 M.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP; M.ctx.nr_frames=1;
 rc=rel_afxdp_complete(NULL,&M.ctx);
 EXPECT(rc==XDEV_EXT_MP_RECYCLE);
 EXPECT(hold_calls==0);
 if (m.type==XDEV_EXT_REL_ACK) { EXPECT(control_calls==1); EXPECT(view_calls==0); }
 else { EXPECT(view_calls==1); EXPECT(control_calls==0); }
 EXPECT(data_calls==0); EXPECT(crc_calls==0);
 printf("production BPF %s: %u checks, %u failures\n",argv[1],checks,failures);
 return failures != 0;
}
