/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement: explicit configure_receive validates caller options and is
 * accepted only on an XSK pool before CREATE. Interface transcribed frozen v1. */
#define SHARED_RECEIVE_FIXTURE_ONLY
#include "session_rings.c"
#include <linux/if_link.h>
struct contract_receive_opts {
 size_t sz;__u32 xdp_flags,dst_ipv4,payload_magic;__u16 dst_port,reserved;__u32 flags;
};
struct contract_network_error {int error;char operation[32],reason[160];};
extern int configure(struct xdev_ext_session *,const struct contract_receive_opts *,struct contract_network_error *)
 __asm__("xdev_ext_session_configure_receive");
static void rejected(struct xdev_ext_session *s,const struct contract_receive_opts *o,int want,const char *name)
{
 struct contract_network_error e={0};int ret=configure(s,o,&e);
 if(ret!=want)printf("ret=%d want=%d operation=%s reason=%s\n",ret,want,e.operation,e.reason);
 check(ret==want,name);check(e.error==ret,"configure failure diagnostic agrees with returned error");
 check(rings_untouched(),"invalid receive options do not seed or consume any ring");
}
int main(void)
{
 const struct xdev_ext_sys sys={.io_uring_setup=setup,.io_uring_register=reg};
 struct xdev_ext_pool_opts p=XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
  .pool_kind=XDEV_EXT_MECH_POOL_XSK,.xsk_mode=XDEV_EXT_XSK_COPY,.ifname="fixture0",.queue=3,.nr_frames=8);
 const struct contract_receive_opts valid={.sz=sizeof(valid),.xdp_flags=XDP_FLAGS_DRV_MODE,
  .dst_ipv4=0xc6336402,.payload_magic=0x11223344,.dst_port=9000};
 struct contract_receive_opts o;struct xdev_ext_session *s=NULL;int ret;
 struct {struct contract_receive_opts opts;unsigned char tail[8];} extended;
 struct xdev_ext_create_opts create=XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
  .group_bytes=1024,.depth=1,.mtu=1500,.nr_stages=1,.peer={.local_mac={2,0,0,0,0,1}},
  .st={{.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=-1}});
 xdev_ext__set_sys(&sys);
 rejected(NULL,&valid,-EINVAL,"NULL session is rejected");
 ret=xdev_ext_session_open(&p,&s);check(ret==0 && s,"XSK session opens for receive-option checks");if(ret)return 2;
 rejected(s,NULL,-EINVAL,"NULL receive options are rejected");
 o=valid;o.sz=sizeof(o)-1;rejected(s,&o,-EINVAL,"truncated receive options are rejected");
 extended.opts=valid;memset(extended.tail,0,sizeof(extended.tail));extended.opts.sz=sizeof(extended);extended.tail[7]=1;
 rejected(s,&extended.opts,-EOPNOTSUPP,"unknown nonzero future receive option tail is rejected");
 o=valid;o.flags=1;rejected(s,&o,-EOPNOTSUPP,"unknown receive flags are rejected");
 o=valid;o.reserved=1;rejected(s,&o,-EINVAL,"reserved receive field must be zero");
 o=valid;o.dst_port=0;rejected(s,&o,-EINVAL,"receive destination port must be nonzero");
 o=valid;o.xdp_flags=0;rejected(s,&o,-EINVAL,"receive mode cannot be unspecified");
 o=valid;o.xdp_flags=XDP_FLAGS_DRV_MODE|XDP_FLAGS_SKB_MODE;rejected(s,&o,-EINVAL,"receive cannot request two XDP modes");
 allow_create=1;ret=xdev_ext_session_create(s,&create);check(ret==0,"real library CREATE state is established through kernel boundary fixture");
 if(!ret) {
  struct contract_network_error e={0};ret=configure(s,&valid,&e);
  check(ret<0 && e.error==ret,"configure receive is refused after successful CREATE");
 }
 check(xdev_ext_session_close(s)==0,"invalid or late configure preserves normal close");
 check(active_maps()==0,"option and ordering failures release all ring backing on close");
 nr_maps=ring_options=close_count=0;p.pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM;p.ifname=NULL;s=NULL;
 ret=xdev_ext_session_open(&p,&s);check(ret==0 && s,"IOU UMEM pool opens for unsupported-pool check");
 if(!ret){rejected(s,&valid,-EOPNOTSUPP,"automatic AF_XDP receive is unavailable for IOU UMEM");check(xdev_ext_session_close(s)==0,"unsupported pool rejection preserves pool close");}
 check(!has_map(XDP_PGOFF_RX_RING,128+2048*sizeof(struct xdp_desc)),"IOU pool never constructs AF_XDP ring backing");
 printf("RESULT failures=%d\n",failures);return failures?1:0;
}
