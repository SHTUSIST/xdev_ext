/* SPDX-License-Identifier: GPL-2.0 */
/* Frozen contract scenarios; public API only. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "libxdev_ext.h"
#include "library_integration_boundary.h"
#include "ownership_boundary.h"

struct receive_contract {size_t sz;__u32 xdp_flags,dst_ipv4,payload_magic;__u16 dst_port,reserved;__u32 flags;};
struct network_contract_error {int error;char operation[32],reason[160];};
extern int configure_receive(struct xdev_ext_session *,const struct receive_contract *,struct network_contract_error *)
 __asm__("xdev_ext_session_configure_receive");
static int failures;
static const struct receive_contract receive={.sz=sizeof(receive),.xdp_flags=XDP_FLAGS_DRV_MODE,
 .dst_ipv4=0xc6336402,.payload_magic=0x11223344,.dst_port=9000};
static void check(int ok,const char *name)
{printf("%s - %s\n",ok?"ok":"not ok",name);fflush(stdout);failures+=!ok;}
static int configure(struct xdev_ext_session *session)
{
 struct network_contract_error error={0};int ret=configure_receive(session,&receive,&error);
 printf("configure ret=%d operation=%s reason=%s\n",ret,error.operation,error.reason);return ret;
}
static int open_xsk(struct xdev_ext_session **out)
{
 struct xdev_ext_pool_opts pool=XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
  .pool_kind=XDEV_EXT_MECH_POOL_XSK,.xsk_mode=XDEV_EXT_XSK_COPY,.ifname="fixture0",.queue=3,.nr_frames=8);
 int ret=xdev_ext_session_open(&pool,out);
 check(ret==0 && *out,"COPY XSK pool opens through OS boundary");
 if(ret || !*out)return -1;
 check(!xdev_ext_session_zero_copy(*out),"pool retains requested COPY mode");
 check(library_fixture_rings_unseeded(),"open leaves RX/FILL/CQ/TX ownership untouched");
 library_fixture_payload_prepare();return 0;
}
static void assert_empty(void)
{
 struct library_observation o=library_fixture_observe();
 check(fixture_rule_count()==0 && fixture_current_xdp()==0 && fixture_pin_count()==0,"final close releases its rule, attachment and pins");
 check(o.xsk_closes==1 && o.umem_unmaps==1 && o.active_maps==0 && o.live_xsk_aliases==0,"final close releases socket, all ring backing and UMEM exactly once");
 check(o.early_network_cleanup==0 && o.early_backing_release==0,"network cleanup follows kernel release and backing follows network cleanup");
 check(o.custody_violations==0 && library_fixture_payload_unchanged(),"library never changes payload or kernel/device-owned ring data");
 check(fixture_unconditional_detach==0,"library cleanup avoids unconditional XDP detach");
}
static void success_duplicate(void)
{
 struct xdev_ext_session *s=NULL;struct ethtool_rx_flow_spec before,after;uint32_t program;int ret;
 if(open_xsk(&s))return;
 ret=configure(s);check(ret==0,"explicit library configure_receive succeeds for an open XSK pool");if(ret)return;
 program=fixture_current_xdp();
 check(program && fixture_rule_count()==1 && fixture_pin_count()>0,"successful configure owns dispatcher and one hardware tuple");
 check(library_fixture_rings_unseeded() && library_fixture_payload_unchanged(),"configure does not seed frames or process payload");
 check(fixture_get_rule(0,&before)==0,"configured hardware rule is observable");
 check(configure(s)==-EALREADY,"second configure returns -EALREADY");
 check(fixture_rule_count()==1 && fixture_current_xdp()==program && fixture_get_rule(0,&after)==0 && !memcmp(&before,&after,sizeof(before)),"duplicate configure preserves original flow and dispatcher");
 check(library_fixture_rings_unseeded() && library_fixture_payload_unchanged(),"duplicate configure preserves custody and payload");
 check(xdev_ext_session_close(s)==0,"configured session closes before CREATE");assert_empty();
}
static void peer_rejection(void)
{
 struct xdev_ext_session *s=NULL;int authority=open("/dev/null",O_RDWR|O_CLOEXEC),ret;
 struct xdev_ext_peer_pool_opts pool=XDEV_EXT_OPTS_INIT(xdev_ext_peer_pool_opts,.allocation_fd=authority);
 check(authority>=0,"valid allocation authority exists at FD boundary");if(authority<0)return;
 ret=xdev_ext_session_open_peer(&pool,&s);check(ret==0 && s,"PEER pool handle opens through public API");
 if(!ret && s) {
  check(configure(s)==-EOPNOTSUPP,"PEER pool rejects automatic AF_XDP receive");
  check(fixture_rule_count()==0 && fixture_current_xdp()==0 && fixture_pin_count()==0,"PEER rejection creates no network ownership");
  check(xdev_ext_session_close(s)==0,"PEER pool remains closable after rejection");
  check(fcntl(authority,F_GETFD)>=0,"PEER close preserves caller's original allocation authority");
 }
 close(authority);
}
static void retained_copy(void)
{
 struct xdev_ext_session *s=NULL;struct library_observation o,before,after;int ret,xsk;uint32_t program;unsigned int backing_count;
 struct xdev_ext_create_opts create=XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
  .group_bytes=1024,.depth=1,.mtu=1500,.nr_stages=1,.peer={.local_mac={2,0,0,0,0,1}},
  .st={{.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE}});
 struct xdev_ext_start_opts start=XDEV_EXT_OPTS_INIT(xdev_ext_start_opts,.nr_batches=1,.first_seq=1);
 if(open_xsk(&s))return;
 backing_count=library_fixture_observe().active_maps;
 xsk=xdev_ext_session_xsk_fd(s);ret=configure(s);check(ret==0,"COPY source configures receive");if(ret)return;
 program=fixture_current_xdp();create.st[0].fd=xsk;
 check(library_fixture_rings_unseeded(),"configure leaves fill provisioning until START");
 ret=xdev_ext_session_create(s,&create);check(ret==0,"configured COPY source CREATE succeeds");if(ret)return;
 check(library_fixture_rings_unseeded() && library_fixture_payload_unchanged(),"CREATE preserves ring custody and payload");
 ret=xdev_ext_session_start(s,&start);check(ret==0,"configured COPY receive source starts");if(ret)return;
 o=library_fixture_observe();
 check(o.start_requests==1 && o.start_saw_valid_fill==1,"COPY source seeds valid FILL frames before kernel START delivery");
 check(library_fixture_fill_valid() && library_fixture_nonfill_untouched() && library_fixture_payload_unchanged(),"START writes only valid FILL ownership metadata");
 library_fixture_stop_retains();ret=xdev_ext_session_close(s);
 check(ret==-EBUSY && xdev_ext_session_retained(s),"STOP retention makes close return -EBUSY and retain the session");
 o=library_fixture_observe();
 check(o.xsk_closes==0 && o.umem_unmaps==0 && o.active_maps==backing_count && xdev_ext_session_xsk_fd(s)==xsk,"kernel-retained STOP preserves XSK and all registered backing");
 check(o.delete_attempts==0 && fixture_rule_count()==1 && fixture_current_xdp()==program,"kernel-retained STOP preserves network ownership");
 library_fixture_release_available();library_fixture_fail_next_rule_delete();ret=xdev_ext_session_close(s);
 check(ret==-EIO,"network cleanup failure reaches session close as -EIO");
 o=library_fixture_observe();
 check(o.kernel_release_observed && o.delete_attempts==1 && o.early_network_cleanup==0,"network delete is attempted only after observed kernel release");
 check(o.xsk_closes==0 && o.umem_unmaps==0 && o.active_maps==backing_count && fixture_rule_count()==1,"failed network close retains XSK, UMEM, ring maps and hardware rule");
 check(xdev_ext_session_retained(s),"failed network cleanup marks session retained and close-only");
 before=o;
 check(xdev_ext_session_create(s,&create)<0,"retained network cleanup forbids CREATE");
 check(xdev_ext_session_start(s,&start)<0,"retained network cleanup forbids START");
 check(configure(s)<0,"retained network cleanup forbids configure");
 after=library_fixture_observe();
 check(after.create_requests==before.create_requests && after.start_requests==before.start_requests && after.delete_attempts==before.delete_attempts && fixture_rule_count()==1 && fixture_current_xdp()==program,"close-only API rejections cause no new kernel or hardware mutation");
 check(library_fixture_fill_valid() && library_fixture_nonfill_untouched() && library_fixture_payload_unchanged(),"close-only calls preserve ring custody and payload");
 check(xdev_ext_session_close(s)==0,"retained network close succeeds on retry");assert_empty();
}
int main(int argc,char **argv)
{
 if(argc!=3)return 2;
 library_fixture_init(argv[1]);
 if(!strcmp(argv[2],"success"))success_duplicate();
 else if(!strcmp(argv[2],"peer"))peer_rejection();
 else if(!strcmp(argv[2],"retained-copy"))retained_copy();
 else return 2;
 printf("RESULT failures=%d\n",failures);return failures?1:0;
}
