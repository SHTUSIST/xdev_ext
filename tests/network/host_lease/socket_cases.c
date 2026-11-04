#include "host_shim.h"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_batch batches[3];
static struct xdev_ext_mech_stage stage;
static struct sock sk;
static struct socket sock;
static struct file file;
static u8 buffers[3][128], states[3];
static struct xdev_ext_socket_send_desc desc[2];
static void saved_ready(struct sock *s) {CHECK(false);}
static void setup(bool rx,bool nxp) {
 CHECK(allocations==0&&cred_refs==0);
 alloc_calls=alloc_fail=0;kicks=completions=claims=peer_calls=requester_calls=family_calls=0;
 sends=recv_calls=packet_calls=send_results=recv_results=element_callbacks=0;stop_after_send=false;stop_session=&session;
 memset(&session,0,sizeof(session));memset(batches,0,sizeof(batches));
 memset(&sk,0,sizeof(sk));memset(&stage,0,sizeof(stage));
 sk.sk_family=AF_INET;sk.sk_protocol=IPPROTO_UDP;sk.sk_state=TCP_ESTABLISHED;sk.sk_data_ready=saved_ready;
 sock=(struct socket){&sk,SOCK_DGRAM};file.socket=&sock;file.refs=1;
 session.depth=2;session.admits=true;session.batches=batches;
 session.layout.seg_len=8;session.pool.frame_size=128;session.pool.nr_frames=3;session.pool.state=states;
 stage.s=&session;stage.file=&file;stage.direction=rx?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE;
 for(u32 j=0;j<3;j++) {
  batches[j].s=&session;batches[j].id=70+j;batches[j].key=90+j;batches[j].nr_frames=2;batches[j].bytes=16;
  xdev_ext_mech_completion_init(&batches[j].completion);
  CHECK(xdev_ext_mech_completion_begin(&batches[j].completion,&batches[j].ticket)==0);
  for(u32 i=0;i<2;i++) batches[j].f[i]=(struct xdev_ext_mech_frame){.kaddr=buffers[i],.umem_addr=i*128,.index=i,.data_off=3+i,.data_len=8};
 }
 states[0]=states[1]=XDEV_EXT_MECH_F_INFLIGHT;
 desc[0]=(struct xdev_ext_socket_send_desc){0,3,8,0};desc[1]=(struct xdev_ext_socket_send_desc){1,4,8,0};
 struct xdev_ext_mech_stage_uapi u={};if(nxp){u.flags=XDEV_EXT_SOCKET_F_NXP;u.arg0=14;u.arg1=1500;}
 CHECK(xdev_ext_socket_class_bind(&stage,&u)==0);
 CHECK(xdev_ext_socket_validate(&stage,&batches[0],(u8 *)desc,2)==0);
}
static void teardown(void) {
 xdev_ext_socket_class_unbind(&stage);CHECK(stage.priv==NULL);CHECK(allocations==0&&cred_refs==0&&file.refs==1);CHECK(current_cred==&worker_cred);CHECK(peer_calls==0&&requester_calls==0);CHECK(callback_locks==0);
 if(stage.direction==XDEV_EXT_MECH_DIR_FROM_DEVICE)CHECK(family_calls==0);
}
static void plain_case(int native,int want_ret,int want_status,u32 want_bytes,u32 want_ops) {
 setup(false,false);send_results=1;send_result[0]=native;
 CHECK(xdev_ext_socket_class_submit(&stage,&batches[0])==want_ret);
 CHECK(sends==1&&send_indices[0]==2);CHECK(send_ptr[0][0]==buffers[0]+3&&send_ptr[0][1]==buffers[1]+4);
 CHECK(send_len[0][0]==8&&send_len[0][1]==8);
 CHECK(completions==(want_ret?0:1));
 CHECK(element_callbacks==(HOST_AVAILABLE&&!want_ret?2:0));
 struct xdev_ext_socket_mech_cqe c={};xdev_ext_socket_class_fill_cqe(&stage,&batches[0],&c);
 if(!want_ret){CHECK(c.status==want_status&&c.bytes_sent==want_bytes&&c.bytes_received==0&&c.flags==0);}
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==want_ops);CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==(want_ops?16:0));
 CHECK(xdev_ext_socket_progress(&stage)==0);
 printf("plain native=%d ret=%d status=%d bytes=%u ops=%llu callbacks=%d\n",native,want_ret,want_status,want_bytes,(unsigned long long)session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS],completions);teardown();
}
static void preflight(void) {
 setup(false,false);struct xdev_ext_socket_stage *ss=stage.priv;int before=family_calls;
 ss->dead=true;session.admits=false;CHECK(xdev_ext_socket_submit(&stage,&batches[2])==-ENODEV);
 ss->dead=false;CHECK(xdev_ext_socket_submit(&stage,&batches[2])==-ESHUTDOWN);
 session.admits=true;CHECK(xdev_ext_socket_submit(&stage,&batches[2])==-EINVAL);
 sk.sk_shutdown=SEND_SHUTDOWN;states[0]=XDEV_EXT_MECH_F_HELD;CHECK(xdev_ext_socket_submit(&stage,&batches[0])==-ESHUTDOWN);
 sk.sk_shutdown=0;CHECK(xdev_ext_socket_submit(&stage,&batches[0])==-EBUSY);
 CHECK(!sends&&!completions&&family_calls==before);puts("preflight dead/admission/slot/ready/frame preserved");teardown();
}
static void validation(void) {
 setup(false,false);struct xdev_ext_mech_batch *b=&batches[0];
 b->bytes=0;desc[0].flags=1;CHECK(xdev_ext_socket_validate(&stage,b,(u8 *)desc,0)==-EMSGSIZE);
 b->bytes=16;CHECK(xdev_ext_socket_validate(&stage,b,(u8 *)desc,2)==-EINVAL);
 desc[0].flags=0;desc[0].frame_off=4;CHECK(xdev_ext_socket_validate(&stage,b,(u8 *)desc,2)==-EINVAL);
 desc[0].frame_off=3;b->f[0].kaddr=NULL;CHECK(xdev_ext_socket_validate(&stage,b,(u8 *)desc,2)==-EINVAL);
 b->f[0].kaddr=buffers[0];b->f[0].index=3;CHECK(xdev_ext_socket_validate(&stage,b,(u8 *)desc,2)==-EINVAL);
 b->f[0].index=0;b->bytes=15;CHECK(xdev_ext_socket_validate(&stage,b,(u8 *)desc,2)==-EINVAL);
 CHECK(!sends&&!completions);puts("validate bytes/flags/cover/kaddr/index/total preserved");teardown();
}
static void nxp_retry(void) {
 setup(false,true);send_results=3;send_result[0]=48;send_result[1]=-EAGAIN;send_result[2]=48;
 CHECK(xdev_ext_socket_submit(&stage,&batches[0])==-EAGAIN);
 CHECK(element_callbacks==0);
 struct xdev_ext_socket_stage *ss=stage.priv;CHECK(ss->request[0].cursor==1&&completions==0);
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==1&&session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==8);
 CHECK(xdev_ext_socket_validate(&stage,&batches[0],(u8 *)desc,2)==0);CHECK(ss->request[0].cursor==1);
 CHECK(xdev_ext_socket_submit(&stage,&batches[0])==0);CHECK(completions==1&&batches[0].status==0&&ss->request[0].cursor==2);
 CHECK(sends==3&&packet_calls==3);CHECK(send_ptr[0][1]==buffers[0]+3&&send_ptr[1][1]==buffers[1]+4&&send_ptr[2][1]==buffers[1]+4);
 CHECK(element_callbacks==(HOST_AVAILABLE?2:0));
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==2&&session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==16);
 puts("nxp prefix-EAGAIN retry cursor=2 sends=3 ops=2 bytes=16 callbacks=1");teardown();
}
static void nxp_failure(int second,int want) {
 setup(false,true);send_results=2;send_result[0]=48;send_result[1]=second;
 CHECK(xdev_ext_socket_submit(&stage,&batches[0])==0);CHECK(batches[0].status==want&&completions==1);
 CHECK(((struct xdev_ext_socket_stage *)stage.priv)->request[0].cursor==1);
 struct xdev_ext_socket_mech_cqe c={};xdev_ext_socket_fill_cqe(&stage,&batches[0],&c);CHECK(c.status==want&&c.bytes_sent==0);
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==1&&session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==8);
 printf("nxp terminal native=%d status=%d cursor=1 ops=1 bytes_sent=0\n",second,want);teardown();
}
static void bind_failures(void) {
 setup(false,false);int total=alloc_calls;teardown();
 for(int n=1;n<=total;n++) {
  setup(false,false);teardown();alloc_calls=0;alloc_fail=n;
  struct xdev_ext_mech_stage_uapi u={};CHECK(xdev_ext_socket_class_bind(&stage,&u)==-ENOMEM);
  CHECK(stage.priv==NULL&&allocations==0&&cred_refs==0&&file.refs==1);
 }
 puts("bind all allocation failure points no publication/leak");
 setup(true,false);total=alloc_calls;teardown();
 for(int n=1;n<=total;n++) {
  alloc_calls=0;alloc_fail=n;struct xdev_ext_mech_stage_uapi u={};
  CHECK(xdev_ext_socket_class_bind(&stage,&u)==-ENOMEM);
  CHECK(stage.priv==NULL&&allocations==0&&cred_refs==0&&sk.sk_user_data==NULL&&sk.sk_data_ready==saved_ready);
  CHECK(family_calls==0&&callback_locks==0);
 }
 puts("RX bind all allocation failure points no callback publication/leak");
}
static void stop_cases(void) {
 setup(false,true);stop_after_send=true;
 CHECK(xdev_ext_socket_submit(&stage,&batches[0])==0);
 CHECK(sends==1&&completions==1&&batches[0].status==-ESHUTDOWN);
 CHECK(((struct xdev_ext_socket_stage *)stage.priv)->request[0].cursor==1);
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==1&&session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==8);
 teardown();puts("nxp STOP after prefix status=-108 sends=1 cursor=1 counts=1/8");
 setup(true,false);CHECK(xdev_ext_socket_class_submit(&stage,&batches[0])==0);
 xdev_ext_socket_class_mark_dead(&stage);xdev_ext_socket_progress(&stage);
 CHECK(batches[0].status==-ENODEV&&batches[0].locally_cancelled&&recv_calls==0);teardown();puts("rx STOP cancelled=-19 no recv");
}
static void nxp_rx(void) {
 setup(true,true);CHECK(xdev_ext_socket_class_submit(&stage,&batches[0])==0);
 recv_results=4;for(int i=0;i<4;i++)recv_result[i]=48;
 CHECK(xdev_ext_socket_progress(&stage)==0);
 CHECK(batches[0].status==0&&batches[0].produced==16&&completions==1);
 CHECK(((struct xdev_ext_socket_stage *)stage.priv)->request[0].cursor==2);
 CHECK(packet_calls==4&&recv_calls==4);
 CHECK(recv_seen_flags[0]==(MSG_DONTWAIT|MSG_PEEK|MSG_TRUNC)&&recv_seen_flags[1]==MSG_DONTWAIT);
 CHECK(recv_seen_flags[2]==(MSG_DONTWAIT|MSG_PEEK|MSG_TRUNC)&&recv_seen_flags[3]==MSG_DONTWAIT);
 CHECK(recv_seen_nr[0]==1&&recv_seen_nr[1]==2&&recv_seen_nr[2]==1&&recv_seen_nr[3]==2);
 CHECK(recv_seen_ptr[1][1]==buffers[0]+3&&recv_seen_ptr[3][1]==buffers[1]+4);
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==2&&session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==16);
 teardown();puts("nxp RX peek/consume/check cursor=2 produced=16 counts=2/16");
}
static void rx_cases(void) {
 setup(true,false);struct xdev_ext_socket_stage *ss=stage.priv;
 CHECK(xdev_ext_socket_validate(&stage,&batches[1],(u8 *)desc,2)==0);
 CHECK(sk.sk_data_ready==xdev_ext_socket_data_ready&&sk.sk_user_data==ss->rx);
 int old=kicks;sk.sk_data_ready(&sk);CHECK(kicks==old+1);
 CHECK(xdev_ext_socket_class_submit(&stage,&batches[1])==0);CHECK(xdev_ext_socket_class_submit(&stage,&batches[0])==0);
 CHECK(ss->rx->count==2&&ss->rx->fifo[0]==1&&ss->rx->fifo[1]==0);
 recv_results=2;recv_result[0]=7;recv_result[1]=-EAGAIN;
 CHECK(xdev_ext_socket_progress(&stage)==0);CHECK(completions==1&&batches[1].produced==7&&batches[1].status==0);
 CHECK(ss->rx->count==1&&ss->rx->head==1);
 recv_results=3;recv_result[2]=0;CHECK(xdev_ext_socket_progress(&stage)==0);CHECK(completions==2&&batches[0].status==-ENODATA&&batches[0].produced==0&&ss->rx->count==0);
 CHECK(session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==1&&session.counts[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==7);
 struct xdev_ext_socket_mech_cqe c={};xdev_ext_socket_class_fill_cqe(&stage,&batches[1],&c);CHECK(c.status==0&&c.bytes_received==7);
 teardown();CHECK(sk.sk_data_ready==saved_ready&&sk.sk_user_data==NULL);
 puts("rx FIFO slots=1,0 produced=7 ENODATA=-61 counts=1/7 callback restored");
 setup(true,false);CHECK(xdev_ext_socket_class_submit(&stage,&batches[0])==0);recv_results=1;recv_result[0]=16;recv_flags[0]=MSG_TRUNC;
 xdev_ext_socket_progress(&stage);xdev_ext_socket_class_fill_cqe(&stage,&batches[0],&c);CHECK(c.status==-EMSGSIZE&&c.flags==XDEV_EXT_SOCKET_CQE_F_TRUNC&&c.bytes_received==0);teardown();puts("rx TRUNC status=-90 produced=0 flags=1");
}
#include "host_cases.c"
int main(int argc,char **argv) {
 if(argc>1&&strcmp(argv[1],"host")==0){direct_host_cases();return 0;}
 preflight();validation();plain_case(16,0,0,16,1);plain_case(15,0,-EIO,0,0);plain_case(-EIO,0,-EIO,0,0);plain_case(-EAGAIN,-EAGAIN,0,0,0);
 nxp_retry();nxp_failure(-ENETDOWN,-ENETDOWN);nxp_failure(47,-EIO);bind_failures();rx_cases();stop_cases();nxp_rx();
 puts("PASS actual socket consumer assertions");return 0;
}
