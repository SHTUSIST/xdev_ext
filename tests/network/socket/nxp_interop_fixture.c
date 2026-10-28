/* SPDX-License-Identifier: GPL-2.0 */
static void nxp_setup(struct rx *r, bool tx)
{
 struct sockaddr_in peer; socklen_t n=sizeof(peer);
 struct xdev_ext_mech_stage_uapi u={.class_id=XDEV_EXT_MECH_CLASS_SOCKET,
  .flags=XDEV_EXT_SOCKET_F_NXP,.arg0=270019,.arg1=1500};
 setup_family(r,AF_INET);CHECK(!getsockname(r->peer,(void *)&peer,&n));
 CHECK(!connect(r->fd,(void *)&peer,n));r->sk.sk_state=TCP_ESTABLISHED;
 r->st.direction=u.direction=tx?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE;
 CHECK(!xdev_ext_socket_class_bind(&r->st,&u));shim_packet_call=run_packet;
 builds=checks=0;corrupt_plan=0;eagain_call=0;send_calls=0;
}
static struct xdev_ext_mech_peer wire_peer(void)
{
 return (struct xdev_ext_mech_peer){.local_ip=htonl(0xc0000201),.peer_ip=htonl(0xc0000202),
  .local_port=htons(12345),.peer_port=htons(23456)};
}
static void encoded(unsigned char *pkt,u32 group,u32 idx,bool badcrc)
{
 struct xdev_ext_mech_peer p=wire_peer();
 struct xdev_ext_mp_tx_seg seg={.session_id=270019,.generation=group,.total_len=GROUP,
  .count=2,.index=idx,.relative_offset=idx*SEG,.payload_len=idx?GROUP-SEG:SEG};
 unsigned char hdr[40];u32 crc;
 CHECK(!xdev_ext_mp_tx_encode(pkt,&p,&seg));
 for(u32 j=0;j<seg.payload_len;j++)pkt[82+j]=pattern(group,j+idx*SEG);
 xdev_ext_mp_nxp_crc_prep(hdr,pkt+42);crc=bpf_xdev_ext_crc32c(hdr,40,~0U);
 crc=bpf_xdev_ext_crc32c(pkt+82,seg.payload_len,crc);
 xdev_ext_mp_nxp_crc_store(pkt+42,crc^(badcrc?1U:0U));
 xdev_ext_mp_put_be16(pkt+24,xdev_ext_mp_ip_csum(pkt+14));
}
static void incoming(struct rx *r,u32 group,u32 idx,bool badcrc)
{
 unsigned char pkt[2048];u32 len=40+(idx?GROUP-SEG:SEG);encoded(pkt,group,idx,badcrc);
 CHECK(send(r->peer,pkt+42,len,0)==len);
}
static void exact(struct rx *r,u32 slot,u32 group)
{
 CHECK(r->b[slot].completions==1&&!r->b[slot].status&&r->b[slot].produced==GROUP);
 for(u32 i=0;i<2;i++){
  u32 len=i?GROUP-SEG:SEG;
  for(u32 j=0;j<HDR;j++)CHECK(r->pages[2*slot+i][j]==CANARY);
  for(u32 j=0;j<len;j++)CHECK(r->pages[2*slot+i][HDR+j]==pattern(group,i*SEG+j));
  for(u32 j=HDR+len;j<FRAME;j++)CHECK(r->pages[2*slot+i][j]==CANARY);
 }
}
static void rx_ordered(void)
{
 struct rx r;nxp_setup(&r,false);arm(&r,0);arm(&r,1);int alloc=shim_alloc_calls;
 incoming(&r,2,0,false); /* A posted future batch cannot steal the FIFO head. */
 incoming(&r,1,1,false); /* Out of order is dropped without writing any frame. */
 xdev_ext_socket_progress(&r.st);CHECK(!r.b[0].completions&&!r.b[1].completions);
 CHECK(r.pages[0][HDR]==CANARY&&r.pages[2][HDR]==CANARY);
 incoming(&r,1,0,false);incoming(&r,1,0,false);incoming(&r,1,1,false);
 incoming(&r,1,1,false);incoming(&r,2,0,false);incoming(&r,2,1,false);
 xdev_ext_socket_progress(&r.st);exact(&r,0,1);exact(&r,1,2);
 CHECK(checks==4&&builds==8);CHECK(shim_alloc_calls==alloc);
 CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==4);
 CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==2*GROUP);check_no_zc();teardown(&r);
 puts("PASS AF_XDP reference TX -> socket RX: exact payload, two groups, future/duplicate/order guards, no packet allocation");
}
static void rx_invalid(void)
{
 struct rx r;unsigned char pkt[2048];nxp_setup(&r,false);arm(&r,0);
 encoded(pkt,1,0,false);pkt[42+32]=1;CHECK(send(r.peer,pkt+42,40+SEG,0)==40+SEG);
 xdev_ext_socket_progress(&r.st);CHECK(!r.b[0].completions&&r.pages[0][HDR]==CANARY);
 incoming(&r,1,0,true);xdev_ext_socket_progress(&r.st);
 CHECK(r.b[0].completions==1&&r.b[0].status==-EBADMSG&&!r.b[0].produced);
 CHECK(checks==1);teardown(&r);
 puts("PASS invalid NXP length and CRC cannot publish success");
}
static void tx_interop(void)
{
 struct rx r;unsigned char pkt[2048],expected[2048],hdr[40];
 struct xdev_ext_mp_rx_cfg cfg={.session_id=270019,.mtu=1500,.frame_size=FRAME,.hdr_room=HDR,.seg_len=SEG,.group_bytes=GROUP};
 struct xdev_ext_mech_peer p=wire_peer(),receiver=p;
 struct xdev_ext_mp_segment seg;struct xdev_ext_mp_rx_order order={};
 receiver.local_ip=p.peer_ip;receiver.peer_ip=p.local_ip;receiver.local_port=p.peer_port;receiver.peer_port=p.local_port;
 nxp_setup(&r,true);
 for(u32 i=0;i<2;i++)for(u32 j=0;j<r.b[0].f[i].data_len;j++)r.pages[i][HDR+j]=pattern(1,i*SEG+j);
 CHECK(!xdev_ext_socket_validate(&r.st,&r.b[0],(void *)r.d[0],2));int alloc=shim_alloc_calls;
 eagain_call=2;CHECK(xdev_ext_socket_class_submit(&r.st,&r.b[0])==-EAGAIN);CHECK(!r.b[0].completions);
 CHECK(!xdev_ext_socket_validate(&r.st,&r.b[0],(void *)r.d[0],2));
 CHECK(!xdev_ext_socket_class_submit(&r.st,&r.b[0]));CHECK(r.b[0].completions==1&&!r.b[0].status);
 for(u32 i=0;i<2;i++){
  u32 payload=i?GROUP-SEG:SEG;encoded(expected,1,i,false);memcpy(pkt,expected,82);
  CHECK(recv(r.peer,pkt+42,sizeof(pkt)-42,MSG_DONTWAIT)==40+payload);
  CHECK(!memcmp(pkt+42,expected+42,40+payload)); /* Independent full wire oracle. */
  CHECK(xdev_ext_mp_rx_parse(pkt,HDR-82,82+payload,&receiver,&cfg,&seg)==XDEV_EXT_MP_RX_SEGMENT);
  xdev_ext_mp_nxp_crc_prep(hdr,pkt+42);u32 crc=bpf_xdev_ext_crc32c(hdr,40,~0U);crc=bpf_xdev_ext_crc32c(pkt+82,payload,crc);
  CHECK(xdev_ext_mp_nxp_crc_ok(pkt+42,crc));CHECK(xdev_ext_mp_rx_order(&order,&seg,1)==XDEV_EXT_MP_HOLD);
 }
 CHECK(recv(r.peer,pkt,sizeof(pkt),MSG_DONTWAIT)<0&&errno==EAGAIN);
 CHECK(order.last_generation==1&&shim_alloc_calls==alloc&&builds==3&&!checks);
 CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]==2);
 CHECK(shim_counters[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]==GROUP);check_no_zc();teardown(&r);
 puts("PASS socket TX -> AF_XDP reference RX: exact NXP2 wire, EAGAIN suffix resumes without resending accepted prefix");
}
static void tx_short_group(void)
{
 struct rx r;nxp_setup(&r,true);r.b[0].bytes--;
 r.b[0].f[1].data_len--;r.d[0][1].len--;
 CHECK(!xdev_ext_socket_validate(&r.st,&r.b[0],(void *)r.d[0],2));
 CHECK(!xdev_ext_socket_class_submit(&r.st,&r.b[0]));
 CHECK(r.b[0].status==-EBADMSG&&send_calls==0);teardown(&r);
 puts("PASS NXP short group refused before any native send, preserving AF_XDP full-group contract");
}
static void rx_forged_plan(void)
{
 for(int bad=1;bad<=7;bad++){
  struct rx r;nxp_setup(&r,false);arm(&r,0);corrupt_plan=bad;
  incoming(&r,1,0,false);xdev_ext_socket_progress(&r.st);
  CHECK(!r.b[0].completions&&r.pages[0][HDR]==CANARY&&!checks);
  corrupt_plan=0;incoming(&r,1,0,false);incoming(&r,1,1,false);
  xdev_ext_socket_progress(&r.st);exact(&r,0,1);teardown(&r);
 }
 puts("PASS C rejects forged key/frame/offset/length/relative/header/reserved plans before payload copy");
}
static struct rx *racing;
static void steal_peeked(int rc)
{
 unsigned char trash[2048];
 if(rc<0||!(last_recv_flags&MSG_PEEK))return;
 recv_hook=NULL;CHECK(recv(racing->fd,trash,sizeof(trash),MSG_DONTWAIT)>0);
}
static void rx_reader_race(void)
{
 for(int oversized=0;oversized<2;oversized++){
  struct rx r;unsigned char pkt[2048];nxp_setup(&r,false);arm(&r,0);
  incoming(&r,1,0,false);encoded(pkt,1,0,!oversized);
  CHECK(send(r.peer,pkt+42,40+SEG+oversized,0)==40+SEG+oversized);
  racing=&r;recv_hook=steal_peeked;xdev_ext_socket_progress(&r.st);
  CHECK(r.b[0].completions==1&&r.b[0].status==-EPROTO&&!r.b[0].produced&&!checks);
  teardown(&r);
 }
 puts("PASS concurrent-reader header mismatch and truncation fail without publication");
}
static void rx_stop_partial(void)
{
 struct rx r;nxp_setup(&r,false);arm(&r,0);incoming(&r,1,0,false);
 xdev_ext_socket_progress(&r.st);CHECK(!r.b[0].completions);
 r.s.admits=false;xdev_ext_socket_progress(&r.st);
 CHECK(r.b[0].cancelled==1&&r.b[0].status==-ESHUTDOWN&&!r.b[0].produced);teardown(&r);
 puts("PASS STOP cancels partially received group without publishing partial payload");
}
int main(void)
{test_case="nxp_interop";rx_ordered();rx_invalid();rx_forged_plan();rx_reader_race();rx_stop_partial();tx_interop();tx_short_group();return 0;}
