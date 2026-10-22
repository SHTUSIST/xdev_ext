/* SPDX-License-Identifier: GPL-2.0 */
int main(void)
{
 struct xdev_ext_mech_session session={.depth=8,.admits=true,.pool={.frame_size=2048,.nr_frames=8},.l={.frame_size=2048,.hdr_room=16,.seg_len=1000,.group_bytes=1500}};
 struct sock sk={.sk_family=AF_INET,.sk_protocol=IPPROTO_UDP,.sk_state=TCP_ESTABLISHED};
 struct socket endpoint={.type=SOCK_DGRAM,.sk=&sk};
 struct file file={.sock=&endpoint};
 struct xdev_ext_mech_stage st={.file=&file,.s=&session,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi u={.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_batch b={.nr=2,.bytes=1500,.ticket=42};
 struct xdev_ext_socket_send_desc d[2]={{0,16,1000,0},{1,16,500,0}};
 struct xdev_ext_socket_mech_info info;
 struct xdev_ext_socket_mech_cqe cqe;
 struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
 socklen_t alen=sizeof(addr);u8 pages[8][2048],received[1600];unsigned i,g;
 int peer=socket(AF_INET,SOCK_DGRAM,0);
 assert(peer>=0);assert(!bind(peer,(void *)&addr,sizeof(addr)));assert(!getsockname(peer,(void *)&addr,&alen));
 endpoint.fd=socket(AF_INET,SOCK_DGRAM,0);assert(endpoint.fd>=0);assert(!connect(endpoint.fd,(void *)&addr,sizeof(addr)));
 for(i=0;i<8;i++) {memset(pages[i],0xa5,2048);session.pool.state[i]=XDEV_EXT_MECH_F_INFLIGHT;}
 for(i=0;i<2;i++) b.f[i]=(struct xdev_ext_mech_frame){.kaddr=pages[i],.index=i,.data_off=16,.data_len=i?500:1000};
 assert(!xdev_ext_socket_bind(&st,&u));
 xdev_ext_socket_fill_info(&st,&b,&info);assert(info.nr_frames==2 && info.max_datagram==65507);
 assert(!xdev_ext_socket_validate(&st,&b,(void *)d,2));
 d[0].flags=MSG_ZEROCOPY;assert(xdev_ext_socket_validate(&st,&b,(void *)d,2)==-EINVAL);d[0].flags=0;
 d[0].frame_off--;assert(xdev_ext_socket_validate(&st,&b,(void *)d,2)==-EINVAL);d[0].frame_off++;
 d[1].len--;assert(xdev_ext_socket_validate(&st,&b,(void *)d,2)==-EINVAL);d[1].len++;
 d[1].frame_pos=0;assert(xdev_ext_socket_validate(&st,&b,(void *)d,2)==-EINVAL);d[1].frame_pos=1;
 assert(xdev_ext_socket_validate(&st,&b,(void *)d,1)==-EINVAL);
 b.bytes=65508;assert(xdev_ext_socket_validate(&st,&b,(void *)d,2)==-EMSGSIZE);b.bytes=1500;
 for(g=0;g<257;g++) {
  b.slot=g%8;b.ticket++;b.completions=0;
  for(i=0;i<1000;i++)pages[0][16+i]=(u8)(g+i*13);
  for(i=0;i<500;i++)pages[1][16+i]=(u8)(g+(1000+i)*13);
  assert(!xdev_ext_socket_validate(&st,&b,(void *)d,2));
  assert(!xdev_ext_socket_submit(&st,&b));assert(b.completions==1 && !b.status && b.completed_ticket==b.ticket);
  assert(recv(peer,received,sizeof(received),MSG_DONTWAIT)==1500);
  for(i=0;i<1500;i++)assert(received[i]==(u8)(g+i*13));
  assert(pages[0][15]==0xa5 && pages[0][1016]==0xa5 && pages[1][15]==0xa5 && pages[1][516]==0xa5);
  xdev_ext_socket_fill_cqe(&st,&b,&cqe);assert(!cqe.status && cqe.bytes_sent==1500);
 }
 assert(send_calls==257 && last_send_flags==(MSG_DONTWAIT|MSG_NOSIGNAL));
 b.completions=0;forced_send=-EAGAIN;assert(xdev_ext_socket_submit(&st,&b)==-EAGAIN && !b.completions);
 forced_send=-ECONNREFUSED;assert(!xdev_ext_socket_submit(&st,&b) && b.completions==1 && b.status==-ECONNREFUSED);
 forced_send=123;assert(!xdev_ext_socket_submit(&st,&b) && b.status==-EIO);
 forced_send=999999;session.pool.state[1]=XDEV_EXT_MECH_F_HELD;i=send_calls;
 assert(xdev_ext_socket_submit(&st,&b)==-EBUSY && send_calls==(int)i);session.pool.state[1]=XDEV_EXT_MECH_F_INFLIGHT;
 session.admits=false;assert(xdev_ext_socket_submit(&st,&b)==-ESHUTDOWN);session.admits=true;
 sk.udp.cork=true;assert(xdev_ext_socket_submit(&st,&b)==-EOPNOTSUPP);sk.udp.cork=false;
 sk.sk_shutdown=SEND_SHUTDOWN;assert(xdev_ext_socket_submit(&st,&b)==-ESHUTDOWN);sk.sk_shutdown=0;
 xdev_ext_socket_mark_dead(&st);assert(xdev_ext_socket_submit(&st,&b)==-ENODEV);
 xdev_ext_socket_unbind(&st);assert(!st.priv);
 u.arg0=1;assert(xdev_ext_socket_bind(&st,&u)==-EINVAL);u.arg0=0;
 sk.sk_state=0;assert(xdev_ext_socket_bind(&st,&u)==-ENOTCONN);sk.sk_state=TCP_ESTABLISHED;
 sk.sk_protocol=IPPROTO_TCP;assert(xdev_ext_socket_bind(&st,&u)==-EPROTONOSUPPORT);sk.sk_protocol=IPPROTO_UDP;
 st.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;assert(xdev_ext_socket_bind(&st,&u)==-EINVAL);st.direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
 file.sock=NULL;assert(xdev_ext_socket_bind(&st,&u)==-ENOTSOCK);file.sock=&endpoint;
 close(peer);close(endpoint.fd);
 /* Exercise the same production adapter with a real IPv6 peer and an fd
  * table replacement. The retained boundary object keeps the old socket,
  * matching core fget(st->file), rather than looking u.fd up on submission.
  */
 {
  struct sockaddr_in6 addr6={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
  int original,reused,retained,peer6=socket(AF_INET6,SOCK_DGRAM,0);
  alen=sizeof(addr6);assert(peer6>=0);assert(!bind(peer6,(void *)&addr6,sizeof(addr6)));
  assert(!getsockname(peer6,(void *)&addr6,&alen));
  original=socket(AF_INET6,SOCK_DGRAM,0);assert(original>=0);
  assert(!connect(original,(void *)&addr6,sizeof(addr6)));
  retained=dup(original);assert(retained>=0);endpoint.fd=retained;sk.sk_family=AF_INET6;
  u.fd=original;assert(!xdev_ext_socket_bind(&st,&u));close(original);
  reused=socket(AF_INET6,SOCK_DGRAM,0);assert(reused>=0);
  if(reused!=original){assert(dup2(reused,original)==original);close(reused);}
  assert(!xdev_ext_socket_validate(&st,&b,(void *)d,2));
  assert(!xdev_ext_socket_submit(&st,&b));
  assert(recv(peer6,received,sizeof(received),MSG_DONTWAIT)==1500);
  for(i=0;i<1500;i++)assert(received[i]==(u8)(256+i*13));
  assert(!shutdown(retained,SHUT_WR));
  assert(!xdev_ext_socket_submit(&st,&b) && b.status==-EPIPE);
  xdev_ext_socket_unbind(&st);close(peer6);close(retained);close(original);
 }

 puts("PASS socket sink production adapter: 257 datagrams, 8 request slots, bounds, guards, native errors, ownership, STOP");
 return 0;
}
