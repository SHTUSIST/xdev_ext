#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual ctl UDP setup and START-loan report over host loopback sockets."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[5]
PREAMBLE=r'''
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
struct ctl_opts {struct xdev_ext_mech_peer peer;__u64 groups,group_bytes;bool reliable;};
'''
MAIN=r'''
int main(void)
{
 struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)},
  txaddr,rxaddr,wrongip; socklen_t n=sizeof(a);
 int reserve=socket(AF_INET,SOCK_DGRAM,0);assert(reserve>=0&&!bind(reserve,(void *)&a,n));
 assert(!getsockname(reserve,(void *)&txaddr,&n));
 int reserve_rx=socket(AF_INET,SOCK_DGRAM,0);assert(reserve_rx>=0&&!bind(reserve_rx,(void *)&a,n));
 assert(!getsockname(reserve_rx,(void *)&rxaddr,&n));close(reserve_rx);close(reserve);
 struct ctl_opts o={.groups=64,.group_bytes=8192,.peer={.local_ip=rxaddr.sin_addr.s_addr,
  .local_port=rxaddr.sin_port,.peer_ip=txaddr.sin_addr.s_addr,.peer_port=txaddr.sin_port}};
 int rx=ctl_socket_open(&o,true),tx;assert(rx>=0);
 o.peer.local_ip=txaddr.sin_addr.s_addr;o.peer.local_port=txaddr.sin_port;
 o.peer.peer_ip=rxaddr.sin_addr.s_addr;o.peer.peer_port=rxaddr.sin_port;
 tx=ctl_socket_open(&o,false);assert(tx>=0);
 int foreign=socket(AF_INET,SOCK_DGRAM,0),ipforeign=socket(AF_INET,SOCK_DGRAM,0);
 assert(foreign>=0&&ipforeign>=0);wrongip=txaddr;wrongip.sin_addr.s_addr=htonl(0x7f000002);
 assert(!bind(ipforeign,(void *)&wrongip,n));
 assert(sendto(foreign,"PORT",4,0,(void *)&rxaddr,n)==4);
 assert(sendto(ipforeign,"IP",2,0,(void *)&rxaddr,n)==2);
 char data[8]={0};assert(recv(rx,data,sizeof(data),MSG_DONTWAIT)<0&&errno==EAGAIN);
 assert(send(tx,"payload",7,0)==7);assert(recv(rx,data,sizeof(data),MSG_DONTWAIT)==7&&!strcmp(data,"payload"));
 close(rx);close(tx);close(foreign);close(ipforeign);
 o.reliable=true;assert(ctl_socket_open(&o,true)==-EOPNOTSUPP);o.reliable=false;
 o.group_bytes=65508;tx=ctl_socket_open(&o,false);assert(tx>=0);close(tx);
 char line[512];struct xdev_ext_mech_stats s={.state=XDEV_EXT_MECH_SESSION_ACTIVE,.batches_done=64,.recycled=360,.published=24,.submitted={64,64,64,64},.completed={64,64,64,64}};
 assert(ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,2));
 assert(strstr(line,"XDEV_EXT_MECH_NIC_NVME_E2E=PASS")&&strstr(line,"held=0")&&strstr(line,"published=24"));
 assert(ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,4));
 s.submitted[0]=0;assert(!ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,2));s.submitted[0]=64;
 s.published--;assert(!ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,2));s.published++;
 s.recycled++;assert(!ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,2));s.recycled--;
 s.held=384;assert(!ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,2));s.held=0;
 s.last_err=-EIO;assert(!ctl_socket_rx_report(line,sizeof(line),&s,64,6,24,2));
 puts("PASS ctl socket setup, wrong source IP/port rejected, reliable refusal and true START-loan accounting");
}
'''
class CtlSocket(unittest.TestCase):
 def test_setup_and_ledger(self):
  source=(ROOT/'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
  bodies=[]
  for name in ('ctl_socket_open','ctl_socket_rx_report'):
   m=re.search(r'^static (?:int|bool) '+name+r'\([^;{}]*\)\s*\{.*?^\}',source,re.M|re.S)
   self.assertIsNotNone(m,'missing '+name);bodies.append(m[0])
  with tempfile.TemporaryDirectory() as tmp:
   c=Path(tmp)/'ctl.c';exe=Path(tmp)/'ctl';c.write_text(PREAMBLE+'\n'.join(bodies)+MAIN)
   p=subprocess.run([os.environ.get('CC','gcc'),'-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-I'+str(ROOT),str(c),'-o',str(exe)],capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stdout+p.stderr)
   p=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
   self.assertEqual(p.returncode,0,p.stdout+p.stderr);print(p.stdout,end='')
if __name__=='__main__':unittest.main(verbosity=2)
