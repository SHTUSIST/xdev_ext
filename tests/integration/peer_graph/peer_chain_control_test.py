#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual production one-START controller against syscall traces.
No kernel module, software device, disk or CUDA allocation is created here.
"""
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[5]
source=(ROOT/'tools/xdev_ext_mech/xdev_ext_peer_chain.c').read_text()
code=source[source.index('static int mech('):source.index('static int parse_u64(')]
code+=source[source.index('static int mac('):source.index('int main(')]
shim=r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include "IOURING"
#include "MECH"
typedef __u32 u32;
static unsigned int operations[16], calls, opens, closes, starts;
static int failure;
static bool reject_device_access;
static uint64_t identity=0x123456789abcdefULL;
static struct xdev_ext_mech_create created;
static int fake_open(const char *path,int flags) { assert(!reject_device_access && "invalid work must fail before device access");(void)path;(void)flags;return 10+opens++; }
static int fake_close(int fd) { assert(fd>=10&&fd<=13);closes++;return 0; }
static int fake_eventfd(unsigned int n,int flags) { (void)flags;assert(!n);return 12; }
static int fake_poll(struct pollfd *p,unsigned long nr,int timeout) { assert(nr==1&&p->fd==12&&timeout>0);p->revents=POLLIN;return 1; }
static long fake_syscall(long number,...)
{
 va_list args; va_start(args,number);
 if(number==__NR_io_uring_setup) { va_end(args);return 13; }
 assert(number==__NR_io_uring_register);
 assert(va_arg(args,int)==13);assert(va_arg(args,unsigned int)==IORING_REGISTER_XDEV_EXT_MECH);
 struct io_uring_xdev_ext_mech *r=va_arg(args,struct io_uring_xdev_ext_mech *);
 assert(va_arg(args,int)==1);va_end(args);operations[calls++]=r->op;
 if(r->op==XDEV_EXT_MECH_OP_CREATE) {
  struct xdev_ext_mech_create *c=(void*)(uintptr_t)r->arg;
  assert(c->pool_kind==XDEV_EXT_MECH_POOL_PEER&&c->pool_fd==9&&c->depth==1&&c->nr_stages==2);
  assert(c->layout.frame_size==65536&&!c->layout.hdr_room&&c->layout.group_bytes==8192);
  assert(c->st[0].class_id==XDEV_EXT_MECH_CLASS_NVME&&c->st[0].direction==XDEV_EXT_MECH_DIR_FROM_DEVICE);
  assert(c->st[0].arg0==100&&c->st[0].arg1==48);created=*c;c->session_id=identity;
 } else if(r->op==XDEV_EXT_MECH_OP_NOTIFY_ARM) {
  struct xdev_ext_mech_notify_arm *a=(void*)(uintptr_t)r->arg;assert(a->session_id==identity&&a->batches_target==3);
 } else if(r->op==XDEV_EXT_MECH_OP_START) {
  struct xdev_ext_mech_start *s=(void*)(uintptr_t)r->arg;assert(s->session_id==identity&&s->nr_batches==3&&!s->flags&&!s->nr_user_frames&&!s->user_frames);starts++;
 } else if(r->op==XDEV_EXT_MECH_OP_STATS) {
  struct xdev_ext_mech_stats *s=(void*)(uintptr_t)r->arg;assert(s->session_id==identity);
  s->batches_done=3;s->completed[0]=s->completed[1]=3;if(failure)s->batches_abort=1;
 } else if(r->op==XDEV_EXT_MECH_OP_STOP) {
  if(r->arg!=identity){errno=ENOENT;return -1;}
 } else assert(0);
 return 0;
}
#define open fake_open
#define close fake_close
#define eventfd(...) fake_eventfd(__VA_ARGS__)
#define poll fake_poll
#define syscall fake_syscall
'''.replace('IOURING',str(ROOT/'include/uapi/linux/io_uring.h')).replace('"MECH"','"'+str(ROOT/'include/uapi/linux/xdev_ext_mech.h')+'"')
main=r'''
int main(void)
{
 assert(run_chain(9,"src","dst",3,8192,9,100,200)==0);
 assert(starts==1&&calls==5&&operations[0]==XDEV_EXT_MECH_OP_CREATE&&operations[4]==XDEV_EXT_MECH_OP_STOP&&closes==4);
 assert(created.st[1].class_id==XDEV_EXT_MECH_CLASS_NVME&&created.st[1].arg0==200&&created.st[1].arg1==48);
 puts("ok 1 - actual controller lends one GPU pool, arms once, STARTs once, and STOP uses full 64-bit identity");
 calls=opens=closes=starts=0;
 assert(run_chain(9,"src","net/2/0/02:00:00:00:00:01/02:00:00:00:00:02",3,8192,9,100,200)==0);
 assert(starts==1&&created.st[1].class_id==XDEV_EXT_MECH_CLASS_NET&&created.st[1].arg0==2&&!created.st[1].arg1);
 assert(created.peer.local_mac[5]==1&&created.peer.peer_mac[5]==2);
 puts("ok 2 - same one-START caller selects generic native NET stage and explicit CPU-header endpoint metadata");
 calls=opens=closes=starts=0;failure=1;
 assert(run_chain(9,"src","dst",3,8192,9,100,200)==-EIO&&calls==5&&closes==4);
 calls=opens=closes=starts=0;
 assert(run_chain(9,"src","dst",0,8192,9,100,200)==-EINVAL&&!calls&&!opens);
 reject_device_access=true;
 assert(run_chain(9,"src","net/2/0/02:00:00:00:00:01/02:00:00:00:00:02",3,32768,9,100,200)==-EINVAL&&!calls&&!opens);
 puts("ok 3 - actual controller preserves failed verdicts, tears down, and rejects invalid work/reference NET geometry before device access");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev-peer-chain-') as directory:
 p=Path(directory);(p/'test.c').write_text(shim+code+main)
 subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
