/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "include/uapi/linux/xdev_ext_peer.h"

int __real_open(const char *path,int flags,...);
int __wrap_open(const char *path,int flags,...)
{
 if(!strcmp(path,"/dev/xdev_ext_peer_sw") || !strcmp(path,"/dev/xdev_ext_peer") || !strcmp(path,"/dev/ng0n1"))return eventfd(0,EFD_CLOEXEC);
 if(flags&O_CREAT) {va_list a;va_start(a,flags);mode_t mode=va_arg(a,int);va_end(a);return __real_open(path,flags,mode);}
 return __real_open(path,flags);
}
int __wrap_ioctl(int fd,unsigned long op,...)
{
 va_list a;va_start(a,op);void *p=va_arg(a,void *);va_end(a);(void)fd;
 if(op==XDEV_EXT_PEER_REGISTER) {struct xdev_ext_peer_register *r=p;r->generation=81;return eventfd(0,EFD_CLOEXEC);}
 errno=ENOTTY;return -1;
}
long __wrap_syscall(long nr,...)
{
 va_list a;va_start(a,nr);
 if(nr==__NR_io_uring_setup) {va_end(a);return eventfd(0,EFD_CLOEXEC);}
 if(nr==__NR_io_uring_register) {
 int fd=va_arg(a,int);unsigned opcode=va_arg(a,unsigned);void *arg=va_arg(a,void *);unsigned count=va_arg(a,unsigned);va_end(a);
 if(opcode==IORING_REGISTER_XDEV_EXT_UMEM) return 0;
 if(fd<0 || opcode!=IORING_REGISTER_XDEV_EXT_MECH || count!=1) {errno=EINVAL;return -1;}
 struct io_uring_xdev_ext_mech *m=arg;fprintf(stderr,"HOOK op=%u\n",m->op);
 if(m->op==10) {
  struct xdev_ext_mech_create_with_report *e=(void *)(uintptr_t)m->arg;
  if(getenv("R3_UNSUPPORTED")) {errno=EOPNOTSUPP;return -1;}
  e->report=(struct xdev_ext_mech_create_report){.size=288,.version=1,.result=-EXDEV,.rollback_errno=-EIO,.phase=12,.failed_stage=0,.cleanup=1,.valid=15,.requester={3,4,17,0},.caps={.size=64,.version=1,.stage=0,.family=1,.reachability=3,.refused=1}};
  return 0;
 }
 if(m->op==XDEV_EXT_MECH_OP_CREATE) {errno=EXDEV;return -1;}
 errno=EINVAL;return -1;
 }
 va_end(a);errno=ENOSYS;return -1;
}
