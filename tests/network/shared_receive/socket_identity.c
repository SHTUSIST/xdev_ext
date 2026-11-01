/* SPDX-License-Identifier: GPL-2.0 */
/* Requirement: shared_open rejects an unproven borrowed XSK before touching
 * pins, maps or devices. All socket/network boundaries are fixtures. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/if_xdp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/xdp_diag.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "contract_api.h"
#include "abi_transport.h"

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif
#define BORROWED 90001
#define CONTROL 90002
#define DIAG 90003
static const char *scenario="valid-control";
static unsigned char socket_copy[65536];
static int original_backing=-1;
static unsigned int forbidden,diagnostic_replies,getsockname_calls;
static uint32_t sequence;
static int failures;
long __real_syscall(long number,...);
static int is_socket(int fd)
{return fd==BORROWED || (fd>=0 && fd<65536 && socket_copy[fd]);}
static int duplicate_socket(int fd,int command,long minimum)
{
 int backing,n;
 if(!is_socket(fd)){errno=EBADF;return -1;}
 if(fd==BORROWED) {
  if(original_backing<0)original_backing=(int)__real_syscall(SYS_openat,AT_FDCWD,"/dev/null",O_RDWR|O_CLOEXEC,0);
  backing=original_backing;
 } else backing=fd;
 if(backing<0)return -1;
 n=(int)__real_syscall(SYS_fcntl,backing,command,minimum);
 if(n>=65536){__real_syscall(SYS_close,n);errno=EMFILE;return -1;}
 if(n>=0)socket_copy[n]=1;
 return n;
}
static int is(const char *name){return !strcmp(scenario,name);}
static int deny(void){forbidden++;errno=EACCES;return -1;}
static void check(int yes,const char *name)
{printf("%s - %s\n",yes?"ok":"not ok",name);failures+=!yes;}
unsigned int __wrap_if_nametoindex(const char *name)
{if(!strcmp(name,"fixture0"))return 7;errno=ENODEV;return 0;}
int __wrap_socket(int domain,int type,int protocol)
{
 (void)type;
 if(domain==AF_INET && protocol==0)return CONTROL;
 if(domain==AF_NETLINK && protocol==NETLINK_SOCK_DIAG){if(is("diag-unavailable")){errno=EPROTONOSUPPORT;return -1;}return DIAG;}
 if(domain==AF_XDP){errno=EACCES;return -1;}
 errno=EAFNOSUPPORT;return -1;
}
int __wrap_close(int fd)
{
 if(fd==BORROWED){check(0,"borrowed socket is never closed by shared open");return 0;}
 if(fd==CONTROL || fd==DIAG)return 0;
 if(fd>=0 && fd<65536)socket_copy[fd]=0;
 return (int)__real_syscall(SYS_close,fd);
}
int __wrap_fstat(int fd,struct stat *st)
{
 if(is_socket(fd)){memset(st,0,sizeof(*st));st->st_mode=S_IFSOCK|0600;st->st_ino=0x12345;st->st_uid=geteuid();return 0;}
 return (int)__real_syscall(SYS_fstat,fd,st);
}
int __wrap_fstat64(int fd,struct stat64 *st)
{
 struct stat value;int ret=__wrap_fstat(fd,&value);
 if(!ret)fixture_copy_stat64(st,&value);
 return ret;
}
int __wrap_getsockopt(int fd,int level,int opt,void *value,socklen_t *bytes)
{
 if(level==SOL_SOCKET && opt==SO_DOMAIN && is_socket(fd)){int n=is("wrong-domain")?AF_INET:AF_XDP;memcpy(value,&n,sizeof(n));*bytes=sizeof(n);return 0;}
 if(level==SOL_SOCKET && opt==SO_TYPE && is_socket(fd)){int n=is("wrong-type")?SOCK_DGRAM:SOCK_RAW;memcpy(value,&n,sizeof(n));*bytes=sizeof(n);return 0;}
 if(level==SOL_SOCKET && opt==SO_NETNS_COOKIE && (is_socket(fd) || fd==CONTROL)) {
  uint64_t n=(is_socket(fd) && is("wrong-netns-cookie"))?0x89:0x88;
  if(is("netns-cookie-unavailable")){errno=ENOPROTOOPT;return -1;}
  memcpy(value,&n,sizeof(n));*bytes=sizeof(n);return 0;
 }
 if(level==SOL_SOCKET && opt==SO_COOKIE && is_socket(fd)) {
  uint64_t n=0x1122334455667788ULL;
  if(is("socket-cookie-unavailable")){errno=ENOPROTOOPT;return -1;}
  memcpy(value,&n,sizeof(n));*bytes=sizeof(n);return 0;
 }
 if(level==SOL_XDP && opt==XDP_OPTIONS && is_socket(fd)) {
  struct xdp_options o={.flags=XDP_OPTIONS_ZEROCOPY};
  if(is("xdp-options-unavailable")){errno=ENOPROTOOPT;return -1;}
  memcpy(value,&o,sizeof(o));*bytes=is("xdp-options-short")?0:sizeof(o);return 0;
 }
 errno=ENOPROTOOPT;return -1;
}
int __wrap_getsockname(int fd,struct sockaddr *addr,socklen_t *bytes)
{
 if(fd==DIAG && *bytes>=sizeof(struct sockaddr_nl)) {
  struct sockaddr_nl a={.nl_family=AF_NETLINK,.nl_pid=1234};
  memcpy(addr,&a,sizeof(a));*bytes=sizeof(a);return 0;
 }
 getsockname_calls++;errno=EOPNOTSUPP;return -1;
}
int __wrap_connect(int fd,const struct sockaddr *addr,socklen_t bytes)
{(void)addr;(void)bytes;if(fd==DIAG)return 0;errno=EINVAL;return -1;}
int __wrap_setsockopt(int fd,int level,int opt,const void *value,socklen_t bytes)
{(void)level;(void)opt;(void)value;(void)bytes;if(fd==DIAG)return 0;errno=ENOPROTOOPT;return -1;}
int __wrap_fcntl(int fd,int command,...)
{
 va_list ap;long argument=0;
 if(command!=F_GETFD && command!=F_GETFL){va_start(ap,command);argument=va_arg(ap,long);va_end(ap);}
 if(is_socket(fd) && (command==F_DUPFD || command==F_DUPFD_CLOEXEC))return duplicate_socket(fd,command,argument);
 if(fd>=0 && fd<65536 && socket_copy[fd])return (int)__real_syscall(SYS_fcntl,fd,command,argument);
 if(fd==DIAG || fd==CONTROL || fd==BORROWED) {
  if(command==F_GETFD)return FD_CLOEXEC;
  if(command==F_SETFD)return 0;
 }
 errno=EINVAL;return -1;
}
int __wrap_fcntl64(int fd,int command,...)
{
 va_list ap;long argument=0;
 if(command!=F_GETFD && command!=F_GETFL){va_start(ap,command);argument=va_arg(ap,long);va_end(ap);}
 return __wrap_fcntl(fd,command,argument);
}
static ssize_t sent(const void *buf,size_t n)
{
 const struct nlmsghdr *h=buf;
 if(n>=sizeof(*h))sequence=h->nlmsg_seq;
 return (ssize_t)n;
}
ssize_t __wrap_sendmsg(int fd,const struct msghdr *m,int flags)
{(void)flags;if(fd!=DIAG){errno=EBADF;return -1;}return sent(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len);}
ssize_t __wrap_sendto(int fd,const void *buf,size_t n,int flags,const struct sockaddr *addr,socklen_t bytes)
{(void)flags;(void)addr;(void)bytes;if(fd!=DIAG){errno=EBADF;return -1;}return sent(buf,n);}
ssize_t __wrap_send(int fd,const void *buf,size_t n,int flags)
{return __wrap_sendto(fd,buf,n,flags,NULL,0);}
static ssize_t received(void *buf,size_t capacity)
{
 unsigned char data[128]={0};struct nlmsghdr *h=(void *)data;
 struct xdp_diag_msg *d=NLMSG_DATA(h);struct rtattr *a;
 struct xdp_diag_info *info;
 size_t n;
 if(is("diag-unavailable")){errno=EOPNOTSUPP;return -1;}
 h->nlmsg_seq=sequence;h->nlmsg_pid=0;
 if(diagnostic_replies++) {h->nlmsg_type=NLMSG_DONE;h->nlmsg_len=NLMSG_LENGTH(0);}
 else {
  h->nlmsg_type=SOCK_DIAG_BY_FAMILY;h->nlmsg_flags=NLM_F_MULTI;
  d->xdiag_family=AF_XDP;d->xdiag_type=SOCK_RAW;
  d->xdiag_ino=is("wrong-inode")?0x12346:0x12345;
  d->xdiag_cookie[0]=is("wrong-diag-cookie")?0x55667789:0x55667788;
  d->xdiag_cookie[1]=0x11223344;
  h->nlmsg_len=NLMSG_LENGTH(sizeof(*d));
  if(!is("diag-info-missing")) {
   a=(void *)(data+NLMSG_ALIGN(h->nlmsg_len));a->rta_type=XDP_DIAG_INFO;
   a->rta_len=is("diag-info-short")?RTA_LENGTH(1):RTA_LENGTH(sizeof(*info));
   info=RTA_DATA(a);info->ifindex=is("wrong-ifindex")?8:7;info->queue_id=is("wrong-queue")?4:3;
   h->nlmsg_len=NLMSG_ALIGN(h->nlmsg_len)+RTA_ALIGN(a->rta_len);
  }
 }
 n=h->nlmsg_len;if(capacity<n){errno=EMSGSIZE;return -1;}memcpy(buf,data,n);return (ssize_t)n;
}
ssize_t __wrap_recvmsg(int fd,struct msghdr *m,int flags)
{
 struct sockaddr_nl peer={.nl_family=AF_NETLINK};
 (void)flags;if(fd!=DIAG){errno=EBADF;return -1;}
 if(m->msg_name && m->msg_namelen>=sizeof(peer))memcpy(m->msg_name,&peer,sizeof(peer));
 m->msg_namelen=sizeof(peer);m->msg_flags=0;
 return received(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len);
}
ssize_t __wrap_recvfrom(int fd,void *buf,size_t n,int flags,struct sockaddr *addr,socklen_t *bytes)
{
 struct sockaddr_nl peer={.nl_family=AF_NETLINK};(void)flags;
 if(fd!=DIAG){errno=EBADF;return -1;}
 if(addr && bytes && *bytes>=sizeof(peer)){memcpy(addr,&peer,sizeof(peer));*bytes=sizeof(peer);}
 return received(buf,n);
}
ssize_t __wrap_recv(int fd,void *buf,size_t n,int flags)
{return __wrap_recvfrom(fd,buf,n,flags,NULL,NULL);}
int __wrap_bind(int fd,const struct sockaddr *addr,socklen_t n)
{(void)addr;(void)n;if(fd==DIAG)return 0;return deny();}
int __wrap_open(const char *path,int flags,...)
{
 if(!strcmp(path,"/proc/thread-self/ns/net") || !strcmp(path,"/proc/self/ns/net"))
  return (int)__real_syscall(SYS_openat,AT_FDCWD,path,flags,0);
 return deny();
}
int __wrap_open64(const char *path,int flags,...){return __wrap_open(path,flags);}
int __wrap_openat(int dir,const char *path,int flags,...)
{(void)dir;return __wrap_open(path,flags);}
int __wrap_mkdir(const char *path,mode_t mode){(void)path;(void)mode;return deny();}
int __wrap_mkdirat(int dir,const char *path,mode_t mode){(void)dir;return __wrap_mkdir(path,mode);}
int __wrap_unlink(const char *path){(void)path;return deny();}
int __wrap_unlinkat(int dir,const char *path,int flags){(void)dir;(void)flags;return __wrap_unlink(path);}
int __wrap_ioctl(int fd,unsigned long req,...){(void)fd;(void)req;return deny();}
/* libbpf/raw bpf syscalls are also denied, so fixture bugs cannot load BPF. */
long __wrap_syscall(long number,...){(void)number;return deny();}
int main(int argc,char **argv)
{
 struct xdev_ext_xsk_shared_opts opts={.sz=sizeof(opts),.ifname="fixture0",.queue_id=3,
  .xdp_flags=XDP_FLAGS_DRV_MODE,.xsk_fd=BORROWED,
  .filter={.flags=XDEV_EXT_XSK_FILTER_F_DST_IPV4|XDEV_EXT_XSK_FILTER_F_DST_PORT|XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC,
   .dst_ipv4=0xc6336402,.dst_port=9000,.payload_magic=0x11223344}};
 struct xdev_ext_xsk_shared *out=(void *)1;
 struct xdev_ext_xsk_shared_error error;
 int ret,unsupported;
 scenario=argc>1?argv[1]:"socket-cookie-unavailable";memset(&error,0xa5,sizeof(error));
 if(is("unknown-flags"))opts.flags=1;
 if(is("bad-mode"))opts.xdp_flags=XDP_FLAGS_DRV_MODE|XDP_FLAGS_SKB_MODE;
 if(is("bad-queue"))opts.queue_id=4096;
 if(is("zero-port"))opts.filter.dst_port=0;
 if(is("short-size"))opts.sz=sizeof(opts)-1;
 if(is("missing-magic-filter"))opts.filter.flags&=~XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC;
 ret=xdev_ext_xsk_shared_open(&opts,&out,&error);
 printf("scenario=%s ret=%d gate=%u diag=%u operation=%.*s reason=%.*s\n",scenario,ret,forbidden,diagnostic_replies,32,error.operation,160,error.reason);
 unsupported=is("socket-cookie-unavailable")||is("netns-cookie-unavailable")||is("diag-unavailable");
 if(is("valid-control")) {
  check(forbidden>0,"fully proven borrowed XSK proceeds to explicit OS permission boundary");
  check(ret==-EACCES,"OS permission failure is preserved without unsupported downgrade");
 } else {
  check(ret<0,"unproven borrowed socket or invalid options are rejected");
  if(unsupported)check(ret==-EOPNOTSUPP,"missing identity capability reports -EOPNOTSUPP");
  check(forbidden==0,"rejection happens before pins, maps or device access");
 }
 check(out==NULL,"ordinary failed open leaves no retained handle");
 check(error.error==ret && error.operation[0] && error.reason[0],"failure returns contextual diagnostic matching negative errno");
 check(memchr(error.operation,0,sizeof(error.operation)) && memchr(error.reason,0,sizeof(error.reason)),"diagnostics remain bounded strings");
 check(getsockname_calls==0,"XDP identity never falls back to unavailable getsockname");
 printf("RESULT failures=%d\n",failures);return failures?1:0;
}
