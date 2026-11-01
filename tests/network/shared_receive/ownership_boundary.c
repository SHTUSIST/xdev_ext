/* SPDX-License-Identifier: GPL-2.0 */
/* OS boundary fixture: opaque BPF maps/pins/link records and literal ethtool
 * state persist in ordinary files. Queue/global flock remain real libc calls.
 * No session ownership/state algorithm is implemented here. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/ethtool.h>
#include <linux/if_xdp.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/sockios.h>
#include <linux/xdp_diag.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "ownership_boundary.h"
#include "abi_transport.h"

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif
#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif
#define BORROWED 90000
#define CONTROL 91000
#define DIAG 91001
#define MAX_FD 65536
#define ROWS 64
#define LINK_DETACHED 1U
unsigned int fixture_netns=11;
int fixture_crash_after_insert;
unsigned int fixture_unconditional_detach;
static char root[1024];
static uint32_t fd_object[MAX_FD],ns_fd[MAX_FD];
static uint32_t fd_socket[MAX_FD],socket_ns[MAX_FD];
static struct {uint32_t queue,netns;int backing;} socket_originals[128];
static unsigned int nr_socket_originals;
static uint32_t sequence,diag_queue;
static unsigned int reply_index;
long __real_syscall(long number,...);
int __real_open(const char *,int,...);
int __real_openat(int,const char *,int,...);
int __real_close(int);
int __real_fstat(int,struct stat *);
int __real_mkdir(const char *,mode_t);
int __real_mkdirat(int,const char *,mode_t);
int __real_unlink(const char *);
int __real_unlinkat(int,const char *,int);
int __real_rmdir(const char *);
int __real_stat(const char *,struct stat *);
int __real_lstat(const char *,struct stat *);
int __real_fstatat(int,const char *,struct stat *,int);
int __real_fstatfs(int,struct statfs *);
int __real_statfs(const char *,struct statfs *);
int __real_fcntl(int,int,...);
struct row {uint32_t used;unsigned char key[256],value[512];};
struct object {
 uint32_t kind,id,type,key_size,value_size,max_entries,flags,prog_id,ifindex,nr_maps,map_ids[8],pins,netns;
 char name[16];struct row rows[ROWS];
};
struct rules {uint32_t used[32];struct ethtool_rx_flow_spec rule[32];};
static int socket_queue(int fd)
{
 if(fd==CONTROL || fd==DIAG)return -1;
 if(fd>=BORROWED && fd<BORROWED+4096)return fd-BORROWED;
 if(fd>=0 && fd<MAX_FD && fd_socket[fd])return (int)fd_socket[fd]-1;
 return -1;
}
static int duplicate_socket(int fd,int command,long minimum)
{
 int backing,n,queue=socket_queue(fd);uint32_t netns;unsigned int i;
 if(queue<0){errno=EBADF;return -1;}
 netns=fd>=0 && fd<MAX_FD && fd_socket[fd]?socket_ns[fd]:fixture_netns;
 if(fd>=0 && fd<MAX_FD && fd_socket[fd])backing=fd;
 else {
  for(i=0;i<nr_socket_originals;i++)if(socket_originals[i].queue==(uint32_t)queue && socket_originals[i].netns==netns)break;
  if(i==nr_socket_originals) {
   if(i==128){errno=EMFILE;return -1;}
   backing=__real_open("/dev/null",O_RDWR|O_CLOEXEC);if(backing<0)return -1;
   socket_originals[i].queue=(uint32_t)queue;socket_originals[i].netns=netns;socket_originals[i].backing=backing;nr_socket_originals++;
  }
  backing=socket_originals[i].backing;
 }
 n=__real_fcntl(backing,command,minimum);
 if(n>=MAX_FD){__real_close(n);errno=EMFILE;return -1;}
 if(n>=0){fd_socket[n]=(uint32_t)queue+1;socket_ns[n]=netns;}
 return n;
}
static void die(const char *what){perror(what);_exit(99);}
static void path(char *buf,size_t n,const char *suffix)
{if(snprintf(buf,n,"%s/%s",root,suffix)>=(int)n)die("path too long");}
static void namespace_path(char *buf,size_t n,const char *suffix)
{if(snprintf(buf,n,"%s/ns-%u-%s",root,fixture_netns,suffix)>=(int)n)die("namespace path too long");}
static const char *translated(const char *in,char *out,size_t n)
{
 if(!strcmp(in,"/")||!strcmp(in,"/run")||!strncmp(in,"/run/",5)||!strcmp(in,"/sys")||!strncmp(in,"/sys/",5)) {
  if(snprintf(out,n,"%s%s",root,in)>=(int)n)die("translated path too long");
  return out;
 }
 return in;
}
static const char *at_path(int dir,const char *p,char *out,size_t n)
{
 char base[1200],fdpath[64];ssize_t bytes;
 if(*p=='/')return p;
 if(dir==AT_FDCWD){if(!getcwd(base,sizeof(base)))die("fixture cwd");}
 else {
  snprintf(fdpath,sizeof(fdpath),"/proc/self/fd/%d",dir);bytes=readlink(fdpath,base,sizeof(base)-1);
  if(bytes<0)die("fixture fd path");
  base[bytes]=0;
 }
 if(snprintf(out,n,"%s/%s",base,p)>=(int)n)die("fixture at path");
 return out;
}
static int object_read(uint32_t id,struct object *o)
{
 char name[1200];int fd;snprintf(name,sizeof(name),"%s/object-%u",root,id);
 fd=__real_open(name,O_RDONLY|O_CLOEXEC);if(fd<0)return -1;
 if(pread(fd,o,sizeof(*o),0)!=(ssize_t)sizeof(*o)){__real_close(fd);errno=EIO;return -1;}
 __real_close(fd);return 0;
}
static int object_write(const struct object *o)
{
 char name[1200];int fd;snprintf(name,sizeof(name),"%s/object-%u",root,o->id);
 fd=__real_open(name,O_CREAT|O_RDWR|O_CLOEXEC,0600);if(fd<0)return -1;
 if(pwrite(fd,o,sizeof(*o),0)!=(ssize_t)sizeof(*o)){__real_close(fd);errno=EIO;return -1;}
 __real_close(fd);return 0;
}
static uint32_t next_id(void)
{
 char name[1200];uint32_t id=1;int fd;path(name,sizeof(name),"ids");
 fd=__real_open(name,O_CREAT|O_RDWR|O_CLOEXEC,0600);if(fd<0)die("id open");
 if(flock(fd,LOCK_EX))die("id lock");
 if(pread(fd,&id,sizeof(id),0)!=(ssize_t)sizeof(id))id=1;
 id++;if(pwrite(fd,&id,sizeof(id),0)!=(ssize_t)sizeof(id))die("id write");
 __real_close(fd);return id;
}
static int object_fd(uint32_t id)
{
 char name[1200];int fd;snprintf(name,sizeof(name),"%s/object-%u",root,id);
 fd=__real_open(name,O_RDWR|O_CLOEXEC);if(fd<0)return -1;
 if(fd>=MAX_FD)die("fd limit");
 fd_object[fd]=id;
 if(flock(fd,LOCK_SH))die("object fd lease");
 return fd;
}
static uint32_t current(void)
{
 char name[1200];uint32_t id=0;int fd;namespace_path(name,sizeof(name),"xdp");
 fd=__real_open(name,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;
 if(read(fd,&id,sizeof(id))!=(ssize_t)sizeof(id))id=0;
 __real_close(fd);
 if(id) {
  DIR *d=opendir(root);struct dirent *entry;
  if(!d)die("current objects");
  while((entry=readdir(d))) {
   struct object o;unsigned int object_id;
   if(sscanf(entry->d_name,"object-%u",&object_id)!=1)continue;
   if(object_read(object_id,&o)||o.kind!=3||o.prog_id!=id||o.netns!=fixture_netns)continue;
   if(o.flags&LINK_DETACHED)id=0;
   else if(!o.pins) {
    snprintf(name,sizeof(name),"%s/object-%u",root,object_id);
    fd=__real_open(name,O_RDWR|O_CLOEXEC);
    if(fd>=0) {
     if(!flock(fd,LOCK_EX|LOCK_NB))id=0;
     __real_close(fd);
    }
   }
   break;
  }
  closedir(d);
 }
 return id;
}
static void set_current(uint32_t id)
{
 char name[1200];int fd;namespace_path(name,sizeof(name),"xdp");
 fd=__real_open(name,O_CREAT|O_TRUNC|O_WRONLY|O_CLOEXEC,0600);if(fd<0)die("set xdp");
 if(write(fd,&id,sizeof(id))!=(ssize_t)sizeof(id))die("set xdp write");
 __real_close(fd);
}
static void maybe_detach(uint32_t id)
{
 struct object o;int fd;unsigned int saved;
 if(object_read(id,&o)||o.kind!=3||o.pins)return;
 fd=object_fd(id);if(fd<0)return;
 if(!flock(fd,LOCK_EX|LOCK_NB)) {
  saved=fixture_netns;fixture_netns=o.netns;if(current()==o.prog_id)set_current(0);fixture_netns=saved;
 }
 fd_object[fd]=0;__real_close(fd);
}
void fixture_init(const char *p)
{
 char name[1200];const char *dirs[]={"run","run/xdev_ext","sys","sys/fs","sys/fs/bpf"};size_t i;
 if(strlen(p)>=sizeof(root))die("root too long");
 strcpy(root,p);
 if(__real_mkdir(root,0700)&&errno!=EEXIST)die("root mkdir");
 for(i=0;i<sizeof(dirs)/sizeof(*dirs);i++){path(name,sizeof(name),dirs[i]);if(__real_mkdir(name,0700)&&errno!=EEXIST)die("fixture mkdir");}
}
int fixture_borrowed(unsigned int queue){return BORROWED+(int)queue;}
void fixture_foreign_xdp(uint32_t id){set_current(id);}
uint32_t fixture_current_xdp(void){return current();}
static void rules_read(struct rules *r)
{
 char name[1200];int fd;memset(r,0,sizeof(*r));namespace_path(name,sizeof(name),"rules");
 fd=__real_open(name,O_RDONLY|O_CLOEXEC);if(fd<0)return;
 if(pread(fd,r,sizeof(*r),0)!=(ssize_t)sizeof(*r))die("rules read");
 __real_close(fd);
}
static void rules_write(const struct rules *r)
{
 char name[1200];int fd;namespace_path(name,sizeof(name),"rules");
 fd=__real_open(name,O_CREAT|O_RDWR|O_TRUNC|O_CLOEXEC,0600);if(fd<0)die("rules open");
 if(pwrite(fd,r,sizeof(*r),0)!=(ssize_t)sizeof(*r))die("rules write");
 __real_close(fd);
}
int fixture_rule_count(void){struct rules r;int n=0,i;rules_read(&r);for(i=0;i<32;i++)n+=!!r.used[i];return n;}
int fixture_get_rule(unsigned int index,struct ethtool_rx_flow_spec *out)
{struct rules r;unsigned int i,n=0;rules_read(&r);for(i=0;i<32;i++)if(r.used[i]){if(n++==index){*out=r.rule[i];return 0;}}return -1;}
void fixture_replace_rule(const struct ethtool_rx_flow_spec *rule)
{struct rules r;rules_read(&r);if(rule->location>=32)die("rule location");r.used[rule->location]=1;r.rule[rule->location]=*rule;rules_write(&r);}
void fixture_add_foreign_rule(uint32_t ip,uint16_t port)
{
 struct ethtool_rx_flow_spec r={.flow_type=UDP_V4_FLOW,.ring_cookie=6,.location=17};
 r.h_u.udp_ip4_spec.ip4dst=htonl(ip);r.h_u.udp_ip4_spec.pdst=htons(port);
 r.m_u.udp_ip4_spec.ip4dst=0xffffffffU;r.m_u.udp_ip4_spec.pdst=0xffffU;fixture_replace_rule(&r);
}
static int count_pins(const char *dir,const char *corrupt)
{
 DIR *d=opendir(dir);struct dirent *e;int n=0;if(!d)return 0;
 while((e=readdir(d))) {
  char name[1400];struct stat st;int fd;
  if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;
  if(snprintf(name,sizeof(name),"%s/%s",dir,e->d_name)>=(int)sizeof(name))die("pin path");
  if(lstat(name,&st))die("pin stat");
  if(S_ISDIR(st.st_mode))n+=count_pins(name,corrupt);
  else {
   n++;
   if(corrupt && !strcmp(e->d_name,corrupt)){
    uint32_t id=0;fd=__real_open(name,O_WRONLY|O_TRUNC|O_CLOEXEC);if(fd<0)die("pin corrupt");
    if(write(fd,&id,sizeof(id))!=(ssize_t)sizeof(id))die("pin corrupt write");
    __real_close(fd);
   }
  }
 }
 closedir(d);return n;
}
int fixture_pin_count(void){char name[1200];path(name,sizeof(name),"sys/fs/bpf");return count_pins(name,NULL);}
int fixture_corrupt_pin(const char *name){char dir[1200];path(dir,sizeof(dir),"sys/fs/bpf");return count_pins(dir,name);}

int __wrap_open(const char *p,int flags,...)
{
 char name[1400];mode_t mode=0;int fd;va_list ap;
 if(flags&O_CREAT){va_start(ap,flags);mode=(mode_t)va_arg(ap,int);va_end(ap);}
 fd=__real_open(translated(p,name,sizeof(name)),flags,mode);
 if(fd>=0 && fd<MAX_FD && (!strcmp(p,"/proc/thread-self/ns/net")||!strcmp(p,"/proc/self/ns/net")))ns_fd[fd]=fixture_netns;
 return fd;
}
int __wrap_open64(const char *p,int flags,...)
{va_list ap;mode_t mode=0;if(flags&O_CREAT){va_start(ap,flags);mode=(mode_t)va_arg(ap,int);va_end(ap);}return __wrap_open(p,flags,mode);}
int __wrap_openat(int dir,const char *p,int flags,...)
{
 char name[1400];va_list ap;mode_t mode=0;if(flags&O_CREAT){va_start(ap,flags);mode=(mode_t)va_arg(ap,int);va_end(ap);}
 return __wrap_open(at_path(dir,p,name,sizeof(name)),flags,mode);
}
int __wrap_mkdir(const char *p,mode_t mode){char name[1400];return __real_mkdir(translated(p,name,sizeof(name)),mode);}
int __wrap_mkdirat(int dir,const char *p,mode_t mode)
{char name[1400];return __wrap_mkdir(at_path(dir,p,name,sizeof(name)),mode);}
int __wrap_rmdir(const char *p){char name[1400];return __real_rmdir(translated(p,name,sizeof(name)));}
int __wrap_stat(const char *p,struct stat *st){char name[1400];return __real_stat(translated(p,name,sizeof(name)),st);}
int __wrap_lstat(const char *p,struct stat *st){char name[1400];return __real_lstat(translated(p,name,sizeof(name)),st);}
int __wrap_fstatat(int dir,const char *p,struct stat *st,int flags)
{char name[1400],mapped[1500];const char *full=at_path(dir,p,name,sizeof(name));return __real_fstatat(AT_FDCWD,translated(full,mapped,sizeof(mapped)),st,flags);}
static void pin_removed(const char *p)
{
 int fd;uint32_t id;struct object o;
 fd=__real_open(p,O_RDONLY|O_CLOEXEC);if(fd<0)return;
 if(read(fd,&id,sizeof(id))==(ssize_t)sizeof(id)&&!object_read(id,&o)) {if(o.pins)o.pins--;object_write(&o);}
 __real_close(fd);
}
int __wrap_unlink(const char *p)
{char name[1400];const char *mapped=translated(p,name,sizeof(name));pin_removed(mapped);return __real_unlink(mapped);}
int __wrap_unlinkat(int dir,const char *p,int flags)
{
 char name[1400],base[1200],fdpath[64];ssize_t n;
 if(*p=='/')return __wrap_unlink(p);
 snprintf(fdpath,sizeof(fdpath),"/proc/self/fd/%d",dir);n=readlink(fdpath,base,sizeof(base)-1);
 if(n>0){base[n]=0;snprintf(name,sizeof(name),"%s/%s",base,p);pin_removed(name);}
 return __real_unlinkat(dir,p,flags);
}
int __wrap_fstat(int fd,struct stat *st)
{
 int queue=socket_queue(fd);
 if(queue>=0){memset(st,0,sizeof(*st));st->st_mode=S_IFSOCK|0600;st->st_ino=0x123450+queue;st->st_uid=geteuid();return 0;}
 if(__real_fstat(fd,st))return -1;
 if(fd<MAX_FD&&ns_fd[fd]){st->st_dev=900;st->st_ino=ns_fd[fd];}return 0;
}
int __wrap_fstat64(int fd,struct stat64 *st)
{
 struct stat value;int ret=__wrap_fstat(fd,&value);
 if(!ret)fixture_copy_stat64(st,&value);
 return ret;
}
int __wrap_close(int fd)
{
 uint32_t id=fd>=0&&fd<MAX_FD?fd_object[fd]:0;int ret;
 if(fd>=BORROWED && fd<BORROWED+4096){errno=EBADF;return -1;}
 if(fd==CONTROL||fd==DIAG)return 0;
 if(fd>=0&&fd<MAX_FD){fd_object[fd]=0;ns_fd[fd]=0;fd_socket[fd]=0;socket_ns[fd]=0;}
 ret=__real_close(fd);if(id)maybe_detach(id);return ret;
}
int __wrap_fstatfs(int fd,struct statfs *st)
{
 char p[1400],fdpath[64];ssize_t n;int ret=__real_fstatfs(fd,st);
 snprintf(fdpath,sizeof(fdpath),"/proc/self/fd/%d",fd);n=readlink(fdpath,p,sizeof(p)-1);
 if(!ret&&n>=0){p[n]=0;if(strstr(p,"/sys/fs/bpf"))st->f_type=BPF_FS_MAGIC;}return ret;
}
int __wrap_statfs(const char *p,struct statfs *st)
{char name[1400];int ret=__real_statfs(translated(p,name,sizeof(name)),st);if(!ret&&strstr(p,"/sys/fs/bpf"))st->f_type=BPF_FS_MAGIC;return ret;}
int __wrap_fstatfs64(int fd,struct statfs64 *st)
{
 struct statfs value;int ret=__wrap_fstatfs(fd,&value);
 if(!ret)fixture_copy_statfs64(st,&value);
 return ret;
}
int __wrap_statfs64(const char *p,struct statfs64 *st)
{
 struct statfs value;int ret=__wrap_statfs(p,&value);
 if(!ret)fixture_copy_statfs64(st,&value);
 return ret;
}
int __wrap_fcntl(int fd,int cmd,...)
{
 va_list ap;long arg=0;int n;
 if(cmd!=F_GETFD&&cmd!=F_GETFL){va_start(ap,cmd);arg=va_arg(ap,long);va_end(ap);}
 if(socket_queue(fd)>=0 && (cmd==F_DUPFD || cmd==F_DUPFD_CLOEXEC))return duplicate_socket(fd,cmd,arg);
 if(fd>=BORROWED && fd<BORROWED+4096){if(cmd==F_GETFD)return FD_CLOEXEC;errno=EINVAL;return -1;}
 n=__real_fcntl(fd,cmd,arg);
 if(n>=0&&(cmd==F_DUPFD||cmd==F_DUPFD_CLOEXEC)&&n<MAX_FD&&fd<MAX_FD){fd_object[n]=fd_object[fd];ns_fd[n]=ns_fd[fd];fd_socket[n]=fd_socket[fd];socket_ns[n]=socket_ns[fd];}
 return n;
}
int __wrap_fcntl64(int fd,int cmd,...)
{
 va_list ap;long arg=0;
 if(cmd!=F_GETFD&&cmd!=F_GETFL){va_start(ap,cmd);arg=va_arg(ap,long);va_end(ap);}
 return __wrap_fcntl(fd,cmd,arg);
}
unsigned int __wrap_if_nametoindex(const char *p){if(!strcmp(p,"fixture0"))return 7;errno=ENODEV;return 0;}
int __wrap_socket(int domain,int type,int protocol)
{(void)type;if(domain==AF_INET&&protocol==0)return CONTROL;if(domain==AF_NETLINK&&protocol==NETLINK_SOCK_DIAG){reply_index=0;return DIAG;}errno=EAFNOSUPPORT;return -1;}
int __wrap_bind(int fd,const struct sockaddr *p,socklen_t n){(void)p;(void)n;if(fd==DIAG)return 0;errno=EINVAL;return -1;}
int __wrap_connect(int fd,const struct sockaddr *p,socklen_t n){return __wrap_bind(fd,p,n);}
int __wrap_getsockname(int fd,struct sockaddr *p,socklen_t *n)
{struct sockaddr_nl a={.nl_family=AF_NETLINK,.nl_pid=1234};if(fd==DIAG&&*n>=sizeof(a)){memcpy(p,&a,sizeof(a));*n=sizeof(a);return 0;}errno=EOPNOTSUPP;return -1;}
int __wrap_setsockopt(int fd,int level,int opt,const void *v,socklen_t n)
{(void)level;(void)opt;(void)v;(void)n;if(fd==DIAG)return 0;errno=ENOPROTOOPT;return -1;}
int __wrap_getsockopt(int fd,int level,int opt,void *v,socklen_t *n)
{
 uint64_t cookie;int value,queue=socket_queue(fd);int borrowed=queue>=0;
 if(level==SOL_SOCKET&&opt==SO_NETNS_COOKIE&&(borrowed||fd==CONTROL)){cookie=borrowed&&fd<MAX_FD&&fd_socket[fd]?socket_ns[fd]:fixture_netns;memcpy(v,&cookie,8);*n=8;return 0;}
 if(borrowed&&level==SOL_SOCKET&&opt==SO_DOMAIN){value=AF_XDP;memcpy(v,&value,4);*n=4;return 0;}
 if(borrowed&&level==SOL_SOCKET&&opt==SO_TYPE){value=SOCK_RAW;memcpy(v,&value,4);*n=4;return 0;}
 if(borrowed&&level==SOL_SOCKET&&opt==SO_COOKIE){diag_queue=(uint32_t)queue;cookie=0x1122334400000000ULL+diag_queue;memcpy(v,&cookie,8);*n=8;return 0;}
 if(borrowed&&level==SOL_XDP&&opt==XDP_OPTIONS){struct xdp_options o={.flags=XDP_OPTIONS_ZEROCOPY};memcpy(v,&o,sizeof(o));*n=sizeof(o);return 0;}
 errno=ENOPROTOOPT;return -1;
}
static ssize_t sent(const void *p,size_t n)
{if(n>=sizeof(struct nlmsghdr))sequence=((const struct nlmsghdr *)p)->nlmsg_seq;return (ssize_t)n;}
ssize_t __wrap_sendmsg(int fd,const struct msghdr *m,int f)
{(void)f;if(fd!=DIAG){errno=EBADF;return -1;}return sent(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len);}
ssize_t __wrap_sendto(int fd,const void *p,size_t n,int f,const struct sockaddr *a,socklen_t z)
{(void)f;(void)a;(void)z;if(fd!=DIAG){errno=EBADF;return -1;}return sent(p,n);}
ssize_t __wrap_send(int fd,const void *p,size_t n,int f){return __wrap_sendto(fd,p,n,f,NULL,0);}
static ssize_t received(void *p,size_t n)
{
 unsigned char buf[128]={0};struct nlmsghdr *h=(void *)buf;struct xdp_diag_msg *d=NLMSG_DATA(h);struct rtattr *a;struct xdp_diag_info *i;
 h->nlmsg_seq=sequence;h->nlmsg_pid=0;
 if(reply_index++){h->nlmsg_type=NLMSG_DONE;h->nlmsg_len=NLMSG_LENGTH(0);}
 else {
  h->nlmsg_type=SOCK_DIAG_BY_FAMILY;h->nlmsg_flags=NLM_F_MULTI;h->nlmsg_len=NLMSG_LENGTH(sizeof(*d));
  d->xdiag_family=AF_XDP;d->xdiag_type=SOCK_RAW;d->xdiag_ino=0x123450+diag_queue;d->xdiag_cookie[0]=diag_queue;d->xdiag_cookie[1]=0x11223344;
  a=(void *)(buf+NLMSG_ALIGN(h->nlmsg_len));a->rta_type=XDP_DIAG_INFO;a->rta_len=RTA_LENGTH(sizeof(*i));i=RTA_DATA(a);i->ifindex=7;i->queue_id=diag_queue;
  h->nlmsg_len=NLMSG_ALIGN(h->nlmsg_len)+RTA_ALIGN(a->rta_len);
 }
 if(n<h->nlmsg_len){errno=EMSGSIZE;return -1;}memcpy(p,buf,h->nlmsg_len);return h->nlmsg_len;
}
ssize_t __wrap_recvmsg(int fd,struct msghdr *m,int f)
{struct sockaddr_nl a={.nl_family=AF_NETLINK};(void)f;if(fd!=DIAG){errno=EBADF;return -1;}if(m->msg_name&&m->msg_namelen>=sizeof(a))memcpy(m->msg_name,&a,sizeof(a));m->msg_namelen=sizeof(a);m->msg_flags=0;return received(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len);}
ssize_t __wrap_recvfrom(int fd,void *p,size_t n,int f,struct sockaddr *a,socklen_t *z)
{(void)f;(void)a;(void)z;if(fd!=DIAG){errno=EBADF;return -1;}return received(p,n);}
ssize_t __wrap_recv(int fd,void *p,size_t n,int f){return __wrap_recvfrom(fd,p,n,f,NULL,NULL);}

int __wrap_ioctl(int fd,unsigned long request,...)
{
 va_list ap;struct ifreq *ifr;struct ethtool_rxnfc *c;struct rules rules;unsigned int i,count;
 va_start(ap,request);ifr=va_arg(ap,struct ifreq *);va_end(ap);
 if(fd!=CONTROL||request!=SIOCETHTOOL){errno=EOPNOTSUPP;return -1;}
 c=(void *)ifr->ifr_data;if(!c){errno=EINVAL;return -1;}rules_read(&rules);
 switch(c->cmd) {
 case ETHTOOL_GRXRINGS:c->data=8;return 0;
 case ETHTOOL_GRXCLSRLCNT:count=0;for(i=0;i<32;i++)count+=!!rules.used[i];c->rule_cnt=count;c->data=32|RX_CLS_LOC_SPECIAL;return 0;
 case ETHTOOL_GRXCLSRLALL:
  count=0;for(i=0;i<32;i++)count+=!!rules.used[i];if(c->rule_cnt<count){c->rule_cnt=count;errno=EMSGSIZE;return -1;}
  count=0;for(i=0;i<32;i++)if(rules.used[i])c->rule_locs[count++]=i;c->rule_cnt=count;c->data=32;return 0;
 case ETHTOOL_GRXCLSRULE:
  i=c->fs.location;if(i>=32||!rules.used[i]){errno=ENOENT;return -1;}c->fs=rules.rule[i];return 0;
 case ETHTOOL_SRXCLSRLINS:
  if(c->fs.location!=RX_CLS_LOC_ANY){errno=EINVAL;return -1;}
  for(i=0;i<32&&rules.used[i];i++) {}
  if(i==32){errno=ENOSPC;return -1;}
  c->fs.location=i;rules.used[i]=1;rules.rule[i]=c->fs;rules_write(&rules);
  if(fixture_crash_after_insert)_exit(77);
  return 0;
 case ETHTOOL_SRXCLSRLDEL:
  i=c->fs.location;if(i>=32||!rules.used[i]){errno=ENOENT;return -1;}rules.used[i]=0;rules_write(&rules);return 0;
 default:errno=EOPNOTSUPP;return -1;
 }
}

static int bpf_call(int cmd,union bpf_attr *a)
{
 struct object o;uint32_t id=0;int fd;unsigned int i;char name[1400];
 if(cmd==BPF_MAP_CREATE) {
  if(a->key_size>256||a->value_size>512){errno=E2BIG;return -1;}
  memset(&o,0,sizeof(o));o.kind=1;o.id=next_id();o.type=a->map_type;o.key_size=a->key_size;o.value_size=a->value_size;o.max_entries=a->max_entries;o.flags=a->map_flags;
  memcpy(o.name,a->map_name,16);if(object_write(&o))return -1;return object_fd(o.id);
 }
 if(cmd==BPF_PROG_LOAD) {
  const struct bpf_insn *p=(void *)(uintptr_t)a->insns;memset(&o,0,sizeof(o));o.kind=2;o.id=next_id();o.type=a->prog_type;
  for(i=0;i<a->insn_cnt;i++)if(p[i].code==(BPF_LD|BPF_DW|BPF_IMM)&&p[i].src_reg==BPF_PSEUDO_MAP_FD) {
   unsigned int j;uint32_t map=p[i].imm>=0&&p[i].imm<MAX_FD?fd_object[p[i].imm]:0;
   for(j=0;j<o.nr_maps&&o.map_ids[j]!=map;j++) {}
   if(j==o.nr_maps&&o.nr_maps<8)o.map_ids[o.nr_maps++]=map;
  }
  memcpy(o.name,a->prog_name,16);if(object_write(&o))return -1;return object_fd(o.id);
 }
 if(cmd==BPF_LINK_CREATE) {
  if(current()){errno=EBUSY;return -1;}
  memset(&o,0,sizeof(o));o.kind=3;o.id=next_id();o.type=BPF_LINK_TYPE_XDP;o.prog_id=fd_object[a->link_create.prog_fd];o.ifindex=a->link_create.target_ifindex;o.netns=fixture_netns;
  if(object_write(&o))return -1;
  set_current(o.prog_id);return object_fd(o.id);
 }
 if(cmd==BPF_OBJ_PIN) {
  const char *p=(void *)(uintptr_t)a->pathname;id=a->bpf_fd<MAX_FD?fd_object[a->bpf_fd]:0;
  if(!id||object_read(id,&o)){errno=EBADF;return -1;}
  fd=__real_open(translated(p,name,sizeof(name)),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);if(fd<0)return -1;
  if(write(fd,&id,4)!=4)die("pin write");
  __real_close(fd);o.pins++;return object_write(&o);
 }
 if(cmd==BPF_OBJ_GET) {
  const char *p=(void *)(uintptr_t)a->pathname;fd=__real_open(translated(p,name,sizeof(name)),O_RDONLY|O_CLOEXEC);if(fd<0)return -1;
  if(read(fd,&id,4)!=4)id=0;
  __real_close(fd);if(!id){errno=ESTALE;return -1;}return object_fd(id);
 }
 if(cmd==BPF_MAP_GET_FD_BY_ID)return object_fd(a->map_id);
 if(cmd==BPF_PROG_GET_FD_BY_ID)return object_fd(a->prog_id);
 if(cmd==BPF_LINK_GET_FD_BY_ID)return object_fd(a->link_id);
 if(cmd==BPF_OBJ_GET_INFO_BY_FD) {
  void *info=(void *)(uintptr_t)a->info.info;id=a->info.bpf_fd<MAX_FD?fd_object[a->info.bpf_fd]:0;
  if(!id||object_read(id,&o)){errno=EBADF;return -1;}
  if(o.kind==1) {
   struct bpf_map_info mi={.type=o.type,.id=o.id,.key_size=o.key_size,.value_size=o.value_size,.max_entries=o.max_entries,.map_flags=o.flags};
   memcpy(mi.name,o.name,16);if(a->info.info_len>sizeof(mi))a->info.info_len=sizeof(mi);memcpy(info,&mi,a->info.info_len);
  } else if(o.kind==2) {
   struct bpf_prog_info *pi=info;uint64_t maps=pi->map_ids;uint32_t cap=pi->nr_map_ids;struct bpf_prog_info v={.type=o.type,.id=o.id,.nr_map_ids=o.nr_maps,.map_ids=maps};
   if(maps){if(cap<o.nr_maps){errno=ENOSPC;return -1;}memcpy((void *)(uintptr_t)maps,o.map_ids,o.nr_maps*4);}
   memcpy(v.name,o.name,16);if(a->info.info_len>sizeof(v))a->info.info_len=sizeof(v);memcpy(info,&v,a->info.info_len);
  } else {
   struct bpf_link_info li={.type=BPF_LINK_TYPE_XDP,.id=o.id,.prog_id=o.prog_id};li.xdp.ifindex=o.flags&LINK_DETACHED?0:o.ifindex;
   if(a->info.info_len>sizeof(li))a->info.info_len=sizeof(li);
   memcpy(info,&li,a->info.info_len);
  }
  return 0;
 }
 if(cmd==BPF_LINK_DETACH) {
  unsigned int calling_netns;int attached;
  fd=(int)a->link_detach.link_fd;
  id=fd>=0&&fd<MAX_FD?fd_object[fd]:0;
  if(!id) {
   if(__real_fcntl(fd,F_GETFD)<0)errno=EBADF;
   else errno=EINVAL;
   return -1;
  }
  if(object_read(id,&o))return -1;
  if(o.kind!=3||o.type!=BPF_LINK_TYPE_XDP){errno=EINVAL;return -1;}
  if(o.flags&LINK_DETACHED)return 0;
  calling_netns=fixture_netns;fixture_netns=o.netns;
  attached=current()==o.prog_id;
  o.flags|=LINK_DETACHED;
  if(object_write(&o)){fixture_netns=calling_netns;return -1;}
  if(attached)set_current(0);
  fixture_netns=calling_netns;
  return 0;
 }
 if(cmd==BPF_MAP_LOOKUP_ELEM||cmd==BPF_MAP_UPDATE_ELEM||cmd==BPF_MAP_DELETE_ELEM||cmd==BPF_MAP_GET_NEXT_KEY) {
  const void *key=(void *)(uintptr_t)a->key;void *value=(void *)(uintptr_t)a->value;
  id=a->map_fd<MAX_FD?fd_object[a->map_fd]:0;if(!id||object_read(id,&o)||o.kind!=1){errno=EBADF;return -1;}
  if(cmd==BPF_MAP_GET_NEXT_KEY) {
   unsigned int start=0;if(key)for(i=0;i<ROWS;i++)if(o.rows[i].used&&!memcmp(o.rows[i].key,key,o.key_size)){start=i+1;break;}
   for(i=start;i<ROWS;i++)if(o.rows[i].used){memcpy(value,o.rows[i].key,o.key_size);return 0;}
   errno=ENOENT;return -1;
  }
  for(i=0;i<ROWS;i++)if(o.rows[i].used&&!memcmp(o.rows[i].key,key,o.key_size))break;
  if(cmd==BPF_MAP_LOOKUP_ELEM) {
   if(i==ROWS){if(o.type==BPF_MAP_TYPE_ARRAY){memset(value,0,o.value_size);return 0;}errno=ENOENT;return -1;}
   memcpy(value,o.rows[i].value,o.value_size);return 0;
  }
  if(cmd==BPF_MAP_DELETE_ELEM){if(i==ROWS){errno=ENOENT;return -1;}o.rows[i].used=0;return object_write(&o);}
  if(i<ROWS&&(a->flags&BPF_NOEXIST)){errno=EEXIST;return -1;}
  if(i==ROWS&&(a->flags&BPF_EXIST)){errno=ENOENT;return -1;}
  if(i==ROWS){for(i=0;i<ROWS&&o.rows[i].used;i++);if(i==ROWS){errno=ENOSPC;return -1;}}
  o.rows[i].used=1;memcpy(o.rows[i].key,key,o.key_size);memcpy(o.rows[i].value,value,o.value_size);return object_write(&o);
 }
 errno=EOPNOTSUPP;return -1;
}
long __wrap_syscall(long number,...)
{
 va_list ap;long cmd;union bpf_attr *a;
 va_start(ap,number);
 if(number==SYS_bpf){cmd=va_arg(ap,long);a=va_arg(ap,union bpf_attr *);va_end(ap);return bpf_call((int)cmd,a);}
 va_end(ap);errno=EOPNOTSUPP;return -1;
}
int __wrap_bpf_xdp_query_id(int ifindex,int flags,uint32_t *id)
{(void)flags;if(ifindex!=7){errno=ENODEV;return -1;}*id=current();return 0;}
int __wrap_bpf_xdp_query(int ifindex,int flags,struct bpf_xdp_query_opts *opts)
{uint32_t id;int ret=__wrap_bpf_xdp_query_id(ifindex,flags,&id);if(ret)return ret;opts->prog_id=id;opts->drv_prog_id=id;opts->skb_prog_id=id;return 0;}
int __wrap_bpf_xdp_attach(int ifindex,int fd,uint32_t flags,const struct bpf_xdp_attach_opts *opts)
{(void)ifindex;(void)fd;(void)flags;(void)opts;fixture_unconditional_detach++;errno=EPERM;return -1;}
int __wrap_bpf_xdp_detach(int ifindex,uint32_t flags,const struct bpf_xdp_attach_opts *opts)
{return __wrap_bpf_xdp_attach(ifindex,-1,flags,opts);}
