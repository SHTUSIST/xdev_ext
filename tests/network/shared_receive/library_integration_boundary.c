/* SPDX-License-Identifier: GPL-2.0 */
/* Library OS adapter. Shared-manager boundary implementation stays v4 bytes. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/if_xdp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "library_integration_boundary.h"
#include "ownership_boundary.h"

#define OWN_XSK_FD 90003
#define MAX_FD 65536
#define RING_ENTRIES 2048U
int manager_socket(int,int,int);
int manager_getsockopt(int,int,int,void *,socklen_t *);
int manager_setsockopt(int,int,int,const void *,socklen_t);
int manager_bind(int,const struct sockaddr *,socklen_t);
int manager_close(int);
int manager_fcntl(int,int,...);
int manager_ioctl(int,unsigned long,...);
long manager_syscall(long,...);
int __real_open(const char *,int,...);

struct mapping {void *base;size_t len;uint64_t offset;int active,is_ring,is_umem;};
static struct mapping mapping[16];
static unsigned int nr_mapping;
static unsigned char xsk_alias[MAX_FD],uring_fd[MAX_FD];
static struct library_observation seen;
static int own_xsk_alive,kernel_created,stop_busy,release_available,delete_failures;
static int payload_prepared,payload_changed;
static void *umem;
static size_t umem_bytes;
static struct xdp_mmap_offsets offsets;

static long error(int value){errno=value;return -1;}
static int socket_alias(int fd)
{return fd==OWN_XSK_FD || (fd>=0 && fd<MAX_FD && xsk_alias[fd]);}
static struct mapping *ring(uint64_t offset)
{
 unsigned int i;
 for(i=0;i<nr_mapping;i++)if(mapping[i].active && mapping[i].is_ring && mapping[i].offset==offset)return &mapping[i];
 return NULL;
}
static int zero_bytes(const void *p,size_t n)
{size_t i;const unsigned char *b=p;for(i=0;i<n;i++)if(b[i])return 0;return 1;}
static int payload_ok(void)
{
 size_t i;const unsigned char *b=umem;
 if(payload_changed)return 0;
 if(!payload_prepared)return 1;
 if(!umem)return 1;
 for(i=0;i<umem_bytes;i++)if(b[i]!=0x5a)return 0;
 return 1;
}
int library_fixture_nonfill_untouched(void)
{
 uint64_t values[]={XDP_PGOFF_RX_RING,XDP_PGOFF_TX_RING,XDP_UMEM_PGOFF_COMPLETION_RING};
 unsigned int i;
 for(i=0;i<3;i++){struct mapping *m=ring(values[i]);if(!m || !zero_bytes(m->base,m->len))return 0;}
 return 1;
}
int library_fixture_rings_unseeded(void)
{
 struct mapping *m=ring(XDP_UMEM_PGOFF_FILL_RING);
 return m && zero_bytes(m->base,m->len) && library_fixture_nonfill_untouched();
}
int library_fixture_fill_valid(void)
{
 struct mapping *m=ring(XDP_UMEM_PGOFF_FILL_RING);uint32_t producer,consumer,count,i,j;uint64_t *addresses;
 if(!m || !umem || !umem_bytes)return 0;
 memcpy(&producer,(char *)m->base+offsets.fr.producer,4);memcpy(&consumer,(char *)m->base+offsets.fr.consumer,4);
 count=producer-consumer;
 if(!count || count>RING_ENTRIES || count>umem_bytes/4096U)return 0;
 addresses=(void *)((char *)m->base+offsets.fr.desc);
 for(i=0;i<count;i++) {
  uint64_t value=addresses[(consumer+i)&(RING_ENTRIES-1)];
  if(value%4096U || value>=umem_bytes || value+4096U>umem_bytes)return 0;
  for(j=0;j<i;j++)if(value==addresses[(consumer+j)&(RING_ENTRIES-1)])return 0;
 }
 return 1;
}
void library_fixture_init(const char *root)
{
 fixture_init(root);
 offsets.rx=(struct xdp_ring_offset){.producer=16,.consumer=32,.desc=128,.flags=48};
 offsets.tx=(struct xdp_ring_offset){.producer=20,.consumer=36,.desc=192,.flags=52};
 offsets.fr=(struct xdp_ring_offset){.producer=24,.consumer=40,.desc=256,.flags=56};
 offsets.cr=(struct xdp_ring_offset){.producer=28,.consumer=44,.desc=320,.flags=60};
}
void library_fixture_payload_prepare(void)
{if(umem){memset(umem,0x5a,umem_bytes);payload_prepared=1;}}
int library_fixture_payload_unchanged(void){return payload_ok();}
struct library_observation library_fixture_observe(void)
{
 struct library_observation value=seen;unsigned int i;value.active_maps=0;value.live_xsk_aliases=0;
 for(i=0;i<nr_mapping;i++)value.active_maps+=mapping[i].active;
 for(i=0;i<MAX_FD;i++)value.live_xsk_aliases+=xsk_alias[i]!=0;
 return value;
}
void library_fixture_stop_retains(void){stop_busy=1;}
void library_fixture_release_available(void){release_available=1;}
void library_fixture_fail_next_rule_delete(void){delete_failures++;}

int __wrap_socket(int domain,int type,int protocol)
{
 if(domain==AF_XDP && type==(SOCK_RAW|SOCK_CLOEXEC) && protocol==0) {
  if(own_xsk_alive)return (int)error(EMFILE);
  own_xsk_alive=1;return OWN_XSK_FD;
 }
 return manager_socket(domain,type,protocol);
}
int __wrap_setsockopt(int fd,int level,int opt,const void *value,socklen_t len)
{
 if(fd==OWN_XSK_FD && level==SOL_XDP) {
  if(opt==XDP_UMEM_REG) {
   const struct xdp_umem_reg *r=value;unsigned int i;
   if(len!=sizeof(*r) || r->chunk_size!=4096 || r->len!=8U*4096U)return (int)error(EINVAL);
   for(i=0;i<nr_mapping;i++)if(mapping[i].active && mapping[i].base==(void *)(uintptr_t)r->addr && mapping[i].len==r->len)break;
   if(i==nr_mapping)return (int)error(EINVAL);
   mapping[i].is_umem=1;umem=mapping[i].base;umem_bytes=mapping[i].len;return 0;
  }
  if((opt==XDP_RX_RING || opt==XDP_TX_RING || opt==XDP_UMEM_FILL_RING || opt==XDP_UMEM_COMPLETION_RING) && len==4 && *(const uint32_t *)value==RING_ENTRIES)return 0;
  return (int)error(EINVAL);
 }
 return manager_setsockopt(fd,level,opt,value,len);
}
int __wrap_getsockopt(int fd,int level,int opt,void *value,socklen_t *len)
{
 if(socket_alias(fd) && level==SOL_XDP) {
  if(opt==XDP_OPTIONS && *len>=sizeof(struct xdp_options)){struct xdp_options o={0};memcpy(value,&o,sizeof(o));*len=sizeof(o);return 0;}
  if(opt==XDP_MMAP_OFFSETS && *len>=sizeof(offsets)){memcpy(value,&offsets,sizeof(offsets));*len=sizeof(offsets);return 0;}
  return (int)error(EINVAL);
 }
 return manager_getsockopt(fd,level,opt,value,len);
}
int __wrap_bind(int fd,const struct sockaddr *address,socklen_t len)
{
 if(fd==OWN_XSK_FD) {
  const struct sockaddr_xdp *a=(const void *)address;
  if(len!=sizeof(*a) || a->sxdp_family!=AF_XDP || a->sxdp_ifindex!=7 || a->sxdp_queue_id!=3 || !(a->sxdp_flags&XDP_COPY) || (a->sxdp_flags&XDP_ZEROCOPY))return (int)error(EINVAL);
  return 0;
 }
 return manager_bind(fd,address,len);
}
static int duplicate(int fd,int command,long arg)
{
 int result=manager_fcntl(fd,command,arg);
 if(result>=0 && result<MAX_FD && (command==F_DUPFD || command==F_DUPFD_CLOEXEC) && socket_alias(fd))xsk_alias[result]=1;
 return result;
}
int __wrap_fcntl(int fd,int command,...)
{
 va_list ap;long arg=0;
 if(command!=F_GETFD && command!=F_GETFL){va_start(ap,command);arg=va_arg(ap,long);va_end(ap);}
 return duplicate(fd,command,arg);
}
int __wrap_fcntl64(int fd,int command,...)
{
 va_list ap;long arg=0;
 if(command!=F_GETFD && command!=F_GETFL){va_start(ap,command);arg=va_arg(ap,long);va_end(ap);}
 return duplicate(fd,command,arg);
}
int __wrap_eventfd(unsigned int initial,int flags)
{(void)flags;if(initial)return (int)error(EINVAL);return __real_open("/dev/null",O_RDWR|O_CLOEXEC);}
int __wrap_close(int fd)
{
 if(fd==OWN_XSK_FD) {
  if(!own_xsk_alive)return (int)error(EBADF);
  if((kernel_created && !seen.kernel_release_observed) || fixture_rule_count() || fixture_current_xdp() || fixture_pin_count())seen.early_backing_release++;
  own_xsk_alive=0;seen.xsk_closes++;return 0;
 }
 if(fd>=0 && fd<MAX_FD)xsk_alias[fd]=0;
 return manager_close(fd);
}
void *__wrap_mmap(void *address,size_t len,int prot,int flags,int fd,off_t offset)
{
 void *p;(void)address;(void)prot;(void)flags;
 if(nr_mapping==16 || (fd!=-1 && fd!=OWN_XSK_FD)){errno=EINVAL;return MAP_FAILED;}
 p=calloc(1,len);if(!p){errno=ENOMEM;return MAP_FAILED;}
 mapping[nr_mapping++]=(struct mapping){.base=p,.len=len,.offset=(uint64_t)offset,.active=1,.is_ring=fd==OWN_XSK_FD};
 return p;
}
void *__wrap_mmap64(void *address,size_t len,int prot,int flags,int fd,off64_t offset)
{return __wrap_mmap(address,len,prot,flags,fd,(off_t)offset);}
int __wrap_munmap(void *address,size_t len)
{
 unsigned int i;
 for(i=0;i<nr_mapping;i++)if(mapping[i].active && mapping[i].base==address) {
  if(mapping[i].len!=len)return (int)error(EINVAL);
  if((kernel_created && !seen.kernel_release_observed) || fixture_rule_count() || fixture_current_xdp() || fixture_pin_count())seen.early_backing_release++;
  if(mapping[i].is_umem) {
   if(!payload_ok())payload_changed=1;
   seen.umem_unmaps++;umem=NULL;
  }
  free(address);mapping[i].active=0;return 0;
 }
 return (int)error(EINVAL);
}
int __wrap_ioctl(int fd,unsigned long request,...)
{
 va_list ap;struct ifreq *ifr;
 va_start(ap,request);ifr=va_arg(ap,struct ifreq *);va_end(ap);
 if(request==SIOCGIFHWADDR){const unsigned char mac[6]={2,0,0,0,0,1};ifr->ifr_hwaddr.sa_family=ARPHRD_ETHER;memcpy(ifr->ifr_hwaddr.sa_data,mac,6);return 0;}
 if(request==SIOCGIFMTU){ifr->ifr_mtu=1500;return 0;}
 if(request==SIOCETHTOOL && ifr && ifr->ifr_data && ((struct ethtool_rxnfc *)ifr->ifr_data)->cmd==ETHTOOL_SRXCLSRLDEL) {
  seen.delete_attempts++;
  if(kernel_created && !seen.kernel_release_observed)seen.early_network_cleanup++;
  if(delete_failures){delete_failures--;return (int)error(EIO);}
 }
 return manager_ioctl(fd,request,ifr);
}
long __wrap_syscall(long number,...)
{
 va_list ap;va_start(ap,number);
 if(number==SYS_io_uring_setup) {
  unsigned int entries=va_arg(ap,unsigned int);struct io_uring_params *p=va_arg(ap,struct io_uring_params *);int fd;
  va_end(ap);if(!entries || !p)return error(EINVAL);
  memset(p,0,sizeof(*p));fd=__real_open("/dev/null",O_RDWR|O_CLOEXEC);
  if(fd>=0 && fd<MAX_FD)uring_fd[fd]=1;
  return fd;
 }
 if(number==SYS_io_uring_register) {
  int fd=va_arg(ap,int);unsigned int opcode=va_arg(ap,unsigned int);void *argument=va_arg(ap,void *);unsigned int count=va_arg(ap,unsigned int);
  struct io_uring_xdev_ext_mech *request=argument;va_end(ap);
  if(fd<0 || fd>=MAX_FD || !uring_fd[fd] || count!=1)return error(EINVAL);
  if(opcode==IORING_REGISTER_XDEV_EXT_UMEM)return 0;
  if(opcode!=IORING_REGISTER_XDEV_EXT_MECH || !request)return error(EOPNOTSUPP);
  if(request->op==XDEV_EXT_MECH_OP_CREATE) {
   struct xdev_ext_mech_create *c=(void *)(uintptr_t)request->arg;seen.create_requests++;
   if(!c || c->abi_version!=XDEV_EXT_MECH_ABI_VERSION || c->pool_kind!=XDEV_EXT_MECH_POOL_XSK || c->pool_fd!=OWN_XSK_FD || c->nr_stages!=1 || c->depth!=1)return error(EINVAL);
   c->session_id=101;kernel_created=1;return 0;
  }
  if(request->op==XDEV_EXT_MECH_OP_START) {
   seen.start_requests++;
   if(library_fixture_fill_valid())seen.start_saw_valid_fill++;
   if(!library_fixture_nonfill_untouched() || !payload_ok())seen.custody_violations++;
   return 0;
  }
  if(request->op==XDEV_EXT_MECH_OP_STOP) {
   seen.stop_requests++;
   if(stop_busy && !release_available)return error(EBUSY);
   seen.kernel_release_observed=1;return 0;
  }
  if(request->op==XDEV_EXT_MECH_OP_STATS) {
   seen.stats_requests++;
   if(release_available){seen.kernel_release_observed=1;return error(ENOENT);}
   return 0;
  }
  return error(EOPNOTSUPP);
 }
 if(number==SYS_bpf) {
  long command=va_arg(ap,long);void *attribute=va_arg(ap,void *);size_t size=va_arg(ap,size_t);
  va_end(ap);return manager_syscall(number,command,attribute,size);
 }
 va_end(ap);return error(EOPNOTSUPP);
}
