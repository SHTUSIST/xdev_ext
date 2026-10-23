/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <sys/stat.h>
/* Isolate the newer product statx layout from older host libc declarations. */
#define statx hft_statx
#define statx_timestamp hft_statx_timestamp
#include "../../../kernel/include/uapi/linux/stat.h"
#undef statx_timestamp
#undef statx
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <linux/if_xdp.h>
#include "hft_runtime.h"
#include "benchmark_policy.h"
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_prog.h"

static uint64_t now_ns(void)
{
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t)) abort();
 return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
void hft_setup_begin(struct hft_actor *a) {if(a->c->measured)a->timing.setup_started=now_ns();}
void hft_setup_done(struct hft_actor *a) {if(a->c->measured)a->timing.setup_completed=now_ns();}
void hft_burst_begin(struct hft_actor *a,unsigned b)
{if(a->c->measured){struct hft_burst_sample *s=&a->timing.samples[b];s->first=(uint64_t)b*a->c->burst+1;s->start_reads=a->counts.reads;s->start_sends=a->counts.sends;s->started=now_ns();}}
void hft_burst_release(struct hft_actor *a,unsigned b)
{if(a->c->measured){struct hft_burst_sample *s=&a->timing.samples[b];s->local_release=now_ns();s->reads=a->counts.reads-s->start_reads;s->sends=a->counts.sends-s->start_sends;}}
void hft_burst_done(struct hft_actor *a,unsigned b)
{if(a->c->measured){struct hft_burst_sample *s=&a->timing.samples[b];s->peer_receipt=now_ns();s->completed=now_ns();}}
void hft_teardown_begin(struct hft_actor *a) {if(a->c->measured&&!a->timing.teardown_started)a->timing.teardown_started=now_ns();}
void hft_teardown_done(struct hft_actor *a) {if(a->c->measured)a->timing.teardown_completed=now_ns();}
int hft_source_info(const char *path)
{
 struct hft_statx sx={0};unsigned sector=0;uint64_t bytes=0;
 int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return 4;
 if(ioctl(fd,BLKSSZGET,&sector)||ioctl(fd,BLKGETSIZE64,&bytes)||
    syscall(__NR_statx,fd,"",AT_EMPTY_PATH,STATX_DIOALIGN,&sx)||!(sx.stx_mask&STATX_DIOALIGN)) {close(fd);return 4;}
 printf("{\"lba_bytes\":%u,\"capacity_bytes\":%llu,\"dio_mem_align\":%u,\"dio_offset_align\":%u}\n",sector,(unsigned long long)bytes,sx.stx_dio_mem_align,sx.stx_dio_offset_align);
 close(fd);return 0;
}
int hft_source_geometry(const struct hft_config *c)
{
 struct hft_statx sx={0};unsigned sector=0;uint64_t bytes=0;
 uint64_t groups=(uint64_t)c->actors*c->burst*c->bursts;
 int fd=open(c->source_block,O_RDONLY|O_CLOEXEC),ret=-1;
 if(fd<0) return -1;
 if(ioctl(fd,BLKSSZGET,&sector)||ioctl(fd,BLKGETSIZE64,&bytes)||!sector||
    c->payload%sector||c->slba>bytes/sector||c->nlb>bytes/sector-c->slba||
    c->nlb<groups*(c->payload/sector)||c->source_offset!=c->slba*sector) goto out;
 /* Refuse unknown DIO alignment instead of silently attempting another path.
  * Product UAPI supplies the named fields even on older host build headers. */
 if(syscall(__NR_statx,fd,"",AT_EMPTY_PATH,STATX_DIOALIGN,&sx)||!(sx.stx_mask&STATX_DIOALIGN)||
    !sx.stx_dio_mem_align||!sx.stx_dio_offset_align||512%sx.stx_dio_mem_align||
    c->payload%sx.stx_dio_offset_align||c->source_offset%sx.stx_dio_offset_align) goto out;
 ret=0;
 out: close(fd);return ret;
}
int hft_allocate(struct hft_buffer *b,unsigned index,unsigned payload)
{
 memset(b,0,sizeof(*b)); b->bytes=4096;
 if(posix_memalign((void **)&b->allocation,4096,b->bytes)) return -1;
 memset(b->allocation,0xa5,512); b->payload=b->allocation+512;
 memset(b->payload+payload,0x5a,4096-512-payload); hft_slot_init(&b->life,index);return 0;
}
int hft_buffer_ok(const struct hft_buffer *b,unsigned payload)
{
 /* Header span [430,512) is written by the encoder, outside both guards. */
 return hft_guards_ok(b->allocation,430,430,0) &&
        hft_guards_ok(b->payload,b->bytes-512,0,payload);
}
static uint32_t crc32c(uint32_t crc,const unsigned char *p,size_t n)
{ for(size_t i=0;i<n;i++) {crc^=p[i];for(unsigned k=0;k<8;k++) crc=(crc>>1)^((crc&1)?0x82f63b78U:0);}return crc;}
int hft_encode(struct hft_buffer *b,const struct hft_actor *a,unsigned group)
{
 if(a->c->measured)return hftb_encode_header(b->payload-40,a->c->session_base+a->id,group+1,a->c->payload);
 struct xdev_ext_mech_peer peer={0};
 struct xdev_ext_mp_tx_seg seg={.session_id=a->c->session_base+a->id,
  .generation=group+1,.count=1,.total_len=a->c->payload,.payload_len=a->c->payload};
 unsigned char *packet=b->payload-82; uint32_t crc;
 if(xdev_ext_mp_tx_encode(packet,&peer,&seg)) return -1;
 crc=crc32c(XDEV_EXT_MP_CRC32C_SEED,packet+42,40);
 crc=crc32c(crc,b->payload,a->c->payload);
 xdev_ext_mp_put_be32(packet+42+36,~crc); return 0;
}
int hft_connect(const char *ip,unsigned port)
{
 int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(port)};
 struct timeval timeout={.tv_sec=20};
 if(fd<0) return -1;
 if(inet_pton(AF_INET,ip,&addr.sin_addr)!=1 || connect(fd,(void *)&addr,sizeof(addr)) ||
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) {close(fd);return -1;}
 return fd;
}
int hft_data_connect(const struct hft_config *c)
{
 struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(c->local_port)},peer={.sin_family=AF_INET,.sin_port=htons(c->peer_port)};
 struct timeval timeout={.tv_sec=20};int fd;
 if(!c->source_block)return hft_connect(c->peer_ip,c->peer_port);
 fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
 if(inet_pton(AF_INET,c->local_ip,&local.sin_addr)!=1||inet_pton(AF_INET,c->peer_ip,&peer.sin_addr)!=1||
    setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,c->ifname,strlen(c->ifname)+1)||bind(fd,(void *)&local,sizeof(local))||
    connect(fd,(void *)&peer,sizeof(peer))||setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) {close(fd);return -1;}
 if(c->measured) {
  int value=1,observed=0;socklen_t length=sizeof(observed);
  if(setsockopt(fd,SOL_SOCKET,SO_NO_CHECK,&value,sizeof(value))||getsockopt(fd,SOL_SOCKET,SO_NO_CHECK,&observed,&length)||length!=sizeof(observed)||observed!=1){close(fd);return -1;}
 }
 return fd;
}
int hft_receipt(int fd,const struct hft_actor *a,unsigned first)
{
 char req[256],reply[512],expected[256];ssize_t n;unsigned i=0;
 int len=snprintf(req,sizeof(req),"{\"op\":\"receipt\",\"actor\":%u,\"first\":%u,\"count\":%u,\"session_base\":%llu}",a->id,first,a->c->burst,(unsigned long long)a->c->session_base);
 do {n=send(fd,req,(size_t)len,0);} while(n<0 && errno==EINTR);
 if(n!=len) return -1;
 do {n=recv(fd,reply,sizeof(reply)-1,0);} while(n<0 && errno==EINTR);
 if(n<=0) return -1;
 reply[n]=0;
 /* The receiver emits compactable fixed-schema JSON; normalize whitespace. */
 for(unsigned j=0;j<(unsigned)n;j++) if(reply[j]!=' ' && reply[j]!='\n') reply[i++]=reply[j];
 reply[i]=0;
 snprintf(expected,sizeof(expected),"{\"status\":\"ok\",\"actor\":%u,\"first\":%u,\"count\":%u,\"validated_bytes\":%u,\"session_base\":%llu}",a->id,first,a->c->burst,a->c->burst*a->c->payload,(unsigned long long)a->c->session_base);
 if(a->c->measured)snprintf(expected,sizeof(expected),"{\"status\":\"received\",\"actor\":%u,\"first\":%u,\"count\":%u,\"received_bytes\":%u,\"session_base\":%llu}",a->id,first,a->c->burst,a->c->burst*a->c->payload,(unsigned long long)a->c->session_base);
 return strcmp(reply,expected)?-1:0;
}
int hft_posix(struct hft_actor *a)
{
 const struct hft_config *c=a->c;struct hft_buffer slots[8]={0};
 int fd=-1,sock=-1,ctl=-1,ret=1;unsigned initialized=0;
 hft_setup_begin(a);
 fd=open(c->source_block?c->source_block:c->reference,O_RDONLY|O_CLOEXEC|(c->source_block?O_DIRECT:0));
 sock=hft_data_connect(c);ctl=hft_connect(c->control_ip,c->control_port);
 for(;initialized<c->depth;initialized++) if(hft_allocate(&slots[initialized],initialized,c->payload)) break;
 /* All actors enter the barrier even on setup failure, preventing deadlock. */
 if(hft_history_setup(a)||fd<0||sock<0||ctl<0||initialized!=c->depth) atomic_store(a->startup_error,1);
 pthread_barrier_wait(a->barrier);
 if(atomic_load(a->startup_error)) goto out;
 hft_setup_done(a);
 for(unsigned burst=0;burst<c->bursts;burst++) {
  hft_burst_begin(a,burst);
  for(unsigned base=0;base<c->burst;base+=c->depth) {
   unsigned count=c->burst-base<c->depth?c->burst-base:c->depth;
   for(unsigned i=0;i<count;i++) {
    unsigned g=burst*c->burst+base+i;struct hft_buffer *b=&slots[g%c->depth];
    uint64_t token=(uint64_t)g*2+1,offset=c->source_offset+((uint64_t)a->id*c->bursts*c->burst+g)*c->payload;
    ssize_t n;
    if(hft_slot_read_begin(&b->life,token)) goto out;
    do {n=pread(fd,b->payload,c->payload,(off_t)offset);} while(n<0&&errno==EINTR);
    a->counts.reads++;
    if(hft_slot_read_complete(&b->life,token,(int)n,c->payload)||hft_encode(b,a,g)) goto out;
   }
   for(unsigned i=0;i<count;i++) {
    unsigned g=burst*c->burst+base+i;struct hft_buffer *b=&slots[g%c->depth];
    struct iovec iov[2]={{.iov_base=b->payload-40,.iov_len=40},{.iov_base=b->payload,.iov_len=c->payload}};
    struct msghdr msg={.msg_iov=iov,.msg_iovlen=2};ssize_t n;
    do {n=sendmsg(sock,&msg,MSG_NOSIGNAL);} while(n<0&&errno==EINTR);
    if(hft_slot_send_begin(&b->life,(uint64_t)g*2+2,c->payload+40)) goto out;
    a->counts.sends++;
    if(hft_slot_cqe(&b->life,(uint64_t)g*2+2,(int)n,0)||hft_history_commit(a,b,g)) goto out;
    if(!c->measured&&!hft_buffer_ok(b,c->payload)) goto out;
   }
  }
  hft_burst_release(a,burst);
  if(hft_receipt(ctl,a,burst*c->burst)) goto out;
  hft_burst_done(a,burst);
 }
 ret=0;
 out:
 hft_teardown_begin(a);
 for(unsigned i=0;i<initialized;i++) {if(!c->measured&&!hft_buffer_ok(&slots[i],c->payload)) ret=1;free(slots[i].allocation);}
 if(fd>=0) close(fd);
 if(sock>=0) close(sock);
 if(ctl>=0) close(ctl);
 hft_teardown_done(a);
 return ret;
}
