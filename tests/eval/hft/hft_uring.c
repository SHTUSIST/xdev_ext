/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "hft_runtime.h"
#ifdef HFT_HAVE_URING
/* The checked-in UAPI is required: no hardcoded SEND_ZC opcode guessing. */
#include "../../../kernel/include/uapi/linux/io_uring.h"
#include <liburing.h>
#include "hft_send_zc.h"
static int publish(struct io_uring *ring)
{
 int n;
 /* Re-entering submit flushes only remaining SQ entries; never rebuild SQEs. */
 do {n=io_uring_submit(ring);} while(n==-EINTR);
 return n<0?n:0;
}
static int queue_read(struct io_uring *ring,struct hft_buffer *b,struct hft_actor *a,int fd,unsigned group)
{
 const struct hft_config *c=a->c;struct io_uring_sqe *sqe=io_uring_get_sqe(ring);
 uint64_t token=((uint64_t)group*c->depth+b->life.index+1)*2;
 uint64_t offset=c->source_offset+((uint64_t)a->id*c->burst*c->bursts+group)*c->payload;
 if(!sqe||hft_slot_read_begin(&b->life,token)) return -1;
 b->group=group;
 io_uring_prep_read_fixed(sqe,fd,b->payload,c->payload,offset,b->life.index);
 sqe->user_data=token;a->counts.reads++;
 return 0;
}
int hft_uring(struct hft_actor *a)
{
 const struct hft_config *c=a->c;struct io_uring ring;
 struct hft_buffer slots[8]={0};struct iovec iov[8];struct io_uring_probe *probe=NULL;
 hft_setup_begin(a);
 unsigned allocated=0;int fd=-1,sock=-1,ctl=-1,initialized=0,registered=0,ret=4,unsafe=0;
 fd=open(c->source_block?c->source_block:c->reference,O_RDONLY|O_CLOEXEC|(c->source_block?O_DIRECT:0));
 sock=hft_data_connect(c);ctl=hft_connect(c->control_ip,c->control_port);
 for(;allocated<c->depth;allocated++) {
  if(hft_allocate(&slots[allocated],allocated,c->payload)) break;
  iov[allocated]=(struct iovec){.iov_base=slots[allocated].allocation,.iov_len=slots[allocated].bytes};
 }
 if(fd<0||sock<0||ctl<0||allocated!=c->depth) goto setup_done;
 if(io_uring_queue_init(c->depth*4,&ring,0)<0) goto setup_done;
 initialized=1;probe=io_uring_get_probe_ring(&ring);
 if(!probe||!io_uring_opcode_supported(probe,IORING_OP_READ_FIXED)||!io_uring_opcode_supported(probe,IORING_OP_SEND_ZC)) goto setup_done;
 if(io_uring_register_buffers(&ring,iov,c->depth)<0) goto setup_done;
 registered=1;a->counts.registrations++;ret=hft_history_setup(a)?4:0;
 setup_done:
 if(ret) atomic_store(a->startup_error,4);
 pthread_barrier_wait(a->barrier);
 if(atomic_load(a->startup_error)) {ret=4;goto out;}
 ret=1;hft_setup_done(a);
 for(unsigned burst=0;burst<c->bursts;burst++) {
  hft_burst_begin(a,burst);
  unsigned next=0,done=0;
  for(unsigned i=0;i<c->depth && next<c->burst;i++,next++)
   if(queue_read(&ring,&slots[(burst*c->burst+next)%c->depth],a,fd,burst*c->burst+next)) goto unknown;
  if(publish(&ring)) goto unknown;
  while(done<c->burst) {
   struct io_uring_cqe *ptr,cqe;struct hft_buffer *b=NULL;int n;
   struct __kernel_timespec timeout={.tv_sec=20};
   do {n=io_uring_wait_cqe_timeout(&ring,&ptr,&timeout);} while(n==-EINTR);
   if(n<0) goto unknown;
   cqe=*ptr;io_uring_cqe_seen(&ring,ptr);
   for(unsigned i=0;i<c->depth;i++) if(slots[i].life.token==cqe.user_data) {b=&slots[i];break;}
   if(!b) goto unknown;
   if(b->life.phase==HFT_READ_PENDING) {
    struct io_uring_sqe *sqe;
    a->counts.read_cqes++;
    if(cqe.flags || hft_slot_read_complete(&b->life,cqe.user_data,cqe.res,c->payload)||hft_encode(b,a,b->group)) goto unknown;
    sqe=io_uring_get_sqe(&ring);
    if(!sqe||hft_slot_send_begin(&b->life,cqe.user_data+1,c->payload+40)) goto unknown;
    prep_send_zc_fixed(sqe,sock,b->payload-40,c->payload+40,MSG_NOSIGNAL,b->life.index);
    sqe->user_data=b->life.token;a->counts.sends++;
    if(publish(&ring)) goto unknown;
   } else {
    if(wait_zc_cqes(&b->life,&cqe,&a->counts)) goto unknown;
    if(hft_slot_reusable(&b->life)) {
     if(hft_history_commit(a,b,b->group)||(!c->measured&&!hft_buffer_ok(b,c->payload))) goto unknown;
     done++;
     while(next<c->burst&&hft_slot_reusable(&slots[(burst*c->burst+next)%c->depth].life)) {
      struct hft_buffer *ready=&slots[(burst*c->burst+next)%c->depth];
      if(queue_read(&ring,ready,a,fd,burst*c->burst+next++)) goto unknown;
      if(publish(&ring)) goto unknown;
     }
    }
   }
  }
  /* Quiescence also dispatches unexpected terminal duplicates. */
  {struct io_uring_cqe *extra;if(io_uring_peek_cqe(&ring,&extra)==0) goto unknown;}
  hft_burst_release(a,burst);
  if(hft_receipt(ctl,a,burst*c->burst)) goto out;
  hft_burst_done(a,burst);
 }
 ret=0;goto out;
 unknown:
 /* An accepted request is never replayed. This error path conservatively retains
  * existing tokens; it does not claim cancellation/drain evidence.
  * If terminal evidence cannot be established, retain buffers and ring refs;
  * no unregister/free or successful release is reported. Kernel pins survive
  * process teardown until its own authoritative request completion. */
 unsafe=1;
 for(unsigned i=0;i<c->depth;i++) if(!hft_slot_reusable(&slots[i].life)) hft_slot_unknown(&slots[i].life);
 fputs("{\"status\":\"error\",\"diagnostic\":\"accepted io_uring ownership UNKNOWN; allocations retained\"}\n",stderr);
 out:
 hft_teardown_begin(a);
 if(probe) io_uring_free_probe(probe);
 if(!unsafe) {
  if(registered && io_uring_unregister_buffers(&ring)<0) ret=1;
  if(initialized) io_uring_queue_exit(&ring);
  for(unsigned i=0;i<allocated;i++) {if(!c->measured&&!hft_buffer_ok(&slots[i],c->payload)) ret=1;free(slots[i].allocation);}
  if(fd>=0) close(fd);
  if(sock>=0) close(sock);
 }
 if(ctl>=0) close(ctl);
 hft_teardown_done(a);
 return ret;
}
#else
int hft_uring(struct hft_actor *a)
{ atomic_store(a->startup_error,4);pthread_barrier_wait(a->barrier);return 4; }
#endif
