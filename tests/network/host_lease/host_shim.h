/* Controlled host boundaries only. All tested socket/family bodies are extracted. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>
typedef __u8 u8; typedef __u16 u16; typedef __u32 u32; typedef __u64 u64; typedef __s32 s32;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define EXPORT_SYMBOL_GPL(x)
#define GFP_KERNEL 0
#define NSEC_PER_MSEC 1000000ULL
#define THIS_MODULE NULL
#define TCP_ESTABLISHED 1
#define SEND_SHUTDOWN 2
#define RCV_SHUTDOWN 1
#define CORK 1
#define GRO_ENABLED 2
#define ENCAP_ENABLED 4
#define udp_test_bit(b,s) ((s)->udp_flags & (b))
#define udp_sk(s) (s)
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096L)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
typedef int spinlock_t;
#define spin_lock_init(p) (*(p)=0)
#define spin_lock_irqsave(p,f) do { (f)=0; } while(0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); } while(0)
static int callback_locks;
#define read_lock_bh(p) (++callback_locks)
#define read_unlock_bh(p) (--callback_locks)
#define write_lock_bh(p) (++callback_locks)
#define write_unlock_bh(p) (--callback_locks)
struct sock { int sk_family,sk_protocol,sk_shutdown,sk_state; u32 udp_flags,pending,gso_size; void *sk_user_data; void (*sk_data_ready)(struct sock *); int sk_callback_lock; };
struct socket { struct sock *sk; int type; };
struct file { struct socket *socket; int refs; };
struct cred { int id; };
struct kvec { void *iov_base; size_t iov_len; };
struct pci_dev; struct module; struct page; struct xdev_ext_mech_pool_ops;
struct xdev_ext_mech_session; struct xdev_ext_mech_class_ops;
#include "types.inc"
#include "xdev_ext_mech_lifecycle.h"
#define XDEV_EXT_MECH_LOAD_U8(p) __atomic_load_n(p,__ATOMIC_RELAXED)
/* The primitive is extracted below by run.py, not reimplemented here. */
#include <linux/xdev_ext_peer_net_track.h>
#include <linux/xdev_ext_mech_reliable_core.h>
#include "netfam_core.inc"
#define XDEV_EXT_PEER_HOST_TEST
/* Only the unreachable PEER syscall boundary's handle representation. */
struct xdev_ext_peer_fd_lease { struct file *file; struct { void *mapping; u64 dma_address; u32 len; } lease; };
struct xdev_ext_requester { int boundary; };
enum dma_data_direction { DMA_TO_DEVICE=1,DMA_FROM_DEVICE=2 };
struct xdev_ext_mech_batch {
 struct xdev_ext_mech_session *s; struct xdev_ext_mech_batch *parent;
 struct xdev_ext_mech_completion completion; u64 ticket,id,key;
 int status; u32 nr_frames,bytes,produced; bool produced_set,locally_cancelled,sequester;
 struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; struct xdev_ext_mech_pool pool; u32 depth; bool admits; struct xdev_ext_mech_batch *batches; u64 counts[XDEV_EXT_MECH_CNT_NR]; };
static int alloc_calls, alloc_fail, allocations, cred_refs, kicks, completions, claims, peer_calls, requester_calls;
static struct cred worker_cred={1}, caller_cred={2};
static const struct cred *current_cred=&worker_cred;
static void *host_alloc(size_t n) { if (++alloc_calls==alloc_fail) return NULL; void *p=calloc(1,n); if(p) allocations++; return p; }
#define kzalloc(n,g) host_alloc(n)
#define kvcalloc(n,s,g) host_alloc((n)*(s))
static void host_free(void *p) { if(p) { allocations--; free(p); } }
#define kfree(p) host_free(p)
#define kvfree(p) host_free(p)
static struct socket *sock_from_file(struct file *f) {return f?f->socket:NULL;}
static struct file *get_file(struct file *f) {f->refs++;return f;}
static void fput(struct file *f) {assert(f->refs>0);f->refs--;}
static const struct cred *get_current_cred(void) {cred_refs++; return &caller_cred;}
static void put_cred(const struct cred *c) {assert(c==&caller_cred); cred_refs--;}
static const struct cred *override_creds(const struct cred *c) {const struct cred *o=current_cred;current_cred=c;return o;}
static void revert_creds(const struct cred *c) {current_cred=c;}
static bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session *s) {return s->admits;}
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s,enum xdev_ext_mech_counter c,u64 n) {s->counts[c]+=n;}
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *s) {kicks++;}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *s,int e) {s->s->admits=false;}
static u64 ktime_get_boottime_ns(void) {return 5000000;}
static unsigned long msecs_to_jiffies(unsigned long n) {return n;}
static int xdev_ext_requester_bind(struct xdev_ext_requester *r,struct xdev_ext_mech_stage *s,struct pci_dev *p,u32 f) {requester_calls++; return -EINVAL;}
static void xdev_ext_requester_unbind(struct xdev_ext_requester *r) {requester_calls++;}
/* HOST CPU borrows only: the family's IOU_UMEM host DMA leases are unreachable. */
static int xdev_ext_requester_host_lease(struct xdev_ext_requester *r,u64 o,u32 n,enum dma_data_direction d,u64 *dma) {abort();}
static void xdev_ext_requester_host_release(struct xdev_ext_requester *r,u64 dma,u32 n,bool q) {abort();}
static int xdev_ext_requester_bind_host(struct xdev_ext_requester *r,struct xdev_ext_mech_stage *s,struct pci_dev *p) {abort();}
static void xdev_ext_requester_unbind_host(struct xdev_ext_requester *r) {abort();}
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p) {peer_calls++; return NULL;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p) {peer_calls++;return 0;}
static int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 g,u64 o,u32 n,enum dma_data_direction d,struct xdev_ext_peer_fd_lease *l) {peer_calls++;return -EINVAL;}
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool q) {peer_calls++;}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool sequester);
#include "core.inc"
#include "netfam.inc"
static int sends, recv_calls, packet_calls, send_result[16], send_results, recv_result[16], recv_flags[16], recv_results;
static int recv_seen_flags[16];static void *recv_seen_ptr[16][2];static size_t recv_seen_nr[16];
static u32 send_indices[16]; static void *send_ptr[16][32]; static size_t send_len[16][32];
static bool stop_after_send;
static struct xdev_ext_mech_session *stop_session;
static int element_callbacks;
static void observe_element_callback(struct xdev_ext_net_elem *e,int status,u32 done,u32 hdr,bool quiet);
static int kernel_sendmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t bytes) {
 assert(current_cred==&caller_cred); assert(m->msg_flags==(MSG_DONTWAIT|MSG_NOSIGNAL)); assert(n<=32);
 for(size_t i=0;i<n;i++) { send_ptr[sends][i]=v[i].iov_base; send_len[sends][i]=v[i].iov_len; }
 send_indices[sends]=n;
 int ret=sends<send_results?send_result[sends]:(int)bytes;
 sends++; if(stop_after_send) stop_session->admits=false;
 return ret;
}
static int kernel_recvmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t bytes,int flags) {
 assert(current_cred==&caller_cred); assert(flags & MSG_DONTWAIT);
 int j=recv_calls++; if(j>=recv_results) return -EAGAIN;
 recv_seen_flags[j]=flags;recv_seen_nr[j]=n;for(size_t i=0;i<n&&i<2;i++)recv_seen_ptr[j][i]=v[i].iov_base;
 m->msg_flags=recv_flags[j];
 if(recv_result[j]>0) { size_t left=(size_t)recv_result[j];for(size_t i=0;i<n&&left;i++){size_t z=v[i].iov_len<left?v[i].iov_len:left;memset(v[i].iov_base,0x5a,z);left-=z;} }
 return recv_result[j];
}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_call_args *a,s32 *v,struct xdev_ext_mech_hold_intent *h) {
 struct xdev_ext_socket_mech_info *info=(void *)a->info;
 struct xdev_ext_socket_packet_desc *d=(void *)a->scratch;u32 i=info->cursor;
 packet_calls++; *v=info->phase==XDEV_EXT_SOCKET_PACKET_RX_CHECK?XDEV_EXT_MECH_NEXT:XDEV_EXT_MECH_BUILD_SUBMIT;
 *d=(struct xdev_ext_socket_packet_desc){.key=a->b->key,.frame_pos=i,.frame_off=a->frames[i].data_off,.len=a->frames[i].data_len,.relative_offset=i*info->l.seg_len,.header_len=XDEV_EXT_SOCKET_HEADER_SIZE};memset(d->header,0x5a,sizeof(d->header));return 0;
}
static int family_calls;
static int host_family_init(struct xdev_ext_netfam_stage *n,struct xdev_ext_mech_stage *s,const struct xdev_ext_net_member *m,bool rx,u32 h){family_calls++;return xdev_ext_netfam_init(n,s,m,rx,h);}
static int host_family_attach(struct xdev_ext_netfam_stage *n,const struct xdev_ext_mech_stage_uapi *u,u32 f){family_calls++;return xdev_ext_netfam_attach(n,u,f);}
static void host_family_fini(struct xdev_ext_netfam_stage *n){family_calls++;xdev_ext_netfam_fini(n);}
static struct xdev_ext_net_slot *host_family_slot(struct xdev_ext_netfam_stage *n,struct xdev_ext_mech_batch *b){family_calls++;return xdev_ext_netfam_slot_get(n,b);}
static int host_family_post(struct xdev_ext_netfam_stage *n,struct xdev_ext_net_slot *s){family_calls++;return xdev_ext_netfam_post(n,s);}
static void host_family_fill(struct xdev_ext_netfam_stage *n,struct xdev_ext_net_slot **s){family_calls++;xdev_ext_netfam_fill_cqe(n,s);}
#if HOST_AVAILABLE
static int host_family_lease(struct xdev_ext_netfam_stage *n,struct xdev_ext_net_slot *s,u32 i,u32 p,u32 o,u32 l){family_calls++;return xdev_ext_netfam_lease_host(n,s,i,p,o,l);}
#define xdev_ext_netfam_lease_host host_family_lease
#endif
#define xdev_ext_netfam_init host_family_init
#define xdev_ext_netfam_attach host_family_attach
#define xdev_ext_netfam_fini host_family_fini
#define xdev_ext_netfam_slot_get host_family_slot
#define xdev_ext_netfam_post host_family_post
#define xdev_ext_netfam_fill_cqe host_family_fill
#define xdev_ext_net_elem_done observe_element_callback
#include "socket.inc"
#undef xdev_ext_net_elem_done
#undef xdev_ext_netfam_init
#undef xdev_ext_netfam_attach
#undef xdev_ext_netfam_fini
#undef xdev_ext_netfam_slot_get
#undef xdev_ext_netfam_post
#undef xdev_ext_netfam_fill_cqe
#undef xdev_ext_netfam_lease_host
static void observe_element_callback(struct xdev_ext_net_elem *e,int status,u32 done,u32 hdr,bool quiet) {
 struct xdev_ext_net_slot *slot=e->slot;
 struct xdev_ext_socket_stage *ss=slot->ns->st->priv;
 u32 index=xdev_ext_mech_batch_slot(slot->batch);
 assert(current_cred==&worker_cred);assert(quiet);assert(hdr==0);
 assert(done==(status?0:e->len));
#include "publication.inc"
 u64 before[XDEV_EXT_MECH_CNT_NR];memcpy(before,slot->batch->s->counts,sizeof(before));
 element_callbacks++;xdev_ext_net_elem_done(e,status,done,hdr,quiet);
 assert(memcmp(before,slot->batch->s->counts,sizeof(before))==0);
}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool sequester) {
 assert(current_cred==&worker_cred); assert(callback_locks==0);
 assert(xdev_ext_mech_completion_publish(&b->completion,ticket,status)==0);
 b->status=status;b->sequester=sequester;completions++;
}
