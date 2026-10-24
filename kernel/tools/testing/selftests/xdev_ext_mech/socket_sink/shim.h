/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "include/linux/xdev_ext_mech.h"
/* Boundary stubs a given fixture may not call (clang -Wunused-function). */
#define SHIM_INLINE static inline __attribute__((unused))
typedef int32_t s32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
#define GFP_KERNEL 0
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x,y) (*(volatile __typeof__(x) *)&(x)=(y))
#define TCP_ESTABLISHED 1
#define RCV_SHUTDOWN 1
#define SEND_SHUTDOWN 2
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
/* Frame states come from the real include/linux/xdev_ext_mech.h enum. */
/* Allocation boundary: counts calls/frees; shim_fail_alloc_at = N fails the
 * N-th allocation from the last reset (error-path tests). */
static int shim_alloc_calls,shim_free_calls,shim_fail_alloc_at;
SHIM_INLINE bool shim_alloc_fails(void){shim_alloc_calls++;return shim_fail_alloc_at&&shim_alloc_calls==shim_fail_alloc_at;}
SHIM_INLINE void *kzalloc(size_t n,int g) {(void)g;return shim_alloc_fails()?NULL:calloc(1,n);}
SHIM_INLINE void *kvcalloc(size_t n,size_t z,int g) {(void)g;return shim_alloc_fails()?NULL:calloc(n,z);}
SHIM_INLINE void *kcalloc(size_t n,size_t z,int g) {(void)g;return shim_alloc_fails()?NULL:calloc(n,z);}
SHIM_INLINE void *kmalloc(size_t n,int g) {(void)g;return shim_alloc_fails()?NULL:malloc(n);}
SHIM_INLINE void *kmalloc_array(size_t n,size_t z,int g) {(void)g;return shim_alloc_fails()?NULL:calloc(n,z);}
SHIM_INLINE void *kvzalloc(size_t n,int g) {(void)g;return shim_alloc_fails()?NULL:calloc(1,n);}
SHIM_INLINE void kfree(const void *p) {if(p)shim_free_calls++;free((void *)p);}
SHIM_INLINE void kvfree(const void *p) {if(p)shim_free_calls++;free((void *)p);}
struct udp_sock {bool cork,gro,encap;int pending;u32 gso_size;};
/* Kernel rwlock_t model: writer excludes readers; counts lock use. */
typedef struct {int v;} rwlock_t;
static int shim_write_locks,shim_read_locks,shim_read_waiters;
/* Run while the writer holds the lock / right after a reader acquired it
 * (explicit unbind interleavings). */
static void (*shim_write_lock_hook)(void);
static void (*shim_read_lock_hook)(void);
SHIM_INLINE void shim_read_lock(rwlock_t *l)
{__atomic_add_fetch(&shim_read_waiters,1,__ATOMIC_SEQ_CST);
 for(;;){int v=__atomic_load_n(&l->v,__ATOMIC_ACQUIRE);if(v>=0&&__atomic_compare_exchange_n(&l->v,&v,v+1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))break;}
 __atomic_sub_fetch(&shim_read_waiters,1,__ATOMIC_SEQ_CST);__atomic_add_fetch(&shim_read_locks,1,__ATOMIC_RELAXED);
 if(shim_read_lock_hook)shim_read_lock_hook();}
SHIM_INLINE void shim_read_unlock(rwlock_t *l){assert(__atomic_load_n(&l->v,__ATOMIC_ACQUIRE)>0);__atomic_sub_fetch(&l->v,1,__ATOMIC_RELEASE);}
SHIM_INLINE void shim_write_lock(rwlock_t *l)
{for(;;){int v=0;if(__atomic_compare_exchange_n(&l->v,&v,-1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))break;}__atomic_add_fetch(&shim_write_locks,1,__ATOMIC_RELAXED);
 if(shim_write_lock_hook)shim_write_lock_hook();}
SHIM_INLINE void shim_write_unlock(rwlock_t *l){assert(__atomic_load_n(&l->v,__ATOMIC_ACQUIRE)==-1);__atomic_store_n(&l->v,0,__ATOMIC_RELEASE);}
#define read_lock_bh(l) shim_read_lock(l)
#define read_unlock_bh(l) shim_read_unlock(l)
#define read_lock(l) shim_read_lock(l)
#define read_unlock(l) shim_read_unlock(l)
#define write_lock_bh(l) shim_write_lock(l)
#define write_unlock_bh(l) shim_write_unlock(l)
#define write_lock(l) shim_write_lock(l)
#define write_unlock(l) shim_write_unlock(l)
struct sock {int sk_family,sk_protocol,sk_state,sk_shutdown;struct udp_sock udp;
 void (*sk_data_ready)(struct sock *sk);void *sk_user_data;rwlock_t sk_callback_lock;};
/* RCU model: a reader section is counted; synchronize_rcu() waits for none. */
static int shim_rcu_readers,shim_rcu_syncs;
SHIM_INLINE void rcu_read_lock(void){__atomic_add_fetch(&shim_rcu_readers,1,__ATOMIC_SEQ_CST);}
SHIM_INLINE void rcu_read_unlock(void){__atomic_sub_fetch(&shim_rcu_readers,1,__ATOMIC_SEQ_CST);}
SHIM_INLINE void synchronize_rcu(void){shim_rcu_syncs++;while(__atomic_load_n(&shim_rcu_readers,__ATOMIC_SEQ_CST));}
#define rcu_dereference(p) __atomic_load_n(&(p),__ATOMIC_SEQ_CST)
#define rcu_assign_pointer(p,v) __atomic_store_n(&(p),(v),__ATOMIC_SEQ_CST)
#define rcu_dereference_sk_user_data(sk) rcu_dereference((sk)->sk_user_data)
#define rcu_assign_sk_user_data(sk,ptr) rcu_assign_pointer((sk)->sk_user_data,(void *)(ptr))
struct socket {int type,fd;struct sock *sk;};
struct file {struct socket *sock;};
static struct socket *sock_from_file(struct file *f) {return f->sock;}
#define udp_sk(sk) (&(sk)->udp)
/* udp_test_bit(NAME, sk) tests UDP_FLAGS_NAME; unknown names fail to compile. */
#define udp_test_bit(flag,sk) udp_bit_##flag(sk)
#define udp_bit_CORK(sk) ((sk)->udp.cork)
#define udp_bit_GRO_ENABLED(sk) ((sk)->udp.gro)
#define udp_bit_ENCAP_ENABLED(sk) ((sk)->udp.encap)
struct kvec {void *iov_base;size_t iov_len;};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;};
struct xdev_ext_mech_pool {u32 frame_size,nr_frames;u8 state[256];};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout l;u32 depth;bool admits;};
struct xdev_ext_mech_stage {void *priv;struct file *file;struct xdev_ext_mech_session *s;u32 direction;u32 class_id,flags,index;u64 arg0,arg1;};
struct xdev_ext_mech_batch {u32 nr,bytes,slot;u64 ticket;struct xdev_ext_mech_frame f[32];int status;u64 completed_ticket;u32 completions;
 u64 key,id;u32 produced,cancelled,stale,order;};
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->l;}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admits;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){return b->nr;}
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b){return b->bytes;}
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch *b){return b->slot;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *f){if(i>=b->nr)return -ERANGE;*f=b->f[i];return 0;}
static u32 xdev_ext_mech_pool_frame_state(struct xdev_ext_mech_pool *p,u32 i){return i<p->nr_frames?p->state[i]:99;}
static int xdev_ext_mech_batch_status(struct xdev_ext_mech_batch *b){return b->status;}
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 t,int e){assert(t==b->ticket);b->status=e;b->completions++;b->completed_ticket=t;}
/* Socket RX boundary of the common core (API.md 2.2, 3.5-3.7). */
static u32 shim_completion_order;
static int shim_kicks;
static u64 shim_counters[64];
SHIM_INLINE void xdev_ext_mech_batch_complete_produced(struct xdev_ext_mech_batch *b,u64 t,int e,u32 produced)
{if(t!=b->ticket){b->stale++;return;}if(!e&&(!produced||produced>b->bytes))e=-EOVERFLOW;b->status=e;b->produced=e?0:produced;b->completions++;b->completed_ticket=t;b->order=++shim_completion_order;}
SHIM_INLINE void xdev_ext_mech_batch_complete_cancelled(struct xdev_ext_mech_batch *b,u64 t,int e)
{if(t!=b->ticket){b->stale++;return;}b->status=e;b->produced=0;b->cancelled++;b->completions++;b->completed_ticket=t;b->order=++shim_completion_order;}
SHIM_INLINE u32 xdev_ext_mech_batch_produced(const struct xdev_ext_mech_batch *b){return b->produced;}
SHIM_INLINE u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch *b){return b->id;}
SHIM_INLINE u64 xdev_ext_mech_batch_key(const struct xdev_ext_mech_batch *b){return b->key;}
SHIM_INLINE void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st){(void)st;__atomic_add_fetch(&shim_kicks,1,__ATOMIC_SEQ_CST);}
SHIM_INLINE void xdev_ext_mech_count(struct xdev_ext_mech_session *s,enum xdev_ext_mech_counter c,u64 n)
{(void)s;assert((unsigned)c<64);__atomic_add_fetch(&shim_counters[c],n,__ATOMIC_RELAXED);}

struct xdev_ext_mech_call_args {
	u32 member;			/* enum xdev_ext_mech_member */
	u32 callsite;			/* enum xdev_ext_mech_callsite */
	const struct xdev_ext_binding_ctx_v2 *base;
	struct xdev_ext_mech_batch *b;
	u64 batch_id;
	const struct xdev_ext_mech_frame *frames;
	u32 nr_frames;
	u32 frame_size;
	u32 hdr_room;
	u32 batch_frames;
	u32 info_size;
	const void *info;
	u8 *scratch;
	u32 desc_size;
	u32 desc_cap;
	const void *cqe;
	u32 cqe_size;
	u32 cqe_cap;
};
static int (*shim_packet_call)(struct xdev_ext_mech_stage *, const struct xdev_ext_mech_call_args *, s32 *);
SHIM_INLINE int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,
 const struct xdev_ext_mech_call_args *a, s32 *ret, struct xdev_ext_mech_hold_intent *hold)
{(void)hold;return shim_packet_call?shim_packet_call(st,a,ret):-EOPNOTSUPP;}

static int forced_send = 999999,send_calls,last_send_flags;
/* The independent credential oracle replaces this section completely. */
struct cred {unsigned refs;};
static struct cred host_cred = {.refs=1};
static const struct cred *host_active_cred = &host_cred;
SHIM_INLINE const struct cred *get_current_cred(void)
{((struct cred *)host_active_cred)->refs++;return host_active_cred;}
SHIM_INLINE void put_cred(const struct cred *cred)
{assert(cred && cred->refs>1);((struct cred *)cred)->refs--;}
SHIM_INLINE const struct cred *override_creds(const struct cred *cred)
{const struct cred *old=host_active_cred;host_active_cred=cred;return old;}
SHIM_INLINE void revert_creds(const struct cred *cred) {host_active_cred=cred;}
/* RX boundary: recvmsg(2) on the real host socket, MSG_DONTWAIT required.
 * forced_recv overrides the result; recv_hook(rc) runs after the native call
 * returned rc and before kernel_recvmsg returns (explicit interleavings);
 * recv_cred records the subject of each call. */
static int forced_recv = 999999,recv_calls,last_recv_flags;
static size_t last_recv_len;
static const struct cred *recv_cred;
static void (*recv_hook)(int rc);
SHIM_INLINE int kernel_recvmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t len,int flags){
 struct iovec iov[32];struct msghdr h={0};size_t i,total=0;ssize_t rc;
 recv_calls++;last_recv_flags=flags;last_recv_len=len;recv_cred=host_active_cred;
 assert(flags&MSG_DONTWAIT);assert(n>=1&&n<=32);
 for(i=0;i<n;i++){iov[i].iov_base=v[i].iov_base;iov[i].iov_len=v[i].iov_len;total+=v[i].iov_len;}
 assert(total==len);
 if(forced_recv!=999999)rc=forced_recv;
 else{h.msg_iov=iov;h.msg_iovlen=n;rc=recvmsg(s->fd,&h,flags);if(rc<0)rc=-errno;else m->msg_flags=h.msg_flags;}
 if(recv_hook)recv_hook((int)rc);
 return (int)rc;
}
static int kernel_sendmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t bytes){
 struct iovec iov[32];size_t i;ssize_t rc;
 send_calls++;last_send_flags=m->msg_flags;
 if(forced_send!=999999)return forced_send;
 for(i=0;i<n;i++){iov[i].iov_base=v[i].iov_base;iov[i].iov_len=v[i].iov_len;}
 m->msg_iov=iov;m->msg_iovlen=n;rc=sendmsg(s->fd,m,m->msg_flags);
 if(rc<0)return -errno;
 assert((size_t)rc<=bytes);return rc;
}
