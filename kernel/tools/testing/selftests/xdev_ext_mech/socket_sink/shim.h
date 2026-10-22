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
#include "include/uapi/linux/xdev_ext_mech.h"
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
#define GFP_KERNEL 0
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,y) ((x)=(y))
#define TCP_ESTABLISHED 1
#define SEND_SHUTDOWN 2
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define XDEV_EXT_MECH_F_HELD 1
#define XDEV_EXT_MECH_F_INFLIGHT 2
static void *kzalloc(size_t n,int g) {(void)g;return calloc(1,n);}
static void *kvcalloc(size_t n,size_t z,int g) {(void)g;return calloc(n,z);}
#define kfree free
#define kvfree free
struct udp_sock {bool cork;int pending;u32 gso_size;};
struct sock {int sk_family,sk_protocol,sk_state,sk_shutdown;struct udp_sock udp;};
struct socket {int type,fd;struct sock *sk;};
struct file {struct socket *sock;};
static struct socket *sock_from_file(struct file *f) {return f->sock;}
#define udp_sk(sk) (&(sk)->udp)
#define udp_test_bit(flag,sk) ((sk)->udp.cork)
struct kvec {void *iov_base;size_t iov_len;};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;};
struct xdev_ext_mech_pool {u32 frame_size,nr_frames;u8 state[256];};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout l;u32 depth;bool admits;};
struct xdev_ext_mech_stage {void *priv;struct file *file;struct xdev_ext_mech_session *s;u32 direction;};
struct xdev_ext_mech_batch {u32 nr,bytes,slot;u64 ticket;struct xdev_ext_mech_frame f[32];int status;u64 completed_ticket;u32 completions;};
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
static int forced_send = 999999,send_calls,last_send_flags;
/* The independent credential oracle replaces this section completely. */
struct cred {unsigned refs;};
static struct cred host_cred = {.refs=1};
static const struct cred *host_active_cred = &host_cred;
static inline const struct cred *get_current_cred(void)
{((struct cred *)host_active_cred)->refs++;return host_active_cred;}
static inline void put_cred(const struct cred *cred)
{assert(cred && cred->refs>1);((struct cred *)cred)->refs--;}
static inline const struct cred *override_creds(const struct cred *cred)
{const struct cred *old=host_active_cred;host_active_cred=cred;return old;}
static inline void revert_creds(const struct cred *cred) {host_active_cred=cred;}
static int kernel_sendmsg(struct socket *s,struct msghdr *m,struct kvec *v,size_t n,size_t bytes){
 struct iovec iov[32];size_t i;ssize_t rc;
 send_calls++;last_send_flags=m->msg_flags;
 if(forced_send!=999999)return forced_send;
 for(i=0;i<n;i++){iov[i].iov_base=v[i].iov_base;iov[i].iov_len=v[i].iov_len;}
 m->msg_iov=iov;m->msg_iovlen=n;rc=sendmsg(s->fd,m,m->msg_flags);
 if(rc<0)return -errno;
 assert((size_t)rc<=bytes);return rc;
}
