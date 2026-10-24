/* SPDX-License-Identifier: GPL-2.0-only */
/* Host-only allocator/refcount/queue-result boundaries for actual parent C bodies.
 * No device, command emulation, DMA, VM, timing or performance measurement. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#define CONFIG_XDEV_EXT_MECH 1
#define netdev_err(d,...) ((void)(d))
typedef unsigned short u16;
#define THIS_MODULE ((void*)1)
#define __rcu
#define lockdep_is_held(p) true
#define mlx5e_state_dereference(p,x) (x)
#define rcu_replace_pointer(p,v,c) ({__typeof__(p) old=(p);(p)=(v);old;})
#define spin_lock_irqsave(l,f) do{(void)(l);(f)=0;}while(0)
#define spin_unlock_irqrestore(l,f) do{(void)(l);(void)(f);}while(0)
#define MLX5E_CHANNEL_STATE_XSK 0
struct list_head {struct list_head *next,*prev;};
#define INIT_LIST_HEAD(h) do{(h)->next=(h);(h)->prev=(h);}while(0)
static void list_add_tail(struct list_head *n,struct list_head *h){n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static int mlx5e_peer_owner_lock;
static struct list_head mlx5e_peer_quarantine={&mlx5e_peer_quarantine,&mlx5e_peer_quarantine};
struct device {int refs;};
struct devlink {int refs;};
struct net_device {int refs;};
struct mlx5_core_dev {struct device *device;struct devlink *devlink;};
struct mlx5e_channel;
struct mlx5e_params {unsigned num_channels;};
struct mlx5e_priv {bool peer_quarantined;int state_lock;struct {struct mlx5e_params params;struct mlx5e_channel **c;} channels;};
struct mlx5e_channel;
struct mlx5e_txqsq {struct mlx5e_channel *channel;struct list_head peer_quarantine_node;int result,cq;};
struct rq {int result,cq;};
struct ico {int recover_work,cq;};
struct mlx5e_channel {struct devlink *peer_devlink;bool peer_quarantined,peer_napi_deleted;
 struct list_head peer_quarantine_node,peer_quarantine_sqs;
 struct mlx5_core_dev *mdev;struct mlx5e_priv *priv;struct net_device *netdev;
 bool xdp;unsigned long state[1];int num_tc,napi,icosq_recovery_lock;
 struct rq rq;struct {int cq;} rq_xdpsq;struct ico icosq,async_icosq;
 struct mlx5e_txqsq sq[2],**qos_sqs;int qos_sqs_size;void *xdpsq;
};
static int module_refs,deny_module,deny_devlink,rq_closes,sq_closes,cq_closes,napi_deletes,channel_frees,qos_frees;
static struct mlx5e_channel *active_channel;
static struct mlx5e_txqsq *active_qos;
static bool try_module_get(void *p){assert(p);if(deny_module)return false;module_refs++;return true;}
static void module_put(void *p){assert(p&&module_refs>0);module_refs--;}
static struct devlink *priv_to_devlink(struct mlx5_core_dev *m){return m->devlink;}
static struct devlink *devlink_try_get(struct devlink *d){if(deny_devlink)return NULL;d->refs++;return d;}
static void devlink_put(struct devlink *d){assert(d->refs>1);d->refs--;}
static void dev_hold(struct net_device *d){d->refs++;}
static void dev_put(struct net_device *d){assert(d->refs>1);d->refs--;}
static struct device *get_device(struct device *d){d->refs++;return d;}
static void put_device(struct device *d){assert(d->refs>1);d->refs--;}
static int mlx5e_close_rq(struct rq *r){rq_closes++;return r->result;}
static int mlx5e_close_txqsq(struct mlx5e_txqsq *s){sq_closes++;return s->result;}
static void cancel_work_sync(int *p){(void)p;}
static void mlx5e_close_xdpsq(void *p){(void)p;}
static void mlx5e_close_icosq(void *p){(void)p;}
static void mutex_destroy(void *p){(void)p;}
static void mlx5e_close_cq(int *p){(void)p;cq_closes++;}
static void mlx5e_close_xdpredirect_sq(void *p){(void)p;}
static void mlx5e_close_tx_cqs(struct mlx5e_channel *c){cq_closes+=c->num_tc;}
static void mlx5e_close_xsk(struct mlx5e_channel *c){(void)c;}
static bool test_bit(int b,unsigned long *s){return !!(*s&(1UL<<b));}
static void netif_napi_del_locked(int *p){(void)p;napi_deletes++;}
static void synchronize_rcu(void){}
static void release_memory(void *p){if(p==active_channel)channel_frees++;if(p==active_qos)qos_frees++;free(p);}
#define kvfree release_memory
#define kfree release_memory
