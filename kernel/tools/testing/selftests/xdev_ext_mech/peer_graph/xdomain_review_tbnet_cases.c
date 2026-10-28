// SPDX-License-Identifier: GPL-2.0
/* A successful LOGIN must survive ordinary domain-lock contention.
 * The production trylock-and-EAGAIN regression leaves carrier down forever.
 * Pthreads provide the real lock/barrier; hardware APIs are boundary stubs.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define READ_ONCE(x) (x)
#define TB_TYPE_NHI 1
#define TBNET_RING_SIZE 64
#define TBNET_LOGIN_DELAY 1000
#define TBNET_LOGIN_RETRIES 60
#define msecs_to_jiffies(x) (x)
#define netdev_dbg(...) ((void)0)
#define netdev_err(...) ((void)0)
#define netdev_info(...) ((void)0)
#define tb_port_info(...) ((void)0)

#include <pthread.h>
#include <sched.h>
static void usleep_range(unsigned int lo, unsigned int hi) { (void)lo; (void)hi; sched_yield(); }
struct mutex { pthread_mutex_t lock; };
static struct mutex *watched;
static pthread_mutex_t gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;
static bool reached;
static void notify(struct mutex *m){if(m==watched){pthread_mutex_lock(&gate);reached=1;pthread_cond_signal(&cond);pthread_mutex_unlock(&gate);}}
static int mutex_trylock(struct mutex*m){int r=pthread_mutex_trylock(&m->lock);notify(m);return r==0;}
static void mutex_lock(struct mutex*m){notify(m);assert(!pthread_mutex_lock(&m->lock));}
static void mutex_unlock(struct mutex*m){assert(!pthread_mutex_unlock(&m->lock));}
struct work_struct{int x;}; struct delayed_work{struct work_struct work;};
struct list_head{int x;};struct tb_tunnel{struct list_head list;};
struct tb_switch{bool is_unplugged;}; struct tb_xdomain; struct tb_port{struct tb_xdomain*xdomain;};
struct tb_cm{struct list_head tunnel_list;}; struct tb{struct mutex lock;struct tb_switch*root_switch;struct tb_cm cm;};
struct tb_xdomain{bool is_unplugged;struct tb*tb;struct{struct tb_switch*parent;}dev;unsigned long route;};
static struct tb_port port;
static struct tb_cm*tb_priv(struct tb*t){return &t->cm;} static struct tb_switch*tb_to_switch(struct tb_switch*s){return s;} static struct tb_port*tb_port_at(unsigned long r,struct tb_switch*s){return &port;} static struct tb_port*tb_switch_find_port(struct tb_switch*s,int type){return &port;}
static void tb_disable_clx(struct tb_switch*s){} static void tb_enable_clx(struct tb_switch*s){} static struct tb_tunnel*tb_tunnel_alloc_dma(struct tb*t,struct tb_port*a,struct tb_port*b,int c,int d,int e,int f){static struct tb_tunnel tun;return &tun;} static int tb_tunnel_activate(struct tb_tunnel*t){return 0;} static void tb_tunnel_put(struct tb_tunnel*t){} static void list_add_tail(struct list_head*a,struct list_head*b){}

static int tb_approve_xdomain_paths(struct tb *, struct tb_xdomain *, int, int, int, int);
struct net_device{bool carrier;}; struct tb_ring{int hop;};struct tbnet_ring{struct tb_ring*ring;};
struct tbnet{struct work_struct connected_work;struct delayed_work login_work;struct net_device*dev;struct mutex connection_lock;bool login_sent,login_received;int login_retries;struct tb_xdomain*xd;int local_transmit_path,remote_transmit_path;struct tbnet_ring tx_ring,rx_ring;};
static int queued, stops, releases, system_long_wq;
static int netif_carrier_ok(struct net_device*d){return d->carrier;} static void netif_carrier_on(struct net_device*d){d->carrier=1;} static void netif_start_queue(struct net_device*d){}
static int tb_xdomain_alloc_in_hopid(struct tb_xdomain*x,int p){return p;} static void tb_xdomain_release_in_hopid(struct tb_xdomain*x,int p){releases++;}
static void tb_ring_start(struct tb_ring*r){} static void tb_ring_stop(struct tb_ring*r){stops++;}
static int tbnet_alloc_rx_buffers(struct tbnet*n,int c){return 0;} static int tbnet_alloc_tx_buffers(struct tbnet*n){return 0;} static void tbnet_free_buffers(struct tbnet_ring*r){}
static int tb_xdomain_enable_paths(struct tb_xdomain*x,int a,int b,int c,int d){return tb_approve_xdomain_paths(x->tb,x,a,b,c,d);}
static int tbnet_login_request(struct tbnet*n,int seq){return 0;}
static void queue_work(int q,struct work_struct*w){queued++;} static void queue_delayed_work(int q,struct delayed_work*w,unsigned long d){queued++;}


/* ACTUAL_PRODUCTION_BODIES */

static void*worker(void*p){tbnet_connected_work(&((struct tbnet*)p)->connected_work);return NULL;}
int main(void){struct tb_switch sw={0};struct tb tb={.root_switch=&sw};struct tb_xdomain xd={.tb=&tb,.dev={.parent=&sw}};struct net_device dev={0};struct tb_ring tx={.hop=1},rx={.hop=2};struct tbnet n={.dev=&dev,.xd=&xd,.login_received=1,.local_transmit_path=1,.remote_transmit_path=2,.tx_ring={&tx},.rx_ring={&rx}};port.xdomain=&xd;pthread_t thread;
 pthread_mutex_init(&tb.lock.lock,0);pthread_mutex_init(&n.connection_lock.lock,0);watched=&tb.lock;
 tbnet_login_work(&n.login_work.work);assert(n.login_sent&&queued==1);queued--;
 pthread_mutex_lock(&tb.lock.lock);pthread_create(&thread,0,worker,&n);
 pthread_mutex_lock(&gate);while(!reached)pthread_cond_wait(&cond,&gate);pthread_mutex_unlock(&gate);
 pthread_mutex_unlock(&tb.lock.lock);pthread_join(thread,0);
 printf("actual tbnet LOGIN succeeded; real pthread TB-lock contention completed; carrier=%u queued=%d ring_stops=%d hop_releases=%d\n",dev.carrier,queued,stops,releases);fflush(stdout);
 assert(dev.carrier && queued == 0 && stops == 0 && releases == 0);return 0;}
