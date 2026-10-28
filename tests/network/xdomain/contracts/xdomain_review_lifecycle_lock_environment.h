/* SPDX-License-Identifier: GPL-2.0 */
/* Only scheduling, topology and native tunnel operation boundaries. */
struct tb_port { int id; struct tb_xdomain *xdomain; };
struct tb_switch { struct tb_port port; bool is_unplugged; };
struct tb_tunnel {struct list_head list;struct tb_port *src_port,*dst_port;};
struct tb_cm {struct list_head tunnel_list;};
#define TB_TYPE_NHI 1
#define list_for_each_entry_safe(p,n,h,m) \
 for(p=container_of((h)->next,typeof(*p),m),n=container_of(p->m.next,typeof(*p),m); &p->m!=(h);p=n,n=container_of(n->m.next,typeof(*n),m))
static struct mutex *review_tb_mutex;
static pthread_mutex_t review_gate=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t review_condition=PTHREAD_COND_INITIALIZER;
static bool review_entered,review_continue,review_done,review_worker_started;
static _Thread_local bool review_is_worker,review_hook_passed;
static unsigned review_tunnels,review_tunnels_freed,review_activations;
static void review_before_mutex(struct mutex *m)
{
    if(m!=review_tb_mutex || !review_is_worker || review_hook_passed)return;
    review_hook_passed=true;
    assert(!pthread_mutex_lock(&review_gate));review_entered=true;
    fprintf(stderr,"# barrier: worker reached production TB acquisition (unplugged was false for disconnect)\n");fflush(stderr);
    pthread_cond_broadcast(&review_condition);
    while(!review_continue)assert(!pthread_cond_wait(&review_condition,&review_gate));
    assert(!pthread_mutex_unlock(&review_gate));
}
static void review_cancel_wait(struct work_struct *w)
{
    (void)w;
    if(review_is_worker)return;
    assert(!pthread_mutex_lock(&review_gate));
    while(review_worker_started&&!review_done)assert(!pthread_cond_wait(&review_condition,&review_gate));
    assert(!pthread_mutex_unlock(&review_gate));
}
static struct tb_cm *tb_priv(struct tb *tb){return tb->priv;}
static struct tb_switch *tb_to_switch(struct device *d){return d->owner;}
static struct tb_port *tb_port_at(u64 route,struct tb_switch *sw){(void)route;return &sw->port;}
static struct tb_port *tb_switch_find_port(struct tb_switch *sw,int type){(void)type;return &sw->port;}
static void tb_disable_clx(struct tb_switch *sw){(void)sw;}
static void tb_enable_clx(struct tb_switch *sw){(void)sw;}
static struct tb_tunnel *tb_tunnel_alloc_dma(struct tb *tb,struct tb_port *src,struct tb_port *dst,int tp,int tr,int rp,int rr)
{(void)tb;(void)tp;(void)tr;(void)rp;(void)rr;struct tb_tunnel *t=calloc(1,sizeof(*t));assert(t);t->src_port=src;t->dst_port=dst;review_tunnels++;return t;}
static int tb_tunnel_activate(struct tb_tunnel *t){(void)t;review_activations++;return 0;}
static void tb_port_info(struct tb_port *p,const char *s){(void)p;(void)s;}
static void tb_tunnel_put(struct tb_tunnel *t){review_tunnels_freed++;free(t);}
static bool tb_tunnel_is_dma(struct tb_tunnel *t){(void)t;return true;}
static bool tb_tunnel_match_dma(struct tb_tunnel *t,int tp,int tr,int rp,int rr){(void)t;(void)tp;(void)tr;(void)rp;(void)rr;return true;}
static void tb_deactivate_and_free_tunnel(struct tb_tunnel *t){list_del(&t->list);tb_tunnel_put(t);}
static void usleep_range(unsigned lo,unsigned hi){(void)hi;usleep(lo);}
static int tb_approve_xdomain_paths(struct tb *,struct tb_xdomain *,int,int,int,int);
static int tb_disconnect_xdomain_paths(struct tb *,struct tb_xdomain *,int,int,int,int);
