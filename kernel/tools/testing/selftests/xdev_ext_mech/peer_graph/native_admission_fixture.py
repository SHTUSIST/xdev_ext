# SPDX-License-Identifier: GPL-2.0-only
"""Independent review layouts/cases, no firmware or DMA emulator."""

PROFILE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define CONFIG_XDEV_EXT_MECH 1
#define MLX5E_STATE_OPENED 0
#define MLX5E_STATE_DESTROYING 1
#define MLX5_DEVICE_STATE_INTERNAL_ERROR 99
typedef uint32_t u32;typedef uint64_t u64;typedef uint8_t u8;

struct mlx5e_priv;
struct mlx5e_profile {void(*disable)(struct mlx5e_priv*);void(*cleanup_rx)(struct mlx5e_priv*);void(*cleanup_tx)(struct mlx5e_priv*);void(*cleanup)(struct mlx5e_priv*);};
struct net_device{int unused;};struct mlx5_core_dev{int state;};
struct mlx5e_priv {const struct mlx5e_profile *profile;struct net_device *netdev;struct mlx5_core_dev *mdev;void *ppriv,*fs,*wq;unsigned long state;bool peer_quarantined;int update_stats_work;};
static int disable_count,rx_cleanup,tx_cleanup,profile_cleanup,priv_cleanup,attach_count;
static void disable(struct mlx5e_priv*p){(void)p;disable_count++;}
static void rx(struct mlx5e_priv*p){(void)p;rx_cleanup++;}
static void tx(struct mlx5e_priv*p){(void)p;tx_cleanup++;}
static void cleanup(struct mlx5e_priv*p){(void)p;profile_cleanup++;}
static void set_bit(int b,unsigned long*p){*p|=1UL<<b;}
static bool test_bit(int b,unsigned long*p){return !!(*p&(1UL<<b));}
static void mlx5e_fs_set_state_destroy(void*p,bool v){(void)p;(void)v;}
static void flush_workqueue(void*p){(void)p;}
static void mlx5e_reset_channels(struct net_device*p){(void)p;}
static void cancel_work_sync(int*p){(void)p;}
static void mlx5e_priv_cleanup(struct mlx5e_priv*p){(void)p;priv_cleanup++;}
static int mlx5e_netdev_init_profile(struct net_device*n,struct mlx5_core_dev*m,const struct mlx5e_profile*p,void*v){(void)n;(void)m;(void)p;(void)v;attach_count++;return 0;}
#define mlx5e_netdev_attach_profile mlx5e_netdev_init_profile
#define netdev_warn(...) ((void)0)
#define netdev_err(...) ((void)0)
'''

PROFILE_MAIN = r'''
int main(int argc,char**argv){
 struct net_device n={};struct mlx5_core_dev m={};const struct mlx5e_profile p={disable,rx,tx,cleanup};
 struct mlx5e_priv priv={.profile=&p,.netdev=&n,.mdev=&m,.peer_quarantined=atoi(argv[1])};
 int ret=mlx5e_netdev_change_profile(&priv,&p,NULL);
 printf("quarantined=%d ret=%d disable=%d cleanup_rx=%d cleanup_tx=%d profile_cleanup=%d priv_cleanup=%d attach=%d\n",priv.peer_quarantined,ret,disable_count,rx_cleanup,tx_cleanup,profile_cleanup,priv_cleanup,attach_count);
 if(priv.peer_quarantined)return ret!=-EIO||disable_count||rx_cleanup||tx_cleanup||profile_cleanup||priv_cleanup||attach_count;
 return ret||disable_count!=1||rx_cleanup!=1||tx_cleanup!=1||attach_count!=1;
}
'''

RX = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define CONFIG_XDEV_EXT_MECH 1
#define MLX5E_STATE_OPENED 0
#define MLX5E_STATE_DESTROYING 1
#define MLX5_DEVICE_STATE_INTERNAL_ERROR 99
typedef uint32_t u32;typedef uint64_t u64;typedef uint8_t u8;

#define MLX5_WQ_TYPE_CYCLIC 1
#define MLX5E_PFLAG_RX_CQE_COMPRESS 1
#define MLX5E_GET_PFLAG(p,f) ((p)->compress)
#define MLX5_ST_SZ_DW(x) 1
#define MLX5_ADDR_OF(t,p,f) (p)
#define MLX5_GET(t,p,f) cap_##f
#define MLX5_MKC_ACCESS_MODE_PA 0
#define MLX5_RQC_STATE_RDY 1
#define GFP_KERNEL 0
#define be32_to_cpu(x) (x)
#define rcu_access_pointer(x) (x)
#define kvfree free
#define kfree free
static int cap_access_mode_4_2,cap_access_mode_1_0,cap_lw=1,cap_length64=1;
struct mlx5e_channel{int unused;};
struct mlx5_wq_cyc{struct{unsigned log_stride;} fbc;};
struct mlx5e_peer_rq{u32 size,stride;u64 owner;u32 terminate_lkey_be;int lock;void**posted;void*saved;u8*headers;u64 headers_dma;};
struct mlx5e_rq{struct mlx5e_peer_rq *peer;struct mlx5e_channel *channel;int wq_type;void*xsk_pool,*xdp_prog,*pdev;u32 mkey_be;struct{struct mlx5_wq_cyc wq;}wqe;struct{void*napi;}cq;};
struct channel{struct mlx5e_rq rq;};struct mlx5_core_dev{int unused;};
struct mlx5e_priv{int state_lock;unsigned long state;struct{u32 num;struct channel**c;struct{bool compress;u32 terminate_lkey_be;}params;}channels;struct mlx5_core_dev*mdev;};
struct net_device{struct mlx5e_priv*priv;};
static int owner_calls,query_calls,allocation_calls,flush_calls;
static void*netdev_priv(struct net_device*d){return d->priv;}
static void mutex_lock(int*p){(void)p;}static void mutex_unlock(int*p){(void)p;}
static bool test_bit(int b,unsigned long*p){return !!(*p&(1UL<<b));}
static int mlx5e_peer_channel_get(struct mlx5e_channel*c){(void)c;owner_calls++;return 0;}
static int mlx5_core_query_mkey(struct mlx5_core_dev*d,u32 key,u32*out,size_t n){(void)d;(void)key;(void)out;(void)n;query_calls++;return 0;}
static u32 mlx5_wq_cyc_get_size(struct mlx5_wq_cyc*w){(void)w;return 8;}
static void*kzalloc(size_t n,int g){(void)g;allocation_calls++;return calloc(1,n);}
static void*kvcalloc(size_t n,size_t s,int g){(void)g;return calloc(n,s);}
static void spin_lock_init(int*p){*p=0;}
static void*dma_alloc_coherent(void*d,size_t n,u64*a,int g){(void)d;(void)a;(void)g;return calloc(1,n);}
static void dma_free_coherent(void*d,size_t n,void*p,u64 a){(void)d;(void)n;(void)a;free(p);}
static void napi_disable(void*n){(void)n;}static void napi_enable(void*n){(void)n;}
static int mlx5e_flush_rq(struct mlx5e_rq*r,int s){(void)r;(void)s;flush_calls++;return 0;}
static void*mlx5_wq_cyc_get_wqe(struct mlx5_wq_cyc*w,u32 i){(void)w;(void)i;static char p[128];return p;}
'''

RX_MAIN = r'''
int main(int argc,char**argv){
 struct channel ch={};struct channel*cp=&ch;struct mlx5_core_dev m={};
 struct mlx5e_priv priv={.state=1,.channels={.num=1,.c=&cp},.mdev=&m};struct net_device d={&priv};
 int mode=atoi(argv[1]);ch.rq.wq_type=MLX5_WQ_TYPE_CYCLIC;ch.rq.wqe.wq.fbc.log_stride=6;
 switch(mode){case 0:ch.rq.wq_type=0;break;case 1:ch.rq.xsk_pool=&m;break;case 2:ch.rq.xdp_prog=&m;break;case 3:ch.rq.wqe.wq.fbc.log_stride=4;break;case 4:priv.channels.params.compress=true;break;}
 int ret=mlx5e_peer_rx_open(&d,0,1);
 printf("mode=%d ret=%d peer=%d owner_calls=%d query=%d allocation=%d flush=%d\n",mode,ret,!!ch.rq.peer,owner_calls,query_calls,allocation_calls,flush_calls);
 return mode<5 ? ret!=-EOPNOTSUPP||ch.rq.peer||query_calls||allocation_calls||flush_calls : ret||!ch.rq.peer;
}
'''
