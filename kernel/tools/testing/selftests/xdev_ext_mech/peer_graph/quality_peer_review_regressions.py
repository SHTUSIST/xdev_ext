#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Native RX ownership/MKEY and ice teardown regressions, without device DMA.
Extract production functions on every run. OS/firmware adapters control the
completion and reset evidence; assertions do not infer it from implementation.
"""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import ice_peer_ring_test as ice
import mlx5_peer_rx_ring_test as mlx5

KERNEL = Path(__file__).resolve().parents[5]
MLX = KERNEL / 'drivers/net/ethernet/mellanox/mlx5/core'


def run(name, code):
    with tempfile.TemporaryDirectory(prefix=name + '-') as tmp:
        p = Path(tmp)
        (p / 'test.c').write_text(code)
        subprocess.run(shlex.split(os.environ.get('CC', 'cc'))+['-std=gnu11', '-Wall', '-Wextra',
                        '-Werror', '-Wno-unused-function', '-Wno-sign-compare',
                        '-fsanitize=undefined', '-pthread', str(p / 'test.c'),
                        '-o', str(p / 'test')], check=True)
        subprocess.run([str(p / 'test')], check=True)


def mlx5_test():
    shim = mlx5.SHIM.replace('#include <errno.h>', '#include <errno.h>\n#include <stdlib.h>\n#include <pthread.h>')
    shim = shim.replace('u16 head,used;', 'u16 head,used;struct {u32 log_stride;} fbc;')
    shim = shim.replace('u32 stride;u64 owner;', 'u32 stride,size;u8 *saved;u64 owner;')
    shim = shim.replace('struct mlx5e_peer_rq *peer;unsigned long state;', 'struct mlx5e_peer_rq *peer;struct channel *channel;void *pdev,*xsk_pool,*xdp_prog;int wq_type;struct {void *napi;} cq;unsigned long state;')
    shim = shim.replace('int state_lock;unsigned long state;struct {u32 num;struct channel **c;}channels;', 'pthread_mutex_t state_lock;void *mdev;unsigned long state;struct {u32 num;struct channel **c;struct {u32 terminate_lkey_be;}params;}channels;')
    start = shim.index('static bool mutex_trylock(')
    end = shim.index('static void spin_lock_bh(', start)
    shim = shim[:start] + r'''
static void mutex_lock(pthread_mutex_t *l){assert(!pthread_mutex_lock(l));}
static bool mutex_trylock(pthread_mutex_t *l){return !pthread_mutex_trylock(l);}
static void mutex_unlock(pthread_mutex_t *l){assert(!pthread_mutex_unlock(l));}
''' + shim[end:]
    shim += r'''
#define MLX5_WQ_TYPE_CYCLIC 1
#define MLX5_RQC_STATE_RDY 1
#define GFP_KERNEL 0
#define MLX5_ST_SZ_DW(t) 1
#define MLX5_ADDR_OF(t,p,f) ((void*)(p))
#define MLX5_GET(t,p,f) ((void)(p),test_##f)
#define MLX5_MKC_ACCESS_MODE_PA 0
#define MLX5E_GET_PFLAG(p,f) 0
#define rcu_access_pointer(p) (p)
#define be32_to_cpu(v) (v)
static int test_access_mode_4_2,test_access_mode_1_0,test_lw=1,test_length64=1;
static int flushes,fail_reset,allocations,frees;
/* Inject only the owner API result. Real owner references are covered by the
 * independent owner/parent teardown test, not by this successful default. */
static int owner_get_result=0,owner_get_calls;
static int mlx5e_peer_channel_get(struct channel *channel)
{(void)channel;owner_get_calls++;return owner_get_result;}
static void *kzalloc(size_t n,int g){(void)g;allocations++;return calloc(1,n);}
static void *kvcalloc(size_t n,size_t z,int g){return kzalloc(n*z,g);}
static void kfree(void *p){if(p){frees++;free(p);}}
#define kvfree kfree
static void *dma_alloc_coherent(void *d,size_t n,u64 *addr,int g){(void)d;*addr=0x500000;return kzalloc(n,g);}
static void dma_free_coherent(void *d,size_t n,void *p,u64 addr){(void)d;(void)n;(void)addr;kfree(p);}
static void spin_lock_init(int *l){*l=0;}
static void napi_disable(void *p){(void)p;}
static void napi_enable(void *p){(void)p;}
static void napi_schedule(void *p){(void)p;}
static u32 mlx5_wq_cyc_get_size(struct mlx5_wq_cyc *w){(void)w;return 8;}
static int mlx5_core_query_mkey(void *d,u32 key,u32 *out,size_t n){(void)d;(void)key;(void)out;(void)n;return 0;}
static void mlx5e_peer_rx_done(struct mlx5e_rq *,u16,int,u32);
static int mlx5e_flush_rq(struct mlx5e_rq *rq,int state){
 (void)state;flushes++;
 if(fail_reset)return -EIO;
 if(rq->peer)for(int i=0;i<8;i++)mlx5e_peer_rx_done(rq,i,-ECANCELED,0);
 rq->wqe.wq.head=rq->wqe.wq.used=0;return 0;
}
'''
    main = r'''
struct flush_arg {struct net_device *dev;u64 owner;};
static void *flush_thread(void *p){struct flush_arg *a=p;assert(!mlx5e_peer_rx_flush(a->dev,0,a->owner));return NULL;}
int main(void){
 struct channel ch={.rq={.state=1,.mkey_be=77,.wq_type=MLX5_WQ_TYPE_CYCLIC}}, replacement=ch;
 struct channel *cp=&ch;
 struct mlx5e_priv priv={.state_lock=PTHREAD_MUTEX_INITIALIZER,.state=1,.channels={.num=1,.c=&cp}};
 struct net_device dev={&priv,1500};u8 dest[42];
 struct xdev_ext_peer_rx rx={.dma_address=0x700000,.len=1472,.header_room=42,.header=dest,.complete=done};
 u32 keys[]={MLX5_TERMINATE_SCATTER_LIST_LKEY,0x12345600};
 assert(mlx5e_peer_rx_open(&dev,0,0)==-EINVAL&&!ch.rq.peer);
 ch.rq.wqe.wq.fbc.log_stride=5;
 owner_get_result=-ENOMEM;
 assert(mlx5e_peer_rx_open(&dev,0,1)==-ENOMEM&&!ch.rq.peer);
 assert(owner_get_calls==1&&!doorbells&&!allocations&&!flushes);
 owner_get_result=0;
 for(int key=0;key<2;key++)for(int stride=5;stride<=6;stride++){
  priv.channels.params.terminate_lkey_be=keys[key];ch.rq.wqe.wq.fbc.log_stride=stride;
  assert(!mlx5e_peer_rx_open(&dev,0,1));
  assert(mlx5e_peer_rx_open(&dev,0,2)==-EBUSY);
  memset(ch.rq.wqe.wq.dseg[0],0x5a,sizeof(ch.rq.wqe.wq.dseg[0]));
  assert(!mlx5e_peer_recv(&dev,0,1,&rx));
  assert(ch.rq.wqe.wq.dseg[0][0].lkey==77&&ch.rq.wqe.wq.dseg[0][1].lkey==77);
  assert(ch.rq.wqe.wq.dseg[0][2].lkey==(stride==6?keys[key]:0x5a5a5a5a));
  int before=callbacks;assert(!mlx5e_peer_rx_flush(&dev,0,1));assert(callbacks==before+1&&!ch.rq.peer);
  assert(!mlx5e_peer_rx_flush(&dev,0,1)&&callbacks==before+1);
 }
 puts("ok - actual mlx5 open propagates default/nondefault device MKEY; 32-byte WQE has no spare segment; wider WQE terminates correctly");
 ch.rq.wqe.wq.fbc.log_stride=6;
 assert(!mlx5e_peer_rx_open(&dev,0,2));assert(!mlx5e_peer_recv(&dev,0,2,&rx));
 int before=callbacks,flushed=flushes;
 assert(!mlx5e_peer_rx_flush(&dev,0,1)&&flushes==flushed&&ch.rq.peer->owner==2);
 assert(mlx5e_peer_recv(&dev,0,1,&rx)==-ESTALE&&callbacks==before);
 mutex_lock(&priv.state_lock);assert(mlx5e_peer_recv(&dev,0,2,&rx)==-EAGAIN);mutex_unlock(&priv.state_lock);
 fail_reset=1;assert(mlx5e_peer_rx_flush(&dev,0,2)==-EIO&&ch.rq.peer&&callbacks==before);fail_reset=0;
 pthread_t t[2];struct flush_arg a={&dev,2};
 assert(!pthread_create(&t[0],NULL,flush_thread,&a));assert(!pthread_create(&t[1],NULL,flush_thread,&a));
 assert(!pthread_join(t[0],NULL)&&!pthread_join(t[1],NULL));assert(!ch.rq.peer&&callbacks==before+1);
 puts("ok - stale RX post/flush preserve new owner; reset failure retains requests; concurrent duplicate flush retires exactly once");
 assert(!mlx5e_peer_rx_open(&dev,0,3));assert(!mlx5e_peer_recv(&dev,0,3,&rx));
 /* Channel destruction drains its CQ before free; replacement uses same queue index. */
 assert(!mlx5e_flush_rq(&ch.rq,MLX5_RQC_STATE_RDY));mlx5e_peer_rx_free(&ch.rq);
 cp=&replacement;replacement.rq.wqe.wq.fbc.log_stride=6;
 assert(!mlx5e_peer_rx_open(&dev,0,4));flushed=flushes;
 assert(!mlx5e_peer_rx_flush(&dev,0,3)&&flushes==flushed&&replacement.rq.peer->owner==4);
 assert(mlx5e_peer_recv(&dev,0,3,&rx)==-ESTALE);
 assert(!mlx5e_peer_recv(&dev,0,4,&rx));before=callbacks;
 mlx5e_peer_rx_done(&replacement.rq,0,0,1514);mlx5e_peer_rx_done(&replacement.rq,0,0,1514);
 assert(callbacks==before+1);assert(!mlx5e_peer_rx_flush(&dev,0,4)&&callbacks==before+1);
 assert(allocations==frees);
 puts("ok - queue replacement rejects old token; CQ then flush has exactly one callback and all quiesced allocations freed");
 return 0;
}
'''
    control = (MLX / 'en_main.c').read_text()
    data = (MLX / 'en_rx.c').read_text()
    code = '\n'.join(ice.function(control, name) for name in ['mlx5e_peer_rx_open', 'mlx5e_peer_rx_free', 'mlx5e_peer_rx_flush'])
    code += '\n' + '\n'.join(ice.function(data, name) for name in ['mlx5e_peer_recv', 'mlx5e_peer_rx_done'])
    run('mlx5-peer-owner', shim + code + main)


def ice_test():
    shim = ice.SHIM.replace('ICE_TX_BUF_XDP_XMIT};', 'ICE_TX_BUF_XDP_XMIT,ICE_TX_BUF_DUMMY,ICE_TX_BUF_SKB};')
    shim = shim.replace('void *raw_buf,*xdpf;', 'void *raw_buf,*xdpf,*skb,*next_to_watch;')
    shim = shim.replace('void *xsk_pool;};', 'void *xsk_pool;bool peer_quarantined;};')
    shim = shim[:shim.index('static void done(')] + r'''
#define dma_unmap_page dma_unmap_single
static void devm_kfree(struct device *d,void *p){(void)d;(void)p;assert(0);}
static void dev_kfree_skb_any(void *p){(void)p;assert(0);}
static void xdp_return_frame(void *p){(void)p;assert(0);}
static struct xdev_ext_peer_tx *requests;
static int seen[16],qseen[16],expected_status;
static void done(struct xdev_ext_peer_tx *tx,int status,bool q){
 int i=tx-requests;assert(i>=0&&i<16&&seen[i]++==0&&status==expected_status);qseen[i]=q;callbacks++;
}
'''
    main = r'''
int main(void){
 int sizes[]={1,2,3,16};
 for(int nidx=0;nidx<4;nidx++)for(int wrap=0;wrap<2;wrap++)for(int dd=0;dd<2;dd++)for(int clean=0;clean<2;clean++){
  int n=sizes[nidx],start=wrap?59:0;u8 headers[64*128]={0},h[42]={0};
  struct ice_tx_ring ring={.count=64,.peer_headers=headers,.peer_headers_dma=0x500000,.next_to_use=start,.next_to_clean=start};
  struct ice_tx_ring *rp=&ring;struct pci_dev pdev;struct ice_pf pf={&pdev};
  struct ice_vsi vsi={.xdp=true,.num_xdp_txq=1,.xdp_rings=&rp,.back=&pf};struct ice_netdev_priv np={&vsi};struct net_device dev={&np,1500};
  struct xdev_ext_peer_tx tx[16];requests=tx;callbacks=unmaps=0;memset(seen,0,sizeof(seen));memset(qseen,0,sizeof(qseen));
  for(int i=0;i<n;i++)tx[i]=(struct xdev_ext_peer_tx){.dma_address=0x700000+(u64)i*4096,.len=1024,.header_len=42,.header=h,.complete=done,.next=i<n-1?&tx[i+1]:NULL};
  assert(!ice_peer_xmit(&dev,0,tx));int tail=(start+n*2-1)%64;
  if(dd)ring.desc[tail].cmd_type_offset_bsz=ICE_TX_DESC_DTYPE_DESC_DONE;
  expected_status=0;
  if(clean){assert(ice_peer_clean_xdp(&ring));assert(callbacks==(dd?n:0));}
  expected_status=-ECANCELED;
  for(int i=0;i<64;i++)ice_unmap_and_free_tx_buf(&ring,&ring.tx_buf[i]);
  assert(callbacks==n&&ring.peer_quarantined==!dd&&!unmaps);
  for(int i=0;i<n;i++)assert(seen[i]==1&&qseen[i]==dd);
  /* Teardown is idempotent; later DD cannot convert an unknown callback. */
  ring.desc[tail].cmd_type_offset_bsz=ICE_TX_DESC_DTYPE_DESC_DONE;
  for(int i=0;i<64;i++)ice_unmap_and_free_tx_buf(&ring,&ring.tx_buf[i]);
  assert(callbacks==n&&ring.peer_quarantined==!dd&&!unmaps);
 }
 puts("ok - ice 1/2/3/16 packet chains: wraparound, final DD present/absent, cleaner before teardown, exactly-once callbacks, no peer DMA unmap");
 return 0;
}
'''
    source = (ice.BASE / 'ice_txrx_lib.c').read_text()
    code = '\n'.join(ice.function(source, name) for name in ['ice_clean_xdp_tx_buf', 'ice_clean_xdp_irq', 'ice_peer_xmit', 'ice_peer_clean_xdp'])
    code += ice.function((ice.BASE / 'ice_txrx.c').read_text(), 'ice_unmap_and_free_tx_buf')
    run('ice-peer-teardown', shim + code + main)


def endpoint_test():
    import independent_peer_net_endpoint as endpoint
    source = (KERNEL / 'io_uring/xdev_ext_peer_net.c').read_text()
    code = source[source.index('struct xdev_ext_peer_tx_wait {'):source.index('long xdev_ext_peer_net_ioctl(')]
    shim = ('#define XDEV_EXT_PEER_NET_SYNC_ONE\n#include "' + str(KERNEL / 'include/uapi/linux/xdev_ext_peer.h') + '"\n'
            '#include "' + str(KERNEL / 'io_uring/xdev_ext_peer_net_core.h') + '"\n' + endpoint.SHIM)
    main = r"""
static u64 owner_seen;static int rx_posts,rx_flushes,rx_callbacks;
static int rx_open(struct net_device *d,u32 q,u64 owner){assert(d==&devices[0]&&q==2&&rtnl_depth==1&&owner);if(owner_seen)return -EBUSY;owner_seen=owner;return 0;}
static int rx_post(struct net_device *d,u32 q,u64 owner,struct xdev_ext_peer_rx *r){assert(d==&devices[0]&&q==2&&!rtnl_depth);if(owner!=owner_seen)return -ESTALE;rx_posts++;r->complete(r,0,42,100,true);return 0;}
static int rx_flush(struct net_device *d,u32 q,u64 owner){assert(d==&devices[0]&&q==2&&rtnl_depth==1);if(owner==owner_seen){owner_seen=0;rx_flushes++;}return 0;}
static void rx_complete(struct xdev_ext_peer_rx *r,int status,u32 h,u32 p,bool q){assert(r&&!status&&h==42&&p==100&&q);rx_callbacks++;}
int main(void){
 reset();init_once();struct net_device_ops rxops=ops;
 rxops.ndo_xdev_ext_peer_rx_open=rx_open;rxops.ndo_xdev_ext_peer_rx=rx_post;rxops.ndo_xdev_ext_peer_rx_flush=rx_flush;
 devices[0].netdev_ops=&rxops;
 struct xdev_ext_peer_net_endpoint *a=xdev_ext_peer_net_bind_dir(4,2,true,NULL,NULL);assert(!IS_ERR(a));u64 aid=a->rx_owner;assert(aid&&owner_seen==aid);
 struct xdev_ext_peer_net_endpoint *bad=xdev_ext_peer_net_bind_dir(4,2,true,NULL,NULL);assert(PTR_ERR(bad)==-EBUSY&&owner_seen==aid);
 assert(!xdev_ext_peer_net_rx_flush(a));
 struct xdev_ext_peer_net_endpoint *b=xdev_ext_peer_net_bind_dir(4,2,true,NULL,NULL);assert(!IS_ERR(b)&&b->rx_owner>aid&&owner_seen==b->rx_owner);
 struct xdev_ext_peer_rx rx={.complete=rx_complete};
 assert(xdev_ext_peer_net_post_rx(a,&rx)==-ESTALE&&!rx_posts&&!rx_callbacks);
 xdev_ext_peer_net_unbind(a);assert(owner_seen==b->rx_owner&&rx_flushes==1);
 assert(!xdev_ext_peer_net_post_rx(b,&rx)&&rx_posts==1&&rx_callbacks==1);
 xdev_ext_peer_net_unbind(b);assert(!owner_seen&&rx_flushes==2&&!devices[0].refs&&!peer_pci.refs&&allocs==frees);
 xdev_ext_peer_net_rx_owner=U64_MAX;
 for(int i=0;i<2;i++){bad=xdev_ext_peer_net_bind_dir(4,2,true,NULL,NULL);assert(PTR_ERR(bad)==-EOVERFLOW&&xdev_ext_peer_net_rx_owner==U64_MAX&&!owner_seen&&!devices[0].refs&&!peer_pci.refs&&allocs==frees);}
 rxops.ndo_xdev_ext_peer_rx_open=NULL;
 bad=xdev_ext_peer_net_bind_dir(4,2,true,NULL,NULL);assert(PTR_ERR(bad)==-EOPNOTSUPP&&!devices[0].refs&&!peer_pci.refs&&allocs==frees);
 puts("ok - actual endpoint bind/post/flush/unbind propagates unique owner, failed bind cannot recycle it, saturated counter refuses ABA without ref leaks");
 return 0;
}
"""
    # Preserve the original independent TX/refcount/late-completion assertions.
    # Read runtime pointers for weak-symbol probes: newer GCC diagnoses direct
    # address checks when the extracted production body defines the function.
    original_main = endpoint.MAIN
    probes = ''
    for symbol in ('test_initcall', 'xdev_ext_peer_net_send_stoppable',
                   'xdev_ext_peer_net_bind_stage'):
        check = 'if(!' + symbol + ')'
        assert original_main.count(check) == 1, symbol
        probe = symbol + '_probe'
        probes += 'static __typeof__(&' + symbol + ') volatile ' + probe + '=' + symbol + ';\n'
        original_main = original_main.replace(check, 'if(!' + probe + ')')
    run('peer-endpoint-owner', shim + code + probes + '\n#define main original_main\n' + original_main + '\n#undef main\n' + main)


if __name__ == '__main__':
    mlx5_test()
    ice_test()
    endpoint_test()
