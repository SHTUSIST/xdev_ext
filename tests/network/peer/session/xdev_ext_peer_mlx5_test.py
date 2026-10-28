#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual mlx5 peer WQE/retirement code with a software SQ adapter.
No physical NIC, GPU or hardware DMA assertion is made by this test.
"""
# P3/P4: extend the native shim with the production TX-chain field; assertions unchanged.
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
kernel = Path(__file__).resolve().parents[4]
source = (kernel/'drivers/net/ethernet/mellanox/mlx5/core/en_tx.c').read_text()
marker = '#ifdef CONFIG_XDEV_EXT_MECH\n'
start = source.rindex(marker, 0, source.index('struct pci_dev *mlx5e_peer_device(')) + len(marker)
end = source.index('\n#endif', start)
functions = source[start:end]
shim = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#define ETH_HLEN 14
#define ETH_ZLEN 60
#define MLX5_ST_SZ_DW(t) 16
#define MLX5_ADDR_OF(t,p,m) ((void *)(p))
#define MLX5_GET(t,p,m) ((void)(p), cap_##m)
#define MLX5_MKC_ACCESS_MODE_PA 0
#define MLX5_SEND_WQE_DS 16
#define MLX5_SEND_WQEBB_NUM_DS 4
#define MLX5_SEND_WQE_BB 64
#define MLX5E_TX_WQE_EMPTY_DS_COUNT 2
#define INL_HDR_START_SZ 2
#define MLX5_OPCODE_SEND 0x0a
#define MLX5_INLINE_MODE_L2 1
#define MLX5E_SQ_STATE_ENABLED 0
#define MLX5E_SQ_STATE_RECOVERING 1
#define MLX5E_SQ_STATE_IPSEC 2
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define cpu_to_be16(x) (x)
#define cpu_to_be32(x) (x)
#define cpu_to_be64(x) (x)
#define unsafe_memcpy(d,s,n,why) memcpy(d,s,n)
#define MLX5_UNSAFE_MEMCPY_DISCLAIMER "test header"
struct pci_dev { int unused; };
struct xdev_ext_peer_tx { u64 dma_address; u32 len; u16 header_len; const u8 *header; void (*complete)(struct xdev_ext_peer_tx *,int,bool); struct xdev_ext_peer_tx *next; };
struct mlx5e_tx_wqe_info { struct xdev_ext_peer_tx *peer; u32 num_bytes; u8 num_wqebbs, num_dma; };
struct mlx5_wqe_data_seg { u32 byte_count, lkey; u64 addr; };
struct mlx5_wqe_ctrl_seg { u32 opmod_idx_opcode, qpn_ds; u64 reserved; };
struct mlx5_wqe_eth_seg { u8 reserved[12]; struct { u16 sz; u8 start[2]; } inline_hdr; };
struct mlx5e_tx_wqe { struct mlx5_wqe_ctrl_seg ctrl; struct mlx5_wqe_eth_seg eth; struct mlx5_wqe_data_seg data[16]; };
struct mlx5_wq_cyc { int unused; };
struct netdev_queue { bool stopped; };
struct mlx5e_sq_stats { u64 packets,bytes; };
struct mlx5e_channel { int unused; };
struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(h) do { (h)->next=(h); (h)->prev=(h); } while (0)
/* Only the owner API boundary is injected here. Actual owner references and
 * parent teardown are exercised separately by test_native_owner_teardown.py. */
static int owner_get_result=0, owner_get_calls;
static int mlx5e_peer_channel_get(struct mlx5e_channel *channel)
{ (void)channel; owner_get_calls++; return owner_get_result; }
struct mlx5e_txqsq { struct mlx5e_channel *channel; bool peer_active; struct list_head peer_quarantine_node; struct mlx5_wq_cyc wq; u16 cc,pc,stop_room; u32 mkey_be,sqn; void *ptpsq; u8 min_inline_mode; unsigned long state; void *uar_map; struct mlx5e_sq_stats *stats; struct { struct mlx5e_tx_wqe_info *wqe_info; } db; };
struct mdev { struct { struct { u32 mkey; } hw_objs; } mlx5e_res; struct pci_dev *pdev; };
struct mlx5e_priv { struct mdev *mdev; struct mlx5e_txqsq **txq2sq; };
struct net_device { u32 mtu,real_num_tx_queues; bool running; struct mlx5e_priv *priv; struct netdev_queue *txq; };
static int cap_access_mode_4_2=0, cap_access_mode_1_0=0, cap_lr=1, cap_length64=1, query_result, notified, callbacks, last_status;
static bool room=true, last_quiesced;
static struct mlx5e_tx_wqe native_wqe;
static struct mlx5e_priv *netdev_priv(struct net_device *d) { return d->priv; }
static int mlx5_core_query_mkey(struct mdev *m, u32 key, u32 *out, int size) { (void)m;(void)key;(void)out;(void)size;return query_result; }
static struct netdev_queue *netdev_get_tx_queue(struct net_device *d,u32 q) { (void)q; return d->txq; }
static void __netif_tx_lock_bh(struct netdev_queue *q) { (void)q; }
static void __netif_tx_unlock_bh(struct netdev_queue *q) { (void)q; }
static bool netif_running(struct net_device *d) { return d->running; }
static bool netif_tx_queue_stopped(struct netdev_queue *q) { return q->stopped; }
static bool test_bit(int b,unsigned long *s) { return (*s>>b)&1; }
static bool mlx5e_wqc_has_room_for(struct mlx5_wq_cyc *w,u16 c,u16 p,u16 n) { (void)w;(void)c;(void)p;(void)n;return room; }
static void mlx5e_tx_mpwqe_ensure_complete(struct mlx5e_txqsq *s) { (void)s; }
static u16 mlx5e_txqsq_get_next_pi(struct mlx5e_txqsq *s,u16 n) { (void)s;(void)n;return 0; }
#define MLX5E_TX_FETCH_WQE(s,p) (&native_wqe)
static void mlx5e_tx_check_stop(struct mlx5e_txqsq *s) { (void)s; }
static void __netdev_tx_sent_queue(struct netdev_queue *q,u32 n,bool more) { (void)q;(void)n;(void)more; }
static void mlx5e_notify_hw(struct mlx5_wq_cyc *w,u16 p,void *map,struct mlx5_wqe_ctrl_seg *c) { (void)w;(void)p;(void)map;(void)c;notified++; }
static void complete_tx(struct xdev_ext_peer_tx *t,int status,bool quiesced) { (void)t;callbacks++;last_status=status;last_quiesced=quiesced; }
'''
main = r'''
int main(void)
{
 struct pci_dev pdev={0}; struct mdev m={.mlx5e_res.hw_objs.mkey=0x22,.pdev=&pdev}; struct mlx5e_tx_wqe_info wi={0}; struct mlx5e_sq_stats stats={0};
 struct mlx5e_txqsq sq={.mkey_be=0x22,.state=1,.stats=&stats,.db.wqe_info=&wi}; struct mlx5e_txqsq *sqs[]={&sq};
 struct mlx5e_priv priv={&m,sqs}; struct netdev_queue txq={0}; struct net_device d={1500,1,true,&priv,&txq};
 u8 header[82]; memset(header,0x5c,sizeof(header));
 struct xdev_ext_peer_tx tx={.dma_address=0x700123,.len=1024,.header_len=82,.header=header,.complete=complete_tx};
 assert(mlx5e_peer_xmit(&d,0,&tx)==0 && notified==1 && wi.peer==&tx && wi.num_dma==0);
 u16 inl=DIV_ROUND_UP(82-INL_HDR_START_SZ,MLX5_SEND_WQE_DS);
 assert(!memcmp(native_wqe.eth.inline_hdr.start,header,82));
 assert(native_wqe.data[inl].addr==0x700123 && native_wqe.data[inl].byte_count==1024 && native_wqe.data[inl].lkey==sq.mkey_be);
 assert(wi.num_bytes==1106 && sq.pc==wi.num_wqebbs);
 assert(mlx5e_peer_complete_wi(&wi,0,true) && callbacks==1 && last_status==0 && last_quiesced);
 assert(!mlx5e_peer_complete_wi(&wi,0,true) && callbacks==1);
 puts("ok 1 - actual mlx5 CPU-inline/header GPU-data WQE, native doorbell, no host DMA unmap, exactly one completion");
 assert(mlx5e_peer_xmit(&d,0,&tx)==0 && notified==2);
 assert(mlx5e_peer_complete_wi(&wi,-ECANCELED,false) && callbacks==2 && !last_quiesced);
 puts("ok 2 - unquiesced native completion (error CQE) yields unknown DMA ownership without command resend");
 assert(mlx5e_peer_device(&d)==&pdev);
 cap_access_mode_1_0=1; assert(!mlx5e_peer_device(&d));
 cap_access_mode_1_0=0; cap_access_mode_4_2=1; assert(!mlx5e_peer_device(&d));
 cap_access_mode_4_2=0; cap_lr=0; assert(!mlx5e_peer_device(&d));
 cap_lr=1; query_result=-EIO; assert(!mlx5e_peer_device(&d)); query_result=0;
 room=false; assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && notified==2);
 room=true; sq.state=3; assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && notified==2);
 puts("ok 3 - actual bind-time MKEY mode/read permission, ring pressure and recovery admission precede native acceptance");
 sq.state=1; sq.peer_active=false; sq.peer_quarantine_node=(struct list_head){0};
 struct mlx5e_tx_wqe before_wqe=native_wqe;
 struct mlx5e_tx_wqe_info before_wi=wi;
 struct mlx5e_sq_stats before_stats=stats;
 u16 before_pc=sq.pc; int before_owner_calls=owner_get_calls;
 owner_get_result=-ENOMEM;
 assert(mlx5e_peer_xmit(&d,0,&tx)==-ENOMEM && notified==2 && callbacks==2);
 assert(owner_get_calls==before_owner_calls+1 && sq.pc==before_pc);
 assert(!memcmp(&native_wqe,&before_wqe,sizeof(native_wqe)));
 assert(!memcmp(&wi,&before_wi,sizeof(wi)) && !memcmp(&stats,&before_stats,sizeof(stats)));
 assert(!sq.peer_active && !sq.peer_quarantine_node.next && !sq.peer_quarantine_node.prev);
 puts("ok 4 - owner acquisition failure rejects before WQE, queue state, accounting or doorbell writes");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev-peer-mlx5-') as directory:
    p=Path(directory)
    (p/'test.c').write_text(shim+functions+main)
    subprocess.run(shlex.split(os.environ.get('CC', 'cc'))+['-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
