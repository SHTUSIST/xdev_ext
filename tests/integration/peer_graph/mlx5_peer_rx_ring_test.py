#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual mlx5 peer RX post/completion over ring metadata. No GPU/NIC/DMA."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
KERNEL=Path(__file__).resolve().parents[5]
# RX adapter now carries the owner token and the device-provided termination key.
SHIM=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define ETH_HLEN 14
#define READ_ONCE(x) (x)
#define MLX5E_STATE_OPENED 0
#define MLX5E_RQ_STATE_ENABLED 0
#define MLX5E_RQ_STATE_RECOVERING 1
#define MLX5_TERMINATE_SCATTER_LIST_LKEY 0x100
#define cpu_to_be32(x) (x)
#define cpu_to_be64(x) (x)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
struct xdev_ext_peer_rx {struct xdev_ext_peer_rx *next;u64 dma_address;u32 len;u16 header_room;u8 *header;void(*complete)(struct xdev_ext_peer_rx*,int,u32,u32,bool);};
struct mlx5_wqe_data_seg {u32 byte_count,lkey;u64 addr;};
struct mlx5_wq_cyc {u16 head,used;struct mlx5_wqe_data_seg dseg[8][4];};
struct mlx5e_peer_rq {int lock;struct xdev_ext_peer_rx **posted;u8 *headers;u64 headers_dma;u32 stride;u64 owner;u32 terminate_lkey_be;};
struct mlx5e_rq {struct mlx5e_peer_rq *peer;unsigned long state;u32 mkey_be;struct {struct mlx5_wq_cyc wq;}wqe;};
struct channel {bool peer_quarantined;struct mlx5e_rq rq;};
struct mlx5e_priv {bool peer_quarantined;int state_lock;unsigned long state;struct {u32 num;struct channel **c;}channels;};
struct net_device {struct mlx5e_priv *priv;u32 mtu;};
static int doorbells,callbacks,status_seen;static u32 header_seen,payload_seen;
static void *netdev_priv(struct net_device *d){return d->priv;}
static bool mutex_trylock(int *l){if(*l)return false;*l=1;return true;}
static void mutex_unlock(int *l){assert(*l);*l=0;}
static void spin_lock_bh(int *l){assert(!*l);*l=1;}
static void spin_unlock_bh(int *l){assert(*l);*l=0;}
static bool test_bit(int b,unsigned long *p){return !!(*p&(1UL<<b));}
static int mlx5_wq_cyc_missing(struct mlx5_wq_cyc *w){return 8-w->used;}
static u16 mlx5_wq_cyc_get_head(struct mlx5_wq_cyc *w){return w->head;}
static void *mlx5_wq_cyc_get_wqe(struct mlx5_wq_cyc *w,u16 i){return w->dseg[i];}
static void mlx5_wq_cyc_push(struct mlx5_wq_cyc *w){assert(w->used<8);w->used++;w->head=(w->head+1)%8;}
static void dma_wmb(void){}
static void mlx5_wq_cyc_update_db_record(struct mlx5_wq_cyc *w){(void)w;doorbells++;}
static void done(struct xdev_ext_peer_rx *r,int status,u32 h,u32 p,bool q){assert(r&&q);callbacks++;status_seen=status;header_seen=h;payload_seen=p;}
'''
MAIN=r'''
int main(void)
{
 u8 headers[8*128]={0},dest[2][42];struct xdev_ext_peer_rx *posted[8]={0};
 struct mlx5e_peer_rq peer={.posted=posted,.headers=headers,.headers_dma=0x500000,.stride=64,.owner=1,.terminate_lkey_be=MLX5_TERMINATE_SCATTER_LIST_LKEY};
 struct channel ch={.rq={.peer=&peer,.state=1,.mkey_be=77}};struct channel *cp=&ch;
 struct mlx5e_priv priv={.state=1,.channels={1,&cp}};struct net_device dev={&priv,1500};
 struct xdev_ext_peer_rx rx[2]={{.dma_address=0x700000,.len=1472,.header_room=42,.header=dest[0],.complete=done},{.dma_address=0x800000,.len=1472,.header_room=42,.header=dest[1],.complete=done}};rx[0].next=&rx[1];
 assert(!mlx5e_peer_recv(&dev,0,1,rx)&&doorbells==1&&!callbacks&&ch.rq.wqe.wq.used==2);
 for(int i=0;i<2;i++){struct mlx5_wqe_data_seg *d=ch.rq.wqe.wq.dseg[i];assert(d[0].addr==0x500000+(u64)i*128&&d[0].byte_count==42&&d[0].lkey==77);assert(d[1].addr==rx[i].dma_address&&d[1].byte_count==1472&&d[1].lkey==77);assert(d[2].byte_count==0&&d[2].lkey==MLX5_TERMINATE_SCATTER_LIST_LKEY);}
 memset(headers,0xab,42);mlx5e_peer_rx_done(&ch.rq,0,0,1514);assert(callbacks==1&&!status_seen&&header_seen==42&&payload_seen==1472&&!memcmp(dest[0],headers,42));
 mlx5e_peer_rx_done(&ch.rq,0,0,1514);assert(callbacks==1);
 mlx5e_peer_rx_done(&ch.rq,1,0,2000);assert(callbacks==2&&status_seen==-EMSGSIZE&&!header_seen&&!payload_seen);
 puts("ok 1 - mlx5 RX posts two-segment header/peer WQEs with termination and one doorbell; CQ copies bounded header and retires each once");
 ch.rq.wqe.wq.used=7;assert(mlx5e_peer_recv(&dev,0,1,rx)==-EAGAIN&&doorbells==1&&!posted[2]);
 ch.rq.wqe.wq.used=0;rx[1].header_room=129;assert(mlx5e_peer_recv(&dev,0,1,rx)==-EINVAL&&doorbells==1&&!posted[2]);
 puts("ok 2 - mlx5 RX rejects insufficient whole-chain room and invalid later elements before writing WQEs");
 return 0;
}
'''
def main():
 s=(KERNEL/'drivers/net/ethernet/mellanox/mlx5/core/en_rx.c').read_text()
 a=s.index('int mlx5e_peer_recv(');b=s.index('\n#endif',a)
 code=s[a:b]
 with tempfile.TemporaryDirectory(prefix='mlx5-peer-rx-') as tmp:
  p=Path(tmp);(p/'test.c').write_text(SHIM+code+MAIN)
  subprocess.run(shlex.split(os.environ.get('CC','cc'))+['-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
if __name__=='__main__':main()
