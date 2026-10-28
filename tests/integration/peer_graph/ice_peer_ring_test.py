#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual ice peer TX/clean functions against descriptor bookkeeping.
No DMA or E810 hardware is represented. Checks chain atomicity, descriptor
addresses, coherent headers, CQ ownership and interrupt rearming."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
KERNEL=Path(__file__).resolve().parents[5]
BASE=KERNEL/'drivers/net/ethernet/intel/ice'

def function(s,name):
 m=re.search(r'^(?:static\s+)?[\w\s*]+?\b'+name+r'\([^;{]*\)\s*\{',s,re.M)
 assert m,name
 i=m.end();depth=1
 while depth:
  depth+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
SHIM=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
#define CONFIG_XDEV_EXT_MECH 1
#define ETH_HLEN 14
#define ETH_ZLEN 60
#define ICE_VSI_DOWN 0
#define ICE_TX_DESC_DTYPE_DESC_DONE 15ULL
#define ICE_TX_DESC_CMD_EOP 1ULL
#define ICE_TX_DESC_CMD_RS 2ULL
#define ICE_TXD_QW1_CMD_S 4
#define cpu_to_le64(x) (x)
#define READ_ONCE(x) (x)
#define unlikely(x) (x)
#define DMA_TO_DEVICE 1
#define ICE_DESC_UNUSED(r) (((r)->next_to_clean>(r)->next_to_use?(r)->next_to_clean-(r)->next_to_use:(r)->count+(r)->next_to_clean-(r)->next_to_use)-1)
#define ICE_TX_DESC(r,i) (&(r)->desc[i])
#define dma_unmap_addr(p,f) ((p)->f)
#define dma_unmap_len(p,f) ((p)->f)
#define dma_unmap_len_set(p,f,v) ((p)->f=(v))
struct device {int unused;};struct pci_dev {int unused;};
struct xdev_ext_peer_tx {u64 dma_address;u32 len;u16 header_len;const u8 *header;void(*complete)(struct xdev_ext_peer_tx*,int,bool);struct xdev_ext_peer_tx *next;};
enum {ICE_TX_BUF_EMPTY,ICE_TX_BUF_PEER,ICE_TX_BUF_PEER_DATA,ICE_TX_BUF_XDP_TX,ICE_TX_BUF_XDP_XMIT};
struct ice_tx_desc {u64 buf_addr,cmd_type_offset_bsz;};
struct ice_tx_buf {u32 rs_idx,bytecount,nr_frags,type;struct xdev_ext_peer_tx *peer;void *raw_buf,*xdpf;u32 len;u64 dma;};
struct ice_tx_ring {struct device *dev;struct ice_tx_desc desc[64];struct ice_tx_buf tx_buf[64];u32 count,next_to_clean,next_to_use,xdp_tx_active;u8 *peer_headers;u64 peer_headers_dma;int tx_lock;void *xsk_pool;};
struct ice_pf {struct pci_dev *pdev;};
struct ice_vsi {unsigned long state[1];bool xdp;u32 num_xdp_txq;struct ice_tx_ring **xdp_rings;struct ice_pf *back;};
struct ice_netdev_priv {struct ice_vsi *vsi;};
struct net_device {struct ice_netdev_priv *np;u32 mtu;};
struct xdp_frame_bulk {int unused;};
static int rings,callbacks,unmaps,locks;
static void *netdev_priv(struct net_device *d){return d->np;}
static bool test_bit(int bit,unsigned long *p){return !!(*p&(1UL<<bit));}
static bool ice_is_xdp_ena_vsi(struct ice_vsi *v){return v->xdp;}
static void spin_lock(int *p){assert(!*p);*p=1;locks++;}
static void spin_unlock(int *p){assert(*p);*p=0;locks--;}
#define spin_lock_bh spin_lock
#define spin_unlock_bh spin_unlock
static void rcu_read_lock(void){}
static void rcu_read_unlock(void){}
static void dma_unmap_single(struct device *d,u64 a,u32 n,int dir){(void)d;(void)a;(void)n;(void)dir;unmaps++;}
static void page_frag_free(void *p){(void)p;assert(0);}
static void xdp_return_frame_bulk(void *p,struct xdp_frame_bulk *b){(void)p;(void)b;assert(0);}
static void xdp_frame_bulk_init(struct xdp_frame_bulk *b){(void)b;}
static void xdp_flush_frame_bulk(struct xdp_frame_bulk *b){(void)b;}
static void ice_update_tx_ring_stats(struct ice_tx_ring *r,u32 p,u32 b){(void)r;(void)p;(void)b;}
static u64 ice_build_ctob(u64 cmd,u32 off,u32 size,u32 tag){(void)off;(void)tag;return cmd<<4|(u64)size<<32;}
static void ice_xdp_ring_update_tail(struct ice_tx_ring *r){assert(r->tx_lock);rings++;}
static void done(struct xdev_ext_peer_tx *tx,int status,bool quiesced){assert(tx&&!status&&quiesced);callbacks++;}
'''
MAIN=r'''
int main(void)
{
 u8 headers[64*128]={0}, h[42];memset(h,0xab,sizeof(h));
 struct ice_tx_ring ring={.count=64,.peer_headers=headers,.peer_headers_dma=0x500000};
 struct ice_tx_ring *rp=&ring;struct pci_dev pdev;struct ice_pf pf={&pdev};
 struct ice_vsi vsi={.xdp=true,.num_xdp_txq=1,.xdp_rings=&rp,.back=&pf};struct ice_netdev_priv np={&vsi};struct net_device dev={&np,1500};
 struct xdev_ext_peer_tx tx[2]={{.dma_address=0x700000,.len=1024,.header_len=42,.header=h,.complete=done}, {.dma_address=0x800000,.len=512,.header_len=42,.header=h,.complete=done}};tx[0].next=&tx[1];
 assert(ice_peer_device(&dev)==&pdev);
 assert(!ice_peer_xmit(&dev,0,tx)&&rings==1&&!callbacks&&ring.next_to_use==4&&ring.xdp_tx_active==2&&!locks);
 assert(ring.desc[0].buf_addr==0x500000&&ring.desc[1].buf_addr==0x700000&&ring.desc[2].buf_addr==0x500100&&ring.desc[3].buf_addr==0x800000);
 assert(!memcmp(headers,h,42)&&!memcmp(headers+256,h,42));
 assert(ring.desc[1].cmd_type_offset_bsz&(ICE_TX_DESC_CMD_EOP<<4));assert(ring.desc[3].cmd_type_offset_bsz&(ICE_TX_DESC_CMD_RS<<4));
 assert(ice_peer_clean_xdp(&ring)&&!callbacks); /* CQ absent: rearm IRQ, don't busy-poll. */
 ring.desc[3].cmd_type_offset_bsz=ICE_TX_DESC_DTYPE_DESC_DONE;
 assert(ice_peer_clean_xdp(&ring)&&callbacks==2&&!unmaps&&ring.next_to_clean==4&&!ring.xdp_tx_active);
 assert(ice_peer_clean_xdp(&ring)&&callbacks==2);
 puts("ok 1 - ice posts two peer packets with coherent header + payload descriptors, one tail, completion once, no peer DMA unmap");
 ring.next_to_use=62;ring.next_to_clean=0;assert(ice_peer_xmit(&dev,0,tx)==-EAGAIN&&rings==1&&callbacks==2);
 ring.next_to_use=4;tx[1].len=16000;assert(ice_peer_xmit(&dev,0,tx)==-EINVAL&&rings==1&&callbacks==2);
 puts("ok 2 - ice validates the entire chain and ring room before writing any descriptor");
 return 0;
}
'''
def main():
 s=(BASE/'ice_txrx_lib.c').read_text()
 code='\n'.join(function(s,n) for n in ['ice_clean_xdp_tx_buf','ice_clean_xdp_irq','ice_peer_device','ice_peer_xmit','ice_peer_clean_xdp'])
 with tempfile.TemporaryDirectory(prefix='ice-peer-ring-') as tmp:
  p=Path(tmp);(p/'test.c').write_text(SHIM+code+MAIN)
  subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
 s=function((BASE/'ice_main.c').read_text(),'ice_xdp_alloc_setup_rings')
 assert s.index('ice_set_ring_xdp(xdp_ring)')<s.index('ice_setup_tx_ring(xdp_ring)'), 'XDP type must be set before setup allocates coherent header slots'
 print('ok 3 - XDP ring type is set before setup allocates peer header storage')
if __name__=='__main__':main()
