#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual mlx5 peer-TX hooks: bind-time MKEY validation,
RTNL-free admission under the TX queue lock, and SQ teardown ownership.

Compiles the xdev_ext block of en_tx.c and the real mlx5e_free_txqsq_descs()
against a software SQ adapter. No NIC, GPU, firmware command or DMA is used;
the MKEY query is an adapter that only counts calls and returns attributes.
"""
# P3/P4: extend the native shim with the production TX-chain field; assertions unchanged.
from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
SHIM = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#define UNUSED __attribute__((unused))
#define CONFIG_XDEV_EXT_MECH 1
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
#define likely(x) (x)
#define unlikely(x) (x)
struct pci_dev { int unused; };
struct sk_buff { int unused; };
struct xdev_ext_peer_tx { u64 dma_address; u32 len; u16 header_len; const u8 *header; void (*complete)(struct xdev_ext_peer_tx *,int,bool); struct xdev_ext_peer_tx *next; };
struct mlx5e_tx_wqe_info { struct xdev_ext_peer_tx *peer; struct sk_buff *skb; u32 num_bytes; u8 num_wqebbs, num_dma, num_fifo_pkts; };
struct mlx5_wqe_data_seg { u32 byte_count, lkey; u64 addr; };
struct mlx5_wqe_ctrl_seg { u32 opmod_idx_opcode, qpn_ds; u64 reserved; };
struct mlx5_wqe_eth_seg { u8 reserved[12]; struct { u16 sz; u8 start[2]; } inline_hdr; };
struct mlx5e_tx_wqe { struct mlx5_wqe_ctrl_seg ctrl; struct mlx5_wqe_eth_seg eth; struct mlx5_wqe_data_seg data[16]; };
struct mlx5_wq_cyc { u16 size; };
struct netdev_queue { bool stopped; int locked; };
struct mlx5e_sq_stats { u64 packets,bytes; };
struct mlx5e_channel;
struct list_head { struct list_head *next,*prev; };
#define INIT_LIST_HEAD(h) do { (h)->next=(h); (h)->prev=(h); } while (0)
/* Owner acquisition is a boundary here; test_native_owner_teardown.py executes
 * the actual owner/ref and parent close functions. Original MAIN is unchanged. */
static int mlx5e_peer_channel_get(struct mlx5e_channel *c) { (void)c; return 0; }
struct mlx5e_txqsq { struct mlx5e_channel *channel; bool peer_active,peer_destroy_unknown; struct list_head peer_quarantine_node; struct mlx5_wq_cyc wq; u16 cc,pc,stop_room; u32 mkey_be,sqn,dma_fifo_cc; void *ptpsq; u8 min_inline_mode; unsigned long state; void *uar_map; struct mlx5e_sq_stats *stats; struct netdev_queue *txq; bool freed; struct { struct mlx5e_tx_wqe_info *wqe_info; } db; };
struct mdev { struct { struct { u32 mkey; } hw_objs; } mlx5e_res; struct pci_dev *pdev; };
struct mlx5e_priv { struct mdev *mdev; struct mlx5e_txqsq **txq2sq; };
struct net_device { u32 mtu,real_num_tx_queues; bool running; struct mlx5e_priv *priv; struct netdev_queue *txq; };
static int cap_access_mode_4_2=0, cap_access_mode_1_0=0, cap_lr=1, cap_length64=1, query_result, queries, notified, callbacks, last_status, quiesced_callbacks, completed_pkts, shrink_on_lock;
static bool room=true, last_quiesced;
static struct mlx5e_tx_wqe native_wqe;
static struct mlx5e_priv *netdev_priv(struct net_device *d) { return d->priv; }
static UNUSED int mlx5_core_query_mkey(struct mdev *m, u32 key, u32 *out, int size) { assert(m && key==m->mlx5e_res.hw_objs.mkey);(void)out;(void)size;queries++;return query_result; }
static struct netdev_queue *netdev_get_tx_queue(struct net_device *d,u32 q) { return &d->txq[q]; }
static struct net_device *locked_dev;
static void __netif_tx_lock_bh(struct netdev_queue *q) { assert(!q->locked); q->locked=1; if (shrink_on_lock) locked_dev->real_num_tx_queues=1; }
static void __netif_tx_unlock_bh(struct netdev_queue *q) { assert(q->locked); q->locked=0; }
static bool netif_running(struct net_device *d) { return d->running; }
static bool netif_tx_queue_stopped(struct netdev_queue *q) { return q->stopped; }
static bool test_bit(int b,unsigned long *s) { return (*s>>b)&1; }
static bool mlx5e_wqc_has_room_for(struct mlx5_wq_cyc *w,u16 c,u16 p,u16 n) { (void)w;(void)c;(void)p;(void)n;return room; }
static void mlx5e_tx_mpwqe_ensure_complete(struct mlx5e_txqsq *s) { assert(!s->freed); }
static u16 mlx5e_txqsq_get_next_pi(struct mlx5e_txqsq *s,u16 n) { (void)n; assert(!s->freed && s->txq->locked); return s->pc % s->wq.size; }
#define MLX5E_TX_FETCH_WQE(s,p) (&native_wqe)
static void mlx5e_tx_check_stop(struct mlx5e_txqsq *s) { (void)s; }
static void __netdev_tx_sent_queue(struct netdev_queue *q,u32 n,bool more) { (void)q;(void)n;(void)more; }
static void mlx5e_notify_hw(struct mlx5_wq_cyc *w,u16 p,void *map,struct mlx5_wqe_ctrl_seg *c) { (void)w;(void)p;(void)map;(void)c;notified++; }
static u16 mlx5_wq_cyc_ctr2ix(struct mlx5_wq_cyc *w,u16 c) { return c % w->size; }
static void mlx5e_tx_wi_dma_unmap(struct mlx5e_txqsq *s,struct mlx5e_tx_wqe_info *wi,u32 *cc) { (void)s;*cc+=wi->num_dma; }
static void dev_kfree_skb_any(struct sk_buff *skb) { (void)skb; }
static bool mlx5e_ktls_tx_try_handle_resync_dump_comp(struct mlx5e_txqsq *s,struct mlx5e_tx_wqe_info *wi,u32 *cc) { (void)s;(void)wi;(void)cc;return false; }
static void mlx5e_tx_wi_kfree_fifo_skbs(struct mlx5e_txqsq *s,struct mlx5e_tx_wqe_info *wi) { (void)s;(void)wi; }
static void netdev_tx_completed_queue(struct netdev_queue *q,u32 pkts,u32 bytes) { (void)q;(void)bytes;completed_pkts+=pkts; }
static void complete_tx(struct xdev_ext_peer_tx *t,int status,bool quiesced) { (void)t;callbacks++;last_status=status;last_quiesced=quiesced;quiesced_callbacks+=quiesced; }
'''
MAIN = r'''
static struct mdev m; static struct pci_dev pdev; static struct mlx5e_tx_wqe_info wi[8]; static struct mlx5e_sq_stats stats;
static struct mlx5e_txqsq sq, stale; static struct mlx5e_txqsq *sqs[2]; static struct mlx5e_priv priv; static struct netdev_queue txq[2]; static struct net_device d;
static u8 header[82]; static struct xdev_ext_peer_tx tx;
static void reset(void)
{
 m=(struct mdev){.mlx5e_res.hw_objs.mkey=0x22,.pdev=&pdev}; memset(wi,0,sizeof(wi)); memset(&stats,0,sizeof(stats));
 sq=(struct mlx5e_txqsq){.wq={8},.mkey_be=0x22,.state=1,.stats=&stats,.txq=&txq[0],.db.wqe_info=wi};
 stale=sq; stale.freed=true; stale.txq=&txq[1]; sqs[0]=&sq; sqs[1]=&stale;
 priv=(struct mlx5e_priv){&m,sqs}; memset(txq,0,sizeof(txq)); d=(struct net_device){1500,2,true,&priv,txq}; locked_dev=&d;
 memset(header,0x5c,sizeof(header)); tx=(struct xdev_ext_peer_tx){.dma_address=0x700123,.len=1024,.header_len=82,.header=header,.complete=complete_tx};
 cap_access_mode_4_2=cap_access_mode_1_0=0; cap_lr=cap_length64=1; query_result=queries=notified=callbacks=last_status=quiesced_callbacks=completed_pkts=shrink_on_lock=0; room=true; last_quiesced=false;
}
static int case_teardown(void)
{
 reset();
 assert(!mlx5e_peer_xmit(&d,0,&tx) && !mlx5e_peer_xmit(&d,0,&tx) && notified==2 && sq.pc!=sq.cc);
 mlx5e_free_txqsq_descs(&sq);
 assert(callbacks==2 && last_status==-ECANCELED && sq.cc==sq.pc && completed_pkts==2);
 if (quiesced_callbacks!=2) { fprintf(stderr,"RED SQ teardown after DESTROY_SQ reports %d of 2 peer sends unquiesced; each permanently retains its GPU mapping\n",2-quiesced_callbacks); return 1; }
 puts("ok 1 - actual mlx5 teardown after SQ destruction returns peer sends as quiesced, exactly once each");
 return 0;
}
static int case_mkey(void)
{
 reset();
 if (mlx5e_peer_device(&d)!=&pdev || queries!=1) { fprintf(stderr,"RED bind does not validate the MKEY (queries at bind=%d)\n",queries); return 1; }
 for (int i=0;i<8;i++) { assert(!mlx5e_peer_xmit(&d,0,&tx)); sq.cc=sq.pc; }
 if (queries!=1) { fprintf(stderr,"RED 8 peer sends issued %d firmware MKEY queries\n",queries-1); return 1; }
 cap_access_mode_1_0=1; assert(!mlx5e_peer_device(&d));
 cap_access_mode_1_0=0; cap_access_mode_4_2=1; assert(!mlx5e_peer_device(&d));
 cap_access_mode_4_2=0; cap_lr=0; assert(!mlx5e_peer_device(&d));
 cap_lr=1; cap_length64=0; assert(!mlx5e_peer_device(&d));
 cap_length64=1; query_result=-EIO; assert(!mlx5e_peer_device(&d));
 query_result=0; assert(mlx5e_peer_device(&d)==&pdev);
 /* The per-send check still pins the SQ to the validated device MKEY. */
 sq.mkey_be=0x23; assert(mlx5e_peer_xmit(&d,0,&tx)==-EOPNOTSUPP); sq.mkey_be=0x22;
 puts("ok 2 - actual mlx5 validates the MKEY once at bind, refuses translated/unreadable keys, and sends issue no firmware query");
 return 0;
}
static int case_admission(void)
{
 reset();
 /* ethtool -L shrank the queues between the range check and the lock: the
  * stale SQ of queue 1 is never used. */
 shrink_on_lock=1; assert(mlx5e_peer_xmit(&d,1,&tx)<0 && !notified && !txq[1].locked);
 shrink_on_lock=0; d.real_num_tx_queues=2;
 txq[1].stopped=true; assert(mlx5e_peer_xmit(&d,1,&tx)==-EAGAIN && !notified);
 txq[0].stopped=true; assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && !notified); txq[0].stopped=false;
 room=false; assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && !notified); room=true;
 sq.state=3; assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && !notified); sq.state=1;
 d.running=false; assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && !notified); d.running=true;
 /* mlx5e_netdev_change_profile: the stopped queues of a registered netdev
  * outlive mlx5e_priv_cleanup(), which clears priv->mdev; the send must be
  * refused before anything below priv is read. */
 d.running=false; txq[0].stopped=true; priv.mdev=NULL;
 assert(mlx5e_peer_xmit(&d,0,&tx)==-EAGAIN && !notified && !txq[0].locked);
 priv.mdev=&m; txq[0].stopped=false; d.running=true;
 assert(!mlx5e_peer_xmit(&d,0,&tx) && notified==1 && !txq[0].locked);
 puts("ok 3 - actual mlx5 peer admission rechecks queue range and state under the TX queue lock before touching the SQ");
 return 0;
}
int main(int argc,char **argv)
{
 assert(argc==2);
 if(!strcmp(argv[1],"teardown"))return case_teardown();
 if(!strcmp(argv[1],"mkey"))return case_mkey();
 if(!strcmp(argv[1],"admission"))return case_admission();
 return 2;
}
'''
CASES = ("teardown", "mkey", "admission")


def build(peer, descs, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(SHIM + peer + "\n" + descs + MAIN)
    compiled = subprocess.run(shlex.split(os.environ.get("CC", "cc"))+["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-address", "-Wno-unused-function", "-fsanitize=undefined", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return binary


def run(binary, case):
    return subprocess.run([str(binary), case], capture_output=True, text=True, timeout=15)


def main():
    source = (KERNEL / "drivers/net/ethernet/mellanox/mlx5/core/en_tx.c").read_text()
    marker = "#ifdef CONFIG_XDEV_EXT_MECH\n"
    start = source.rindex(marker, 0, source.index("struct pci_dev *mlx5e_peer_device(")) + len(marker)
    peer = source[start:source.index("\n#endif", start)]
    start = source.index("void mlx5e_free_txqsq_descs(")
    descs = source[start:source.index("\n}\n", start) + 3]
    mutations = [
        ("teardown reported unquiesced", "teardown", peer, descs.replace("mlx5e_peer_complete_wi(wi, -ECANCELED, true)", "mlx5e_peer_complete_wi(wi, -ECANCELED, false)")),
        ("MKEY queried on every send", "mkey", peer.replace(" sq = priv->txq2sq[queue];", " if (mlx5e_peer_check_mkey(priv)) { ret = -EOPNOTSUPP; goto unlock; }\n sq = priv->txq2sq[queue];"), descs),
        ("bind skips MKEY validation", "mkey", peer.replace(" if (mlx5e_peer_check_mkey(priv)) return NULL;", ""), descs),
        ("device MKEY read before the locked queue state checks", "admission", peer.replace(" mkey = priv->mdev->mlx5e_res.hw_objs.mkey;\n", "").replace(" u32 mkey;\n", " u32 mkey = priv->mdev->mlx5e_res.hw_objs.mkey;\n"), descs),
        ("queue range not rechecked under the lock", "admission", peer.replace(" if (queue >= dev->real_num_tx_queues || !netif_running(dev) ||", " if (!netif_running(dev) ||"), descs),
    ]
    failed = []
    with tempfile.TemporaryDirectory(prefix="independent-mlx5-peer-") as tmp:
        directory = Path(tmp)
        actual = build(peer, descs, directory, "actual")
        for case in CASES:
            result = run(actual, case)
            print(result.stdout, end="")
            if result.returncode:
                failed.append(case)
                print(result.stderr, end="", file=sys.stderr)
        if failed:
            raise SystemExit("not ok - actual mlx5 peer hooks failed: " + ", ".join(failed))
        for i, (name, case, changed_peer, changed_descs) in enumerate(mutations):
            assert (changed_peer, changed_descs) != (peer, descs), name
            result = run(build(changed_peer, changed_descs, directory, "mutation" + str(i)), case)
            assert result.returncode != 0, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
