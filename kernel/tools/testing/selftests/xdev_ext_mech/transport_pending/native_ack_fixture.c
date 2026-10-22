
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define XDEV_EXT_MECH_F_INFLIGHT 1
#define XDEV_EXT_MECH_F_HELD 2
#define DMA_BIDIRECTIONAL 0
#define container_of(p, type, field) ((type *)((char *)(p)-offsetof(type, field)))
#define spin_lock_irqsave(p,f) do { (void)(p); (f)=0; } while (0)
#define spin_unlock_irqrestore(p,f) do { (void)(p); (void)(f); } while (0)
struct xdp_desc { u64 addr; u32 len; };
struct xdev_ext_mech_batch { u64 group; };
struct xdev_ext_mech_frame { u32 index; u64 umem_addr; u32 data_off; };
struct xsk_mech_zc_batch { bool uncertain; int status; };
struct xdev_ext_mech_stage;
struct xsk_xdev_ext_mech_tx_batch {
 struct xdev_ext_mech_stage *reliable_stage;
 bool control, cancelled_before_native;
 int native_error;
 struct xsk_mech_zc_batch completion;
 struct xdev_ext_mech_batch *batch;
 u32 attempt;
};
struct xsk_rel_data { u32 count; struct xdp_desc desc[32]; };
struct xsk_rel_control {
 struct xsk_xdev_ext_mech_tx_batch tb;
 struct xdev_ext_mech_frame frame;
 bool busy, uncertain;
};
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xsk_rel_data data[32]; };
struct fake_xp { void *dev, *dma_pages; };
struct xsk_xdev_ext_mech_provider { struct fake_xp *xp; bool stopped; int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct fake_session { struct xdev_ext_mech_pool pool; int native_controls; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; bool dead; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct fake_session *s; };
static int invalid_map_reads, syncs, frame_moves, kicks;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct fake_session *s) { return &s->pool; }
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b) { return b->group; }
static u64 ktime_get_ns(void) { return 42; }
static u64 xp_raw_get_dma(struct fake_xp *xp, u64 address)
{
 if (!xp->dev || !xp->dma_pages) invalid_map_reads++;
 return address;
}
static void dma_sync_single_for_cpu(void *dev, u64 address, u32 len, int direction)
{ (void)dev; (void)address; (void)len; (void)direction; syncs++; }
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p, u32 index, int from, int to)
{ (void)p; (void)index; (void)from; (void)to; frame_moves++; return 0; }
static void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage *st) { st->s->native_controls--; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { (void)st; kicks++; }
/* PRODUCTION_NATIVE_DONE */
