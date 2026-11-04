/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STORAGE_BLOCK_TEST_BOUNDARY_H
#define STORAGE_BLOCK_TEST_BOUNDARY_H
#if defined(BLOCK_NEW) && (!defined(CONFIG_BLOCK) || CONFIG_BLOCK != 1)
#error The whole block runtime fixture requires CONFIG_BLOCK=1
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
typedef __u8 u8;typedef __u16 u16;typedef __u32 u32;typedef __u64 u64;
#define __force
#define __aligned(n) __attribute__((aligned(n)))
/* Exact scalar/flag/hctx declarations extracted from the supplied locked source. */
#include "actual_block_native.inc"
_Static_assert(sizeof(blk_opf_t)==sizeof(__u32),"native blk_opf_t must remain u32");
/* Exact include/linux/blkdev.h declarations, Linux
 * 89be9a83ccf1f88522317ce02f854f30d6115c41 (GPL-2.0).
 * Portions Copyright (C) 1992 Drew Eckhardt. */
typedef unsigned int __bitwise blk_features_t;
#define BLK_FEAT_POLL			((__force blk_features_t)(1u << 9))
#define PAGE_SHIFT 12
#define PAGE_SIZE (1U<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1UL))
#define SECTOR_SHIFT 9
#ifndef BIO_MAX_INLINE_VECS
#define BIO_MAX_INLINE_VECS 4
#endif
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) min((t)(a),(t)(b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define offset_in_page(v) ((v)&(PAGE_SIZE-1))
#define EXPORT_SYMBOL_GPL(name)
#define pr_warn_once(...) ((void)0)
#define atomic64_inc(p) (++*(p))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x,v) (*(volatile __typeof__(x) *)&(x)=(v))
/* Single-thread host boundary only; no kernel atomic/concurrency claim. */
typedef struct {int counter;} atomic_t;
static inline void atomic_set(atomic_t *a,int value){a->counter=value;}
static inline int atomic_read(const atomic_t *a){return a->counter;}
#if defined(BLOCK_FAMILY_7A) || defined(BLOCK_FAMILY_7B)
/* Complete declarations captured from the selected source headers. */
#include "actual_fixture_native.inc"
#endif
struct page {unsigned opaque_id;};
struct blk_mq_queue_map {unsigned nr_queues;};
struct blk_mq_tag_set {unsigned nr_maps;struct blk_mq_queue_map map[HCTX_MAX_TYPES];};
struct blk_mq_hw_ctx {unsigned short type;unsigned queue_num;};
struct queue_limits {u32 align_and_pad;blk_features_t features;};
struct request_queue {struct queue_limits limits;u64 boundary;u32 segments,segment_size,sectors;struct blk_mq_tag_set *tag_set;};
#define queue_virt_boundary(q) ((q)->boundary)
#define blk_lim_dma_alignment_and_pad(l) ((l)->align_and_pad)
#define queue_max_segments(q) ((q)->segments)
#define queue_max_segment_size(q) ((q)->segment_size)
#define queue_max_hw_sectors(q) ((q)->sectors)
struct bio_vec {struct page *page;u32 off,len;};
struct bio {struct bio_vec bi_inline_vecs[128];unsigned initialized;};
struct request {blk_opf_t cmd_flags;struct bio *bio;struct blk_mq_hw_ctx *mq_hctx;};
/* 6A never calls these native poll boundaries. No success stub or poll model. */
static inline bool blk_rq_is_poll(struct request *req){(void)req;fputs("unexpected blk_rq_is_poll in 6A cohort\n",stderr);abort();}
static inline int blk_mq_poll_hw_queue(struct request_queue *q,unsigned n,void *batch){(void)q;(void)n;(void)batch;fputs("unexpected blk_mq_poll_hw_queue in 6A cohort\n",stderr);abort();}
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv;};
struct xdev_ext_mech_pool {struct page **pages;u32 frame_size,nr_frames,nr_pages,first_page_off;u32 kind;};
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;void *priv;u64 arg0,arg1;u32 direction;bool poll;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;
#if defined(BLOCK_FAMILY_7A) || defined(BLOCK_FAMILY_7B)
struct xdev_ext_mech_layout layout;u32 depth;struct {u32 state;} ss;struct xdev_ext_mech_stage st[1];
#endif
};
struct xdev_ext_mech_batch {u32 nr_frames,bytes;struct xdev_ext_mech_frame f[128];u64 id,ticket;void *priv;struct xdev_ext_mech_session *s;struct {u32 stage;} bs;};
#ifdef BLOCK_NEW
#ifdef BLOCK_FAMILY_7B
/* Transparent spelling compatibility: the actual common field is host_io.
 * The same alias is active for actual header and complete source compilation.
 * Slot storage and field type remain the production declaration. */
#define host_io slot
#endif
#include <linux/xdev_ext_storfam_block.h>
#endif
struct nvme_ns {struct request_queue *queue;};
struct nvme_xdev_ext_mech_stage {struct nvme_ns *ns;struct {u8 lba_shift;} identity;u16 nr_vecs;bool write;
#if defined(BLOCK_FAMILY_7A) || defined(BLOCK_FAMILY_7B)
struct xdev_ext_stor_stage family;
#endif
};
#ifdef BLOCK_FAMILY_7B
/* The legacy fixture names now refer to the actual family-owned objects. */
#define nvme_xdev_ext_mech_slot xdev_ext_stor_io
#define nvme_xdev_ext_mech_batch xdev_ext_stor_batch
#else
struct nvme_xdev_ext_mech_slot {struct bio *bio;struct page **bounce;u32 nr_bounce;bool bio_live;};
struct nvme_xdev_ext_mech_batch {struct bio *bio;struct nvme_xdev_ext_mech_slot *slot;struct page **bounce;u32 nr_bounce;};
#endif
extern int native_bio_add_page(struct bio*,struct page*,unsigned,unsigned);
extern void native_bio_init(struct bio*,void*,struct bio_vec*,unsigned,unsigned);
extern void native_bio_uninit(struct bio*);
extern int native_append_bio(struct request*,struct bio*);
#define bio_add_page native_bio_add_page
#define bio_init native_bio_init
#define bio_uninit native_bio_uninit
#define blk_rq_append_bio native_append_bio
struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session*);
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch*);
u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch*);
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch*,u32,struct xdev_ext_mech_frame*);
struct page *xdev_ext_mech_frame_page(const struct xdev_ext_mech_pool*,const struct xdev_ext_mech_frame*,u32,u32*,u32*);
#if defined(BLOCK_FAMILY_7A) || defined(BLOCK_FAMILY_7B)
const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(const struct xdev_ext_mech_session*);
u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch*);
#endif
#ifdef BLOCK_FAMILY_7B
/* These native APIs are declarations only. Uncalled added family exports
 * are discarded after the whole source has compiled; no success stub exists. */
typedef u64 dma_addr_t;
enum dma_data_direction {DMA_BIDIRECTIONAL=0,DMA_TO_DEVICE=1,DMA_FROM_DEVICE=2,DMA_NONE=3};
struct device {unsigned opaque_id;};
struct pci_dev {struct device dev;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define to_pci_dev(p) container_of(p,struct pci_dev,dev)
#define GFP_KERNEL 0
#define SZ_4K 4096U
#define WARN_ON_ONCE(x) (!!(x))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define ERR_CAST(p) ((void *)(p))
void *kcalloc(size_t,size_t,unsigned);
void *kvcalloc(size_t,size_t,unsigned);
void *kzalloc(size_t,unsigned);
void kfree(const void*);
void kvfree(const void*);
struct page *alloc_page(unsigned);
void __free_page(struct page*);
struct bio *bio_kmalloc(unsigned short,unsigned);
void *dma_alloc_coherent(struct device*,size_t,dma_addr_t*,unsigned);
void dma_free_coherent(struct device*,size_t,void*,dma_addr_t);
struct request *blk_mq_alloc_request(struct request_queue*,blk_opf_t,blk_mq_req_flags_t);
void blk_mq_free_request(struct request*);
u32 xdev_ext_mech_session_depth(const struct xdev_ext_mech_session*);
u32 xdev_ext_mech_session_state(const struct xdev_ext_mech_session*);
u64 xdev_ext_mech_batch_ticket(const struct xdev_ext_mech_batch*);
void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch*);
struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(const struct xdev_ext_mech_batch*);
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool*);
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool*);
int xdev_ext_peer_lease_split(struct file*,struct pci_dev*,u64,u64,u32,enum dma_data_direction,struct xdev_ext_peer_fd_lease*);
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease*,bool);
#endif
static inline void memcpy_to_page(struct page *p,u32 o,const void *s,u32 n){(void)p;(void)o;(void)s;(void)n;abort();}
static inline void memcpy_from_page(void *d,struct page *p,u32 o,u32 n){(void)d;(void)p;(void)o;(void)n;abort();}
#endif
