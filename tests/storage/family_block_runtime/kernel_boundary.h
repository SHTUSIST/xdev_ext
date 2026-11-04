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
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;void *priv;};
struct xdev_ext_mech_batch {u32 nr_frames,bytes;struct xdev_ext_mech_frame f[128];};
struct nvme_ns {struct request_queue *queue;};
struct nvme_xdev_ext_mech_stage {struct nvme_ns *ns;struct {u8 lba_shift;} identity;u16 nr_vecs;bool write;};
struct nvme_xdev_ext_mech_slot {struct bio *bio;struct page **bounce;u32 nr_bounce;bool bio_live;};
struct nvme_xdev_ext_mech_batch {struct bio *bio;struct nvme_xdev_ext_mech_slot *slot;struct page **bounce;u32 nr_bounce;};
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
static inline void memcpy_to_page(struct page *p,u32 o,const void *s,u32 n){(void)p;(void)o;(void)s;(void)n;abort();}
static inline void memcpy_from_page(void *d,struct page *p,u32 o,u32 n){(void)d;(void)p;(void)o;(void)n;abort();}
#endif
