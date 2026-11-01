/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STORAGE_BLOCK_TEST_BOUNDARY_H
#define STORAGE_BLOCK_TEST_BOUNDARY_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
typedef __u8 u8;typedef __u16 u16;typedef __u32 u32;typedef __u64 u64;
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
struct page {unsigned opaque_id;};
struct queue_limits {u32 align_and_pad;};
struct request_queue {struct queue_limits limits;u64 boundary;u32 segments,segment_size,sectors;};
#define queue_virt_boundary(q) ((q)->boundary)
#define blk_lim_dma_alignment_and_pad(l) ((l)->align_and_pad)
#define queue_max_segments(q) ((q)->segments)
#define queue_max_segment_size(q) ((q)->segment_size)
#define queue_max_hw_sectors(q) ((q)->sectors)
struct bio_vec {struct page *page;u32 off,len;};
struct bio {struct bio_vec bi_inline_vecs[128];unsigned initialized;};
struct request {unsigned cmd_flags;struct bio *bio;};
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
