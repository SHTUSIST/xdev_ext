/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STORAGE_POLL_BOUNDARY_H
#define STORAGE_POLL_BOUNDARY_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
typedef __u8 u8;typedef __u16 u16;typedef __u32 u32;typedef __u64 u64;
#define __force
#include "actual_native_flags.inc"
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define EXPORT_SYMBOL_GPL(name)
#define PAGE_SIZE 4096U
#define SECTOR_SHIFT 9
#define BIO_MAX_INLINE_VECS 4
#define min(a,b) ((a)<(b)?(a):(b))
#define queue_virt_boundary(q) ((q)->boundary)
#define blk_lim_dma_alignment_and_pad(l) ((l)->alignment)
#define queue_max_segments(q) ((q)->segments)
#define queue_max_segment_size(q) ((q)->segment_size)
#define queue_max_hw_sectors(q) ((q)->sectors)
struct blk_mq_queue_map {unsigned nr_queues;};
struct blk_mq_tag_set {unsigned nr_maps;struct blk_mq_queue_map *map;};
struct queue_limits {blk_features_t features;u32 alignment;};
struct request_queue {struct queue_limits limits;struct blk_mq_tag_set *tag_set;u64 boundary;u32 segments,segment_size,sectors;};
struct blk_mq_hw_ctx {unsigned type,queue_num;};
enum rq_end_io_ret {RQ_END_IO_NONE, RQ_END_IO_FREE};
typedef int blk_status_t;
struct request {struct blk_mq_hw_ctx *mq_hctx;blk_opf_t cmd_flags;enum rq_end_io_ret (*end_io)(struct request*,blk_status_t);void *end_io_data;struct bio *bio;u32 bytes;};
struct page;struct bio;struct xdev_ext_mech_pool;
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv;};
struct xdev_ext_mech_batch {u64 id,ticket;void *priv;};
u32 xdev_ext_mech_batch_nr_frames(const struct xdev_ext_mech_batch*);
u32 xdev_ext_mech_batch_bytes(const struct xdev_ext_mech_batch*);
int xdev_ext_mech_batch_frame(const struct xdev_ext_mech_batch*,u32,struct xdev_ext_mech_frame*);
struct page *xdev_ext_mech_frame_page(const struct xdev_ext_mech_pool*,const struct xdev_ext_mech_frame*,u32,u32*,u32*);
int bio_add_page(struct bio*,struct page*,u32,u32);
int blk_rq_append_bio(struct request*,struct bio*);
#include <linux/xdev_ext_storfam_runtime.h>
#include "consumer_types.h"
void boundary_read(const void*,size_t);
void boundary_before_write(const void*,size_t,const void*);
#define READ_ONCE(x) ({ __typeof__(x) _v=*(volatile __typeof__(x) *)&(x);boundary_read(&(x),sizeof(x));_v; })
#define WRITE_ONCE(x,v) ({ __typeof__(x) _v=(v);boundary_before_write(&(x),sizeof(x),&_v);*(volatile __typeof__(x) *)&(x)=_v;_v; })
bool blk_rq_is_poll(struct request*);
int blk_mq_poll_hw_queue(struct request_queue*,unsigned,void*);
int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch*,u64);
void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch*,u64,int,bool);
void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch*,u64,int);
#ifdef STORAGE_MEMBER_FAMILY
const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session*);
u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch*);
int fixture_window_bind(struct xdev_ext_stor_window*,u64,u8,bool,u64,u64,u32);
#define xdev_ext_stor_window_bind(...) fixture_window_bind(__VA_ARGS__)
#endif
#endif
