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
#include <assert.h>
#include <linux/types.h>
typedef __u8 u8;typedef __u16 u16;typedef __u32 u32;typedef __u64 u64;
#define __force
#include "actual_native_flags.inc"
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define EXPORT_SYMBOL_GPL(name)
#define PAGE_SIZE 4096U
#define PAGE_SHIFT 12
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
#ifdef STORAGE_CURRENT_COMMON
#include "include/linux/xdev_ext_requester_core.h"
#define ERR_CAST(p) ((void *)(p))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define min_t(t,a,b) ((t)min(a,b))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define SZ_4K 4096U
#define NVME_SGL_FMT_DATA_DESC 0
#define NVME_SGL_FMT_LAST_SEG_DESC 3
#define NVME_REQ_XDEV_EXT_ZC 16U
#define WARN_ON_ONCE(v) (!!(v))
struct page {u8 data[PAGE_SIZE];};
struct bio {unsigned bi_inline_vecs[BIO_MAX_INLINE_VECS],used,capacity,bytes;
struct {sector_t bi_sector;unsigned int bi_size;} bi_iter;};
#ifdef STORAGE_COMMON_TU
struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session*);
u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session*);
u32 xdev_ext_mech_session_state(struct xdev_ext_mech_session*);
void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch*);
u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch*);
struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch*);
void *kzalloc(size_t,int);void *kcalloc(size_t,size_t,int);void *kvcalloc(size_t,size_t,int);
void kfree(void*);void kvfree(void*);
struct bio *bio_kmalloc(u16,int);void bio_uninit(struct bio*);
void bio_init(struct bio*,void*,void*,u32,u32);
void *dma_alloc_coherent(struct device*,size_t,dma_addr_t*,int);
void dma_free_coherent(struct device*,size_t,void*,dma_addr_t);
struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool*);
u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool*);
int xdev_ext_peer_lease_split(struct file*,struct pci_dev*,u64,u64,u32,enum dma_data_direction,struct xdev_ext_peer_fd_lease*);
struct request *blk_mq_alloc_request(struct request_queue*,blk_opf_t,unsigned);
void blk_mq_free_request(struct request*);
void fixture_before_slot(bool,struct xdev_ext_stor_stage*,struct xdev_ext_stor_batch*);
struct xdev_ext_stor_io *fixture_slot_result(struct xdev_ext_stor_io*);
void fixture_before_put(bool,struct xdev_ext_stor_stage*,struct xdev_ext_stor_batch*);
void fixture_before_map(bool);
int __wrap_xdev_ext_stor_block_poll_check(bool,struct request*);
#endif
#endif
#endif
