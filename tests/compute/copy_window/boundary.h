/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdev_ext_mech_ce_core.h"
#include "xdev_ext_mech_dma_core.h"
#include "xdev_ext_mech_window.h"
#include "xdev_ext_dma_scope_core.h"
#include "xdev_ext_compfam_core.h"
#if __has_include("xdev_ext_compfam_copy_core.h")
#include "xdev_ext_compfam_copy_core.h"
#define HAVE_TYPED 1
#endif
typedef __u64 u64;
typedef __u32 u32;
typedef __u8 u8;
typedef int atomic_t;
struct list_head { struct list_head *next, *prev; };
struct module; struct file_operations; struct page; struct file; struct xdev_ext_dma_scope_ops;
struct xdev_ext_ce_cookie; struct xdev_ext_dma_cookie;
struct xdev_ext_mech_pool { struct page **pages; u32 nr_pages, first_page_off, frame_size, nr_frames; };
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; u32 depth; struct xdev_ext_mech_pool pool; };
struct xdev_ext_mech_stage { void *priv; struct xdev_ext_mech_session *s; struct file *file; u32 direction; bool poll; };
struct xdev_ext_mech_frame { u64 umem_addr; u32 data_off, data_len, index; };
struct xdev_ext_mech_batch { u64 id; u32 slot, nr; int frame_error, claim_refuse; u32 claim_calls; struct xdev_ext_mech_frame frame[32]; u64 owner[32], generation[32]; unsigned char payload[8192]; };
#define PAGE_SHIFT 12
#define GFP_KERNEL 0
#define U64_MAX UINT64_MAX
#define READ_ONCE(x) (x)
static void *kzalloc(size_t n, int flags) { return calloc(1,n); }
static void kfree(void *p) { free(p); }
static void module_put(struct module *p) { (void)p; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s) { return s->depth; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->layout; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { return b->nr; }
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch *b) { return b->slot; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { return b->id; }
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b, u32 i, struct xdev_ext_mech_frame *f) { if (b->frame_error) return b->frame_error; *f=b->frame[i]; return 0; }
static int xdev_ext_mech_batch_frame_claim(const struct xdev_ext_mech_batch *batch, u32 pos, u64 *owner, u64 *generation) {
 struct xdev_ext_mech_batch *b=(void *)batch; b->claim_calls++;
 if (pos>=b->nr || (int)pos==b->claim_refuse) return -EACCES;
 *owner=b->owner[pos]; *generation=b->generation[pos]; return 0;
}
#define EQ(a,b) do { long long aa=(long long)(a),bb=(long long)(b); if(aa!=bb) { fprintf(stderr,"ASSERT %s:%d: %s=%lld wanted %s=%lld\n",__FILE__,__LINE__,#a,aa,#b,bb); abort(); } } while(0)
