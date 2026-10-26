# SPDX-License-Identifier: GPL-2.0
"""Execute the production range observer and SG zipper; check provider wiring.

These are software fixtures, not evidence of physical DMA execution.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


def function(source, name):
    start = re.search(r'\b' + re.escape(name) + r'\(', source).start()
    start = source.rfind('\n', 0, start) + 1
    opening = source.index('{', start)
    level, end = 1, opening + 1
    while level:
        level += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PREFIX = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t phys_addr_t;
typedef uint64_t dma_addr_t;
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define U32_MAX UINT32_MAX
#define min_t(t,a,b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define offset_in_page(a) ((a) & (PAGE_SIZE - 1))
#define __ffs(a) __builtin_ctzl(a)
struct device { int backend; };
struct dma_map_ops { int unused; };
struct iommu_domain { unsigned long pgsize_bitmap; };
static struct iommu_domain domain = { .pgsize_bitmap = 4096 };
static u64 corrupt_at = UINT64_MAX;
static int lookups;
static const struct dma_map_ops *get_dma_ops(struct device *d) { (void)d; return 0; }
static bool dma_map_direct(struct device *d, const struct dma_map_ops *o)
{ (void)o; return d->backend == 1; }
static bool arch_dma_unmap_page_direct(struct device *d, dma_addr_t a)
{ (void)a; return d->backend == 4; }
static bool use_dma_iommu(struct device *d) { return d->backend == 2 || d->backend == 3; }
static struct iommu_domain *iommu_get_domain_for_dev(struct device *d)
{ return d->backend == 3 ? 0 : &domain; }
static phys_addr_t dma_to_phys(struct device *d, dma_addr_t a)
{ (void)d; lookups++; return a >= corrupt_at ? a + 4096 : a; }
static phys_addr_t iommu_iova_to_phys(struct iommu_domain *d, dma_addr_t a)
{ (void)d; lookups++; a -= 0x100000; return a >= corrupt_at ? a + 4096 : a; }
static void *swiotlb_find_pool(struct device *d, phys_addr_t a)
{ (void)d; return a >= 0x800000 && a < 0x900000 ? &domain : 0; }
'''

RANGE_MAIN = r'''
int main(void)
{
 struct device direct={1}, iommu={2}, unknown={0}, missing={3}, arch={4};
 assert(dma_range_is_unbounced(&direct, 4096+127, 4096+127, 61));
 assert(dma_range_is_unbounced(&direct, 4096+127, 4096+127, 9000));
 assert(dma_range_is_unbounced(&arch, 4096,4096,4096));
 assert(dma_range_is_unbounced(&iommu,4096+127,0x101000+127,9000));
 assert(!dma_range_is_unbounced(&unknown,4096,4096,4096));
 assert(!dma_range_is_unbounced(&missing,4096,0x101000,4096));
 assert(!dma_range_is_unbounced(&direct,4096,4096,0));
 assert(!dma_range_is_unbounced(&direct,UINT64_MAX-9,4096,11));
 assert(!dma_range_is_unbounced(&direct,4096,UINT64_MAX-9,11));
 assert(!dma_range_is_unbounced(&direct,4096,8192,4096));
 assert(!dma_range_is_unbounced(&direct,0x800000,0x800000,4096));
 corrupt_at=8192;
 assert(!dma_range_is_unbounced(&direct,4096+127,4096+127,5000));
 assert(!dma_range_is_unbounced(&iommu,4096+127,0x101000+127,5000));
 /* A backend with sub-page translation granules must inspect the second one. */
 corrupt_at=5120; domain.pgsize_bitmap=1024;
 assert(!dma_range_is_unbounced(&iommu,4096+127,0x101000+127,1500));
 corrupt_at=UINT64_MAX; domain.pgsize_bitmap=0;
 assert(!dma_range_is_unbounced(&iommu,4096,0x101000,4096));
 domain.pgsize_bitmap=4096;
 assert(!dma_range_is_unbounced(&iommu,0,0x100000,4096));
 return 0;
}
'''

TRACE_PREFIX = r'''
struct page { u64 phys; bool peer; };
struct scatterlist { struct page *page; u32 offset,length; dma_addr_t dma; u32 dma_len; struct scatterlist *next; };
struct sg_table { struct scatterlist *sgl; u32 nents,orig_nents; };
#define sg_next(s) ((s)->next)
#define sg_page(s) ((s)->page)
#define sg_phys(s) ((s)->page->phys + (s)->offset)
#define sg_dma_address(s) ((s)->dma)
#define sg_dma_len(s) ((s)->dma_len)
#define page_to_phys(p) ((p)->phys)
#define is_pci_p2pdma_page(p) ((p)->peer)
static bool dma_sgtable_is_unbounced(struct device *d,struct sg_table *s)
{ (void)d; (void)s; return true; }
struct xdev_ext_native_event {
 const char *phase,*origin; u32 class_id; int accepted,status;
 u64 cookie,address; u32 bytes; u64 aux,sequence,native_user_data;
};
static struct xdev_ext_native_event events[64];
static unsigned int emitted;
static bool enabled=true;
static bool trace_native_event_enabled(void) { return enabled; }
static void trace_native_event(struct xdev_ext_native_event *e) { assert(emitted<64); events[emitted++]=*e; }
'''

SG_MAIN = r'''
int main(void)
{
 struct device d={2};
 struct page p[3]={{4096,false},{12288,false},{32768,false}};
 /* Three physical extents, two coalesced DMA entries. Never pair by index. */
 struct scatterlist s[3]={
  {&p[0],128,1024,0x101080,3072,&s[1]},
  {&p[1],64,2048,0x108000,512,&s[2]},
  {&p[2],0,512,0,0,0}};
 struct sg_table t={s,2,3};
 struct xdev_ext_native_event e={.phase="dma_span",.origin="U",.class_id=3};
 /* IOVA has independent runs: emulate the exact expected physical pieces. */
 assert(nvme_native_dma_sg(&d,&t,&e)==false);
 assert(emitted==3);
 assert(events[0].address==4224 && events[0].native_user_data==0x101080 && events[0].aux==0 && events[0].bytes==1024);
 assert(events[1].address==12352 && events[1].native_user_data==0x101480 && events[1].aux==1024 && events[1].bytes==2048);
 assert(events[2].address==32768 && events[2].native_user_data==0x108000 && events[2].aux==3072 && events[2].bytes==512);
 assert(e.sequence==3 && e.aux==3584);
 /* Contiguous source extents can map as one larger DMA span. */
 p[1].phys=4096; s[1].offset=1152; p[2].phys=4096; s[2].offset=3200;
 s[0].dma_len=3584; t.nents=1;
 emitted=0; memset(&e,0,sizeof(e));
 assert(nvme_native_dma_sg(&d,&t,&e));
 assert(emitted==3 && e.sequence==3 && e.aux==3584);
 assert(events[0].accepted && events[1].accepted && events[2].accepted);
 /* A short mapped list, or an extra mapped tail, cannot be sealed complete. */
 s[0].dma_len=3583; emitted=0; memset(&e,0,sizeof(e));
 assert(!nvme_native_dma_sg(&d,&t,&e));
 s[0].dma_len=3585; emitted=0; memset(&e,0,sizeof(e));
 assert(!nvme_native_dma_sg(&d,&t,&e));
 s[0].dma_len=3584; p[1].peer=true; emitted=0; memset(&e,0,sizeof(e));
 assert(!nvme_native_dma_sg(&d,&t,&e));
 /* A mapped-entry boundary can also split the middle of one source extent. */
 p[1].peer=false; s[0].length=3072; s[0].dma_len=1024;
 s[1].offset=3200; s[1].length=512; s[1].dma=0x101480; s[1].dma_len=2560;
 t.nents=t.orig_nents=2; emitted=0; memset(&e,0,sizeof(e));
 assert(nvme_native_dma_sg(&d,&t,&e));
 assert(emitted==3 && e.aux==3584);
 assert(events[1].address==5248 && events[1].bytes==2048 && events[1].aux==1024 && events[1].native_user_data==0x101480);
 assert(events[2].address==7296 && events[2].bytes==512 && events[2].aux==3072 && events[2].native_user_data==0x101c80);
 /* A single original SG extent can itself cross a CPU page boundary. */
 s[0].length=s[0].dma_len=5000; t.nents=t.orig_nents=1;
 emitted=0; memset(&e,0,sizeof(e));
 assert(nvme_native_dma_sg(&d,&t,&e));
 assert(emitted==2 && events[0].bytes==3968 && events[1].address==8192 && events[1].bytes==1032 && e.aux==5000);
 return 0;
}
'''



NVME_PREFIX = r"""
#define NVME_REQ_XDEV_EXT_ZC 16
#define NVME_REQ_USERCMD 2
struct bio_vec { struct page *bv_page; u32 bv_offset,bv_len; };
struct nvme_iod { u32 dma_len; dma_addr_t first_dma; struct sg_table sgt; };
struct nvme_request { u32 flags; };
struct request { struct nvme_request native; struct nvme_iod iod; struct bio_vec bv; u32 payload,nr_segments; bool integrity; };
struct nvme_dev { struct device *dev; };
static struct nvme_request *nvme_req(struct request *r) { return &r->native; }
static struct nvme_iod *blk_mq_rq_to_pdu(struct request *r) { return &r->iod; }
static struct bio_vec req_bvec(struct request *r) { return r->bv; }
static u32 blk_rq_payload_bytes(struct request *r) { return r->payload; }
static u32 blk_rq_nr_phys_segments(struct request *r) { return r->nr_segments; }
static bool blk_integrity_rq(struct request *r) { return r->integrity; }
"""
NVME_MAIN = r"""
int main(void)
{
 struct device d={2}; struct nvme_dev dev={&d}; struct page page={4096,false};
 struct request r={.native={NVME_REQ_USERCMD},.iod={5000,0x101080,{0}},.bv={&page,128,5000},.payload=5000,.nr_segments=1};
 nvme_native_dma_trace(&dev,&r);
 assert(emitted==2 && !strcmp(events[0].phase,"dma_span") && !strcmp(events[0].origin,"U"));
 assert(events[0].address==4224 && events[0].bytes==5000 && events[0].native_user_data==0x101080 && !events[0].sequence && !events[0].aux);
 assert(!strcmp(events[1].phase,"dma_seal") && events[1].accepted && !events[1].status && events[1].bytes==5000 && events[1].aux==1);
 assert(!events[1].address && !events[1].sequence && !events[1].native_user_data);
 /* A repeated request snapshot stays visible rather than being collapsed. */
 nvme_native_dma_trace(&dev,&r); assert(emitted==4);
 nvme_native_dma_unmap(&r);
 assert(emitted==5 && !strcmp(events[4].phase,"dma_unmap") && events[4].cookie==(u64)(uintptr_t)&r && events[4].bytes==5000);
 r.integrity=true; emitted=0; nvme_native_dma_trace(&dev,&r); assert(!events[1].accepted);
 r.integrity=false; r.payload=4999; emitted=0; nvme_native_dma_trace(&dev,&r); assert(!events[1].accepted);
 r.payload=5000; corrupt_at=8192; emitted=0; nvme_native_dma_trace(&dev,&r); assert(!events[0].accepted && !events[1].accepted);
 corrupt_at=UINT64_MAX; r.native.flags=0; emitted=lookups=0; nvme_native_dma_trace(&dev,&r); assert(!emitted && !lookups);
 r.native.flags=NVME_REQ_USERCMD; r.nr_segments=0; nvme_native_dma_trace(&dev,&r); assert(!emitted && !lookups);
 r.nr_segments=1; r.native.flags=NVME_REQ_XDEV_EXT_ZC; emitted=0; nvme_native_dma_trace(&dev,&r); assert(!strcmp(events[0].origin,"K"));
 enabled=false; emitted=lookups=0; nvme_native_dma_trace(0,0); nvme_native_dma_unmap(0); assert(!emitted && !lookups);
 return 0;
}
"""

POOL_PREFIX = r"""
#define XSK_NEXT_PG_CONTIG_MASK 1ULL
struct umem { u32 npgs; struct page **pgs; };
struct xsk_buff_pool {
 u32 dma_pages_cnt; dma_addr_t *dma_pages; struct device *dev;
 struct umem *umem; bool unaligned; u32 tx_metadata_len;
};
"""
POOL_MAIN = r"""
int main(void)
{
 struct device d={2}; struct page p[2]={{4096,false},{8192,false}};
 struct page *pages[2]={&p[0],&p[1]};
 dma_addr_t maps[2]={0x101001,0x102000};
 struct umem u={2,pages}; struct xsk_buff_pool pool={2,maps,&d,&u,false,0};
 xp_native_dma_trace(&pool);
 assert(emitted==3 && events[0].native_user_data==0x101000);
 assert(events[0].address==4096 && events[0].bytes==4096 && events[0].aux==0 && events[0].sequence==0);
 assert(events[1].address==8192 && events[1].aux==4096 && events[1].sequence==1);
 assert(!strcmp(events[2].phase,"dma_seal") && events[2].accepted && events[2].status==0);
 assert(events[2].bytes==8192 && events[2].aux==2 && events[2].address==0 && events[2].sequence==0 && events[2].native_user_data==0);
 emitted=0; corrupt_at=4096;
 xp_native_dma_trace(&pool);
 assert(emitted==3 && !events[0].accepted && !events[1].accepted && !events[2].accepted);
 corrupt_at=UINT64_MAX;
 /* Unsupported layout and incomplete attachment never earn a positive seal. */
 pool.unaligned=true; emitted=0; xp_native_dma_trace(&pool);
 assert(!events[emitted-1].accepted);
 pool.unaligned=false; pool.tx_metadata_len=8; emitted=0; xp_native_dma_trace(&pool);
 assert(!events[emitted-1].accepted);
 pool.tx_metadata_len=0; pool.dma_pages_cnt=1; emitted=0; xp_native_dma_trace(&pool);
 assert(!events[emitted-1].accepted);
 pool.dma_pages_cnt=1048576; emitted=0; xp_native_dma_trace(&pool);
 assert(emitted==1 && !events[0].accepted && !events[0].bytes);
 emitted=0; xp_native_dma_unmap(&pool);
 assert(emitted==1 && !strcmp(events[0].phase,"dma_unmap") && events[0].cookie==(u64)(uintptr_t)&pool);
 enabled=false; emitted=lookups=0; xp_native_dma_trace(0); xp_native_dma_unmap(0);
 assert(!emitted && !lookups);
 return 0;
}
"""

ICE_PREFIX = r"""
typedef uint16_t u16;
struct xdp_desc { u64 addr; u32 len,options; };
struct xsk_buff_pool { int unused; };
struct ice_tx_desc { u64 buf_addr,cmd_type_offset_bsz; };
struct ice_tx_ring { u16 next_to_use; struct ice_tx_desc descriptors[8]; };
#define ICE_TX_DESC(r,i) (&(r)->descriptors[(i)])
#define PKTS_PER_BATCH 4
#define unrolled_count(n)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
static dma_addr_t xsk_buff_raw_get_dma(struct xsk_buff_pool *p,u64 addr) { (void)p;return addr+0x100000; }
static void xsk_buff_raw_dma_sync_for_device(struct xsk_buff_pool *p,dma_addr_t a,u32 n) { (void)p;(void)a;(void)n; }
static bool xsk_is_eop_desc(struct xdp_desc *d) { return !d->options; }
static u64 ice_build_ctob(bool e,int a,u32 len,int z) { (void)e;(void)a;(void)z;return len; }
"""
ICE_MAIN = r"""
int main(void)
{
 struct xsk_buff_pool pool={0}; struct ice_tx_ring ring={0};
 struct xdp_desc d[4]={{4096,100,0},{8192,200,0},{12288,300,0},{16384,400,0}};
 unsigned int bytes=0;
 ice_xmit_pkt(&ring,&pool,&d[0],&bytes);
 assert(emitted==1 && ring.next_to_use==1 && bytes==100);
 assert(!strcmp(events[0].phase,"dma_tx") && !strcmp(events[0].origin,"U"));
 assert(events[0].cookie==(u64)(uintptr_t)&pool && events[0].address==4096 && events[0].bytes==100);
 assert(events[0].native_user_data==ring.descriptors[0].buf_addr && events[0].native_user_data==0x101000);
 assert(events[0].accepted && !events[0].status && !events[0].aux && !events[0].sequence);
 ice_xmit_pkt_batch(&ring,&pool,d,&bytes);
 assert(emitted==5 && ring.next_to_use==5 && bytes==1100);
 assert(events[4].address==16384 && events[4].bytes==400 && events[4].native_user_data==ring.descriptors[4].buf_addr);
 d[0].options=1; emitted=0; ice_xmit_pkt(&ring,&pool,&d[0],&bytes);
 assert(!events[0].accepted && events[0].status==-EOPNOTSUPP);
 enabled=false; emitted=0; ice_native_dma_tx(0,0,0); assert(!emitted);
 return 0;
}
"""


class DMABackingHooks(unittest.TestCase):
    def compile_run(self, source):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'observer.c'
            path.write_text(source)
            binary = Path(temp) / 'observer'
            result = subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra',
                                     '-Werror', '-Wno-unused-function', str(path),
                                     '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_range_observer(self):
        source = (ROOT / 'kernel/kernel/dma/mapping.c').read_text()
        self.assertTrue('bool dma_range_is_unbounced(' in source,
                        'range-aware actual-map observer is missing')
        self.compile_run(PREFIX + function(source, 'dma_range_is_unbounced') + RANGE_MAIN)

    def test_actual_sg_zipper_splits_original_and_mapped_lists(self):
        mapping = (ROOT / 'kernel/kernel/dma/mapping.c').read_text()
        pci = (ROOT / 'kernel/drivers/nvme/host/pci.c').read_text()
        self.assertTrue('static bool nvme_native_dma_sg(' in pci,
                        'mapped SG/source byte zipper is missing')
        functions = '\n'.join((function(mapping, 'dma_range_is_unbounced'),
                               function(pci, 'nvme_native_dma_span'),
                               function(pci, 'nvme_native_dma_sg')))
        self.compile_run(PREFIX + TRACE_PREFIX + functions + SG_MAIN)

    def test_actual_nvme_simple_seal_identity_failures_and_trace_disabled_cost(self):
        mapping = (ROOT / 'kernel/kernel/dma/mapping.c').read_text()
        pci = (ROOT / 'kernel/drivers/nvme/host/pci.c').read_text()
        functions = function(mapping, 'dma_range_is_unbounced') + '\n'
        functions += '\n'.join(function(pci, name) for name in
                                 ('nvme_native_dma_span', 'nvme_native_dma_sg',
                                  'nvme_native_dma_enabled', 'nvme_native_dma_trace',
                                  'nvme_native_dma_unmap'))
        self.compile_run(PREFIX + TRACE_PREFIX + NVME_PREFIX + functions + NVME_MAIN)

    def test_actual_xsk_snapshot_fields_failures_and_trace_disabled_cost(self):
        mapping = (ROOT / 'kernel/kernel/dma/mapping.c').read_text()
        pool = (ROOT / 'kernel/net/xdp/xsk_buff_pool.c').read_text()
        functions = '\n'.join((function(mapping, 'dma_range_is_unbounced'),
                                 function(pool, 'xp_native_dma_trace'),
                                 function(pool, 'xp_native_dma_unmap')))
        self.compile_run(PREFIX + TRACE_PREFIX + POOL_PREFIX + functions + POOL_MAIN)

    def test_actual_ice_single_batch_dma_descriptor_observation(self):
        ice = (ROOT / 'kernel/drivers/net/ethernet/intel/ice/ice_xsk.c').read_text()
        self.assertTrue('static void ice_native_dma_tx(' in ice,
                        'actual ice DMA descriptor observation missing')
        functions = '\n'.join(function(ice, name) for name in
                                ('ice_native_dma_tx', 'ice_xmit_pkt', 'ice_xmit_pkt_batch'))
        self.compile_run(PREFIX + TRACE_PREFIX + ICE_PREFIX + functions + ICE_MAIN)

    def test_snapshot_at_both_actual_nvme_submission_boundaries(self):
        source = (ROOT / 'kernel/drivers/nvme/host/pci.c').read_text()
        for name in ('nvme_queue_rq', 'nvme_submit_cmds'):
            actual = function(source, name)
            self.assertIn('nvme_native_dma_trace(', actual,
                          name + ' omits actual mapped snapshot')
            self.assertLess(actual.index('nvme_native_dma_trace('),
                            actual.index('nvme_sq_copy_cmd('))
        actual = function(source, 'nvme_unmap_data')
        self.assertIn('nvme_native_dma_unmap(', actual)
        self.assertLess(actual.index('nvme_native_dma_unmap('),
                        actual.index('dma_unmap_page('))

    def test_xsk_reused_mapping_and_detach_are_observed(self):
        source = (ROOT / 'kernel/net/xdp/xsk_buff_pool.c').read_text()
        actual = function(source, 'xp_dma_map')
        self.assertEqual(actual.count('xp_native_dma_trace(pool)'), 2,
                         'new and shared-map attachment both need complete snapshots')
        self.assertIn('xp_native_dma_unmap(pool)', function(source, 'xp_dma_unmap'))
        trace = function(source, 'xp_native_dma_trace')
        self.assertLess(trace.index('trace_native_event_enabled()'),
                        trace.index('pool->dma_pages'))


if __name__ == '__main__':
    unittest.main()
