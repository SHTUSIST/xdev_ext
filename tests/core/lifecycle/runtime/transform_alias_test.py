#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Transform output aliasing: proven once at CREATE, not rescanned per batch.

The pool's pages are pinned at UMEM registration and never change while a
session holds the pool.  xdev_ext_mech_transform_reserve() therefore proves
at CREATE that no reserved output frame shares bytes of a physical page
with any other pool frame.  Per batch, begin keeps the index, range, owner
and state checks and the alias checks against its own batch, but must not
walk every reserved frame of the pool again.  CREATE itself must stay
near-linear in the pool size and offer reschedules under uring_lock.

The pool, page and custody boundary is iaa_transform/lease_fixture.c, with a
page model in which every frame's first half lives at a chosen offset of a
chosen page and its second half on a private page.
"""
import subprocess
import tempfile
import unittest

from lease_boundary import build

FRAME_PAGE = '''static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len) {
 if(f->index>=p->nr_frames || off>=FS)return NULL;
 *po=off;*len=FS-off;return &pages[page_map[f->index]];
}'''
SPLIT_PAGE = '''static unsigned long frame_page_calls;
static u32 base_off[N];
static struct page private_pages[N];
static struct page *xdev_ext_mech_frame_page(struct xdev_ext_mech_pool *p,const struct xdev_ext_mech_frame *f,u32 off,u32 *po,u32 *len) {
 frame_page_calls++;
 if(f->index>=p->nr_frames || off>=FS)return NULL;
 if(off<FS/2){*po=base_off[f->index]+off;*len=FS/2-off;return &pages[page_map[f->index]];}
 *po=off-FS/2;*len=FS-off;return &private_pages[f->index];
}'''

SCENARIO = r'''
static struct xdev_ext_mech_session s;
static struct xdev_ext_mech_batch b;
static int failures;
#define EXPECT(c,msg) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",msg);failures++;}}while(0)
static bool untouched(u32 first,u32 nr) {
 for(u32 i=first;i<first+nr;i++)if(s.pool.state[i]!=XDEV_EXT_MECH_F_USER||s.transform_owner[i])return false;
 return true;
}
int main(int argc,char **argv) {
 assert(argc==3);const char *mode=argv[1];u32 reserved=(u32)atoi(argv[2]);
 setup(&s);
 if(!strcmp(mode,"begin_cost")) {
  /* Cost of one batch must not depend on other reserved output frames. */
  source(&s,&b,0);
  assert(!xdev_ext_mech_transform_reserve(&s.st[0],10,2));
  if(reserved)assert(!xdev_ext_mech_transform_reserve(&s.st[1],20,reserved));
  struct xdev_ext_mech_frame dst[]={frame(10,FS),frame(11,FS)};
  frame_page_calls=0;
  EXPECT(!xdev_ext_mech_batch_transform_begin(&b,dst,2),"valid lease refused");
  printf("BEGIN_FRAME_PAGE_CALLS %lu\n",frame_page_calls);
 } else if(!strcmp(mode,"reserve_cost")) {
  frame_page_calls=0;test_reschedules=0;
  EXPECT(!xdev_ext_mech_transform_reserve(&s.st[0],16,reserved),"large reservation refused");
  printf("RESERVE_FRAME_PAGE_CALLS %lu RESCHEDULES %lu\n",frame_page_calls,test_reschedules);
  EXPECT(test_live_allocs==0,"reservation leaked its scratch table");
 } else if(!strcmp(mode,"semantics")) {
  /* Frames 30 and 10 share a page at disjoint offsets: not an alias. */
  page_map[30]=page_map[10];base_off[30]=FS/2;
  EXPECT(!xdev_ext_mech_transform_reserve(&s.st[0],10,3),"disjoint bytes of a shared page refused");
  xdev_ext_mech_transform_unreserve(&s.st[0],10,3);EXPECT(untouched(10,3),"unreserve");
  /* Overlapping bytes of the shared page alias reserved frame 10. */
  base_off[30]=FS/4;
  EXPECT(xdev_ext_mech_transform_reserve(&s.st[0],10,3)==-EINVAL,"output aliasing a later frame accepted");
  EXPECT(untouched(10,3),"refused reservation changed custody");
  EXPECT(xdev_ext_mech_transform_reserve(&s.st[0],30,1)==-EINVAL,"output aliasing an earlier frame accepted");
  page_map[30]=30;base_off[30]=0;
  /* Two reserved frames of one stage alias each other. */
  page_map[12]=page_map[11];
  EXPECT(xdev_ext_mech_transform_reserve(&s.st[0],10,3)==-EINVAL,"aliasing reserved outputs accepted");
  EXPECT(untouched(10,3),"refused reservation changed custody");
  page_map[12]=12;
  /* Aliases among ordinary frames only are not the reservation's concern. */
  page_map[51]=page_map[50];
  EXPECT(!xdev_ext_mech_transform_reserve(&s.st[0],10,3),"unrelated ordinary aliases refused a reservation");
  /* A later stage's output aliasing an earlier stage's output. */
  page_map[40]=page_map[11];
  EXPECT(xdev_ext_mech_transform_reserve(&s.st[1],40,2)==-EINVAL,"outputs of two stages alias");
  EXPECT(untouched(40,2)&&s.transform_owner[11]==1,"refused second stage disturbed custody");
  page_map[40]=40;
  EXPECT(!xdev_ext_mech_transform_reserve(&s.st[1],40,2),"independent second stage refused");
  EXPECT(xdev_ext_mech_transform_reserve(&s.st[1],12,1)==-EBUSY,"overlapping reservation not busy");
  /* The last frame of the pool and a reservation covering it. */
  EXPECT(!xdev_ext_mech_transform_reserve(&s.st[0],N-1,1),"last pool frame refused");
  EXPECT(xdev_ext_mech_transform_reserve(&s.st[0],N-1,2)==-EINVAL,"reservation past the pool accepted");
  EXPECT(test_live_allocs==0,"reservation leaked its scratch table");
 } else return 2;
 if(!failures)printf("PASS %s\n",mode);
 return failures!=0;
}
'''


def run(binary, *args):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=60)
    return result


class TransformAlias(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev_ext-transform-alias-')
        cls.addClassCleanup(cls.tmp.cleanup)
        patches = ((FRAME_PAGE, SPLIT_PAGE),)
        cls.small = build(SCENARIO, cls.tmp.name, nr_frames=80, name='small', patches=patches)
        cls.large = build(SCENARIO, cls.tmp.name, nr_frames=4096, name='large', patches=patches)

    def value(self, binary, mode, reserved, key):
        result = run(binary, mode, str(reserved))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        words = result.stdout.split()
        return int(words[words.index(key) + 1])

    def test_reservation_aliasing_is_byte_precise(self):
        for binary in (self.small, self.large):
            result = run(binary, 'semantics', '0')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_begin_does_not_rescan_other_reserved_outputs(self):
        alone = self.value(self.large, 'begin_cost', 0, 'BEGIN_FRAME_PAGE_CALLS')
        crowded = self.value(self.large, 'begin_cost', 2048, 'BEGIN_FRAME_PAGE_CALLS')
        self.assertEqual(crowded, alone, 'begin walked other reserved outputs per batch')

    def test_begin_cost_is_independent_of_pool_size(self):
        small = self.value(self.small, 'begin_cost', 40, 'BEGIN_FRAME_PAGE_CALLS')
        large = self.value(self.large, 'begin_cost', 40, 'BEGIN_FRAME_PAGE_CALLS')
        self.assertEqual(large, small)

    def test_reservation_is_near_linear_in_pool_size(self):
        frames, reserved = 4096, 2048
        calls = self.value(self.large, 'reserve_cost', reserved, 'RESERVE_FRAME_PAGE_CALLS')
        # Two page segments per frame: a linear walk of the pool plus the table.
        self.assertLessEqual(calls, 4 * (frames + reserved), 'reservation compares frame pairs')

    def test_large_reservation_offers_reschedules(self):
        resched = self.value(self.large, 'reserve_cost', 2048, 'RESCHEDULES')
        self.assertGreater(resched, 0, 'CREATE walks the pool under uring_lock without cond_resched')


if __name__ == '__main__':
    unittest.main(verbosity=2)
