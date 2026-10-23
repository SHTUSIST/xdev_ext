#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production frames_release sequesters exactly the frames it did not return.

frames_release() hands a finished batch's HELD frames back one position at a
time.  When a later position fails (a broken custody or lifecycle invariant,
WARN-guarded), the earlier frames already belong to user space or the pool
again.  The quarantine must then move every remaining HELD frame to
SEQUESTERED and count exactly those, not leave them HELD behind an
all-or-nothing move that the first returned frame makes fail.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from lease_boundary import build

SCENARIO = r'''
static struct xdev_ext_mech_session s;
static struct xdev_ext_mech_batch b;
static int failures;
#define EXPECT(c,msg) do {if(!(c)){fprintf(stderr,"FAIL: %s\n",msg);failures++;}}while(0)
int main(int argc,char **argv) {
 assert(argc==2);
 setup(&s);memset(&b,0,sizeof(b));b.s=&s;b.nr_frames=3;b.present=7;b.bytes=3*700;
 for(u32 i=0;i<3;i++){b.f[i]=frame(i,700);s.pool.state[i]=XDEV_EXT_MECH_F_HELD;}
 if(!strcmp(argv[1],"late_failure")) {
  /* Position 0 returns to the pool, position 1's return fails. */
  fail_source_return_index=1;
  EXPECT(xdev_ext_mech_frames_release(&s,&b)==-EIO,"failed return reported success");
  EXPECT(s.pool.state[0]==XDEV_EXT_MECH_F_K_FREE&&released[0]==1,"returned frame was taken back");
  EXPECT(s.pool.state[1]==XDEV_EXT_MECH_F_SEQUESTERED,"failing frame stayed HELD");
  EXPECT(s.pool.state[2]==XDEV_EXT_MECH_F_SEQUESTERED,"unreturned frame stayed HELD");
  EXPECT(!released[1]&&!released[2],"unreturned frame reached the pool");
  EXPECT(s.count[XDEV_EXT_MECH_CNT_SEQUESTERED]==2,"sequestered count includes a returned frame");
  EXPECT(s.count[XDEV_EXT_MECH_CNT_RECYCLED]==1,"recycled count changed");
 } else if(!strcmp(argv[1],"validation_failure")) {
  /* A device still owns position 1: nothing may return, HELD ones park. */
  s.pool.state[1]=XDEV_EXT_MECH_F_INFLIGHT;
  EXPECT(xdev_ext_mech_frames_release(&s,&b)==-EIO,"invalid batch reported success");
  EXPECT(s.pool.state[0]==XDEV_EXT_MECH_F_SEQUESTERED&&s.pool.state[2]==XDEV_EXT_MECH_F_SEQUESTERED,
         "HELD frames of an invalid batch stayed HELD");
  EXPECT(s.pool.state[1]==XDEV_EXT_MECH_F_INFLIGHT,"device-owned frame custody changed");
  EXPECT(!released[0]&&!released[1]&&!released[2],"invalid batch returned a frame");
  EXPECT(s.count[XDEV_EXT_MECH_CNT_SEQUESTERED]==2,"sequestered count includes a frame not sequestered");
 } else if(!strcmp(argv[1],"success")) {
  EXPECT(!xdev_ext_mech_frames_release(&s,&b),"valid release failed");
  for(u32 i=0;i<3;i++)EXPECT(s.pool.state[i]==XDEV_EXT_MECH_F_K_FREE&&released[i]==1,"valid frame not returned");
  EXPECT(!s.count[XDEV_EXT_MECH_CNT_SEQUESTERED]&&s.count[XDEV_EXT_MECH_CNT_RECYCLED]==3,"valid release counters");
 } else return 2;
 if(!failures)printf("PASS frames_release %s\n",argv[1]);
 return failures!=0;
}
'''


class FramesRelease(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev_ext-frames-release-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary = build(SCENARIO, cls.tmp.name)

    def probe(self, mode):
        run = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_failure_after_partial_return_sequesters_remaining_frames(self):
        self.probe('late_failure')

    def test_validation_failure_sequesters_only_held_frames(self):
        self.probe('validation_failure')

    def test_valid_batch_returns_every_frame(self):
        self.probe('success')


if __name__ == '__main__':
    unittest.main(verbosity=2)
