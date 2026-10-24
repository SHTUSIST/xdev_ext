# SPDX-License-Identifier: GPL-2.0
"""Execute real UO journal code without starting providers."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
class UOJournal(unittest.TestCase):
 def test_snapshots_survive_slot_reuse_and_preserve_exact_tx_spans(self):
  source=ROOT/'tests/eval/userspace_orchestrator/uo_bench.c'
  self.assertIn('struct uo_native_record',source.read_text(),'preallocated immutable U journal missing')
  csrc=r'''
#define main uo_actual_main
#include "SOURCE"
#undef main
int main(int argc,char **argv) {
 struct uo u={.native_capacity=4};
 if(argc!=2) return 1;
 u.native_path=argv[1];
 u.native_records=calloc(4,sizeof(*u.native_records));
 u.slot=calloc(2,sizeof(*u.slot));
 if(!u.native_records || !u.slot) return 2;
 u.m.segs=2; u.m.l.seg_len=1024; u.m.l.group_bytes=2048; u.m.l.hdr_room=256;
 u.s.group_bytes=2048; u.s.lba_bytes=512; u.s.slba=100; u.s.burst=1; u.s.nxp_session=9;
 u.s.nvme_io=UO_IO_PASSTHRU_VEC;
 u.slot[1].g=17;
 uo_native_note(&u,"nvme",1,uo_native_cookie(17),0);
 uo_native_note(&u,"tx",1,uo_native_cookie(17),1);
 u.slot[1].g=33;
 if(u.native_records[0].generation!=17 || u.native_records[2].generation!=17) return 3;
 if(u.native_records[2].descriptor_bytes!=1024+XDEV_EXT_MP_PKT_HDR_LEN) return 4;
 if(u.native_records[2].address!=2*UO_CHUNK+256-XDEV_EXT_MP_PKT_HDR_LEN) return 5;
 uo_native_note(&u,"record_terminal",1,uo_native_cookie(33),1);
 if(!u.native_lost || u.native_count!=4) return 6;
 if(uo_native_flush(&u)) return 7;
 if(uo_native_flush(&u)!=-EEXIST) return 8;
 free(u.native_records);free(u.slot);return 0;
}
'''.replace('SOURCE',str(source))
  with tempfile.TemporaryDirectory() as tmp:
   c=Path(tmp)/'test.c';c.write_text(csrc); binary=Path(tmp)/'test'; journal=Path(tmp)/'journal.jsonl'
   build=subprocess.run(['cc','-std=gnu11','-O1','-Wall','-Wextra','-Werror',str(c),str(ROOT/'kernel/tools/xdev_ext_xsk_redirect.c'),'-lbpf','-lelf','-lz','-ldl','-o',str(binary)],capture_output=True,text=True)
   self.assertEqual(build.returncode,0,build.stderr)
   self.assertEqual(subprocess.run([str(binary),str(journal)]).returncode,0)
   lines=[json.loads(line) for line in journal.read_text().splitlines()]
   self.assertEqual(len(lines),5)
   self.assertTrue(lines[0]['lost'])
   self.assertGreater(lines[0]['process_start_ticks'],0)
   self.assertEqual(lines[0]['role'],'sender')
   self.assertTrue(all(r['generation']==17 for r in lines[1:]))
   self.assertEqual([r['kind'] for r in lines[1:]],['nvme','nvme','tx','tx'])
   self.assertEqual([r['frame_ordinal'] for r in lines[1:]],[0,1,0,1])
   self.assertEqual([r['frame_offset'] for r in lines[1:]],[0,1024,0,1024])
   self.assertTrue(all(r['frame_length']==1024 for r in lines[1:]))
   self.assertTrue(all(r['cookie']==(18<<8)|1 for r in lines[1:]))
   self.assertTrue(all(r['record_id']==17 and r['lba']==168 for r in lines[1:]))
if __name__=='__main__': unittest.main()
