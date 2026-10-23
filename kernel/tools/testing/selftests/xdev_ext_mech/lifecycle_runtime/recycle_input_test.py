#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Repeated CPU-input START after final reference recycle; actual core scheduler."""
import sys, os, re, subprocess, tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'fanout_scheduler'))
from run import generate, definition, ROOT, HERE
core=(ROOT/'io_uring/xdev_ext_mech.c').read_text()
helper='xdev_ext_mech_start_publication'
body=definition(core,helper) if re.search(r'static int '+helper+r'\(',core) else ''
case=r'''
int main(void) {
 struct xdev_ext_mech_session s={0};struct xdev_ext_mech_batch b={0};
 struct xdev_ext_mech_life life;u8 custody=XDEV_EXT_MECH_F_HELD;u64 input,oldticket;
 s.life=&life;s.nr_stages=1;s.depth=1;s.batches=&b;s.start_recycle=true;
 s.pool=(struct xdev_ext_mech_pool){.ops=&pool_ops,.state=&custody,.nr_frames=1};
 s.plan[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_SOCKET,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 s.st[0]=(struct xdev_ext_mech_stage){.s=&s,.cls=&cls,.class_id=XDEV_EXT_MECH_CLASS_SOCKET,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 xdev_ext_mech_sess_init(&s.ss);xdev_ext_mech_life_init(&life);
 REQUIRE(!xdev_ext_mech_life_claim(&life,XDEV_EXT_MECH_L_OWNER_START,&input),"CPU START input claimed");
 REQUIRE(!xdev_ext_mech_life_publish(&life,input,1,128),"CPU START input published");
 b.s=&s;b.nr_frames=1;b.present=1;b.bytes=128;b.priv=priv[0];b.cookie=cookies[0];b.to_user=true;
 b.f[0]=(struct xdev_ext_mech_frame){.index=0,.data_len=128};
 xdev_ext_mech_bstate_init(&b.bs,1);xdev_ext_mech_batch_step(&b.bs,XDEV_EXT_MECH_EV_READY,0);
 xdev_ext_mech_batch_run(&s,&b);REQUIRE(accepts[0]==1,"first native consumer accepted");oldticket=tickets[0];
 callback(0,0);xdev_ext_mech_batch_drain(&s.drain_work);
 REQUIRE(xdev_ext_mech_life_phase(&life)==XDEV_EXT_MECH_L_FREE,"first final reference recycles");
 xdev_ext_mech_bstate_init(&b.bs,1);xdev_ext_mech_batch_step(&b.bs,XDEV_EXT_MECH_EV_READY,0);
 START_PUBLICATION
 xdev_ext_mech_batch_run(&s,&b);REQUIRE(accepts[0]==2,"RECYCLE admits second CPU-input publication");
 u64 word=life.ctrl;xdev_ext_mech_batch_complete(&b,oldticket,0);
 CHECK(word==life.ctrl,"old callback cannot release the republished input");
 callback(0,0);xdev_ext_mech_batch_drain(&s.drain_work);
 CHECK(ends==2&&released==2,"two bounded batches retire exactly once each");
 CHECK(xdev_ext_mech_life_gen(&life)==2,"each publication advances generation only on final put");
 if(!failures)puts("PASS repeated CPU START, final-reference recycle, late-ticket rejection");
 return failures!=0;
}
'''.replace('START_PUBLICATION', 'REQUIRE(!'+helper+'(&s,&b),"CPU input republished after allocator custody");' if body else '/* Existing start_more has no publication here. */')
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'),prefix='recycle-input-') as tmp:
 p=Path(tmp); src=p/'fixture.c'; out=p/'fixture'
 src.write_text(generate().replace('int main(int argc,char**argv)','int baseline_main(int argc,char**argv)')+'\n'+body+case)
 subprocess.run([os.environ.get('CC','gcc'),'-std=gnu11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-fsanitize=undefined','-pthread','-I'+str(ROOT),'-I'+str(HERE),str(src),'-o',str(out)],check=True)
 raise SystemExit(subprocess.run([str(out)]).returncode)
