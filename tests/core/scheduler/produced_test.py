#!/usr/bin/env python3
"""Run native produced-length callback and worker tail retirement from core."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

from run import generate, HERE, ROOT

CASE = r'''
int main(void) {
 struct xdev_ext_mech_session s={0};
 struct xdev_ext_mech_batch b={0};
 struct xdev_ext_mech_life life[3];
 u8 custody[3]={XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_HELD};
 u8 reserved[3]={0};
 s.life=life;s.transform_owner=reserved;s.nr_stages=3;s.depth=1;s.batches=&b;
 s.pool=(struct xdev_ext_mech_pool){.ops=&pool_ops,.state=custody,.nr_frames=3};
 xdev_ext_mech_sess_init(&s.ss);
 for(u32 i=0;i<3;i++) {
  xdev_ext_mech_life_init(&life[i]);
  s.st[i]=(struct xdev_ext_mech_stage){.s=&s,.index=i,.cls=&cls,
   .class_id=XDEV_EXT_MECH_CLASS_SOCKET,.direction=i?XDEV_EXT_MECH_DIR_TO_DEVICE:XDEV_EXT_MECH_DIR_FROM_DEVICE};
  s.plan[i]=(struct xdev_ext_mech_stage_uapi){.class_id=s.st[i].class_id,.direction=s.st[i].direction};
  b.f[i]=(struct xdev_ext_mech_frame){.index=i,.data_len=128};
 }
 s.plan[2].flags=XDEV_EXT_MECH_STAGE_F_FANOUT;
 b.s=&s;b.nr_frames=3;b.present=7;b.bytes=384;b.priv=priv[0];b.cookie=cookies[0];b.to_user=true;
 xdev_ext_mech_bstate_init(&b.bs,3);xdev_ext_mech_batch_step(&b.bs,XDEV_EXT_MECH_EV_READY,0);
 xdev_ext_mech_batch_run(&s,&b);
 REQUIRE(accepts[0]==1,"variable producer was submitted");
 xdev_ext_mech_batch_complete_produced(&b,tickets[0],0,180);
 CHECK(b.bytes==180 && b.f[0].data_len==128 && b.f[1].data_len==52 && b.f[2].data_len==0,"callback trims byte spans before publication");
 CHECK(life[0].valid_len==128 && life[1].valid_len==52,"callback publishes exact per-frame valid lengths");
 CHECK(xdev_ext_mech_life_refs(&life[0])==2 && xdev_ext_mech_life_refs(&life[1])==2,"each produced frame carries both downstream references");
 CHECK(xdev_ext_mech_life_phase(&life[2])==XDEV_EXT_MECH_L_FREE && xdev_ext_mech_life_gen(&life[2])==1 && life[2].valid_len==0,"empty tail never becomes READY");
 CHECK(custody[2]==XDEV_EXT_MECH_F_INFLIGHT,"callback does not run provider custody return");
 u64 words[3]={life[0].ctrl,life[1].ctrl,life[2].ctrl};
 xdev_ext_mech_batch_complete_produced(&b,tickets[0],0,300);
 CHECK(b.bytes==180 && b.f[1].data_len==52 && b.f[2].data_len==0,"duplicate ticket cannot rewrite produced metadata");
 CHECK(life[0].ctrl==words[0] && life[1].ctrl==words[1] && life[2].ctrl==words[2],"duplicate ticket cannot alter lifecycle");
 REQUIRE(!xdev_ext_mech_frames_move(&s,&b,XDEV_EXT_MECH_F_INFLIGHT,XDEV_EXT_MECH_F_HELD),"worker acquired returned provider custody");
 REQUIRE(!xdev_ext_mech_recycle_produced_tail(&s,&b),"real worker tail retirement succeeded");
 CHECK(b.nr_frames==2 && b.present==3 && custody[2]==XDEV_EXT_MECH_F_USER,"only empty tail returned to user");
 CHECK(custody[0]==XDEV_EXT_MECH_F_HELD && custody[1]==XDEV_EXT_MECH_F_HELD,"produced frames retained for consumer group");
 CHECK(!warnings,"production warning count remains zero");
 if(!failures)puts("PASS actual produced callback lengths, refs, empty tail, duplicate, worker retirement (5 checks)");
 return failures!=0;
}
'''


with tempfile.TemporaryDirectory(prefix="fanout-produced-") as tmp:
    tmp = Path(tmp)
    source = tmp / "probe.c"
    source.write_text(generate().replace("int main(int argc,char**argv)",
                                        "int baseline_main(int argc,char**argv)") + CASE)
    binary = tmp / "probe"
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + ["-std=gnu11", "-O1",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-variable",
        "-Wno-unused-parameter", "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
        "-pthread", "-I" + str(ROOT), "-I" + str(HERE), str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
