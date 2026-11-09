#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""KV USER planner must retain external source custody until completion or isolation.

Reuses the complete production USER/core lifecycle fixture. Delayed completion,
STOP, deadline and owner death are host boundary controls, not CUDA/device tests.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
for base in (HERE, *HERE.parents):
    if (base / 'source-layout.json').is_file() or (base / 'view.json').is_file():
        sys.path.insert(0, str(base / 'tests/compute'))
        break
else:
    raise RuntimeError('missing owned checkout/view')
from transform_source import owned_dependency, verify_entry  # noqa: E402

verify_entry(__file__, 'tests/benchmarks/kv_restore/test_user_stage_source_lifetime.py')
sys.path.insert(0, str(owned_dependency(
    __file__, 'tests/compute/user_stage/strict_async_test.py').parent))
import strict_async_test as strict  # noqa: E402


CASES = r'''
static int exercise_planner_lifetime(const char *mode) {
 REQUIRE(!real_setup(true,false,false,false),"planner-created host USER binds");
 struct xdev_ext_mech_batch *b=start(0,4092);
 REQUIRE(b&&us->nr_held==1,"producer publishes ready batch to user");
 struct xdev_ext_user_ready ready=take();
 REQUIRE(held_out_pending(b),"consumer source starts OUT_PENDING");
 /* No completion record represents the external consumer's delayed last use. */
 if(!strcmp(mode,"normal")) {
  post(0,ready.ticket,0);progress();drain();
  CHECK(accepts[2]==1,"matching quiesced completion advances once");
  callback(2,0);drain();CHECK(ends==1,"normal completed batch ends");
 } else {
  if(!strcmp(mode,"death"))xdev_ext_user_mark_dead(&session.st[1]);
  else if(!strncmp(mode,"deadline",8))jiffies+=TIMEOUT;
  else xdev_ext_mech_sess_stop(&session.ss);
  progress();drain();
  if(!strcmp(mode,"death")) {
   CHECK(quarantined(b),"owner death without last-use acknowledgement isolates source");
   CHECK(end_how==XDEV_EXT_MECH_END_SEQUESTER,"unknown source never enters ordinary release");
  } else {
   CHECK(us->nr_held==1&&held_out_pending(b)&&!ends,
         "STOP/deadline before external completion retains source custody");
   if(us->nr_held) {
    if(!strcmp(mode,"deadline-noack")) {
     jiffies+=1000;progress();drain();
     CHECK(quarantined(b),"missing last-use acknowledgement through grace isolates source");
    } else {
     post(0,ready.ticket,0);progress();drain();
     CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT,"late quiesced completion safely aborts");
     CHECK(!attempts[2],"cancelled batch never submits downstream");
    }
   }
  }
 }
 CHECK(!warnings,"no production warnings");
 return failures!=0;
}
int main(int argc,char **argv){return argc==2?exercise_planner_lifetime(argv[1]):2;}
'''


def replace_once(code, before, after):
    if code.count(before) != 1:
        raise RuntimeError('existing USER fixture boundary changed: ' + before[:70])
    return code.replace(before, after, 1)


def generate():
    code = strict.generate()
    scheduler = strict.scheduler
    core = scheduler.read_native(strict.ROOT, 'io_uring/xdev_ext_mech.c')
    # Reuse the existing terminal session shell, with the real frame-release
    # decision. Provider recycle and ordered-loan refusal remain OS boundaries.
    start = code.index('static void xdev_ext_mech_end(')
    end = code.index('\n}', start) + 2
    terminal = r'''
static int xdev_ext_mech_start_queue_release(struct xdev_ext_mech_session *s,
 struct xdev_ext_mech_batch *b,bool success) {
 (void)s;(void)b;(void)success;abort(); /* no ordered loan in this test */
}
int xdev_ext_mech_frames_release(struct xdev_ext_mech_session*,struct xdev_ext_mech_batch*);
static void xdev_ext_mech_end(struct xdev_ext_mech_session*s,
 struct xdev_ext_mech_batch*b,int how,int err) {
 ends++;end_how=how;end_err=err;
 if(how!=XDEV_EXT_MECH_END_SEQUESTER)
  CHECK(!xdev_ext_mech_frames_release(s,b),"production frame-release decision");
 xdev_ext_mech_sess_batch_end(&s->ss,how==XDEV_EXT_MECH_END_SEQUESTER);
}
'''
    code = code[:start] + terminal + code[end:]
    release = scheduler.definition(core, 'xdev_ext_mech_pool_frame_state') + '\n'
    release += scheduler.definition(core, 'xdev_ext_mech_frames_release')
    code = replace_once(code, 'static int native_submit(', release + '\nstatic int native_submit(')
    code = replace_once(code, 'static const struct xdev_ext_mech_pool_ops pool_ops={0};',
                        'static void pool_recycle(struct xdev_ext_mech_pool*p,struct xdev_ext_mech_frame*f)'
                        '{(void)p;(void)f;}\n'
                        'static const struct xdev_ext_mech_pool_ops pool_ops={.recycle=pool_recycle};')
    code = replace_once(code, 's->life=life;',
                        'static u8 transform_owner[DEPTH_MAX*FRAMES];'
                        's->transform_owner=transform_owner;s->life=life;')
    helper = owned_dependency(__file__, 'tests/benchmarks/kv_restore/kv_plan.h').read_text()
    pattern = owned_dependency(__file__, 'tests/benchmarks/kv_restore/kv_pattern.h').read_text()
    helper = replace_once(helper, '#include "kv_pattern.h"', pattern)
    code = replace_once(code, 'static int real_setup(', helper + '\nstatic int real_setup(')
    code = replace_once(code,
                        'session.plan[1].arg1=bind_delta;session.plan[1].flags=(strict?XDEV_EXT_USER_F_STRICT_ASYNC:0)|bind_extra;',
                        'kv_plan_user_stage(&session.plan[1],req.fd,TIMEOUT);')
    return code[:code.index('int main(int argc,char **argv)')] + CASES


class UserStageSourceLifetime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='kv-user-lifetime-', dir=HERE)
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        code = generate()
        include = strict.scheduler.compiler_headers(strict.ROOT, work / 'include', code)
        source = work / 'probe.c'
        source.write_text(code)
        cls.binary = work / 'probe'
        command = shlex.split(os.environ.get('CC', 'gcc')) + [
            '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
            '-fsanitize=undefined', '-fno-sanitize-recover=undefined', '-pthread',
            '-I' + str(include), str(source), '-o', str(cls.binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=30)
        cls.evidence = Path(os.environ['XDEV_EXT_B1_EVIDENCE_DIR']) if os.environ.get('XDEV_EXT_B1_EVIDENCE_DIR') else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True, exist_ok=True)
            (cls.evidence / 'probe.c').write_text(code)
            (cls.evidence / 'compile.log').write_text(built.stdout + built.stderr)
            (cls.evidence / 'inputs.json').write_text(json.dumps({
                'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'compiler': command,
                'planner_sha256': hashlib.sha256(owned_dependency(
                    __file__, 'tests/benchmarks/kv_restore/kv_plan.h').read_bytes()).hexdigest(),
                'generated_sha256': hashlib.sha256(code.encode()).hexdigest(),
                'scope': 'Production USER/core/frame-release, existing host boundary controls; no CUDA/DMA',
            }, indent=2) + '\n')
        if built.returncode:
            raise RuntimeError('existing USER fixture failed to compile:\n' + built.stdout + built.stderr)

    def run_case(self, case):
        run = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
        if self.evidence:
            (self.evidence / (case + '.log')).write_text(run.stdout + run.stderr + f'exit={run.returncode}\n')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_normal_completion_advances_once(self):
        self.run_case('normal')

    def test_stop_retains_source_until_late_quiesced_completion(self):
        self.run_case('stop')

    def test_deadline_retains_source_until_late_quiesced_completion(self):
        self.run_case('deadline')

    def test_deadline_without_completion_isolates_after_grace(self):
        self.run_case('deadline-noack')

    def test_owner_death_isolates_unacknowledged_source(self):
        self.run_case('death')


if __name__ == '__main__':
    unittest.main(verbosity=2)
