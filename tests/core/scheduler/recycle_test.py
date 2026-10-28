#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""A terminal CPU transform must recycle its current span, not its old capacity."""
import os
from pathlib import Path
import subprocess
import tempfile

from run import ROOT, HERE, definition, generate


def main():
    core = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
    code = generate().replace('int main(int argc,char**argv)',
                              'int baseline_main(int argc,char**argv)')
    code += '\n' + '\n'.join(definition(core, name) for name in (
        'xdev_ext_mech_start_publication',))
    code += r'''
static void recycle_cb(struct xdev_ext_mech_pool *p, struct xdev_ext_mech_frame *f)
{ (void)p; (void)f; }
int main(void)
{
 struct xdev_ext_mech_session s = {0};
 struct xdev_ext_mech_batch b = {0};
 struct xdev_ext_mech_life life;
 u8 state = XDEV_EXT_MECH_F_HELD, owner = 0;
 struct xdev_ext_mech_class_ops cpu = {.flags = XDEV_EXT_MECH_CLASS_F_TRANSFORM};
 struct xdev_ext_mech_pool_ops ops = {.recycle = recycle_cb};
 u8 payload[64] = {32, 0, 0, 0};
 u32 len = 0;
 u64 claim, generation;
 bool sequester = false;

 s.life = &life; s.nr_stages = 1; s.start_recycle = true;
 s.start_left = 1; s.transform_owner = &owner;
 s.pool = (struct xdev_ext_mech_pool){.ops = &ops, .state = &state,
                                  .nr_frames = 1, .frame_size = 64};
 xdev_ext_mech_sess_init(&s.ss);
 xdev_ext_mech_life_init(&life);
 s.plan[0] = (struct xdev_ext_mech_stage_uapi){
  .class_id = XDEV_EXT_MECH_CLASS_CPU, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
  .fd = -1, .arg0 = XDEV_EXT_CPU_XFORM_PARSE_STRIP, .arg1 = 8};
 s.st[0] = (struct xdev_ext_mech_stage){.s = &s, .cls = &cpu,
  .class_id = XDEV_EXT_MECH_CLASS_CPU, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE};
 b.s = &s; b.nr_frames = 1; b.present = 1; b.bytes = 40; b.to_user = true;
 b.f[0] = (struct xdev_ext_mech_frame){.index = 0, .data_len = 40};
 REQUIRE(!xdev_ext_mech_life_claim(&life, XDEV_EXT_MECH_L_OWNER_START, &claim), "initial claim");
 REQUIRE(!xdev_ext_mech_life_publish(&life, claim, 1, 40), "initial publication");
 REQUIRE(!xdev_ext_mech_batch_acquire(&s, &b), "first CPU acquisition");
 REQUIRE(!xdev_ext_mech_cpu_apply(&(struct xdev_ext_mech_cpu_prims){0},
  XDEV_EXT_CPU_XFORM_PARSE_STRIP, 8, payload, 40, 64, &len), "real strip transform");
 b.f[0].data_len = len; b.bytes = len;
 REQUIRE(!xdev_ext_mech_batch_handoff(&b, 0, &sequester) && !sequester, "native CPU handoff");
 generation = xdev_ext_mech_life_gen(&life);
 REQUIRE(!xdev_ext_mech_frames_release(&s, &b), "completed batch return");
 REQUIRE(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_FREE, "terminal output recycled");
 REQUIRE(xdev_ext_mech_life_gen(&life) == generation + 1, "recycle advances generation once");
 REQUIRE(!xdev_ext_mech_pool_frame_move(&s.pool, 0, XDEV_EXT_MECH_F_K_FREE,
  XDEV_EXT_MECH_F_HELD), "next allocator loan");
 /* start_more reconstructs the CREATE capacity before refreshing publication. */
 b.f[0].data_len = 40; b.bytes = 40;
 REQUIRE(!xdev_ext_mech_start_publication(&s, &b), "next CPU publication");
 REQUIRE(b.f[0].data_len == 32 && b.bytes == 32 && life.valid_len == 32,
         "stripped tail never becomes valid input again");
 REQUIRE(!xdev_ext_mech_batch_acquire(&s, &b), "second CPU exclusive acquisition");
 puts("ok 1 - terminal CPU recycling preserves valid span and renews consumers");
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='cpu-recycle-') as tmp:
        source = Path(tmp) / 'probe.c'
        binary = Path(tmp) / 'probe'
        source.write_text(code)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                        '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                        '-Wno-unused-variable', '-Wno-unused-parameter',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all', '-pthread',
                        '-I' + str(ROOT), '-I' + str(HERE), str(source), '-o', str(binary)],
                       check=True)
        return subprocess.run([str(binary)], check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
