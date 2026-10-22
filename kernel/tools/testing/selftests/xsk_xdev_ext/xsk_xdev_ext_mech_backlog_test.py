#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run real AF_XDP RX and pending ownership against a bounded core admission seam.

Core batch admission/completion are controlled scheduling boundaries here, not
an alternative backlog implementation. Payload/guard E2E remains in the guest.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


def extract(source, name, kind='function'):
    pattern = (r'^struct ' + name + r'\s*\{.*?^};' if kind == 'struct' else
               r'^(?:static )?(?:inline )?(?:int|void|unsigned long|bool|s32)\s+' + name + r'\([^;{}]*\)\s*\{.*?^}')
    match = re.search(pattern, source, re.M | re.S)
    return match[0] if match else ''


class Backlog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev-rx-backlog-')
        cls.addClassCleanup(cls.tmp.cleanup)
        source = (ROOT / 'net/xdp/xsk_xdev_ext_mech.c').read_text()
        pending = ROOT / 'net/xdp/xsk_xdev_ext_mech_rx_pending.inc'
        types = '\n'.join(extract(source, n, 'struct') for n in
                         ('xsk_mech_rx_pending_entry', 'xsk_mech_rx_pending'))
        helper = pending.read_text() if pending.exists() else ''
        prog = (ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_prog.h').read_text()
        protocol = '\n'.join(extract(prog, n, 'struct') for n in
                             ('xdev_ext_mp_segment', 'xdev_ext_mp_rx_order'))
        protocol += '\n' + extract(prog.replace('XDEV_EXT_MP_INLINE ', 'static inline '),
                                    'xdev_ext_mp_rx_order')
        code = (HERE / 'xsk_xdev_ext_mech_backlog_fixture.c').read_text()
        has_pending = bool(types.strip())
        code = code.replace('/* PENDING_TYPES */', types)
        code = code.replace('/* PROTOCOL */', protocol)
        code = code.replace('/* PENDING_MEMBER */',
                            'struct xsk_mech_rx_pending pending;' if has_pending else '')
        code = code.replace('/* PENDING_FUNCTIONS */', helper)
        code = code.replace('/* RX_FUNCTION */', extract(source, 'xsk_xdev_ext_mech_rx'))
        core = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
        batch_get = re.search(r'^static struct xdev_ext_mech_batch \*\n'
                              r'xdev_ext_mech_batch_get_locked\([^;]*?\)\n\{.*?^}', core, re.M | re.S)
        assert batch_get is not None, 'must execute the real core batch availability decision'
        code = code.replace('/* CORE_BATCH_GET */', batch_get[0])

        code = code.replace('/* INITIALIZE */', '''
 xst.pending.entries=calloc(pool.nr_frames,sizeof(*xst.pending.entries));
 xst.pending.capacity=capacity;
''' if has_pending else '')
        code = code.replace('/* DUPLICATE */',
                            'CHECK(xsk_xdev_ext_mech_rx(&xs,&f,100,2)==XDEV_EXT_MECH_HOLD);')
        code = code.replace('/* PROGRESS */',
                            'xsk_rx_pending_drain(&st,stop);' if has_pending else '(void)stop;')
        code = code.replace('/* PENDING_COUNT */',
                            'return xs->xdev_ext_mech_rx->priv->pending.count;' if has_pending else 'return 0;')
        path = Path(cls.tmp.name)
        (path/'probe.c').write_text(code)
        cls.exe = path/'probe'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                        '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                        '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                        str(path/'probe.c'), '-o', str(cls.exe)], check=True)

    def run_case(self, mode):
        run = subprocess.run([str(self.exe), mode], capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_depth_saturated_257_groups_retain_then_resume_in_order(self):
        self.run_case('flow')

    def test_core_preaccept_eagain_also_preserves_fifo(self):
        self.run_case('again')

    def test_full_queue_is_explicit_overflow_and_preserves_earlier_owners(self):
        self.run_case('full')

    def test_stop_recycles_pending_once_without_native_submission(self):
        self.run_case('stop')

    def test_stop_winning_during_core_admission_is_local_cancellation(self):
        self.run_case('stop-race')

    def test_stale_pending_cannot_recycle_another_owner(self):
        self.run_case('stale')

    def test_duplicate_frame_does_not_release_original_pending_owner(self):
        self.run_case('duplicate')


HERE = Path(__file__).resolve().parent
if __name__ == '__main__':
    unittest.main(verbosity=2)
