#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NIC-boundary copy-mode accounting is exported and never counted as zero-copy.

Paper 04_implementation.tex:102-107: "The accounting path records the NIC
boundary as copy-mode, so fallback operations are never counted as zero-copy
bindings." Contract: track S API.md 1.3 and 2.1. Checks:
- the append-only TRANSPORT_STATS version 3 layout (versions 1/2 and the
  168-byte legacy STATS unchanged);
- the four session counters, appended without renumbering existing ones;
- the shared zero-copy/copy counter selection used by AF_XDP stages;
- source contract: the core exports the counters through version 3, the
  AF_XDP provider selects counters from the socket's zero-copy state, and the
  socket adapter only ever adds to copy counters.
The socket adapter's counting behaviour itself runs in rx_adapter_test.py.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]

LAYOUT = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "include/linux/xdev_ext_mech.h"
#define S(c) _Static_assert(c, #c)
S(sizeof(struct xdev_ext_mech_stats) == 168);
S(sizeof(struct xdev_ext_mech_transport_stats) == 32);
S(sizeof(struct xdev_ext_mech_transport_stats_v2) == 64);
S(XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3 == 3U);
S(sizeof(struct xdev_ext_mech_transport_stats_v3) == 96);
S(offsetof(struct xdev_ext_mech_transport_stats_v3, v2) == 0);
S(offsetof(struct xdev_ext_mech_transport_stats_v3, nic_copy_ops) == 64);
S(offsetof(struct xdev_ext_mech_transport_stats_v3, nic_copy_bytes) == 72);
S(offsetof(struct xdev_ext_mech_transport_stats_v3, nic_zc_ops) == 80);
S(offsetof(struct xdev_ext_mech_transport_stats_v3, nic_zc_bytes) == 88);
S(XDEV_EXT_MECH_CNT_REJECTS == 0 && XDEV_EXT_MECH_CNT_PUBLISHED == 7);
S(XDEV_EXT_MECH_CNT_NIC_COPY_OPS == 8 && XDEV_EXT_MECH_CNT_NIC_COPY_BYTES == 9);
S(XDEV_EXT_MECH_CNT_NIC_ZC_OPS == 10 && XDEV_EXT_MECH_CNT_NIC_ZC_BYTES == 11);
S(XDEV_EXT_MECH_CNT_NR == 12);
int main(void)
{
 int bad = 0;
 bad |= xdev_ext_mech_nic_ops_counter(true) != XDEV_EXT_MECH_CNT_NIC_ZC_OPS;
 bad |= xdev_ext_mech_nic_ops_counter(false) != XDEV_EXT_MECH_CNT_NIC_COPY_OPS;
 bad |= xdev_ext_mech_nic_bytes_counter(true) != XDEV_EXT_MECH_CNT_NIC_ZC_BYTES;
 bad |= xdev_ext_mech_nic_bytes_counter(false) != XDEV_EXT_MECH_CNT_NIC_COPY_BYTES;
 puts(bad ? "FAIL nic counter selection" : "PASS nic accounting layout");
 return bad;
}
'''


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


class NicAccounting(unittest.TestCase):
    def test_uapi_layout_and_counter_selection(self):
        with tempfile.TemporaryDirectory(prefix='nic-accounting-') as tmp:
            source = Path(tmp) / 'layout.c'
            exe = Path(tmp) / 'layout'
            source.write_text(LAYOUT)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-I' + str(ROOT), str(source), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_core_exports_version_3(self):
        core = strip_comments((ROOT / 'io_uring/xdev_ext_mech.c').read_text())
        self.assertTrue('XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3' in core,
                        'TRANSPORT_STATS must accept and fill version 3')
        for field, counter in (('nic_copy_ops', 'NIC_COPY_OPS'), ('nic_copy_bytes', 'NIC_COPY_BYTES'),
                               ('nic_zc_ops', 'NIC_ZC_OPS'), ('nic_zc_bytes', 'NIC_ZC_BYTES')):
            with self.subTest(field=field):
                self.assertTrue(re.search(r'\b' + field + r'\s*=\s*atomic64_read\(\s*&s->cnt\[XDEV_EXT_MECH_CNT_' +
                                          counter + r'\]\s*\)', core),
                                'version 3 %s must come from s->cnt[XDEV_EXT_MECH_CNT_%s]' % (field, counter))
                self.assertTrue(re.search(r'\b\w+\.' + field + r'\b\s*(\|\||\))', core),
                                'version 3 input %s must be checked to be zero' % field)

    def test_afxdp_selects_counter_by_zero_copy_state(self):
        files = sorted((ROOT / 'net/xdp').glob('xsk_xdev_ext_mech*'))
        text = '\n'.join(strip_comments(p.read_text()) for p in files)
        ops = re.findall(r'xdev_ext_mech_count\([^;]*xdev_ext_mech_nic_ops_counter\(([^()]*)\)', text)
        nbytes = re.findall(r'xdev_ext_mech_count\([^;]*xdev_ext_mech_nic_bytes_counter\(([^()]*)\)', text)
        self.assertGreaterEqual(len(ops), 2, 'AF_XDP TX completion and RX admission must count NIC operations')
        self.assertGreaterEqual(len(nbytes), 2, 'AF_XDP TX completion and RX admission must count NIC bytes')
        for arg in ops + nbytes:
            with self.subTest(arg=arg):
                self.assertTrue(re.search(r'zc\b', arg.strip()), 'counter choice must follow the socket zero-copy state')
        self.assertFalse(re.search(r'XDEV_EXT_MECH_CNT_NIC_(ZC|COPY)_', text),
                         'AF_XDP code must not hard-code a NIC counter; use the zero-copy selection')

    def test_socket_adapter_counts_copy_only(self):
        text = strip_comments((ROOT / 'io_uring/xdev_ext_mech_socket.c').read_text())
        self.assertFalse('XDEV_EXT_MECH_CNT_NIC_ZC_' in text, 'socket adapter counted zero-copy')
        self.assertFalse('xdev_ext_mech_nic_ops_counter' in text, 'socket adapter is always copy-mode')
        self.assertGreaterEqual(text.count('XDEV_EXT_MECH_CNT_NIC_COPY_OPS'), 2, 'send and receive both count')
        self.assertGreaterEqual(text.count('XDEV_EXT_MECH_CNT_NIC_COPY_BYTES'), 2, 'send and receive both count')


if __name__ == '__main__':
    unittest.main(verbosity=2)
