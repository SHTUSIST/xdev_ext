#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Placement guard for the NIC-boundary fallback guest section (track S).

The section in xdev_ext_integration/xdev_ext_mech_zc_kvm.sh must run after the
zero-copy trace check (its copy-mode calls would otherwise reach the traced
xsk_kernel_xmit/__xsk_rcv) and before the AF_XDP/NVMe programs are detached,
only in the normal non-reliable campaign, with both forced socket fallback and
AF_XDP copy mode, a byte comparison against the source after each run, and a
host-side check of its PASS marker. This is a wiring guard, not guest evidence.
"""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[5]
SCRIPT = ROOT / 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'


class NicFallbackHarness(unittest.TestCase):
    def setUp(self):
        self.text = SCRIPT.read_text()
        start = self.text.index('# --- Track S (appended): NIC-boundary copy fallback')
        self.section = self.text[start:self.text.index('# --- end track S section', start)]
        self.start = start

    def test_position(self):
        trace = self.text.index('echo "XDEV_EXT_ZC_COPY_FALLBACK=PASS calls=$copy_calls"')
        detach = self.text.index('$ctl detach --pin /sys/fs/bpf/zc-afxdp')
        self.assertLess(trace, self.start)
        self.assertLess(self.start, detach)

    def test_content(self):
        s = self.section
        self.assertRegex(s, r'\[ "\$fault" = none \] && \[ "\$reliable" = 0 \] && \[ "\$rx_ce" = 0 \]')
        self.assertEqual(len(re.findall(r'--nic-fallback force', s)), 2)
        self.assertEqual(len(re.findall(r'\$ctl (nic-nvme|nvme-nic) --copy ', s)), 2)
        self.assertEqual(s.count('nicfb_compare\n'), 2)
        self.assertEqual(s.count('nicfb_clear\n'), 2)
        self.assertIn('path=socket nic_copy_ops=$groups', s)
        self.assertIn('path=copy nic_copy_ops=$((groups * nicfb_frames))', s)
        self.assertIn('path=zc nic_copy_ops=0 nic_copy_bytes=0', s)
        self.assertIn('XDEV_EXT_ZC_NIC_FALLBACK=PASS', s)
        self.assertNotRegex(s, r'elapsed|latency|throughput|Gbps|MB/s')

    def test_host_checks_marker(self):
        self.assertIn('grep -Fxq "XDEV_EXT_ZC_NIC_FALLBACK=PASS socket_groups=$GROUP_COUNT', self.text)
        self.assertIn('printf \'nic_fallback=%s\\n\' "$NIC_FALLBACK" >"$ROOT/opt/xdev_ext/nic_fallback.env"', self.text)

    def test_guest_shell_syntax(self):
        guest = self.text[self.text.index("cat >\"$ROOT/init\" <<'GUEST'\n") + len("cat >\"$ROOT/init\" <<'GUEST'\n"):]
        guest = guest[:guest.index('\nGUEST\n')]
        r = subprocess.run(['sh', '-n'], input=guest, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
