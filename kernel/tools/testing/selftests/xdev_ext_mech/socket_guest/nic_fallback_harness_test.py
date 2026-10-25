#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Placement guard for the NIC-boundary fallback guest section (track S).

The section in xdev_ext_integration/xdev_ext_mech_zc_kvm.sh must run after the
zero-copy trace check (its copy-mode calls would otherwise reach the traced
xsk_kernel_xmit/__xsk_rcv) and before the AF_XDP/NVMe programs are detached,
in every fault-free normal campaign (strict included), with both forced socket fallback and
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
        # Track S runs in every fault-free normal campaign, including the
        # strict reliable/rx-ce one; its own sub-cases are never reliable.
        self.assertIn('if [ "$nic_fallback" = 1 ] && [ "$fault" = none ]; then\n', s)
        self.assertNotRegex(s, r'nic_fallback" = 1 \][^\n]*(reliable|rx_ce)')
        self.assertEqual(len(re.findall(r'--nic-fallback force', s)), 2)
        self.assertEqual(len(re.findall(r'\$ctl (nic-nvme|nvme-nic) --copy ', s)), 2)
        self.assertEqual(s.count('nicfb_compare\n'), 3)
        self.assertEqual(s.count('nicfb_clear\n'), 3)
        self.assertIn('path=socket nic_copy_ops=$((groups * nicfb_frames))', s)
        self.assertIn('path=copy nic_copy_ops=$((groups * nicfb_frames))', s)
        self.assertIn('path=zc nic_copy_ops=0 nic_copy_bytes=0', s)
        self.assertIn('XDEV_EXT_ZC_NIC_FALLBACK=PASS', s)
        self.assertIn('XDEV_EXT_ZC_NIC_AUTO_INTEROP=PASS', s)
        self.assertIn('nicfb_rx_policy=auto', s)
        self.assertIn('nicfb_tx_policy=auto', s)
        self.assertNotRegex(s, r'elapsed|latency|throughput|Gbps|MB/s')

    def test_strict_campaign_keeps_track_s(self):
        # Only fault injection and dedicated provider cases switch it off.
        self.assertIn('if [[ "$FAULT" != none || "$PROVIDER_CASE" != normal ]]; then NIC_FALLBACK=0; fi', self.text)
        self.assertNotRegex(self.text, r'RELIABLE" != 0 \|\|[^\n]*then NIC_FALLBACK=0')
        s = self.section
        # The exact zero-copy accounting of the main run is kept where its
        # shape is known (plain AF_XDP run, one data frame per segment).
        main = s.index('if [ "$reliable" = 0 ] && [ "$rx_ce" = 0 ]; then\n')
        self.assertLess(main, s.index('path=zc nic_copy_ops=0 nic_copy_bytes=0 nic_zc_ops=$((groups * nicfb_frames))'))
        self.assertEqual(s.count('path=zc nic_copy_ops=0 nic_copy_bytes=0 nic_zc_ops=$((groups * nicfb_frames)) nic_zc_bytes=$nicfb_bytes'), 2)
        # The reliable campaign published the reliable AF_XDP program; the
        # class has one program, so Track S swaps in the plain one first.
        swap = re.search(r'if \[ "\$reliable" = 1 \]; then\n(?:\s*#[^\n]*\n)*'
                         r'\s*\$ctl detach --pin /sys/fs/bpf/zc-afxdp\n'
                         r'\s*\$ctl attach --obj /opt/xdev_ext/nxp_mech\.bpf\.o --map nxp_afxdp_ops \\\n'
                         r'\s*--pin /sys/fs/bpf/zc-afxdp --set nxp_session=270019\n\s*fi\n', s)
        self.assertIsNotNone(swap)
        self.assertLess(swap.start(), s.index('$ctl nic-nvme --nic-fallback force'))
        # Frames per group come from Track S's own (plain) receiver.
        ready = s.index("nicfb_run_frames=$(/bin/busybox sed -n 's/^XDEV_EXT_MECH_READY mode=nic-nvme .* frames=\\([0-9]*\\) .*/\\1/p' /tmp/nicfb-socket-rx.log)")
        self.assertLess(ready, s.index('path=socket nic_copy_ops=$((groups * nicfb_frames))'))
        self.assertIn('[ -z "$nicfb_frames" ] || test "$nicfb_frames" = "$nicfb_run_frames"', s)

    def test_static_neighbour_uses_a_busybox_applet(self):
        # The guest image only has busybox, whose "ip neigh" implements show
        # and flush; replace/add/change/del exit 1 and stop the guest under
        # set -e before the socket-TX AUTO case runs. busybox arp -s sets a
        # permanent entry (SIOCSARP) and arp -d removes it.
        s = self.section
        self.assertNotRegex(s, r'\bip neigh (replace|add|change|del)\b')
        self.assertEqual(s.count('/bin/busybox arp -i eth0 -s 192.0.2.2 02:00:00:00:00:02\n'), 1)
        self.assertEqual(s.count('/bin/busybox arp -i eth0 -d 192.0.2.2\n'), 1)
        self.assertLess(s.index('ip addr add 192.0.2.1/24 dev eth0'),
                        s.index('/bin/busybox arp -i eth0 -s 192.0.2.2'))
        self.assertLess(s.index('/bin/busybox arp -i eth0 -d 192.0.2.2'),
                        s.index('ip addr del 192.0.2.1/24 dev eth0'))
        # The host refuses to build an image whose busybox lacks the applet.
        self.assertIn("/bin/busybox --list | grep -Fxq arp", self.text)

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
