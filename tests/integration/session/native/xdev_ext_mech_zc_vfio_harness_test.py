#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Harness wiring of VFIO passthrough, the real-GPU mode and the NIC model."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'
GPU_GUEST = HERE / 'xdev_ext_gpu_guest.sh'
GPU_DMABUF = HERE / 'xdev_ext_gpu_dmabuf.c'
TB_GUEST = HERE / 'xdev_ext_tb_nhi_guest.sh'


def function(script, name):
    match = re.search(r'(?ms)^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', script)
    assert match, name
    return match.group()


class VfioArguments(unittest.TestCase):
    def setUp(self):
        self.script = HARNESS.read_text()
        self.tmp = tempfile.TemporaryDirectory(prefix='vfio-args-')
        base = Path(self.tmp.name)
        self.helper = base / 'helper.py'
        self.evidence = base / 'evidence'
        self.evidence.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_args(self, devices, ready):
        # The stub answers like vfio_passthrough.py check for the listed BDFs.
        self.helper.write_text(
            'import sys\n'
            f'ready = {sorted(ready)!r}\n'
            'bdf = sys.argv[2]\n'
            'if sys.argv[1] == "check" and bdf in ready:\n'
            '    print("VFIO_READY " + bdf); sys.exit(0)\n'
            'print("REFUSED " + bdf, file=sys.stderr); sys.exit(1)\n')
        program = ('set -euo pipefail\nGPU=0\nGPU_BDF=\n' +
                   f'VFIO_HELPER={self.helper}\nEV={self.evidence}\n' +
                   'VFIO_DEVICES=(' + ' '.join(devices) + ')\n' +
                   'GPU_DEVICE_ID=unknown\n' +
                   function(self.script, 'vfio_qemu_args') +
                   'vfio_qemu_args\nprintf "%s\\n" "${VFIO_ARGS[@]}"\n')
        return subprocess.run(['bash', '-c', program], capture_output=True, text=True)

    def test_every_ready_device_is_assigned_behind_its_own_root_port(self):
        run = self.run_args(['0000:01:00.0', '0000:4a:00.0'], {'0000:01:00.0', '0000:4a:00.0'})
        self.assertEqual(run.returncode, 0, run.stderr)
        args = run.stdout.splitlines()
        self.assertIn('vfio-pci,host=0000:01:00.0,bus=vfio_rp1', args)
        self.assertIn('vfio-pci,host=0000:4a:00.0,bus=vfio_rp2', args)
        self.assertTrue(any(a.startswith('pcie-root-port,id=vfio_rp1,') for a in args))
        self.assertTrue(any(a.startswith('pcie-root-port,id=vfio_rp2,') for a in args))
        self.assertIn('q35-pcihost.pci-hole64-size=256G', args)

    def test_a_device_that_fails_the_guard_stops_the_harness(self):
        run = self.run_args(['0000:01:00.0', '0000:4a:00.0'], {'0000:01:00.0'})
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('0000:4a:00.0 not ready', run.stderr)
        self.assertNotIn('vfio-pci,host=0000:4a:00.0', run.stdout)

    def test_no_devices_add_no_arguments(self):
        run = self.run_args([], set())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), '')

    def test_guard_runs_before_qemu_and_arguments_reach_qemu(self):
        call = self.script.index('\nvfio_qemu_args\n')
        qemu = self.script.index('"$QEMU_TIMEOUT_SECONDS" "$QEMU"')
        self.assertLess(call, qemu)
        self.assertIn('args+=("${VFIO_ARGS[@]}")', self.script)


class ModeRefusals(unittest.TestCase):
    def refuse(self, *options):
        run = subprocess.run(['bash', str(HARNESS), *options], capture_output=True, text=True,
                             env=dict(os.environ, PATH='/usr/bin:/bin'))
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        return run.stderr

    def test_unknown_nic_model_is_refused(self):
        self.assertIn('invalid --nic', self.refuse('--nic', 'e1000'))

    def test_igb_is_refused_where_it_is_not_wired(self):
        self.assertIn('--nic igb applies', self.refuse('--nic', 'igb', '--xdomain'))

    def test_gpu_requires_official_user_space(self):
        self.assertIn('--nvidia-userspace', self.refuse('--gpu', '0000:01:00.0'))

    def test_gpu_excludes_the_cpu_standin_and_other_modes(self):
        for extra in (('--ce-sim',), ('--reliable',), ('--lifecycle',), ('--fault', 'drop-middle')):
            with self.subTest(extra=extra):
                self.assertIn('gpu requires its exclusive correctness mode',
                              self.refuse('--gpu', '0000:01:00.0', '--nvidia-userspace', '/', *extra))

    def test_tb_nhi_is_exclusive_of_gpu_and_xdomain(self):
        for extra in (('--gpu', '0000:01:00.0', '--nvidia-userspace', '/'), ('--lifecycle',)):
            with self.subTest(extra=extra):
                self.assertIn('exclusive correctness mode',
                              self.refuse('--tb-nhi', '0000:4a:00.0', *extra))

    def test_vfio_is_refused_in_modes_with_their_own_qemu_setup(self):
        self.assertIn('vfio devices are not wired', self.refuse('--vfio', '0000:4a:00.0', '--xdomain'))

    def test_tb_nhi_cycles_must_be_a_single_digit_count(self):
        for value in ('x', '10', '-1', ''):
            with self.subTest(value=value):
                self.assertIn('invalid --tb-nhi-cycles',
                              self.refuse('--tb-nhi', '0000:00:0d.2', '--tb-nhi-cycles', value))

    def test_tb_nhi_suboptions_require_the_tb_nhi_mode(self):
        for extra in (('--tb-nhi-cycles', '0'), ('--tb-nhi-enumerate',), ('--tb-nhi-selfloop-echo',)):
            with self.subTest(extra=extra):
                self.assertIn('require --tb-nhi', self.refuse(*extra))

    def test_tb_nhi_poll_needs_enumeration_and_a_bounded_count(self):
        self.assertIn('--tb-nhi-poll requires --tb-nhi-enumerate',
                      self.refuse('--tb-nhi', '0000:00:0d.2', '--tb-nhi-poll', '60'))
        for value in ('x', '-1', '', '301', '1000'):
            with self.subTest(value=value):
                self.assertIn('invalid --tb-nhi-poll',
                              self.refuse('--tb-nhi', '0000:00:0d.2', '--tb-nhi-enumerate',
                                          '--tb-nhi-poll', value))


    def test_selfloop_echo_needs_the_topology_report(self):
        self.assertIn('--tb-nhi-selfloop-echo requires --tb-nhi-enumerate',
                      self.refuse('--tb-nhi', '0000:00:0d.2', '--tb-nhi-selfloop-echo'))


class BusyboxAppletCheck(unittest.TestCase):
    """grep -q stops reading early; with pipefail the writer's SIGPIPE turns a
    present applet into a spurious FAIL (seen with Ubuntu 26.04 busybox)."""

    def test_applet_presence_check_consumes_the_whole_list(self):
        script = HARNESS.read_text()
        checks = re.findall(r'(?m)^.*busybox --list \| grep[^\n]*$', script)
        self.assertTrue(checks)
        for line in checks:
            self.assertNotRegex(line, r'grep -[A-Za-z]*q', line)

    def test_check_survives_a_writer_that_outlives_the_match(self):
        line = next(l for l in HARNESS.read_text().splitlines() if 'busybox --list | grep' in l)
        condition = line.split('||')[0].strip()
        fake = ('busybox() { echo arp; for i in $(seq 1 20000); do echo applet$i; done; }\n')
        program = 'set -euo pipefail\n' + fake + condition.replace('/bin/busybox', 'busybox') + ' && echo FOUND\n'
        for _ in range(5):
            run = subprocess.run(['bash', '-c', program], capture_output=True, text=True)
            self.assertEqual(run.stdout.strip(), 'FOUND', run.stderr)


class GuestGpuWiring(unittest.TestCase):
    def setUp(self):
        self.script = HARNESS.read_text()

    def test_modules_are_unloaded_on_every_guest_exit_path(self):
        finish = re.search(r'(?ms)^finish\(\) \{\n.*?^\}', self.script).group()
        self.assertIn('xdev_ext_gpu_guest.sh unload', finish)
        self.assertLess(finish.index('xdev_ext_gpu_guest.sh unload'), finish.index('poweroff -f'))

    def test_gpu_cases_get_the_ce_window_and_the_host_expects_it(self):
        self.assertIn('"$source_slba" "$ce_slba" "$groups" "$depth" "$ce_len" "$cli_timeout_ms"', self.script)
        block = self.script.index("<<'PYGPUEXPECT'")
        self.assertIn('if (( ${GPU:-0} )); then', self.script[block - 120:block])
        self.assertIn("expected[ce_offset:ce_offset+size] = source[source_offset:source_offset+size]",
                      self.script[block:block + 900])
        self.assertLess(self.script.index("(p/'expected.raw').write_bytes(expected)"), block)
        self.assertIn("ce_sim=options['ce_sim'] or sys.argv[11] == '1'", self.script)

    def test_gpu_verdict_is_recorded_before_the_debug_gate(self):
        # A debug-locking FAIL stops the harness (set -e with pipefail), as in
        # the first strict-debug RTX 5090 window, which left no gpu-result.
        self.assertEqual(self.script.count('python3 -B "$GPU_VALIDATOR"'), 1)
        self.assertEqual(self.script.count('python3 "$DEBUG_HELPER" console'), 1)
        self.assertLess(self.script.index('python3 -B "$GPU_VALIDATOR"'),
                        self.script.index('python3 "$DEBUG_HELPER" console'))

    def test_tb_nhi_mode_builds_usb4_in_and_runs_rebind_cycles(self):
        self.assertIn('if (( ${TB_NHI:-0} )); then cfg -e USB4; fi', self.script)
        self.assertIn('sh /opt/xdev_ext/tb/xdev_ext_tb_nhi_guest.sh "$tb_nhi_cycles"', self.script)
        self.assertIn('grep -Fxq "XDEV_EXT_TB_NHI=PASS cycles=$TB_NHI_CYCLES" "$EV/guest.log"', self.script)

    def test_tb_nhi_defaults_keep_three_rebind_cycles_without_enumeration(self):
        self.assertRegex(self.script, r'(?m)^TB_NHI_CYCLES=3$')
        self.assertRegex(self.script, r'(?m)^TB_NHI_ENUMERATE=0$')

    def test_tb_nhi_enumeration_reaches_the_guest_and_its_report_is_kept(self):
        self.assertIn('--tb-nhi-enumerate) TB_NHI_ENUMERATE=1; shift ;;', self.script)
        self.assertIn('printf \'tb_nhi_enumerate=%s\\n\' "${TB_NHI_ENUMERATE:-0}" >>"$ROOT/opt/xdev_ext/zc.env"',
                      self.script)
        # Positional order in the guest: CYCLES ENUMERATE ECHO POLL.
        self.assertIn('sh /opt/xdev_ext/tb/xdev_ext_tb_nhi_guest.sh "$tb_nhi_cycles" "${tb_nhi_enumerate:-0}" '
                      '"${tb_nhi_selfloop_echo:-0}" "${tb_nhi_poll:-0}"', self.script)
        self.assertIn('printf \'tb_nhi_poll=%s\\n\' "$TB_NHI_POLL" >>"$ROOT/opt/xdev_ext/zc.env"', self.script)
        # The poll lengthens the guest; the QEMU limit grows with it.
        self.assertIn('QEMU_TIMEOUT_SECONDS=$((QEMU_TIMEOUT_SECONDS + TB_NHI_POLL))', self.script)
        self.assertIn('for app in seq tr od; do ln -sf /bin/busybox "$ROOT/bin/$app"; done', self.script)
        keep = 'grep -E \'^XDEV_EXT_TB_NHI_ENUM \' "$EV/guest.log" >"$EV/tb-nhi-enum.txt" || true'
        self.assertIn(keep, self.script)
        poll = 'grep -E \'^XDEV_EXT_TB_NHI_POLL \' "$EV/guest.log" >"$EV/tb-nhi-poll.txt" || true'
        self.assertIn(poll, self.script)
        self.assertLess(self.script.index(poll),
                        self.script.index('grep -Fxq "XDEV_EXT_TB_NHI=PASS cycles=$TB_NHI_CYCLES"'))
        # The report is saved before the verdict can stop the harness.
        self.assertLess(self.script.index(keep),
                        self.script.index('grep -Fxq "XDEV_EXT_TB_NHI=PASS cycles=$TB_NHI_CYCLES"'))

    def test_selfloop_echo_is_off_by_default(self):
        self.assertRegex(self.script, r'(?m)^TB_NHI_SELFLOOP_ECHO=0$')
        self.assertIn('--tb-nhi-selfloop-echo) TB_NHI_SELFLOOP_ECHO=1; shift ;;', self.script)

    def test_selfloop_echo_builds_the_xdomain_module_and_reaches_the_guest(self):
        # Only the echo build has loadable modules; the read-only check is unchanged.
        self.assertIn('if (( ${TB_NHI_SELFLOOP_ECHO:-0} )); then cfg -e MODULES -e MODULE_UNLOAD -m XDEV_EXT_MECH_XDOMAIN; fi',
                      self.script)
        self.assertIn('grep -Fxq CONFIG_XDEV_EXT_MECH_XDOMAIN=m "$BUILD/.config"', self.script)
        self.assertIn('TB_SELFLOOP_MODULE=$BUILD/io_uring/xdomain/xdev_ext_xdomain.ko', self.script)
        self.assertIn('sha256sum "$TB_SELFLOOP_MODULE" >>"$BUILD/xdev-ext-artifacts.sha256"', self.script)
        self.assertIn('cp "$TB_SELFLOOP_MODULE" "$ROOT/opt/xdev_ext/tb/"', self.script)
        self.assertIn('printf \'tb_nhi_selfloop_echo=%s\\n\' "${TB_NHI_SELFLOOP_ECHO:-0}" >>"$ROOT/opt/xdev_ext/zc.env"',
                      self.script)
        self.assertIn('sh /opt/xdev_ext/tb/xdev_ext_tb_nhi_guest.sh "$tb_nhi_cycles" "${tb_nhi_enumerate:-0}" '
                      '"${tb_nhi_selfloop_echo:-0}"', self.script)

    def test_run_only_refuses_a_build_without_the_echo_module(self):
        self.assertIn("verify_tb_selfloop_identity", self.script)
        body = function(self.script, 'verify_tb_selfloop_identity')
        self.assertIn('CONFIG_XDEV_EXT_MECH_XDOMAIN=m', body)
        self.assertIn('$TB_SELFLOOP_MODULE', body)
        self.assertIn('if (( ${TB_NHI_SELFLOOP_ECHO:-0} )); then verify_tb_selfloop_identity; fi', self.script)

    def test_selfloop_echo_report_is_kept_and_a_failure_fails_the_run(self):
        keep = 'grep -E \'^XDEV_EXT_TB_SELFLOOP_ECHO\' "$EV/guest.log" >"$EV/tb-selfloop-echo.txt" || true'
        self.assertIn(keep, self.script)
        verdict = 'grep -Eq \'^XDEV_EXT_TB_SELFLOOP_ECHO=(PASS|NOT_RUN)( |$)\' "$EV/guest.log"'
        self.assertIn(verdict, self.script)
        self.assertLess(self.script.index(keep), self.script.index(verdict))

    def test_finish_reports_driver_counters_of_every_wire_port(self):
        finish = re.search(r'(?ms)^finish\(\) \{\n.*?^\}', self.script).group()
        self.assertIn('XDEV_EXT_ZC_NETDEV_STATS', finish)
        for counter in ('tx_packets', 'rx_packets', 'rx_dropped', 'rx_missed_errors'):
            self.assertIn(counter, finish)

    def test_igb_mode_boots_one_cpu_and_uses_the_qemu_igb_model(self):
        self.assertIn("KERNEL_APPEND+=' maxcpus=1'", self.script)
        # QEMU's igb is an SR-IOV PF: on pcie.0 its VF placeholders take the next
        # slots ("slot 19 function 0 not available for igbvf" on giga), so each
        # port sits behind its own pcie-root-port, as a real NIC would.
        start = self.script.index('nic_args=(-device pcie-root-port')
        block = self.script[start:self.script.index('\n\tKERNEL_APPEND', start)]
        for port, wire, mac in (('nic_rp0', 'wire0', '01'), ('nic_rp1', 'wire1', '02')):
            self.assertIn(f'pcie-root-port,id={port},', block)
            self.assertIn(f'igb,netdev={wire},mac=02:00:00:00:00:{mac},bus={port}', block)
        self.assertIn('cfg -e NET_VENDOR_INTEL -e IGB', self.script)


# Stand-ins for the guest tools: each prints what $FAKE/<name>.out holds and
# exits with $FAKE/<name>.rc (default 0); successful copies move the window.
FAKE_CTL = r'''#!/bin/sh
echo "$*" >>"$FAKE/ctl.calls"
if [ "$1" != ce-chain ]; then
	verb=$1 pin=
	while [ $# -gt 0 ]; do [ "$1" != --pin ] || pin=$2; shift; done
	[ ! -f "$FAKE/$verb-${pin##*/}.sleep" ] || sleep "$(cat "$FAKE/$verb-${pin##*/}.sleep")"
	exit 0
fi
chain= src= slba= dst= dslba= nlb=
while [ $# -gt 0 ]; do
	case $1 in
	--chain) chain=$2; shift ;;
	--src-ng) src=$2; shift ;;
	--slba) slba=$2; shift ;;
	--dst-ng) dst=$2; shift ;;
	--dst-slba) dslba=$2; shift ;;
	--nlb) nlb=$2; shift ;;
	esac
	shift
done
[ ! -f "$FAKE/ce-$chain.dmesg" ] || cat "$FAKE/ce-$chain.dmesg" >>"$FAKE/dmesg.out"
[ ! -f "$FAKE/ce-$chain.sleep" ] || sleep "$(cat "$FAKE/ce-$chain.sleep")"
cat "$FAKE/ce-$chain.out" 2>/dev/null
rc=$(cat "$FAKE/ce-$chain.rc" 2>/dev/null || echo 0)
[ "$rc" != 0 ] || [ -z "$dst" ] || dd if="$src" of="$dst" bs=512 skip="$slba" seek="$dslba" count="$nlb" conv=notrunc 2>/dev/null
exit "$rc"
'''
FAKE_PEER = r'''#!/bin/sh
case $1 in --cuda) shift 3 ;; *) shift 2 ;; esac
src=$1 dst=$2 groups=$3 sslba=$6 dslba=$7
out=peer
[ -z "${FAKE_DMABUF:-}" ] || out=dmabuf-peer
cat "$FAKE/$out.out" 2>/dev/null
rc=$(cat "$FAKE/$out.rc" 2>/dev/null || echo 0)
[ "$rc" != 0 ] || dd if="$src" of="$dst" bs=512 skip="$sslba" seek="$dslba" count=$((groups * 16)) conv=notrunc 2>/dev/null
exit "$rc"
'''
FAKE_DMABUF = r'''#!/bin/sh
if [ "$1" = --caps ]; then
	cat "$FAKE/caps.out" 2>/dev/null
	exit "$(cat "$FAKE/caps.rc" 2>/dev/null || echo 0)"
fi
cat "$FAKE/dmabuf.out" 2>/dev/null
rc=$(cat "$FAKE/dmabuf.rc" 2>/dev/null || echo 0)
[ "$rc" = 0 ] || exit "$rc"
batches=
while [ "$1" != -- ]; do
	[ "$1" != --batches ] || batches=$2
	shift
done
shift
program=$1
shift 3
groups=$3
FAKE_DMABUF=1 "$program" --allocation-fd 3 "$@"
rc=$?
# As the tool: the source window holds GROUPS slots, the last batch read
# slot BATCHES % GROUPS; without --batches the tool refuses to run.
[ -n "$batches" ] || exit 2
echo "XDEV_EXT_GPU_DMABUF vram_holds_last_batch_group=yes group=$((batches % groups))"
exit "$rc"
'''
CE_PASS = ('XDEV_EXT_MECH_CE_WINDOW=PASS chain={chain} written=4 depth=8 poison=0xc3 '
           'reference=frames error=0\n'
           'XDEV_EXT_MECH_CE_GPU=PASS chain={chain}\n'
           'XDEV_EXT_MECH_STATS session=1 state=ACTIVE last_err=0 batches_done=4 batches_abort=0 '
           'rejects=0 recycled=0 held=0 sequestered=0 timeouts=0 inflight=0 native_publish=0\n'
           'CUDA allocation=native released=yes\n')
# Without GPUDirect RDMA the window is a VMM allocation whose POSIX-FD
# export the tool attaches to both CE stage fds.
CE_PASS_VMM = CE_PASS.replace(
    'CUDA allocation=native released=yes\n',
    'CUDA allocation=vmm bdf=0000:01:00.0 va=0x7a4879200000 bytes=32768 mapped=2097152 '
    'export=posix-fd attached=2\nCUDA allocation=vmm released=yes\n')
PEER_PASS = 'peer chain: done=4 abort=0 inflight=0 sequestered=0 status=0\n'
CAPS_GEFORCE = 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=0 dma_buf=0 pointer_rdma=0\n'
GEFORCE_CE = dict(ce_d_out=CE_PASS_VMM.format(chain='d'), ce_a_out=CE_PASS_VMM.format(chain='a'))


class GpuGuestCases(unittest.TestCase):
    """xdev_ext_gpu_guest.sh against stand-in tools in a scratch root; only the
    case logic and the console lines it prints are under test here."""

    def guest(self, env=None, rc=0, **outputs):
        tmp = tempfile.TemporaryDirectory(prefix='gpu-guest-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.root = root
        gpu, fake, bin_dir = root / 'gpu', root / 'fake', root / 'bin'
        for directory in (gpu, fake, bin_dir, root / 'tmp', root / 'dev', root / 'proc/sys/vm',
                          root / 'proc/driver/nvidia', root / 'sys/bus/pci/drivers/nvidia',
                          root / 'sys/bus/pci/devices/0000:01:00.0'):
            directory.mkdir(parents=True, exist_ok=True)
        (root / 'sys/bus/pci/drivers/nvidia/0000:01:00.0').touch()
        (root / 'sys/bus/pci/devices/0000:01:00.0/vendor').write_text('0x10de\n')
        (root / 'sys/bus/pci/devices/0000:01:00.0/device').write_text('0x2b85\n')
        (root / 'proc/devices').write_text('195 nvidia\n509 nvidia-uvm\n')
        (root / 'proc/driver/nvidia/version').write_text('NVRM version: 590.48.01\n')
        (root / 'proc/sys/vm/drop_caches').write_text('')
        (gpu / 'release').write_text('590.48.01\n')
        (root / 'src.img').write_bytes(os.urandom(128 * 512))
        (root / 'dst.img').write_bytes(bytes(256 * 512))
        defaults = {'ce-d.out': CE_PASS.format(chain='d'), 'ce-a.out': CE_PASS.format(chain='a'),
                    'peer.out': PEER_PASS, 'dmabuf-peer.out': PEER_PASS,
                    'dmabuf.out': 'XDEV_EXT_GPU_DMABUF device=0000:01:00.0 dma_buf_supported=1\n',
                    'caps.out': 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=1 dma_buf=1 pointer_rdma=1\n'}
        defaults.update({name.replace('_', '-').replace('-out', '.out').replace('-rc', '.rc')
                         .replace('-sleep', '.sleep').replace('-dmesg', '.dmesg'): value
                         for name, value in outputs.items()})
        for name, value in defaults.items():
            (fake / name).write_text(value)
        for path, text in ((root / 'ctl', FAKE_CTL), (gpu / 'xdev_ext_peer_chain', FAKE_PEER),
                           (gpu / 'xdev_ext_gpu_dmabuf', FAKE_DMABUF),
                           (bin_dir / 'insmod', '#!/bin/sh\necho "$*" >>"$FAKE/insmod.calls"\n'
                            '[ ! -f "$FAKE/insmod.sleep" ] || sleep "$(cat "$FAKE/insmod.sleep")"\n'),
                           (bin_dir / 'dmesg', '#!/bin/sh\ncat "$FAKE/dmesg.out" 2>/dev/null\n'),
                           (bin_dir / 'nvidia-smi', '#!/bin/sh\n'
                            '[ ! -f "$FAKE/smi.sleep" ] || sleep "$(cat "$FAKE/smi.sleep")"\n'
                            'echo "NVIDIA GeForce RTX 5090, '
                            '00000000:01:00.0, 590.48.01, 98.02.2E.40.EE, 32607 MiB"\n')):
            path.write_text(text)
            path.chmod(0o755)
        for name in ('mknod', 'rmmod', 'sync'):
            (bin_dir / name).write_text('#!/bin/sh\nexit 0\n')
            (bin_dir / name).chmod(0o755)
        # One pass, so a scratch root under /tmp is not rewritten again.
        script = re.sub(r'/(?:sys|proc|tmp)/|/dev/nvidia',
                        lambda match: str(root) + match.group(0), GPU_GUEST.read_text())
        image = str(root / 'src.img'), str(root / 'dst.img')
        run = subprocess.run(['sh', '-c', script, 'xdev_ext_gpu_guest.sh', 'run', str(gpu),
                              str(root / 'ctl'), image[0], image[0], image[1], image[1],
                              '0', '64', '4', '4', '32768', '60000'],
                             capture_output=True, text=True, timeout=120,
                             env=dict(os.environ, FAKE=str(fake), PATH=f'{bin_dir}:/usr/bin:/bin',
                                      **(env or {})))
        self.assertEqual(run.returncode, rc, run.stdout + run.stderr)
        return run.stdout

    def verdicts(self, console):
        return {fields['name']: fields for fields in
                (dict(item.split('=', 1) for item in line.split()[1:] if '=' in item)
                 for line in console.splitlines() if line.startswith('XDEV_EXT_GPU_CASE '))}

    def test_stand_ins_pass_every_case(self):
        console = self.guest()
        self.assertEqual({name: v['result'] for name, v in self.verdicts(console).items()},
                         dict.fromkeys(('ce-chain-d', 'ce-chain-a', 'peer-nvme', 'dmabuf-peer'), 'PASS'))
        self.assertIn('XDEV_EXT_GPU_GUEST=PASS failed=0', console)

    def test_nvidia_is_loaded_with_the_ce_backend_enabled(self):
        # nv-xdev_ext-ce-backend.c registers the CE backend only for
        # NVreg_EnableXdevExtCeDma=1; without it every CE stage bind is ENODEV.
        self.guest()
        calls = (self.root / 'fake/insmod.calls').read_text().splitlines()
        self.assertEqual(calls, [f'{self.root}/gpu/nvidia.ko NVreg_EnableXdevExtCeDma=1',
                                 f'{self.root}/gpu/nvidia-uvm.ko'])

    def test_failed_ce_chain_reports_the_create_phase_and_stage(self):
        console = self.guest(
            ce_d_out='diagnostics result=-19 rollback_errno=0 phase=9 stage=0 cleanup=1 valid=15 '
                     'requester=0000:00:00.0 reachability=0 refused=0\n'
                     'xdev_ext_mech_ctl: chain d: No such device\n', ce_d_rc='3\n')
        case = self.verdicts(console)['ce-chain-d']
        self.assertEqual({key: case.get(key) for key in ('result', 'rc', 'create_result', 'phase', 'stage')},
                         dict(result='FAIL', rc='3', create_result='-19', phase='9', stage='0'))
        chains = [line.split() for line in (self.root / 'fake/ctl.calls').read_text().splitlines()
                  if line.startswith('ce-chain ')]
        self.assertEqual(len(chains), 2)
        for words in chains:
            self.assertIn('--diagnostics', words)

    def test_cuda_capabilities_are_printed_for_the_validator(self):
        self.assertIn('\nXDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=1 dma_buf=1 pointer_rdma=1\n',
                      self.guest())
        for outputs in (dict(caps_out='', caps_rc='1\n'), dict(caps_rc='1\n')):
            with self.subTest(**outputs):
                # A probe that failed, even after printing values, is no evidence.
                console = self.guest(**outputs)
                self.assertIn('\nXDEV_EXT_GPU_CAPS bdf=0000:01:00.0 probe=failed\n', console)

    REGISTER_EINVAL = ('peer chain: cuda va=0x7f0000000000 bytes=65536\n'
                       'peer chain failed at register: Invalid argument (-22)\n')
    NO_DMA_BUF = 'XDEV_EXT_GPU_DMABUF device=0000:01:00.0 dma_buf_supported=0\n'
    PIN_REFUSED = '[   14.1] NVRM: XDEV_EXT peer pin: nvidia_p2p_get_pages_persistent failed: -22\n'

    def ce_calls(self):
        return [line.split() for line in (self.root / 'fake/ctl.calls').read_text().splitlines()
                if line.startswith('ce-chain ')]

    def test_ce_chains_use_the_vmm_export_where_cuda_reports_no_rdma(self):
        console = self.guest(caps_out=CAPS_GEFORCE, **GEFORCE_CE)
        cases = self.verdicts(console)
        for name in ('ce-chain-d', 'ce-chain-a'):
            self.assertEqual((cases[name]['result'], cases[name]['allocation']), ('PASS', 'vmm'),
                             cases[name])
        self.assertEqual(cases['ce-chain-a']['compare'], 'equal')
        for words in self.ce_calls():
            self.assertIn('--ce-vmm', words)
            self.assertNotIn('--ce-alloc', words)

    def test_ce_chains_keep_cumemalloc_where_cuda_reports_rdma(self):
        cases = self.verdicts(self.guest())
        for name in ('ce-chain-d', 'ce-chain-a'):
            self.assertEqual((cases[name]['result'], cases[name]['allocation']), ('PASS', 'native'))
        for words in self.ce_calls():
            self.assertIn('--ce-alloc', words)
            self.assertNotIn('--ce-vmm', words)

    def test_a_vmm_pass_needs_the_attach_and_release_lines(self):
        for name, text in (('no attach', CE_PASS_VMM.replace(' attached=2', ' attached=1')),
                           ('released=no', CE_PASS_VMM.replace('vmm released=yes', 'vmm released=no')),
                           ('native lines on GeForce', CE_PASS)):
            with self.subTest(name):
                console = self.guest(caps_out=CAPS_GEFORCE, ce_d_out=text.format(chain='d'),
                                     ce_a_out=CE_PASS_VMM.format(chain='a'))
                self.assertEqual(self.verdicts(console)['ce-chain-d']['result'], 'FAIL')

    def test_a_ce_pass_needs_the_device_window_check(self):
        # Chains d and a copy out to VRAM and back into the same frames:
        # without the device-window line a no-op copy engine would pass.
        window = CE_PASS.split('\n', 1)[0] + '\n'
        for name, text in (('no window line', CE_PASS.replace(window, '')),
                           ('window FAIL', CE_PASS.replace('WINDOW=PASS', 'WINDOW=FAIL')),
                           ('nothing written', CE_PASS.replace('written=4', 'written=0'))):
            for case in ('d', 'a'):
                with self.subTest(name, chain=case):
                    console = self.guest(**{f'ce_{case}_out': text.format(chain=case)})
                    self.assertEqual(self.verdicts(console)[f'ce-chain-{case}']['result'], 'FAIL')

    def test_geforce_refusals_are_unsupported_not_failed(self):
        # What CUDA reported on the RTX 5090: no GPUDirect RDMA, no dma_buf.
        console = self.guest(caps_out=CAPS_GEFORCE, peer_out=self.REGISTER_EINVAL, peer_rc='1\n',
                             dmesg_out=self.PIN_REFUSED, dmabuf_out=self.NO_DMA_BUF, dmabuf_rc='1\n',
                             **GEFORCE_CE)
        cases = self.verdicts(console)
        self.assertEqual({key: cases['peer-nvme'].get(key) for key in ('result', 'reason', 'step', 'errno')},
                         dict(result='UNSUPPORTED', reason='cuda-no-gpudirect-rdma', step='register',
                              errno='-22'))
        self.assertEqual({key: cases['dmabuf-peer'].get(key) for key in ('result', 'reason')},
                         dict(result='UNSUPPORTED', reason='cuda-no-dma-buf'))
        self.assertIn('\nXDEV_EXT_GPU_GUEST=UNSUPPORTED failed=0 unsupported=2\n', console)

    def test_refusals_without_matching_cuda_evidence_still_fail(self):
        for name, outputs in (
                ('peer refused later than REGISTER',
                 dict(caps_out=CAPS_GEFORCE, peer_rc='1\n', dmesg_out=self.PIN_REFUSED,
                      peer_out='peer chain failed at create: Invalid argument (-22)\n')),
                ('REGISTER -22 not from NVIDIA\'s persistent pin',
                 dict(caps_out=CAPS_GEFORCE, peer_out=self.REGISTER_EINVAL, peer_rc='1\n')),
                ('peer REGISTER refused although CUDA reports RDMA',
                 dict(peer_out=self.REGISTER_EINVAL, peer_rc='1\n', dmesg_out=self.PIN_REFUSED)),
                ('no dma_buf although CUDA reports dma_buf',
                 dict(dmabuf_out=self.NO_DMA_BUF, dmabuf_rc='1\n')),
                ('dma_buf export failed after CUDA reported support',
                 dict(caps_out=CAPS_GEFORCE, dmabuf_rc='1\n')),
                ('caps probe failed', dict(caps_out='', caps_rc='1\n', peer_out=self.REGISTER_EINVAL,
                                           peer_rc='1\n', dmabuf_out=self.NO_DMA_BUF, dmabuf_rc='1\n'))):
            with self.subTest(name):
                console = self.guest(**outputs)
                results = {case: v['result'] for case, v in self.verdicts(console).items()}
                self.assertNotIn('UNSUPPORTED', results.values(), results)
                self.assertIn('FAIL', results.values(), results)
                self.assertRegex(console, r'\nXDEV_EXT_GPU_GUEST=FAIL failed=[1-9] unsupported=0\n')

    # A tool blocked in the kernel (a thread left owning RM's GPU locks) never
    # returns; the guest must not wait for it past its limit, must say why,
    # and must skip the later GPU cases so the harness still unloads.
    RM_LOCK_ASSERT = ('[    8.7] NVRM: nvAssertFailedNoLog: Assertion failed: '
                      'GPU lock already acquired by this thread @ locks.c:992\n')

    def test_a_hung_tool_is_bounded_and_the_later_gpu_cases_are_skipped(self):
        started = time.monotonic()
        console = self.guest(env={'XDEV_EXT_GPU_CASE_LIMIT_S': '2'}, ce_d_sleep='60\n',
                             caps_out=CAPS_GEFORCE, **GEFORCE_CE)
        self.assertLess(time.monotonic() - started, 30, 'the guest waited for the hung tool')
        self.assertIn('\nXDEV_EXT_GPU_PROBLEM case=ce-chain-d reason=timeout limit_s=2\n', console)
        cases = self.verdicts(console)
        self.assertEqual((cases['ce-chain-d']['result'], cases['ce-chain-d'].get('reason')),
                         ('FAIL', 'timeout'))
        for name in ('ce-chain-a', 'peer-nvme', 'dmabuf-peer'):
            self.assertEqual((cases[name]['result'], cases[name].get('reason')),
                             ('FAIL', 'skipped-after-timeout'), name)
        self.assertRegex(console, r'\nXDEV_EXT_GPU_GUEST=FAIL failed=4 unsupported=0\n')
        calls = (self.root / 'fake/ctl.calls').read_text()
        self.assertEqual(calls.count('ce-chain --chain a'), 0, calls)

    def test_rm_lock_assertions_stop_the_gpu_cases(self):
        console = self.guest(caps_out=CAPS_GEFORCE, ce_d_dmesg=self.RM_LOCK_ASSERT, **GEFORCE_CE)
        self.assertIn('\nXDEV_EXT_GPU_PROBLEM case=ce-chain-d reason=rm-lock-state\n', console)
        cases = self.verdicts(console)
        for name in ('ce-chain-a', 'peer-nvme', 'dmabuf-peer'):
            self.assertEqual((cases[name]['result'], cases[name].get('reason')),
                             ('FAIL', 'skipped-after-rm-lock-state'), name)
        self.assertIn('XDEV_EXT_GPU_GUEST=FAIL', console)

    def test_rm_lock_assertions_after_the_caps_probe_stop_every_case(self):
        # The probe is CUDA's first use of the GPU; no CE stage may run after it.
        console = self.guest(caps_out=CAPS_GEFORCE, dmesg_out=self.RM_LOCK_ASSERT, **GEFORCE_CE)
        self.assertIn('\nXDEV_EXT_GPU_PROBLEM case=caps reason=rm-lock-state\n', console)
        cases = self.verdicts(console)
        for name in ('ce-chain-d', 'ce-chain-a', 'peer-nvme', 'dmabuf-peer'):
            self.assertEqual((cases[name]['result'], cases[name].get('reason')),
                             ('FAIL', 'skipped-after-rm-lock-state'), name)
        self.assertNotIn('ce-chain', (self.root / 'fake/ctl.calls').read_text())

    # Steps before the cases (module load, the first client open) and the
    # struct_ops attach and detach around them are bounded the same way.
    def hung_module_step(self, step, **hang):
        started = time.monotonic()
        console = self.guest(env={'XDEV_EXT_GPU_CASE_LIMIT_S': '2'}, rc=1, **hang)
        self.assertLess(time.monotonic() - started, 30, f'the guest waited for {step}')
        # These lines can open the console: match them at any line start.
        self.assertRegex(console, rf'(?m)^XDEV_EXT_GPU_PROBLEM case={step} reason=timeout limit_s=2$')
        self.assertRegex(console, rf'(?m)^XDEV_EXT_GPU_MODULES=FAIL step={step} reason=timeout ')
        self.assertNotIn('XDEV_EXT_GPU_CASE ', console)

    def test_a_hung_module_load_is_bounded(self):
        self.hung_module_step('insmod-nvidia', insmod_sleep='60\n')

    def test_a_hung_first_client_open_is_bounded(self):
        # RM boots GSP on the first open (nvidia-smi); a GPU whose GSP still
        # runs from an earlier guest may hang it.
        self.hung_module_step('nvidia-smi', smi_sleep='60\n')

    def test_a_hung_ce_plan_attach_is_bounded(self):
        self.hung_module_step('attach-ce-plan', attach_gpu_ce_sleep='60\n')

    def test_a_hung_ce_plan_detach_skips_the_later_cases(self):
        console = self.guest(env={'XDEV_EXT_GPU_CASE_LIMIT_S': '2'}, detach_gpu_ce_sleep='60\n')
        self.assertIn('\nXDEV_EXT_GPU_PROBLEM case=detach-ce-plan reason=timeout limit_s=2\n', console)
        cases = self.verdicts(console)
        self.assertEqual((cases['ce-chain-d']['result'], cases['ce-chain-a']['result']), ('PASS', 'PASS'))
        for name in ('peer-nvme', 'dmabuf-peer'):
            self.assertEqual((cases[name]['result'], cases[name].get('reason')),
                             ('FAIL', 'skipped-after-timeout'), name)

    def test_a_hung_nvme_detach_fails_the_peer_case_and_still_reattaches(self):
        console = self.guest(env={'XDEV_EXT_GPU_CASE_LIMIT_S': '2'}, detach_zc_nvme_sleep='60\n')
        self.assertIn('\nXDEV_EXT_GPU_PROBLEM case=detach-nvme reason=timeout limit_s=2\n', console)
        cases = self.verdicts(console)
        self.assertEqual((cases['peer-nvme']['result'], cases['peer-nvme'].get('reason')),
                         ('FAIL', 'timeout'))
        self.assertEqual((cases['dmabuf-peer']['result'], cases['dmabuf-peer'].get('reason')),
                         ('FAIL', 'skipped-after-timeout'))
        self.assertIn('attach --obj /opt/xdev_ext/nxp_mech.bpf.o', (self.root / 'fake/ctl.calls').read_text())

    def test_a_hung_nvme_reattach_is_bounded(self):
        started = time.monotonic()
        console = self.guest(env={'XDEV_EXT_GPU_CASE_LIMIT_S': '2'}, attach_zc_nvme_sleep='60\n')
        self.assertLess(time.monotonic() - started, 30, 'the guest waited for the re-attach')
        self.assertIn('\nXDEV_EXT_GPU_PROBLEM case=reattach-nvme reason=timeout limit_s=2\n', console)
        self.assertEqual(self.verdicts(console)['reattach-nvme']['result'], 'FAIL')

    def test_cleanup_after_a_problem_gets_the_short_limit(self):
        # After a hung step the CE plan detach and the NVMe re-attach must not
        # spend a whole case limit each: the main guest still needs time for
        # its campaign, the unload and poweroff within the QEMU limit.
        env = {'XDEV_EXT_GPU_CASE_LIMIT_S': '3', 'XDEV_EXT_GPU_CLEANUP_LIMIT_S': '1'}
        for hang, step in ((dict(ce_d_sleep='60\n', detach_gpu_ce_sleep='60\n'), 'detach-ce-plan'),
                           (dict(detach_zc_nvme_sleep='60\n', attach_zc_nvme_sleep='60\n'), 'reattach-nvme')):
            with self.subTest(step=step):
                console = self.guest(env=env, **hang)
                self.assertRegex(console, r'(?m)^XDEV_EXT_GPU_PROBLEM case=\S+ reason=timeout limit_s=3$')
                self.assertRegex(console, rf'(?m)^XDEV_EXT_GPU_PROBLEM case={step} reason=timeout limit_s=1$')

    def test_unload_is_bounded(self):
        tmp = tempfile.TemporaryDirectory(prefix='gpu-unload-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        bin_dir = root / 'bin'
        for directory in (bin_dir, root / 'tmp', root / 'sys/module/nvidia_uvm/holders',
                          root / 'sys/module/nvidia'):
            directory.mkdir(parents=True, exist_ok=True)
        (root / 'sys/module/nvidia_uvm/refcnt').write_text('1\n')
        (bin_dir / 'rmmod').write_text('#!/bin/sh\nsleep 60\n')
        (bin_dir / 'rmmod').chmod(0o755)
        script = re.sub(r'/(?:sys|proc|tmp)/|/dev/nvidia',
                        lambda match: str(root) + match.group(0), GPU_GUEST.read_text())
        started = time.monotonic()
        run = subprocess.run(['sh', '-c', script, 'xdev_ext_gpu_guest.sh', 'unload'],
                             capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, PATH=f'{bin_dir}:/usr/bin:/bin',
                                      XDEV_EXT_GPU_UNLOAD_LIMIT_S='2'))
        self.assertLess(time.monotonic() - started, 20, 'unload waited for a blocked rmmod')
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertRegex(run.stdout, r'^XDEV_EXT_GPU_UNLOAD=FAIL module=nvidia_uvm reason=timeout limit_s=2 ')

    def test_one_failure_keeps_the_summary_failed(self):
        console = self.guest(caps_out=CAPS_GEFORCE, peer_out=self.REGISTER_EINVAL, peer_rc='1\n',
                             dmesg_out=self.PIN_REFUSED, dmabuf_out=self.NO_DMA_BUF, dmabuf_rc='1\n',
                             ce_a_out=CE_PASS_VMM.format(chain='a'), ce_d_out='', ce_d_rc='3\n')
        self.assertIn('\nXDEV_EXT_GPU_GUEST=FAIL failed=1 unsupported=2\n', console)


FAKE_LIBCUDA = r'''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int CUresult;
typedef int CUdevice;
typedef void *CUcontext;
typedef unsigned long long CUdeviceptr;
static int value(const char *name) { const char *text = getenv(name); return text ? atoi(text) : 0; }
CUresult cuInit(unsigned int flags) { (void)flags; return 0; }
CUresult cuDeviceGetCount(int *count) { *count = 1; return 0; }
CUresult cuDeviceGet(CUdevice *device, int ordinal) { *device = ordinal; return 0; }
CUresult cuDeviceGetPCIBusId(char *text, int size, CUdevice device)
{ (void)device; snprintf(text, size, "%s", getenv("FAKE_BDF")); return 0; }
CUresult cuDeviceGetAttribute(int *out, int attribute, CUdevice device)
{
	(void)device;
	if (value("FAKE_ATTR_FAIL"))
		return 1;
	*out = attribute == 116 ? value("FAKE_RDMA") : attribute == 124 ? value("FAKE_DMA_BUF") :
	       attribute == 102 ? value("FAKE_VMM") : attribute == 103 ? value("FAKE_POSIX_FD") : 7;
	return 0;
}
CUresult cuDevicePrimaryCtxRetain(CUcontext *context, CUdevice device) { (void)device; *context = (void *)1; return 0; }
CUresult cuDevicePrimaryCtxRelease_v2(CUdevice device) { (void)device; fputs("FAKE release\n", stderr); return 0; }
CUresult cuCtxSetCurrent(CUcontext context) { (void)context; return 0; }
CUresult cuMemAlloc_v2(CUdeviceptr *pointer, size_t size)
{ (void)size; if (value("FAKE_ALLOC_FAIL")) return 2; *pointer = 0x7f0000000000ULL; return 0; }
CUresult cuMemFree_v2(CUdeviceptr pointer) { (void)pointer; fputs("FAKE free\n", stderr); return value("FAKE_FREE_FAIL"); }
CUresult cuMemsetD8_v2(CUdeviceptr pointer, unsigned char byte, size_t size) { (void)pointer; (void)byte; (void)size; return 0; }
/* FAKE_VRAM names a file with the device contents; the rest stays 0xa5. */
CUresult cuMemcpyDtoH_v2(void *host, CUdeviceptr pointer, size_t size)
{
	const char *path = getenv("FAKE_VRAM");
	FILE *file;
	size_t got = 0;

	(void)pointer;
	if (path) {
		file = fopen(path, "rb");
		if (!file)
			return 3;
		got = fread(host, 1, size, file);
		fclose(file);
	}
	memset((char *)host + got, 0xa5, size - got);
	return 0;
}
CUresult cuCtxSynchronize(void) { return 0; }
/* FAKE_EXPORT=1 exports a descriptor; otherwise CUDA_ERROR_NOT_SUPPORTED. */
CUresult cuMemGetHandleForAddressRange(void *handle, CUdeviceptr pointer, size_t size, int type, unsigned long long flags)
{
	(void)pointer; (void)size; (void)flags;
	if (!value("FAKE_EXPORT") || type != 1)
		return 801;
	*(int *)handle = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return *(int *)handle < 0 ? 1 : 0;
}
CUresult cuPointerGetAttribute(void *data, int attribute, CUdeviceptr pointer)
{
	(void)pointer;
	if (attribute != 15 || value("FAKE_POINTER_FAIL"))
		return 1;
	*(int *)data = value("FAKE_POINTER_RDMA");
	return 0;
}
'''


class GpuCapsProbe(unittest.TestCase):
    """xdev_ext_gpu_dmabuf --caps reports what CUDA itself says about the GPU:
    CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED (116), _DMA_BUF_SUPPORTED
    (124) and, for a fresh cuMemAlloc block, CU_POINTER_ATTRIBUTE_
    IS_GPU_DIRECT_RDMA_CAPABLE (15). The guest cases cite this as evidence."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='gpu-caps-')
        root = Path(cls.tmp.name)
        (root / 'fake.c').write_text(FAKE_LIBCUDA)
        subprocess.run(['cc', '-shared', '-fPIC', '-o', str(root / 'libcuda.so.1'), str(root / 'fake.c')],
                       check=True)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-o',
                        str(root / 'probe'), str(GPU_DMABUF), '-ldl'], check=True)
        cls.root = root

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def probe(self, bdf='0000:01:00.0', **values):
        env = dict(os.environ, LD_LIBRARY_PATH=str(self.root), FAKE_BDF='0000:01:00.0',
                   **{f'FAKE_{key.upper()}': str(value) for key, value in values.items()})
        return subprocess.run([str(self.root / 'probe'), '--caps', '--bdf', bdf],
                              capture_output=True, text=True, env=env, timeout=30)

    def test_reports_cuda_rdma_and_dma_buf_support_and_releases_the_probe_block(self):
        # CU_DEVICE_ATTRIBUTE_VIRTUAL_MEMORY_MANAGEMENT_SUPPORTED (102) and
        # _HANDLE_TYPE_POSIX_FILE_DESCRIPTOR_SUPPORTED (103) back the VMM window.
        for rdma, dma_buf, pointer, vmm in ((0, 0, 0, 1), (1, 1, 1, 0)):
            with self.subTest(rdma=rdma, dma_buf=dma_buf, pointer=pointer, vmm=vmm):
                run = self.probe(rdma=rdma, dma_buf=dma_buf, pointer_rdma=pointer, vmm=vmm,
                                 posix_fd=vmm)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout, f'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma={rdma} '
                                             f'dma_buf={dma_buf} pointer_rdma={pointer} '
                                             f'vmm={vmm} posix_fd={vmm}\n')
                self.assertEqual(run.stderr.split(), ['FAKE', 'free', 'FAKE', 'release'])

    def test_cuda_failures_never_print_a_value_and_still_clean_up(self):
        # A refused device attribute or allocation prints no CAPS line; a refused
        # pointer attribute is -1, never 0; every acquired resource is released.
        for knob, code, stdout, cleanup in (
                ('attr_fail', 1, '', []),
                ('alloc_fail', 1, '', ['FAKE', 'release']),
                ('pointer_fail', 0, 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=0 dma_buf=0 '
                                    'pointer_rdma=-1 vmm=0 posix_fd=0\n', ['FAKE', 'free', 'FAKE', 'release']),
                ('free_fail', 1, 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=0 dma_buf=0 '
                                 'pointer_rdma=0 vmm=0 posix_fd=0\n', ['FAKE', 'free', 'FAKE', 'release'])):
            with self.subTest(knob):
                run = self.probe(**{knob: 1})
                self.assertEqual(run.returncode, code, run.stdout + run.stderr)
                self.assertEqual(run.stdout, stdout)
                self.assertEqual([word for word in run.stderr.split() if word in ('FAKE', 'free', 'release')],
                                 cleanup, run.stderr)

    def test_fails_without_a_cuda_device_at_that_address(self):
        run = self.probe(bdf='0000:02:00.0')
        self.assertNotEqual(run.returncode, 0)
        self.assertNotIn('XDEV_EXT_GPU_CAPS', run.stdout)


# /dev/xdev_ext_peer stand-in: REGISTER of a DMA-BUF returns an allocation fd.
PEER_SHIM = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "@HEADER@"

static int control = -1;

static int real_open(const char *path, int flags, mode_t mode)
{
	int (*next)(const char *, int, ...) = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");

	return next(path, flags, mode);
}

static int peer_open(const char *path, int flags, va_list args)
{
	mode_t mode = (flags & O_CREAT) ? va_arg(args, mode_t) : 0;

	if (!strcmp(path, "/dev/xdev_ext_peer"))
		return control = real_open("/dev/null", O_RDWR | (flags & O_CLOEXEC), 0);
	return real_open(path, flags, mode);
}

int open(const char *path, int flags, ...)
{
	va_list args;
	int fd;

	va_start(args, flags);
	fd = peer_open(path, flags, args);
	va_end(args);
	return fd;
}

int open64(const char *path, int flags, ...)
{
	va_list args;
	int fd;

	va_start(args, flags);
	fd = peer_open(path, flags, args);
	va_end(args);
	return fd;
}

int ioctl(int fd, unsigned long request, ...)
{
	int (*next)(int, unsigned long, ...) = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
	struct xdev_ext_peer_register *reg;
	va_list args;

	va_start(args, request);
	reg = va_arg(args, struct xdev_ext_peer_register *);
	va_end(args);
	if (fd != control || control < 0)
		return next(fd, request, reg);
	if (request != XDEV_EXT_PEER_REGISTER || reg->flags != XDEV_EXT_PEER_REGISTER_F_DMABUF ||
	    reg->gpu_fd < 0 || reg->gpu_va || !reg->len)
		return -1;
	reg->generation = 3;
	return real_open("/dev/null", O_RDWR | O_CLOEXEC, 0);
}
"""


class GpuDmabufVramGroup(unittest.TestCase):
    """The G4 VRAM oracle names the group the session's last batch read.

    The NVMe program places batch @request_id at slot request_id % slots of
    the source window (xdev_ext_mp_nvme_s0_slba), and the session numbers its
    batches from 1 (b->id = ++next_batch_id).  The peer chain runs one frame
    at depth 1, so after N batches frame 0 holds group N % slots: with one
    batch per slot that is group 0, not the window's last group."""

    GROUP = 8192
    FRAME = 65536
    BYTES = 2 * 1024 * 1024

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='gpu-dmabuf-')
        root = Path(cls.tmp.name)
        header = (HERE / '../../../../include/uapi/linux/xdev_ext_peer.h').resolve()
        (root / 'fake.c').write_text(FAKE_LIBCUDA)
        (root / 'shim.c').write_text(PEER_SHIM.replace('@HEADER@', str(header)))
        subprocess.run(['cc', '-shared', '-fPIC', '-o', str(root / 'libcuda.so.1'), str(root / 'fake.c')],
                       check=True)
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', '-o',
                        str(root / 'peer_shim.so'), str(root / 'shim.c'), '-ldl'], check=True)
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-o',
                        str(root / 'dmabuf'), str(GPU_DMABUF), '-ldl'], check=True)
        cls.root = root

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def group_bytes(index):
        return bytes([0x10 + index]) * GpuDmabufVramGroup.GROUP

    def run_tool(self, slots, batches, frame0_group):
        root = self.root
        source = root / f'src-{slots}.bin'
        source.write_bytes(b''.join(self.group_bytes(i) for i in range(slots)))
        vram = root / 'vram.bin'
        vram.write_bytes(self.group_bytes(frame0_group))
        env = dict(os.environ, LD_LIBRARY_PATH=str(root), LD_PRELOAD=str(root / 'peer_shim.so'),
                   FAKE_BDF='0000:01:00.0', FAKE_DMA_BUF='1', FAKE_EXPORT='1', FAKE_VRAM=str(vram))
        return subprocess.run([str(root / 'dmabuf'), '--bdf', '0000:01:00.0', '--bytes', str(self.BYTES),
                               '--expect', str(source), '--group-bytes', str(self.GROUP),
                               '--frame-bytes', str(self.FRAME), '--batches', str(batches),
                               '--', '/bin/true', '{fd}'],
                              capture_output=True, text=True, env=env, timeout=30)

    def test_frame_zero_must_hold_the_group_of_the_last_request_id(self):
        # (slots, batches): one batch per slot as the peer chain runs it, and
        # sequences that wrap the window or stop short of it.
        for slots, batches in ((4, 4), (4, 6), (3, 7), (4, 3), (1, 5)):
            expected = batches % slots
            for held in range(slots):
                with self.subTest(slots=slots, batches=batches, held=held):
                    run = self.run_tool(slots, batches, held)
                    self.assertIn('XDEV_EXT_GPU_DMABUF program_exit=0\n', run.stdout, run.stderr)
                    verdict = 'yes' if held == expected else 'no'
                    self.assertIn(f'XDEV_EXT_GPU_DMABUF vram_holds_last_batch_group={verdict} '
                                  f'group={expected}\n', run.stdout, run.stderr)
                    self.assertEqual(run.returncode, 0 if held == expected else 1, run.stdout + run.stderr)

    def test_batches_is_required_and_positive(self):
        root = self.root
        source = root / 'src-usage.bin'
        source.write_bytes(self.group_bytes(0) * 4)
        base = [str(root / 'dmabuf'), '--bdf', '0000:01:00.0', '--bytes', str(self.BYTES),
                '--expect', str(source), '--group-bytes', str(self.GROUP), '--frame-bytes', str(self.FRAME)]
        for extra in ([], ['--batches', '0']):
            with self.subTest(extra=extra):
                run = subprocess.run(base + extra + ['--', '/bin/true'], capture_output=True, text=True,
                                     timeout=30)
                self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
                self.assertNotIn('XDEV_EXT_GPU_DMABUF', run.stdout)


class GuestLinkReadiness(unittest.TestCase):
    """igb resets its link whenever an XDP program is attached or removed (a
    receiver's redirect, the transmit-only pass program, their detach at exit),
    so a sender must not start before both wire ports carry traffic again."""

    def setUp(self):
        self.script = HARNESS.read_text()

    def wait(self, carriers, rounds=3):
        tmp = tempfile.TemporaryDirectory(prefix='link-wait-')
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name, value in carriers.items():
            (root / name).mkdir()
            if value is not None:
                (root / name / 'carrier').write_text(value + '\n')
        program = ('set -eu\ntimeout_factor=1\nsleep() { :; }\n' +
                   function(self.script, 'nic_link_wait').replace('/sys/class/net', str(root)) +
                   f'nic_link_wait {rounds}\n')
        return subprocess.run(['sh', '-c', program], capture_output=True, text=True)

    def test_wait_returns_once_both_ports_have_carrier(self):
        self.assertEqual(self.wait({'eth0': '1', 'eth1': '1'}).returncode, 0)

    def test_wait_fails_bounded_when_a_port_stays_down(self):
        for carriers in ({'eth0': '1', 'eth1': '0'}, {'eth0': '0', 'eth1': '1'},
                         {'eth0': None, 'eth1': '1'}):
            run = self.wait(carriers)
            self.assertNotEqual(run.returncode, 0, carriers)
            self.assertIn('FAIL wire link down', run.stderr)

    def test_every_wire_sender_waits_for_both_links(self):
        guest = self.script[self.script.index("cat >\"$ROOT/init\" <<'GUEST'"):]
        guest = guest[:guest.index('\nGUEST\n')]
        senders = [m.start() for m in re.finditer(
            r'(?m)^\s*\$ctl (?:"\$@"|nvme-nic) .*--ifname (?:eth0|"\$nicfb_tx_if")', guest)]
        self.assertGreaterEqual(len(senders), 4, 'main, socket, copy and mixed senders')
        for at in senders:
            before = guest[:at]
            ready = max(before.rfind('test "$ready" = 1'), before.rfind('nicfb_ready /tmp/'))
            self.assertGreaterEqual(ready, 0)
            self.assertIn('nic_link_wait', before[ready:], guest[at:at + 80])



class TbNhiGuestEnumeration(unittest.TestCase):
    """The enumerate mode of the guest NHI script against a fake sysfs."""

    def setUp(self):
        self.script = TB_GUEST.read_text()
        self.tmp = tempfile.TemporaryDirectory(prefix='tb-enum-')
        self.sys = Path(self.tmp.name) / 'sys'

    def tearDown(self):
        self.tmp.cleanup()

    def node(self, relative, **attributes):
        path = self.sys / relative
        path.mkdir(parents=True, exist_ok=True)
        for name, value in attributes.items():
            (path / name).write_text(value + '\n')
        return path

    def host_router(self, uuid, port_links):
        devices = 'bus/thunderbolt/devices'
        self.node(devices + '/domain0', uevent='DEVTYPE=thunderbolt_domain', security='none',
                  iommu_dma_protection='0')
        self.node(devices + '/0-0', uevent='DEVTYPE=thunderbolt_device', vendor='0x8087',
                  vendor_name='Intel', device='0x7ec2', device_name='Meteor Lake',
                  unique_id=uuid, generation='4', authorized='1')
        for number, link in port_links.items():
            self.node(f'{devices}/0-0/usb4_port{number}', link=link)
        regs = self.node('kernel/debug/thunderbolt/0-0/port1')
        (regs / 'regs').write_text('# offset relative_offset cap_id vs_cap_id value\n'
                                   '0x0000    0 0x00 0x00 0x11111111\n')

    def snapshot(self):
        return {str(path): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in sorted(self.sys.rglob('*')) if path.is_file()}

    def enumerate(self):
        program = ('set -u\n'
                   f'sysfs={self.sys}\nsettle_max=3\nsettle_stable=2\n'
                   'sleep() { :; }\nmount() { echo "UNEXPECTED mount $*"; }\n' +
                   function(self.script, 'topology') + function(self.script, 'enumerate') +
                   'enumerate\n')
        before = self.snapshot()
        run = subprocess.run(['sh', '-c', program], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(before, self.snapshot(), 'enumeration must not write below sysfs')
        self.assertNotIn('UNEXPECTED', run.stdout)
        return run.stdout.splitlines()

    def test_nothing_connected_reports_the_host_router_and_idle_ports(self):
        uuid = 'd6da8780-0069-3029-ffff-ffffffffffff'
        self.host_router(uuid, {1: 'none', 3: 'none'})
        lines = self.enumerate()
        self.assertIn('XDEV_EXT_TB_NHI_ENUM device=domain0 type=thunderbolt_domain '
                      'security=none iommu_dma_protection=0', lines)
        self.assertIn('XDEV_EXT_TB_NHI_ENUM device=0-0 type=thunderbolt_device vendor=0x8087 '
                      'vendor_name=Intel device=0x7ec2 device_name=Meteor_Lake '
                      f'unique_id={uuid} generation=4', lines)
        self.assertIn('XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port1 link=none', lines)
        self.assertIn('XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port3 link=none', lines)
        self.assertIn('XDEV_EXT_TB_NHI_ENUM regs 0-0 port1 0x0000    0 0x00 0x00 0x11111111', lines)
        self.assertEqual(lines[-1], 'XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=0 '
                                    'same_uuid_xdomains=0')
        self.assertTrue(any(line.startswith('XDEV_EXT_TB_NHI_ENUM settle ') for line in lines))

    def test_a_cable_between_the_host_ports_is_an_xdomain_with_the_host_uuid(self):
        uuid = '7a1d0000-0000-0000-ffff-ffffffffffff'
        self.host_router(uuid, {1: 'usb4', 3: 'usb4'})
        self.node('bus/thunderbolt/devices/0-1', uevent='DEVTYPE=thunderbolt_xdomain',
                  unique_id=uuid, rx_speed='20.0 Gb/s', rx_lanes='1', tx_speed='20.0 Gb/s',
                  tx_lanes='1', maxhopid='15')
        lines = self.enumerate()
        self.assertIn('XDEV_EXT_TB_NHI_ENUM device=0-1 type=thunderbolt_xdomain '
                      f'unique_id={uuid} rx_speed=20.0_Gb/s rx_lanes=1 tx_speed=20.0_Gb/s '
                      'tx_lanes=1 maxhopid=15 same_uuid_as_host=yes', lines)
        self.assertEqual(lines[-1], 'XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=1 '
                                    'same_uuid_xdomains=1')

    def test_a_different_host_is_not_counted_as_the_same_uuid(self):
        self.host_router('11111111-0000-0000-ffff-ffffffffffff', {1: 'usb4'})
        self.node('bus/thunderbolt/devices/0-1', uevent='DEVTYPE=thunderbolt_xdomain',
                  unique_id='22222222-0000-0000-ffff-ffffffffffff')
        lines = self.enumerate()
        self.assertTrue(any(line.startswith('XDEV_EXT_TB_NHI_ENUM device=0-1 ') and
                            line.endswith(' same_uuid_as_host=no') for line in lines), lines)
        self.assertEqual(lines[-1], 'XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=1 '
                                    'same_uuid_xdomains=0')

    def service(self, name, local_inc, remote_inc, verified=1, required=1, phase=4, error=0,
                ping=1, pong=1, up=1):
        self.node('bus/thunderbolt/devices/' + name,
                  xdev_ext_link_state=f'version=1 token=1 local_inc={local_inc} remote_inc={remote_inc} '
                                      f'up={up} closing=0 nhi_gone=0 channels=1',
                  xdev_ext_data_state=f'version=1 control_ready={up} data_verified_mask={verified} '
                                      f'required_mask={required} phase={phase} error={error} '
                                      f'backing_qualified=not_queried local_inc={local_inc} '
                                      f'remote_inc={remote_inc} startup_successes={1 if verified else 0} '
                                      'startup_failures=0 stale=0\n'
                                      'channel=0 rx0_actual_len=128 rx0_flags=0 rx0_canceled=0 '
                                      'rx1_actual_len=4096 rx1_flags=0 rx1_canceled=0 '
                                      f'rx_ping_ok={ping} rx_pong_ok={pong} tx_ping_submitted_len=128 '
                                      'tx_pong_submitted_len=4096 tx_ping_complete=1 tx_pong_complete=1')

    def echo(self, same, insmod='insmod() { echo "LOADED $*"; }'):
        program = ('set -u\n'
                   f'sysfs={self.sys}\nsame={same}\necho_max=2\n'
                   'sleep() { :; }\n' + insmod + '\nrmmod() { echo "UNLOADED $*"; }\n' +
                   function(self.script, 'echo_state') + function(self.script, 'selfloop_echo') +
                   'selfloop_echo\n')
        run = subprocess.run(['sh', '-c', program], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.splitlines()

    def test_echo_does_not_run_without_a_self_loop(self):
        lines = self.echo(0)
        self.assertEqual(lines, ['XDEV_EXT_TB_SELFLOOP_ECHO=NOT_RUN reason=no-self-loop same_uuid_xdomains=0'])

    def test_echo_loads_the_module_in_test_mode_and_passes_when_both_ends_verified(self):
        self.service('0-1.1', 11, 22)
        self.service('0-3.1', 22, 11)
        lines = self.echo(2)
        self.assertEqual(lines[0], 'LOADED /opt/xdev_ext/tb/xdev_ext_xdomain.ko self_loop_test=1')
        self.assertTrue(any(l.startswith('XDEV_EXT_TB_SELFLOOP_ECHO end=0-1.1 version=1 control_ready=1 ')
                            for l in lines), lines)
        self.assertTrue(any(l.startswith('XDEV_EXT_TB_SELFLOOP_ECHO end=0-3.1 channel=0 ') for l in lines), lines)
        self.assertIn('UNLOADED xdev_ext_xdomain', lines)
        self.assertEqual(lines[-1], 'XDEV_EXT_TB_SELFLOOP_ECHO=PASS ends=2 channels=1 '
                                    'bytes_each_way=4224 compare=in-kernel-pattern-crc-nonce')

    def test_echo_fails_when_an_end_did_not_verify_its_bytes(self):
        self.service('0-1.1', 11, 22)
        self.service('0-3.1', 22, 11, verified=0, phase=5, error=-74, pong=0)
        self.assertEqual(self.echo(2)[-1], 'XDEV_EXT_TB_SELFLOOP_ECHO=FAIL reason=end-not-verified end=0-3.1')

    def test_echo_fails_when_the_two_ends_are_not_each_other(self):
        self.service('0-1.1', 11, 22)
        self.service('0-3.1', 33, 11)
        self.assertEqual(self.echo(2)[-1], 'XDEV_EXT_TB_SELFLOOP_ECHO=FAIL reason=ends-not-paired')

    def test_echo_fails_with_only_one_end(self):
        self.service('0-1.1', 11, 22)
        self.assertEqual(self.echo(2)[-1], 'XDEV_EXT_TB_SELFLOOP_ECHO=FAIL reason=ends ends=1')

    def test_echo_fails_when_the_module_does_not_load(self):
        lines = self.echo(2, insmod='insmod() { return 1; }')
        self.assertEqual(lines, ['XDEV_EXT_TB_SELFLOOP_ECHO=FAIL reason=insmod'])

    def test_echo_runs_after_enumeration_and_before_rebind_cycles(self):
        self.assertIn('echo_mode=${3:-0}', self.script)
        self.assertIn('if [ "$echo_mode" = 1 ] && [ "$result" = PASS ]; then', self.script)
        self.assertLess(self.script.index('\tenumerate\nfi'),
                        self.script.index('then\n\tselfloop_echo\nfi'))
        self.assertLess(self.script.index('then\n\tselfloop_echo\nfi'),
                        self.script.index('while [ "$result" = PASS ] && [ "$cycle" -le "$cycles" ]'))

    def test_rebind_cycles_stay_the_default_path(self):
        self.assertIn('enumerate_mode=${2:-0}', self.script)
        self.assertIn('echo_mode=${3:-0}', self.script)
        self.assertIn('poll_seconds=${4:-0}', self.script)
        self.assertIn('if [ "$enumerate_mode" = 1 ] && [ "$result" = PASS ]; then', self.script)
        self.assertLess(self.script.index('then\n\t[ "$poll_seconds" -gt 0 ] && poll\n\tenumerate\nfi'),
                        self.script.index('while [ "$result" = PASS ] && [ "$cycle" -le "$cycles" ]'))

    def nhi_config(self, vs_cap_9, vs_cap_22):
        nhi = self.node('bus/pci/devices/0000:00:0d.2')
        config = bytearray(256)
        config[0xc8:0xcc] = vs_cap_9.to_bytes(4, 'little')
        config[0xfc:0x100] = vs_cap_22.to_bytes(4, 'little')
        (nhi / 'config').write_bytes(bytes(config))
        self.node('bus/pci/devices/0000:00:0d.2/power', runtime_status='active')
        proc = self.sys.parent / 'proc'
        proc.mkdir(exist_ok=True)
        (proc / 'uptime').write_text('2.71 9.80\n')

    def poll(self, seconds, sleep='sleep() { :; }\n'):
        program = ('set -u\n'
                   f'sysfs={self.sys}\nnhi=0000:00:0d.2\npoll_seconds={seconds}\n' + sleep +
                   'mount() { echo "UNEXPECTED mount $*"; }\n' +
                   function(self.script, 'topology') + function(self.script, 'config_dword') +
                   function(self.script, 'poll') + 'poll\n')
        run = subprocess.run(['sh', '-c', program], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn('UNEXPECTED', run.stdout)
        return run.stdout.splitlines()

    def lane_regs(self, port, lane_cs_1):
        regs = self.node(f'kernel/debug/thunderbolt/0-0/{port}')
        (regs / 'regs').write_text('# offset relative_offset cap_id vs_cap_id value\n'
                                   '0x0000    0 0x00 0x00 0x00000001\n'
                                   '0x0036    0 0x01 0x00 0x1c3c013e\n'
                                   f'0x0037    1 0x01 0x00 0x{lane_cs_1:08x}\n'
                                   '0x00ae   18 0x06 0x00 0x00000410\n'
                                   '0x00af   19 0x06 0x00 0x00040006\n')
        return regs / 'regs'

    def test_poll_reports_nhi_dwords_and_capability_rows_without_writing(self):
        self.host_router('d6da8780-0069-3029-ffff-ffffffffffff', {1: 'none', 3: 'none'})
        self.nhi_config(0x80000000, 0x22000002)
        self.lane_regs('port1', 0x5c18001c)
        before = self.snapshot()
        lines = self.poll(3)
        self.assertEqual(before, self.snapshot(), 'poll must not write below sysfs')
        first = [line for line in lines if line.startswith('XDEV_EXT_TB_NHI_POLL t=1 ')]
        self.assertTrue(first[0].startswith('XDEV_EXT_TB_NHI_POLL t=1 uptime=2.71 nhi_runtime=active '
                                            'vs_cap_9=0x80000000 vs_cap_22=0x22000002 topology='), first)
        self.assertIn('0-0:usb4_port1=none:usb4_port3=none', first[0])
        self.assertIn('XDEV_EXT_TB_NHI_POLL t=1 regs 0-0 port1 0x0037    1 0x01 0x00 0x5c18001c', lines)
        self.assertIn('XDEV_EXT_TB_NHI_POLL t=3 regs 0-0 port1 0x00ae   18 0x06 0x00 0x00000410', lines)
        self.assertIn('XDEV_EXT_TB_NHI_POLL t=3 regs 0-0 port1 0x00af   19 0x06 0x00 0x00040006', lines)
        # Only lane adapter and USB4 port capability rows are repeated.
        self.assertFalse(any(' 0x0000    0 0x00 ' in line for line in lines))
        self.assertEqual(lines[-1], 'XDEV_EXT_TB_NHI_POLL summary samples=3 changed_samples=0')

    def test_poll_counts_a_sample_whose_adapter_dump_changed(self):
        self.host_router('d6da8780-0069-3029-ffff-ffffffffffff', {1: 'none'})
        self.nhi_config(0, 0)
        regs = self.lane_regs('port1', 0x5c18001c)
        # The "cable" arrives during the first one-second wait.
        sleep = ('sleep() { [ -e "$sysfs/plugged" ] && return; : >"$sysfs/plugged"; '
                 f"sed -i 's/0x5c18001c/0x40420040/' {regs}; }}\n")
        lines = self.poll(3, sleep)
        self.assertIn('XDEV_EXT_TB_NHI_POLL t=2 adapter_dump_changed=1', lines)
        self.assertIn('XDEV_EXT_TB_NHI_POLL t=2 regs 0-0 port1 0x0037    1 0x01 0x00 0x40420040', lines)
        self.assertNotIn('XDEV_EXT_TB_NHI_POLL t=3 adapter_dump_changed=1', lines)
        self.assertEqual(lines[-1], 'XDEV_EXT_TB_NHI_POLL summary samples=3 changed_samples=1')


if __name__ == '__main__':
    unittest.main()
