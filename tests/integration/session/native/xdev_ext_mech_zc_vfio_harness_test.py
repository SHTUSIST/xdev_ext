#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Harness wiring of VFIO passthrough, the real-GPU mode and the NIC model."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'
GPU_GUEST = HERE / 'xdev_ext_gpu_guest.sh'
GPU_DMABUF = HERE / 'xdev_ext_gpu_dmabuf.c'


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
[ "$1" = ce-chain ] || exit 0
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
while [ "$1" != -- ]; do shift; done
shift
program=$1
shift 3
FAKE_DMABUF=1 "$program" --allocation-fd 3 "$@"
rc=$?
echo 'XDEV_EXT_GPU_DMABUF vram_holds_last_group=yes'
exit "$rc"
'''
CE_PASS = ('XDEV_EXT_MECH_CE_GPU=PASS chain={chain}\n'
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

    def guest(self, **outputs):
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
        defaults.update({name.replace('_', '-').replace('-out', '.out').replace('-rc', '.rc'): value
                         for name, value in outputs.items()})
        for name, value in defaults.items():
            (fake / name).write_text(value)
        for path, text in ((root / 'ctl', FAKE_CTL), (gpu / 'xdev_ext_peer_chain', FAKE_PEER),
                           (gpu / 'xdev_ext_gpu_dmabuf', FAKE_DMABUF),
                           (bin_dir / 'insmod', '#!/bin/sh\necho "$*" >>"$FAKE/insmod.calls"\n'),
                           (bin_dir / 'dmesg', '#!/bin/sh\ncat "$FAKE/dmesg.out" 2>/dev/null\n'),
                           (bin_dir / 'nvidia-smi', '#!/bin/sh\necho "NVIDIA GeForce RTX 5090, '
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
                             env=dict(os.environ, FAKE=str(fake), PATH=f'{bin_dir}:/usr/bin:/bin'))
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
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

    def test_one_failure_keeps_the_summary_failed(self):
        console = self.guest(caps_out=CAPS_GEFORCE, peer_out=self.REGISTER_EINVAL, peer_rc='1\n',
                             dmesg_out=self.PIN_REFUSED, dmabuf_out=self.NO_DMA_BUF, dmabuf_rc='1\n',
                             ce_a_out=CE_PASS_VMM.format(chain='a'), ce_d_out='', ce_d_rc='3\n')
        self.assertIn('\nXDEV_EXT_GPU_GUEST=FAIL failed=1 unsupported=2\n', console)


FAKE_LIBCUDA = r'''
#include <stdio.h>
#include <stdlib.h>
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
CUresult cuMemcpyDtoH_v2(void *host, CUdeviceptr pointer, size_t size) { (void)host; (void)pointer; (void)size; return 0; }
CUresult cuCtxSynchronize(void) { return 0; }
CUresult cuMemGetHandleForAddressRange(void *handle, CUdeviceptr pointer, size_t size, int type, unsigned long long flags)
{ (void)handle; (void)pointer; (void)size; (void)type; (void)flags; return 801; }
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


if __name__ == '__main__':
    unittest.main()
