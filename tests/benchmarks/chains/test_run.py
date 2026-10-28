#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of run.py and hardware_gate.py; no device, VM or root needed.

Run: python3 tests/eval/chains/test_run.py -v
The C side (chain_spec.h, chain_oracle.h) is reached through the
test_chain_spec binary this test builds with `make test`.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hardware_gate  # noqa: E402
import run  # noqa: E402

PEER_TX = dict(ifname='eth0', queue=0, mac='02:00:00:00:00:01', ip='192.0.2.1', port=54321,
               mtu=1500)
PEER_RX = dict(ifname='eth1', queue=0, mac='02:00:00:00:00:02', ip='192.0.2.2', port=12345,
               mtu=1500)
RIG = dict(
    nvme_src=dict(ng='/dev/ng0n1', block='/dev/nvme0n1', slba=0, nlb=1 << 20, lba_bytes=512),
    nvme_dst=dict(ng='/dev/ng1n1', block='/dev/nvme1n1', slba=2048, nlb=1 << 20, lba_bytes=512),
    tx=PEER_TX, rx=PEER_RX,
    ce=dict(dev='/dev/xdev_ext_ce_sim', len=4 << 20, tx_va=0, rx_va=4 << 20),
    attached=['nxp_nvme_ops', 'nxp_afxdp_ops', 'ce_plan_ops'],
    plans=dict(iaa='/opt/chains/chain_plan.bpf.o'),
    nxp_session=270019, iaa_software=True)


class Built:
    tmp = None
    tool = None

    @classmethod
    def get(cls):
        if cls.tool is None:
            cls.tmp = tempfile.TemporaryDirectory(prefix='.chains-test-', dir=HERE)
            subprocess.run(['make', '-s', '-C', str(HERE), 'BUILD=' + cls.tmp.name, 'test'],
                           check=True)
            cls.tool = Path(cls.tmp.name) / 'test_chain_spec'
        return cls.tool


def args(*extra):
    return run.parse(['--rig', 'unused', *extra])


class Pattern(unittest.TestCase):
    def c_bytes(self, seed, g, off, n, text=False):
        out = subprocess.run([str(Built.get()), '--pattern', str(seed), str(g), str(off), str(n),
                              *(['text'] if text else [])], capture_output=True, text=True,
                             check=True)
        return bytes.fromhex(out.stdout.strip())

    def test_python_transcription_matches_c(self):
        for seed, g, off, n in ((1, 0, 0, 64), (0xdeadbeefcafe, 77, 8, 300),
                                (2**63 + 5, 2**40 + 3, 4000, 200), (9, 1, 61, 9)):
            for text in (False, True):
                want = run.group_bytes(seed, g, off + n, text)[off:]
                self.assertEqual(self.c_bytes(seed, g, off, n, text), want, (seed, g, off, text))

    def test_groups_are_unique_and_led_by_index(self):
        a, b = run.group_bytes(5, 3, 4096), run.group_bytes(5, 4, 4096)
        self.assertEqual(a[:8], (3).to_bytes(8, 'little'))
        self.assertNotEqual(a[8:], b[8:])
        self.assertNotEqual(run.group_bytes(6, 3, 4096), a)

    def test_compressed_record_inflates_to_the_text_group(self):
        rec = run.compressed_record(11, 7, 65536, 65536)
        self.assertEqual(len(rec), 65536)
        d = zlib.decompressobj(-15)
        self.assertEqual(d.decompress(rec), run.group_bytes(11, 7, 65536, text=True))
        self.assertTrue(d.eof)
        self.assertEqual(set(d.unused_data), {0})       # zero padding after the stream
        with self.assertRaises(run.Usage):
            run.compressed_record(11, 7, 65536, 64)


class Arguments(unittest.TestCase):
    def test_powers_and_sweep(self):
        self.assertEqual(run.powers('4K..32K'), [4096, 8192, 16384, 32768])
        self.assertEqual(run.powers('4096,1M'), [4096, 1 << 20])
        for bad in ('3K..8K', '8K..4K', '4K,4K', 'x', ''):
            with self.assertRaises(run.Usage):
                run.powers(bad)
        axes = run.sweep('frame=4K..2M,pool=64M..64G,qd=1..256,sessions=1..64')
        self.assertEqual(len(axes['frame']), 10)
        self.assertEqual(len(axes['pool']), 11)
        self.assertEqual(axes['qd'][-1], 256)
        self.assertEqual(len(axes['sessions']), 7)
        for bad in ('qd=1..4,qd=8', 'size=4K', 'qd'):
            with self.assertRaises(run.Usage):
                run.sweep(bad)

    def test_cli_rejections(self):
        for bad in (['--chain', 'nope'], ['--chain', 'nvme-nic', '--arms', 'gpu'],
                    ['--chain', 'nvme-nic', '--sizes', '1000'],
                    ['--chain', 'nvme-nic', '--correctness-only', '--pairs', '3'],
                    ['--chain', 'nvme-nic', '--role', 'sender'],
                    ['--chain', 'nvme-nic', '--ablate', 'cas']):
            with self.assertRaises(run.Usage, msg=bad):
                args(*bad)

    def test_record_shape(self):
        self.assertEqual(run.record_shape('nvme-gpu-nic', 4 << 20, RIG), (32768, 128, 4096))
        jumbo = dict(RIG, tx=dict(PEER_TX, mtu=9000), rx=dict(PEER_RX, mtu=9000))
        self.assertEqual(run.record_shape('nvme-nic', 4 << 20, jumbo), (65536, 64, 4096))
        self.assertEqual(run.record_shape('nvme-nic', 4096, RIG), (4096, 1, 4096))
        # deflate admits CRYPTO_ACOMP_DST_MAX = 128 KiB per batch: bursts above that.
        self.assertEqual(run.record_shape('nvme-iaa-gpu', 4 << 20, RIG), (131072, 32, 131072))
        self.assertEqual(run.record_shape('nvme-iaa-gpu', 256 << 10, RIG), (131072, 2, 131072))
        self.assertEqual(run.record_shape('nvme-iaa-gpu', 64 << 10, RIG), (65536, 1, 65536))
        self.assertEqual(run.seg_len(1500), 1432)


class Planning(unittest.TestCase):
    def plan(self, *extra):
        return run.cases(args(*extra), RIG)

    def test_variants_one_change_each(self):
        labels = [v['label'] for v in run.variants(args(
            '--chain', 'nvme-nic', '--ablate', 'afxdp-mode,start-per,plan', '--sweep', 'qd=8..32'))]
        self.assertEqual(labels, ['base', 'ablate-afxdp-mode=copy', 'ablate-start-per=run',
                                  'ablate-plan=default', 'sweep-qd=16', 'sweep-qd=32'])

    def test_refusals(self):
        def why(chain, arm='session', **var):
            v = dict(run.variants(args('--chain', 'nvme-nic'))[0], **var)
            return run.refusal(chain, arm, v, RIG, False) or ''
        self.assertTrue(why('nvme-crc-nic').startswith(
            'unsupported: in-frame transform not implemented'))
        self.assertTrue(why('nvme-crc-nic', 'staged').startswith('unsupported: in-frame'))
        self.assertIn('AF_XDP RX and an IAA transform', why('nic-iaa-gpu'))
        self.assertIn('default_build', why('nvme-nic', plan='default'))
        self.assertIn('XDEV_EXT_MECH_MAX_DEPTH', why('nvme-iaa-gpu', depth=128))
        self.assertIn('fixed at 4 KiB', why('nvme-gpu-nic', frame=8192))
        self.assertIn('4096 x 4 KiB', why('nic-nvme', pool=64 << 20))
        self.assertIn('XDP redirect', why('nvme-nic', sessions=2))
        self.assertIn('no IAA stage', why('nvme-iaa-gpu', 'userspace-shared'))
        self.assertIn('no device decompressor', why('nvme-iaa-gpu', 'staged'))
        self.assertIn('no START', why('nic-nvme', start_per='run'))
        self.assertIn('only for the session arm', why('nvme-nic', 'staged', start_per='run'))
        # Concurrent sessions share each class's one struct_ops plan.
        self.assertIn('4 concurrent sessions share one struct_ops plan per class; attach '
                      'chain_iaa_ops once', why('nvme-iaa-gpu', sessions=4))
        every = dict(RIG, attached=RIG['attached'] + ['chain_iaa_ops'])
        v = run.variants(args('--chain', 'nvme-nic'))[0]
        self.assertIsNone(run.refusal('nvme-iaa-gpu', 'session', dict(v, sessions=4), every, False))
        self.assertIn('below depth x group_bytes = 8388608',
                      run.refusal('nvme-iaa-gpu', 'session', dict(v, depth=64), RIG, False, 2 << 20))
        self.assertIn('over 2 sessions', run.refusal('nvme-iaa-gpu', 'session',
                                                     dict(v, sessions=2, depth=32), RIG, False,
                                                     1 << 19))
        # The sustained load already is one START; start-per run is closed-only.
        self.assertIn('closed-load option', run.refusal('nvme-nic', 'session',
                                                        dict(v, start_per='run'), RIG, False,
                                                        4096, 'sustained'))
        self.assertIsNone(run.refusal('nvme-nic', 'session', dict(v, start_per='run'), RIG,
                                      False, 4096, 'closed'))
        # Both ends' CE windows on one host must not overlap.
        overlap = dict(RIG, ce=dict(RIG['ce'], rx_va=2 << 20))
        self.assertIn("GPU windows overlap: [tx_va, tx_va + len) = [0, 4194304) and "
                      "[rx_va, rx_va + len) = [2097152, 6291456)",
                      run.refusal('nvme-gpu-nic', 'session', v, overlap, True))
        self.assertIsNone(run.refusal('nvme-gpu-nic', 'session', v, overlap, True, role='sender'))
        cuda = dict(overlap, ce=dict(overlap['ce'], dev='/dev/nvidia0', bdf='0000:65:00.0'))
        self.assertIsNone(run.refusal('nvme-gpu-nic', 'staged', v, cuda, True))
        lone = dict(RIG, attached=[])
        v = run.variants(args('--chain', 'nvme-nic'))[0]
        self.assertIn('attach nxp_nvme_ops, nxp_afxdp_ops', run.refusal(
            'nvme-nic', 'session', v, lone, False))
        self.assertIn('lacks the ce, iaa, nxp object', run.refusal(
            'nvme-iaa-gpu', 'session', v, dict(RIG, attached=[], plans={}), False) or '')

    def test_abba_order(self):
        order = [(c['rep'], c['arm']) for c in self.plan(
            '--chain', 'nvme-nic', '--arms', 'staged,session', '--pairs', '3')]
        self.assertEqual(order, [(0, 'staged'), (0, 'session'), (1, 'session'), (1, 'staged'),
                                 (2, 'staged'), (2, 'session')])

    def test_uo_arm_multiplies_waits(self):
        waits = [c['wait'] for c in self.plan('--chain', 'nvme-nic', '--arms',
                                               'userspace-shared,session', '--wait', 'poll,eventfd')]
        self.assertEqual(waits, ['poll', 'eventfd', None])


class Specs(unittest.TestCase):
    def validate(self, spec):
        with tempfile.NamedTemporaryFile('w', suffix='.json', dir=Built.get().parent,
                                         delete=False) as f:
            json.dump(spec, f)
        out = subprocess.run([str(Built.get()), '--validate', f.name], capture_output=True,
                             text=True)
        os.unlink(f.name)
        return out.returncode, out.stdout.strip()

    def specs(self, chain, arm, *extra, load='closed', size=None, rig=RIG):
        a = args('--chain', chain, '--arms', arm, '--correctness-only', *extra)
        case = [c for c in run.cases(a, rig) if c['arm'] == arm and c['load'] == load and
                (size is None or c['size'] == size)][0]
        shape = run.record_shape(chain, case['size'], rig)
        names = [chain] + ([run.COMPLEMENT[chain]] if chain in run.COMPLEMENT else [])
        return {n: run.chain_spec(case, n, rig, a, shape, 99, Path('/tmp/x')) for n in names}

    def test_generated_specs_pass_the_c_validator(self):
        for chain in ('nvme-gpu-nic', 'nic-gpu-nvme', 'nvme-nic', 'nic-nvme', 'nvme-iaa-gpu'):
            for arm in ('session', 'staged'):
                for load in ('closed', 'sustained'):
                    for size in (4096, 65536):
                        for name, spec in self.specs(chain, arm, '--sizes', '4096,65536',
                                                     load=load, size=size).items():
                            code, text = self.validate(spec)
                            self.assertEqual(code, 0, (chain, arm, load, name, text))
                            self.assertEqual(spec['load'], load)

    def test_large_iaa_records_are_bursts_the_kernel_admits(self):
        for size in (256 << 10, 4 << 20):
            spec = self.specs('nvme-iaa-gpu', 'session', '--sizes', str(size), '--depth', '4',
                              load='sustained')['nvme-iaa-gpu']
            self.assertEqual(spec['group_bytes'], 131072)
            self.assertEqual(spec['stages'][1]['capacity'], 131072)
            self.assertEqual(spec['burst'], size // 131072)
            self.assertFalse(spec['oracle']['every_window'])
            code, text = self.validate(spec)
            self.assertEqual(code, 0, text)
        spec['group_bytes'] = spec['stages'][1]['capacity'] = spec['stages'][1]['expect'] = 262144
        code, text = self.validate(spec)
        self.assertEqual(code, 4)
        self.assertIn('CRYPTO_ACOMP_DST_MAX = 131072', text)

    def test_pinned_iaa_counters_follow_the_rig(self):
        rig = dict(RIG, attached=RIG['attached'] + ['chain_iaa_ops'],
                   iaa_counts_pin='/sys/fs/bpf/chain_counts')
        spec = self.specs('nvme-iaa-gpu', 'session', rig=rig)['nvme-iaa-gpu']
        self.assertEqual(spec['iaa_counts_pin'], '/sys/fs/bpf/chain_counts')
        self.assertNotIn('plans', spec)
        self.assertEqual(self.validate(spec)[0], 0)
        self.assertNotIn('iaa_counts_pin', self.specs('nvme-iaa-gpu', 'session')['nvme-iaa-gpu'])

    def test_receiver_oracle_and_plan_reuse(self):
        s = self.specs('nvme-gpu-nic', 'session')
        rx, tx = s['nic-gpu-nvme'], s['nvme-gpu-nic']
        self.assertEqual(rx['oracle']['kind'], 'file')
        self.assertEqual(rx['oracle']['path'], '/dev/nvme1n1')
        self.assertEqual(rx['oracle']['offset'], 2048 * 512)
        self.assertEqual(rx['stages'][3]['slba'], 2048)
        self.assertNotIn('oracle', tx)
        self.assertNotIn('plans', tx)               # every class already attached
        self.assertEqual(tx['ce']['va'], 0)
        self.assertEqual(rx['ce']['va'], 4 << 20)
        self.assertEqual(tx['peer']['local_ip'], '192.0.2.1')
        self.assertEqual(rx['peer']['local_ip'], '192.0.2.2')
        self.assertEqual(rx['start_per'], 'batch')
        iaa = self.specs('nvme-iaa-gpu', 'session')['nvme-iaa-gpu']
        self.assertEqual(iaa['plans'], [dict(obj='/opt/chains/chain_plan.bpf.o',
                                             map='chain_iaa_ops', set=dict(expect_out=4096))])
        self.assertTrue(iaa['oracle']['every_window'])
        self.assertEqual(iaa['stages'][1]['expect'], 4096)
        staged = self.specs('nvme-gpu-nic', 'staged')['nvme-gpu-nic']
        self.assertEqual(staged['staged_gpu'], 'ce-sim')

    def test_refused_spec_reaches_the_c_refusal(self):
        spec = self.specs('nvme-nic', 'session')['nvme-nic']
        spec['chain'] = 'nvme-crc-nic'
        code, text = self.validate(spec)
        self.assertEqual(code, 4)
        self.assertTrue(text.startswith('unsupported: in-frame transform not implemented'))
        spec = self.specs('nvme-nic', 'session')['nvme-nic']
        spec['plan'] = 'default'
        code, text = self.validate(spec)
        self.assertEqual((code, text.split(',')[0]), (4, 'unsupported: no mechanism class '
                                                         'registers default_build'))


class Summary(unittest.TestCase):
    @staticmethod
    def row(chain, arm, load, timings, label='base'):
        side = 'receiver' if chain.startswith('nic-') else 'sender'
        recs = [dict(timing=t, cost=dict(syscalls=3, observer_syscalls=1)) for t in timings]
        result = {side: recs[0]} if len(recs) == 1 else dict(sessions=recs)
        return dict(chain=chain, size=8192, arm=arm, wait=None, load=load,
                    var=dict(label=label), result=result)

    def test_sustained_throughput_and_gaps(self):
        t = dict(load='sustained', record_bytes=8192, t0_ns=1000, completions=[100, 300, 400, 800])
        out = run.summarize([self.row('nvme-nic', 'session', 'sustained', [t])])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['records'], 4)
        self.assertEqual(out[0]['p50_ns'], 200)        # gaps 100, 200, 100, 400
        self.assertEqual(sorted(run.gaps(t['completions'])), [100, 100, 200, 400])
        self.assertAlmostEqual(out[0]['gbytes_per_s'], 4 * 8192 / 800)
        self.assertEqual(out[0]['observer_syscalls'], 1)
        self.assertIn('depth in flight', out[0]['latency'])

    def test_concurrent_sessions_share_one_clock(self):
        a = dict(load='sustained', record_bytes=1000, t0_ns=0, completions=[50, 100])
        b = dict(load='sustained', record_bytes=1000, t0_ns=50, completions=[100, 150])
        self.assertAlmostEqual(run.sustained_rate([a, b]), 4000 / 200)
        self.assertAlmostEqual(run.sustained_rate([b, a]), 4000 / 200)     # order-free
        out = run.summarize([self.row('nvme-iaa-gpu', 'session', 'sustained', [a, b])])
        self.assertAlmostEqual(out[0]['gbytes_per_s'], 20.0)
        self.assertIsNone(run.sustained_rate([dict(a, completions=[])]))

    def test_closed_rows_keep_their_own_label(self):
        t = dict(load='closed', window_bytes=8192, samples=[1000, 2000, 3000])
        out = run.summarize([self.row('nvme-nic', 'staged', 'closed', [t])])
        self.assertEqual(out[0]['p50_ns'], 2000)
        self.assertAlmostEqual(out[0]['gbytes_per_s_closed_loop_at_p50'], 8192 / 2000)
        self.assertNotIn('gbytes_per_s', out[0])


class Cli(unittest.TestCase):
    def call(self, *extra):
        with tempfile.TemporaryDirectory(prefix='.chains-cli-', dir=HERE) as tmp:
            rig = Path(tmp) / 'rig.json'
            rig.write_text(json.dumps(RIG))
            out = subprocess.run([sys.executable, str(HERE / 'run.py'), '--rig', str(rig),
                                  '--out-dir', tmp, *extra], capture_output=True, text=True)
            return out.returncode, out.stdout, sorted(p.name for p in Path(tmp).rglob('*.json'))

    def test_only_refused_cases_exit_4(self):
        code, out, _ = self.call('--chain', 'nvme-crc-nic', '--correctness-only')
        self.assertEqual(code, 4)
        row = json.loads(out.splitlines()[0])
        self.assertEqual(row['status'], 'not_run')
        self.assertIn('in-frame transform not implemented', row['failure'])

    def test_timing_refused_without_physical_devices(self):
        code, out, files = self.call('--chain', 'nvme-gpu-nic', '--sizes', '4096')
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(out)['status'], 'not_run_hardware')
        self.assertEqual(files, ['rig.json'])        # nothing ran, nothing written

    def test_dry_run_writes_both_ends(self):
        code, out, files = self.call('--chain', 'nic-gpu-nvme', '--correctness-only', '--dry-run')
        self.assertEqual(code, 0, out)
        # Correctness runs exercise both loads: one directory each.
        self.assertEqual(files, ['nic-gpu-nvme.spec.json'] * 2 + ['nvme-gpu-nic.spec.json'] * 2 +
                         ['rig.json'])
        self.assertEqual([json.loads(line)['load'] for line in out.splitlines()],
                         ['closed', 'sustained'])

    def test_bad_arguments_exit_2(self):
        code, _, _ = self.call('--chain', 'nvme-nic', '--sizes', '3000')
        self.assertEqual(code, 2)


def tree(root, **over):
    """A fabricated physical host for the gate; @over replaces files."""
    files = {
        'sys/class/dmi/id/sys_vendor': 'Supermicro', 'sys/class/dmi/id/product_name': 'X12',
        'sys/class/dmi/id/board_vendor': 'Supermicro', 'proc/cpuinfo': 'flags\t: fpu sse\n',
        'proc/crypto': 'name         : deflate\ndriver       : deflate-iaa\n',
        'sys/devices/pci0000:00/0000:01:00.0/vendor': '0x144d',
        'sys/devices/pci0000:00/0000:02:00.0/vendor': '0x15b3',
        'sys/devices/pci0000:00/0000:03:00.0/vendor': '0x10de',
        'sys/devices/pci0000:00/0000:04:00.0/vendor': '0x10de',
        'dev/nvidia0': '', 'dev/nvidia1': '',
        'proc/driver/nvidia/gpus/0000:03:00.0/information': 'Model: X\nDevice Minor: 0\n',
        'proc/driver/nvidia/gpus/0000:04:00.0/information': 'Model: X\nDevice Minor: 1\n',
        'sys/bus/pci/drivers/mlx5_core/.keep': '',
        'sys/bus/dsa/devices/iax1/.keep': '',
    }
    files.update(over)
    for name, text in files.items():
        if text is None:
            continue
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    ctrl = root / 'sys/devices/pci0000:00/0000:01:00.0/nvme/nvme0'
    ctrl.mkdir(parents=True, exist_ok=True)
    for cls, name in (('block', 'nvme0n1'), ('nvme-generic', 'ng0n1')):
        d = root / 'sys/class' / cls / name
        d.mkdir(parents=True, exist_ok=True)
        if not (d / 'device').exists():
            (d / 'device').symlink_to(ctrl)
    net = root / 'sys/class/net/eth0'
    net.mkdir(parents=True, exist_ok=True)
    pci = root / 'sys/devices/pci0000:00/0000:02:00.0'
    if not (pci / 'driver').exists():
        (pci / 'driver').symlink_to(root / 'sys/bus/pci/drivers/mlx5_core')
    if not (net / 'device').exists():
        (net / 'device').symlink_to(pci)
    for bdf in ('0000:03:00.0', '0000:04:00.0'):
        gpu = root / 'sys/bus/pci/devices' / bdf
        gpu.parent.mkdir(parents=True, exist_ok=True)
        if not gpu.exists():
            gpu.symlink_to(root / 'sys/devices/pci0000:00' / bdf)
    boot = root / 'boot' / ('config-' + os.uname().release)
    boot.parent.mkdir(parents=True, exist_ok=True)
    if 'kernel' not in over:
        boot.write_text('CONFIG_XDEV_EXT_MECH=y\nCONFIG_XDEV_EXT_MECH_ZEROCOPY=y\n')
    return root


class Gate(unittest.TestCase):
    rig = dict(nvme_src=dict(block='/dev/nvme0n1', ng='/dev/ng0n1'),
               tx=dict(ifname='eth0'), ce=dict(dev='/dev/nvidia0', bdf='0000:03:00.0'),
               iaa_software=False)
    stages = [('nvme', 'from', 'src'), ('ce', 'to', 'tx'), ('afxdp', 'to', 'tx'),
              ('iaa', 'from', 'src')]

    def setUp(self):
        # A fabricated tree has no device nodes: /dev/nvidiaN is major 195, minor N.
        real = hardware_gate._char_dev
        hardware_gate._char_dev = lambda p: (195, int(Path(p).name[len('nvidia'):]))
        self.addCleanup(setattr, hardware_gate, '_char_dev', real)

    def admit(self, rig=None, **over):
        with tempfile.TemporaryDirectory(prefix='.chains-gate-', dir=HERE) as tmp:
            return hardware_gate.admit(rig or self.rig, self.stages, ['session'],
                                       tree(Path(tmp), **over))

    def refused(self, text, rig=None, **over):
        with self.assertRaises(hardware_gate.Refusal) as ctx:
            self.admit(rig, **over)
        self.assertIn(text, str(ctx.exception))

    def test_physical_tree_admits(self):
        ev = self.admit()
        self.assertEqual([d.get('vendor') for d in ev['devices']], ['0x144d', '0x10de', '0x15b3',
                                                                     None])
        self.assertEqual(ev['devices'][2]['driver'], 'mlx5_core')

    def test_each_refusal(self):
        self.refused('hypervisor', **{'sys/hypervisor/type': 'kvm'})
        self.refused('CPU flags include hypervisor', **{'proc/cpuinfo': 'flags\t: fpu hypervisor\n'})
        self.refused('virtual platform DMI', **{'sys/class/dmi/id/product_name': 'QEMU Standard PC'})
        self.refused('virtio/Red Hat', **{'sys/devices/pci0000:00/0000:01:00.0/vendor': '0x1af4'})
        self.refused('not an NVIDIA GPU', **{'sys/devices/pci0000:00/0000:03:00.0/vendor': '0x1234'})
        self.refused('CPU memcpy simulator', dict(self.rig, ce=dict(dev='/dev/xdev_ext_ce_sim',
                                                                    bdf='0000:03:00.0')))
        self.refused('deflate-generic', dict(self.rig, iaa_software=True))
        self.refused('deflate-iaa is not registered', **{'proc/crypto': 'driver : deflate-generic\n'})
        self.refused('CONFIG_XDEV_EXT_MECH_ZEROCOPY', kernel=None,
                     **{'boot/config-' + os.uname().release: 'CONFIG_XDEV_EXT_MECH=y\n'})
        self.refused('not the same NVMe namespace', dict(self.rig, nvme_src=dict(
            block='/dev/nvme0n1', ng='/dev/ng9n9')))

    def test_ce_device_is_the_rig_gpu(self):
        other = dict(self.rig, ce=dict(dev='/dev/nvidia0', bdf='0000:04:00.0'))
        self.refused('CE device /dev/nvidia0 is GPU 0000:03:00.0, not rig ce.bdf 0000:04:00.0',
                     other)
        self.assertEqual(self.admit(dict(self.rig, ce=dict(dev='/dev/nvidia1',
                                                           bdf='0000:04:00.0')))['devices'][1]
                         ['ce_dev'], '/dev/nvidia1')
        self.refused('is not an NVIDIA GPU node', dict(self.rig, ce=dict(dev='/dev/dri/card0',
                                                                         bdf='0000:03:00.0')),
                     **{'dev/dri/card0': ''})
        self.refused('0 NVIDIA GPUs report device minor 0', **{
            'proc/driver/nvidia/gpus/0000:03:00.0/information': 'Device Minor: 7\n'})


if __name__ == '__main__':
    unittest.main()
