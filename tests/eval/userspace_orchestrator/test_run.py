#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of the user-space orchestrator front end and its specs.

Run: python3 tests/eval/userspace_orchestrator/test_run.py -v
Specs are checked by the test_uo_core binary (`make test`); nothing opens a
device, a socket or a GPU.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('uo_run', HERE / 'run.py')
uo_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uo_run)
chains = uo_run.chains

RIG = dict(
    nvme_src=dict(ng='/dev/ng0n1', block='/dev/nvme0n1', slba=0, nlb=1 << 20, lba_bytes=512),
    nvme_dst=dict(ng='/dev/ng1n1', block='/dev/nvme1n1', slba=4096, nlb=1 << 20, lba_bytes=4096),
    tx=dict(ifname='eth0', mac='02:00:00:00:00:01', ip='192.0.2.1', port=54321, mtu=1500),
    rx=dict(ifname='eth1', mac='02:00:00:00:00:02', ip='192.0.2.2', port=12345, mtu=1500,
            queue=2),
    ce=dict(dev='/dev/nvidia0', len=1 << 30, bdf='0000:65:00.0'),
    attached=['nxp_nvme_ops', 'nxp_afxdp_ops', 'ce_plan_ops'], nxp_session=270019)


class Tool:
    tmp = None

    @classmethod
    def path(cls):
        if cls.tmp is None:
            cls.tmp = tempfile.TemporaryDirectory(prefix='.uo-test-', dir=HERE)
            subprocess.run(['make', '-s', '-C', str(HERE), 'BUILD=' + cls.tmp.name, 'test'],
                           check=True)
        return Path(cls.tmp.name) / 'test_uo_core'


class FrontEnd(unittest.TestCase):
    def test_forwarding(self):
        _, out = uo_run.parse(['--rig', 'r.json', '--chain', 'nvme-nic', '--depth', '1..8',
                               '--records', '4'])
        self.assertEqual(out, ['--rig', 'r.json', '--chain', 'nvme-nic', '--wait', 'poll,eventfd',
                               '--sizes', '4096', '--arms', 'userspace-shared', '--depth', '1',
                               '--records', '4', '--sweep', 'qd=2,4,8'])
        _, out = uo_run.parse(['--rig', 'r.json', '--with-session'])
        self.assertIn('userspace-shared,session', out)
        for bad in (['--chain', 'nvme-nic'], ['--rig', 'r', '--depth', '-1']):
            with self.assertRaises(chains.Usage):
                uo_run.parse(bad)

    def test_loc_counts_code_only(self):
        with tempfile.NamedTemporaryFile('w', suffix='.c', dir=HERE, delete=False) as f:
            f.write('/* a\n * b */\nint x;\n\n// c\nint y; /* d */\n  /* e */ int z;\n')
        try:
            self.assertEqual(uo_run.code_lines(f.name), 3)
        finally:
            os.unlink(f.name)
        out = subprocess.run([sys.executable, str(HERE / 'run.py'), '--loc'], capture_output=True,
                             text=True, check=True).stdout.split('\n')
        self.assertTrue(out[0].startswith('userspace-shared '))
        self.assertTrue(out[1].startswith('session '))


class Specs(unittest.TestCase):
    def validate(self, spec, cuda=False):
        with tempfile.NamedTemporaryFile('w', suffix='.json', dir=Tool.path().parent,
                                         delete=False) as f:
            json.dump(spec, f)
        out = subprocess.run([str(Tool.path()), '--validate', f.name, *(['cuda'] if cuda else [])],
                             capture_output=True, text=True)
        os.unlink(f.name)
        return out.returncode, out.stdout.strip()

    def uo_specs(self, chain, wait='eventfd', load='closed'):
        a = chains.parse(['--rig', 'x', '--chain', chain, '--arms', 'userspace-shared',
                          '--wait', wait, '--correctness-only'])
        case = [c for c in chains.cases(a, RIG) if c['load'] == load][0]
        shape = chains.record_shape(chain, 4096, RIG)
        names = [chain, chains.COMPLEMENT[chain]]
        return {n: chains.uo_spec(case, n, RIG, a, shape, 5, Path('/tmp/o')) for n in names}

    def test_generated_specs_validate(self):
        for chain in ('nvme-nic', 'nic-nvme'):
            for wait in ('poll', 'eventfd'):
                for name, s in self.uo_specs(chain, wait).items():
                    self.assertEqual(self.validate(s)[0], 0, (name, s))
        for name, s in self.uo_specs('nvme-gpu-nic').items():
            self.assertEqual(self.validate(s, cuda=True)[0], 0, name)
            code, text = self.validate(s)
            self.assertEqual(code, 4)
            self.assertIn('needs a UO_CUDA=1 build', text)

    def test_sustained_specs_validate(self):
        for chain in ('nvme-nic', 'nic-nvme'):
            for name, s in self.uo_specs(chain, load='sustained').items():
                self.assertEqual(s['load'], 'sustained')
                self.assertEqual(self.validate(s)[0], 0, (name, s))
        _, out = uo_run.parse(['--rig', 'r.json', '--load', 'sustained'])
        self.assertEqual(out[-2:], ['--load', 'sustained'])

    def test_seed_schema_accepts_real_producer_and_rejects_invalid_values(self):
        for wait in ('poll', 'eventfd'):
            for name, generated in self.uo_specs('nvme-nic', wait).items():
                for seed in (0, 5, (1 << 64) - 1):
                    with self.subTest(wait=wait, chain=name, seed=seed):
                        self.assertEqual(self.validate(dict(generated, seed=seed))[0], 0)
                legacy = dict(generated)
                del legacy['seed']
                self.assertEqual(self.validate(legacy)[0], 0)
                for seed in (True, False, None, '5', 1.5, -1, 1 << 64):
                    with self.subTest(wait=wait, chain=name, invalid_seed=seed):
                        self.assertEqual(self.validate(dict(generated, seed=seed))[0], 2)
                bad = dict(generated, seed_typo=17)
                code, diagnostic = self.validate(bad)
                self.assertEqual(code, 2)
                self.assertIn('unknown member seed_typo', diagnostic)

    def test_receiver_has_the_oracle(self):
        s = self.uo_specs('nvme-nic')
        self.assertNotIn('oracle', s['nvme-nic'])
        rx = s['nic-nvme']
        self.assertEqual(rx['oracle']['path'], '/dev/nvme1n1')
        self.assertEqual(rx['oracle']['offset'], 4096 * 4096)
        self.assertEqual(rx['nic'], dict(ifname='eth1', queue=2))
        self.assertEqual(rx['peer']['local_port'], 12345)
        self.assertEqual(rx['nvme']['lba_bytes'], 4096)


class Cli(unittest.TestCase):
    def call(self, *extra):
        with tempfile.TemporaryDirectory(prefix='.uo-cli-', dir=HERE) as tmp:
            rig = Path(tmp) / 'rig.json'
            rig.write_text(json.dumps(RIG))
            out = subprocess.run([sys.executable, str(HERE / 'run.py'), '--rig', str(rig),
                                  '--out-dir', tmp, *extra], capture_output=True, text=True)
            return out.returncode, out.stdout

    def test_iaa_chain_is_refused(self):
        code, out = self.call('--chain', 'nvme-iaa-gpu', '--correctness-only')
        self.assertEqual(code, 4)
        self.assertIn('no IAA stage', out)

    def test_timing_needs_physical_devices(self):
        code, out = self.call('--chain', 'nvme-nic')
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(out)['status'], 'not_run_hardware')

    def test_depth_above_session_limit_is_refused(self):
        code, out = self.call('--chain', 'nvme-nic', '--depth', '128', '--correctness-only')
        self.assertEqual(code, 4)
        self.assertIn('XDEV_EXT_MECH_MAX_DEPTH', out)


if __name__ == '__main__':
    unittest.main()
