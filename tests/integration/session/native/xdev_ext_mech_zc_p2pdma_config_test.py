#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Every guest kernel profile must carry upstream PCI P2PDMA.

Without CONFIG_PCI_P2PDMA, pci_p2pdma_distance_many() is the header stub that
returns -1, so a PEER session whose device DMA targets a GPU BAR fails
REQUESTER_DECIDE with NO_P2P_PATH.  This executes the harness's actual
configuration block (only scripts/config and make are doubles) for each
profile, plus the helper used by the run-only reuse admission, without KVM.
"""
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'
HELPER = HERE / 'xdev_ext_mech_zc_debug.py'
P2PDMA = ('MEMORY_HOTPLUG', 'MEMORY_HOTREMOVE', 'MIGRATION', 'SPARSEMEM_VMEMMAP',
          'ZONE_DEVICE', 'PCI_P2PDMA')
PROFILES = {
    'default': dict(DEBUG_LOCKING=0),
    'strict-debug': dict(DEBUG_LOCKING=1),
    'gpu-debug': dict(DEBUG_LOCKING=1, GPU=1),
    'peer': dict(DEBUG_LOCKING=0, PEER=1),
    'ce-sim-debug': dict(DEBUG_LOCKING=1, CE_SIM=1),
    'lifecycle': dict(DEBUG_LOCKING=0, LIFECYCLE=1),
}

CONFIG_TOOL = '''#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
assert args.pop(0) == '--file'
path = pathlib.Path(args.pop(0))
values = dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)
while args:
    op, symbol = args.pop(0), args.pop(0)
    if op == '--set-str':
        values['CONFIG_' + symbol] = '"' + args.pop(0) + '"'
    elif op in ('-e', '-m', '-d'):
        values['CONFIG_' + symbol] = {'-e': 'y', '-m': 'm', '-d': 'n'}[op]
    else:
        raise SystemExit('unknown scripts/config operation ' + op)
path.write_text(''.join(k + '=' + v + '\\n' for k, v in values.items()))
'''


class P2pdmaHelper(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('p2pdma_debug', HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        return helper

    def test_each_p2pdma_symbol_is_required(self):
        helper = self.load()
        config = ''.join(f'CONFIG_{key}=y\n' for key in P2PDMA)
        helper.check_p2pdma(config)
        for key in P2PDMA:
            for replacement in ('', f'# CONFIG_{key} is not set\n', f'CONFIG_{key}=m\n'):
                with self.subTest(key=key, replacement=replacement), self.assertRaises(ValueError):
                    helper.check_p2pdma(config.replace(f'CONFIG_{key}=y\n', replacement))

    def test_cli_action_rejects_config_without_p2pdma(self):
        with tempfile.TemporaryDirectory(prefix='p2pdma-cli-') as tmp:
            config = Path(tmp) / '.config'
            config.write_text('CONFIG_PCI=y\n')
            command = ['python3', '-I', str(HELPER), 'p2pdma', str(config), '/dev/null', '0']
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('PCI_P2PDMA', result.stderr)
            config.write_text(''.join(f'CONFIG_{key}=y\n' for key in P2PDMA))
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class HarnessConfigBlock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = HARNESS.read_text()

    def run_block(self, profile, drop=''):
        start = self.harness.find('if (( ! RUN_ONLY )); then\n\tkmake defconfig')
        self.assertGreaterEqual(start, 0, 'actual config block missing')
        match = re.search(r'^\s*if \(\( PREPARE_ONLY \)\); then.*?; fi\s*$', self.harness[start:], re.M)
        self.assertIsNotNone(match, 'actual prepare-only boundary missing')
        block = self.harness[start:start + match.end()] + '\nfi\n'
        with tempfile.TemporaryDirectory(prefix='p2pdma-config-') as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            (root / 'build').mkdir()
            tool = root / 'scripts/config'
            tool.write_text(CONFIG_TOOL)
            tool.chmod(0o700)
            shutil.copyfile(HELPER, root / 'debug.py')
            settings = dict(XDOMAIN=0, MECHANISM_VARIANTS=0, RUN_ONLY=0, CE_SIM=0, LIFECYCLE=0,
                            FENCE_CHECK=0, SOCKET_REQUIRED=0, COMPAT=0, PEER=0, VIOMMU=0,
                            GPU=0, TB_NHI=0, DEBUG_LOCKING=0, PREPARE_ONLY=1)
            settings.update(profile)
            prefix = 'set -euo pipefail\nSRC=$1; BUILD=$SRC/build; EV=$SRC; DEBUG_HELPER=$SRC/debug.py\n'
            prefix += ''.join(f'{key}={value}\n' for key, value in settings.items())
            prefix += 'PROVIDER_CASE=normal; NIC_MODEL=virtio\nverify_socket_config() { :; }\n'
            # make double: olddefconfig keeps requested values (and derives
            # LOCKDEP/ACOMP2 as Kconfig does) unless a drop is injected.
            prefix += '''kmake() {
    if [[ $1 == defconfig ]]; then : > "$BUILD/.config"; fi
    if [[ $1 == olddefconfig ]]; then
        if grep -Fxq CONFIG_PROVE_LOCKING=y "$BUILD/.config"; then echo CONFIG_LOCKDEP=y >>"$BUILD/.config"; fi
        if grep -Fxq CONFIG_CRYPTO_DEFLATE=y "$BUILD/.config"; then echo CONFIG_CRYPTO_ACOMP2=y >>"$BUILD/.config"; fi
        if [[ -n ${DROP_SYMBOL:-} ]]; then sed -i "/^CONFIG_${DROP_SYMBOL}=/d" "$BUILD/.config"; fi
    fi
    return 0
}
'''
            prefix += 'DROP_SYMBOL=' + drop + '\n'
            result = subprocess.run(['bash', '-c', prefix + block, 'fixture', str(root)],
                                    text=True, capture_output=True)
            config = (root / 'build/.config').read_text()
            return result, dict(line.split('=', 1) for line in config.splitlines() if '=' in line)

    def test_every_profile_enables_p2pdma(self):
        for name, profile in PROFILES.items():
            with self.subTest(profile=name):
                result, config = self.run_block(profile)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)
                for symbol in P2PDMA:
                    self.assertEqual(config.get('CONFIG_' + symbol), 'y', name + ' lacks ' + symbol)

    def test_olddefconfig_cannot_silently_drop_p2pdma(self):
        for name in ('default', 'strict-debug'):
            for symbol in ('PCI_P2PDMA', 'ZONE_DEVICE', 'MEMORY_HOTREMOVE'):
                with self.subTest(profile=name, symbol=symbol):
                    result, _ = self.run_block(PROFILES[name], drop=symbol)
                    self.assertNotEqual(result.returncode, 0, 'dropped ' + symbol + ' accepted')
                    self.assertNotIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)

    def test_run_only_reuse_rejects_build_without_p2pdma(self):
        # Execute the real run-only admission on a reused build directory,
        # as the fence reuse test does; an old build without P2PDMA must not
        # be run again.
        start = self.harness.index('if (( RUN_ONLY )); then\n')
        block = self.harness[start:self.harness.index('\nlowprio()', start)]
        socket_check = re.search(r'(verify_socket_config\(\) \{.*?^\})', self.harness,
                                 re.S | re.M).group(1)
        for config, want in (('CONFIG_MODULES=y\n', 1),
                             ('CONFIG_MODULES=y\n' + ''.join(f'CONFIG_{k}=y\n' for k in P2PDMA), 0)):
            with self.subTest(p2pdma=bool(want == 0)), tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp)
                (p / 'evidence').mkdir()
                (p / '.config').write_text(config)
                (p / 'xdev-ext-source.commit').write_text('b' * 40 + '\n')
                artifact = p / 'artifact'
                artifact.write_text('unit artifact\n')
                (p / 'xdev-ext-artifacts.sha256').write_text(
                    subprocess.check_output(['sha256sum', str(artifact)], text=True))
                subprocess.run(['python3', str(HELPER), 'record', str(p / '.config'),
                                str(p / 'xdev-ext-debug-profile.json'), '0'], check=True)
                cmd = (f'RUN_ONLY=1; SOCKET_REQUIRED=0; EVAL_SESSION=0; MECHANISM_VARIANTS=0; '
                       f'DEBUG_LOCKING=0; DEBUG_HELPER={HELPER}; BUILD={p}; EV={p}/evidence; '
                       f'SOURCE_COMMIT={"b" * 40};\n' + socket_check + '\n' + block)
                result = subprocess.run(['bash', '-eu', '-c', cmd], capture_output=True, text=True)
                if want:
                    self.assertNotEqual(result.returncode, 0, 'reuse accepted a build without P2PDMA')
                    self.assertIn('PCI_P2PDMA', result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()
