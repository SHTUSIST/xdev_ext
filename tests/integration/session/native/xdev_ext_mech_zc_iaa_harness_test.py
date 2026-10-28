#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual run-only software IAA identity gate with hostile inputs."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'


class IAAIdentityGate(unittest.TestCase):
    def run_gate(self, *, missing_symbol=None, missing_record=None, missing_file=None):
        text = HARNESS.read_text()
        match = re.search(r'^verify_iaa_identity\(\) \{\n.*?^\}', text, re.M | re.S)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory(prefix='iaa-identity-') as directory:
            path = Path(directory)
            build = path / 'build'
            output = path / 'iaa'
            build.mkdir()
            output.mkdir()
            symbols = ('XDEV_EXT_MECH_IAA', 'CRYPTO_ACOMP2', 'CRYPTO_DEFLATE')
            (build / '.config').write_text('\n'.join('CONFIG_' + symbol + '=y' for symbol in symbols if symbol != missing_symbol) + '\n')
            records = []
            for artifact in ('iaa_runtime', 'iaa_pair.bpf.o'):
                if artifact != missing_file:
                    (output / artifact).write_text('synthetic identity test')
                if artifact != missing_record:
                    records.append('0' * 64 + '  ' + str(output / artifact))
            (build / 'xdev-ext-artifacts.sha256').write_text('\n'.join(records) + '\n')
            return subprocess.run(['bash', '-euc', match.group() + '\nverify_iaa_identity'],
                env=dict(os.environ, BUILD=str(build), IAA_OUT=str(output)),
                capture_output=True, text=True)

    def test_complete_config_and_identity_is_accepted(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_old_build_without_any_required_config_is_rejected(self):
        for symbol in ('XDEV_EXT_MECH_IAA', 'CRYPTO_ACOMP2', 'CRYPTO_DEFLATE'):
            with self.subTest(symbol=symbol):
                self.assertNotEqual(self.run_gate(missing_symbol=symbol).returncode, 0)

    def test_existing_artifact_without_hashed_build_identity_is_rejected(self):
        for name in ('iaa_runtime', 'iaa_pair.bpf.o'):
            with self.subTest(artifact=name):
                self.assertNotEqual(self.run_gate(missing_record=name).returncode, 0)

    def test_missing_runtime_or_bpf_is_rejected(self):
        for name in ('iaa_runtime', 'iaa_pair.bpf.o'):
            with self.subTest(artifact=name):
                self.assertNotEqual(self.run_gate(missing_file=name).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
