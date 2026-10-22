#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the optional compatibility guest's exact-build identity gate."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HARNESS = Path(__file__).with_name('xdev_ext_mech_zc_kvm.sh')
SYMBOLS = ('XDEV_EXT_MECH_SOCKET', 'IO_URING_XDEV_EXT_IAA', 'EXT4_FS', 'VIRTIO_BLK')
ARTIFACTS = ('socket/socket_runtime', 'socket/ce_observe.bpf.o',
             'tools/socket_sink.bpf.o', 'preload/libio_uring_unified.so',
             'preload/xdev_ext_preload_mech_workload',
             'preload/xdev_ext_preload_socket_smoke',
             'preload/xdev_ext_preload_db_workload')


class CompatibilityIdentity(unittest.TestCase):
    def gate(self, missing_symbol=None, missing_file=None, missing_record=None):
        match = re.search(r'^verify_compat_identity\(\) \{\n.*?^\}', HARNESS.read_text(), re.M | re.S)
        self.assertIsNotNone(match, 'compatibility guest must reject stale builds')
        with tempfile.TemporaryDirectory(prefix='xdev-compat-identity-') as directory:
            root = Path(directory)
            build = root/'build'
            build.mkdir()
            (build/'.config').write_text(''.join(f'CONFIG_{s}=y\n' for s in SYMBOLS if s != missing_symbol))
            records = []
            for name in ARTIFACTS:
                path = root/name
                path.parent.mkdir(exist_ok=True)
                if name != missing_file:
                    path.write_text('identity fixture\n')
                if name != missing_record:
                    records.append('0'*64+'  '+str(path))
            (build/'xdev-ext-artifacts.sha256').write_text('\n'.join(records)+'\n')
            return subprocess.run(['bash', '-euc', match.group()+'\nverify_compat_identity'],
                env=dict(os.environ, BUILD=str(build), TOOLS=str(root/'tools'),
                         SOCKET_OUT=str(root/'socket'), PRELOAD_OUT=str(root/'preload')),
                text=True, capture_output=True)

    def test_complete(self):
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_config_required(self):
        for name in SYMBOLS:
            with self.subTest(name=name):
                self.assertNotEqual(self.gate(missing_symbol=name).returncode, 0)

    def test_each_artifact_and_identity_required(self):
        for name in ARTIFACTS:
            with self.subTest(name=name):
                self.assertNotEqual(self.gate(missing_file=name).returncode, 0)
                self.assertNotEqual(self.gate(missing_record=name).returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
