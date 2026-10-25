#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise both real runner preflights without booting or building a kernel."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[6]
LIB = 'kernel/tools/testing/selftests/xdev_ext_lib'
PEER = 'kernel/tools/testing/selftests/xdev_ext_peer/guest'
SCRIPTS = (ROOT / LIB / 'guest/lib_kvm.sh', ROOT / PEER / 'session_kvm.sh')


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='xdev-build-reuse-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.build = self.base / 'build'
        self.build.mkdir()
        self.tools = self.base / 'tools'
        (self.tools / 'peer-guest').mkdir(parents=True)
        self.scratch = self.base / 'scratch'
        self.scratch.mkdir(mode=0o700)
        self.git('init', '-q')
        self.git('config', 'user.email', 'selftest@example.invalid')
        self.git('config', 'user.name', 'Build reuse selftest')
        self.write('kernel/io_uring/xdev_ext_mech.c', 'native implementation\n')
        for name in ('xdev_ext_peer_sw.c', 'sw_provider_uapi.h'):
            self.write(f'{PEER}/{name}', 'matching module source\n')
            (self.tools / 'peer-guest' / name).write_text('matching module source\n')
        self.commit()
        sha = self.git('rev-parse', 'HEAD').strip()
        (self.build / 'xdev-ext-source.commit').write_text(sha + '\n')
        # Reaching this deliberately missing config proves identity admission;
        # execution stops before module inspection, builds, or QEMU.
        (self.build / '.config').write_text('')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.source), *args],
                                       text=True, stderr=subprocess.STDOUT)

    def write(self, name, data):
        target = self.source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'selftest input')

    def run_gate(self, script):
        result = subprocess.run(['bash', str(script), '--scratch', str(self.scratch),
                                 '--source', str(self.source), '--build', str(self.build),
                                 '--tools', str(self.tools)], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=15, env={**os.environ, 'CC': 'gcc'})
        self.assertEqual(result.returncode, 1, result.stdout)
        return result.stdout

    def test_combined_test_only_changes_are_admitted(self):
        self.write(f'{LIB}/guest/test.c', 'library guest change\n')
        self.write(f'{PEER}/test.c', 'peer guest change\n')
        self.write('.github/workflows/host.yml', 'test workflow change\n')
        self.commit()
        for script in SCRIPTS:
            with self.subTest(runner=script.name):
                self.assertIn('FAIL kernel requires CONFIG_MODULES=y', self.run_gate(script))

    def test_native_source_change_is_refused(self):
        self.write('kernel/io_uring/xdev_ext_mech.c', 'changed native implementation\n')
        self.commit()
        for script in SCRIPTS:
            with self.subTest(runner=script.name):
                self.assertIn('FAIL source differs', self.run_gate(script))

    def test_peer_module_change_is_refused(self):
        self.write(f'{PEER}/xdev_ext_peer_sw.c', 'different module\n')
        self.commit()
        self.assertIn('FAIL provider module source changed', self.run_gate(SCRIPTS[1]))

    def test_peer_module_copy_mismatch_is_refused(self):
        (self.tools / 'peer-guest/sw_provider_uapi.h').write_text('stale module copy\n')
        self.assertNotIn('FAIL kernel requires', self.run_gate(SCRIPTS[1]))

    def test_uncommitted_source_is_refused(self):
        self.write('kernel/io_uring/xdev_ext_mech.c', 'uncommitted native change\n')
        for script in SCRIPTS:
            with self.subTest(runner=script.name):
                self.assertNotIn('FAIL kernel requires', self.run_gate(script))


if __name__ == '__main__':
    unittest.main()
