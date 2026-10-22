#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual guest dependency staging with two real dynamic executables."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'


class GuestLibraries(unittest.TestCase):
    def test_both_real_programs_and_second_program_only_library_are_staged(self):
        script = HARNESS.read_text()
        begin = script.index('GUEST_PROGRAMS=(')
        end = script.index('cat >"$ROOT/init"', begin)
        fragment = script[begin:end]
        with tempfile.TemporaryDirectory(prefix='xdev-ext-guest-libs-') as directory:
            base = Path(directory)
            tools, iaa, deps, root, evidence = (base / part for part in ('tools', 'iaa', 'deps', 'root', 'evidence'))
            for folder in (tools, iaa, deps, root, evidence):
                folder.mkdir()
            (base / 'plain.c').write_text('int main(void) { return 0; }\n')
            (base / 'library.c').write_text('int additional_iaa_library(void) { return 42; }\n')
            (base / 'extra.c').write_text('extern int additional_iaa_library(void); int main(void) { return additional_iaa_library() != 42; }\n')
            extra_library = deps / 'libiaa_staging_probe.so'
            cc = os.environ.get('CC', 'cc')
            commands = ([cc, str(base / 'plain.c'), '-o', str(tools / 'xdev_ext_mech_ctl')],
                        [cc, '-shared', '-fPIC', str(base / 'library.c'), '-o', str(extra_library)],
                        [cc, str(base / 'extra.c'), '-L' + str(deps), '-liaa_staging_probe',
                         '-Wl,-rpath,' + str(deps), '-o', str(iaa / 'iaa_runtime')])
            for command in commands:
                build = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            programs = (tools / 'xdev_ext_mech_ctl', iaa / 'iaa_runtime')
            dependencies = []
            for program in programs:
                result = subprocess.run(['ldd', str(program)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                paths = set(re.findall(r'^\s*(?:\S+\s+=>\s+)?(/\S+)', result.stdout, re.M))
                self.assertTrue(paths, 'fixture must be a real dynamic executable')
                dependencies.append(paths)
            self.assertNotIn(str(extra_library), dependencies[0])
            self.assertIn(str(extra_library), dependencies[1], 'second executable must add its own real library')
            run = subprocess.run(['bash', '-euc', fragment],
                env=dict(os.environ, TOOLS=str(tools), IAA_OUT=str(iaa), ROOT=str(root),
                         EV=str(evidence), CE_SIM='1', PROVIDER_CASE='normal'),
                capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            expected = set.union(*dependencies)
            for library in expected:
                staged = root / library.lstrip('/')
                self.assertTrue(staged.is_file(), 'missing real dependency: ' + library)
                self.assertEqual(staged.read_bytes(), Path(library).read_bytes())
            staged_files = [str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()]
            self.assertEqual(set(staged_files), {path.lstrip('/') for path in expected})
            self.assertFalse(any(path.endswith(':') for path in staged_files), 'ldd executable headers became fake library paths')


if __name__ == '__main__':
    unittest.main(verbosity=2)
