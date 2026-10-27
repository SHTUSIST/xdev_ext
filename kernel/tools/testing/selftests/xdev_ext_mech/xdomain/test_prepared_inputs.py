#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Prepared Linux inputs must not poison stack C or inflate mutation copies.

Use actual production units, wrappers and the unchanged independent 12-case
oracle in private source trees. No full-tree copy, actual mutation campaign,
physical device or performance measurement is performed here.
"""
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]
REL = HERE.relative_to(KERNEL)
POISON = (Path('include/linux/types.h'), Path('include/uapi/linux/types.h'))
UNRELATED = Path('drivers/unrelated_vendor/prepared-upstream.sparse')


class PreparedInputs(unittest.TestCase):
    def minimal_tree(self):
        temporary = tempfile.TemporaryDirectory(prefix='stack-prepared-inputs-', dir=KERNEL.parent.parent)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        kernel = root / 'kernel'
        expected = json.loads((HERE / 'stack_expected.json').read_text())
        seeds = [KERNEL.parent / name for name in expected['source_units']]
        seeds += [HERE / name for name in expected['wrappers']]
        seeds += [HERE / name for name in ('stack_cases.c', 'stack_kernel_compat.h',
                                          'stack_expected.json', 'stack_test.py', 'test_mutations.py')]
        # Resolve only project-owned C definitions. Kernel/libc environmental
        # headers belong to stack_test's real facade or installed exported UAPI.
        pending = list(seeds)
        inputs = {}
        include = re.compile(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', re.M)
        while pending:
            path = pending.pop().resolve()
            relative = path.relative_to(KERNEL.resolve())
            if relative in inputs:
                continue
            data = path.read_bytes()
            inputs[relative] = data
            if path.suffix not in ('.c', '.h'):
                continue
            for name in include.findall(data.decode()):
                candidates = (path.parent / name, KERNEL / name,
                              KERNEL / 'include' / name, KERNEL / 'include/uapi' / name,
                              KERNEL / 'tools/xdev_ext_mech' / name)
                for candidate in candidates:
                    if candidate.is_file() and 'xdev_ext' in candidate.name:
                        pending.append(candidate)
                        break
        for relative, data in inputs.items():
            target = kernel / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for relative in POISON:
            target = kernel / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('#error STACK_PREPARED_INTERNAL_TYPES_MUST_NOT_BE_INCLUDED\n')
        sparse = kernel / UNRELATED
        sparse.parent.mkdir(parents=True)
        with sparse.open('wb') as stream:
            stream.write(b'unrelated prepared upstream input\n')
            stream.seek((64 << 20) - 1)
            stream.write(b'\0')
        return root, kernel, inputs

    def assert_actual_stack(self, kernel, out):
        script = kernel / REL / 'stack_test.py'
        result = subprocess.run([sys.executable, '-I', str(script), '--kernel', str(kernel),
                                 '--keep-build', str(out)],
                                env={**os.environ, 'CC': 'gcc'}, capture_output=True,
                                text=True, timeout=150)
        self.assertEqual(result.returncode, 0,
                         'prepared-input stack must execute, not accept compiler failure:\n' + result.stdout + result.stderr)
        self.assertIn('1..12', result.stdout.splitlines())
        successes = [line for line in result.stdout.splitlines() if re.match(r'^ok [0-9]+ - ', line)]
        self.assertEqual(len(successes), 12, 'all unchanged independent stack cases must execute')
        self.assertNotIn('not ok ', result.stdout)
        self.assertNotIn('STACK_COMPILE_FAILURE', result.stdout + result.stderr)
        self.assertNotIn('STACK_MISSING_COMPOSITION_RED', result.stdout + result.stderr)

    def test_real_stack_passes_with_prepared_internal_and_raw_uapi_types_present(self):
        root, kernel, _ = self.minimal_tree()
        self.assert_actual_stack(kernel, root / 'stack-build')
        # The runner must not remove the inputs to manufacture a passing build.
        for relative in POISON:
            self.assertIn('STACK_PREPARED_INTERNAL_TYPES_MUST_NOT_BE_INCLUDED',
                          (kernel / relative).read_text())
        self.assertEqual((kernel / UNRELATED).stat().st_size, 64 << 20)

    def test_mutation_copy_preserves_required_real_inputs_and_excludes_upstream_data(self):
        copy_inputs = runpy.run_path(str(HERE / 'test_mutations.py')).get('copy_mutation_inputs')
        self.assertTrue(callable(copy_inputs), 'missing copy_mutation_inputs(kernel, dest) overlay-copy contract')
        root, kernel, inputs = self.minimal_tree()
        destination = root / 'copied-kernel'
        self.assertFalse(destination.exists())
        self.assertIsNone(copy_inputs(kernel, destination))
        self.assertTrue(destination.is_dir())
        for relative in POISON + (UNRELATED,):
            self.assertFalse((destination / relative).exists(), 'unrelated upstream input copied: ' + str(relative))
        for relative, data in inputs.items():
            with self.subTest(required_input=str(relative)):
                target = destination / relative
                self.assertTrue(target.is_file(), 'required actual input omitted: ' + str(relative))
                self.assertEqual(target.read_bytes(), data, 'copy rewrote a real input: ' + str(relative))
                self.assertEqual((kernel / relative).read_bytes(), data, 'copy modified the source: ' + str(relative))
        for relative in POISON:
            self.assertIn('STACK_PREPARED_INTERNAL_TYPES_MUST_NOT_BE_INCLUDED', (kernel / relative).read_text())
        self.assertEqual((kernel / UNRELATED).stat().st_size, 64 << 20)
        self.assert_actual_stack(destination, root / 'copied-stack-build')


if __name__ == '__main__':
    unittest.main(verbosity=2)
