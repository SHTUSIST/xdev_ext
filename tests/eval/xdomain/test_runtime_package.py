#!/usr/bin/env python3
"""Build input qualification only; actual deployment is audited from SDK receipt."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RUNTIME = ('platform_facts.py', 'native_barrier.py', 'action_provider.py')
DEPLOYED = (*RUNTIME, 'check_protocol.py')


def load_builder():
    spec = importlib.util.spec_from_file_location('real_build', HERE / 'build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def isolated_imports(directory):
    # Mirror the owner's isolated interpreter and explicit helpers directory.
    # Importing these real modules performs no CUDA or action execution.
    code = ('import importlib,json,sys; sys.path.insert(0,sys.argv[1]); '
            'print(json.dumps({name:importlib.import_module(name).__file__ '
            'for name in ("platform_facts","native_barrier","action_provider")}))')
    return subprocess.run([sys.executable, '-I', '-c', code, str(directory)],
                          cwd=directory, capture_output=True, text=True)

class RuntimePackage(unittest.TestCase):
    def test_transitive_protocol_dependency_is_required(self):
        self.assertIn(HERE / 'check_protocol.py', load_builder().required_sources(HERE),
                      'native barrier and action helper need deployed check_protocol')

    def test_inventoried_runtime_imports_in_clean_directory(self):
        # This qualifies the actual source inventory; it does not claim an SDK
        # build. Only official receipt mode below audits actual builder output.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for path in load_builder().required_sources(HERE):
                if path.suffix == '.py':
                    shutil.copyfile(path, directory / path.name)
            result = isolated_imports(directory)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            origins = json.loads(result.stdout)
            for name in RUNTIME:
                self.assertEqual(Path(origins[Path(name).stem]), directory / name)

    def test_real_owner_and_runtime_inputs_are_required(self):
        spec = importlib.util.spec_from_file_location('real_build', HERE / 'build.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        paths = set(module.required_sources(HERE))
        for name in ('native_trace_owner.cc', 'native_trace_owner.h', *RUNTIME):
            self.assertIn(HERE / name, paths)

    def test_missing_runtime_module_is_durable_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'repo/tests/eval/xdomain'
            source.mkdir(parents=True)
            shutil.copyfile(HERE / 'build.py', source / 'build.py')
            out = root / 'out'
            result = subprocess.run([sys.executable, '-I', str(source / 'build.py'),
                '--cuda-home', str(root / 'missing-sdk'), '--out', str(out)],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            receipt = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(receipt['status'], 'unavailable')
            missing = {Path(p).name for p in receipt['missing_sources']}
            self.assertTrue(set(RUNTIME) <= missing, missing)
            self.assertEqual(receipt['execution'], 'not-run')


class OfficialRuntimePackage(unittest.TestCase):
    def test_actual_sdk_output_has_hashed_importable_runtime(self):
        receipt = json.loads(Path(SDK_RECEIPT).read_text())
        self.assertEqual(receipt['status'], 'built')
        self.assertEqual(receipt['execution'], 'not-run')
        self.assertTrue(any('--ptx' in command['argv'] and command['returncode'] == 0
                            for command in receipt['commands']))
        self.assertTrue(any('-lcuda' in command['argv'] and command['returncode'] == 0
                            for command in receipt['commands']))
        directory = Path(receipt['artifacts']['executable']).parent
        for name in DEPLOYED:
            path = directory / name
            self.assertEqual(receipt['artifacts'].get(Path(name).stem), str(path))
            self.assertTrue(path.is_file(), 'actual deployed module missing: ' + name)
            self.assertEqual(receipt['artifact_sha256'].get(str(path)),
                             hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(path.read_bytes(), (HERE / name).read_bytes(),
                             'deployed module differs from real source: ' + name)
        result = isolated_imports(directory)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        origins = json.loads(result.stdout)
        for name in RUNTIME:
            self.assertEqual(Path(origins[Path(name).stem]), directory / name)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-receipt', default='')
    options = parser.parse_args()
    SDK_RECEIPT = options.sdk_receipt
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimePackage)
    if SDK_RECEIPT:
        suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(OfficialRuntimePackage))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
