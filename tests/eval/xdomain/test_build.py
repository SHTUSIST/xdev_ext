#!/usr/bin/env python3
"""Exercise the real builder's failures. SDK compile/link has a separate receipt.

Default tests require no CUDA installation. --cuda-home adds the actual compiler
failure test; --sdk-receipt audits an already executed official SDK build. Neither
mode executes the linked GPU program or treats unavailable as a successful build.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
BUILDER = HERE / 'build.py'
OPTIONS = None


class BuilderTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BUILDER.is_file(), 'RED: production build.py is missing')
        self.temp = tempfile.TemporaryDirectory(prefix='tb-builder-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, home, compiler='g++'):
        out = self.root / 'out'
        cmd = [sys.executable, '-I', str(BUILDER), '--cuda-home', str(home),
               '--host-cxx', compiler, '--arch', 'sm_80', '--out', str(out)]
        result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        print('+ ' + ' '.join(cmd), flush=True)
        print(result.stdout, end='', flush=True)
        print('builder returncode=' + str(result.returncode), flush=True)
        self.assertNotEqual(result.returncode, 0, 'negative became successful build')
        receipt = out / 'receipt.json'
        self.assertTrue(receipt.is_file(), 'nonzero build needs durable receipt.json')
        data = json.loads(receipt.read_text())
        self.assertEqual(data.get('execution'), 'not-run')
        self.assertIn(data.get('status'), ('unavailable', 'failed'))
        return data, result

    def assert_unavailable(self, data, result, reason):
        self.assertEqual(data.get('status'), 'unavailable')
        self.assertIsInstance(data.get('missing'), list, 'typed missing-prerequisite list absent')
        self.assertIn(reason, data['missing'])
        self.assertTrue(all(isinstance(item, str) for item in data['missing']))

    def sdk_view(self):
        """Prerequisite-only view: never a build-success SDK or synthetic header."""
        home = self.root / 'prerequisite-view'
        (home / 'bin').mkdir(parents=True)
        # This negative fixture proves preflight refuses absent header/stub before
        # invoking any compiler. /bin/false cannot produce PTX or fake success.
        (home / 'bin/nvcc').symlink_to('/bin/false')
        return home

    def test_missing_sdk_is_nonzero_unavailable(self):
        data, result = self.invoke(self.root / 'absent-sdk')
        self.assert_unavailable(data, result, 'nvcc')

    def test_missing_header_is_nonzero_unavailable(self):
        data, result = self.invoke(self.sdk_view())
        self.assert_unavailable(data, result, 'cuda.h')

    def test_missing_stub_is_nonzero_unavailable(self):
        data, result = self.invoke(self.sdk_view())
        self.assert_unavailable(data, result, 'libcuda')
        self.assertIn('cuda.h', data['missing'], 'preflight must aggregate header and stub absence')


class OfficialCompilerFailureTest(BuilderTest):
    # This class is added only with an explicit SDK path. A missing SDK is a test
    # failure here, never a skip or evidence of compiler rejection.
    def test_actual_compiler_nonzero_is_failed(self):
        home = Path(OPTIONS.cuda_home)
        self.assertTrue((home / 'bin/nvcc').is_file(), 'official nvcc required')
        self.assertTrue((home / 'include/cuda.h').is_file(), 'official cuda.h required')
        self.assertTrue(any((home / p).is_file() for p in
                            ('lib64/stubs/libcuda.so', 'targets/x86_64-linux/lib/stubs/libcuda.so')),
                        'official libcuda stub required')
        data, _ = self.invoke(home, '/bin/false')
        self.assertEqual(data.get('status'), 'failed')
        commands = data.get('commands', [])
        self.assertTrue(any(item.get('returncode', 0) != 0 and
                            item.get('argv', [None])[0] == '/bin/false'
                            for item in commands), 'actual requested compiler failure missing')


class OfficialReceiptTest(unittest.TestCase):
    def test_executed_official_build_receipt_and_inventory(self):
        path = Path(OPTIONS.sdk_receipt)
        data = json.loads(path.read_text())
        self.assertEqual(data.get('status'), 'built')
        self.assertEqual(data.get('execution'), 'not-run')
        self.assertTrue(data.get('sdk'), 'official SDK provenance absent')
        self.assertTrue(data.get('tool_versions'), 'actual compiler versions absent')
        commands = data.get('commands', [])
        self.assertTrue(commands, 'no actual commands')
        for item in commands:
            self.assertEqual(item.get('returncode'), 0, repr(item))
            self.assertTrue(item.get('argv'), repr(item))
        argv = [item['argv'] for item in commands]
        flat = [' '.join(map(str, a)) for a in argv]
        for source in ('check_contract.c', 'epoch_control.c', 'gpu_adapter.cc',
                       'xdomain_gpu_pattern.cu'):
            self.assertTrue(any(source in cmd for cmd in flat), source + ' not compiled')
        self.assertTrue(any('nvcc' in a[0] and ('--ptx' in a or '-ptx' in a)
                            and ('compute_80' in ' '.join(a) or 'sm_80' in ' '.join(a))
                            for a in argv), 'actual architecture/PTX command missing')
        self.assertTrue(any('-lcuda' in a for a in argv), 'Driver API link missing')
        self.assertTrue(any('agent' in cmd and ('.cc' in cmd or '.cpp' in cmd)
                            for cmd in flat), 'production agent not compiled')
        for cmd in flat:
            self.assertFalse(('rpath' in cmd.lower() or 'ld_library_path' in cmd.lower())
                             and 'stubs' in cmd, 'runtime configured for stub')
        names = {Path(p).name for p in data.get('sources', [])}
        self.assertTrue({'check_contract.c', 'epoch_control.c', 'gpu_adapter.cc',
                         'xdomain_gpu_pattern.cu'} <= names, 'source inventory missing')
        artifacts = data.get('artifacts', {})
        for key in ('ptx', 'executable'):
            value = artifacts.get(key)
            self.assertTrue(value, key + ' absent')
            artifact = Path(value)
            if not artifact.is_absolute():
                artifact = path.parent / artifact
            self.assertTrue(artifact.is_file() and artifact.stat().st_size > 0,
                            key + ' missing/empty')



# Independent SPEC regressions. The three original BuilderTest methods above
# remain unchanged and continue to qualify SDK prerequisite refusal.
class RequiredSourcesTest(unittest.TestCase):
    def load_builder(self):
        self.assertTrue(BUILDER.is_file(), 'production builder absent')
        spec = importlib.util.spec_from_file_location('tb_actual_builder_inventory', BUILDER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(getattr(module, 'required_sources', None)),
                        'RED: production required_sources(source_root) API missing')
        return module

    def test_required_inventory_contains_observer_contract(self):
        module = self.load_builder()
        root = Path('/recording-only-source-root/tests/eval/xdomain')
        paths = module.required_sources(root)
        self.assertIsInstance(paths, list)
        self.assertTrue(all(isinstance(p, Path) for p in paths))
        self.assertEqual(len(paths), len(set(paths)), 'duplicate source inventory entry')
        expected = {'check_contract.c', 'epoch_control.c', 'gpu_adapter.cc',
                    'agent_supervisor.cc', 'xdomain_agent.cc', 'xdomain_gpu_pattern.cu',
                    'xdomain_gpu_pattern.h', 'check_contract.h', 'epoch_control.h',
                    'gpu_adapter.h', 'agent_supervisor.h', 'observer_contract.h'}
        self.assertTrue({root / name for name in expected} <= set(paths),
                        'incorrect source_root convention for original local inputs')
        self.assertTrue(expected <= {p.name for p in paths},
                        'actual C observer header missing from required inventory')

    def test_missing_observer_header_is_actual_cli_unavailable(self):
        with tempfile.TemporaryDirectory(prefix='tb-builder-source-') as temp:
            root = Path(temp)
            source = root / 'repo/tests/eval/xdomain'
            source.mkdir(parents=True)
            # Copy actual production files only. No CUDA headers or successful
            # SDK stand-ins are manufactured for this SDK-free preflight test.
            for name in ('build.py', 'check_contract.c', 'epoch_control.c',
                         'gpu_adapter.cc', 'agent_supervisor.cc', 'xdomain_agent.cc',
                         'xdomain_gpu_pattern.cu', 'xdomain_gpu_pattern.h',
                         'check_contract.h', 'epoch_control.h', 'gpu_adapter.h',
                         'agent_supervisor.h'):
                if (HERE / name).is_file():
                    shutil.copyfile(HERE / name, source / name)
            out = root / 'out'
            command = [sys.executable, '-I', str(source / 'build.py'),
                       '--cuda-home', str(root / 'absent-sdk'), '--host-cxx', 'g++',
                       '--arch', 'sm_80', '--out', str(out)]
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, check=False)
            print('+ ' + ' '.join(command), flush=True)
            print(result.stdout, end='', flush=True)
            print('builder returncode=' + str(result.returncode), flush=True)
            self.assertNotEqual(result.returncode, 0)
            data = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(data['status'], 'unavailable')
            self.assertEqual(data['execution'], 'not-run')
            missing = {Path(p).name for p in data.get('missing_sources', [])}
            self.assertIn('observer_contract.h', missing,
                          'RED: actual missing-source qualifier omits observer header')
            self.assertIn('observer_contract.h', {Path(p).name for p in data['sources']})
            self.assertIn('nvcc', data['missing'], 'source qualifier must coexist with SDK absence')

    def test_main_consumes_required_sources_api(self):
        module = self.load_builder()
        with tempfile.TemporaryDirectory(prefix='tb-builder-api-') as temp:
            root = Path(temp)
            marker = root / 'must-be-required-source.h'
            inventory = module.required_sources(HERE) + [marker]
            argv = ['build.py', '--cuda-home', str(root / 'absent-sdk'),
                    '--host-cxx', 'g++', '--arch', 'sm_80', '--out', str(root / 'out')]
            with mock.patch.object(module, 'required_sources', return_value=inventory) as required:
                with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
                    result = module.main()
            self.assertNotEqual(result, 0)
            required.assert_called_once_with(HERE)
            data = json.loads((root / 'out/receipt.json').read_text())
            self.assertEqual(data['status'], 'unavailable')
            self.assertEqual(data['execution'], 'not-run')
            self.assertIn(str(marker), data['sources'])
            self.assertIn(str(marker), data['missing_sources'],
                          'production main bypassed actual required_sources result')


class RequiredSourceReceiptTest(unittest.TestCase):
    def test_actual_sdk_receipt_hashes_observer_contract(self):
        data = json.loads(Path(OPTIONS.sdk_receipt).read_text())
        self.assertEqual(data.get('status'), 'built')
        self.assertEqual(data.get('execution'), 'not-run')
        sources = {Path(p).name: p for p in data.get('sources', [])}
        self.assertIn('observer_contract.h', sources, 'actual receipt source inventory incomplete')
        self.assertIn(sources['observer_contract.h'], data.get('source_sha256', {}),
                      'actual receipt does not cover included C observer header')


# B-QUALITY-1: project ABI inputs are actual repository paths, including the
# transitive binding header and io_uring.h selected by the build include path.
PROJECT_ABI_INPUTS = ('kernel/include/uapi/linux/xdev_ext_mech.h',
                      'kernel/include/uapi/linux/xdev_ext_policy.h',
                      'kernel/include/uapi/linux/xdev_ext_binding.h',
                      'kernel/include/uapi/linux/io_uring.h')


class ProjectABIInventoryTest(unittest.TestCase):
    def load_builder(self):
        spec = importlib.util.spec_from_file_location('tb_actual_builder_abi', BUILDER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_inventory_preserves_actual_repository_abi_paths(self):
        source = Path('/recording-only-repo/tests/eval/xdomain')
        expected = {source.parents[2] / name for name in PROJECT_ABI_INPUTS}
        paths = self.load_builder().required_sources(source)
        self.assertTrue(expected <= set(paths),
                        'RED: required inventory omits actual project ABI paths: ' +
                        repr(sorted(map(str, expected - set(paths)))))
        self.assertFalse({source / p.name for p in expected} & set(paths),
                         'project ABI inputs were collapsed to local basenames')

    def test_missing_project_abi_headers_aggregate_in_actual_cli_preflight(self):
        with tempfile.TemporaryDirectory(prefix='tb-builder-abi-') as temp:
            root = Path(temp)
            source = root / 'repo/tests/eval/xdomain'
            source.mkdir(parents=True)
            # Real local production inputs only. Deliberately omit all four
            # actual repo ABI paths, but provide same-basename local decoys.
            # No SDK, compiler success substitute, PTX, or executable is made.
            for path in self.load_builder().required_sources(HERE):
                if path.parent == HERE and path.is_file():
                    shutil.copyfile(path, source / path.name)
            shutil.copyfile(BUILDER, source / 'build.py')
            expected = {source.parents[2] / name for name in PROJECT_ABI_INPUTS}
            for name in PROJECT_ABI_INPUTS:
                actual = HERE.parents[2] / name
                self.assertTrue(actual.is_file(), 'actual project ABI input absent: ' + str(actual))
                shutil.copyfile(actual, source / actual.name)
            out = root / 'out'
            command = [sys.executable, '-I', str(source / 'build.py'),
                       '--cuda-home', str(root / 'absent-sdk'), '--host-cxx', 'g++',
                       '--arch', 'sm_80', '--out', str(out)]
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, check=False)
            print('+ ' + ' '.join(command), flush=True)
            print(result.stdout, end='', flush=True)
            print('builder returncode=' + str(result.returncode), flush=True)
            self.assertEqual(result.returncode, 2)
            data = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(data['status'], 'unavailable')
            self.assertEqual(data['execution'], 'not-run')
            self.assertIn('nvcc', data['missing'])
            self.assertIn('cuda.h', data['missing'])
            self.assertIn('libcuda', data['missing'])
            self.assertTrue(expected <= {Path(p) for p in data.get('missing_sources', [])},
                            'RED: actual preflight omits absent repository ABI headers')
            self.assertTrue(expected <= {Path(p) for p in data['sources']},
                            'receipt omitted actual repository paths')
            self.assertFalse(any('-c' in item['argv'] or '--ptx' in item['argv']
                                 for item in data['commands']),
                             'missing inputs reached compilation')
            self.assertIsNone(data['artifacts']['ptx'])
            self.assertIsNone(data['artifacts']['executable'])


class ProjectABIReceiptTest(unittest.TestCase):
    def test_actual_sdk_receipt_hashes_every_actual_project_input(self):
        # Only invoked against a genuine root-supplied SDK build receipt.
        data = json.loads(Path(OPTIONS.sdk_receipt).read_text())
        self.assertEqual(data.get('status'), 'built')
        self.assertEqual(data.get('execution'), 'not-run')
        sources = {Path(p) for p in data.get('sources', [])}
        expected = {HERE.parents[2] / name for name in PROJECT_ABI_INPUTS}
        self.assertTrue(expected <= sources, 'actual receipt omitted repository ABI paths')
        hashes = data.get('source_sha256', {})
        for source in sources:
            self.assertTrue(source.is_file(), 'actual inventoried input absent: ' + str(source))
            self.assertEqual(hashes.get(str(source)),
                             hashlib.sha256(source.read_bytes()).hexdigest(),
                             'actual path/hash missing or stale: ' + str(source))


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cuda-home', default='')
    parser.add_argument('--sdk-receipt', default='')
    OPTIONS = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BuilderTest)
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(RequiredSourcesTest))
    suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(ProjectABIInventoryTest))
    if OPTIONS.cuda_home:
        suite.addTest(OfficialCompilerFailureTest('test_actual_compiler_nonzero_is_failed'))
    if OPTIONS.sdk_receipt:
        suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(OfficialReceiptTest))
        suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(RequiredSourceReceiptTest))
        suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(ProjectABIReceiptTest))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not OPTIONS.cuda_home or not OPTIONS.sdk_receipt:
        print('Official SDK compile/link receipt and compiler-failure coverage: '
              'not-run unless explicitly supplied; no GPU execution')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
