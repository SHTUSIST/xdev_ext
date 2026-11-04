"""V3 minimal qualification and public activation; synthetic ordinary evidence.

Static ELF fixtures are never executed. Git responses come from harmless Python
children at the subprocess boundary. The only other checker child is readelf.
"""
import argparse
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import copy
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_executor import HERE, cell, shape

REVISION = 'd01447808d10af78011e9203d53796a15a032a03'
SUBMODULE = '58c382a8e3d7081364d2f5c62e7f429f0412743b'
REAL_POPEN = subprocess.Popen


def dump(path, value):
    path.write_text(json.dumps(value) + '\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class QualificationCorpus:
    """Evidence generator independent of the qualifier; no executable algorithm."""
    def __init__(self, root):
        self.root = root
        self.source = root / 'source'; (self.source / 'extern' / 'pybind11').mkdir(parents=True)
        self.libs = root / 'libs'; self.libs.mkdir()
        cfile = root / 'fixture.c'; cfile.write_text('int fixture(void) { return 7; }\n')
        for name in ('libcuda.so.1', 'libcudart.so.12', 'liburing.so.2'):
            subprocess.run(['gcc', '-shared', '-fPIC', str(cfile), '-Wl,-soname,' + name,
                            '-o', str(self.libs / name)], check=True, capture_output=True)
        main = root / 'main.c'; main.write_text('int main(void) { return 0; }\n')
        self.binary = root / 'tebench-static-fixture'
        subprocess.run(['gcc', str(main), '-L' + str(self.libs), '-Wl,--no-as-needed',
                        '-l:libcuda.so.1', '-l:libcudart.so.12', '-l:liburing.so.2',
                        '-Wl,-rpath,' + str(self.libs), '-o', str(self.binary)],
                       check=True, capture_output=True)
        # Readelf is a static file reader; neither executable nor loader is run.
        dynamic = subprocess.run(['/usr/bin/readelf', '--wide', '--file-header',
                                 '--program-headers', '--dynamic', str(self.binary)],
                                 check=True, capture_output=True, text=True).stdout
        needed_lines = [line.strip() for line in dynamic.splitlines() if '(NEEDED)' in line]
        names = [line.split('[')[1].split(']')[0] for line in needed_lines]
        self.evidence = root / 'prior-evidence.log'
        self.evidence.write_text('synthetic fixture declaration, no hardware observation\n' + dynamic)
        self.input = root / 'input'; self.input.write_bytes(b'\0' * 1048576)
        self.rig = dict(schema_version=1, physical_run_authorized=True, execution='physical',
            kernel_release=os.uname().release, kernel_source_revision='fixture-kernel-source',
            nvidia_driver_version='fixture-driver', cuda_version='fixture-cuda',
            gpu_uuid='fixture-gpu', gpu_pci_bdf='0000:00:00.0', gpu_model='fixture-model',
            cpuset=str(min(os.sched_getaffinity(0))), numa_node=0,
            cpu_budget_description='fixture declared expanded all-thread RPC/poll/IRQ budget',
            source_revision=REVISION, source_tree_verified=True,
            build_receipt={'USE_TENT': True, 'USE_CUDA': True, 'liburing': True},
            input_file=str(self.input), input_initialized=True, filesystem='fixture-fs',
            mount_options=['rw'], namespace_identity='fixture-namespace', namespace_capacity_bytes=1048576)
        facts = dict(input_file=str(self.input), target_offset=0, target_bytes=1048576,
                     evidence=[str(self.evidence)])
        for key in ('input_validation_receipt', 'file_extent_receipt', 'exclusive_window_receipt'):
            self.rig[key] = dict(facts)
        self.build = dict(source={'exit': 0, 'stdout': REVISION + '\n', 'stderr': ''},
            source_worktree={'exit': 0, 'stdout': '', 'stderr': ''},
            submodules={'exit': 0, 'stdout': ' ' + SUBMODULE + ' extern/pybind11 (fixture)\n', 'stderr': ''},
            source_unchanged=True, target='/relocated-old-host/tebench',
            bytes=self.binary.stat().st_size, sha256=digest(self.binary),
            compiler={'exit': 0, 'stdout': 'gcc fixture compiler identity', 'stderr': ''},
            cuda_compiler={'exit': 0, 'stdout': 'synthetic SDK identity', 'stderr': ''},
            selected_cmake_cache=['USE_TENT:BOOL=ON', 'USE_CUDA:BOOL=ON'],
            needed=needed_lines, elf_read_exit=0, benchmark_executed=False, physical_qualification=False)
        entries = []
        libdirs = [str(self.libs)]
        for name in names:
            path = self.libs / name
            if not path.exists():
                # GCC's ordinary linked libc file. Never run ld-linux/ldd.
                path = Path('/lib/x86_64-linux-gnu') / name
                path = path.resolve(strict=True)
                if str(path.parent) not in libdirs:
                    libdirs.append(str(path.parent))
            entries.append(dict(needed=name, path=str(path), sha256=digest(path)))
        # Explicit retained resolver declarations are synthetic fixture evidence.
        # DT_NEEDED alone never declares which ordinary current path was resolved.
        with self.evidence.open('a') as stream:
            stream.write('\nSynthetic retained direct-library resolution (no loader executed):\n')
            for entry in entries:
                stream.write(entry['needed'] + ' => ' + entry['path'] + '\n')
        self.runtime = dict(schema_version=1, source_revision=REVISION,
            tebench_sha256=digest(self.binary), profile='native', endpoint='local',
            kernel_release=os.uname().release, libraries=entries, library_search_dirs=libdirs,
            evidence=[str(self.evidence)], gpu_uuid='fixture-gpu', gpu_pci_bdf='0000:00:00.0',
            nvidia_driver_version='fixture-driver', cuda_version='fixture-cuda')
        self.correctness = dict(status='passed', source_revision=REVISION, profile='native',
            experiment='e4', arm='iouring-default', shape=shape(), rig_identity=copy.deepcopy(self.rig),
            evidence=[str(self.evidence)], scope='separate-upstream-roundtrip')
        self.budget = dict(source_revision=REVISION, profile='native', endpoint='local',
            cpuset=self.rig['cpuset'], cpu_budget_description=self.rig['cpu_budget_description'],
            evidence=[str(self.evidence)])
        self.qualification = dict(schema_version=1, build_receipt='build.json',
            runtime_receipt='runtime.json', correctness_receipt='correctness.json',
            budget_receipt='budget.json')
        self.path = root / 'qualification.json'
        self.args = argparse.Namespace(source_root=self.source, tebench=self.binary,
            rig=root / 'rig.json', shape=root / 'shape.json',
            experiment='e4', mode='run', profile='native',
            cell_id=cell()['cell_id'], endpoint='local', qualification=self.path,
            output_dir=root / 'output')
        self.git_fault = None
        self.tool_fault = None
        self.tool_calls = []
        self.save()

    def save(self):
        for name in ('build', 'runtime', 'correctness', 'budget', 'qualification', 'rig'):
            dump(self.root / (name + '.json'), getattr(self, name))
        dump(self.root / 'shape.json', shape())

    def tools(self, argv, *args, **kwargs):
        """Only external fixed Git output is substituted; readelf stays real."""
        tokens = list(map(str, argv))
        self.tool_calls.append((tokens, copy.copy(kwargs)))
        if Path(tokens[0]).name == 'git':
            if kwargs.get('shell'):
                raise AssertionError('checker may not use shell')
            if '-c' not in tokens or 'core.fsmonitor=false' not in tokens:
                raise AssertionError('read-only Git disables fsmonitor')
            if kwargs.get('env', {}).get('GIT_OPTIONAL_LOCKS') != '0':
                raise AssertionError('read-only Git disables optional locks')
            allowed = [
                ['-c', 'core.fsmonitor=false', '-C', str(self.source), 'rev-parse', 'HEAD'],
                ['-c', 'core.fsmonitor=false', '-C', str(self.source), 'status', '--porcelain', '--untracked-files=normal'],
                ['-c', 'core.fsmonitor=false', '-C', str(self.source), 'ls-tree', 'HEAD', 'extern/pybind11'],
                ['-c', 'core.fsmonitor=false', '-C', str(self.source / 'extern' / 'pybind11'), 'rev-parse', 'HEAD'],
            ]
            if tokens[1:] not in allowed:
                raise AssertionError('non-fixed Git query: ' + repr(tokens))
            if 'status' in tokens:
                if '--porcelain' not in tokens or '--untracked-files=normal' not in tokens:
                    raise AssertionError('source dirty/untracked check omitted')
                output = ' M changed.cc\n' if self.git_fault == 'dirty' else ''
            elif 'ls-tree' in tokens:
                output = '160000 commit ' + SUBMODULE + '\textern/pybind11\n'
            elif 'rev-parse' in tokens:
                is_submodule = str(self.source / 'extern' / 'pybind11') in tokens
                output = (SUBMODULE if is_submodule else REVISION) + '\n'
                if self.git_fault == ('submodule' if is_submodule else 'revision'):
                    output = '0' * 40 + '\n'
            else:
                raise AssertionError('unapproved Git query: ' + repr(tokens))
            code = 3 if self.git_fault == 'error' else 0
            # Real harmless child exercises bounded collection for tool outputs.
            replacement = [sys.executable, '-c',
                           'import sys;sys.stdout.write(sys.argv[1]);sys.exit(int(sys.argv[2]))',
                           output, str(code)]
            return REAL_POPEN(replacement, *args, **kwargs)
        if tokens[0] != '/usr/bin/readelf':
            raise AssertionError('unexpected checker subprocess: ' + repr(tokens))
        for flag in ('--wide', '--file-header', '--program-headers', '--dynamic'):
            if flag not in tokens:
                raise AssertionError('incomplete fixed readelf query')
        if self.tool_fault:
            code = 3 if self.tool_fault == 'nonzero' else 0
            return REAL_POPEN([sys.executable, '-c', 'import sys;print(\"malformed ELF output\");sys.exit(int(sys.argv[1]))', str(code)], *args, **kwargs)
        return REAL_POPEN(argv, *args, **kwargs)


class QualificationAdmission(unittest.TestCase):
    def setUp(self):
        try:
            self.qual = importlib.import_module('qualification')
        except ModuleNotFoundError as error:
            raise RuntimeError('NEW_COMPONENT_SETUP: qualification is absent; no semantic RED') from error
        self.temp = tempfile.TemporaryDirectory(prefix='mooncake-qualification-')
        self.addCleanup(self.temp.cleanup)
        self.corpus = QualificationCorpus(Path(self.temp.name))

    def validate(self, save=True):
        if save:
            self.corpus.save()
        request = cell(); request['rig_identity'] = copy.deepcopy(self.corpus.rig)
        with mock.patch('subprocess.Popen', side_effect=self.corpus.tools):
            return self.qual.validate_qualification(self.corpus.path, self.corpus.args,
                                                   shape(), self.corpus.rig, request)

    def assert_refused(self):
        try:
            verdict = self.validate()
        except (ValueError, OSError):
            return
        self.assertFalse(verdict['qualified'])

    def test_exact_small_receipt_corpus_qualifies_without_auth_manifest_or_cache(self):
        verdict = self.validate()
        self.assertTrue(verdict['qualified'])
        self.assertTrue(verdict['mechanically_checked'])
        self.assertTrue(verdict['evidence_declared'])
        context = self.qual.context_from_qualification(verdict)
        self.assertEqual(context.profile, 'native')
        self.assertEqual(context.kind, 'physical')
        self.assertFalse(any('loader' in Path(call[0][0]).name for call in self.corpus.tool_calls))
        self.assertFalse((self.corpus.root / 'validation-cache.json').exists())

    def test_empty_duplicate_unknown_schema_and_oversized_json_refuse(self):
        raw_cases = [b'', b'{}', b'[]', b'{"schema_version":true}',
                     b'{"schema_version":1,"schema_version":1}',
                     b'{"schema_version":1,"build_receipt":"build.json", "runtime_receipt":"runtime.json",'
                     b'"correctness_receipt":"correctness.json","budget_receipt":"budget.json","unknown":0}',
                     b' ' * (1024 * 1024 + 1)]
        for index, raw in enumerate(raw_cases):
            with self.subTest(corruption=index):
                self.corpus.path.write_bytes(raw)
                try:
                    verdict = self.validate(save=False)
                except (ValueError, OSError):
                    continue
                self.assertFalse(verdict['qualified'])

    def test_static_tool_nonzero_or_malformed_output_never_qualifies(self):
        for fault in ('nonzero', 'malformed'):
            with self.subTest(fault=fault):
                self.corpus.tool_fault = fault
                self.assert_refused()

    def test_each_fixed_source_git_fault_refuses(self):
        for fault in ('dirty', 'revision', 'submodule', 'error'):
            with self.subTest(fault=fault):
                self.corpus.git_fault = fault
                self.assert_refused()

    def test_unknown_qualification_key_never_becomes_authorization(self):
        self.corpus.qualification['execution_kind'] = 'physical'
        self.assert_refused()

    def test_missing_nonregular_and_symlink_receipts_refuse(self):
        for value in ('absent.json', '.', 'alias.json'):
            with self.subTest(path=value):
                link = self.corpus.root / 'alias.json'
                if not link.exists():
                    link.symlink_to(self.corpus.root / 'build.json')
                self.corpus.qualification['build_receipt'] = value
                self.assert_refused()

    def test_source_binary_runtime_kernel_profile_and_correctness_mismatches_refuse(self):
        cases = [('build', 'source_unchanged', False),
                 ('build', 'sha256', '0' * 64), ('build', 'bytes', 1),
                 ('runtime', 'source_revision', '0' * 40),
                 ('runtime', 'tebench_sha256', '0' * 64),
                 ('runtime', 'kernel_release', 'wrong-kernel'),
                 ('runtime', 'profile', 'xdev_ext'), ('runtime', 'endpoint', 'destination'),
                 ('runtime', 'gpu_uuid', 'wrong-gpu'),
                 ('correctness', 'status', 'failed'), ('correctness', 'profile', 'xdev_ext'),
                 ('correctness', 'experiment', 'e7'), ('correctness', 'arm', 'iouring-pinned'),
                 ('correctness', 'scope', 'complete-random-read-oracle'),
                 ('budget', 'cpuset', '999999'), ('budget', 'evidence', [])]
        for object_name, key, value in cases:
            with self.subTest(object=object_name, key=key):
                obj = getattr(self.corpus, object_name); old = obj.get(key)
                obj[key] = value
                try:
                    self.assert_refused()
                finally:
                    obj[key] = old

    def test_needed_search_order_key_hash_and_stubs_are_checked(self):
        saved = copy.deepcopy(self.corpus.runtime)
        self.corpus.runtime['libraries'].pop()
        self.assert_refused()
        self.corpus.runtime = copy.deepcopy(saved)
        self.corpus.runtime['libraries'].append(copy.deepcopy(saved['libraries'][0]))
        self.assert_refused()
        self.corpus.runtime = copy.deepcopy(saved)
        self.corpus.runtime['libraries'][0]['sha256'] = '0' * 64
        self.assert_refused()
        self.corpus.runtime = copy.deepcopy(saved)
        stubs = self.corpus.root / 'stubs'; stubs.mkdir()
        self.corpus.runtime['library_search_dirs'].insert(0, str(stubs))
        self.assert_refused()
        self.corpus.runtime = copy.deepcopy(saved)
        shadow = self.corpus.root / 'shadow'; shadow.mkdir()
        shutil.copyfile(self.corpus.libs / 'libcuda.so.1', shadow / 'libcuda.so.1')
        self.corpus.runtime['library_search_dirs'].insert(0, str(shadow))
        self.assert_refused()

    def test_missing_input_small_input_and_declared_range_mismatch_refuse(self):
        self.corpus.input.write_bytes(b'\0' * 4096)
        self.assert_refused()
        self.corpus.input.write_bytes(b'\0' * 1048576)
        self.corpus.rig['file_extent_receipt']['target_offset'] = 4096
        self.assert_refused()
        self.corpus.rig['file_extent_receipt']['target_offset'] = 0
        alias = self.corpus.root / 'input-alias'; alias.symlink_to(self.corpus.input)
        self.corpus.rig['input_file'] = str(alias)
        self.assert_refused()
        self.corpus.rig['input_file'] = str(self.corpus.input)
        self.corpus.input.unlink()
        self.assert_refused()

    def test_source_submodule_queries_do_not_run_benchmark_or_loader(self):
        self.assertTrue(self.validate()['qualified'])
        calls = [tokens for tokens, kwargs in self.corpus.tool_calls]
        self.assertTrue(any('ls-tree' in tokens for tokens in calls))
        self.assertTrue(any(str(self.corpus.source / 'extern' / 'pybind11') in tokens for tokens in calls))
        self.assertTrue(all(Path(tokens[0]).name == 'git' or tokens[0] == '/usr/bin/readelf'
                            for tokens in calls))


class PublicCliReachability(unittest.TestCase):
    setUp = QualificationAdmission.setUp
    # This control reaches the real public run branch; it does not start a physical ELF.
    def cli(self, mode='run', corrupt=False):
        spec = importlib.util.spec_from_file_location('mooncake_public_cli_under_test', HERE / 'run.py')
        run = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = run
        spec.loader.exec_module(run)
        if corrupt:
            self.corpus.runtime['profile'] = 'xdev_ext'
        self.corpus.save()
        argv = ['--mode', mode, '--experiment', 'e4', '--shape', str(self.corpus.root / 'shape.json'),
                '--rig', str(self.corpus.root / 'rig.json'), '--source-root', str(self.corpus.source),
                '--tebench', str(self.corpus.binary), '--profile', 'native',
                '--cell-id', cell()['cell_id'], '--qualification', str(self.corpus.path),
                '--output-dir', str(self.corpus.root / 'cli-output')]
        reached = []
        class FixtureLaunchObserved(Exception):
            pass
        def observer(command, selected, context, output_dir, timeout_seconds):
            reached.append((command, selected, context))
            raise FixtureLaunchObserved('physical launcher boundary observed; never spawned')
        with ExitStack() as stack:
            stack.enter_context(mock.patch('subprocess.Popen', side_effect=self.corpus.tools))
            stack.enter_context(mock.patch.object(run, 'execute_cell', side_effect=observer, create=True))
            stack.enter_context(mock.patch.object(importlib.import_module('executor'), 'execute_cell',
                                                   side_effect=observer))
            stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            try:
                code = run.main(argv)
            except FixtureLaunchObserved:
                code = None
        return code, reached

    def test_public_run_complete_minimal_evidence_reaches_actual_launcher(self):
        _, reached = self.cli()
        self.assertEqual(len(reached), 1)
        command, selected, context = reached[0]
        self.assertEqual(selected['cell_id'], 'native-iouring-default-b4096-q8-r0')
        self.assertEqual(selected['profile'], 'native')
        self.assertEqual(context.kind, 'physical')
        self.assertTrue(any(str(self.corpus.binary) == arg for arg in command['argv']))
        # Observer stopped execution before any physical result was written.
        for receipt in (self.corpus.root / 'cli-output').rglob('receipt.json'):
            result = json.loads(receipt.read_text())
            self.assertNotEqual(result.get('status'), 'completed')

    def test_public_run_mismatched_evidence_refuses_before_launcher(self):
        code, reached = self.cli(corrupt=True)
        self.assertEqual(code, 4)
        self.assertEqual(reached, [])

    def test_qualified_check_setup_is_nonexecuting(self):
        code, reached = self.cli(mode='check-setup')
        self.assertEqual(code, 0)
        self.assertEqual(reached, [])
        summary = json.loads((self.corpus.root / 'cli-output' / 'summary.json').read_text())
        self.assertEqual(summary['execution'], 'none')
        self.assertEqual(summary['performance_claim'], 'none')


if __name__ == '__main__':
    unittest.main()
