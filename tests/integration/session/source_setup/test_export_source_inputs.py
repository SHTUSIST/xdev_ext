#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reject unqualified actual-core compiler inputs before the compiler boundary.

This is a separate source-provenance cohort. It never changes the existing
old-ticket ledger, source-admission tests, or runtime evidence oracles.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('export_input_fixture', HERE / 'fixture.py')
SETUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SETUP)

# Independently named review obligations. GCC must also demonstrate that each
# is an actual dependency of the successful actual-core export, below.
HEADERS = (
    'kernel/include/linux/xdev_ext_family_core.h',
    'kernel/include/linux/xdev_ext_compfam_core.h',
    'kernel/include/linux/xdev_ext_binding_ctx.h',
    'kernel/include/uapi/linux/xdev_ext_binding.h',
)
EXPORTER = 'tests/benchmarks/mechanism_variants/export_old_ticket.py'
MUTATIONS = ('changed-bytes', 'missing', 'symlink', 'canonical-inode-alias')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def is_elf(path):
    with path.open('rb') as stream:
        return stream.read(4) == b'\x7fELF'


class ExportSourceInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = Path(os.environ.get('XDEV_EXPORT_INPUT_ARTIFACTS',
                                  SETUP.PRODUCT / 'build/export-input-tests'))
        base.mkdir(parents=True, exist_ok=True)
        cls.artifacts = Path(tempfile.mkdtemp(prefix='export-inputs-', dir=base))
        cls.source = SETUP.Fixture(actual_core=True)
        cls.addClassCleanup(cls.source.cleanup)
        cls.cc = shutil.which('gcc')
        if cls.cc is None:
            raise RuntimeError('actual GCC is required; no source-only positive substitute')
        gate, _ = cls.source.gate(e2=True)
        (cls.artifacts / 'setup.stdout').write_text(gate.stdout)
        (cls.artifacts / 'setup.stderr').write_text(gate.stderr)
        if gate.returncode:
            raise RuntimeError('checked actual-core source fixture failed: ' + gate.stderr)
        # Copy opaque candidate bytes before execution. Never inspect exporter
        # implementation or derive an expectation from its source selection.
        shutil.copytree(cls.source.repo, cls.artifacts / 'frozen-canonical',
                        ignore=shutil.ignore_patterns('build'))
        (cls.artifacts / 'test-source.py').write_bytes(Path(__file__).read_bytes())
        cls.authority = {}
        for logical in HEADERS:
            original = cls.source.repo / cls.source.by_logical[logical]
            copied = cls.source.view / logical
            if (not copied.is_file() or copied.is_symlink()
                    or copied.read_bytes() != original.read_bytes()
                    or os.path.samefile(copied, original)):
                raise RuntimeError('invalid positive copied-header fixture: ' + logical)
            cls.authority[logical] = original.read_bytes()
        record_json(cls.artifacts / 'inputs.json', {
            'product': str(SETUP.PRODUCT),
            'private_canonical_revision': cls.source.sha,
            'exporter_sha256': digest(cls.source.repo / EXPORTER),
            'test_sha256': digest(Path(__file__)),
            'headers': {logical: hashlib.sha256(data).hexdigest()
                        for logical, data in cls.authority.items()},
        })
        cls.compiler = cls.artifacts / 'observe-cc'
        cls.compiler.write_text('#!' + sys.executable + '\n' + '''import json,os,pathlib,subprocess,sys
args=sys.argv[1:]
folder=pathlib.Path(os.environ['EXPORT_INPUT_CASE'])
with (folder/'compiler-argv.jsonl').open('a') as log:
    log.write(json.dumps(args)+'\\n')
compiles=any(arg.endswith(('.c','.cc','.cpp')) for arg in args)
if compiles:
    (folder/'compiler-entered').write_text('actual compilation boundary reached\\n')
    if os.environ.get('EXPORT_INPUT_REFUSE_COMPILE')=='1':
        print('independent compiler boundary sentinel',file=sys.stderr)
        sys.exit(47)
    args=['-MD','-MF',str(folder/'actual-dependencies.d'),*args]
sys.exit(subprocess.call([os.environ['EXPORT_INPUT_REAL_CC'],*args]))
''')
        cls.compiler.chmod(0o700)
        cls.positive_dir, cls.positive = cls.run_export('positive-actual-export', False)
        if cls.positive.returncode:
            raise RuntimeError('positive actual-core export failed before negatives: '
                               + cls.positive.stdout + cls.positive.stderr)
        if not (cls.positive_dir / 'compiler-entered').is_file():
            raise RuntimeError('positive did not traverse actual GCC compilation')
        cls.capture = cls.positive_dir / 'capture'
        binary = cls.capture / 'old-ticket-fixture'
        if binary.read_bytes()[:4] != b'\x7fELF':
            raise RuntimeError('positive did not retain an actual compiled ELF fixture')
        negative = json.loads((cls.capture / 'old_ticket.json').read_text())
        if (negative.get('evidence_kind') != 'actual-core-host-fixture'
                or negative['old_ticket'] == negative['current_ticket']):
            raise RuntimeError('positive did not execute the actual-core old-ticket oracle')
        # GCC dependency output is an independent observation of the actual
        # include chain, not an exporter-generated source manifest.
        dependencies = (cls.positive_dir / 'actual-dependencies.d').read_text()
        dependency_words = shlex.split(dependencies.replace('\\\n', ' '))
        cls.dependencies = {str(Path(word).resolve()) for word in dependency_words[1:]}
        for logical in HEADERS:
            if str((cls.source.view / logical).resolve()) not in cls.dependencies:
                raise RuntimeError('named header was not actually compiled: ' + logical)
        record_json(cls.artifacts / 'actual-compiled-inputs.json', sorted(cls.dependencies))

    @classmethod
    def run_export(cls, name, refuse_compile):
        folder = cls.artifacts / name
        folder.mkdir()
        argv = [sys.executable, '-B', str(cls.source.repo / EXPORTER),
                str(cls.source.view / 'kernel'), str(folder / 'capture'),
                '--cc', str(cls.compiler)]
        result = subprocess.run(argv, env={**os.environ,
            'PYTHONDONTWRITEBYTECODE': '1', 'EXPORT_INPUT_CASE': str(folder),
            'EXPORT_INPUT_REAL_CC': cls.cc,
            'EXPORT_INPUT_REFUSE_COMPILE': str(int(refuse_compile)),
        }, capture_output=True, text=True, timeout=90)
        (folder / 'stdout').write_text(result.stdout)
        (folder / 'stderr').write_text(result.stderr)
        record_json(folder / 'command.json', {'argv': argv, 'exit': result.returncode})
        return folder, result

    def test_00_real_export_compiles_all_four_headers(self):
        self.assertEqual(self.positive.returncode, 0)
        self.assertEqual((self.capture / 'old-ticket-fixture').read_bytes()[:4], b'\x7fELF')
        for logical in HEADERS:
            self.assertIn(str((self.source.view / logical).resolve()), self.dependencies)

    def assert_header_refused(self, logical):
        copied = self.source.view / logical
        original = self.source.repo / self.source.by_logical[logical]
        clean = self.authority[logical]
        for mutation in MUTATIONS:
            with self.subTest(header=logical, mutation=mutation):
                try:
                    copied.unlink()
                    if mutation == 'changed-bytes':
                        # Valid inert C; a syntax error cannot certify rejection.
                        copied.write_bytes(clean + b'\n/* independent changed copied input */\n')
                    elif mutation == 'symlink':
                        copied.symlink_to(original)
                    elif mutation == 'canonical-inode-alias':
                        os.link(original, copied)
                    folder, result = self.run_export(Path(logical).name + '-' + mutation, True)
                    self.assertNotEqual(result.returncode, 0,
                                        'export accepted unqualified copied compiler input')
                    self.assertFalse((folder / 'compiler-entered').exists(),
                                     'unqualified input reached compilation; compiler failure is not source refusal')
                    executables = [p for p in folder.rglob('*') if p.is_file()
                                   and p.name != 'compiler-entered'
                                   and is_elf(p)]
                    self.assertEqual(executables, [],
                                     'export created a binary before copied-source qualification')
                finally:
                    if copied.exists() or copied.is_symlink():
                        copied.unlink()
                    copied.write_bytes(clean)
                    self.assertEqual(original.read_bytes(), clean,
                                     'test mutation changed canonical authority bytes')

    def test_family_core_copy_is_qualified_before_compile(self):
        self.assert_header_refused(HEADERS[0])

    def test_compfam_core_copy_is_qualified_before_compile(self):
        self.assert_header_refused(HEADERS[1])

    def test_binding_context_copy_is_qualified_before_compile(self):
        self.assert_header_refused(HEADERS[2])

    def test_uapi_binding_copy_is_qualified_before_compile(self):
        self.assert_header_refused(HEADERS[3])


if __name__ == '__main__':
    unittest.main(verbosity=2)
