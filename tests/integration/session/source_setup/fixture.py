#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private source-admission fixtures; never a device or guest model."""
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

sys.dont_write_bytecode = True
PRODUCT = Path(os.environ.get('XDEV_SETUP_PRODUCT', Path(__file__).resolve().parents[4])).resolve()
ARTIFACTS = Path(os.environ.get('XDEV_SETUP_ARTIFACTS', PRODUCT / 'build/source-setup-tests'))
HARNESS = 'tests/integration/session/native/xdev_ext_mech_zc_kvm.sh'
RUNNER = 'tests/benchmarks/dmabuf_lifecycle/run.py'
HEADER = 'src/core/io_uring/xdev_ext_mech_lifecycle.h'
LOGICAL_HEADER = 'kernel/io_uring/xdev_ext_mech_lifecycle.h'
E2 = 'tests/eval/mechanism_variants'
FENCE = 'tests/eval/dmabuf_lifecycle'


def command(argv, cwd=None, env=None):
    return subprocess.run([str(a) for a in argv], cwd=cwd, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', **(env or {})}, text=True, capture_output=True, timeout=40)


def checked(argv, cwd=None, env=None):
    result = command(argv, cwd, env)
    if result.returncode:
        raise RuntimeError(f'fixture command failed: {argv!r}\n{result.stdout}\n{result.stderr}')
    return result.stdout.strip()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())


def write_json(path, value):
    write(path, json.dumps(value, indent=2) + '\n')


def extract_shell_function(path, name):
    # Preserve every byte of the real function, including heredoc Python and argv.
    text = path.read_text()
    start = text.index(name + '() {\n')
    end = text.index('\n}\n', start) + 3
    return text[start:end]


def import_file(path):
    name = 'slice_a_' + hashlib.sha256(str(path).encode()).hexdigest()
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Fixture:
    def __init__(self, actual_core=False):
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='source-case-', dir=ARTIFACTS)
        self.root = Path(self.temporary.name)
        self.repo = self.root / 'canonical'
        self.repo.mkdir()
        self.upstream = self.root / 'tiny-upstream'
        self.upstream.mkdir()
        self.init_git(self.upstream)
        for name, text in {'Makefile': '# private source-only upstream\n', 'Kconfig': '# no build\n', 'scripts/Makefile.build': '# no build\n', 'include/linux/types.h': '/* no kernel build */\n'}.items():
            write(self.upstream / name, text)
        self.upstream_sha = self.commit(self.upstream)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        checked(['git', 'clone', '--bare', '--quiet', self.upstream, self.cache / 'linux.git'])
        self.init_git(self.repo)
        actual = json.loads((PRODUCT / 'source-layout.json').read_text())
        self.entries = []
        self.by_logical = {}
        for entry in actual['files']:
            source = entry['source']
            logical = ('kernel/' if entry.get('component') == 'linux' else 'gpu/') + entry['native_path'] if 'component' in entry else entry['logical_path']
            # Real consumed support/build dependencies. Existing tests are not read.
            selected = (source in {'tools/layout.py', 'tools/build/prepare_sources.py', HARNESS, RUNNER, HEADER, 'src/core/include/linux/xdev_ext_mech.h'}
                        or source.startswith('tests/benchmarks/dmabuf_lifecycle/') and Path(source).name in {'Kbuild', 'Makefile', 'lifecycle_core.h', 'lifecycle_bench.c'}
                        or source.startswith('tests/benchmarks/mechanism_variants/') and Path(source).name in {'Makefile', 'kvm_mode.sh', 'mv_ctl.c', 'mv_sink.c', 'mv_create_capture.h', 'mv_umem_guard.h', 'mv_policy_capture.h', 'bpf_body.c', 'nvme_reverse.bpf.c', 'nvme_gray.bpf.c'}
                        or source in {'tests/integration/session/native/xdev_ext_fence_guest.sh', 'tests/integration/session/native/xdev_ext_fence_validate.py', 'tests/integration/session/native/xdev_ext_mech_zc_debug.py'}
                        or logical.startswith('kernel/tools/xdev_ext_mech/lib/')
                        or logical.startswith('kernel/tools/include/')
                        or logical in {'kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c', 'kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h', 'kernel/tools/xdev_ext_xsk_shared.c', 'kernel/tools/xdev_ext_xsk_steer.c', 'kernel/tools/xdev_ext_xsk_redirect.c', 'kernel/tools/xdev_ext_gpu_identity.c', 'kernel/include/uapi/linux/xdev_ext_mech.h', 'kernel/include/uapi/linux/io_uring.h'})
            if actual_core:
                selected = (selected or source == 'tests/compute/transform_source.py' or source.startswith((
                    'src/core/', 'src/network/net/xdp/',
                    'tests/benchmarks/mechanism_variants/',
                    'tests/integration/lifecycle/',
                    'tests/integration/session/native/',
                )) or logical.startswith((
                    'kernel/io_uring/', 'kernel/include/',
                    'kernel/tools/testing/selftests/xdev_ext_mech/fanout_scheduler/',
                    'kernel/tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/',
                )) or logical == 'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c')
            if selected:
                self.entries.append(entry)
                self.by_logical[logical] = source
                write(self.repo / source, (PRODUCT / source).read_bytes())
        # Literal harmless inputs for membership/hash assertions, never executed.
        synthetic = {
            'kernel/net/xdp/xsk_xdev_ext_mech_zc_core.h': 'src/network/net/xdp/xsk_xdev_ext_mech_zc_core.h',
            'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py': 'tests/integration/session/native/xdev_ext_mech_zc_wire.py',
            'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_validate.py': 'tests/integration/session/native/xdev_ext_mech_zc_validate.py',
            'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py': 'tests/integration/session/native/xdev_ext_mech_zc_debug.py',
            'kernel/io_uring/xdev_ext_mech.c': 'src/core/io_uring/xdev_ext_mech.c',
            'kernel/io_uring/extra_admission_input.h': 'src/core/io_uring/extra_admission_input.h',
            'kernel/include/trace/events/xdev_ext.h': 'src/core/include/trace/events/xdev_ext.h',
            'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c': 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c',
            'kernel/net/xdp/xsk.c': 'src/network/net/xdp/xsk.c',
        }
        for logical, source in synthetic.items():
            if logical in self.by_logical:
                continue
            self.entries.append(dict(source=source, component='linux', native_path=logical.removeprefix('kernel/')))
            self.by_logical[logical] = source
            write(self.repo / source, f'/* private source marker {logical} */\n')
        self.manifest = {'schema': 1, 'dependency_lock': 'third_party/sources.lock.json', 'files': self.entries}
        write_json(self.repo / 'source-layout.json', self.manifest)
        self.lock = {'schema': 2, 'components': {'linux': {'url': str(self.upstream), 'ref': 'refs/heads/master', 'commit': self.upstream_sha}}}
        write_json(self.repo / 'third_party/sources.lock.json', self.lock)
        write(self.repo / '.gitignore', '/build/\n')
        self.sha = self.commit(self.repo)
        self.native = self.repo / 'build/assembled/linux'
        self.prepare(self.native)
        self.view = self.repo / 'build/source-view'

    def cleanup(self):
        self.temporary.cleanup()

    @staticmethod
    def init_git(root):
        checked(['git', 'init', '-q', '-b', 'master', root])
        checked(['git', '-C', root, 'config', 'user.name', 'Private fixture'])
        checked(['git', '-C', root, 'config', 'user.email', 'fixture@example.invalid'])

    @staticmethod
    def commit(root):
        checked(['git', '-C', root, 'add', '.'])
        checked(['git', '-C', root, 'commit', '-qm', 'private source fixture'], env={'GIT_AUTHOR_DATE': '2000-01-01T00:00:00Z', 'GIT_COMMITTER_DATE': '2000-01-01T00:00:00Z'})
        return checked(['git', '-C', root, 'rev-parse', 'HEAD'])

    def prepare(self, output):
        checked([sys.executable, '-B', self.repo / 'tools/build/prepare_sources.py', '--component', 'linux', '--cache', self.cache, '--output', output, '--offline'])

    def materialize(self, output=None):
        layout = import_file(self.repo / 'tools/layout.py')
        return layout.materialize_view(self.repo, output).root

    def gate(self, selected=None, e2=False, fence=False, run_only=False):
        variables = {'SRC': str(selected or self.repo), 'LIFECYCLE': '0', 'EVAL_SESSION': '0', 'MECHANISM_VARIANTS': str(int(e2)), 'FENCE_CHECK': str(int(fence)), 'RUN_ONLY': str(int(run_only)), 'PREPARE_ONLY': str(int(not run_only))}
        shell = 'set -euo pipefail\n' + '\n'.join(k + '=' + shlex.quote(v) for k, v in variables.items()) + '\n'
        shell += extract_shell_function(PRODUCT / HARNESS, 'verify_source_checkout')
        shell += '\nverify_source_checkout\n'
        for name in ('SRC', 'SOURCE_GIT_ROOT', 'SOURCE_COMMIT', 'SOURCE_LAYOUT', 'SOURCE_SUPPORT_VIEW', 'E2_SOURCE', 'FENCE_OUT', 'LIFECYCLE_HEADER_SOURCE', 'LIFECYCLE_HEADER_COPY'):
            shell += 'printf "%s=%s\\n" ' + shlex.quote(name) + ' "${' + name + '-}"\n'
        result = command(['bash', '-c', shell])
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        return result, values

    def identity(self, directory=None):
        runner = import_file((directory or self.repo / Path(RUNNER).parent) / 'run.py')
        if not callable(getattr(runner, 'source_identity', None)):
            raise AssertionError('missing required source-only source_identity(directory) interface')
        return runner.source_identity(directory or self.repo / Path(RUNNER).parent)

    def query(self, directory, field, env=None):
        return command([sys.executable, '-B', directory / 'run.py', '--identity-field', field], env=env)

    def header_hash(self):
        return hashlib.sha256((self.repo / HEADER).read_bytes()).hexdigest()

    def foreign_parent(self):
        parent = self.root / 'foreign'
        parent.mkdir()
        self.init_git(parent)
        write(parent / 'unrelated.txt', 'unrelated authority\n')
        foreign_sha = self.commit(parent)
        return parent, foreign_sha
