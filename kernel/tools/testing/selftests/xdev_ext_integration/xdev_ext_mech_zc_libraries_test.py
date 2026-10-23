#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual guest dependency staging with two real dynamic executables."""
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'


class GuestLibraries(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, 'isolated dynamic runtime requires chroot')
    def test_real_pthread_cancel_runs_in_staged_compat_root(self):
        script = HARNESS.read_text()
        fragment = script[script.index('GUEST_PROGRAMS=('):script.index('cat >"$ROOT/init"')]
        with tempfile.TemporaryDirectory(prefix='xdev-ext-cancel-libs-') as directory:
            base = Path(directory)
            tools, iaa, socket, preload, root, evidence, compiler = (
                base/part for part in ('tools', 'iaa', 'socket', 'preload', 'root', 'evidence', 'compiler'))
            for folder in (tools, iaa, socket, preload, root, evidence, compiler):
                folder.mkdir()
            cc = shutil.which(os.environ.get('CC', 'cc'))
            self.assertIsNotNone(cc)
            # The harness uses gcc-14 on the build server; local regression
            # invokes the available real compiler through that command name.
            (compiler/'gcc-14').symlink_to(cc)
            source = base/'cancel.c'
            source.write_text('''#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
static pthread_barrier_t ready;
static int fds[2];
static void *worker(void *unused) {
 (void)unused; char c; pthread_barrier_wait(&ready);
 while (read(fds[0], &c, 1) >= 0) {} return NULL;
}
int main(void) {
 pthread_t thread; void *result;
 if (pipe(fds) || pthread_barrier_init(&ready, NULL, 2) ||
     pthread_create(&thread, NULL, worker, NULL)) return 2;
 pthread_barrier_wait(&ready);
 if (pthread_cancel(thread) || pthread_join(thread, &result) || result != PTHREAD_CANCELED) return 3;
 puts("CANCEL_RUNTIME=PASS"); return 0;
}
''')
            binary = tools/'xdev_ext_mech_ctl'
            subprocess.run([cc, '-pthread', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)],
                           check=True, capture_output=True, text=True)
            linked = subprocess.run(['ldd', str(binary)], check=True, capture_output=True, text=True)
            self.assertNotIn('libgcc_s', linked.stdout, 'fixture must exercise a dlopen-only dependency')
            for path in (socket/'socket_runtime', preload/'xdev_ext_preload_mech_workload',
                         preload/'xdev_ext_preload_socket_smoke', preload/'xdev_ext_preload_db_workload',
                         preload/'xdev_ext_preload_ordinary_fork_guest'):
                shutil.copy2(binary, path)
            library_source = base/'library.c'
            library_source.write_text('#include <stdio.h>\nint probe(void) { return puts("probe"); }\n')
            subprocess.run([cc, '-shared', '-fPIC', str(library_source), '-o',
                            str(preload/'libio_uring_unified.so')], check=True, capture_output=True, text=True)
            env = dict(os.environ, PATH=str(compiler)+':'+os.environ['PATH'], TOOLS=str(tools),
                       IAA_OUT=str(iaa), SOCKET_OUT=str(socket), PRELOAD_OUT=str(preload),
                       ROOT=str(root), EV=str(evidence), CE_SIM='0', PROVIDER_CASE='normal', COMPAT='1')
            staged = subprocess.run(['bash', '-euc', fragment], env=env, capture_output=True, text=True)
            self.assertEqual(staged.returncode, 0, staged.stdout+staged.stderr)
            (root/'opt').mkdir()
            shutil.copy2(binary, root/'opt/cancel')
            run = subprocess.run(['chroot', str(root), '/opt/cancel'], capture_output=True, text=True,
                                 timeout=10, preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
            self.assertEqual(run.returncode, 0, run.stdout+run.stderr)
            self.assertEqual(run.stdout, 'CANCEL_RUNTIME=PASS\n')
            runtime = Path(subprocess.check_output(
                [cc, '-print-file-name=libgcc_s.so.1'], text=True).strip()).resolve()
            staged_runtime = root/runtime.relative_to('/')
            self.assertEqual(staged_runtime.read_bytes(), runtime.read_bytes())
            recorded = (evidence/'guest-library-paths.txt').read_text().splitlines()
            self.assertIn(str(runtime), recorded, 'resolved dlopen runtime must be in staging evidence')
            runtime_deps = subprocess.check_output(['ldd', str(runtime)], text=True)
            for dependency in re.findall(r'^\s*(?:\S+\s+=>\s+)?(/\S+)', runtime_deps, re.M):
                self.assertTrue((root/dependency.lstrip('/')).is_file(),
                                'missing cancellation runtime dependency: '+dependency)
            (compiler/'gcc-14').unlink()
            for unresolved in ('libgcc_s.so.1', str(base/'missing/libgcc_s.so.1')):
                with self.subTest(unresolved=unresolved):
                    (compiler/'gcc-14').write_text("#!/bin/sh\nprintf '%s\\n' '"+unresolved+"'\n")
                    (compiler/'gcc-14').chmod(0o700)
                    failed = subprocess.run(['bash', '-euc', fragment], env=env,
                                            capture_output=True, text=True)
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn('FAIL compatibility cancellation runtime libgcc_s.so.1 is unresolved',
                                  failed.stderr)

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
