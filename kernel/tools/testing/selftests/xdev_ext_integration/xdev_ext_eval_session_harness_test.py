#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-only execution of actual eval opt-in, identity, staging and guest wiring."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'
FILES = ('chain_bench', 'session_nvme_ce', 'session_gpu_nic', 'eval_session_oracle',
         'chain_plan.bpf.o', 'xdev_ext_eval_session_guest.sh')
SYMBOLS = ('MODULES', 'MODULE_UNLOAD', 'XDEV_EXT_MECH', 'XDEV_EXT_MECH_ZEROCOPY',
           'XDEV_EXT_MECH_CE', 'XDEV_EXT_MECH_DMA', 'XDEV_EXT_MECH_IAA',
           'CRYPTO_ACOMP2', 'CRYPTO_DEFLATE')


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', HARNESS.read_text(), re.M | re.S)
    if match is None:
        raise AssertionError('missing actual harness function: '+name)
    return match.group()


def run(script, **env):
    return subprocess.run(['bash', '-euo', 'pipefail', '-c', script], env=dict(os.environ, **env),
                          capture_output=True, text=True)


def manifest(path, files):
    path.write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f)+'\n' for f in files))


class EvalSessionHarness(unittest.TestCase):
    def test_cli_opt_in_and_rejects_fault_combinations_before_any_host_work(self):
        text = HARNESS.read_text().split('[[ "$SCRATCH" =~', 1)[0]
        for args, expected in (([], '0:0'), (['--eval-session'], '1:1'),
                               (['--ce-sim'], '0:1')):
            result = subprocess.run(['bash', '-euc', text+'\nprintf "%s:%s" "$EVAL_SESSION" "$CE_SIM"',
                                     'harness', *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
        for args in (['--fault-campaign', 'nvme-readonly-dest'], ['--fault', 'drop-middle'],
                     ['--provider-case', 'short']):
            result = subprocess.run(['bash', '-euc', text, 'harness', '--eval-session', *args],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)

    def identity(self, *, missing_file=None, missing_record=None, symbol=None,
                 mode='eval_session=1\n', corrupt=None, source_changed=False):
        gate = function('verify_eval_session_identity')
        with tempfile.TemporaryDirectory(prefix='eval-identity-') as directory:
            base = Path(directory)
            build, output = base/'build', base/'eval'
            build.mkdir(); output.mkdir()
            (build/'.config').write_text(''.join('CONFIG_'+s+'=y\n' for s in SYMBOLS if s != symbol))
            artifacts = []
            for name in FILES:
                target = output/name
                target.write_text('identity fixture '+name)
                target.chmod(0o700)
                if name != missing_record:
                    artifacts.append(target)
            source = base/'actual-source.c'
            source.write_text('original source')
            sources = build/'xdev-ext-eval-session-source.sha256'
            manifest(sources, [source])
            profile = build/'xdev-ext-eval-session-mode.txt'
            profile.write_text(mode)
            validator = base/'validator.py'
            validator.write_text('validator identity')
            manifest(build/'xdev-ext-artifacts.sha256', artifacts+[sources, profile, validator])
            if missing_file:
                (output/missing_file).unlink()
            if corrupt:
                (output/corrupt).write_text('corruption')
            if source_changed:
                source.write_text('changed source')
            return run(gate+'\nverify_eval_session_identity', BUILD=str(build),
                       EVAL_SESSION_OUT=str(output), EVAL_SESSION_VALIDATOR=str(validator))

    def test_identity_accepts_exact_complete_build(self):
        result = self.identity()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_identity_rejects_every_missing_file_and_record(self):
        for name in FILES:
            for key in ('missing_file', 'missing_record'):
                with self.subTest(name=name, key=key):
                    self.assertNotEqual(self.identity(**{key: name}).returncode, 0)

    def test_identity_rejects_wrong_modes_config_and_changed_sources_or_artifacts(self):
        for args in ({'mode': 'eval_session=0\n'}, {'source_changed': True},
                     *({'symbol': s} for s in SYMBOLS), *({'corrupt': f} for f in FILES)):
            with self.subTest(args=args):
                self.assertNotEqual(self.identity(**args).returncode, 0)

    def test_source_recording_tracks_real_eval_sources(self):
        record = function('record_eval_session_sources')
        with tempfile.TemporaryDirectory(prefix='eval-sources-') as directory:
            base = Path(directory)
            for relative in ('tests/eval/session_guest/oracle.c', 'tests/eval/chains/chain.c',
                             'kernel/tools/xdev_ext_gpu_identity.c',
                             'kernel/tools/include/xdev_ext_gpu_identity.h',
                             'kernel/include/uapi/linux/io_uring.h'):
                target = base/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(relative)
            subprocess.run(['git', 'init', '-q', str(base)], check=True)
            subprocess.run(['git', '-C', str(base), 'add', 'tests', 'kernel'], check=True)
            result = run(record+'\nrecord_eval_session_sources', SOURCE_GIT_ROOT=str(base), BUILD=str(base))
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = (base/'xdev-ext-eval-session-source.sha256').read_text()
            for path in base.rglob('*.c'):
                self.assertIn(str(path.relative_to(base)), lines)
            for header in ('kernel/tools/include/xdev_ext_gpu_identity.h',
                           'kernel/include/uapi/linux/io_uring.h'):
                self.assertIn(str(base/header), lines)
            checked = run('cd "$SOURCE_GIT_ROOT"; sha256sum -c "$BUILD/xdev-ext-eval-session-source.sha256"',
                          SOURCE_GIT_ROOT=str(base), BUILD=str(base))
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_real_image_copy_and_four_elf_dependency_staging(self):
        stage = function('stage_eval_session_image')
        text = HARNESS.read_text()
        libraries = text[text.index('GUEST_PROGRAMS=('):text.index('cat >"$ROOT/init"')]
        with tempfile.TemporaryDirectory(prefix='eval-staging-') as directory:
            base = Path(directory)
            output, tools, root, evidence, deps = [base/p for p in ('eval', 'tools', 'root', 'evidence', 'deps')]
            for p in (output, tools, root, evidence, deps): p.mkdir()
            cc = os.environ.get('CC', 'cc')
            (base/'plain.c').write_text('int main(void) {return 0;}\n')
            subprocess.run([cc, str(base/'plain.c'), '-o', str(tools/'xdev_ext_mech_ctl')], check=True)
            for index, name in enumerate(FILES[:4]):
                (base/'lib.c').write_text(f'int eval_probe_{index}(void) {{return 0;}}\n')
                lib = deps/f'libeval_probe_{index}.so'
                subprocess.run([cc, '-shared', '-fPIC', str(base/'lib.c'), '-o', str(lib)], check=True)
                (base/'program.c').write_text(f'extern int eval_probe_{index}(void); int main(void) {{return eval_probe_{index}();}}\n')
                subprocess.run([cc, str(base/'program.c'), '-L'+str(deps), f'-leval_probe_{index}',
                                '-Wl,-rpath,'+str(deps), '-o', str(output/name)], check=True)
            for name in FILES[4:]: (output/name).write_text(name)
            result = run(stage+'\nstage_eval_session_image\n'+libraries, EVAL_SESSION='1',
                         EVAL_SESSION_OUT=str(output), ROOT=str(root), TOOLS=str(tools), EV=str(evidence),
                         CE_SIM='0', PROVIDER_CASE='normal')
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in FILES:
                self.assertEqual((root/'opt/xdev_ext/eval'/name).read_bytes(), (output/name).read_bytes())
            for library in deps.glob('*.so'):
                self.assertEqual((root/str(library).lstrip('/')).read_bytes(), library.read_bytes())
            for name in FILES[:4]: self.assertTrue((evidence/('ldd.'+name+'.txt')).is_file())

    def test_generated_guest_invokes_driver_with_exact_roles_and_propagates_failure(self):
        guest = HARNESS.read_text().split("<<'GUEST'\n", 1)[1].split('\nGUEST', 1)[0]
        self.assertIn('if [ "$eval_session" = 1 ]', guest)
        self.assertLess(guest.index('resolve_nvme_roles /'), guest.index('if [ "$eval_session" = 1 ]'))
        self.assertLess(guest.index('ip link set eth1 up'), guest.index('if [ "$eval_session" = 1 ]'))
        self.assertLess(guest.index('if [ "$eval_session" = 1 ]'), guest.index('$ctl attach --obj'))
        self.assertLess(guest.index('if [ "$eval_session" = 1 ]'), guest.index('insmod /opt/xdev_ext/xdev_ext_ce_sim.ko'))
        block = re.search(r'if \[ "\$eval_session" = 1 \]; then\n.*?\nfi', guest, re.S).group()
        with tempfile.TemporaryDirectory(prefix='eval-guest-call-') as directory:
            base = Path(directory)
            driver = base/'driver'
            driver.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >"$CAPTURE"\nexit "$CHILD_EXIT"\n')
            block = block.replace('/opt/xdev_ext/eval/xdev_ext_eval_session_guest.sh', shlex.quote(str(driver)))
            env = dict(eval_session='1', source_block='/dev/testsrc', source_ng='/dev/ngsrc',
                       destination_block='/dev/testdst', destination_ng='/dev/ngdst', cli_timeout_ms='240000',
                       CAPTURE=str(base/'args'))
            for status in ('0', '4', '23'):
                result = run(block+'\necho continued', CHILD_EXIT=status, **env)
                self.assertEqual(result.returncode, int(status), result.stderr)
                self.assertEqual((base/'args').read_text().splitlines(),
                                 ['/opt/xdev_ext/eval', '/opt/xdev_ext', '/dev/testsrc', '/dev/ngsrc',
                                  '/dev/testdst', '/dev/ngdst', '240000'])
                self.assertEqual('continued' in result.stdout, status == '0')

    def test_host_runs_full_console_validator_and_preserves_failure(self):
        text = HARNESS.read_text()
        self.assertIn('if (( EVAL_SESSION )); then\n    python3 "$EVAL_SESSION_VALIDATOR"', text)
        start = text.index('if (( EVAL_SESSION )); then\n    python3 "$EVAL_SESSION_VALIDATOR"')
        block = text[start:text.index('\nfi', start)+3]
        with tempfile.TemporaryDirectory(prefix='eval-validator-') as directory:
            base = Path(directory)
            (base/'guest.log').write_text('complete console\n')
            validator = base/'validator.py'
            validator.write_text('import pathlib,sys\nassert pathlib.Path(sys.argv[1]).read_text()=="complete console\\n"\nsys.exit(19)\n')
            result = run(block+'\necho false-pass', EVAL_SESSION='1', EVAL_SESSION_VALIDATOR=str(validator), EV=str(base))
            self.assertEqual(result.returncode, 19, result.stderr)
            self.assertNotIn('false-pass', result.stdout)
        self.assertLess(text.index('[[ $rc == 0 ]]'), start)
        self.assertIn('validate_images(', text[start:])
        self.assertIn('! grep -Eq \'BUG:|WARNING:|Kernel panic|Oops:\'', text[start:])


if __name__ == '__main__': unittest.main(verbosity=2)
