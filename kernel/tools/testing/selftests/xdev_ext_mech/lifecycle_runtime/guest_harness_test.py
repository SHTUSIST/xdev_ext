#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real harness image preparation without launching a guest."""
import os, pathlib, re, subprocess, sys, tempfile, unittest
kernel = pathlib.Path(__file__).resolve().parents[5]
harness = kernel/'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'
s = harness.read_text()
image = re.search(r"python3 - \"\$SCRATCH\" \"\$GROUP_COUNT\"[^\n]* <<'PY'\n(.*?)\nPY\n", s, re.S).group(1)
with tempfile.TemporaryDirectory() as temp:
    p = pathlib.Path(temp); (p/'evidence').mkdir()
    # The merged image helper takes fault campaign before lifecycle selection.
    subprocess.run([sys.executable, '-', temp, '3', '0', 'none', str(kernel), '', '1'], input=image, text=True, check=True)
    source = (p/'source.raw').read_bytes(); expected = (p/'expected.raw').read_bytes()
    data = source[2048*512:2048*512+3*8192]
    start = 4096*512; size = len(data)
    assert expected[start:start+size] == data
    assert expected[start+size:start+2*size] == data, 'missing second fanout sink oracle'
    transformed = expected[start+2*size:start+3*size]
    assert transformed != data and transformed != bytes(size)
    assert transformed == expected[start+3*size:start+4*size]
    assert expected[:start] == bytes(start)
    assert expected[start+4*size:] == bytes(len(expected)-start-4*size)
assert '--lifecycle)' in s and 'sh /opt/xdev_ext/xdev_ext_mech_lifecycle_guest.sh' in s
assert 'cmp "$SCRATCH/expected.raw" "$SCRATCH/destination.raw"' in s
print('PASS lifecycle harness four sink images, guards, and execution hook')


class SocketConfigRequirements(unittest.TestCase):
    """Exercise host mode selection and config checks, without a kernel build.

    The real shell selects the mode and invokes scripts/config. Only the
    source-preparation/provenance work and external make/config boundaries
    are replaced; no new production helper or its spelling is assumed.
    """

    def run_config(self, options=(), fallback=None, run_only=False,
                   socket=False, drop_socket=False):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            source = root/'src'
            build = root/'build'
            evidence = root/'evidence'
            binary = root/'bin'
            for directory in (source/'scripts', build, evidence, binary):
                directory.mkdir(parents=True)
            integration = source/'tools/testing/selftests/xdev_ext_integration'
            integration.mkdir(parents=True)
            debug = harness.with_name('xdev_ext_mech_zc_debug.py')
            (integration/debug.name).write_text(debug.read_text())
            # These doubles preserve configuration writes. They replace only
            # unavailable upstream scripts/config and expensive make targets.
            config_tool = source/'scripts/config'
            config_tool.write_text('''#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
assert args.pop(0) == '--file'
path = pathlib.Path(args.pop(0))
lines = path.read_text().splitlines()
while args:
    op, symbol = args.pop(0), args.pop(0)
    value = args.pop(0) if op == '--set-str' else ('y' if op == '-e' else None)
    assert op in ('-e', '-d', '--set-str'), op
    lines = [line for line in lines if not line.startswith('CONFIG_'+symbol+'=')
             and line != '# CONFIG_'+symbol+' is not set']
    lines.append('CONFIG_'+symbol+'='+value if value is not None
                 else '# CONFIG_'+symbol+' is not set')
path.write_text('\\n'.join(lines)+'\\n')
''')
            config_tool.chmod(0o755)
            make = binary/'make'
            make.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['MAKE_RECORD'], 'a') as record:
    record.write(' '.join(args)+'\\n')
out = pathlib.Path(next(arg[2:] for arg in args if arg.startswith('O=')))
config = out/'.config'
if 'defconfig' in args:
    config.write_text('# CONFIG_XDEV_EXT_MECH_SOCKET is not set\\n')
elif 'olddefconfig' in args:
    text = config.read_text()
    if 'CONFIG_CRYPTO_DEFLATE=y\\n' in text:
        text += 'CONFIG_CRYPTO_ACOMP2=y\\n'
    if 'CONFIG_PROVE_LOCKING=y\\n' in text:
        text += 'CONFIG_LOCKDEP=y\\n'
    if os.environ.get('DROP_SOCKET') == '1':
        text = text.replace('CONFIG_XDEV_EXT_MECH_SOCKET=y\\n',
                            '# CONFIG_XDEV_EXT_MECH_SOCKET is not set\\n')
    config.write_text(text)
else:
    raise SystemExit('unexpected full build target')
''')
            make.chmod(0o755)
            # Real argument/default validation, before source preparation.
            prefix = s[:s.index('[[ "$SCRATCH" =~')]
            # Real identity functions/run-only checks and configuration body.
            # Omit only provenance collection, which requires a prepared Git
            # source tree but does not choose configuration or guest modes.
            checks = s[s.index('DEBUG_HELPER='):s.index("printf 'date_utc=")]
            config = s[s.index('if (( ! RUN_ONLY )); then\n\tkmake defconfig'):
                       s.index('if (( MECHANISM_VARIANTS && ! RUN_ONLY )); then')]
            shell = prefix + '''
SRC=$SOURCE_OVERRIDE
BUILD=$SCRATCH/build
EV=$SCRATCH/evidence
TOOLS=$SCRATCH/tools
SOURCE_COMMIT=fixture
''' + checks + config + '\necho CONFIG_BOUNDARY_REACHED\n'
            (build/'.config').write_text(
                'CONFIG_XDEV_EXT_MECH_SOCKET=y\n' if socket else
                '# CONFIG_XDEV_EXT_MECH_SOCKET is not set\n')
            (build/'xdev-ext-source.commit').write_text('fixture\n')
            artifact = build/'identity-artifact'
            artifact.write_text('identity\n')
            digest = subprocess.check_output(['sha256sum', str(artifact)], text=True)
            (build/'xdev-ext-artifacts.sha256').write_text(digest)
            subprocess.run([sys.executable, str(integration/debug.name), 'record',
                            str(build/'.config'), str(build/'xdev-ext-debug-profile.json'),
                            '0'], check=True)
            env = os.environ.copy()
            env.pop('XDEV_EXT_ZC_NIC_FALLBACK', None)
            if fallback is not None:
                env['XDEV_EXT_ZC_NIC_FALLBACK'] = fallback
            env.update(PATH=str(binary)+os.pathsep+env['PATH'],
                       MAKE_RECORD=str(root/'make.calls'),
                       DROP_SOCKET=str(int(drop_socket)))
            args = ['bash', '-s', '--', '--scratch', str(root), '--source', str(source),
                    '--run-only' if run_only else '--prepare-only', *options]
            result = subprocess.run(args, input=shell, text=True, env=env,
                                    capture_output=True, timeout=10)
            self.assertNotIn('syntax error', result.stderr)
            self.assertNotIn('unbound variable', result.stderr)
            calls = root/'make.calls'
            return (result, (build/'.config').read_text(),
                    calls.read_text() if calls.exists() else '')

    def assert_prepared(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)

    def test_peer_default_fallback_enables_socket_before_build(self):
        result, config, calls = self.run_config(('--peer', '--groups', '257', '--debug-locking'))
        self.assert_prepared(result)
        self.assertIn('olddefconfig', calls)
        self.assertIn('CONFIG_XDEV_EXT_MECH_SOCKET=y\n', config)

    def test_regular_default_and_strict_fallback_require_socket(self):
        for options in ((), ('--ce-sim', '--rx-ce', '--reliable')):
            with self.subTest(options=options):
                result, config, _ = self.run_config(options)
                self.assert_prepared(result)
                self.assertIn('CONFIG_XDEV_EXT_MECH_SOCKET=y\n', config)

    def test_explicit_opt_out_does_not_enable_socket(self):
        result, config, _ = self.run_config(('--peer', '--groups', '257'), fallback='0')
        self.assert_prepared(result)
        self.assertNotIn('CONFIG_XDEV_EXT_MECH_SOCKET=y\n', config)

    def test_compat_still_enables_socket_with_fallback_opted_out(self):
        result, config, _ = self.run_config(('--compat',), fallback='0')
        self.assert_prepared(result)
        self.assertIn('CONFIG_XDEV_EXT_MECH_SOCKET=y\n', config)

    def test_fault_and_provider_modes_do_not_enable_unused_socket(self):
        for options in (('--fault', 'drop-middle'), ('--provider-case', 'short'),
                        ('--provider-case', 'ambiguous')):
            with self.subTest(options=options):
                result, config, _ = self.run_config(options)
                self.assert_prepared(result)
                self.assertNotIn('CONFIG_XDEV_EXT_MECH_SOCKET=y\n', config)

    def test_lifecycle_does_not_require_socket_after_early_guest_exit(self):
        result, config, _ = self.run_config(('--lifecycle',))
        self.assert_prepared(result)
        self.assertNotIn('CONFIG_XDEV_EXT_MECH_SOCKET=y\n', config)
        # Execute the real guest dispatch at this boundary. An actual shell
        # exit must prevent continuation toward the later Track S section.
        start = s.index('if [ "$lifecycle" = 1 ]; then\n')
        end = s.index('if [ "$peer" = 1 ]; then\n', start)
        setup = '''set -eu
lifecycle=1
ctl=ctl source_ng=ng0 source_block=nvme0 destination_ng=ng1 destination_block=nvme1
source_slba=2048 rx_slba=4096 groups=4 depth=4
sh() { echo LIFECYCLE_DISPATCH; }
'''
        dispatch = subprocess.run(['sh'], input=setup+s[start:end]+
                                  '\necho LATER_GUEST_WORK\n',
                                  text=True, capture_output=True, timeout=5)
        self.assertEqual(dispatch.returncode, 0, dispatch.stderr)
        self.assertEqual(dispatch.stdout, 'LIFECYCLE_DISPATCH\n')

    def test_invalid_fallback_environment_fails_before_make(self):
        for value in ('2', 'banana', '1+0'):
            with self.subTest(value=value):
                result, _, calls = self.run_config(fallback=value)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(calls, '', 'invalid input reached kernel configuration')
                self.assertNotIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)

    def test_required_socket_is_asserted_after_olddefconfig(self):
        for options in ((), ('--compat',)):
            with self.subTest(options=options):
                result, _, calls = self.run_config(options, drop_socket=True)
                self.assertIn('olddefconfig', calls)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)

    def test_run_only_rejects_missing_socket_before_later_build_or_image_work(self):
        result, _, calls = self.run_config(run_only=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('CONFIG_BOUNDARY_REACHED', result.stdout)
        self.assertEqual(calls, '')
        self.assertIn('CONFIG_XDEV_EXT_MECH_SOCKET', result.stdout + result.stderr)

    def test_run_only_opt_out_accepts_existing_socket_free_profile(self):
        for options, fallback in (((), '0'), (('--lifecycle',), None),
                                  (('--fault', 'drop-middle'), None)):
            with self.subTest(options=options, fallback=fallback):
                result, _, calls = self.run_config(options, run_only=True, fallback=fallback)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('CONFIG_BOUNDARY_REACHED', result.stdout)
                self.assertEqual(calls, '')

    def test_run_only_accepts_matching_socket_enabled_config(self):
        result, _, calls = self.run_config(run_only=True, socket=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('CONFIG_BOUNDARY_REACHED', result.stdout)
        self.assertEqual(calls, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
