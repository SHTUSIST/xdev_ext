#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent Task X7 contract tests. Never load BPF or run a guest here.

The frozen matrix comes from Task X7's original six requirements and Q3(b),
expanded by kfunc, member, foreign class, helper and memory-access row.
A PASS record means its actual probe met its expectation, including verifier
rejection with a diagnostic for DENY rows. A compiler/setup error is no DENY.
"""
import importlib.util
import json
import re
import subprocess
import tempfile
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
GUEST = HERE.parent / 'xdomain' / 'guest'
MANIFEST = json.loads((GUEST / 'cases.json').read_text())
NAMES = tuple(sorted(row['name'] for row in MANIFEST['cases']))
SCOPE = 'software-module-and-verifier'


def good_log(names=NAMES):
    return '\n'.join(f'XDEV_EXT_XDOMAIN_CASE=PASS name={name}' for name in names) + '\n'


class VerdictContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parser = GUEST / 'verdict.py'
        if not parser.is_file():
            raise AssertionError(f'X7 MISSING PARSER: {parser}; expected validate(log: str) -> dict; no verifier acceptance claimed')
        spec = importlib.util.spec_from_file_location('xdomain_guest_verdict', parser)
        cls.parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.parser)
        if not callable(getattr(cls.parser, 'validate', None)):
            raise AssertionError('X7 MISSING API: verdict.validate(log: str) -> dict')

    def reject(self, log):
        with self.assertRaises(ValueError):
            self.parser.validate(log)

    def test_complete_matrix_and_sorted_result(self):
        self.assertEqual(self.parser.validate(good_log(reversed(NAMES))),
                         {'status': 'PASS', 'cases': list(NAMES), 'scope': SCOPE})

    def test_missing_every_required_case(self):
        for missing in NAMES:
            with self.subTest(missing=missing):
                self.reject(good_log(n for n in NAMES if n != missing))

    def test_duplicates_every_case(self):
        for duplicate in NAMES:
            with self.subTest(duplicate=duplicate):
                self.reject(good_log() + good_log([duplicate]))

    def test_fail_every_case(self):
        for failed in NAMES:
            with self.subTest(failed=failed):
                self.reject(good_log().replace(f'CASE=PASS name={failed}\n', f'CASE=FAIL name={failed}\n'))

    def test_original_six_pass_total_cannot_satisfy_expanded_matrix(self):
        self.reject(good_log(NAMES[:6]))

    def test_empty_unknown_and_malformed_case_records(self):
        for log in ('', good_log() + good_log(['unknown-case']),
                    good_log() + 'XDEV_EXT_XDOMAIN_CASE=SKIP name=module-load\n',
                    good_log() + 'XDEV_EXT_XDOMAIN_CASE=PASS\n',
                    good_log().replace('name=module-load\n', 'name=module-load extra=unvalidated\n'),
                    good_log().replace('XDEV_EXT_XDOMAIN_CASE=PASS name=module-load\n',
                                       'prefix XDEV_EXT_XDOMAIN_CASE=PASS name=module-load\n')):
            with self.subTest(log=log[-180:]):
                self.reject(log)

    def test_not_ok_skip_and_kernel_diagnostics_rejected(self):
        for diagnostic in ('not ok 1 - failed subtest', 'ok 1 # SKIP no BTF',
                           'SKIP unavailable', 'WARNING: suspicious RCU usage',
                           'BUG: bad page state', 'KASAN: use-after-free',
                           'lockdep: possible circular locking dependency',
                           'possible circular locking dependency detected'):
            with self.subTest(diagnostic=diagnostic):
                self.reject(good_log() + diagnostic + '\n')

    def test_setup_failure_never_counts_as_expected_verifier_rejection(self):
        for diagnostic in ('XDEV_EXT_XDOMAIN_SETUP=FAIL reason=module-unavailable',
                           'SETUP_FAILURE: missing xdev_ext_xdomain_mech_ops BTF type',
                           'libbpf: failed to find valid kernel BTF',
                           'libbpf: failed to open ELF object',
                           'clang: error: compilation failed',
                           'modprobe: FATAL: Module xdev_ext_xdomain not found'):
            with self.subTest(diagnostic=diagnostic):
                self.reject(good_log() + diagnostic + '\n')

    def test_unrelated_guest_boot_chatter_allowed(self):
        self.assertEqual(self.parser.validate('Linux version test\n' + good_log() + 'Power down\n')['status'], 'PASS')

    def test_actual_debug_lockdep_enable_banner_is_not_a_locking_failure(self):
        # Preserved healthy strict-debug boot line from base-lifecycle-guest.
        banner = '[    2.523581] rcu: \tRCU lockdep checking is enabled.\n'
        try:
            result = self.parser.validate(banner + good_log())
        except ValueError as error:
            self.fail('healthy debug boot banner rejected: ' + str(error))
        self.assertEqual(result['status'], 'PASS')
        self.reject(good_log() + 'WARNING: possible circular locking dependency detected\n')

    def test_exact_healthy_kasan_startup_banner_with_timestamp_and_crlf_is_allowed(self):
        healthy = 'kasan: KernelAddressSanitizer initialized'
        for banner in (healthy + '\n', '[    0.141815] ' + healthy + '\n',
                       healthy + '\r\n', '[    0.141815] ' + healthy + '\r\n'):
            with self.subTest(banner=repr(banner)):
                try:
                    result = self.parser.validate(banner + good_log())
                except ValueError as error:
                    self.fail('exact healthy KASAN startup line rejected: ' + str(error))
                self.assertEqual(result['status'], 'PASS')
                self.assertEqual(result['cases'], list(NAMES))

    def test_healthy_kasan_exception_never_hides_unknown_suffix_fault_bug_or_warning(self):
        healthy = '[    0.141815] kasan: KernelAddressSanitizer initialized'
        for diagnostic in (
                'KASAN: use-after-free in xdomain',
                '[    1.000001] kasan: unknown allocator state',
                healthy + ' ERROR trailing fault',
                'prefix kasan: KernelAddressSanitizer initialized',
                '[not-a-time] kasan: KernelAddressSanitizer initialized',
                healthy + '\nBUG: bad page state',
                healthy + '\nWARNING: suspicious RCU usage'):
            with self.subTest(diagnostic=diagnostic):
                self.reject(good_log() + diagnostic + '\r\n')

    def test_normal_delay_calibration_and_zero_skip_kunit_totals_are_allowed(self):
        boot = ('[ 0.336026] Calibrating delay loop (skipped) preset value.. '
                '4800.00 BogoMIPS (lpj=2400000)\n'
                '[ 2.474835] # thunderbolt: pass:45 fail:0 skip:0 total:45\n'
                '# Totals: pass:45 fail:0 skip:0 total:45\n')
        try:
            result = self.parser.validate(boot + good_log())
        except ValueError as error:
            self.fail('normal boot chatter and successful zero-skip KUnit summaries rejected: ' + str(error))
        self.assertEqual(result, {'status': 'PASS', 'cases': list(NAMES), 'scope': SCOPE})

    def test_actual_test_skip_forms_and_nonzero_kunit_skips_remain_rejected(self):
        for diagnostic in (
                'SKIP unavailable',
                '    SKIP: no device',
                'ok 1 - unavailable test # SKIP missing prerequisite',
                'test_example ... skipped \'no device\'',
                'OK (skipped=1)',
                '[ 2.474835] # thunderbolt: pass:44 fail:0 skip:1 total:45',
                '# Totals: pass:44 fail:0 skip:1 total:45',
                '# Totals: pass:35 fail:0 skip:10 total:45',
                '# Totals: pass:44 fail:1 skip:0 total:45'):
            with self.subTest(diagnostic=diagnostic):
                self.reject(good_log() + diagnostic + '\n')


class FrozenInventory(unittest.TestCase):
    def test_matrix_has_all_forty_unique_rows(self):
        self.assertEqual(len(NAMES), 41)
        self.assertEqual(len(set(NAMES)), 41)
        self.assertEqual(MANIFEST['scope'], SCOPE)
        for symbol in ('info', 'verdict'):
            for member in ('build', 'prepare', 'complete'):
                self.assertIn(f'private-{symbol}-xdomain-{member}-' + ('allow' if member == 'complete' else 'deny'), NAMES)
            for cls in ('nvme', 'net', 'af-xdp', 'socket'):
                self.assertIn(f'private-{symbol}-{cls}-complete-deny', NAMES)


class ActualHarnessContract(unittest.TestCase):
    """Run actual option/config fragments with external build tools stubbed.

    This proves build selection/admission only, never compilation or BPF load.
    """
    @classmethod
    def setUpClass(cls):
        cls.harness = (HERE.parents[4] / 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh').read_text()

    def test_actual_guest_provider_startup_has_required_guest_opt_in(self):
        """X7 must reach module-load using the existing guest-only provider.

        Only external module commands are replaced: execute the real startup
        shell. The provider's explicit opt-in protects the host from loading
        the test module; the fixture must never load any host module.
        """
        guest = (GUEST / 'run-guest.sh').read_text()
        boundary = guest.find('# Real registry KUnit rows')
        self.assertGreater(boundary, 0, 'actual guest startup boundary missing')
        external = '''modprobe() { :; }
lsmod() { printf 'thunderbolt 1 0\\nxdev_ext_xdomain 1 0\\n'; }
insmod() {
    [ "$1" = ./xdev_ext_peer_sw.ko ] && [ "$#" -eq 2 ] && [ "$2" = guest_only=1 ]
}
export XDEV_EXT_XDOMAIN_GUEST=1
'''
        with tempfile.TemporaryDirectory(prefix='x7-provider-startup-') as tmp:
            result = subprocess.run(['sh', '-c', external + guest[:boundary],
                                     'fixture', tmp], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('XDEV_EXT_XDOMAIN_CASE=PASS name=module-load', result.stdout)

    def test_actual_guest_dmesg_gate_distinguishes_enable_banner_and_warning(self):
        guest = (GUEST / 'run-guest.sh').read_text()
        boundary = guest.find('dmesg > /tmp/xdomain-final-dmesg')
        self.assertGreater(boundary, 0, 'actual final dmesg gate missing')
        with tempfile.TemporaryDirectory(prefix='x7-final-dmesg-') as tmp:
            block = guest[boundary:].replace('/tmp/xdomain-final-dmesg', tmp + '/dmesg')
            commands = '''dmesg() { printf '%s\\n' "$X7_DMESG"; }
pass() { echo "XDEV_EXT_XDOMAIN_CASE=PASS name=$1"; }
fail() { echo "XDEV_EXT_XDOMAIN_CASE=FAIL name=$1"; exit 1; }
'''
            for message, want in (
                ('rcu: RCU lockdep checking is enabled.', 0),
                ('WARNING: possible circular locking dependency detected', 1),
            ):
                with self.subTest(message=message):
                    result = subprocess.run(['sh', '-c', commands + 'X7_DMESG=$1\n' + block,
                                             'fixture', message], text=True, capture_output=True)
                    self.assertEqual(result.returncode, want, result.stdout + result.stderr)

    def test_actual_option_parser_selects_xdomain(self):
        end = self.harness.find('\n# Fence checks')
        self.assertGreater(end, 0, 'actual option parser boundary missing')
        result = subprocess.run(['bash', '-c', self.harness[:end] + '\nprintf "selected=%s\\n" "${XDOMAIN:-missing}"\n', 'fixture', '--xdomain'], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('selected=1', result.stdout)

    def config_fragment(self, drop=''):
        start = self.harness.find('if (( ! RUN_ONLY )); then\n\tkmake defconfig')
        self.assertGreaterEqual(start, 0, 'actual config block missing')
        match = re.search(r'^\s*if \(\( PREPARE_ONLY \)\); then.*?; fi\s*$', self.harness[start:], re.M)
        self.assertIsNotNone(match, 'actual prepare-only boundary missing')
        block = self.harness[start:start + match.end()] + '\nfi\n'
        with tempfile.TemporaryDirectory(prefix='x7-config-') as tmp:
            root = Path(tmp)
            (root / 'scripts').mkdir()
            (root / 'build').mkdir()
            # External scripts/config double has no expected-symbol list.
            tool = root / 'scripts/config'
            tool.write_text('''#!/usr/bin/env python3
import pathlib, sys
args=sys.argv[1:]
p=pathlib.Path(args[1]); args=args[2:]
values=dict(line.split('=',1) for line in p.read_text().splitlines() if '=' in line)
i=0
while i < len(args):
    op, symbol=args[i:i+2]; i+=2
    if op in ('-e','-m','-d'):
        values['CONFIG_'+symbol]={'-e':'y','-m':'m','-d':'n'}[op]
    elif op == '--set-str': i+=1
    else: raise SystemExit('unknown scripts/config operation '+op)
p.write_text(''.join(k+'='+v+'\\n' for k,v in values.items()))
''')
            tool.chmod(0o700)
            (root / 'debug.py').write_text('# Debug profile validation is a separate contract.\n')
            prefix = '''set -euo pipefail
SRC=$1; BUILD=$SRC/build; EV=$SRC; DEBUG_HELPER=$SRC/debug.py
XDOMAIN=1; MECHANISM_VARIANTS=0; RUN_ONLY=0; CE_SIM=0; LIFECYCLE=0; FENCE_CHECK=0
SOCKET_REQUIRED=0; COMPAT=0; PEER=0; DEBUG_LOCKING=1; PREPARE_ONLY=1
PROVIDER_CASE=normal
verify_socket_config() { :; }
kmake() {
    if [[ $1 == defconfig ]]; then : > "$BUILD/.config"; fi
    if [[ $1 == olddefconfig && -n ${DROP_SYMBOL:-} ]]; then
        sed -i "/^CONFIG_${DROP_SYMBOL}=/d" "$BUILD/.config"
    fi
}
'''
            prefix += 'DROP_SYMBOL=' + drop + '\n'
            result = subprocess.run(['bash', '-c', prefix + block, 'fixture', str(root)], text=True, capture_output=True)
            return result, (root / 'build/.config').read_text()

    def test_actual_config_requests_full_module_and_debug_dependencies(self):
        result, config = self.config_fragment()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)
        actual = dict(line.split('=', 1) for line in config.splitlines())
        for symbol, value in MANIFEST['required_config'].items():
            with self.subTest(symbol=symbol):
                self.assertEqual(actual.get('CONFIG_' + symbol), value)

    def test_olddefconfig_cannot_silently_drop_module_or_p2pdma(self):
        for symbol in ('PCI_P2PDMA', 'XDEV_EXT_MECH_XDOMAIN'):
            with self.subTest(symbol=symbol):
                result, _ = self.config_fragment(drop=symbol)
                self.assertNotEqual(result.returncode, 0, 'actual config admission accepted dropped ' + symbol)
                self.assertNotIn('XDEV_EXT_ZC_CONFIG=PASS', result.stdout)

    def test_kernel_make_selects_gcc_for_target_and_host(self):
        match = re.search(r'^kmake\(\) \{ (.*?) \}$', self.harness, re.M)
        self.assertIsNotNone(match, 'actual kmake function missing')
        script = 'SRC=/fixture; BUILD=/fixture/build\nlowprio() { printf "%s\\n" "$@"; }\n' + match.group(0) + '\nkmake vmlinux\n'
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r'(?m)^CC=gcc(?:-[0-9]+)?$')
        self.assertRegex(result.stdout, r'(?m)^HOSTCC=gcc(?:-[0-9]+)?$')


class ActualRunnerDependencies(unittest.TestCase):
    """Exercise the runner's real dependency function with actual ELF files."""
    @classmethod
    def setUpClass(cls):
        cls.runner = GUEST / 'xdomain_kvm.sh'
        cls.runner_source = cls.runner.read_text()

    def collect(self, binary, destination):
        match = re.search(r'^collect_xdomain_libraries\(\)\s*\{.*?^\}',
                          self.runner_source, re.M | re.S)
        self.assertIsNotNone(match, 'actual collect_xdomain_libraries(binary, destination) missing')
        return subprocess.run(['bash', '-c', 'set -euo pipefail\n' + match.group(0) +
                               '\ncollect_xdomain_libraries "$1" "$2"\n',
                               'fixture', str(binary), str(destination)],
                              text=True, capture_output=True)

    def test_actual_static_busybox_needs_no_libraries(self):
        elf = subprocess.run(['readelf', '-l', '/bin/busybox'], text=True, capture_output=True)
        self.assertEqual(elf.returncode, 0, elf.stderr)
        self.assertNotIn('INTERP', elf.stdout, 'fixture requires actual static BusyBox')
        with tempfile.TemporaryDirectory(prefix='x7-static-elf-') as tmp:
            dest = Path(tmp) / 'libraries'
            result = self.collect('/bin/busybox', dest)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(dest.exists() and dest.read_text().strip())

    def test_actual_dynamic_true_collects_existing_libraries(self):
        with tempfile.TemporaryDirectory(prefix='x7-dynamic-elf-') as tmp:
            dest = Path(tmp) / 'libraries'
            result = self.collect('/bin/true', dest)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(dest.is_file(), result.stdout + result.stderr)
            libraries = dest.read_text().splitlines()
            self.assertTrue(libraries)
            for library in libraries:
                self.assertTrue(Path(library).is_absolute() and Path(library).is_file(), library)

    def test_actual_elf_with_missing_shared_library_is_setup_failure(self):
        with tempfile.TemporaryDirectory(prefix='x7-missing-elf-') as tmp:
            root = Path(tmp)
            (root / 'dep.c').write_text('int x7_dependency(void) { return 0; }\n')
            (root / 'main.c').write_text('extern int x7_dependency(void); int main(void) { return x7_dependency(); }\n')
            for command in (
                ['gcc', '-shared', '-fPIC', str(root / 'dep.c'), '-o', str(root / 'libx7_missing.so')],
                ['gcc', str(root / 'main.c'), '-L' + tmp, '-Wl,-rpath,' + tmp,
                 '-lx7_missing', '-o', str(root / 'dynamic')],
            ):
                built = subprocess.run(command, text=True, capture_output=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            (root / 'libx7_missing.so').unlink()
            missing = subprocess.run(['ldd', str(root / 'dynamic')], text=True, capture_output=True)
            self.assertIn('libx7_missing.so => not found', missing.stdout + missing.stderr)
            result = self.collect(root / 'dynamic', root / 'libraries')
            self.assertNotEqual(result.returncode, 0, 'missing real ELF dependency accepted')

    def test_failed_actual_runner_cannot_retain_previous_pass(self):
        source = subprocess.run(['git', '-C', str(GUEST), 'rev-parse', '--show-toplevel'],
                                text=True, capture_output=True, check=True).stdout.strip()
        with tempfile.TemporaryDirectory(prefix='x7-stale-verdict-') as tmp:
            root = Path(tmp)
            ev = root / 'xdomain-evidence'
            ev.mkdir()
            result_path = ev / 'result.json'
            result_path.write_text('{"status":"PASS","sentinel":"previous-run"}\n')
            result = subprocess.run(['bash', str(self.runner), '--scratch', tmp,
                                     '--source', source, '--build', tmp + '/absent-build',
                                     '--tools', tmp + '/absent-tools'], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            if result_path.exists():
                self.assertNotEqual(json.loads(result_path.read_text()).get('status'), 'PASS',
                                    'failed actual runner retained previous PASS')


if __name__ == '__main__':
    unittest.main(verbosity=2)
