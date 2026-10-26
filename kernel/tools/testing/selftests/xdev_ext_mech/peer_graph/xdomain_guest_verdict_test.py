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


class FrozenInventory(unittest.TestCase):
    def test_matrix_has_all_forty_unique_rows(self):
        self.assertEqual(len(NAMES), 40)
        self.assertEqual(len(set(NAMES)), 40)
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
XDOMAIN=1; RUN_ONLY=0; CE_SIM=0; LIFECYCLE=0; FENCE_CHECK=0
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
