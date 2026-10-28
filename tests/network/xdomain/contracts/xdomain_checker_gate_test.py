#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""X7 must compile, package, attach, diagnose and detach both full objects.

Requirement: closure plan sections 8/11 require the full reference and observer
objects to reach the matching real verifier; an omitted/failed observer cannot
produce a successful X7 receipt.

Test plan (frozen before implementation): execute the guest Makefile against
recording compiler/BTF boundaries; execute the real guest shell with only the
external module/loader commands controlled; exercise the actual receipt parser.
The initramfs copy is checked as a source wiring contract only. This test does
NOT certify actual ELF compilation, kernel BTF compatibility or verifier success:
those remain the separately required root integration execution.

Breaks caught: omitted observer compile/copy/attach, ignored attach error,
missing object accepted, missing diagnostics/detach, observer omitted from the
required receipt inventory. No checker implementation internals are inspected.
"""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]
GUEST = HERE.parent / 'xdomain' / 'guest'
OBSERVER = 'observer-attach'
OBJECTS = ('xdomain_peer.bpf.o', 'xdomain_check.bpf.o')


def executable(path, source):
    path.write_text(source)
    path.chmod(0o700)


class CheckerGate(unittest.TestCase):
    def test_make_compiles_both_full_sources_from_selected_btf(self):
        """Removing either full source compilation must fail this contract."""
        with tempfile.TemporaryDirectory(prefix='xd-check-build-') as temp:
            root = Path(temp)
            compiler = root / 'compiler'
            executable(compiler, '''#!/usr/bin/python3
import json, os, pathlib, sys
with open(os.environ['COMPILE_TRACE'], 'a') as out:
    out.write(json.dumps(sys.argv[1:]) + '\\n')
args = sys.argv[1:]
if '-o' in args:
    dest = pathlib.Path(args[args.index('-o') + 1])
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b'external-compiler-boundary')
''')
            btf = root / 'selected-kernel-vmlinux'
            btf.write_bytes(b'matched-kernel-BTF-boundary')
            bpftool = root / 'bpftool'
            executable(bpftool, '''#!/usr/bin/python3
import json, os, sys
with open(os.environ['BTF_TRACE'], 'w') as out:
    json.dump(sys.argv[1:], out)
print('/* controlled BTF dump boundary */')
''')
            env = dict(os.environ, COMPILE_TRACE=str(root / 'compiles'),
                       BTF_TRACE=str(root / 'btf-command'))
            result = subprocess.run([
                'make', '-C', str(GUEST), 'all', 'OUT=' + str(root / 'out'),
                'KERNEL_SRC=' + str(KERNEL), 'VMLINUX_BTF=' + str(btf),
                'CLANG=' + str(compiler), 'HOSTCC=' + str(compiler),
                'BPFTOOL=' + str(bpftool)], env=env, capture_output=True,
                text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads((root / 'btf-command').read_text()),
                             ['btf', 'dump', 'file', str(btf), 'format', 'c'])
            calls = [json.loads(line) for line in (root / 'compiles').read_text().splitlines()]
            for obj in OBJECTS:
                source = str(KERNEL / 'tools' / 'xdev_ext_mech' / obj.replace('.o', '.c'))
                matching = [args for args in calls if '-c' in args and source in args]
                self.assertEqual(len(matching), 1, 'full source was not compiled exactly once: ' + source)
                args = matching[0]
                self.assertEqual(args[args.index('-o') + 1], str(root / 'out' / obj))
                self.assertIn('-I' + str(root / 'out'), args,
                              'must use header dumped from selected matching kernel BTF')

    def test_initramfs_copy_includes_both_built_objects(self):
        """Source wiring boundary only; this does not execute an initramfs."""
        script = (GUEST / 'xdomain_kvm.sh').read_text()
        # Check the actual copy statement into the guest, allowing one wildcard
        # or explicit object names; comments and unrelated mentions do not count.
        statements = script.replace('\\\n', ' ').splitlines()
        copies = [line for line in statements if re.match(r'^\s*cp\s', line)
                  and 'opt/xdomain/' in line]
        self.assertTrue(copies, 'guest artifact copy is missing')
        inputs = ' '.join(copies)
        for obj in OBJECTS:
            self.assertTrue(obj in inputs or re.search(r'\*\.bpf\.o', inputs),
                            'initramfs does not package ' + obj)
        # The build invocation must select this run's matching BTF, rather than
        # defaulting to the host running the packaging command.
        build = re.search(r'^make\s[^\n]+', script.replace('\\\n', ' '), re.M)
        self.assertIsNotNone(build, 'guest BPF build invocation is missing')
        self.assertIn('VMLINUX_BTF="$BUILD/vmlinux"', build.group())

    def run_guest(self, *, missing=False, reject=False, matrix_name=None,
                  diagnostic='', loader_exit=1, dmesg_extra=''):
        with tempfile.TemporaryDirectory(prefix='xd-check-guest-') as temp:
            root = Path(temp)
            bindir = root / 'bin'
            bindir.mkdir()
            (root / 'tmp').mkdir()
            (root / 'vmlinux').write_bytes(b'matching BTF boundary')
            trace = root / 'trace'
            boundary = '''#!/usr/bin/python3
import os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path(os.environ['GATE_ROOT'])
if name == 'lsmod':
    print('thunderbolt 1 0')
    if not (root / 'removed').exists(): print('xdev_ext_xdomain 1 0')
elif name == 'rmmod' and sys.argv[1] == 'xdev_ext_xdomain':
    (root / 'removed').touch()
elif name == 'dmesg':
    for n in ('active_unregister','next_unregister','data_lifetime','callback_registration','reregister','return_semantics'):
        print('ok 1 tb_test_protocol_' + n)
    sys.stdout.write(os.environ.get('GATE_DMESG_EXTRA', ''))
'''
            for command in ('modprobe', 'lsmod', 'insmod', 'rmmod', 'dmesg', 'sleep'):
                executable(bindir / command, boundary)
            # Model the real single registration slot for each class. The
            # complete load helper owns a transient link and destroys it before
            # returning; ctl attach leaves a pinned link until ctl detach.
            loader_boundary = r'''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['GATE_ROOT'])
args = sys.argv[1:]
command = pathlib.Path(sys.argv[0]).name
trace = pathlib.Path(os.environ['GATE_TRACE'])
def record(row):
    with trace.open('a') as out: out.write(json.dumps(row) + '\n')
record(['load' if command == 'load' else 'ctl'] + args)
state = root / 'slots.json'
slots = json.loads(state.read_text()) if state.exists() else {}
def save(): state.write_text(json.dumps(slots))
if command == 'load':
    if len(args) != 2: sys.exit(3)
    obj, mapname = pathlib.Path(args[0]), args[1]
    if obj.name == os.environ.get('GATE_MATRIX_NAME', '') + '.bpf.o':
        if not obj.is_file() or mapname != 'probe_ops': sys.exit(3)
        print(os.environ['GATE_DIAGNOSTIC'], file=sys.stderr, flush=True)
        sys.exit(int(os.environ['GATE_LOADER_EXIT']))
    print('VERIFIER_DIAGNOSTIC object=' + obj.name, flush=True)
    print('libbpf: DEBUG ' + 'V' * 24000 + ' DEBUG_END object=' + obj.name, file=sys.stderr, flush=True)
    if not obj.is_file(): sys.exit(3)
    if mapname != 'xdomain_peer_ops': sys.exit(3)
    if obj.name == 'xdomain_check.bpf.o' and os.environ['GATE_REJECT'] == '1': sys.exit(1)
    if mapname in slots:
        print('XDOMAIN_SETUP_FAIL EBUSY class=' + mapname, flush=True)
        sys.exit(3)
    slots[mapname] = 'load:' + obj.name
    save()
    record(['load-attach', obj.name, mapname])
    del slots[mapname]
    save()
    record(['load-detach', obj.name, mapname])
    print('XDOMAIN_LOAD_ALLOW', flush=True)
elif args[0] == 'attach':
    obj = pathlib.Path(args[args.index('--obj') + 1])
    mapname = args[args.index('--map') + 1]
    pin = args[args.index('--pin') + 1]
    # ctl's diagnostic boundary is deliberately shorter than load's full
    # logger; substituting ctl cannot satisfy complete diagnostic forwarding.
    print('VERIFIER_DIAGNOSTIC object=' + obj.name, flush=True)
    if not obj.is_file(): sys.exit(9)
    if obj.name == 'xdomain_check.bpf.o' and os.environ['GATE_REJECT'] == '1': sys.exit(10)
    if mapname in slots:
        print('XDOMAIN_SETUP_FAIL EBUSY class=' + mapname, flush=True)
        sys.exit(16)
    slots[mapname] = pin
    save()
elif args[0] == 'detach':
    pin = args[args.index('--pin') + 1]
    for mapname in list(slots):
        if slots[mapname] == pin: del slots[mapname]
    save()
elif args[0] == 'xdomain-probe':
    if 'xdomain_peer_ops' not in slots: sys.exit(19)
    print('XDEV_EXT_XDOMAIN_CREATE errno=' + ('-19' if args[args.index('--link') + 1] == '1' else '-22'))
'''
            executable(root / 'xdev_ext_mech_ctl', loader_boundary)
            executable(root / 'load', loader_boundary)
            (root / 'matrix.txt').write_text(matrix_name + ' DENY\n' if matrix_name else '')
            if matrix_name:
                (root / (matrix_name + '.bpf.o')).write_bytes(b'negative-object-boundary')
            for name in (*OBJECTS, 'nvme_s0.bpf.o'):
                if not (missing and name == 'xdomain_check.bpf.o'):
                    (root / name).write_bytes(b'object-boundary')
            # Remap absolute environment paths only; shell control flow and
            # loader commands are copied unchanged from the real guest runner.
            script = (GUEST / 'run-guest.sh').read_text()
            script = script.replace('/tmp/', str(root / 'tmp') + '/')
            script = script.replace('/sys/kernel/btf/vmlinux', str(root / 'vmlinux'))
            (root / 'run.sh').write_text(script)
            env = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'],
                       XDEV_EXT_XDOMAIN_GUEST='1', GATE_ROOT=str(root),
                       GATE_TRACE=str(trace), GATE_REJECT='1' if reject else '0',
                       GATE_MATRIX_NAME=matrix_name or '', GATE_DIAGNOSTIC=diagnostic,
                       GATE_LOADER_EXIT=str(loader_exit), GATE_DMESG_EXTRA=dmesg_extra)
            result = subprocess.run(['sh', str(root / 'run.sh'), str(root)],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertTrue(trace.exists(), 'guest did not reach loader boundary: ' + result.stdout + result.stderr)
            calls = [json.loads(line) for line in trace.read_text().splitlines()]
            return result, calls

    def test_full_objects_have_named_receipts_complete_diagnostics_and_detach(self):
        result, calls = self.run_guest()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for obj, name in zip(OBJECTS, ('reference-attach', OBSERVER)):
            self.assertIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)
            self.assertIn('VERIFIER_DIAGNOSTIC object=' + obj, result.stdout)
            self.assertIn('libbpf: DEBUG ' + 'V' * 24000 + ' DEBUG_END object=' + obj,
                          result.stdout, 'full DEBUG verifier diagnostic was lost or truncated')
            loads = [(i, args) for i, args in enumerate(calls)
                     if args[0] == 'load' and len(args) == 3
                     and Path(args[1]).name == obj]
            self.assertEqual(len(loads), 1, 'full object must use complete load logger once: ' + obj)
            index, args = loads[0]
            self.assertEqual(args[2], 'xdomain_peer_ops')
            self.assertIn(['load-attach', obj, 'xdomain_peer_ops'], calls[index + 1:])
            self.assertIn(['load-detach', obj, 'xdomain_peer_ops'], calls[index + 1:])

    def test_full_object_verifiers_release_class_slot_before_reference_probes(self):
        result, calls = self.run_guest()
        self.assertEqual(result.returncode, 0,
                         'sequential verification must not encounter an occupied class slot: ' + result.stdout)
        ref_done = calls.index(['load-detach', OBJECTS[0], 'xdomain_peer_ops'])
        observer_start = next(i for i, row in enumerate(calls)
                              if row[0] == 'load' and Path(row[1]).name == OBJECTS[1])
        observer_done = calls.index(['load-detach', OBJECTS[1], 'xdomain_peer_ops'])
        probe_ref = [(i, row) for i, row in enumerate(calls)
                     if row[:2] == ['ctl', 'attach'] and '--obj' in row
                     and Path(row[row.index('--obj') + 1]).name == OBJECTS[0]]
        self.assertEqual(len(probe_ref), 1, 'CREATE probes require one additional reference registration')
        probe_ref_index, attach = probe_ref[0]
        self.assertLess(ref_done, observer_start)
        self.assertLess(observer_done, probe_ref_index,
                        'reference probe link must not occupy the class slot during observer verification')
        probes = [i for i, row in enumerate(calls) if row[:2] == ['ctl', 'xdomain-probe']]
        self.assertEqual(len(probes), 2)
        pin = attach[attach.index('--pin') + 1]
        detach = next(i for i, row in enumerate(calls)
                      if row[:2] == ['ctl', 'detach'] and '--pin' in row
                      and row[row.index('--pin') + 1] == pin)
        self.assertTrue(all(probe_ref_index < i < detach for i in probes))

    def test_missing_observer_object_cannot_pass(self):
        result, _ = self.run_guest(missing=True)
        self.assertNotEqual(result.returncode, 0, 'missing full observer object silently passed')
        self.assertNotIn('XDEV_EXT_XDOMAIN_CASE=PASS name=observer-attach', result.stdout)

    def test_observer_attach_failure_cannot_pass(self):
        result, _ = self.run_guest(reject=True)
        self.assertNotEqual(result.returncode, 0, 'observer loader rejection silently passed')
        self.assertNotIn('XDEV_EXT_XDOMAIN_CASE=PASS name=observer-attach', result.stdout)
        self.assertIn('VERIFIER_DIAGNOSTIC object=xdomain_check.bpf.o', result.stdout)

    def test_sleepable_exact_unsupported_member_is_real_verifier_deny(self):
        name = 'xdomain-complete-sleepable-deny'
        diagnostic = ('-- BEGIN PROG LOAD LOG --\n'
                      'attach to unsupported member complete of struct xdev_ext_xdomain_mech_ops\n'
                      'processed 0 insns (limit 1000000)\n'
                      '-- END PROG LOAD LOG --')
        result, calls = self.run_guest(matrix_name=name, diagnostic=diagnostic)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('XDOMAIN_OBJECT_END name=' + name + ' loader_exit=1', result.stdout)
        self.assertIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)
        self.assertIn(diagnostic, result.stdout, 'complete verifier log must remain visible')
        self.assertIn(['load', './' + name + '.bpf.o', 'probe_ops'], calls)

    def test_unsupported_member_exception_is_exact_and_never_hides_setup_failure(self):
        exact = 'attach to unsupported member complete of struct xdev_ext_xdomain_mech_ops'
        # Literal counterexamples freeze the exception's narrow scope. A real
        # denial diagnostic cannot compensate for an ELF/BTF/setup failure.
        cases = [
            ('xdomain-complete-sleepable-deny', '', 1),
            ('xdomain-complete-sleepable-deny',
             'attach to unsupported member build of struct xdev_ext_xdomain_mech_ops', 1),
            ('xdomain-complete-sleepable-deny',
             'attach to unsupported member complete of struct xdev_ext_nvme_mech_ops', 1),
            ('helper-timer-init-deny', exact, 1),
            ('xdomain-complete-sleepable-deny', exact + '\nfailed to open ELF object', 1),
            ('xdomain-complete-sleepable-deny', exact + '\nfailed to find valid kernel BTF', 1),
            ('xdomain-complete-sleepable-deny', exact + '\nXDOMAIN_SETUP_FAIL missing module', 1),
            ('xdomain-complete-sleepable-deny', exact, 3),
        ]
        for name, diagnostic, code in cases:
            with self.subTest(name=name, diagnostic=diagnostic, loader_exit=code):
                result, _ = self.run_guest(matrix_name=name, diagnostic=diagnostic,
                                           loader_exit=code)
                self.assertNotEqual(result.returncode, 0,
                                    'unrecognized denial/setup was accepted: ' + result.stdout)
                self.assertNotIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)

    def test_helper_type_denials_match_each_of_the_six_explicit_cases(self):
        pairs = (
            ('helper-timer-init-deny', 'bpf_timer_init'),
            ('helper-timer-start-deny', 'bpf_timer_start'),
            ('helper-tail-call-deny', 'bpf_tail_call'),
            ('helper-probe-read-kernel-deny', 'bpf_probe_read_kernel'),
            ('helper-probe-read-user-deny', 'bpf_probe_read_user'),
            ('helper-ringbuf-output-deny', 'bpf_ringbuf_output'),
        )
        for name, helper in pairs:
            diagnostic = ('-- BEGIN PROG LOAD LOG --\n'
                          'program of this type cannot use helper ' + helper + '#169\n'
                          'processed 0 insns (limit 1000000)\n'
                          '-- END PROG LOAD LOG --')
            with self.subTest(case=name, helper=helper):
                result, _ = self.run_guest(matrix_name=name, diagnostic=diagnostic)
                # Keep preceding long DEBUG logs out of failure summaries while
                # the separate full-object test still verifies every byte.
                summary = '\n'.join(line for line in result.stdout.splitlines()
                                    if not line.startswith('libbpf: DEBUG '))
                self.assertEqual(result.returncode, 0, summary + result.stderr)
                self.assertIn('XDOMAIN_OBJECT_END name=' + name + ' loader_exit=1', result.stdout)
                self.assertIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)
                self.assertIn(diagnostic, result.stdout)

    def test_helper_type_denial_exception_requires_matching_case_complete_log_and_no_setup_failure(self):
        pairs = (
            ('helper-timer-init-deny', 'bpf_timer_init'),
            ('helper-timer-start-deny', 'bpf_timer_start'),
            ('helper-tail-call-deny', 'bpf_tail_call'),
            ('helper-probe-read-kernel-deny', 'bpf_probe_read_kernel'),
            ('helper-probe-read-user-deny', 'bpf_probe_read_user'),
            ('helper-ringbuf-output-deny', 'bpf_ringbuf_output'),
        )
        def log(helper, number='169'):
            return ('-- BEGIN PROG LOAD LOG --\n'
                    'program of this type cannot use helper ' + helper + '#' + number + '\n'
                    'processed 0 insns (limit 1000000)\n'
                    '-- END PROG LOAD LOG --')
        cases = []
        for index, (name, helper) in enumerate(pairs):
            wrong_helper = pairs[(index + 1) % len(pairs)][1]
            cases.append(('wrong-helper-' + helper, name, log(wrong_helper), 1))
        valid = log('bpf_timer_init')
        cases.extend([
            ('wrong-case', 'xdomain-complete-sleepable-deny', valid, 1),
            ('missing-end', 'helper-timer-init-deny', valid.replace('-- END PROG LOAD LOG --', ''), 1),
            ('missing-begin', 'helper-timer-init-deny', valid.replace('-- BEGIN PROG LOAD LOG --', ''), 1),
            ('missing-diagnostic', 'helper-timer-init-deny', '-- BEGIN PROG LOAD LOG --\nprocessed 0 insns\n-- END PROG LOAD LOG --', 1),
            ('zero-helper-id', 'helper-timer-init-deny', log('bpf_timer_init', '0'), 1),
            ('negative-helper-id', 'helper-timer-init-deny', log('bpf_timer_init', '-1'), 1),
            ('nonnumeric-helper-id', 'helper-timer-init-deny', log('bpf_timer_init', 'invalid'), 1),
            ('suffix-helper-id', 'helper-timer-init-deny', log('bpf_timer_init', '169x'), 1),
            ('setup-error', 'helper-timer-init-deny', valid + '\nXDOMAIN_SETUP_FAIL missing module', 1),
            ('elf-error', 'helper-timer-init-deny', valid + '\nfailed to open ELF object', 1),
            ('btf-error', 'helper-timer-init-deny', valid + '\nfailed to find valid kernel BTF', 1),
            ('loader-setup-exit', 'helper-timer-init-deny', valid, 3),
        ])
        for problem, name, diagnostic, code in cases:
            with self.subTest(problem=problem, case=name):
                result, _ = self.run_guest(matrix_name=name, diagnostic=diagnostic, loader_exit=code)
                self.assertNotEqual(result.returncode, 0, 'invalid helper denial was accepted: ' + problem)
                self.assertNotIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)

    def test_actual_guest_accepts_only_exact_healthy_kasan_startup_banner(self):
        healthy = 'kasan: KernelAddressSanitizer initialized'
        for banner in (healthy + '\n', '[    0.141815] ' + healthy + '\n',
                       healthy + '\r\n', '[    0.141815] ' + healthy + '\r\n'):
            with self.subTest(banner=repr(banner)):
                result, _ = self.run_guest(dmesg_extra=banner)
                summary = '\n'.join(line for line in result.stdout.splitlines()
                                    if not line.startswith('libbpf: DEBUG '))
                self.assertEqual(result.returncode, 0, summary + result.stderr)
                self.assertIn('XDEV_EXT_XDOMAIN_CASE=PASS name=module-unload', result.stdout)

    def test_actual_guest_still_rejects_kasan_faults_unknown_messages_and_other_kernel_errors(self):
        healthy = '[    0.141815] kasan: KernelAddressSanitizer initialized'
        diagnostics = (
            'KASAN: use-after-free in xdomain',
            '[    1.000001] kasan: unknown allocator state',
            healthy + ' ERROR trailing fault',
            'prefix kasan: KernelAddressSanitizer initialized',
            '[not-a-time] kasan: KernelAddressSanitizer initialized',
            healthy + '\nBUG: bad page state',
            healthy + '\nWARNING: suspicious RCU usage',
        )
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                result, _ = self.run_guest(dmesg_extra=diagnostic + '\r\n')
                self.assertNotEqual(result.returncode, 0, 'kernel diagnostic was ignored: ' + diagnostic)
                self.assertNotIn('XDEV_EXT_XDOMAIN_CASE=PASS name=module-unload', result.stdout)

    def test_required_inventory_names_observer(self):
        cases = json.loads((GUEST / 'cases.json').read_text())['cases']
        rows = [row for row in cases if row['name'] == OBSERVER]
        self.assertEqual(len(rows), 1, 'observer-attach is absent from required case inventory')
        self.assertEqual(rows[0]['expected'], 'PASS')

    def test_receipt_gate_rejects_missing_observer(self):
        validate = runpy.run_path(str(GUEST / 'verdict.py'))['validate']
        names = [row['name'] for row in json.loads((GUEST / 'cases.json').read_text())['cases']]
        without = '\n'.join('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name
                            for name in names if name != OBSERVER)
        with self.assertRaises(ValueError, msg='receipt gate accepted no observer verifier case'):
            validate(without)
        complete = without + '\nXDEV_EXT_XDOMAIN_CASE=PASS name=observer-attach\n'
        self.assertEqual(validate(complete)['status'], 'PASS')


if __name__ == '__main__':
    unittest.main(verbosity=2)
