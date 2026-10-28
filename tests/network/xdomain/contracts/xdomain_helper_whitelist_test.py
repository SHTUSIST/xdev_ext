#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""TODO.27-a X7 requirement, independent of the old ALLOW inventory.

Execute the actual guest shell with only external loaders/modules controlled.
Exact helper refusal must be inside a complete verifier log. These are runner
tests; a synthetic loader boundary never certifies a real kernel rejection.
"""
import importlib.util
import json
import os
import re
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest


def canonical_root():
    if os.environ.get('XDEV_EXT_CANONICAL_ROOT'):
        return Path(os.environ['XDEV_EXT_CANONICAL_ROOT'])
    return next(p for p in Path(__file__).resolve().parents
                if (p / 'source-layout.json').is_file())


ROOT = canonical_root()
CONTRACTS = ROOT / 'tests/network/xdomain/contracts'
GUEST = ROOT / 'tests/network/xdomain/stack/guest'
NEW = 'helper-existing-class-control-deny'
OLD = 'helper-existing-class-control-allow'
# Frozen from the requirements, including every preserved class/member/memory
# row. Computing expected names from the changing manifest would miss a drop.
EXPECTED_NAMES = frozenset('''module-load reference-attach observer-attach
link-1-enodev link-0-einval module-unload
rel-tx-state-nvme-deny rel-tx-state-xdomain-allow
private-info-xdomain-build-deny private-info-xdomain-prepare-deny
private-info-xdomain-complete-allow private-info-nvme-complete-deny
private-info-net-complete-deny private-info-af-xdp-complete-deny
private-info-socket-complete-deny private-verdict-xdomain-build-deny
private-verdict-xdomain-prepare-deny private-verdict-xdomain-complete-allow
private-verdict-nvme-complete-deny private-verdict-net-complete-deny
private-verdict-af-xdp-complete-deny private-verdict-socket-complete-deny
xdomain-complete-sleepable-deny xdomain-complete-nonsleepable-allow
helper-map-lookup-allow helper-timer-init-deny helper-timer-start-deny
helper-tail-call-deny helper-probe-read-kernel-deny helper-probe-read-user-deny
helper-ringbuf-output-deny helper-existing-class-control-deny
memory-ctx-write-deny memory-oob-info-deny memory-oob-verdict-deny
memory-uninit-info-privileged-allow memory-uninit-verdict-privileged-allow
memory-readonly-map-info-deny memory-readonly-map-verdict-deny
memory-initialized-local-info-allow memory-initialized-local-verdict-allow'''.split())


def module_at(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receipt(names):
    return ''.join('XDEV_EXT_XDOMAIN_CASE=PASS name=' + n + '\n' for n in sorted(names))


def diagnostic(helper='bpf_probe_read_kernel', number='113'):
    return ('-- BEGIN PROG LOAD LOG --\n'
            'program of this type cannot use helper ' + helper + '#' + number + '\n'
            '-- END PROG LOAD LOG --\n')


# Hand-written negative examples exercise distinct oracle breaks. Wrong IDs and
# wrong helpers are valid-looking diagnostics which must not certify this case.
DENIAL_VECTORS = {
    'wrong-id': diagnostic(number='114'),
    'wrong-helper': diagnostic(helper='bpf_probe_read_user', number='112'),
    'outside-region': ('program of this type cannot use helper bpf_probe_read_kernel#113\n'
                       '-- BEGIN PROG LOAD LOG --\nprocessed 0 insns\n-- END PROG LOAD LOG --\n'),
    'generic-fallback': ('-- BEGIN PROG LOAD LOG --\n'
                         'calling kernel function bpf_unrelated is not allowed\n'
                         '-- END PROG LOAD LOG --\n'),
    'missing-end': diagnostic().replace('-- END PROG LOAD LOG --\n', ''),
    'missing-begin': diagnostic().replace('-- BEGIN PROG LOAD LOG --\n', ''),
    'reversed-markers': ('-- END PROG LOAD LOG --\n'
                          'program of this type cannot use helper bpf_probe_read_kernel#113\n'
                          '-- BEGIN PROG LOAD LOG --\n'),
    'zero-id': diagnostic(number='0'),
    'negative-id': diagnostic(number='-113'),
    'id-suffix': diagnostic(number='113x'),
    'setup-failure': diagnostic() + 'XDOMAIN_SETUP_FAIL missing module\n',
    'elf-failure': diagnostic() + 'failed to open ELF object\n',
    'btf-failure': diagnostic() + 'failed to find valid kernel BTF\n',
}


class HelperWhitelistX7(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = module_at('helper_x7_parser', GUEST / 'verdict.py')
        cls.gates = module_at('helper_x7_gates', CONTRACTS / 'xdomain_checker_gate_test.py')
        cls.gates.GUEST = GUEST

    def gate(self, name, log, exit_code=1):
        gate = self.gates.CheckerGate()
        result, _ = gate.run_guest(matrix_name=name, diagnostic=log, loader_exit=exit_code)
        return result

    def test_manifest_keeps_all_41_rows_and_replaces_only_shared_control(self):
        rows = json.loads((GUEST / 'cases.json').read_text())['cases']
        self.assertEqual(len(rows), 41)
        self.assertEqual({r['name'] for r in rows}, EXPECTED_NAMES)
        by_name = {r['name']: r for r in rows}
        self.assertEqual(by_name[NEW]['expected'], 'DENY')
        for name in EXPECTED_NAMES:
            if name.endswith('-deny'):
                self.assertEqual(by_name[name]['expected'], 'DENY', name)
            elif name.endswith('-allow'):
                self.assertEqual(by_name[name]['expected'], 'ALLOW', name)

    def test_new_41_row_receipt_is_accepted(self):
        self.assertEqual(len(EXPECTED_NAMES), 41)
        try:
            result = self.parser.validate(receipt(EXPECTED_NAMES))
        except ValueError as error:
            self.fail('required new 41-row receipt rejected: ' + str(error))
        self.assertEqual(result['status'], 'PASS')

    def test_old_allow_receipt_cannot_certify_new_policy(self):
        old = (EXPECTED_NAMES - {NEW}) | {OLD}
        with self.assertRaises(ValueError, msg='old ALLOW inventory still accepted'):
            self.parser.validate(receipt(old))

    def test_new_name_keeps_real_nvme_complete_kernel_read_call(self):
        source = runpy.run_path(str(GUEST / 'generate.py'))['source'](NEW)
        self.assertIn('struct xdev_ext_nvme_mech_ops probe_ops', source)
        self.assertIn('bpf_probe_read_kernel(&x, sizeof(x), (void *)0)', source)
        self.assertIn('bpf_map_lookup_elem(&values, &k)', source)
        self.assertIn('probe_complete', source)

    def test_exact_control_helper_denial_is_accepted(self):
        result = self.gate(NEW, diagnostic())
        self.assertEqual(result.returncode, 0, result.stdout[-2200:] + result.stderr)

    def test_exact_existing_xdomain_helper_denial_is_accepted(self):
        result = self.gate('helper-probe-read-kernel-deny', diagnostic())
        self.assertEqual(result.returncode, 0, result.stdout[-2200:] + result.stderr)

    def test_timer_start_denial_uses_linux_uapi_id_and_rejects_callback_id(self):
        """Catch a copied callback ID without repeating the runner's constants."""
        with tempfile.TemporaryDirectory(prefix='helper-uapi-id-') as temp:
            probe = Path(temp) / 'ids'
            source = ('#include <linux/bpf.h>\n#include <stdio.h>\n'
                      'int main(void) { printf("%u %u\\n", '
                      '(unsigned)BPF_FUNC_timer_start, '
                      '(unsigned)BPF_FUNC_timer_set_callback); return 0; }\n')
            compiled = subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra',
                                       '-Werror', '-x', 'c', '-', '-o', str(probe)],
                                      input=source, capture_output=True, text=True,
                                      timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ids = subprocess.run([str(probe)], check=True, capture_output=True,
                                 text=True, timeout=10).stdout.split()
        self.assertEqual(len(ids), 2)
        start_id, callback_id = ids
        self.assertNotEqual(start_id, callback_id)
        name = 'helper-timer-start-deny'
        valid = diagnostic(helper='bpf_timer_start', number=start_id)
        result = self.gate(name, valid)
        self.assertEqual(result.returncode, 0, result.stdout[-2200:] + result.stderr)
        self.assertIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)
        invalid = {
            'callback-id': diagnostic(helper='bpf_timer_start', number=callback_id),
            'callback-helper': diagnostic(helper='bpf_timer_set_callback', number=start_id),
            'missing-end': valid.replace('-- END PROG LOAD LOG --\n', ''),
            'outside-region': valid.replace('-- BEGIN PROG LOAD LOG --\n', '') +
                              '-- BEGIN PROG LOAD LOG --\n-- END PROG LOAD LOG --\n',
        }
        for label, log in invalid.items():
            with self.subTest(vector=label):
                result = self.gate(name, log)
                self.assertNotEqual(result.returncode, 0, label)
                self.assertNotIn('XDEV_EXT_XDOMAIN_CASE=PASS name=' + name, result.stdout)

    def test_wrong_or_unscoped_diagnostics_never_certify_helper_denial(self):
        for name in (NEW, 'helper-probe-read-kernel-deny'):
            for label, log in DENIAL_VECTORS.items():
                with self.subTest(case=name, vector=label):
                    result = self.gate(name, log)
                    self.assertNotEqual(result.returncode, 0,
                        'invalid diagnostic accepted: ' + name + '/' + label)

    def test_allow_or_setup_exit_never_certifies_helper_denial(self):
        for status in (0, 3):
            with self.subTest(loader_exit=status):
                result = self.gate(NEW, diagnostic(), status)
                self.assertNotEqual(result.returncode, 0)


PROBES = {'map_lookup_elem': 1, 'ktime_get_ns': 5, 'probe_read_kernel': 113,
          'probe_read_kernel_str': 115, 'probe_read_user': 112,
          'probe_read_user_str': 114, 'get_current_task': 35,
          'get_current_task_btf': 158, 'trace_printk': 6, 'trace_vprintk': 177,
          'timer_init': 169, 'tail_call': 12, 'ringbuf_output': 130,
          'map_update_elem': 2}


class DedicatedHelperRunner(unittest.TestCase):
    """Execute runner control flow, with only ctl/BTF/bpffs externalized."""
    def execute(self, selection='probe_read_kernel', log=None, status=3,
                missing=False, detach_failure=False):
        with tempfile.TemporaryDirectory(prefix='helper-runner-contract-') as temp:
            root = Path(temp)
            (root / 'bpffs').mkdir()
            (root / 'vmlinux').write_text('live BTF environment boundary')
            objects = root / 'objects'
            objects.mkdir()
            for name in PROBES:
                if not (missing and name == selection):
                    (objects / ('helper_' + name + '.bpf.o')).write_bytes(b'object-boundary')
            ctl = root / 'ctl'
            ctl.write_text('''#!/usr/bin/python3
import json, os, pathlib, sys
args=sys.argv[1:]; root=pathlib.Path(os.environ['HELPER_BOUNDARY_ROOT'])
with (root/'trace').open('a') as out: out.write(json.dumps(args)+'\\n')
pin=pathlib.Path(args[args.index('--pin')+1])
if args[0]=='detach':
 if os.environ['HELPER_BOUNDARY_DETACH_FAIL']=='1': sys.exit(1)
 pin.unlink(); sys.exit(0)
if args[args.index('--map')+1]!='helper_probe_ops': sys.exit(3)
name=pathlib.Path(args[args.index('--obj')+1]).name.removeprefix('helper_').removesuffix('.bpf.o')
if name in ('map_lookup_elem','ktime_get_ns'):
 pin.touch(); sys.exit(0)
status=int(os.environ['HELPER_BOUNDARY_STATUS'])
if status==0: pin.touch()
log=os.environ['HELPER_BOUNDARY_LOG']
if log=='__PER_CASE__':
 ids=json.loads(os.environ['HELPER_BOUNDARY_IDS'])
 log='-- BEGIN PROG LOAD LOG --\\nprogram of this type cannot use helper bpf_'+name+'#'+str(ids[name])+'\\n-- END PROG LOAD LOG --'
print(log)
sys.exit(status)
''')
            ctl.chmod(0o700)
            script = (ROOT / 'tests/integration/session/native/verifier/run_helpers.sh').read_text()
            script = script.replace('/sys/kernel/btf/vmlinux', str(root / 'vmlinux'))
            script = script.replace('/sys/fs/bpf', str(root / 'bpffs'))
            runner = root / 'run.sh'
            runner.write_text(script)
            env = dict(os.environ, CTL=str(ctl), OBJECT_DIR=str(objects),
                       LOG_DIR=str(root / 'logs'), HELPER_BOUNDARY_ROOT=str(root),
                       HELPER_BOUNDARY_LOG=('__PER_CASE__' if selection == 'all' else diagnostic()) if log is None else log,
                       HELPER_BOUNDARY_IDS=json.dumps(PROBES),
                       HELPER_BOUNDARY_STATUS=str(status),
                       HELPER_BOUNDARY_DETACH_FAIL='1' if detach_failure else '0')
            result = subprocess.run(['sh', str(runner), selection], env=env,
                                    capture_output=True, text=True, timeout=10)
            traces = [json.loads(line) for line in (root / 'trace').read_text().splitlines()] if (root / 'trace').exists() else []
            pins = list((root / 'bpffs').rglob('probe_read_kernel'))
            return result, traces, pins

    def test_cli_attach_verifier_rejection_exit_is_accepted(self):
        """Run the actual CLI attach/main bodies, not a copied exit constant."""
        source = (ROOT / 'src/cli/xdev_ext_mech_ctl.c').read_text()
        enum = re.search(r'enum \{ CTL_PASS[^;]+;', source).group()
        begin = source.index('static int cmd_attach(')
        attach = source[begin:source.index('/* Detach the struct_ops', begin)]
        main = source[source.index('int main(int argc, char **argv)'):]
        # Keep the production dispatch and attach return logic. Only libbpf
        # load and unrelated command/parser boundaries are controlled here.
        boundary = r"""
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t __u64;
struct ctl_opts { const char *obj, *map, *pin, *sets[1]; unsigned nr_sets; bool quiet_wait; };
struct bpf_object { int value; };
struct bpf_map { int value; };
struct bpf_link { int value; };
static struct bpf_object object;
static struct bpf_map map_value;
static struct bpf_link link_value;
#define ctl_err(...) fprintf(stderr, __VA_ARGS__)
#define BPF_MAP_TYPE_STRUCT_OPS 1
#define bpf_object__for_each_map(map, obj) for ((map) = NULL; (map); (map) = NULL)
static struct bpf_object *bpf_object__open_file(const char *s, void *o) { return &object; }
static long libbpf_get_error(const void *o) { return 0; }
static int bpf_map__type(struct bpf_map *m) { return BPF_MAP_TYPE_STRUCT_OPS; }
static const char *bpf_map__name(struct bpf_map *m) { return "helper_probe_ops"; }
static void bpf_map__set_autocreate(struct bpf_map *m, bool v) {}
static int xdev_ext_mech_ctl_parse_set(const char *s, char *n, size_t z, __u64 *v) { return 0; }
static int ctl_set_global(struct bpf_object *o, const char *n, __u64 v) { return 0; }
static int bpf_object__load(struct bpf_object *o) {
 puts("-- BEGIN PROG LOAD LOG --");
 puts("program of this type cannot use helper bpf_probe_read_kernel#113");
 puts("-- END PROG LOAD LOG --"); return -EACCES;
}
static struct bpf_map *bpf_object__find_map_by_name(struct bpf_object *o, const char *s) { return &map_value; }
static struct bpf_link *bpf_map__attach_struct_ops(struct bpf_map *m) { return &link_value; }
static int bpf_link__pin(struct bpf_link *l, const char *s) { return 0; }
static void bpf_link__disconnect(struct bpf_link *l) {}
static void bpf_link__destroy(struct bpf_link *l) {}
static void bpf_object__close(struct bpf_object *o) {}
static int cmd_peer_discover(int a, char **v, bool p) { return 2; }
static int cmd_peer_diag(int a, char **v) { return 2; }
static int cmd_peer_caps(int a, char **v) { return 2; }
static int cmd_xdomain_probe(int a, char **v) { return 2; }
static int ctl_libbpf_print;
static void libbpf_set_print(int p) {}
static void usage(FILE *f) {}
static int parse_options(int a, char **v, struct ctl_opts *o) {
 o->obj="probe.bpf.o"; o->map="helper_probe_ops"; o->pin="unused"; return 0;
}
static int xdev_ext_mech_ctl_quiet_check(bool q, bool n, int v, bool p) { return 0; }
"""
        table = ('static const struct { const char *name; '
                 'int (*run)(struct ctl_opts *); } ctl_commands[] = {{"attach", cmd_attach}};\n')
        with tempfile.TemporaryDirectory(prefix='actual-ctl-attach-') as temp:
            ctl = Path(temp) / 'ctl'
            compiled = subprocess.run(['gcc', '-std=c11', '-Wall', '-Werror',
                                       '-x', 'c', '-', '-o', str(ctl)],
                                      input=boundary + enum + '\n' + attach + table + main,
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            denied = subprocess.run([str(ctl), 'attach'], capture_output=True,
                                    text=True, timeout=10)
        self.assertEqual(denied.returncode, 3, denied.stdout + denied.stderr)
        self.assertIn(diagnostic().strip(), denied.stdout)
        result, _, _ = self.execute(status=denied.returncode, log=denied.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_log_prefix_and_exact_helper_are_accepted(self):
        log = diagnostic().replace('-- BEGIN', "libbpf: prog 'helper_complete': -- BEGIN", 1)
        result, _, pins = self.execute(log=log)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(pins)

    def test_all_fourteen_probes_run_once_with_exact_helper_ids(self):
        result, calls, _ = self.execute(selection='all')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        attached = [Path(c[c.index('--obj') + 1]).name for c in calls if c[0] == 'attach']
        self.assertCountEqual(attached, ['helper_' + n + '.bpf.o' for n in PROBES])
        self.assertEqual(result.stdout.count('XDEV_EXT_MECH_HELPER=PASS '), 14)
        self.assertIn('XDEV_EXT_MECH_HELPERS=PASS cases=14 ', result.stdout)

    def test_invalid_diagnostic_vectors_are_rejected(self):
        for label, log in DENIAL_VECTORS.items():
            with self.subTest(vector=label):
                result, _, _ = self.execute(log=log)
                self.assertNotEqual(result.returncode, 0, label)

    def test_allow_objects_are_pinned_then_detached(self):
        for name in ('map_lookup_elem', 'ktime_get_ns'):
            with self.subTest(case=name):
                result, calls, _ = self.execute(selection=name)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([c[0] for c in calls], ['attach', 'detach'])

    def test_allow_detach_failure_is_terminal(self):
        result, _, _ = self.execute(selection='map_lookup_elem', detach_failure=True)
        self.assertNotEqual(result.returncode, 0)

    def test_unexpected_success_or_other_cli_exit_fails(self):
        for status in (0, 1, 2, 4, 255):
            with self.subTest(status=status):
                result, _, pins = self.execute(status=status)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(pins, 'unexpected success leaked its link')

    def test_missing_object_fails_before_ctl(self):
        result, calls, _ = self.execute(missing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
