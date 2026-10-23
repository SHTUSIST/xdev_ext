#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Probe catalog, bpftrace generation and result arithmetic of breakdown/run.py.

No probe is attached: kallsyms and bpftrace outputs are fixtures, and the
catalog is checked against the function definitions in the kernel sources.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[2] / 'kernel'
spec = importlib.util.spec_from_file_location('breakdown', HERE / 'run.py')
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)

KALLSYMS = """ffffffff81a00000 t xdev_ext_mech_submit
ffffffff81a00100 t xdev_ext_mech_build.isra.0
ffffffff81a00200 T xdev_ext_mech_call
ffffffff81a00300 t xdev_ext_mech_batch_drain
ffffffff81a00400 t xdev_ext_mech_batch_landed
ffffffff81a00500 T xdev_ext_mech_batch_complete
ffffffff81a00600 T xdev_ext_mech_batch_completion_publish
ffffffffc0100000 t nvme_xdev_ext_class_submit\t[nvme_core]
ffffffffc0100100 t nvme_xdev_ext_class_end_io\t[nvme_core]
ffffffff81b00000 t xsk_xdev_ext_mech_submit
ffffffff81b00100 d xdev_ext_mech_ce_class
"""


def resolved():
    return bd.resolve(bd.PROBES, bd.parse_kallsyms(KALLSYMS))


class Catalog(unittest.TestCase):
    def test_every_probe_is_defined_in_its_source_file(self):
        for p in bd.PROBES:
            text = (KERNEL / p['file']).read_text()
            linkage = r'static\s+' if p['linkage'] == 'static' else r''
            pattern = r'^' + linkage + r'[a-z][^;{(]*\b' + re.escape(p['symbol']) + r'\('
            m = re.search(pattern, text, re.M)
            self.assertIsNotNone(m, '%s not defined (%s) in %s' %
                                 (p['symbol'], p['linkage'], p['file']))
            if p.get('batch_arg'):
                head = text[m.start():][:200]
                self.assertRegex(head, r'struct xdev_ext_mech_batch \*' + p['batch_arg'] + r'\b')

    def test_inline_items_are_inline(self):
        for item in bd.UNATTACHABLE:
            text = (KERNEL / item['file']).read_text()
            self.assertRegex(text, r'static inline [^;{(]*\b' + re.escape(item['symbol']) + r'\(')

    def test_tree_names_are_probes(self):
        names = {p['name'] for p in bd.PROBES}
        for parent, children in bd.CHILDREN.items():
            self.assertIn(parent, names)
            for child in children:
                self.assertIn(child, names)


class Resolve(unittest.TestCase):
    def test_kallsyms(self):
        syms = bd.parse_kallsyms(KALLSYMS)
        self.assertEqual(syms['nvme_xdev_ext_class_end_io'], dict(module='nvme_core', clones=[],
                                                                exact=True))
        self.assertEqual(syms['xdev_ext_mech_build'], dict(module=None,
                                                         clones=['xdev_ext_mech_build.isra.0'],
                                                         exact=False))
        self.assertNotIn('xdev_ext_mech_ce_class', syms)

    def test_statuses(self):
        r = {p['name']: p for p in resolved()}
        self.assertEqual(r['core_submit']['status'], 'attachable')
        self.assertEqual(r['nvme_end_io']['attach'], 'nvme_core:nvme_xdev_ext_class_end_io')
        self.assertEqual(r['core_submit']['attach'], 'xdev_ext_mech_submit')
        self.assertEqual(r['build']['status'], 'cloned')
        self.assertIn('tracepoint', r['build']['note'])
        self.assertEqual(r['sync_for_cpu']['status'], 'absent')
        self.assertIn('inlined', r['sync_for_cpu']['note'])
        self.assertEqual(r['ce_complete']['status'], 'absent')
        self.assertIn('not built', r['ce_complete']['note'])


class Generate(unittest.TestCase):
    def test_timing_program(self):
        prog = bd.generate(resolved(), 'timing', 'dot', 'fentry')
        self.assertIn('fentry:xdev_ext_mech_submit\n{\n\t@t_core_submit[tid] = nsecs;\n', prog)
        self.assertIn('fexit:xdev_ext_mech_submit\n{\n\tif (@t_core_submit[tid]) {\n'
                      '\t\t$d = nsecs - @t_core_submit[tid];\n'
                      '\t\t@sum_ns["core_submit"] = sum($d);\n'
                      '\t\t@count["core_submit"] = count();\n', prog)
        # Device interval: class submit entry to the first completion callback.
        self.assertIn('fentry:nvme_core:nvme_xdev_ext_class_submit\n{\n'
                      '\t@t_nvme_submit[tid] = nsecs;\n'
                      '\t@dev0[(uint64)args.b] = nsecs;\n', prog)
        self.assertIn('\tif (retval != 0) {\n\t\tdelete(@dev0[(uint64)args.b]);\n', prog)
        self.assertIn('fentry:xdev_ext_mech_batch_completion_publish\n{\n', prog)
        self.assertIn('\tif (@dev0[(uint64)args.b]) {\n'
                      '\t\t@sum_ns["submit_to_completion"] = sum(nsecs - @dev0[(uint64)args.b]);\n',
                      prog)
        # Direct nesting only: build is a direct child of landed, not via drain.
        self.assertIn('if (@t_landed[tid] && !@t_build[tid])', bd.nest_condition('landed', 'sync_for_cpu'))
        self.assertNotIn('fentry:xdev_ext_mech_build\n', prog)		# cloned: not attachable
        self.assertNotIn('xdev_ext_mech_sync_for_cpu', prog)		# absent
        self.assertIn('END\n{\n', prog)
        self.assertNotRegex(prog, r'\bargs->')

    def test_completion_interval_ends_only_after_a_claim(self):
        """A stale or duplicate xdev_ext_mech_batch_complete() fails its claim;
        only xdev_ext_mech_batch_completion_publish() runs for a claim winner."""
        prog = bd.generate(resolved(), 'timing', 'dot', 'fentry')
        blocks = dict(re.findall(r'(\S+)\n\{\n(.*?)^\}\n', prog, re.S | re.M))
        self.assertNotIn('@dev0', blocks['fentry:xdev_ext_mech_batch_complete'])
        self.assertNotIn('@land0', blocks['fentry:xdev_ext_mech_batch_complete'])
        self.assertIn('submit_to_completion',
                      blocks['fentry:xdev_ext_mech_batch_completion_publish'])
        # Submit to worker landing is keyed on landed, which runs once per
        # published completion even when a caller inlined the publish.
        self.assertIn('\t@sub0[(uint64)args.b] = nsecs;\n',
                      blocks['fentry:nvme_core:nvme_xdev_ext_class_submit'])
        self.assertIn('@sum_ns["submit_to_landed"] = sum(nsecs - @sub0[(uint64)args.b]);',
                      blocks['fentry:xdev_ext_mech_batch_landed'])
        self.assertIn('delete(@sub0[(uint64)args.b]);',
                      blocks['fexit:nvme_core:nvme_xdev_ext_class_submit'])

    def test_arrow_style_and_kfunc_prefix(self):
        prog = bd.generate(resolved(), 'timing', 'arrow', 'kfunc')
        self.assertIn('kfunc:nvme_core:nvme_xdev_ext_class_submit\n', prog)
        self.assertIn('kretfunc:xdev_ext_mech_submit\n', prog)
        self.assertIn('@dev0[(uint64)args->b]', prog)
        self.assertNotRegex(prog, r'args\.b')

    def test_count_program(self):
        prog = bd.generate(resolved(), 'count', 'dot', 'fentry')
        self.assertIn('fentry:xdev_ext_mech_submit\n{\n\t@count["core_submit"] = count();\n}\n',
                      prog)
        self.assertNotIn('fexit:', prog)
        self.assertNotIn('nsecs', prog)


JSON_OUT = '\n'.join(json.dumps(x) for x in [
    dict(type='attached_probes', data=dict(probes=14)),
    dict(type='map', data={'@sum_ns': {'drain': 10000, 'landed': 9000, 'build': 3000,
                                       'core_submit': 2500, 'nvme_submit': 2000,
                                       'bpf_build': 1000, 'bpf_complete': 500,
                                       'submit_to_completion': 40000,
                                       'completion_to_landed': 6000}}),
    dict(type='map', data={'@count': {'drain': 10, 'landed': 10, 'build': 10,
                                      'core_submit': 10, 'nvme_submit': 10, 'bpf_build': 10,
                                      'bpf_complete': 10, 'submit_to_completion': 10,
                                      'completion_to_landed': 10}}),
    dict(type='map', data={'@nest_landed__build': 3000}),
    dict(type='map', data={'@nest_landed__core_submit': 2500}),
    dict(type='map', data={'@nest_landed__bpf_call': 500}),
    dict(type='map', data={'@nest_build__bpf_call': 1000}),
    dict(type='map', data={'@nest_core_submit__nvme_submit': 2000}),
    dict(type='map', data={'@nest_drain__landed': 9000}),
])

TEXT_OUT = """Attaching 14 probes...


@count[core_submit]: 4
@count[landed]: 4
@sum_ns[core_submit]: 800
@sum_ns[landed]: 2000
@nest_landed__core_submit: 800
"""


class Results(unittest.TestCase):
    def test_json_output(self):
        parsed = bd.parse_output(JSON_OUT)
        self.assertEqual(parsed['attached_probes'], 14)
        r = bd.intervals(parsed)
        self.assertEqual(r['landed'], dict(count=10, total_ns=9000, mean_ns=900.0,
                                           exclusive_ns=3000, exclusive_mean_ns=300.0))
        self.assertEqual(r['build']['exclusive_ns'], 2000)
        self.assertEqual(r['core_submit']['exclusive_ns'], 500)
        self.assertEqual(r['drain']['exclusive_ns'], 1000)
        self.assertEqual(r['submit_to_completion']['mean_ns'], 4000.0)
        self.assertNotIn('exclusive_ns', r['submit_to_completion'])

    def test_publish_coverage_warning(self):
        """Fewer publish-closed intervals than landed ones: some caller inlined
        the publish, so submit_to_completion covers only part of the batches."""
        parsed = bd.parse_output(JSON_OUT)
        parsed['maps']['@sum_ns']['submit_to_landed'] = 60000
        parsed['maps']['@count']['submit_to_landed'] = 12
        r = bd.intervals(parsed)
        self.assertEqual(r['submit_to_landed']['mean_ns'], 5000.0)
        self.assertIn('submit_to_completion covers 10 of 12', r['_warnings'][0])
        parsed['maps']['@count']['submit_to_landed'] = 10
        self.assertNotIn('_warnings', bd.intervals(parsed))

    def test_text_output(self):
        r = bd.intervals(bd.parse_output(TEXT_OUT))
        self.assertEqual(r['landed']['exclusive_ns'], 1200)
        self.assertEqual(bd.parse_output(TEXT_OUT)['attached_probes'], 14)

    def test_unknown_lines_rejected(self):
        with self.assertRaises(bd.ParseError):
            bd.parse_output('@sum_ns[x]: notanumber\n')


class Cli(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = bd.main(argv)
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / 'proc').mkdir()
        (root / 'proc/kallsyms').write_text(KALLSYMS)
        (root / 'proc/cpuinfo').write_text('flags\t: fpu hypervisor\n')
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def test_emit_needs_no_privilege(self):
        code, out, _ = self.run_main(['--host-root', str(self.root), '--emit', '--pair',
                                      'nvme-nic', '--', 'true'])
        self.assertEqual(code, 0)
        self.assertIn('fentry:xdev_ext_mech_submit', out)

    def test_timing_refused_in_vm(self):
        code, _, err = self.run_main(['--host-root', str(self.root), '--pair', 'nvme-nic',
                                      '--bpftrace', '/bin/true', '--', 'true'])
        self.assertEqual(code, 4)
        self.assertIn('hypervisor', err)

    def test_attach_check_in_vm_needs_bpftrace(self):
        code, _, err = self.run_main(['--host-root', str(self.root), '--attach-check',
                                      '--bpftrace', 'definitely-not-bpftrace', '--', 'true'])
        self.assertEqual(code, 4)
        self.assertIn('bpftrace', err)

    def test_report_lists_unattachable(self):
        code, out, _ = self.run_main(['--host-root', str(self.root), '--resolve-only'])
        self.assertEqual(code, 0)
        report = json.loads(out)
        status = {p['name']: p['status'] for p in report['probes']}
        self.assertEqual(status['build'], 'cloned')
        self.assertEqual([u['symbol'] for u in report['unattachable']],
                         [u['symbol'] for u in bd.UNATTACHABLE])

    def test_pair_must_be_known(self):
        with self.assertRaises(SystemExit) as raised, \
                contextlib.redirect_stderr(io.StringIO()):
            bd.main(['--host-root', str(self.root), '--pair', 'nic-tape', '--emit', '--', 'x'])
        self.assertEqual(raised.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
