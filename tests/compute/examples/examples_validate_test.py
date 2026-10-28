#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of examples_validate.py, the verdict of the examples KVM run.

- Its Python oracles against published vectors and against xform_oracle.h
  (a C fixture built with $CC, default cc) over many lengths and seeds.
- Its plan against guest/run-guest.sh, and its record layout against the
  guest tool's static assertions.
- Synthetic record streams: a correct pair passes; one changed byte, a wrong
  outcome, a changed chunk byte outside the output, different inputs in the
  two runs, or a corrupted input that is still valid each fail.
"""
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import examples_validate as ev  # noqa: E402

FIXTURE = r'''
#include <stdio.h>
#include "xform_oracle.h"
int main(void)
{
	static unsigned char buf[300];
	static const unsigned long long seeds[] = { 0, 1, 0x5eed, 0x9E3779B185EBCA87ULL };
	unsigned int i, n, s;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char)(i * 131 + 7);
	for (n = 0; n <= sizeof(buf); n++) {
		printf("crc %u %08x\n", n, oracle_crc32c(buf, n));
		for (s = 0; s < 4; s++)
			printf("xxh %u %llu %016llx\n", n, seeds[s],
			       (unsigned long long)oracle_xxh64(buf, n, seeds[s]));
	}
	return 0;
}
'''


class Oracles(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(ev.crc32c(b'123456789'), 0xE3069283)
        self.assertEqual(ev.xxh64(b'', 0), 0xEF46DB3751D8E999)
        self.assertEqual(ev.xxh64(b'abc', 0), 0x44BC2CF5AD770999)

    def test_against_c_oracle(self):
        cc = shlex.split(os.environ.get('CC', 'cc'))
        buf = bytes((i * 131 + 7) & 0xFF for i in range(300))
        with tempfile.TemporaryDirectory() as name:
            src, binary = Path(name) / 'fixture.c', Path(name) / 'fixture'
            src.write_text(FIXTURE)
            subprocess.run(cc + ['-O2', '-I' + str(HERE.parent), str(src), '-o', str(binary)],
                           check=True)
            out = subprocess.run([str(binary)], check=True, capture_output=True,
                                 text=True).stdout
        lines = 0
        for line in out.splitlines():
            words = line.split()
            if words[0] == 'crc':
                n, want = int(words[1]), int(words[2], 16)
                self.assertEqual(ev.crc32c(buf[:n]), want, n)
            else:
                n, seed, want = int(words[1]), int(words[2]), int(words[3], 16)
                self.assertEqual(ev.xxh64(buf[:n], seed), want, (n, seed))
            lines += 1
        self.assertEqual(lines, 301 * 5)

    def test_apply(self):
        body = b'payload!'
        sealed = body + ev.crc32c(body).to_bytes(4, 'little')
        self.assertEqual(ev.apply('crc32c-check', sealed), sealed)
        self.assertEqual(ev.apply('crc32c-strip', sealed), body)
        self.assertIsNone(ev.apply('crc32c-check', sealed[:-1] + b'\0'))
        self.assertIsNone(ev.apply('crc32c-check', b'abc'))
        self.assertEqual(ev.apply('crc32c-append', body), sealed)
        self.assertEqual(ev.apply('xxh64-append:0', b'abc'),
                         b'abc' + (0x44BC2CF5AD770999).to_bytes(8, 'big'))
        frame = (4).to_bytes(4, 'little') + b'h' * 12 + b'data'
        self.assertEqual(ev.apply('parse-check:16', frame), frame)
        self.assertEqual(ev.apply('parse-strip:16', frame), b'data')
        self.assertIsNone(ev.apply('parse-check:16', frame[:15]))
        self.assertIsNone(ev.apply('parse-strip:4', frame))
        self.assertIsNone(ev.expect_batch(['parse-check:16'], [frame, frame[:-1]]))
        self.assertEqual(ev.expect_batch(['parse-check:16', 'parse-strip:16'], [frame]),
                         [b'data'])


def guest_cases():
    """The case_run lines of run-guest.sh, with its variables expanded."""
    text = (HERE / 'guest/run-guest.sh').read_text().replace('\\\n', ' ')
    frames = re.search(r"^FRAMES='([^']*)'", text, re.M).group(1)
    neg = re.search(r'^NEG=(\S+)', text, re.M).group(1)
    cases = {}
    for line in text.splitlines():
        if not line.startswith('case_run '):
            continue
        words = shlex.split(line.replace('$FRAMES', frames).replace('$NEG', neg))
        name, obj, mapname, sets, fixed, bpf, inp, seed = words[1:9]
        cases[name] = dict(object=obj, map=mapname, set=sets, fixed=fixed, bpf=bpf, input=inp,
                           seed=seed, rest=words[9:])
    return cases


def stage_words(text):
    words = text.split()
    assert words[::2] == ['--stage'] * (len(words) // 2)
    out = []
    for spec in words[1::2]:
        x, a = spec.split(':')
        out.append((int(x, 0), int(a, 0) & ((1 << 64) - 1)))
    return out


class Plan(unittest.TestCase):
    def test_guest_plan_matches(self):
        cases = guest_cases()
        self.assertEqual(sorted(cases), sorted(ev.PLAN))
        seeds = set()
        for name, g in cases.items():
            plan = ev.PLAN[name]
            self.assertEqual(g['input'], plan['input'], name)
            self.assertEqual('--negatives' in g['rest'], plan['negatives'], name)
            layouts, rest = [], [w for w in g['rest'] if w != '--negatives']
            for kind, spec in zip(rest[::2], rest[1::2]):
                nums = tuple(int(v) for v in spec.split(':'))
                layouts.append(('spans',) + nums if kind == '--spans' else ('frames',) + nums)
            self.assertEqual(tuple(layouts), plan['layouts'], name)
            self.assertEqual(stage_words(g['fixed']), [ev.STAGES[s] for s in plan['fixed']], name)
            bpf = [(10, ev.BPF_DELTA[s] & ((1 << 64) - 1)) for s in plan['bpf']]
            if name == 'parse_compose_h16':
                bpf = [(10, 0), ev.STAGES['parse-strip:16']]
            self.assertEqual(stage_words(g['bpf']), bpf, name)
            self.assertIn(g['object'], ev.OBJECTS, name)
            seeds.add(g['seed'])
        self.assertEqual(len(seeds), len(cases))

    def test_record_layout(self):
        source = (HERE / 'guest/compute_examples_guest.c').read_text()
        self.assertEqual(ev.STREAM.size, 88)
        self.assertEqual(ev.RECORD.size, 300)
        self.assertEqual(ev.END.size, 16)
        for struct_name, size in (('stream_hdr', 88), ('rec_hdr', 300), ('end_rec', 16)):
            self.assertRegex(source, r'_Static_assert\(sizeof\(struct ' + struct_name +
                             r'\) == ' + str(size))
        self.assertEqual(list(ev.SPAN_EDGES), [int(v) for v in re.search(
            r'span_edges\[\] = \{([^}]*)\}', source).group(1).replace('\n', ' ').split(',')
            if v.strip()])


def make_stream(head_stages, inputs_list, outputs_list, outcomes, layout, corrupted=None,
                stray=None, input_kind='sealed', negatives=1, last_errs=None,
                errs_before=None):
    """A stream as the guest tool writes it, all records of one layout."""
    xs = [s[0] for s in head_stages] + [0] * (2 - len(head_stages))
    args = [s[1] for s in head_stages] + [0] * (2 - len(head_stages))
    data = ev.STREAM.pack(ev.STREAM_MAGIC, 2, len(head_stages), xs[0], xs[1], args[0], args[1],
                          5, 0, negatives, input_kind.encode())
    spans, hdr, seg, group = layout
    done = 0
    for i, (ins, outs) in enumerate(zip(inputs_list, outputs_list)):
        n = len(ins)
        in_len = [len(x) for x in ins] + [0] * (32 - n)
        out_len = [len(x) for x in outs] + [0] * (32 - n)
        err = (last_errs or [0] * len(inputs_list))[i]
        before = (errs_before or [0] * len(inputs_list))[i]
        data += ev.RECORD.pack(ev.REC_MAGIC, spans, hdr, seg, group, n,
                               (corrupted or [0] * len(inputs_list))[i], outcomes[i], before, err,
                               (stray or [0] * len(inputs_list))[i], *in_len, *out_len)
        data += b''.join(ins) + b''.join(outs)
        done += not outcomes[i]
    data += ev.END.pack(ev.END_MAGIC, len(inputs_list), done, len(inputs_list) - done)
    return data


class Streams(unittest.TestCase):
    def setUp(self):
        self.saved_edges = ev.SPAN_EDGES
        ev.SPAN_EDGES = ()
        self.plan = dict(fixed=['crc32c-check'], bpf=['crc32c-check'], input='sealed',
                         negatives=True, layouts=(('spans', 3, 0),), compare='identical')

    def tearDown(self):
        ev.SPAN_EDGES = self.saved_edges

    def sealed_pair(self, **kw):
        # Lengths 1..3 twice each: all shorter than the CRC, so all refused.
        ins = [[bytes([n] * n)] for n in (1, 1, 2, 2, 3, 3)]
        outs = [list(x) for x in ins]
        args = dict(outcomes=[1] * 6, layout=(1, 0, 3, 3), corrupted=[0, 1] * 3,
                    last_errs=[-74] * 6)
        args.update(kw)
        return ins, outs, args

    def run_check(self, mode, data, plan=None):
        plan = plan or self.plan
        head, records, end = ev.parse_stream(data)
        return ev.check_stream('t', mode, plan[mode], plan, head, records, end), records

    def test_refused_batches_pass(self):
        ins, outs, args = self.sealed_pair()
        errors, fixed = self.run_check('fixed', make_stream([(4, 0)], ins, outs, **args))
        self.assertEqual(errors, [])
        errors, bpf = self.run_check('bpf', make_stream([(10, 0)], ins, outs, **args))
        self.assertEqual(errors, [])
        self.assertEqual(ev.compare_runs('t', self.plan, fixed, bpf), [])

    def test_wrong_outcome_fails(self):
        ins, outs, args = self.sealed_pair()
        args['outcomes'] = [1] * 5 + [0]
        errors, _ = self.run_check('bpf', make_stream([(10, 0)], ins, outs, **args))
        self.assertTrue(any('oracle refuses' in e for e in errors), errors)

    def test_stray_and_changed_bytes_fail(self):
        ins, outs, args = self.sealed_pair(stray=[0, 0, 0, 0, 0, 2])
        errors, _ = self.run_check('bpf', make_stream([(10, 0)], ins, outs, **args))
        self.assertTrue(any('outside the output' in e for e in errors), errors)
        ins, outs, args = self.sealed_pair()
        outs[3] = [b'\x07\x07']
        errors, _ = self.run_check('bpf', make_stream([(10, 0)], ins, outs, **args))
        self.assertTrue(any('changed' in e for e in errors), errors)

    def test_appended_bytes(self):
        plan = dict(self.plan, fixed=['crc32c-append'], bpf=['crc32c-append'], input='random',
                    negatives=False)
        ins = [[b'a'], [b'bb'], [b'ccc']]
        outs = [[x[0] + ev.crc32c(x[0]).to_bytes(4, 'little')] for x in ins]
        args = dict(outcomes=[0] * 3, layout=(1, 0, 3, 3), input_kind='random', negatives=0)
        errors, fixed = self.run_check('fixed', make_stream([(1, 0)], ins, outs, **args), plan)
        self.assertEqual(errors, [])
        errors, bpf = self.run_check('bpf', make_stream([(10, 4)], ins, outs, **args), plan)
        self.assertEqual(errors, [])
        self.assertEqual(ev.compare_runs('t', plan, fixed, bpf), [])
        # Big-endian instead of little-endian CRC bytes.
        bad = [[x[0] + ev.crc32c(x[0]).to_bytes(4, 'big')] for x in ins]
        errors, _ = self.run_check('bpf', make_stream([(10, 4)], ins, bad, **args), plan)
        self.assertTrue(any('differs from the oracle' in e for e in errors), errors)
        # The wrong declared length change.
        errors, _ = self.run_check('bpf', make_stream([(10, 8)], ins, outs, **args), plan)
        self.assertTrue(any('stages' in e for e in errors), errors)
        # The two runs saw different inputs.
        _, other = self.run_check('bpf', make_stream([(10, 4)], [[b'a'], [b'bb'], [b'ccd']],
                                  [[b'a' + ev.crc32c(b'a').to_bytes(4, 'little')],
                                   outs[1], [b'ccd' + ev.crc32c(b'ccd').to_bytes(4, 'little')]],
                                  **args), plan)
        self.assertTrue(ev.compare_runs('t', plan, fixed, other))

    def test_corrupted_but_valid_fails(self):
        plan = dict(self.plan, layouts=(('spans', 5, 0),))
        ev.SPAN_EDGES = ()
        body = b'x'
        sealed = body + ev.crc32c(body).to_bytes(4, 'little')
        ins = [[b'\1'], [b'\1'], [b'\2\2'], [b'\2\2'], [b'\3\3\3'], [b'\3\3\3'],
               [b'\4\4\4\4'], [b'\4\4\4\4'], [sealed], [sealed]]
        outs = [list(x) for x in ins]
        outcomes = [1] * 8 + [0, 0]
        args = dict(outcomes=outcomes, layout=(1, 0, 5, 5), corrupted=[0, 1] * 5,
                    last_errs=[-74] * 8 + [0, 0])
        errors, _ = self.run_check('fixed', make_stream([(4, 0)], ins, outs, **args), plan)
        self.assertTrue(any('corrupted input the oracle accepts' in e for e in errors), errors)

    def test_strip_compare(self):
        plan = dict(self.plan, fixed=['parse-strip:4'], bpf=['parse-check:4'], input='parse:4',
                    negatives=False, layouts=(('spans', 6, 0),), compare='strip:4')
        ev.SPAN_EDGES = ()
        ins, fouts, bouts, outcomes = [], [], [], []
        for n in range(1, 7):
            frame = (n - 4).to_bytes(4, 'little') + b'p' * (n - 4) if n >= 4 else bytes(n)
            ins.append([frame])
            ok = n >= 4
            fouts.append([frame[4:]] if ok else [frame])
            bouts.append([frame])
            outcomes.append(0 if ok else 1)
        errs = [0 if o == 0 else -74 for o in outcomes]
        args = dict(outcomes=outcomes, layout=(1, 0, 6, 6), input_kind='parse:4', negatives=0,
                    last_errs=errs)
        errors, fixed = self.run_check('fixed', make_stream([(5, 4)], ins, fouts, **args), plan)
        self.assertEqual(errors, [])
        errors, bpf = self.run_check('bpf', make_stream([(10, 0)], ins, bouts, **args), plan)
        self.assertEqual(errors, [])
        self.assertEqual(ev.compare_runs('t', plan, fixed, bpf), [])

    def test_refused_partial_writes(self):
        """A refused fixed strip may keep earlier frames stripped; a check may not."""
        plan = dict(self.plan, fixed=['parse-strip:4'], bpf=['parse-check:4'], input='parse:4',
                    negatives=False, layouts=(('frames', 6, 12, 0, 1),), compare='strip:4')
        good = (2).to_bytes(4, 'little') + b'pq'
        bad = (3).to_bytes(4, 'little') + b'pq'
        ins = [[good, bad]]
        partial = [[good[4:] + good[2:], bad]]
        args = dict(outcomes=[1], layout=(0, 0, 6, 12), input_kind='parse:4', negatives=0,
                    last_errs=[-74])
        errors, fixed = self.run_check('fixed', make_stream([(5, 4)], ins, partial, **args), plan)
        self.assertEqual(errors, [])
        errors, bpf = self.run_check('bpf', make_stream([(10, 0)], ins, ins, **args), plan)
        self.assertEqual(errors, [])
        self.assertEqual(ev.compare_runs('t', plan, fixed, bpf), [])
        errors, _ = self.run_check('bpf', make_stream([(10, 0)], ins, partial, **args), plan)
        self.assertTrue(any('changed' in e for e in errors), errors)

    def test_later_refusal_errno_is_observed(self):
        """A refused batch's own error code must be checked, not the session's first.

        The kernel latches a session's last_err at its first error. Records of
        one session over three refused batches whose own codes are -EBADMSG,
        -EIO and -EBADMSG therefore all read -EBADMSG after the batch; the
        validator must still see that the second batch's code was not checked.
        """
        ins = [[bytes([n] * n)] for n in (1, 2, 3)]
        outs = [list(x) for x in ins]
        own, latch, before, after = [-74, -5, -74], 0, [], []
        for err in own:
            before.append(latch)
            latch = latch or err
            after.append(latch)
        plan = dict(self.plan, negatives=False)
        args = dict(outcomes=[1] * 3, layout=(1, 0, 3, 3), negatives=0, last_errs=after,
                    errs_before=before)
        errors, _ = self.run_check('bpf', make_stream([(10, 0)], ins, outs, **args), plan)
        self.assertTrue(any('is not observed' in e for e in errors), errors)

    def test_refusal_errno_of_a_fresh_session(self):
        """Each refusal in its own session: a code other than -EBADMSG fails."""
        ins, outs, args = self.sealed_pair(last_errs=[-74, -74, -74, -5, -74, -74])
        errors, _ = self.run_check('bpf', make_stream([(10, 0)], ins, outs, **args))
        self.assertTrue(any('last_err -5 after a refused batch' in e for e in errors), errors)

    def test_completed_batch_with_error_fails(self):
        plan = dict(self.plan, fixed=['crc32c-append'], bpf=['crc32c-append'], input='random',
                    negatives=False)
        ins = [[b'a'], [b'bb'], [b'ccc']]
        outs = [[x[0] + ev.crc32c(x[0]).to_bytes(4, 'little')] for x in ins]
        args = dict(outcomes=[0] * 3, layout=(1, 0, 3, 3), input_kind='random', negatives=0,
                    last_errs=[0, -74, 0])
        errors, _ = self.run_check('bpf', make_stream([(10, 4)], ins, outs, **args), plan)
        self.assertTrue(any('after a completed batch' in e for e in errors), errors)

    def test_truncated_stream(self):
        ins, outs, args = self.sealed_pair()
        data = make_stream([(4, 0)], ins, outs, **args)
        with self.assertRaises(ValueError):
            ev.parse_stream(data[:-20])


class Console(unittest.TestCase):
    def test_kernel_reports(self):
        self.assertEqual(ev.check_console('XDEV_EXT_EXAMPLES_GUEST=PASS\n'), [])
        self.assertTrue(ev.check_console('[    1.0] BUG: KASAN: slab-out-of-bounds in x\n'))

    def test_log_markers(self):
        lines = ['XDEV_EXT_EXAMPLES_CASE=PASS name=' + c for c in ('verifier',) + tuple(ev.PLAN)]
        lines += ['XDEV_EXT_EXAMPLE_VERIFIER_DONE objects=6 failed=0',
                  'XDEV_EXT_EXAMPLES_GUEST=PASS', 'XDEV_EXT_EXAMPLES_GUEST_EXIT=0']
        self.assertEqual(ev.check_log('\n'.join(lines)), [])
        self.assertTrue(ev.check_log('\n'.join(lines[1:])))
        self.assertTrue(ev.check_log('\n'.join(lines + ['XDEV_EXT_EXAMPLE_RUN out=x result=FAIL'])))


class Verifier(unittest.TestCase):
    def test_parse(self):
        lines = []
        for obj in ev.OBJECTS:
            for prog in ('a_comp', 'a_build', 'a_done'):
                lines.append(f'XDEV_EXT_EXAMPLE_VERIFIER object={obj} program={prog} '
                             f'processed_insns=12 verified_insns=12 xlated_insns=9 stats="processed 12 insns"')
        out, errors = ev.parse_verifier('\n'.join(lines))
        self.assertEqual(errors, [])
        self.assertEqual(out['parse_check.bpf.o']['a_comp']['processed_insns'], 12)
        out, errors = ev.parse_verifier('\n'.join(lines[:-1]).replace(
            'processed_insns=12 verified_insns=12', 'processed_insns=12 verified_insns=13', 1))
        self.assertEqual(len(errors), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
