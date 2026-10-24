#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-only tests of the eval session guest validator; no KVM or device.

eval_session_fixtures/*.log are synthetic consoles in the marker protocol of
xdev_ext_eval_session_guest.sh, never evidence that a guest ran.  pass.log
carries the expected hash of every case; each other fixture breaks exactly
one rule of it.  The expected bytes are also derived here from the arms' own
C payload generators (nvme_gpu_core.h, chain_oracle.h), so the validator's
Python transcription is checked against the code that wrote the data.
Run: python3 xdev_ext_eval_session_validate_test.py -v
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'eval_session_fixtures'
GUEST = HERE / 'xdev_ext_eval_session_guest.sh'
EVAL = HERE.parents[3].parent / 'tests/eval'
CC = shlex.split(os.environ.get('CC', 'cc'))


def _load():
    spec = importlib.util.spec_from_file_location(
        'xdev_ext_eval_session_validate', HERE / 'xdev_ext_eval_session_validate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ev = _load()


class Fixtures(unittest.TestCase):
    def read(self, name):
        return (FIXTURES / name).read_text()

    def test_pass(self):
        result = ev.validate(self.read('pass.log'))
        self.assertEqual(result['passed'], len(ev.CASES))
        self.assertEqual(result['total'], len(ev.CASES))
        self.assertEqual(result['performance_claim'], 'none')

    def test_missing_marker(self):
        with self.assertRaisesRegex(ValueError, 'missing marker'):
            ev.validate(self.read('missing.log'))

    def test_wrong_hash(self):
        with self.assertRaisesRegex(ValueError, 'sha256'):
            ev.validate(self.read('wrong_hash.log'))

    def test_extra_fail(self):
        with self.assertRaisesRegex(ValueError, 'FAIL|duplicate'):
            ev.validate(self.read('extra_fail.log'))

    def test_fixtures_differ_from_pass_in_one_place(self):
        base = self.read('pass.log').splitlines()
        for name in ('missing.log', 'wrong_hash.log', 'extra_fail.log'):
            other = self.read(name).splitlines()
            changed = [line for line in set(base) ^ set(other)]
            self.assertLessEqual(len(changed), 2, name)


class Rules(unittest.TestCase):
    def setUp(self):
        self.lines = (FIXTURES / 'pass.log').read_text().splitlines()

    def without(self, predicate):
        return '\n'.join(line for line in self.lines if not predicate(line)) + '\n'

    def replace(self, old, new):
        text = '\n'.join(self.lines) + '\n'
        self.assertIn(old, text)
        return text.replace(old, new, 1)

    def test_done_count_must_match(self):
        done = next(line for line in self.lines if line.startswith('XDEV_EXT_EVAL_SESSION_DONE='))
        with self.assertRaisesRegex(ValueError, 'DONE'):
            ev.validate(self.replace(done, 'XDEV_EXT_EVAL_SESSION_DONE=1/%d' % len(ev.CASES)))
        with self.assertRaisesRegex(ValueError, 'DONE'):
            ev.validate(self.without(lambda line: line.startswith('XDEV_EXT_EVAL_SESSION_DONE=')))

    def test_done_must_follow_every_marker(self):
        done = next(line for line in self.lines if line.startswith('XDEV_EXT_EVAL_SESSION_DONE='))
        lines = [line for line in self.lines if line != done]
        first = next(i for i, line in enumerate(lines) if line.startswith('XDEV_EXT_EVAL_SESSION='))
        lines.insert(first, done)
        with self.assertRaisesRegex(ValueError, 'DONE'):
            ev.validate('\n'.join(lines) + '\n')

    def test_wrong_byte_count(self):
        marker = next(line for line in self.lines if line.startswith('XDEV_EXT_EVAL_SESSION=nvme_gpu:'))
        bad = re.sub(r'bytes=\d+', 'bytes=1', marker)
        with self.assertRaisesRegex(ValueError, 'bytes'):
            ev.validate(self.replace(marker, bad))

    def test_unknown_case_and_malformed_marker(self):
        with self.assertRaisesRegex(ValueError, 'unknown case'):
            ev.validate(self.replace('XDEV_EXT_EVAL_SESSION_DONE=',
                                     'XDEV_EXT_EVAL_SESSION=chains:invented PASS bytes=1 sha256=' + '0' * 64 +
                                     '\nXDEV_EXT_EVAL_SESSION_DONE='))
        with self.assertRaisesRegex(ValueError, 'malformed'):
            ev.validate(self.replace('XDEV_EXT_EVAL_SESSION_DONE=',
                                     'XDEV_EXT_EVAL_SESSION=nvme_gpu:x PASS bytes=1 io_ns=5\n'
                                     'XDEV_EXT_EVAL_SESSION_DONE='))

    def test_backend_and_restore_lines_required(self):
        for prefix in ('XDEV_EXT_EVAL_SESSION_BACKEND=', 'XDEV_EXT_EVAL_SESSION_SCRATCH='):
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(ValueError, prefix.rstrip('=')):
                    ev.validate(self.without(lambda line: line.startswith(prefix)))

    def test_guards_cleanup_counts_and_restore_order(self):
        base = '\n'.join(self.lines) + '\n'
        mutations = (
            self.without(lambda l: l.startswith('XDEV_EXT_EVAL_SESSION_CHECKS=')),
            base.replace('guards=pass', 'guards=fail', 1),
            base.replace('ce_refs=0', 'ce_refs=1', 1),
            base.replace('EVAL_STOP=PASS result=0', 'EVAL_STOP=FAIL result=-16', 1),
            base.replace('EVAL_FD_CHECK=PASS before=3 after=3', 'EVAL_FD_CHECK=PASS before=3 after=4', 1),
            base.replace('batches_done=4', 'batches_done=3', 1),
            base.replace('completed=4,4,0,0', 'completed=4,3,0,0', 1),
            base.replace('inflight=0', 'inflight=1', 1),
            base.replace('XDEV_EXT_EVAL_SESSION_DONE=',
                         'XDEV_EXT_EVAL_ARM=unknown/main EVAL_STOP=PASS result=0\nXDEV_EXT_EVAL_SESSION_DONE=', 1),
        )
        for text in mutations:
            with self.subTest(text=text[:80]), self.assertRaises(ValueError):
                ev.validate(text)
        restore = next(l for l in self.lines if l.startswith('XDEV_EXT_EVAL_SESSION_SCRATCH='))
        with self.assertRaises(ValueError):
            ev.validate(restore + '\n' + base.replace(restore + '\n', ''))

    def test_cli(self):
        ok = subprocess.run(['python3', str(HERE / 'xdev_ext_eval_session_validate.py'),
                             str(FIXTURES / 'pass.log')], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn('XDEV_EXT_EVAL_SESSION_VALIDATE=PASS cases=%d' % len(ev.CASES), ok.stdout)
        bad = subprocess.run(['python3', str(HERE / 'xdev_ext_eval_session_validate.py'),
                              str(FIXTURES / 'wrong_hash.log')], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertEqual(bad.stdout, '')


class CaseTable(unittest.TestCase):
    def test_guest_script_runs_exactly_the_validated_cases(self):
        text = GUEST.read_text()
        calls = re.findall(r'^(nvme_gpu_case|gpu_nic_case|chain_pair_case|chain_iaa_case) (.+)$',
                           text, re.M)
        self.assertEqual([' '.join((f, a)) for f, a in calls], [ev.guest_call(c) for c in ev.CASES])

    def test_case_ids_are_unique(self):
        ids = [ev.case_id(c) for c in ev.CASES]
        self.assertEqual(len(ids), len(set(ids)))
        for arm in ('chains', 'nvme_gpu', 'gpu_nic'):
            self.assertTrue(any(i.startswith(arm + ':') for i in ids))

    def test_guest_script_records_no_timing(self):
        text = GUEST.read_text()
        self.assertIn('performance_claim=none', text)
        self.assertNotRegex(text, r'echo "XDEV_EXT_EVAL_SESSION=[^"]*(_ns|_us|elapsed)')


def compile_dump(source, tmp):
    path = Path(tmp) / 'dump.c'
    path.write_text(source)
    binary = Path(tmp) / 'dump'
    built = subprocess.run([*CC, '-std=gnu11', '-O1', '-Wall', '-Werror', '-I' + str(EVAL / 'nvme_gpu'),
                            '-I' + str(EVAL / 'chains'), str(path), '-o', str(binary)],
                           capture_output=True, text=True)
    if built.returncode:
        raise AssertionError(built.stderr)
    return binary


class AgainstArmGenerators(unittest.TestCase):
    """Expected bytes from the arms' own C generators."""

    def test_xg_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_dump(r'''
#include <stdio.h>
#include <stdlib.h>
#include "nvme_gpu_core.h"
int main(int argc, char **argv) {
    unsigned long long len = strtoull(argv[1], 0, 10); unsigned seed = (unsigned)strtoul(argv[2], 0, 10);
    unsigned char *b = malloc(len);
    if (!b || xg_fill(b, 0, len, seed)) return 1;
    fwrite(b, 1, len, stdout); return 0; }
''', tmp)
            for length, seed in ((32768, 11), (16384, 21), (262144, 14)):
                with self.subTest(length=length, seed=seed):
                    data = subprocess.run([str(binary), str(length), str(seed)], capture_output=True,
                                          check=True).stdout
                    self.assertEqual(data, ev.xg_payload(seed, length))

    def test_chain_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_dump(r'''
#include <stdio.h>
#include <stdlib.h>
#include "chain_oracle.h"
int main(int argc, char **argv) {
    size_t group = strtoull(argv[1], 0, 10), groups = strtoull(argv[2], 0, 10);
    unsigned long long seed = strtoull(argv[3], 0, 10); int text = atoi(argv[4]);
    uint8_t *b = malloc(group);
    for (size_t g = 0; g < groups; g++) { chain_fill(b, group, seed, g, text); fwrite(b, 1, group, stdout); }
    return 0; }
''', tmp)
            for group, groups, seed, text in ((4096, 5, 31, 0), (32768, 10, 36, 0), (65536, 5, 43, 1)):
                with self.subTest(group=group, text=text):
                    data = subprocess.run([str(binary), str(group), str(groups), str(seed), str(text)],
                                          capture_output=True, check=True).stdout
                    self.assertEqual(data, b''.join(ev.chain_group(seed, g, group, bool(text))
                                                    for g in range(groups)))

    def test_expected_hash_is_of_the_canonical_bytes(self):
        for case in ev.CASES:
            with self.subTest(case=ev.case_id(case)):
                data = ev.canonical(case)
                self.assertEqual(ev.expected(case), (len(data), hashlib.sha256(data).hexdigest()))


if __name__ == '__main__':
    unittest.main()
