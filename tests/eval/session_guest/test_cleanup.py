#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual guest cleanup functions; no guest, device or marker evidence."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

GUEST = Path(__file__).resolve().parents[3] / 'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_guest.sh'


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}', GUEST.read_text(), re.M | re.S)
    assert match, name
    return match.group()


class Cleanup(unittest.TestCase):
    def test_abnormal_never_restores_even_if_teardown_succeeds(self):
        for teardown_rc in (0, 1):
            with self.subTest(teardown_rc=teardown_rc), tempfile.TemporaryDirectory() as tmp:
                events = Path(tmp) / 'events'
                script = 'events=' + str(events) + '\n' + '''
restored=0
work=retained
log() { :; }
teardown() { echo teardown >> "$events"; return %d; }
restore() { echo restore >> "$events"; }
''' % teardown_rc + function('abnormal') + '\n(exit 7)\nabnormal\n'
                result = subprocess.run(['sh', '-c', script], capture_output=True, text=True)
                self.assertEqual(result.returncode, 7, result.stderr)
                self.assertEqual(events.read_text().splitlines(), ['teardown'])

    def test_failed_case_returns_failure_and_never_emits_pass(self):
        script = '''
n_pass=0
n_total=0
zero_hash=zero
bad_arm() { return 4; }
guard_prepare() { return 0; }
''' + function('mark') + '\n' + function('run_case') + '\nrun_case nvme_gpu:test bad_arm\n'
        result = subprocess.run(['sh', '-c', script], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(' FAIL ', result.stdout)
        self.assertNotIn(' PASS ', result.stdout)

if __name__ == '__main__':
    unittest.main()
