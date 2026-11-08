#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The correctness hook: greedy first tokens after a restore equal those of recompute.

A prompt passes only when (1) the restored run actually loaded its stored
prefix through the connector (an ok load of exactly the expected prefix
length and no failed load; a silent fallback to recompute must not pass),
(2) both runs produced the first N greedy tokens (fewer only if both stopped at
the same point) and (3) those tokens are identical.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import _paths
from xdev_kv_vllm import verify as kv


def run(pid, tokens, loads=None):
    return {'id': pid, 'prefix_tokens': 32, 'output_token_ids': tokens, 'loads': loads or []}


OK_LOAD = [{'ok': True, 'end_token': 32, 'tokens': 32}]


class Compare(unittest.TestCase):
    def test_pass(self):
        v = kv.compare([run('a', list(range(16)), OK_LOAD)], [run('a', list(range(16)))], n=16)
        self.assertTrue(v['ok'], v)
        self.assertEqual(v['checked'], 1)

    def test_token_mismatch(self):
        other = list(range(16))
        other[5] = 99
        v = kv.compare([run('a', other, OK_LOAD)], [run('a', list(range(16)))], n=16)
        self.assertFalse(v['ok'])
        self.assertEqual(v['prompts']['a']['first_mismatch'], 5)

    def test_fallback_is_not_a_pass(self):
        for loads, why in (([], 'not loaded'),
                           ([{'ok': False, 'end_token': 32, 'tokens': 32, 'reason': 'x'}], 'failed'),
                           (OK_LOAD + [{'ok': False, 'end_token': 32, 'tokens': 32}], 'failed'),
                           ([{'ok': True, 'end_token': 16, 'tokens': 16}], 'not loaded')):
            with self.subTest(loads=loads):
                v = kv.compare([run('a', list(range(16)), loads)], [run('a', list(range(16)))], n=16)
                self.assertFalse(v['ok'])
                self.assertIn(why, v['prompts']['a']['problem'])

    def test_lengths(self):
        same_stop = kv.compare([run('a', [1, 2, 3], OK_LOAD)], [run('a', [1, 2, 3])], n=16)
        self.assertTrue(same_stop['ok'], 'both stopped after 3 tokens')
        v = kv.compare([run('a', [1, 2, 3], OK_LOAD)], [run('a', [1, 2, 3, 4])], n=16)
        self.assertFalse(v['ok'])
        long = kv.compare([run('a', list(range(20)), OK_LOAD)],
                          [run('a', list(range(16)) + [0, 0, 0, 0])], n=16)
        self.assertTrue(long['ok'], 'only the first 16 count')

    def test_prompt_sets_must_match(self):
        v = kv.compare([run('a', [1], OK_LOAD)], [run('b', [1])], n=16)
        self.assertFalse(v['ok'])
        self.assertFalse(kv.compare([], [], n=16)['ok'], 'nothing checked is not a pass')

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'restored.json', Path(tmp) / 'recompute.json'
            a.write_text(json.dumps({'runs': [run('a', list(range(16)), OK_LOAD)]}))
            b.write_text(json.dumps({'runs': [run('a', list(range(16)))]}))
            env_path = str(_paths.PACKAGE)
            r = subprocess.run([sys.executable, '-B', '-m', 'xdev_kv_vllm.verify', 'compare',
                                '--restored', str(a), '--recompute', str(b)], cwd=env_path,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(json.loads(r.stdout)['ok'])
            b.write_text(json.dumps({'runs': [run('a', [9] * 16)]}))
            r = subprocess.run([sys.executable, '-B', '-m', 'xdev_kv_vllm.verify', 'compare',
                                '--restored', str(a), '--recompute', str(b)], cwd=env_path,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


if __name__ == '__main__':
    unittest.main()
