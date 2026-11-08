#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Qualification negatives through the real deployment planner, no services."""
import json
import shlex
import unittest
import test_baselines as t

bp = t.bp


class Qualification(unittest.TestCase):
    def test_keepalive_volume_cannot_qualify_a_known_kv_transfer(self):
        before = {'host1': (100, 100), 'host2': (100, 100)}
        after = {'host1': (101, 101), 'host2': (101, 101)}
        with self.assertRaises(bp.RouteError):
            bp.route_check(before, after, expected_kv_bytes=1024 * 1024)

    def test_unknown_kv_size_is_refused(self):
        with self.assertRaises(bp.RouteError):
            bp.route_check({'host1': (0, 0)}, {'host1': (10**8, 10**8)})

    def test_unknown_volume_refuses_before_any_service_or_http_request(self):
        ex = t.FakeExecutor([])
        state = {'route': {'qualified': True}}
        with self.assertRaises(bp.RouteError):
            bp.execute(t.plan('mooncake-store'), ['up', 'check'], ex, state=state)
        self.assertEqual(ex.calls, [])
        self.assertNotIn('route', state)
        self.assertFalse(state['qualifies_long_running_measurements'])

    def test_volume_is_a_necessary_condition_not_flow_identity(self):
        before = {'host1': (0, 0), 'host2': (0, 0)}
        after = {'host1': (4096, 100), 'host2': (100, 4096)}
        result = bp.route_check(before, after, expected_kv_bytes=4096)
        self.assertTrue(result['volume_sufficient'])
        self.assertFalse(result['qualified'])
        self.assertEqual(result['scope'], 'interface-byte-volume-only')

    def test_recompute_up_prepares_files_without_persistent_server(self):
        p = t.plan('recompute', cold_port=8123)
        ex = t.FakeExecutor([])
        state = bp.execute(p, ['up'], ex)
        self.assertFalse(state['pids'])
        self.assertFalse(any('nohup' in c for _, c, _ in ex.calls))
        self.assertTrue(any('cold_request.py' in c and data for _, c, data in ex.calls))

    def test_each_recompute_check_invokes_the_actual_cold_entry(self):
        p = t.plan('recompute', cold_port=8123)
        calls = []
        def executor(host, command, stdin=None):
            calls.append(command)
            return 0, json.dumps(dict(fresh_process=True, owned_group_cleaned=True,
                                      timing_scope='http-full-response', reported_cached_tokens=[0]))
        state = {}
        for _ in range(2):
            bp.execute(p, ['check'], executor, sleep=lambda _: None, state=state)
        self.assertEqual(len(calls), 2)
        for command in calls:
            self.assertIn('cold_request.py', command)
            self.assertIn('--execute', shlex.split(command))
        self.assertEqual(state['check_scope'], 'single-request-fresh-process-preflight')
        self.assertFalse(state['qualifies_long_running_measurements'])

    def test_recompute_request_body_and_vllm_defaults_are_preserved(self):
        p = t.plan('recompute', cold_port=8123)
        files = dict(p.files)
        bodies = [json.loads(value) for (host, path), value in files.items() if path.endswith('request.json')]
        self.assertEqual(len(bodies), 1)
        self.assertEqual(bodies[0]['prompt'], bp.SMOKE_PROMPT)
        self.assertEqual(bodies[0]['max_tokens'], 16)
        self.assertEqual(t.one(p, 'vllm-serve').argv[1:], ('serve', t.MODEL))


if __name__ == '__main__':
    unittest.main(verbosity=2)
