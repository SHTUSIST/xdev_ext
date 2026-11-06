#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Planned K-KV metrics and verdicts from raw run records.

The records here are synthetic fixtures built in the test (not measurements).
Requirements from the experiment design: median, IQR and CV of the restore
latency per arm and prefix with at least 10 runs; the ratio to Mooncake with
an independent per-arm bootstrap; within +-10% passes, >10% slower is a loss;
CPU core-seconds per GB on each host, a resource claim only if halved on
both hosts; host-2 memory traffic per effective byte <= 0.1 when counters
exist, otherwise "not measured"; comparison with recomputing the prefill.
"""
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_analyze', HERE / 'analyze.py')
ka = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ka)

GB = 10 ** 9


def rows(arm, latencies, cpu1, cpu2, prefix=4096, bytes_=671088640, ok=True, perf=None):
    out = []
    for i, lat in enumerate(latencies):
        out.append(dict(run=f'{arm}-{prefix}-{i}', arm=arm, model='qwen3-14b', prefix_tokens=prefix,
                        rep=i, ordinal=i + 1, bytes=bytes_, ok=ok, latency_ns=int(lat * 1e9),
                        host1_cpu=dict(busy_core_seconds=cpu1 * bytes_ / GB, wall_seconds=lat),
                        host2_cpu=dict(busy_core_seconds=cpu2 * bytes_ / GB, wall_seconds=lat),
                        perf=perf))
    return out


def write_arm(base, arm, records, idle=(0.0, 0.0)):
    d = Path(base) / arm
    d.mkdir()
    (d / 'results.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
    (d / 'run.json').write_text(json.dumps(dict(schema=1, arm=arm, performance_claim='none', idle=dict(
        host1=dict(busy_core_seconds=idle[0], wall_seconds=1.0),
        host2=dict(busy_core_seconds=idle[1], wall_seconds=1.0)))))
    return d


class Statistics(unittest.TestCase):
    def test_summary_values(self):
        lat = [1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.9]
        s = ka.summarize([dict(r, ok=True) for r in rows('a', lat, 1, 1)])
        self.assertAlmostEqual(s['latency_s']['median'], statistics.median(lat))
        q = statistics.quantiles(lat, n=4, method='inclusive')
        self.assertAlmostEqual(s['latency_s']['iqr'], q[2] - q[0])
        self.assertAlmostEqual(s['latency_s']['cv'], statistics.stdev(lat) / statistics.mean(lat))
        self.assertEqual(s['n_ok'], 10)

    def test_failed_runs_counted_not_used(self):
        good = rows('a', [1.0] * 10, 1, 1)
        bad = rows('a', [9.0] * 3, 1, 1, ok=False)
        s = ka.summarize(good + bad)
        self.assertEqual((s['n_ok'], s['n_failed']), (10, 3))
        self.assertAlmostEqual(s['latency_s']['median'], 1.0)

    def test_bootstrap_is_seeded_and_brackets_the_ratio(self):
        a = [1.00 + 0.01 * i for i in range(12)]
        b = [2.00 + 0.02 * i for i in range(12)]
        c1 = ka.bootstrap_ratio(a, b, resamples=2000, seed=3)
        c2 = ka.bootstrap_ratio(a, b, resamples=2000, seed=3)
        self.assertEqual(c1, c2)
        self.assertLessEqual(c1['p2.5'], 0.5)
        self.assertGreaterEqual(c1['p97.5'], 0.5)


class Verdicts(unittest.TestCase):
    def analyze(self, xdev, moon, **kw):
        with tempfile.TemporaryDirectory(prefix='kv-an-') as tmp:
            dirs = [write_arm(tmp, 'xdev-ext', xdev), write_arm(tmp, 'mooncake', moon)]
            return ka.analyze(dirs, resamples=500, seed=1, **kw)

    def point(self, report):
        return report['comparisons'][0]

    def test_latency_thresholds(self):
        for factor, want in ((1.05, 'within_10pct'), (1.2, 'loss_slower_than_10pct'),
                             (0.8, 'faster_by_more_than_10pct')):
            with self.subTest(factor=factor):
                rep = self.analyze(rows('xdev-ext', [factor] * 10, 1, 1),
                                   rows('mooncake', [1.0] * 10, 1, 1))
                self.assertEqual(self.point(rep)['latency_verdict'], want)
                self.assertAlmostEqual(self.point(rep)['latency_ratio_median'], factor)

    def test_too_few_runs_give_no_verdict(self):
        rep = self.analyze(rows('xdev-ext', [1.0] * 9, 1, 1), rows('mooncake', [1.0] * 10, 1, 1))
        self.assertEqual(self.point(rep)['latency_verdict'], 'insufficient_runs')

    def test_cpu_claim_needs_halving_on_both_hosts(self):
        rep = self.analyze(rows('xdev-ext', [1.0] * 10, 1.5, 1.0), rows('mooncake', [1.0] * 10, 4.0, 3.0))
        p = self.point(rep)
        self.assertAlmostEqual(p['cpu_reduction']['host1'], 4.0 / 1.5)
        self.assertTrue(p['resource_claim_allowed'])
        rep = self.analyze(rows('xdev-ext', [1.0] * 10, 2.5, 1.0), rows('mooncake', [1.0] * 10, 4.0, 3.0))
        self.assertFalse(self.point(rep)['resource_claim_allowed'])

    def test_memory_traffic(self):
        perf = {'amd_umc_0/x/': 1_000_000}
        rep = self.analyze(rows('xdev-ext', [1.0] * 10, 1, 1, perf=perf),
                           rows('mooncake', [1.0] * 10, 1, 1), bytes_per_count=64)
        traffic = self.point(rep)['host2_memory_bytes_per_byte']
        self.assertAlmostEqual(traffic['value'], 64e6 / 671088640)
        self.assertEqual(traffic['verdict'], 'pass')
        rep = self.analyze(rows('xdev-ext', [1.0] * 10, 1, 1), rows('mooncake', [1.0] * 10, 1, 1))
        self.assertEqual(self.point(rep)['host2_memory_bytes_per_byte']['verdict'], 'not_measured')

    def test_background_rate_is_reported_beside_the_raw_value(self):
        with tempfile.TemporaryDirectory(prefix='kv-an-') as tmp:
            d = write_arm(tmp, 'xdev-ext', rows('xdev-ext', [2.0] * 10, 1, 1), idle=(0.1, 0.2))
            rep = ka.analyze([d], resamples=100, seed=1)
        s = rep['arms'][0]['points'][0]
        self.assertAlmostEqual(s['host1_core_seconds_per_gb']['raw'], 1.0)
        self.assertAlmostEqual(s['host1_core_seconds_per_gb']['minus_idle'],
                               1.0 - 0.1 * 2.0 / 0.671088640)

    def test_recompute_comparison(self):
        with tempfile.TemporaryDirectory(prefix='kv-an-') as tmp:
            dirs = [write_arm(tmp, 'xdev-ext', rows('xdev-ext', [1.0] * 10, 1, 1))]
            rc = Path(tmp) / 'recompute'
            rc.mkdir()
            (rc / 'run.json').write_text(json.dumps(dict(schema=1, kind='recompute')))
            (rc / 'results.jsonl').write_text(''.join(json.dumps(dict(
                model='qwen3-14b', prefix_tokens=4096, rep=i, ok=True, wall_ns=int(0.5e9),
                reported=dict(prefill_seconds=0.4))) + '\n' for i in range(10)))
            rep = ka.analyze(dirs + [rc], resamples=100, seed=1)
        r = rep['recompute'][0]
        self.assertAlmostEqual(r['recompute_s_median'], 0.4, msg='the command\'s own prefill time')
        self.assertAlmostEqual(r['restore_over_recompute'], 1.0 / 0.4)
        self.assertTrue(rep['slower_than_recompute_on_all_prefixes'])


if __name__ == '__main__':
    unittest.main()
