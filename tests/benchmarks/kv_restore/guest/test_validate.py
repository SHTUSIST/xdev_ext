#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The local-verify oracle rejects every single-fact deviation from a correct run.

A synthetic console in the worker's exact line format passes; changing one
fact (digest, verification, counts, refusal, exit, LBA size, a missing or
extra line) must fail. This tests the oracle only; it boots nothing.
"""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_guest_validate', HERE / 'validate.py')
gv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gv)


def console(expected, edit=None, max_kb=512, dst='dmabuf'):
    """Lines a correct guest prints; edit(run, index, record) may change one."""
    ce = dst == 'ce-vmm'
    out = ['KV_GUEST_FACT lba_bytes=512', f'KV_GUEST_FACT max_hw_sectors_kb={max_kb}']
    for e in gv.adjust(expected, max_kb * 1024):
        out.append(f'KV_GUEST_RUN_BEGIN {e["name"]}')
        ready = dict(role='local-verify', dry_run=False, session_id=7, pool_frames=e['pool_frames'],
                     dst=dst)
        if ce:
            ready['ring_frames'] = e['ring_frames']
        records = [('KV_READY', ready)]
        t = 1000
        for r in e['results']:
            if r.get('build_abort'):
                body = dict(run=r['run'], role='local-verify', ok=False, error=r['error'],
                            dry_run=False, bytes=0, started=True, t0_ns=t, t1_ns=t + 9,
                            latency_ns=9, worker_cpu_us=1, wait_err=r['error'], verified=None,
                            stats=dict(done=0, abort=1, inflight=0, sequestered=0,
                                       last_err=r['error'], submitted=[0, 0], completed=[0, 0]))
            elif r['error']:
                body = dict(run=r['run'], role='local-verify', ok=False, error=r['error'],
                            dry_run=False, bytes=0, started=False, t0_ns=0, t1_ns=0, latency_ns=0,
                            worker_cpu_us=0, wait_err=0, verified=None)
            else:
                body = dict(run=r['run'], role='local-verify', ok=True, error=0, dry_run=False,
                            bytes=r['bytes'], plan=dict(groups=r['groups'], first_seq=r['first_seq']),
                            started=True, t0_ns=t, t1_ns=t + 50, latency_ns=50, worker_cpu_us=3,
                            wait_err=0, verified=True, first_bad=-1, outside_bad=-1,
                            digest=f'0x{r["digest"]:016x}',
                            stats=dict(done=r['cumulative'], abort=0, inflight=0, sequestered=0,
                                       last_err=0,
                                       submitted=[r['cumulative'], r['cumulative'] if ce else 0],
                                       completed=[r['cumulative'], r['cumulative'] if ce else 0]),
                            dst=dst, cpu_copy_bytes=0,
                            payload_path='nvme-read>host-frame>ce-h2d' if ce else
                            'nvme-read>dmabuf-frame')
                t += 100
            records.append(('KV_RESULT', body))
        records.append(('KV_BYE', dict(error=0, stop_error=e['stop_error'], retained=False,
                                        restores=e['restores'])))
        for i, (kind, body) in enumerate(records):
            if edit:
                kind, body = edit(e['name'], i, kind, copy.deepcopy(body))
            if kind:
                out.append(f'{kind} {json.dumps(body)}')
        out.append(f'KV_GUEST_RUN_EXIT {e["name"]} 0')
    return '\n'.join(out) + '\n'


class Oracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(json.dumps(gv.expectations()))

    def test_correct_console_passes(self):
        report = gv.validate(console(self.expected), self.expected)
        self.assertEqual(len(report), 7)
        # With a 128 KiB maximum transfer the 256 KiB run must abort, not pass.
        report = gv.validate(console(self.expected, max_kb=128), self.expected)
        self.assertEqual(len(report), 5)
        with self.assertRaises(gv.OracleError):
            gv.validate(console(self.expected, max_kb=128).replace(
                'max_hw_sectors_kb=128', 'max_hw_sectors_kb=512'), self.expected)

    def test_oversize_group_mutations_fail(self):
        def edit_c(index, change):
            def edit(name, i, kind, body):
                return change(kind, body) if name == 'C' and i == index else (kind, body)
            return console(self.expected, edit, max_kb=128)
        for why, text in {
            'abort with a native command': edit_c(1, lambda k, b: (k, dict(b, stats=dict(
                b['stats'], submitted=[1, 0])))),
            'later restore accepted': edit_c(2, lambda k, b: (k, dict(b, error=-114))),
            'stop error hidden': edit_c(3, lambda k, b: (k, dict(b, stop_error=0))),
        }.items():
            with self.subTest(why=why), self.assertRaises(gv.OracleError):
                gv.validate(text, self.expected)

    def mutate(self, run, index, change):
        def edit(name, i, kind, body):
            if name == run and i == index:
                return change(kind, body)
            return kind, body
        return console(self.expected, edit)

    def test_single_fact_mutations_fail(self):
        def field(key, value):
            def change(kind, body):
                body[key] = value
                return kind, body
            return change

        def stat(key, value):
            def change(kind, body):
                body['stats'][key] = value
                return kind, body
            return change

        mutations = {
            'digest': ('A', 1, field('digest', '0x0000000000000001')),
            'not verified': ('A', 2, field('verified', False)),
            'outside poison touched but verified': ('B', 1, field('verified', None)),
            'done off by one': ('A', 3, stat('done', 20 + 36 + 9)),
            'aborted batch': ('B', 2, stat('abort', 1)),
            'sequestered': ('A', 1, stat('sequestered', 1)),
            'refusal accepted': ('A', 4, field('ok', True)),
            'wrong refusal errno': ('A', 5, field('error', -22)),
            'refused after START': ('A', 4, field('started', True)),
            'bytes differ': ('B', 1, field('bytes', 1)),
            'first_seq differs': ('A', 2, lambda k, b: (k, dict(b, plan=dict(b['plan'], first_seq=1)))),
            'retained at exit': ('A', 6, field('retained', True)),
            'stop error reported': ('B', 3, field('stop_error', -125)),
            'missing result': ('B', 2, lambda k, b: (None, b)),
            'dry run': ('B', 0, field('dry_run', True)),
            'wrong pool': ('A', 0, field('pool_frames', 64)),
        }
        for why, (run, index, change) in mutations.items():
            with self.subTest(why=why), self.assertRaises((gv.OracleError, gv.kp.ProtocolError)):
                gv.validate(self.mutate(run, index, change), self.expected)

    def test_guest_level_mutations_fail(self):
        good = console(self.expected)
        for why, text in {
            'worker exit 1': good.replace('KV_GUEST_RUN_EXIT B 0', 'KV_GUEST_RUN_EXIT B 1'),
            '4096-byte LBAs': good.replace('lba_bytes=512', 'lba_bytes=4096'),
            'run missing': good.split('KV_GUEST_RUN_BEGIN B')[0],
            'extra line': good.replace('KV_GUEST_RUN_EXIT A 0',
                                       'KV_ERROR {"where": "x", "error": -22}\nKV_GUEST_RUN_EXIT A 0'),
        }.items():
            with self.subTest(why=why), self.assertRaises((gv.OracleError, gv.kp.ProtocolError)):
                gv.validate(text, self.expected)

    def test_planned_refusals_must_have_their_stated_reason(self):
        original = gv.RUNS[0]['go']
        bad = list(original)
        # One Qwen3-8B token is not whole groups: refused with EINVAL, not EALREADY.
        bad[3] = ('a4', 'qwen3-8b-ctx', 1, 3, 0, -gv.errno.EALREADY)
        gv.RUNS[0]['go'] = bad
        try:
            with self.assertRaises(gv.kl.LayoutError):
                gv.expectations()
            bad[3] = ('a4', 'qwen3-8b-ctx', 16, 3, 0, -gv.errno.EALREADY)  # larger keys: accepted
            with self.assertRaises(gv.OracleError):
                gv.expectations()
        finally:
            gv.RUNS[0]['go'] = original

    def test_make_plan_image_has_objects_at_their_lbas(self):
        with tempfile.TemporaryDirectory(prefix='kv-guest-plan-') as tmp:
            plan = gv.make_plan(tmp)
            disk = (Path(tmp) / 'source.raw').read_bytes()
            m = gv.manifest()
            for o in m.objects:
                self.assertEqual(disk[o.slba * 512:o.slba * 512 + 8192],
                                 gv.kl.pattern_bytes(o.seed, 0, 8192))
            # Around the objects the window holds the decoy, not zeros.
            q14 = m.object('qwen3-14b-ctx')
            before = q14.slba * 512 - 4096
            self.assertEqual(disk[before:before + 4096],
                             gv.kl.pattern_bytes(gv.DECOY_SEED, before, 4096))
            go = (Path(tmp) / 'go-A.txt').read_text().splitlines()
            self.assertEqual(go[-1], 'QUIT')
            self.assertEqual(len(go), 6)
            self.assertEqual(plan['expectations'], json.loads(json.dumps(gv.expectations())))


class CeVmmOracle(unittest.TestCase):
    """--dst ce-vmm: NVMe READ into a recycled host-frame ring, the GPU copy
    engine into a CUDA VMM allocation; the CPU copies no payload byte."""

    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads(json.dumps(gv.expectations('ce-vmm')))

    def console(self, edit=None):
        return console(self.expected, edit, dst='ce-vmm')

    def test_plan_uses_host_frames_and_a_vram_pool(self):
        for run in gv.runs('ce-vmm'):
            args = [str(a) for a in gv.worker_args(run, 'ce-vmm')]
            self.assertEqual(args[args.index('--frame-bytes') + 1], '4096')
            self.assertEqual(args[args.index('--dst') + 1], 'ce-vmm')
            self.assertIn('--ce-prog', args)
            self.assertIn('--ce-dev', args)
        self.assertTrue(all(e['ring_frames'] for e in self.expected))
        self.assertEqual(sum(1 for e in self.expected for r in e['results'] if not r['error']), 5)
        self.assertEqual({r['error'] for e in self.expected for r in e['results']},
                         {-gv.errno.ENOSPC, -gv.errno.EALREADY, 0})

    def test_correct_console_passes(self):
        report = gv.validate(self.console(), self.expected, 'ce-vmm')
        self.assertEqual(len(report), 5)

    def test_mutations_fail(self):
        def at(run, index, change):
            def edit(name, i, kind, body):
                return change(kind, body) if (name, i) == (run, index) else (kind, body)
            return self.console(edit)

        def stats(key, stage, value):
            def change(kind, body):
                body['stats'][key][stage] = value
                return kind, body
            return change
        for why, text in {
            'CPU copied payload': at('A', 1, lambda k, b: (k, dict(b, cpu_copy_bytes=4096))),
            'copy count missing': at('A', 2, lambda k, b: (k, {x: y for x, y in b.items()
                                                                if x != 'cpu_copy_bytes'})),
            'CE stage did not run': at('A', 1, stats('completed', 1, 0)),
            'CE submitted short': at('B', 2, stats('submitted', 1, 1)),
            'other destination': at('B', 1, lambda k, b: (k, dict(b, dst='dmabuf'))),
            'payload path': at('A', 3, lambda k, b: (k, dict(b, payload_path='nvme-read>dmabuf-frame'))),
            'ready destination': at('A', 0, lambda k, b: (k, dict(b, dst='peer'))),
            'ring size': at('B', 0, lambda k, b: (k, dict(b, ring_frames=1))),
            'digest': at('A', 1, lambda k, b: (k, dict(b, digest='0x0000000000000001'))),
        }.items():
            with self.subTest(why=why), self.assertRaises((gv.OracleError, gv.kp.ProtocolError)):
                gv.validate(text, self.expected, 'ce-vmm')
        with self.assertRaises(gv.OracleError):
            gv.validate(console(json.loads(json.dumps(gv.expectations())), dst='dmabuf'),
                        self.expected, 'ce-vmm')

    def test_make_plan_records_the_destination(self):
        with tempfile.TemporaryDirectory(prefix='kv-guest-ce-') as tmp:
            plan = gv.make_plan(tmp, 'ce-vmm')
            self.assertEqual(plan['dst'], 'ce-vmm')
            self.assertEqual(plan['expectations'], self.expected)
            args = (Path(tmp) / 'args-A.txt').read_text().split()
            self.assertEqual(args[args.index('--dst') + 1], 'ce-vmm')
            self.assertTrue((Path(tmp) / 'source.raw').exists())


if __name__ == '__main__':
    unittest.main()
