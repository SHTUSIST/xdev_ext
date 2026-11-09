#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Legacy RX batch completion must expedite pending depth reuse without ingress.

Runs actual RX/pending, core terminal release/progress and stage-kick bodies at
explicit OS/list/ref/lifecycle/hold-admission seams. No kernel, DMA, concurrency
or throughput result is established. Run directly from the canonical checkout;
logical-view callers supply XDEV_EXT_CANONICAL_ROOT. Optional evidence is written
under XDEV_EXT_WAKE_EVIDENCE_DIR. Temporary executables are cleaned on exit.
"""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def canonical_root():
    if os.environ.get('XDEV_EXT_CANONICAL_ROOT'):
        return Path(os.environ['XDEV_EXT_CANONICAL_ROOT']).resolve()
    for parent in HERE.parents:
        if (parent / 'source-layout.json').is_file():
            return parent
    raise RuntimeError('Set XDEV_EXT_CANONICAL_ROOT to the matching source checkout')


class LegacyRxBatchCompletionWakeup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = canonical_root()
        cls.scratch = tempfile.TemporaryDirectory(
            prefix='legacy-rx-wakeup-', dir=os.environ.get('XDEV_EXT_TEST_TMPDIR', HERE))
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.work = Path(cls.scratch.name)
        cls.evidence = Path(os.environ['XDEV_EXT_WAKE_EVIDENCE_DIR']) if os.environ.get('XDEV_EXT_WAKE_EVIDENCE_DIR') else None
        if cls.evidence:
            cls.evidence.mkdir(parents=True, exist_ok=True)
        spec = importlib.util.spec_from_file_location(
            'legacy_rx_wakeup_extract', cls.root / 'tests/network/pool_dma/adapter.py')
        extract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extract)
        paths = {
            'core': 'src/core/io_uring/xdev_ext_mech.c',
            'net': 'src/network/net/xdp/xsk_xdev_ext_mech.c',
            'rel': 'src/network/net/xdp/xsk_xdev_ext_mech_reliable.inc',
            'pending': 'src/network/net/xdp/xsk_xdev_ext_mech_rx_pending.inc',
            'prog': 'src/bpf/xdev_ext_mech_prog.h',
        }
        sources = {kind: (cls.root / path).read_text() for kind, path in paths.items()}
        code = (HERE / 'legacy_rx_batch_completion_wakeup_fixture.c').read_text()
        for kind, names in {
            'core': ['xdev_ext_mech_batch_get_locked', 'xdev_ext_mech_batch_put_locked',
                     'xdev_ext_mech_leave_locked', 'xdev_ext_mech_retry_kick',
                     'xdev_ext_mech_order_kick', 'xdev_ext_mech_end',
                     'xdev_ext_mech_progress_work', 'xdev_ext_mech_stage_kick'],
            'net': ['xsk_xdev_ext_mech_rx', 'xsk_mech_progress'],
            'rel': ['xsk_rel_batch_end'],
        }.items():
            for name in names:
                body = extract.function(sources[kind], name)
                if name == 'xdev_ext_mech_batch_get_locked':
                    body = 'static struct xdev_ext_mech_batch *\n' + body
                marker = '/* ACTUAL_' + name + ' */'
                if code.count(marker) != 1:
                    raise RuntimeError('Missing unique function marker: ' + name)
                code = code.replace(marker, body)
        for kind, names in {
            'net': ['xsk_mech_rx_pending_entry', 'xsk_mech_rx_pending'],
            'prog': ['xdev_ext_mp_segment', 'xdev_ext_mp_rx_order'],
        }.items():
            for name in names:
                code = code.replace('/* ACTUAL_' + name + ' */',
                                    extract.record(sources[kind], name))
        code = code.replace('/* ACTUAL_RX_ORDER */', extract.function(
            sources['prog'].replace('XDEV_EXT_MP_INLINE ', 'static inline '),
            'xdev_ext_mp_rx_order'))
        code = code.replace('/* ACTUAL_PENDING */', sources['pending'])
        if '/* ACTUAL_' in code:
            raise RuntimeError('Unfilled production source marker')
        source = cls.work / 'probe.c'
        source.write_text(code)
        cls.exe = cls.work / 'probe'
        command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g',
                   '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-Wno-unused-variable', '-fsanitize=undefined',
                   '-fno-sanitize-recover=undefined', str(source), '-o', str(cls.exe)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if cls.evidence:
            (cls.evidence / 'probe.c').write_text(code)
            (cls.evidence / 'compile.log').write_text(built.stdout + built.stderr)
            (cls.evidence / 'inputs.json').write_text(json.dumps({
                'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'compiler': command,
                'source_sha256': {paths[k]: hashlib.sha256(v.encode()).hexdigest()
                                  for k, v in sources.items()},
                'scope': 'Host production-function scheduling seams; no kernel/device acceptance',
            }, indent=2) + '\n')
        if built.returncode:
            raise RuntimeError('Fixture compile failed:\n' + built.stdout + built.stderr)

    def run_case(self, mode):
        run = subprocess.run([str(self.exe), mode], capture_output=True, text=True, timeout=5)
        if self.evidence:
            (self.evidence / (mode + '.log')).write_text(
                run.stdout + run.stderr + f'exit={run.returncode}\n')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('WAKE_REQUIRED mode=' + mode, run.stdout)

    def test_tail_burst_reuses_depth_without_later_packet(self):
        self.run_case('tail')

    def test_empty_pending_queue_does_not_schedule_extra_progress(self):
        self.run_case('empty')

    def test_later_packet_keeps_existing_immediate_wakeup(self):
        self.run_case('new-packet')

    def test_repeated_callbacks_coalesce_without_extra_admission(self):
        self.run_case('repeat')

    def test_stopping_cancels_pending_without_claiming_prior_owner(self):
        self.run_case('stop')

    def test_worker_gone_blocks_new_progress(self):
        self.run_case('worker-gone')

    def test_reliable_ack_stale_and_transmit_branches_keep_their_behavior(self):
        self.run_case('reliable')


if __name__ == '__main__':
    unittest.main(verbosity=2)
