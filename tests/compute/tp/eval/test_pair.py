# SPDX-License-Identifier: GPL-2.0
"""Literal arithmetic fixtures, not physical EARLY or performance evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
PAIR = ROOT / 'tests/benchmarks/tp/pair.py'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class PairTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PAIR.is_file(), 'paired diagnostic analysis is missing')
        self.pair = module(PAIR, 'tp_pair')
        self.runner = module(ROOT / 'tests/benchmarks/tp/run.py', 'tp_pair_runner')

    def summary(self, early, echo=False):
        # Off durations 100/200/300; on 50/100/150. No device ran.
        depth = 1 if echo else 2
        m = dict(record='metadata', native_mode=2, handoff_mode='gpu',
                 early_cts_requested=early, communicator=7, epoch=10 if early else 9,
                 rank=0, clock=1 if echo else 2, trace_dropped=0,
                 requested_depth=depth, native_high_water=depth, group_bytes=128,
                 frame_count=depth, frame_size=4096, wire_header_bytes=64,
                 completed=3 * depth, operation=4 if echo else 1, dtype=3,
                 elements=1, rows=1, iterations=3, first_sequence=23,
                 payload_bytes=4, timeout_ns=600000000000,
                 completion_boundary='kernel-end-prefix',
                 tx_session_id=21 if early else 11, rx_session_id=22 if early else 12)
        if echo:
            m['execution_kind'] = 'echo'
        records = []
        for wave in range(3):
            records.append(dict(record='interval', start=1000 * (wave + 1),
                                end=1000 * (wave + 1) + (wave + 1) * (50 if early else 100),
                                rank=0, clock=1, kind='rtt' if echo else 'batch',
                                completed=True, custody_released=True))
            for j in range(depth):
                records.append(dict(record='validation', sequence=23 + wave * depth + j,
                                    rank=0, direction='rx', payload_bytes=128 if echo else 4,
                                    valid=True))
            if not echo:
                for seq, t, kind, n in [(0,100,1,1), (1,110,1,2), (0,120,3,2),
                                       (0,130,4,2), (0,150,5,1), (1,160,3,1),
                                       (1,170,4,1), (1,200,5,0)]:
                    records.append(dict(record='event', sequence=23 + wave * 2 + seq,
                                        timestamp=(wave * 200 + t) * (1 if early else 2),
                                        kind=kind, clock=2, rank=0, payload_bytes=4,
                                        wire_bytes=128, logical_inflight=n))
        records.append(m)
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / 'raw.jsonl'
            raw.write_text(''.join(json.dumps(r) + '\n' for r in records))
            return self.runner.analyze_file(raw)

    def test_paired_latency_and_two_different_rate_denominators(self):
        result = self.pair.compare(self.summary(False), self.summary(True), warmup=1)
        self.assertEqual(result['qualification'], 'external-required')
        self.assertIsNone(result['actual_early_proven'])
        self.assertEqual(result['rank'], 0)
        self.assertEqual(result['off']['e6']['p50_ns'], 250)
        self.assertEqual(result['on']['e6']['p95_ns'], 147.5)
        self.assertEqual(result['off']['e6']['samples'], 2)
        self.assertEqual(result['off']['e6']['validated_rx_bytes'], 16)
        self.assertEqual(result['off']['e6']['service_rx_bytes_per_second'], 32e6)
        self.assertEqual(result['off']['e7']['whole_trace_rx_bytes_per_second'], 24e6)
        self.assertEqual(result['on']['e7']['whole_trace_rx_bytes_per_second'], 48e6)
        self.assertEqual(result['off']['e7']['logical_inflight_high_water'], 2)
        self.assertEqual(result['on_over_off_service_throughput'], 2)
        self.assertEqual(result['off_over_on_p50_latency'], 2)
        self.assertIsNone(result['dma_consumer_overlap'])

    def test_geometry_rank_and_completion_mismatch_rejected(self):
        for key, value in [('elements', 2), ('dtype', 1), ('requested_depth', 1),
                           ('operation', 3), ('timeout_ns', 4), ('rank', 1),
                           ('completion_boundary', 'user-done'),
                           ('frame_count', 9), ('payload_bytes', 5)]:
            with self.subTest(key=key):
                off, on = self.summary(False), self.summary(True)
                on['metadata'][key] = value
                with self.assertRaises(ValueError):
                    self.pair.compare(off, on)
        off, on = self.summary(False), self.summary(True)
        del on['metadata']['elements']
        with self.assertRaises(ValueError):
            self.pair.compare(off, on)

    def test_request_flag_is_boolean_and_never_proves_mechanism(self):
        for selected in (True, 1, None):
            off, on = self.summary(False), self.summary(True)
            off['metadata']['early_cts_requested'] = selected
            with self.assertRaises(ValueError):
                self.pair.compare(off, on)
        result = self.pair.compare(self.summary(False), self.summary(True))
        self.assertIsNone(result['actual_early_proven'])
        self.assertEqual(result['on']['early_cts_requested'], True)

    def test_incomplete_intervals_or_invalid_payload_not_accepted(self):
        for damage in ('short', 'zero', 'float', 'bytes', 'completed', 'session'):
            off, on = self.summary(False), self.summary(True)
            if damage == 'short':
                on['host_intervals'].pop()
            elif damage == 'zero':
                on['host_intervals'][0]['duration_ns'] = 0
            elif damage == 'float':
                on['host_intervals'][0]['duration_ns'] = float('nan')
            elif damage == 'bytes':
                on['payload_bytes_by_direction']['rx'] = 20
            elif damage == 'completed':
                on['metadata']['completed'] = 5
            else:
                on['metadata']['tx_session_id'] = on['metadata']['rx_session_id']
            with self.subTest(damage=damage), self.assertRaises(ValueError):
                self.pair.compare(off, on)

    def test_echo_does_not_invent_e7_or_validated_tensor_bytes(self):
        result = self.pair.compare(self.summary(False, True), self.summary(True, True))
        self.assertIsNone(result['off']['e7'])
        self.assertIsNone(result['off']['e6']['validated_rx_bytes'])
        self.assertIsNone(result['off']['e6']['service_rx_bytes_per_second'])
        self.assertEqual(result['off']['e6']['p50_ns'], 200)

    def test_invalid_warmup_is_rejected(self):
        for warmup in (-1, 3, True, 0.5):
            with self.subTest(warmup=warmup), self.assertRaises(ValueError):
                self.pair.compare(self.summary(False), self.summary(True), warmup=warmup)

    def test_pair_output_is_exclusive_and_keeps_input_summaries(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            off, on, output = (directory / n for n in ('off.json', 'on.json', 'pair.json'))
            original = []
            for path, flag in ((off, False), (on, True)):
                path.write_text(json.dumps(self.summary(flag)))
                original.append(path.read_bytes())
            command = [sys.executable, str(PAIR), '--off', str(off), '--on', str(on),
                       '--output', str(output)]
            first = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(first.returncode, 0, first.stderr)
            saved = output.read_bytes()
            second = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), saved)
            self.assertEqual([off.read_bytes(), on.read_bytes()], original)


if __name__ == '__main__':
    unittest.main()
