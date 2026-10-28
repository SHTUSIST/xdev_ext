# SPDX-License-Identifier: GPL-2.0
"""Native handoff labels describe primitives and never qualify hardware/E6 arms."""
import contextlib
import importlib.util
import io
import json
import subprocess
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


class HandoffMetadataTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            'tp_handoff_runner', ROOT / 'tests/benchmarks/tp/run.py')
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)

    def records(self, kind, native_mode=1, rank=0):
        # Complete literal software fixtures. These are arithmetic/schema
        # evidence, never a claim that an actual native/GPU operation ran.
        metadata = dict(record='metadata', communicator=7, epoch=9, rank=rank,
                        clock=1 if native_mode == 1 else 2,
                        trace_dropped=0, requested_depth=1,
                        native_high_water=1, completed=1,
                        native_mode=native_mode,
                        handoff_mode='cpu' if native_mode == 1 else 'gpu')
        validation = dict(record='validation', sequence=23, rank=rank,
                          direction='rx', payload_bytes=4, valid=True)
        interval = dict(record='interval', start=100, end=190, rank=rank,
                        clock=1, kind='allreduce', completed=True,
                        custody_released=True)
        if kind == 'echo':
            metadata.update(execution_kind='echo', clock=1, group_bytes=4)
            interval['kind'] = 'rtt' if rank == 0 else 'echo_reply'
            events = []
        else:
            events = [dict(record='event', sequence=23, timestamp=t, kind=k,
                           clock=metadata['clock'], rank=rank,
                           payload_bytes=4, wire_bytes=68, logical_inflight=n)
                      for t, k, n in [(10, 1, 1), (20, 3, 1),
                                      (30, 4, 1), (40, 5, 0)]]
        return events + [validation, interval, metadata]

    def analyze(self, records):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / 'raw.jsonl'
            raw.write_text(''.join(json.dumps(r) + '\n' for r in records))
            return self.runner.analyze_file(raw)

    def test_exact_cpu_gpu_pairs_preserve_echo_and_collective_accounting(self):
        for kind in ('echo', 'collective'):
            for mode, handoff in ((1, 'cpu'), (2, 'gpu')):
                for rank in (0, 1):
                    with self.subTest(kind=kind, mode=mode, rank=rank):
                        summary = self.analyze(self.records(kind, mode, rank))
                        self.assertEqual(summary['metadata']['native_mode'], mode)
                        self.assertEqual(summary['metadata']['handoff_mode'], handoff)
                        self.assertEqual(summary['host_intervals'][0]['duration_ns'], 90)
                        if kind == 'echo':
                            self.assertEqual(summary['one_way_latency'], 'not measured')
                        else:
                            self.assertEqual(summary['payload_bytes_by_direction'], {'rx': 4})

    def test_actual_driver_emits_matching_final_metadata_for_both_branches(self):
        source = (ROOT / 'tests/benchmarks/tp/driver.cc').read_text()
        marker = r'printf("{\"record\":\"metadata\"'
        statements, offset = [], 0
        while True:
            start = source.find(marker, offset)
            if start < 0:
                break
            depth, in_string, escaped = 0, False, False
            end = source.index('(', start)
            for end in range(end, len(source)):
                char = source[end]
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == '\\':
                        escaped = True
                    elif char == '"':
                        in_string = False
                elif char == '"':
                    in_string = True
                elif char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                    if depth == 0:
                        break
            statements.append(source[start:end+1] + ';')
            offset = end + 1
        self.assertEqual(len(statements), 2, 'echo and collective final metadata emitters required')
        code = ('#include <cstdio>\n#include <cstdlib>\n'
                '#include "tests/benchmarks/tp/options.h"\n'
                'struct Stats {unsigned long long trace_dropped=0,logical_inflight_high_water=1,'
                'completed=7,gpu_invocations=7,host_control_calls=0;};\n'
                'int main(int argc,char **argv) { if(argc!=4)return 2; '
                'tp_eval_options o;o.mode=std::strtoul(argv[1],nullptr,10);'
                'o.rank=std::strtoul(argv[2],nullptr,10);o.iterations=7;'
                "Stats stats; if(argv[3][0]=='e'){" + statements[0] + '}'
                'else{' + statements[1] + '}return 0;}')
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / 'metadata.cc'
            executable = Path(directory) / 'metadata'
            probe.write_text(code)
            build = subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                                    '-I' + str(ROOT), str(probe), '-o', str(executable)],
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(build.returncode, 0, build.stderr)
            for mode, handoff in ((1, 'cpu'), (2, 'gpu')):
                for rank in (0, 1):
                    for operation in ('echo', 'collective'):
                        with self.subTest(mode=mode, rank=rank, operation=operation):
                            run = subprocess.run([str(executable), str(mode), str(rank), operation],
                                                 capture_output=True, text=True, timeout=5)
                            self.assertEqual(run.returncode, 0, run.stderr)
                            metadata = json.loads(run.stdout)
                            self.assertEqual(metadata['native_mode'], mode)
                            self.assertEqual(metadata['handoff_mode'], handoff)
                            self.assertEqual(metadata['rank'], rank)
                            self.assertEqual(metadata['completed'], 7)

    def test_missing_native_mode_or_handoff_rejected_before_either_operation(self):
        for kind in ('echo', 'collective'):
            for field in ('native_mode', 'handoff_mode'):
                with self.subTest(kind=kind, missing=field):
                    records = self.records(kind)
                    del records[-1][field]
                    with self.assertRaises(ValueError):
                        self.analyze(records)

    def test_native_mode_requires_exact_int_and_handoff_requires_matching_name(self):
        bad_pairs = [(True, 'cpu'), (False, 'gpu'), (1.0, 'cpu'),
                     ('1', 'cpu'), (None, 'cpu'), (0, 'cpu'), (3, 'gpu'),
                     (1, 'gpu'), (2, 'cpu'), (1, True), (1, 1),
                     (2, None), (2, 'GPU'), (1, '')]
        for kind in ('echo', 'collective'):
            for mode, handoff in bad_pairs:
                with self.subTest(kind=kind, mode=repr(mode), handoff=repr(handoff)):
                    records = self.records(kind)
                    records[-1].update(native_mode=mode, handoff_mode=handoff)
                    with self.assertRaises(ValueError):
                        self.analyze(records)

    def test_analyze_only_requires_external_hardware_qualification(self):
        for kind in ('echo', 'collective'):
            for mode in (1, 2):
                with self.subTest(kind=kind, mode=mode), tempfile.TemporaryDirectory() as directory:
                    raw = Path(directory) / 'raw.jsonl'
                    summary = Path(directory) / 'summary.json'
                    raw.write_text(''.join(json.dumps(r) + '\n'
                                           for r in self.records(kind, mode)))
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        status = self.runner.main(['--analyze-only', '--raw', str(raw),
                                                   '--summary', str(summary)])
                    self.assertEqual(status, 0)
                    receipt = json.loads(output.getvalue())
                    self.assertEqual(receipt['hardware_qualification'], 'external-required')
                    self.assertNotEqual(receipt.get('hardware_qualified'), True)
                    result = json.loads(summary.read_text())
                    self.assertNotIn('evaluation_arm', result)
                    self.assertNotIn('evaluation_arm', result['metadata'])


if __name__ == '__main__':
    unittest.main()
