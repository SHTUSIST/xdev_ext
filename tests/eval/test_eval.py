#!/usr/bin/env python3
"""Functional and negative checks; no throughput acceptance threshold."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
BIN = ROOT / 'build' / 'bench_file_pipeline'
CUDA = ROOT / 'build' / 'bench_cuda_staging'


class EvalContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BIN.is_file(), 'portable eval executable has not been implemented/built')
        self.tmp = tempfile.TemporaryDirectory(prefix='xdev-eval-')
        self.addCleanup(self.tmp.cleanup)
        self.file = Path(self.tmp.name) / 'input.bin'
        self.file.write_bytes(bytes((i * 37 + i // 251) % 256 for i in range(65553)))

    def pipeline(self, *extra, env=None):
        return subprocess.run([str(BIN), '--file', str(self.file), '--bytes', '65553',
                               '--chunk', '4096', '--iterations', '3', *extra],
                              text=True, capture_output=True, timeout=20, env=env)

    def test_full_stream_tail_and_counters(self):
        result = self.pipeline('--compute-bytes', '111')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        for name in ('read_bytes', 'sent_bytes', 'verified_bytes'):
            self.assertEqual(data[name], 65553 * 3, name)
        self.assertEqual(data['backend'], 'posix')
        self.assertEqual(data['route'], 'buffered-file-to-tcp-loopback')
        self.assertEqual(data['completion'], 'receiver-full-byte-compare')
        self.assertEqual(data['status'], 'ok')
        self.assertGreater(data['elapsed_ns'], 0)
        self.assertEqual(data['compute_bytes'], (16 * 111 + 17) * 3)

    def test_eintr_and_partial_real_io(self):
        shim = Path(self.tmp.name) / 'short_io.so'
        build = subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                                str(ROOT / 'short_io_shim.c'), '-o', str(shim), '-ldl'],
                               text=True, capture_output=True)
        self.assertEqual(build.returncode, 0, build.stderr)
        env = os.environ.copy()
        env['LD_PRELOAD'] = str(shim)
        result = self.pipeline(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        self.assertEqual(record['verified_bytes'], 65553 * 3)
        self.assertEqual(record['read_bytes'], record['verified_bytes'])
        self.assertEqual(record['sent_bytes'], record['verified_bytes'])

    def test_corruption_is_failure(self):
        result = self.pipeline('--fault', 'corrupt')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('byte mismatch', result.stderr)
        self.assertNotIn('"status":"ok"', result.stdout)

    def test_truncation_is_failure(self):
        result = self.pipeline('--fault', 'truncate')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('truncated stream', result.stderr)

    def test_backend_error_is_failure(self):
        result = self.pipeline('--fault', 'backend-error')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('injected backend error', result.stderr)

    def test_optional_uring_real_data_and_failure(self):
        for backend in ('io_uring', 'io_uring-fixed'):
            with self.subTest(backend=backend):
                result = self.pipeline('--backend', backend)
                if result.returncode == 4:
                    self.assertIn('unavailable', result.stderr)
                    self.assertEqual(result.stdout, '')
                    continue  # Asserted capability refusal, not a passing device run.
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['verified_bytes'], 65553 * 3)
                for fault, diagnostic in [('corrupt', 'byte mismatch'),
                                          ('truncate', 'truncated stream')]:
                    result = self.pipeline('--backend', backend, '--fault', fault)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(diagnostic, result.stderr)

    def test_bounds_and_invalid_numbers(self):
        for args in [('--bytes', '65554'), ('--bytes', '-1'), ('--chunk', '0'),
                     ('--iterations', '18446744073709551615'),
                     ('--chunk', 'abc'), ('--bytes', '\t1'), ('--compute-bytes', '4097'),
                     ('--backend', 'xdev_ext'), ('--file', self.tmp.name)]:
            with self.subTest(args=args):
                result = self.pipeline(*map(str, args))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')

    def test_missing_cuda_is_explicit_capability_failure(self):
        self.assertTrue(CUDA.is_file(), 'CUDA staging executable missing')
        result = subprocess.run([str(CUDA), '--direction', 'load', '--memory', 'pinned',
                                 '--input', str(self.file), '--bytes', '65553',
                                 '--cuda-library', str(Path(self.tmp.name) / 'missing.so')],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('unavailable', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_verifier_rejects_missing_route_counters_and_nonzero_exit(self):
        spec = importlib.util.spec_from_file_location('eval_run', ROOT / 'run.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = self.pipeline()
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads(result.stdout)
        module.verify_pipeline(record, 65553, 3, 'posix', 4096)
        for field in ('backend', 'route', 'read_bytes', 'sent_bytes', 'verified_bytes', 'completion', 'status', 'chunk', 'chunks', 'cpu_us', 'elapsed_ns'):
            broken = record.copy()
            broken.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.verify_pipeline(broken, 65553, 3, 'posix', 4096)
        broken = record.copy()
        broken['verified_bytes'] -= 1
        with self.assertRaises(ValueError):
            module.verify_pipeline(broken, 65553, 3, 'posix', 4096)
        for field, value in [('backend', 'fake'), ('route', 'native-peer'),
                             ('read_bytes', True), ('sent_bytes', -1),
                             ('chunks', record['chunks'] + 1), ('chunk', 4096.0),
                             ('chunk', '4096'), ('chunk', True), ('elapsed_ns', 0)]:
            broken = record.copy()
            broken[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                module.verify_pipeline(broken, 65553, 3, 'posix', 4096)
        with self.assertRaises(RuntimeError):
            module.checked_result(subprocess.CompletedProcess([], 1, result.stdout, 'backend failed'))

    def test_runner_rejects_real_pipeline_with_self_consistent_wrong_chunk(self):
        spec = importlib.util.spec_from_file_location('eval_run', ROOT / 'run.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        real_invoke = module.invoke
        mutated = []

        def wrong_geometry(command):
            result = real_invoke(command)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(result.stdout)
            self.assertEqual(record['chunk'], 4096)
            self.assertEqual(record['chunks'], 51)
            record['chunk'] = 8192
            record['chunks'] = 27
            mutated.append(record)
            return subprocess.CompletedProcess(result.args, result.returncode,
                                               json.dumps(record), result.stderr)

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(module, 'invoke', side_effect=wrong_geometry), \
                patch.object(module.sys, 'argv', ['run.py', '--suite', 'portable',
                                                  '--bytes', '65553', '--chunk', '4096',
                                                  '--iterations', '3']), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = module.main()
        self.assertTrue(mutated, 'mutation must exercise a real POSIX backend result')
        self.assertEqual(status, 1, stderr.getvalue())
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('chunk', stderr.getvalue())

    def test_runner_rejects_cuda_fixture_with_wrong_chunk(self):
        spec = importlib.util.spec_from_file_location('eval_run', ROOT / 'run.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        record = dict(status='ok', backend='cuda_pageable_staging', direction='load',
                      route='buffered-file-host-cuda', bytes=65553, chunk=8192,
                      completion='synchronous-copy-full-byte-compare',
                      io_bytes=65553, verified_bytes=65553, file_ns=1, transfer_ns=1,
                      elapsed_ns=1, cpu_us=0)
        result = subprocess.CompletedProcess([], 0, json.dumps(record), '')
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(module, 'invoke', return_value=result) as invoke, \
                patch.object(module.sys, 'argv', ['run.py', '--suite', 'cuda',
                                                  '--bytes', '65553', '--chunk', '4096']), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = module.main()
        self.assertEqual(status, 1, stderr.getvalue())
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('chunk', stderr.getvalue())
        self.assertEqual(invoke.call_count, 1)

    def test_cuda_result_validator_rejects_incomplete_metadata(self):
        spec = importlib.util.spec_from_file_location('eval_run', ROOT / 'run.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        record = dict(status='ok', backend='cuda_pinned_staging', direction='checkpoint',
                      route='cuda-host-buffered-file', bytes=65553, chunk=4096,
                      completion='synchronous-copy-full-byte-compare-fsync-file-reread',
                      io_bytes=65553, verified_bytes=65553, file_ns=1, transfer_ns=1,
                      elapsed_ns=1, cpu_us=0)
        module.verify_cuda(record, 65553, 'checkpoint', 'pinned', 4096)
        for field in record:
            incomplete = record.copy()
            incomplete.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.verify_cuda(incomplete, 65553, 'checkpoint', 'pinned', 4096)
        incomplete = record.copy()
        incomplete['verified_bytes'] -= 1
        with self.assertRaises(ValueError):
            module.verify_cuda(incomplete, 65553, 'checkpoint', 'pinned', 4096)
        for chunk in (8192, 4096.0, '4096', True, 0, -1, None):
            incomplete = record.copy()
            incomplete['chunk'] = chunk
            with self.subTest(chunk=chunk), self.assertRaises(ValueError):
                module.verify_cuda(incomplete, 65553, 'checkpoint', 'pinned', 4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
