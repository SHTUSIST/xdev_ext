#!/usr/bin/env python3
"""Actual non-dry-run worker verification using CPU-backed device boundaries.

Includes kv_restore.c unchanged, links the actual libxdev_ext, loads index and
payload files, and calls handle_go. Only session/DMA/CE external boundaries are
substituted. CUDA readback uses dlopen/dlsym on a CPU-memory test DSO. This is
host correctness, never GPU, DMA, vLLM or performance evidence.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import kv_layout as kl

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[2] / 'kernel'
BYTES = 2359296  # one 16-token qwen3-8b block: 16 * 36 * 8 * 512
HASH = 'ab' * 32
# Pinned FNV-1a of b'hello' followed by BYTES-5 zero bytes; no oracle helper
# computes this expected value at runtime. The C fixture also checks the
# standard FNV-1a "hello" test vector before invoking the actual worker.
REAL_FNV = 0x7c8ffb684c22cf39


class WorkerVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='kv-actual-verify-')
        cls.out = Path(cls.tmp.name)
        cc = shutil.which(os.environ.get('CC', 'cc'))
        if not cc:
            raise unittest.SkipTest('C compiler unavailable')
        if subprocess.run(['pkg-config', '--atleast-version=1.0', 'libbpf'],
                          capture_output=True).returncode:
            raise unittest.SkipTest('needs libbpf >= 1.0 for the actual worker/library')
        lib = cls.out / 'lib'
        subprocess.run(['make', '-s', '-C', str(KERNEL / 'tools/xdev_ext_mech/lib'),
                        'BUILD_DIR=' + str(lib)], check=True)
        flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=undefined', '-fno-sanitize-recover=undefined']
        cls.dso = cls.out / 'cuda-boundary.so'
        subprocess.run([cc, *flags, '-shared', '-fPIC',
                        str(HERE / 'worker_verify_cuda_boundary.c'), '-o', str(cls.dso)], check=True)
        cls.binary = cls.out / 'worker-verify'
        wrappers = ['ioctl', 'xdev_ext_session_start_frames', 'xdev_ext_session_wait',
                    'bpf_map__fd', 'bpf_map_update_elem']
        subprocess.run([cc, *flags, '-ffunction-sections', '-fdata-sections',
                        str(HERE / 'worker_verify_boundary.c'), str(lib / 'libxdev_ext.a'),
                        '-Wl,--gc-sections', *['-Wl,--wrap=' + w for w in wrappers],
                        '-lbpf', '-lelf', '-lz', '-ldl', '-pthread', '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def invoke(self, mode, payload, expected=None, guard=False, offset=BYTES):
        path = self.out / 'payload.kv'
        path.write_bytes(payload)
        entry = kl.IndexEntry(HASH, 'obj', 2048, offset, BYTES, 16, expected)
        # Python manifest validation and the actual C loader read the same
        # block geometry and index, including a nonzero object-relative offset.
        manifest = kl.parse_manifest({
            'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
            'window': {'slba': 2048, 'nlb': (64 << 20) // 512},
            'objects': [{'name': 'obj', 'model': 'qwen3-8b-bf16', 'tokens': 32,
                         'seed': 9, 'slba': 2048, 'nlb': 2 * BYTES // 512,
                         'kv': kl.BlockLayout.for_model('qwen3-8b-bf16', 16).to_json()}]})
        kl.PrefixIndex([entry], manifest)
        index = self.out / 'kv.index'
        kl.write_index(index, [entry])
        r = subprocess.run([str(self.binary), str(index), str(path), mode, str(self.dso),
                            'guard' if guard else 'clean'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = [line for line in r.stdout.splitlines() if line.startswith('KV_RESULT ')]
        self.assertEqual(len(lines), 1, r.stdout)
        result = json.loads(lines[0][len('KV_RESULT '):])
        self.assertFalse(result['dry_run'])
        self.assertTrue(result['started'])
        self.assertEqual(result['object_slba'], 2048 + offset // 512)
        return result

    def test_pattern_prefix_nonzero_object_offset_all_paths(self):
        payload = kl.pattern_bytes(9, BYTES, BYTES)
        for mode in ('dmabuf', 'ce', 'peer'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, payload)
                self.assertTrue(result['ok'], result)
                self.assertTrue(result['verified'], result)
                self.assertFalse(result['expect_fnv1a'])

    def test_digest_verification_executes_all_paths(self):
        payload = b'hello' + bytes(BYTES - 5)
        for mode in ('dmabuf', 'ce', 'peer'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, payload, REAL_FNV)
                self.assertTrue(result['ok'], result)
                self.assertTrue(result['verified'], result)
                self.assertTrue(result['expect_fnv1a'])
                self.assertEqual(result['digest'], '0x7c8ffb684c22cf39')

    def test_wrong_digest_is_rejected_all_paths(self):
        for mode in ('dmabuf', 'ce', 'peer'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, b'hello' + bytes(BYTES - 5), REAL_FNV ^ 1)
                self.assertFalse(result['ok'], result)
                self.assertFalse(result['verified'], result)

    def test_corrupt_real_payload_is_rejected_all_paths(self):
        data = bytearray(b'hello' + bytes(BYTES - 5))
        data[-1] = 1
        for mode in ('dmabuf', 'ce', 'peer'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, data, REAL_FNV)
                self.assertFalse(result['ok'], result)
                self.assertFalse(result['verified'], result)

    def test_digest_mode_retains_outside_guards_for_local_verify(self):
        for mode in ('dmabuf', 'ce'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, b'hello' + bytes(BYTES - 5), REAL_FNV, guard=True)
                self.assertFalse(result['ok'], result)
                self.assertEqual(result['outside_bad'], 0)

    def test_real_payload_without_digest_is_not_accepted_as_pattern(self):
        for mode in ('dmabuf', 'ce', 'peer'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, b'hello' + bytes(BYTES - 5))
                self.assertFalse(result['verified'], result)

    def test_zero_offset_pattern_compatibility(self):
        for mode in ('dmabuf', 'ce', 'peer'):
            with self.subTest(mode=mode):
                result = self.invoke(mode, kl.pattern_bytes(9, 0, BYTES), offset=0)
                self.assertTrue(result['verified'], result)


if __name__ == '__main__':
    unittest.main()
