#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The kv_restore worker's options and protocol, without any device.

--dry-run opens nothing: it answers each GO with the plan it would execute.
The plan must equal kv_layout.py's, keys must only grow, and refusals must
be reported, not guessed. Needs libbpf >= 1.0 to build (or KV_RESTORE_BIN).
"""
import errno
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kl, kp = load('kv_layout'), load('kv_protocol')
KIB, GIB = 1 << 10, 1 << 30
WINDOW = ['--window-slba', '2048', '--window-nlb', str(40 * GIB // 512), '--lba-bytes', '512',
          '--group-bytes', str(256 * KIB), '--frame-bytes', str(128 * KIB), '--depth', '32',
          '--window', '32', '--early']


def build_worker():
    given = os.environ.get('KV_RESTORE_BIN')
    if given:
        return Path(given), None
    if not shutil.which('make') or subprocess.run(['pkg-config', '--atleast-version=1.0', 'libbpf'],
                                                  capture_output=True).returncode:
        return None, None
    tmp = tempfile.TemporaryDirectory(prefix='kv-worker-')
    r = subprocess.run(['make', '-s', '-C', str(HERE), f'BUILD={tmp.name}',
                        f'{tmp.name}/kv_restore'], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    return Path(tmp.name) / 'kv_restore', tmp


BIN, _TMP = build_worker()


@unittest.skipUnless(BIN, 'needs libbpf >= 1.0 to build kv_restore (or KV_RESTORE_BIN)')
class DryRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-contract-')
        self.manifest = kl.parse_manifest({
            'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
            'window': {'slba': 2048, 'nlb': 40 * GIB // 512},
            'objects': [{'name': 'q8', 'model': 'qwen3-8b-bf16', 'tokens': 32768, 'seed': 9,
                         'slba': 2048 + 6 * GIB // 512, 'nlb': 9 * GIB // 2 // 512}]})
        self.geometry = kl.Geometry(256 * KIB, 128 * KIB, 32, 32, True)

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, role, extra):
        return kp.Worker([BIN, role, '--dry-run'] + WINDOW + extra, ready_timeout=30,
                         log=Path(self.tmp.name) / f'{role}.log')

    def restore_worker(self, pool_bytes):
        return self.worker('restore', ['--gpu-bdf', '0000:00:00.0', '--gpu-node', '/dev/null',
                                       '--pool-bytes', str(pool_bytes), '--peer', '127.0.0.1:9',
                                       '--link-token', '5'])

    def test_arguments_refused(self):
        for argv in (['serve'], ['restore'] + WINDOW, ['bogus'],
                     ['local-verify', '--dry-run'] + WINDOW + ['--nvme', '/dev/null'],
                     ['restore', '--dry-run'] + WINDOW[:-3] + ['--window', '33', '--gpu-bdf', 'x',
                                                               '--gpu-node', 'y', '--peer', 'h:1',
                                                               '--pool-bytes', '131072',
                                                               '--link-token', '1']):
            with self.subTest(argv=argv):
                r = subprocess.run([str(BIN)] + argv, capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 2, r.stdout)
                kind, body = kp.parse_line(r.stdout.strip().splitlines()[-1])
                self.assertEqual((kind, body['where']), ('KV_ERROR', 'arguments'))

    def test_restore_plans_like_python(self):
        pool = 5 * GIB
        w = self.restore_worker(pool)
        self.assertTrue(w.ready['dry_run'])
        self.assertEqual(w.ready['pool_frames'], pool // (128 * KIB))
        obj = self.manifest.object('q8')
        for ordinal, tokens, dst0 in ((1, 16384, 0), (2, 4096, 100), (5, 32768, 7)):
            want = kl.plan_restore(self.manifest, 'q8', tokens, self.geometry, ordinal, dst0,
                                   pool // (128 * KIB)).to_json()
            r = w.go(run=f'r{ordinal}', ordinal=ordinal, object_slba=obj.slba,
                     bytes=kl.kv_bytes(obj.model, tokens), dst_frame0=dst0, timeout=30)
            self.assertTrue(r['ok'], r)
            self.assertTrue(r['dry_run'])
            for key in ('groups', 'slots', 'slot0', 'first_seq', 'frames_per_group',
                        'host2_frames', 'host2_dst_frame0', 'host1_recycle_frames'):
                self.assertEqual(r['plan'][key], want[key], key)
        again = w.go(run='again', ordinal=5, object_slba=obj.slba, bytes=kl.kv_bytes(obj.model, 4096),
                     dst_frame0=0, timeout=30)
        self.assertFalse(again['ok'])
        self.assertEqual(again['error'], -errno.EALREADY, 'keys may only grow')
        big = w.go(run='big', ordinal=9, object_slba=obj.slba, bytes=kl.kv_bytes(obj.model, 32768),
                   dst_frame0=40000, timeout=30)
        self.assertEqual(big['error'], -errno.ENOSPC, 'destination beyond the pool')
        w.proc.stdin.write('GO run=bad ordinal=x\n')
        w.proc.stdin.flush()
        kind, body = w._next(30, ('KV_RESULT', 'KV_ERROR'))
        self.assertEqual((kind, body['where']), ('KV_ERROR', 'GO arguments'))
        bye = w.quit(timeout=30)
        self.assertEqual((bye['error'], bye['retained']), (0, False))
        self.assertEqual(w.returncode, 0)

    @unittest.skipIf(os.path.exists('/dev/xdev_ext_peer'), 'this host runs the xdev_ext kernel')
    def test_setup_failure_names_its_step(self):
        r = subprocess.run([str(BIN), 'local-verify'] + WINDOW + [
            '--nvme', '/dev/null', '--nvme-prog', '/dev/null', '--pool-bytes', str(64 * 128 * KIB)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout)
        kind, body = kp.parse_line(r.stdout.strip().splitlines()[-1])
        self.assertEqual(kind, 'KV_ERROR')
        self.assertEqual((body['where'], body['error']), ('setup: open /dev/xdev_ext_peer', -errno.ENOENT))

    def test_local_verify_and_serve_start_and_quit(self):
        w = self.worker('local-verify', ['--nvme', '/dev/null', '--nvme-prog', '/dev/null',
                                         '--pool-bytes', str(64 * 128 * KIB)])
        r = w.go(run='lv', ordinal=1, object_slba=2048 + 6 * GIB // 512, bytes=8 * 256 * KIB,
                 dst_frame0=3, timeout=30)
        self.assertTrue(r['ok'], r)
        self.assertEqual(r['plan']['host2_dst_frame0'], 3)
        self.assertEqual(w.quit(timeout=30)['error'], 0)
        s = self.worker('serve', ['--nvme', '/dev/null', '--nvme-prog', '/dev/null',
                                  '--listen', '127.0.0.1:0', '--link-token', '5'])
        self.assertEqual(s.ready['pool_frames'], 32 * 2)
        self.assertEqual(s.quit(timeout=30)['error'], 0)


CE_WINDOW = ['--window-slba', '2048', '--window-nlb', str(40 * GIB // 512), '--lba-bytes', '512',
             '--group-bytes', str(128 * KIB), '--frame-bytes', '4096', '--depth', '32',
             '--window', '32', '--early']
CE = ['--dst', 'ce-vmm', '--gpu-bdf', '0000:01:00.0', '--ce-dev', '/dev/null',
      '--ce-prog', '/dev/null']
RESTORE = ['--pool-bytes', str(6 * GIB), '--peer', '127.0.0.1:9', '--link-token', '5']


@unittest.skipUnless(BIN, 'needs libbpf >= 1.0 to build kv_restore (or KV_RESTORE_BIN)')
class CeVmmDestination(unittest.TestCase):
    """--dst ce-vmm: host frames of the ring's UMEM, the copy engine into a CUDA
    VMM allocation; selected explicitly, the PEER/dma-buf defaults unchanged."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-ce-')
        self.manifest = kl.parse_manifest({
            'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
            'window': {'slba': 2048, 'nlb': 40 * GIB // 512},
            'objects': [{'name': 'q14', 'model': 'qwen3-14b', 'tokens': 32768, 'seed': 9,
                         'slba': 2048, 'nlb': 5 * GIB // 512}]})
        self.geometry = kl.Geometry(128 * KIB, 4 * KIB, 32, 32, True)

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, role, extra):
        return kp.Worker([BIN, role, '--dry-run'] + CE_WINDOW + extra, ready_timeout=30,
                         log=Path(self.tmp.name) / f'{role}.log')

    def refused(self, argv):
        r = subprocess.run([str(BIN)] + argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2, r.stdout)
        kind, body = kp.parse_line(r.stdout.strip().splitlines()[-1])
        self.assertEqual((kind, body['where']), ('KV_ERROR', 'arguments'))

    def test_arguments_refused(self):
        def without(option):
            i = CE.index(option)
            return CE[:i] + CE[i + 2:]
        restore = ['restore', '--dry-run'] + CE_WINDOW + RESTORE
        local = ['local-verify', '--dry-run'] + CE_WINDOW + [
            '--nvme', '/dev/null', '--nvme-prog', '/dev/null', '--pool-bytes', str(64 << 20)]
        cases = {
            'no CE device': restore + without('--ce-dev'),
            'no CE program': restore + without('--ce-prog'),
            'no GPU BDF': restore + without('--gpu-bdf'),
            'PEER registration node': restore + CE + ['--gpu-node', '/dev/nvidia0'],
            'host frames are 4096 bytes': ['restore', '--dry-run'] + CE_WINDOW[:8] + [
                '--frame-bytes', str(128 * KIB)] + CE_WINDOW[10:] + RESTORE + CE,
            'unknown destination': restore + ['--dst', 'vram'],
            'restore takes peer or ce-vmm': restore + ['--dst', 'dmabuf'],
            'local-verify takes dmabuf or ce-vmm': local + ['--dst', 'peer'],
            'CE options need ce-vmm': restore + ['--gpu-bdf', 'x', '--gpu-node', 'y',
                                                 '--ce-dev', '/dev/nvidia0'],
            'CE program needs ce-vmm': local + ['--ce-prog', '/dev/null'],
            'serve has no destination': ['serve', '--dry-run'] + CE_WINDOW + [
                '--nvme', '/dev/null', '--nvme-prog', '/dev/null', '--listen', '127.0.0.1:0',
                '--link-token', '5', '--dst', 'ce-vmm'],
        }
        for name, argv in cases.items():
            with self.subTest(name):
                self.refused(argv)

    def test_restore_receives_into_a_ring(self):
        w = self.worker('restore', RESTORE + CE)
        self.assertEqual(w.ready['dst'], 'ce-vmm')
        self.assertEqual(w.ready['pool_frames'], 6 * GIB // 4096)
        self.assertEqual(w.ready['ring_frames'], 32 * 32)
        obj = self.manifest.object('q14')
        # 5 GiB in 4 KiB frames: 1.3M destination frames, one START lends only the ring.
        want = kl.plan_restore(self.manifest, 'q14', 32768, self.geometry, 1, 8,
                               6 * GIB // 4096, host2_ring=True).to_json()
        r = w.go(run='big', ordinal=1, object_slba=obj.slba, bytes=kl.kv_bytes(obj.model, 32768),
                 dst_frame0=8, timeout=30)
        self.assertTrue(r['ok'], r)
        for key in ('groups', 'first_seq', 'host2_frames', 'host2_dst_frame0',
                    'host2_start_frames'):
            self.assertEqual(r['plan'][key], want[key], key)
        self.assertEqual(r['plan']['host2_start_frames'], 32 * 32)
        self.assertIs(r['plan']['host2_ring'], True)
        self.assertEqual((r['dst'], r['payload_path'], r['cpu_copy_bytes']),
                         ('ce-vmm', 'xdomain-rx>host-frame>ce-h2d', 0))
        past = w.go(run='past', ordinal=2, object_slba=obj.slba,
                    bytes=kl.kv_bytes(obj.model, 32768), dst_frame0=6 * GIB // 4096 - 100,
                    timeout=30)
        self.assertEqual(past['error'], -errno.ENOSPC, 'destination beyond the VMM allocation')
        self.assertEqual(w.quit(timeout=30)['error'], 0)

    def test_local_verify_ce_vmm(self):
        w = self.worker('local-verify', ['--nvme', '/dev/null', '--nvme-prog', '/dev/null',
                                         '--pool-bytes', str(64 << 20)] + CE)
        self.assertEqual((w.ready['dst'], w.ready['ring_frames']), ('ce-vmm', 32 * 32))
        r = w.go(run='lv', ordinal=1, object_slba=2048, bytes=40 * 128 * KIB, dst_frame0=3,
                 timeout=30)
        self.assertTrue(r['ok'], r)
        self.assertEqual((r['dst'], r['payload_path'], r['cpu_copy_bytes']),
                         ('ce-vmm', 'nvme-read>host-frame>ce-h2d', 0))
        self.assertEqual(r['plan']['host2_start_frames'], 32 * 32)
        self.assertEqual(w.quit(timeout=30)['error'], 0)

    def test_ready_names_the_staging_export(self):
        # The vLLM connector maps the staging allocation through KV_READY's
        # vmm_export_fd and vmm_bytes; a dry run has no allocation (-1, 0).
        for role, extra in (('restore', RESTORE + CE),
                            ('local-verify', ['--nvme', '/dev/null', '--nvme-prog', '/dev/null',
                                              '--pool-bytes', str(64 << 20)] + CE)):
            with self.subTest(role=role):
                w = self.worker(role, extra)
                self.assertEqual((w.ready['dst'], w.ready['vmm_export_fd'], w.ready['vmm_bytes']),
                                 ('ce-vmm', -1, 0))
                self.assertEqual(w.quit(timeout=30)['error'], 0)

    def test_defaults_unchanged(self):
        w = kp.Worker([BIN, 'restore', '--dry-run'] + WINDOW + [
            '--gpu-bdf', '0000:00:00.0', '--gpu-node', '/dev/null', '--pool-bytes',
            str(5 * GIB), '--peer', '127.0.0.1:9', '--link-token', '5'], ready_timeout=30,
            log=Path(self.tmp.name) / 'peer.log')
        self.assertEqual(w.ready['dst'], 'peer')
        self.assertEqual((w.ready['vmm_export_fd'], w.ready['vmm_bytes']), (-1, 0))
        r = w.go(run='p', ordinal=1, object_slba=2048, bytes=8 * 256 * KIB, dst_frame0=0,
                 timeout=30)
        self.assertEqual((r['dst'], r['payload_path'], r['cpu_copy_bytes']),
                         ('peer', 'xdomain-rx>gpu-frame', 0))
        self.assertIs(r['plan']['host2_ring'], False)
        self.assertEqual(w.quit(timeout=30)['error'], 0)
        w = kp.Worker([BIN, 'local-verify', '--dry-run'] + WINDOW + [
            '--nvme', '/dev/null', '--nvme-prog', '/dev/null', '--pool-bytes', str(64 * 128 * KIB)],
            ready_timeout=30, log=Path(self.tmp.name) / 'dmabuf.log')
        self.assertEqual(w.ready['dst'], 'dmabuf')
        r = w.go(run='d', ordinal=1, object_slba=2048, bytes=8 * 256 * KIB, dst_frame0=0,
                 timeout=30)
        self.assertEqual((r['dst'], r['payload_path'], r['cpu_copy_bytes']),
                         ('dmabuf', 'nvme-read>dmabuf-frame', 0))
        self.assertEqual(w.quit(timeout=30)['error'], 0)


if __name__ == '__main__':
    unittest.main()
