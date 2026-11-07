#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Orchestrator: device preparation, NVMe-oF target steps, runs, recompute hook.

Requirements: writing the KV pattern to host 1's namespace needs an explicit
overwrite flag and puts each object's bytes at its LBAs; the NVMe-oF target
is exactly the kernel's nvmet configfs steps; a run brackets every restore
with host-2 and host-1 CPU markers, records one line per restore and never a
summary number; the recompute hook only times the operator's command.
Everything is exercised with regular files, a fake configfs tree, a fake
worker and a loopback agent: no device, no network setup, no timing claim.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('kv_run', HERE / 'run.py')
kr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kr)
kl, kc = kr.kl, kr.kc
MIB = 1 << 20

MANIFEST = {'schema': 1, 'kind': 'kv-layout', 'lba_bytes': 512,
            'window': {'slba': 2048, 'nlb': 32 * MIB // 512},
            'objects': [{'name': 'q14', 'model': 'qwen3-14b', 'tokens': 32, 'seed': 3,
                         'slba': 2048 + 8 * MIB // 512, 'nlb': 32 * 163840 // 512},
                        {'name': 'q8', 'model': 'qwen3-8b-bf16', 'tokens': 32, 'seed': 4,
                         'slba': 2048 + 16 * MIB // 512, 'nlb': 32 * 147456 // 512}]}

FAKE_WORKER = textwrap.dedent('''
    import json, sys
    print('KV_READY ' + json.dumps({'role': 'fake'}), flush=True)
    for line in sys.stdin:
        if line.startswith('QUIT'):
            print('KV_BYE {"error": 0, "retained": false, "restores": 0}', flush=True)
            break
        f = dict(w.split('=', 1) for w in line.split()[1:])
        print('KV_RESULT ' + json.dumps({'run': f['run'], 'ok': True, 'error': 0,
              'bytes': int(f['bytes']), 't0_ns': 10, 't1_ns': 20, 'latency_ns': 10,
              'verified': f['verify'] == '1' or None, 'seen': line.strip()}), flush=True)
''')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kv-run-')
        self.dir = Path(self.tmp.name)
        self.manifest = self.dir / 'manifest.json'
        self.manifest.write_text(json.dumps(MANIFEST))

    def tearDown(self):
        self.tmp.cleanup()


class PrepareNvme(Base):
    def test_needs_the_overwrite_flag(self):
        dev = self.dir / 'disk.img'
        dev.write_bytes(bytes(32 * MIB))
        with self.assertRaises(SystemExit):
            kr.main(['prepare-nvme', '--manifest', str(self.manifest), '--device', str(dev)])
        self.assertEqual(dev.read_bytes(), bytes(32 * MIB))

    def test_objects_land_at_their_lbas(self):
        dev = self.dir / 'disk.img'
        dev.write_bytes(bytes(32 * MIB))
        self.assertEqual(kr.main(['prepare-nvme', '--manifest', str(self.manifest), '--device',
                                  str(dev), '--i-understand-this-overwrites']), 0)
        data = dev.read_bytes()
        for o in kl.load_manifest(self.manifest).objects:
            self.assertEqual(data[o.slba * 512:o.slba * 512 + o.bytes], kl.pattern_bytes(o.seed, 0, o.bytes))
        self.assertEqual(data[:2048 * 512], bytes(2048 * 512), 'nothing outside the objects')


class NvmeofTarget(Base):
    def test_up_and_down_are_the_nvmet_configfs_steps(self):
        root = self.dir / 'configfs'
        (root / 'nvmet' / 'subsystems').mkdir(parents=True)
        (root / 'nvmet' / 'ports').mkdir(parents=True)
        args = ['--device', '/dev/nvme9n1', '--addr', '10.9.0.1', '--port', '4420',
                '--nqn', 'nqn.2026-11.io.xdev-ext:kv', '--port-id', '7', '--configfs-root', str(root)]
        steps = kr.nvmet_steps('up', '/dev/nvme9n1', '10.9.0.1', 4420, 'nqn.2026-11.io.xdev-ext:kv', 7)
        want = [('mkdir', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv'),
                ('write', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv/attr_allow_any_host', '1'),
                ('mkdir', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv/namespaces/1'),
                ('write', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv/namespaces/1/device_path', '/dev/nvme9n1'),
                ('write', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv/namespaces/1/enable', '1'),
                ('mkdir', 'nvmet/ports/7'),
                ('write', 'nvmet/ports/7/addr_trtype', 'tcp'),
                ('write', 'nvmet/ports/7/addr_adrfam', 'ipv4'),
                ('write', 'nvmet/ports/7/addr_traddr', '10.9.0.1'),
                ('write', 'nvmet/ports/7/addr_trsvcid', '4420'),
                ('symlink', 'nvmet/ports/7/subsystems/nqn.2026-11.io.xdev-ext:kv',
                 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv')]
        self.assertEqual(steps, want)
        # A fake tree: configfs creates the attribute files and default groups itself.
        sub = root / 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv'
        orig_mkdir = kr._mkdir

        def fake_mkdir(path):
            orig_mkdir(path)
            if path.parent.name == 'subsystems' and path.parent.parent.name == 'nvmet':
                (path / 'namespaces').mkdir()
            if path.parent.name == 'ports':
                (path / 'subsystems').mkdir()
        kr._mkdir = fake_mkdir
        try:
            self.assertEqual(kr.main(['nvmeof-target', 'up'] + args), 0)
        finally:
            kr._mkdir = orig_mkdir
        self.assertEqual((sub / 'namespaces/1/device_path').read_text(), '/dev/nvme9n1\n')
        self.assertEqual(os.readlink(root / 'nvmet/ports/7/subsystems/nqn.2026-11.io.xdev-ext:kv'),
                         str(sub))
        down = kr.nvmet_steps('down', '/dev/nvme9n1', '10.9.0.1', 4420, 'nqn.2026-11.io.xdev-ext:kv', 7)
        self.assertEqual(down[0], ('unlink', 'nvmet/ports/7/subsystems/nqn.2026-11.io.xdev-ext:kv'))
        self.assertIn(('write', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv/namespaces/1/enable', '0'), down)
        self.assertEqual(down[-1], ('rmdir', 'nvmet/subsystems/nqn.2026-11.io.xdev-ext:kv'))

    def test_dry_run_touches_nothing(self):
        root = self.dir / 'configfs'
        root.mkdir()
        self.assertEqual(kr.main(['nvmeof-target', 'up', '--device', '/dev/nvme9n1', '--addr',
                                  '10.9.0.1', '--nqn', 'nqn.x:y', '--configfs-root', str(root),
                                  '--dry-run']), 0)
        self.assertEqual(list(root.iterdir()), [])


class Runs(Base):
    def agent(self):
        proc = self.dir / 'proc'
        (proc / 'sys/vm').mkdir(parents=True)
        (proc / 'stat').write_text('cpu  10 0 10 100 0 0 0 0 0 0\ncpu0 10 0 10 100 0 0 0 0 0 0\n')
        (proc / 'sys/vm/drop_caches').write_text('')
        server = kc.AgentServer(('127.0.0.1', 0), token='tk', proc_root=proc, allow_drop_caches=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        token = self.dir / 'token'
        token.write_text('tk\n')
        return f'127.0.0.1:{server.server_address[1]}', token, proc

    def test_run_brackets_every_restore_and_records_it(self):
        address, token, proc = self.agent()
        fake = self.dir / 'fake_worker.py'
        fake.write_text(FAKE_WORKER)
        out = self.dir / 'results'
        rc = kr.main(['run', '--arm', 'custom', '--manifest', str(self.manifest), '--object', 'q14',
                      '--prefixes', '16,32', '--repetitions', '3', '--host1-agent', address,
                      '--token-file', str(token), '--output', str(out), '--idle-seconds', '0.05',
                      '--worker-argv', json.dumps([sys.executable, '-I', str(fake)]),
                      '--drop-caches-host1', '--group-bytes', str(128 * 1024)])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in (out / 'results.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 6)
        self.assertEqual(sorted(r['prefix_tokens'] for r in rows), [16, 16, 16, 32, 32, 32])
        ordinals = [r['ordinal'] for r in rows]
        self.assertEqual(ordinals, sorted(ordinals), 'ordinals only grow')
        for r in rows:
            self.assertTrue(r['ok'])
            self.assertEqual(r['bytes'], kl.kv_bytes('qwen3-14b', r['prefix_tokens']))
            self.assertIn('busy_core_seconds', r['host1_cpu'])
            self.assertIn('busy_core_seconds', r['host2_cpu'])
            self.assertEqual(r['host1_drop_caches'], True)
            self.assertIn(f'object_slba={2048 + 8 * MIB // 512}', r['worker']['seen'])
        self.assertTrue(rows[0]['worker']['verified'], 'first run of each prefix verifies')
        self.assertEqual((proc / 'sys/vm/drop_caches').read_text(), '3\n')
        meta = json.loads((out / 'run.json').read_text())
        self.assertEqual(meta['performance_claim'], 'none')
        self.assertIsNone(meta['dst'], 'only the xdev-ext arm has a host-2 destination')
        self.assertIn('idle', meta)
        self.assertNotIn('median', json.dumps(meta))
        with self.assertRaises(SystemExit):
            kr.main(['run', '--arm', 'custom', '--manifest', str(self.manifest), '--object', 'q14',
                     '--prefixes', '16', '--repetitions', '1', '--host1-agent', address,
                     '--token-file', str(token), '--output', str(out),
                     '--worker-argv', json.dumps(['true'])])

    def test_perf_counts_only_the_enabled_window(self):
        perf = self.dir / 'perf'
        perf.write_text(textwrap.dedent('''
            #!/usr/bin/env python3
            import signal, sys
            args = sys.argv[1:]
            ctl, ack = [a for a in args if a.startswith('--control=fifo:')][0][15:].split(',')
            out = args[args.index('-o') + 1]
            assert '--delay=-1' in args and '-a' in args
            state = {'on': False, 'n': 0}
            def stop(*_):
                open(out, 'w').write('%d,,ev_a,1,100.00,,\\n' % state['n'])
                sys.exit(0)
            signal.signal(signal.SIGINT, stop)
            c, a = open(ctl), open(ack, 'w')
            for line in c:
                state['on'] = line.strip() == 'enable'
                state['n'] += 10 if state['on'] else 0
                a.write('ack\\n'); a.flush()
        ''').lstrip())
        perf.chmod(0o755)
        p = kr.Perf(str(perf), 'ev_a', self.dir, 't')
        p.enable()
        p.disable()
        self.assertEqual(p.finish(), {'ev_a': 10})

    def test_arm_worker_argv(self):
        args = kr.parser().parse_args([
            'run', '--arm', 'xdev-ext', '--manifest', str(self.manifest), '--object', 'q8',
            '--prefixes', '32', '--repetitions', '1', '--host1-agent', '127.0.0.1:1',
            '--token-file', '/dev/null', '--output', str(self.dir / 'o'), '--worker-bin',
            '/opt/kv_restore', '--gpu-bdf', '0000:65:00.0', '--gpu-node', '/dev/nvidia0',
            '--peer', '10.9.0.1:7700', '--service', 'xdevext-1', '--pool-bytes', str(64 * MIB)])
        argv = kr.worker_argv(args, kl.load_manifest(self.manifest))
        self.assertEqual(argv[:2], ['/opt/kv_restore', 'restore'])
        for flag, value in (('--window-slba', '2048'), ('--window-nlb', str(32 * MIB // 512)),
                            ('--lba-bytes', '512'), ('--group-bytes', str(128 * 1024)),
                            ('--frame-bytes', str(128 * 1024)), ('--depth', '32'), ('--window', '32'),
                            ('--peer', '10.9.0.1:7700'), ('--service', 'xdevext-1')):
            self.assertEqual(argv[argv.index(flag) + 1], value, flag)
        self.assertIn('--early', argv)

    def xdev_args(self, *extra):
        return kr.parser().parse_args([
            'run', '--arm', 'xdev-ext', '--manifest', str(self.manifest), '--object', 'q8',
            '--prefixes', '32', '--repetitions', '1', '--host1-agent', '127.0.0.1:1',
            '--token-file', '/dev/null', '--output', str(self.dir / 'o'), '--worker-bin',
            '/opt/kv_restore', '--gpu-bdf', '0000:65:00.0', '--peer', '10.9.0.1:7700',
            '--service', 'xdevext-1', '--pool-bytes', str(64 * MIB)] + list(extra))

    def test_ce_vmm_destination_argv(self):
        m = kl.load_manifest(self.manifest)
        argv = kr.worker_argv(self.xdev_args('--dst', 'ce-vmm', '--ce-dev', '/dev/nvidia1',
                                             '--ce-prog', '/opt/kv_ce_place.bpf.o',
                                             '--frame-bytes', '4096'), m)
        for flag, value in (('--dst', 'ce-vmm'), ('--ce-dev', '/dev/nvidia1'),
                            ('--ce-prog', '/opt/kv_ce_place.bpf.o'), ('--frame-bytes', '4096'),
                            ('--gpu-bdf', '0000:65:00.0')):
            self.assertEqual(argv[argv.index(flag) + 1], value, flag)
        self.assertNotIn('--gpu-node', argv, 'the PEER registration node is not used')
        peer = kr.worker_argv(self.xdev_args('--gpu-node', '/dev/nvidia0'), m)
        self.assertEqual(peer[peer.index('--dst') + 1], 'peer', 'PEER pool stays the default')
        self.assertNotIn('--ce-dev', peer)
        for bad in (('--dst', 'ce-vmm', '--ce-prog', 'p'), ('--dst', 'ce-vmm', '--ce-dev', 'd'),
                    ('--dst', 'ce-vmm', '--ce-dev', 'd', '--ce-prog', 'p', '--gpu-node', 'n'),
                    ('--ce-dev', 'd', '--gpu-node', 'n'), ()):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                kr.worker_argv(self.xdev_args(*bad), m)

    def test_rows_carry_host2_cpu_copy_bytes(self):
        address, token, _ = self.agent()
        fake = self.dir / 'fake_worker.py'
        fake.write_text(FAKE_WORKER.replace("'seen': line.strip()",
                                            "'seen': line.strip(), 'cpu_copy_bytes': 0"))
        plain = self.dir / 'plain_worker.py'
        plain.write_text(FAKE_WORKER)
        for worker, want in ((fake, 0), (plain, None)):
            out = self.dir / f'results-{worker.stem}'
            rc = kr.main(['run', '--arm', 'custom', '--manifest', str(self.manifest), '--object',
                          'q14', '--prefixes', '16', '--repetitions', '2', '--host1-agent', address,
                          '--token-file', str(token), '--output', str(out), '--idle-seconds', '0',
                          '--worker-argv', json.dumps([sys.executable, '-I', str(worker)]),
                          '--group-bytes', str(128 * 1024)])
            self.assertEqual(rc, 0)
            rows = [json.loads(l) for l in (out / 'results.jsonl').read_text().splitlines()]
            self.assertEqual([r['host2_cpu_copy_bytes'] for r in rows], [want, want])

    def test_dry_run_prints_the_schedule_only(self):
        out = self.dir / 'never'
        self.assertEqual(kr.main(['run', '--arm', 'custom', '--manifest', str(self.manifest),
                                  '--object', 'q8', '--prefixes', '32', '--repetitions', '2',
                                  '--host1-agent', '127.0.0.1:1', '--token-file', '/dev/null',
                                  '--output', str(out), '--worker-argv', '["false"]',
                                  '--dry-run']), 0)
        self.assertFalse(out.exists())


class Recompute(Base):
    def test_times_the_operator_command(self):
        out = self.dir / 'rc'
        cmd = (f'{sys.executable} -I -c "import json,sys; '
               'print(json.dumps({{\'prefill_seconds\': 0.25, \'prompt_tokens\': int(sys.argv[2]), '
               '\'model\': sys.argv[1]}}))" {model} {prompt_tokens}')
        self.assertEqual(kr.main(['recompute', '--command', cmd, '--model', 'qwen3-14b',
                                  '--prefixes', '4096,16384', '--repetitions', '2',
                                  '--output', str(out)]), 0)
        rows = [json.loads(l) for l in (out / 'results.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r['ok'] and r['reported']['prefill_seconds'] == 0.25 for r in rows))
        self.assertTrue(all(r['wall_ns'] > 0 for r in rows))
        self.assertEqual(rows[0]['argv'][-2:], ['qwen3-14b', '4096'])

    def test_failed_command_is_a_failed_run(self):
        out = self.dir / 'rc2'
        self.assertEqual(kr.main(['recompute', '--command', 'false {model} {prompt_tokens}',
                                  '--model', 'qwen3-8b-bf16', '--prefixes', '4096',
                                  '--repetitions', '1', '--output', str(out)]), 1)
        row = json.loads((out / 'results.jsonl').read_text())
        self.assertFalse(row['ok'])


if __name__ == '__main__':
    unittest.main()
