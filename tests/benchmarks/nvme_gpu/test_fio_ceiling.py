#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""fio_ceiling.py against a fake fio; no device is read and no number is real."""
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
TOOL = HERE / 'fio_ceiling.py'
spec = importlib.util.spec_from_file_location('fio_ceiling', TOOL)
fc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fc)

# A fake fio: --version prints FAKE_FIO_VERSION; a job writes fio-shaped
# JSON whose bandwidth grows with bs * iodepth * numjobs (libaio x1.5),
# and logs its argv.  FAKE_FIO_SHORT makes it read one byte less.
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args == ['--version']:
    print(os.environ.get('FAKE_FIO_VERSION', 'fio-3.36'))
    sys.exit(0)
with open(os.environ['FAKE_FIO_LOG'], 'a') as f:
    f.write(json.dumps(args) + '\n')
opt = dict(a[2:].split('=', 1) for a in args if a.startswith('--') and '=' in a)
units = {'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}
def num(v):
    return int(v[:-1]) * units[v[-1].lower()] if v[-1].isalpha() else int(v)
jobs = int(opt.get('numjobs', 1))
size = num(opt['size']) * jobs - (1 if os.environ.get('FAKE_FIO_SHORT') else 0)
bw = num(opt['bs']) * int(opt['iodepth']) * jobs * (3 if opt['ioengine'] == 'libaio' else 2) // 2
if opt['rw'] == 'write':
    out = {'jobs': [{'jobname': opt['name'], 'write': {'io_bytes': size, 'bw_bytes': bw, 'runtime': 1}, 'read': {'io_bytes': 0, 'bw_bytes': 0, 'runtime': 0}}]}
else:
    out = {'fio version': 'fio-3.36', 'jobs': [{'jobname': opt['name'], 'read': {
        'io_bytes': size, 'bw_bytes': bw, 'runtime': 7,
        'clat_ns': {'percentile': {'50.000000': 1000, '99.000000': 9000}}}}]}
if opt['rw'] == 'write':
    with open(opt['filename'], 'r+b') as f:
        f.write(b'\x01' * (num(opt['size'])))
with open(opt['output'], 'w') as f:
    json.dump(out, f)
'''

MIB = 1 << 20


class Parse(unittest.TestCase):
    def test_version_must_be_fio_3(self):
        self.assertEqual(fc.check_version('fio-3.36\n'), 'fio-3.36')
        for bad in ('fio-2.21', 'fio-30.1', 'not fio', ''):
            with self.subTest(bad=bad), self.assertRaises(fc.Refused):
                fc.check_version(bad)

    def test_read_totals_from_fio_json(self):
        doc = {'jobs': [{'read': {'io_bytes': 10, 'bw_bytes': 5, 'runtime': 2}},
                        {'read': {'io_bytes': 30, 'bw_bytes': 15, 'runtime': 3}}]}
        self.assertEqual(fc.read_totals(doc), dict(io_bytes=40, bw_bytes=20, runtime_ms=3,
                                                   clat_p50_ns=None, clat_p99_ns=None))

    def test_sweep_grid(self):
        grid = fc.sweep_grid()
        self.assertEqual(len(grid), 9 * 3 * 2)
        self.assertIn(('libaio', 256, 4), grid)
        self.assertIn(('io_uring', 1, 1), grid)


class Runner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='fio-ceiling-')
        base = Path(self.tmp.name)
        self.fio = base / 'fio'
        self.fio.write_text(FAKE)
        self.fio.chmod(0o755)
        self.log = base / 'fio.log'
        self.env = dict(os.environ, FAKE_FIO_LOG=str(self.log))
        self.file = base / 'window.bin'
        with open(self.file, 'wb') as f:
            f.write(b'\x07' * (4 * MIB))
        self.out = base / 'out'

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *extra, env=None):
        argv = [sys.executable, str(TOOL), '--fio', str(self.fio), '--file', str(self.file),
                '--window-bytes', str(4 * MIB), '--out', str(self.out), *extra]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60,
                              env=env or self.env)

    def calls(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []

    def summary(self):
        return json.loads((self.out / 'summary.json').read_text())

    def test_grid_runs_read_the_same_window_with_odirect(self):
        r = self.run_tool('--sizes', '4096,1048576', '--qd', '1,32', '--repeats', '2')
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2 * 2 * 2)
        for c in calls:
            self.assertIn('--direct=1', c)
            self.assertIn('--rw=read', c)
            self.assertIn('--ioengine=io_uring', c)
            self.assertIn(f'--filename={self.file}', c)
            self.assertIn(f'--size={4 * MIB}', c)
            self.assertIn('--offset=0', c)
            self.assertIn('--numjobs=1', c)
        s = self.summary()
        self.assertEqual(s['schema'], fc.SCHEMA)
        self.assertEqual(s['fio_version'], 'fio-3.36')
        self.assertEqual(s['verdict'], 'ok')
        self.assertEqual(len(s['runs']), 8)
        run = s['runs'][0]
        self.assertTrue((self.out / run['raw']).is_file())
        self.assertEqual(run['io_bytes'], 4 * MIB)
        self.assertEqual(run['argv'][0], str(self.fio))
        self.assertEqual(s['cells'][0]['repeats'], 2)
        self.assertIn('median_bw_bytes', s['cells'][0])
        # Repeats are interleaved over the grid, not back to back.
        bs = [next(a for a in c if a.startswith('--bs=')) for c in calls]
        self.assertEqual(bs[:4], ['--bs=4096', '--bs=4096', '--bs=1048576', '--bs=1048576'])
        self.assertEqual(bs[4:], bs[:4])

    def test_sweep_reports_the_best_4mib_configuration(self):
        with open(self.file, 'wb') as f:
            f.write(b'\x07' * (16 * MIB))
        r = self.run_tool('--sizes', '4194304', '--qd', '32', '--repeats', '1',
                          '--sweep', '--sweep-repeats', '1', '--window-bytes', str(16 * MIB))
        self.assertEqual(r.returncode, 0, r.stderr)
        s = self.summary()
        best = s['sweep']['best']
        self.assertEqual((best['engine'], best['iodepth'], best['numjobs']), ('libaio', 256, 4))
        self.assertEqual(len(s['sweep']['configs']), 54)
        split = [c for c in self.calls() if '--numjobs=4' in c][0]
        self.assertIn(f'--size={4 * MIB}', split)
        self.assertIn(f'--offset_increment={4 * MIB}', split)
        self.assertIn('--group_reporting', split)
        self.assertIn('--bs=4194304', split)

    def test_a_file_with_holes_is_refused(self):
        sparse = Path(self.tmp.name) / 'sparse.bin'
        with open(sparse, 'wb') as f:
            f.truncate(4 * MIB)
        self.file = sparse
        r = self.run_tool('--sizes', '4096', '--qd', '1')
        self.assertEqual(r.returncode, 4)
        self.assertIn('hole', r.stderr)
        self.assertEqual(self.calls(), [])

    def test_fill_writes_the_window_first(self):
        sparse = Path(self.tmp.name) / 'sparse.bin'
        with open(sparse, 'wb') as f:
            f.truncate(4 * MIB)
        self.file = sparse
        r = self.run_tool('--sizes', '4096', '--qd', '1', '--fill')
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertIn('--rw=write', calls[0])
        self.assertIn('--end_fsync=1', calls[0])
        self.assertIn('--rw=read', calls[1])
        self.assertIs(self.summary()['filled_by_tool'], True)

    def test_window_larger_than_the_file_is_refused(self):
        r = self.run_tool('--sizes', '4096', '--qd', '1', '--window-bytes', str(8 * MIB))
        self.assertEqual(r.returncode, 4)

    def test_wrong_fio_is_refused(self):
        env = dict(self.env, FAKE_FIO_VERSION='fio-2.2')
        r = self.run_tool('--sizes', '4096', '--qd', '1', env=env)
        self.assertEqual(r.returncode, 4)
        self.assertIn('fio-3', r.stderr)

    def test_short_read_fails_the_cell(self):
        env = dict(self.env, FAKE_FIO_SHORT='1')
        r = self.run_tool('--sizes', '4096', '--qd', '1', env=env)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.summary()['verdict'], 'short_read')

    def test_dry_run_prints_commands_only(self):
        r = self.run_tool('--sizes', '4096', '--qd', '1,32', '--dry-run')  # default 5 repeats
        self.assertEqual(r.returncode, 0, r.stderr)
        plan = json.loads(r.stdout)
        self.assertEqual(len(plan['commands']), 2 * 5)
        self.assertEqual(self.calls(), [])
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
