#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""run.py planning and the setup_cost binary's refusals; nothing is timed.

The binary tests only exercise paths that stop before any registration or
BPF load: usage errors, the hypervisor refusal of timed modes, and the
counts-only path with an object that does not exist.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('setup_cost_run', HERE / 'run.py')
sr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sr)

M, G = 1 << 20, 1 << 30


def fake_root(base, hypervisor, mem_available_kb=None):
    root = Path(base)
    (root / 'proc').mkdir(parents=True)
    (root / 'proc/cpuinfo').write_text('processor : 0\nflags : fpu sse2%s\n' %
                                       (' hypervisor' if hypervisor else ''))
    if mem_available_kb is not None:
        (root / 'proc/meminfo').write_text('MemTotal: %d kB\nMemAvailable: %d kB\n' %
                                           (mem_available_kb * 2, mem_available_kb))
    return root


class Plan(unittest.TestCase):
    def test_size_ranges(self):
        self.assertEqual(sr.expand_sizes('1M..96G'),
                         [M, 4 * M, 16 * M, 64 * M, 256 * M, G, 4 * G, 16 * G, 64 * G, 96 * G])
        self.assertEqual(sr.expand_sizes('4K,1M'), [4096, M])
        self.assertEqual(sr.expand_sizes('1M..4M', step=2), [M, 2 * M, 4 * M])
        for bad in ('4M..1M', '1M..', 'x', '1M..4M..16M', '3000'):
            with self.assertRaises(ValueError):
                sr.expand_sizes(bad)

    def test_measures_from_devices(self):
        self.assertEqual(sr.measures(''), ['umem', 'iou'])
        self.assertEqual(sr.measures('nvme,nic,gpu'),
                         ['umem', 'iou', 'mech', 'xdp', 'cuda', 'cufile'])
        with self.assertRaises(ValueError):
            sr.measures('tape')

    def test_plan_objects(self):
        with tempfile.TemporaryDirectory() as t:
            for name in ('b.bpf.o', 'a.bpf.o', 'notes.txt'):
                (Path(t) / name).write_text('')
            self.assertEqual([p.name for p in sr.plan_objects('all', Path(t))],
                             ['a.bpf.o', 'b.bpf.o'])
            self.assertEqual([p.name for p in sr.plan_objects('b', Path(t))], ['b.bpf.o'])
            with self.assertRaises(ValueError):
                sr.plan_objects('c', Path(t))
            self.assertEqual(sr.plan_objects('none', Path(t)), [])

    def test_command(self):
        args = sr.parse_args(['--sizes', '1M..4M', '--devices', 'nvme', '--nvme-ng',
                              '/dev/ng0n1', '--nvme-window', '0:65536', '--plans', 'none',
                              '--reps', '3'])
        self.assertEqual(sr.command(args, Path('/b/setup_cost'), []), [
            '/b/setup_cost', '--sizes', '%d,%d' % (M, 4 * M), '--reps', '3',
            '--frame-size', '4096', '--measure', 'umem,iou,mech',
            '--nvme-ng', '/dev/ng0n1', '--nvme-window', '0:65536'])
        capped = sr.parse_args(['--sizes', '1M', '--plans', 'none', '--umem-cap', '1G',
                                '--mem-margin', '16G'])
        self.assertEqual(sr.command(capped, Path('/b/setup_cost'), [])[-4:],
                         ['--umem-cap', str(G), '--mem-margin', str(16 * G)])
        counts = sr.parse_args(['--counts-only', '--plans', 'all'])
        self.assertEqual(sr.command(counts, Path('/b/setup_cost'), [Path('/o/a.bpf.o')]),
                         ['/b/setup_cost', '--counts-only', '--bpf-obj', '/o/a.bpf.o'])
        stats = sr.parse_args(['--prog-stats', '--prog-prefix', 'nxp', '--', 'ctl', 'run'])
        self.assertEqual(sr.command(stats, Path('/b/setup_cost'), []),
                         ['/b/setup_cost', '--prog-stats', '--prog-prefix', 'nxp', '--',
                          'ctl', 'run'])

    def test_usage_errors(self):
        for argv in (['--nvme-ng', '/dev/ng0n1'], ['--counts-only', '--plans', 'none'],
                     ['--prog-stats'], ['--sizes', '1M..']):
            with self.assertRaises(SystemExit) as raised, \
                    contextlib.redirect_stderr(io.StringIO()):
                sr.parse_args(argv)
            self.assertEqual(raised.exception.code, 2, argv)

    def test_timing_refused_in_vm_before_build(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, True)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = sr.main(['--host-root', str(root), '--plans', 'none'])
        self.assertEqual(code, 4)
        self.assertIn('hypervisor', err.getvalue())

    def test_counts_only_without_objects_not_run(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, True)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = sr.main(['--host-root', str(root), '--counts-only', '--plans', 'all',
                                '--bpf-dir', t])
        self.assertEqual(code, 4)
        self.assertIn('no BPF object', err.getvalue())


def binary():
    build = os.environ.get('SETUP_COST_BUILD')
    path = Path(build) / 'setup_cost' if build else None
    if not path or not path.exists():
        raise unittest.SkipTest('setup_cost not built (needs libbpf); run make check')
    return path


class Binary(unittest.TestCase):
    def run_bin(self, argv, root):
        env = dict(os.environ, SETUP_COST_HOST_ROOT=str(root))
        return subprocess.run([str(binary()), *argv], capture_output=True, text=True,
                              env=env, timeout=30)

    def test_usage(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, False)
            for argv in (['--bogus'], ['--sizes', '1M,,2M'], ['--counts-only'],
                         ['--frame-size', '3000'], ['--sizes', '6000'],
                         ['--nvme-ng', '/dev/null'], ['--measure', 'tape'],
                         ['--prog-stats'], ['--reps', '65'], ['--umem-cap', '0'],
                         ['--mem-margin', 'x']):
                self.assertEqual(self.run_bin(argv, root).returncode, 2, argv)

    def test_timed_modes_refuse_hypervisor(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, True)
            for argv in (['--sizes', '1M'], ['--prog-stats', '--', 'true']):
                p = self.run_bin(argv, root)
                self.assertEqual(p.returncode, 4, argv)
                self.assertEqual(p.stdout, '')
                self.assertIn('hypervisor', p.stderr)

    def test_region_above_mem_available_is_not_populated(self):
        """A size that does not fit MemAvailable minus the margin is recorded as
        host_refused before any mmap, so a 96 GiB sweep cannot OOM the host."""
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, False, mem_available_kb=8 << 20)	# 8 GiB
            p = self.run_bin(['--measure', 'iou', '--sizes', '96G', '--reps', '2'], root)
        self.assertEqual(p.returncode, 4, p.stderr)
        r = json.loads(p.stdout)['registration'][0]
        self.assertEqual((r['measure'], r['size'], r['status'], r['step']),
                         ('iou', 96 * G, 'host_refused', 'mem_available'))
        self.assertEqual(r['completed_reps'], 0)
        self.assertEqual(r['mem_available'], 8 * G)
        self.assertEqual(r['mem_margin'], 4 * G)

    def test_unknown_mem_available_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, False)
            p = self.run_bin(['--measure', 'iou', '--sizes', '1M', '--reps', '1'], root)
        r = json.loads(p.stdout)['registration'][0]
        self.assertEqual((r['status'], r['step']), ('host_refused', 'mem_available'))

    def test_umem_cap_skips_without_populating(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, False, mem_available_kb=1 << 40 >> 10)
            p = self.run_bin(['--measure', 'umem', '--sizes', '2G', '--umem-cap', '1G'], root)
        r = json.loads(p.stdout)['registration'][0]
        self.assertEqual((r['measure'], r['status']), ('umem', 'not_run_above_cap'))
        self.assertIn('--umem-cap', r['reason'])

    def test_counts_only_proceeds_in_vm(self):
        with tempfile.TemporaryDirectory() as t:
            root = fake_root(t, True)
            p = self.run_bin(['--counts-only', '--bpf-obj', str(Path(t) / 'missing.bpf.o')],
                             root)
        self.assertEqual(p.returncode, 1)
        doc = json.loads(p.stdout)
        self.assertEqual(doc['mode'], 'counts')
        self.assertNotIn('registration', doc)
        self.assertEqual(doc['bpf'][0]['status'], 'open_failed')
        self.assertNotIn('load_ns', doc['bpf'][0])


FAKE_CUDA = {
    'cuda_runtime_api.h': """#pragma once
#include <stddef.h>
typedef int cudaError_t;
#define cudaHostRegisterDefault 0
cudaError_t cudaSetDevice(int);
cudaError_t cudaFree(void *);
cudaError_t cudaMalloc(void **, size_t);
cudaError_t cudaHostRegister(void *, size_t, unsigned int);
cudaError_t cudaHostUnregister(void *);
const char *cudaGetErrorString(cudaError_t);
""",
    'cufile.h': """#pragma once
#include <stddef.h>
typedef enum { CU_FILE_SUCCESS = 0 } CUfileOpError;
typedef struct { CUfileOpError err; int cu_err; } CUfileError_t;
CUfileError_t cuFileDriverOpen(void);
CUfileError_t cuFileBufRegister(const void *, size_t, int);
CUfileError_t cuFileBufDeregister(const void *);
""",
}


class CudaSyntax(unittest.TestCase):
    def test_cuda_section_compiles_against_declared_api(self):
        """Syntax only: these headers declare the official API subset used."""
        with tempfile.TemporaryDirectory() as t:
            for name, text in FAKE_CUDA.items():
                (Path(t) / name).write_text(text)
            p = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                '-fsyntax-only', '-DSETUP_COST_HAVE_CUDA', '-I' + t,
                                '-I' + str(HERE.parents[2] / 'kernel/tools/include/uapi'),
                                str(HERE / 'setup_cost.c')], capture_output=True, text=True)
        if 'bpf/libbpf.h' in p.stderr:
            self.skipTest('libbpf development headers absent')
        self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == '__main__':
    unittest.main()
