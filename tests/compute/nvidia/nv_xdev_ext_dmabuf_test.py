#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""GCC tests of exact NVIDIA descriptor/lifecycle bodies, not DMA tests."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
NV = REPO / 'src/compute/nvidia/kernel-open/nvidia'

class Describe(unittest.TestCase):
    def test_behavior(self):
        source = NV / 'nv-dmabuf.c'
        if not source.exists():
            upstream = os.environ.get('XDEV_EXT_NVIDIA_UPSTREAM')
            if not upstream:
                self.fail('baseline requires XDEV_EXT_NVIDIA_UPSTREAM pointing to fixed nv-dmabuf.c')
            source = Path(upstream)
        text = source.read_text()
        core = (REPO / 'src/core/include/linux/xdev_ext_peer_dmabuf.h').read_text()
        peer = (REPO / 'src/core/include/linux/xdev_ext_peer.h').read_text()
        parts = [ex.typedef_struct(text, 'nv_dma_buf_mem_handle_t'),
                 ex.typedef_struct(text, 'nv_dma_buf_file_private_t'),
                 ex.struct(peer, 'xdev_ext_peer_backing'),
                 ex.struct(core, 'xdev_ext_peer_dmabuf_desc_ops')]
        names = ('nv_xdev_ext_dmabuf_raw_bus', 'nv_xdev_ext_dmabuf_describe',
                 'nv_xdev_ext_dmabuf_init', 'nv_xdev_ext_dmabuf_exit')
        if ex.has_function(text, names[1]):
            parts.extend(ex.function(text, n) for n in names[:2])
            start = text.index('static const struct xdev_ext_peer_dmabuf_desc_ops')
            end = text.index(';', start) + 1
            parts.append(text[start:end])
            parts.append('static bool nv_xdev_ext_dmabuf_registered;')
            parts.extend(ex.function(text, n) for n in names[2:])
        else:
            parts.append('int nv_xdev_ext_dmabuf_init(void) { return 0; }\n'
                         'void nv_xdev_ext_dmabuf_exit(void) {}')
        with tempfile.TemporaryDirectory(prefix='nv-dmabuf-') as directory:
            out = Path(directory)
            (out / 'actual.inc').write_text('\n\n'.join(parts))
            for direct in (0, 1):
                for phys in (0, 1):
                    binary = out / f'test-{direct}-{phys}'
                    command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g',
                               '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                               '-Wno-unused-function', '-fsanitize=address,undefined',
                               '-fno-pie', '-no-pie', '-I', str(out),
                               '-DTEST_DIRECT=' + str(direct), '-DTEST_PHYS=' + str(phys)]
                    if direct:
                        command.append('-DNV_DMA_IS_DIRECT_PRESENT')
                    if phys:
                        command.append('-DNV_DMA_MAP_OPS_HAS_MAP_PHYS')
                    command += [str(HERE / 'nv_xdev_ext_dmabuf_harness.c'), '-o', str(binary)]
                    built = subprocess.run(command, text=True, capture_output=True)
                    self.assertEqual(built.returncode, 0, 'setup compile failed:\n' + built.stderr)
                    result = subprocess.run([str(binary)], text=True, capture_output=True)
                    print(f'direct={direct} map_phys={phys}: {result.stdout.strip()}')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            nv = (NV / 'nv.c').read_text()
            (out / 'actual_module.inc').write_text('\n'.join(
                ex.function(nv, n) for n in ('nvidia_init_module', 'nvidia_exit_module')))
            for disabled in (False, True):
                if disabled:
                    # Use the real disabled header, not a fixture implementation.
                    header = NV / 'nv-xdev_ext-dmabuf.h'
                    self.assertTrue(header.exists(), 'disabled adapter header missing')
                    (out / 'actual.inc').write_text('\n\n'.join(parts[:4]) +
                         '\n#include "' + str(header) + '"\n')
                for uvm in (False, True):
                    binary = out / f'module-{disabled}-{uvm}'
                    command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g',
                               '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                               '-Wno-unused-function', '-Wno-unused-variable', '-Wno-sign-compare',
                               '-fsanitize=address,undefined', '-fno-pie', '-no-pie',
                               '-I', str(out)]
                    if disabled:
                        command.append('-DTEST_IMPORTER_DISABLED')
                    if uvm:
                        command.append('-DNV_UVM_ENABLE')
                    command += [str(HERE / 'nv_xdev_ext_dmabuf_module_harness.c'),
                                '-o', str(binary)]
                    built = subprocess.run(command, text=True, capture_output=True)
                    self.assertEqual(built.returncode, 0, 'module setup compile failed:\n' + built.stderr)
                    result = subprocess.run([str(binary)], text=True, capture_output=True)
                    print(f'importer_disabled={disabled} uvm={uvm}: {result.stdout.strip()}')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
