#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Static checks of the BPF compute examples (tools/xdev_ext_mech/examples/compute).

- The CRC32C examples are pure BPF: no CRC kfunc in any example source.
- Every example object is a CPU struct_ops map with build, complete and compute.
- The generated CRC32C table header equals what its generator writes now.
- The Makefile builds every example and the README names every one.
No compiler, kernel or guest is involved.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]
EXAMPLES = KERNEL / 'tools/xdev_ext_mech/examples/compute'
REQUIRED = ('crc32c_check.bpf.c', 'crc32c_append.bpf.c', 'xxh64_append.bpf.c',
            'parse_check.bpf.c')


class ExampleSources(unittest.TestCase):
    def sources(self):
        return sorted(EXAMPLES.glob('*.bpf.c'))

    def test_required_examples_exist(self):
        names = {p.name for p in self.sources()}
        for name in REQUIRED:
            self.assertIn(name, names)

    def test_no_crc_kfunc(self):
        for path in self.sources() + sorted(EXAMPLES.glob('*.h')):
            text = path.read_text()
            for kfunc in ('bpf_xdev_ext_crc32c', 'bpf_xdev_ext_frame_crc32c'):
                self.assertNotIn(kfunc, text, f'{path.name} calls {kfunc}')

    def test_cpu_struct_ops_members(self):
        for path in self.sources():
            text = path.read_text()
            maps = re.findall(r'SEC\("\.struct_ops\.link"\)\s*struct xdev_ext_cpu_mech_ops (\w+)'
                              r'\s*=\s*\{(.*?)\};', text, re.S)
            self.assertEqual(len(maps), 1, path.name)
            body = maps[0][1]
            for member in ('abi_version', 'build', 'complete', 'compute'):
                self.assertRegex(body, r'\.' + member + r'\s*=', f'{path.name}: {member}')
            for prog in re.findall(r'\.(?:build|complete|compute)\s*=\s*\(void \*\)(\w+)', body):
                self.assertRegex(text, r'SEC\("struct_ops/' + prog + r'"\)', path.name)
                # The kernel names a program by at most 15 bytes.
                self.assertLessEqual(len(prog), 15, prog)

    def test_table_is_generated(self):
        with tempfile.TemporaryDirectory() as name:
            out = Path(name) / 'crc32c_table.h'
            subprocess.run([sys.executable, '-I', str(EXAMPLES / 'gen_crc32c_table.py'), str(out)],
                           check=True)
            self.assertEqual(out.read_text(), (EXAMPLES / 'crc32c_table.h').read_text())

    def test_makefile_and_readme(self):
        makefile = (EXAMPLES / 'Makefile').read_text().replace('\\\n', ' ')
        readme = (EXAMPLES / 'README.md').read_text()
        objects = re.search(r'^OBJECTS := \$\(addprefix \$\(OUT\)/,([^)]*)\)', makefile, re.M)
        self.assertIsNotNone(objects)
        objects = objects.group(1).split()
        for path in self.sources():
            stem = path.name[:-len('.bpf.c')]
            # A CRC32C source is built once per table variant, the others once.
            built = [o for o in objects if o in (stem + '.bpf.o', stem + '_bytewise.bpf.o',
                                                 stem + '_slice8.bpf.o')]
            want = 2 if stem.startswith('crc32c_') else 1
            self.assertEqual(len(built), want, path.name)
            self.assertIn(path.name, readme)
            for obj in built:
                self.assertIn(obj, readme)


if __name__ == '__main__':
    unittest.main(verbosity=2)
