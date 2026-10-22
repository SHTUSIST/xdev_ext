#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the positive BPF fixture's real build and userspace info filler."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


class CePositive(unittest.TestCase):
    def test_ce_ops_requests_the_lease_abi(self):
        source = (ROOT / 'tools/testing/selftests/bpf/progs/xdev_ext_mech_ce.c').read_text()
        ops = source[source.index('struct xdev_ext_ce_mech_ops ce_ops ='):]
        self.assertRegex(ops, r'\.abi_version\s*=\s*XDEV_EXT_CE_MECH_ABI_VERSION\b')

    def test_real_positive_build_uses_the_host_fixture_lease(self):
        bpf = (ROOT / 'tools/testing/selftests/bpf/progs/xdev_ext_mech_ce.c').read_text()
        host = (ROOT / 'tools/testing/selftests/bpf/prog_tests/xdev_ext_mech.c').read_text()
        build = re.search(r'^__s32 BPF_PROG\(ce_build,.*?^}', bpf, re.M | re.S)
        info = re.search(r'^static void xdev_ext_mech_ce_info\([^)]*\)\n\{.*?^}', host, re.M | re.S)
        defines = '\n'.join(re.findall(r'^#define XDEV_EXT_MECH_T_.*$', host, re.M))
        layout = re.search(r'^static const struct xdev_ext_mech_layout xdev_ext_mech_t_layout =.*?^};', host, re.M | re.S)
        self.assertIsNotNone(build)
        self.assertIsNotNone(info)
        self.assertIsNotNone(layout)
        fixture = (HERE / 'xdev_ext_mech_ce_positive_fixture.c').read_text()
        fixture = fixture.replace('/* REAL_DEFINES */', defines).replace('/* REAL_LAYOUT */', layout[0])
        fixture = fixture.replace('/* REAL_INFO */', info[0]).replace('/* REAL_BUILD */', build[0])
        with tempfile.TemporaryDirectory(prefix='xdev_ext-ce-positive-') as directory:
            path = Path(directory)
            source, binary = path / 'positive.c', path / 'probe'
            source.write_text(fixture)
            compile_run = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11',
                                          '-Wall', '-Wextra', '-Werror', '-I' + str(ROOT),
                                          '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                          str(source), '-o', str(binary)], text=True, capture_output=True)
            self.assertEqual(compile_run.returncode, 0, compile_run.stdout + compile_run.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
