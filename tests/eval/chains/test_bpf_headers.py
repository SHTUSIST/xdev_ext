#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the real plan when CC lacks GCC's multiarch query; no device needed."""
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class BpfHeaders(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)
        for name in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH',
                     'MAKEFLAGS', 'MFLAGS', 'BPF_SYS_INCLUDES', 'MULTIARCH'):
            self.env.pop(name, None)
        self.cc = shlex.split(os.environ.get('CC', 'cc'))
        self.clang = os.environ.get('CLANG', 'clang')

    def build(self, base, cc, *settings):
        output = base/'output'
        result = subprocess.run(['make', '-B', '-C', str(HERE),
                                 'BUILD='+str(output), 'CC='+cc,
                                 'CLANG='+self.clang, *settings, 'bpf'],
                                env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        elf = (output/'chain_plan.bpf.o').read_bytes()
        self.assertEqual(elf[:4], b'\x7fELF')
        endian = '<' if elf[5] == 1 else '>'
        self.assertEqual(struct.unpack_from(endian+'H', elf, 18)[0], 247,
                         'the actual plan must be an EM_BPF object')

    def test_real_bpf_without_print_multiarch(self):
        with tempfile.TemporaryDirectory(prefix='.bpf-headers-', dir=HERE) as directory:
            base = Path(directory)
            # Only the unsupported query is simulated. The native compiler's
            # include discovery and Clang's BPF compilation are both real.
            wrapper = base/'cc-without-multiarch'
            wrapper.write_text('#!'+sys.executable+'\nimport os, sys\n'
                               'if "-print-multiarch" in sys.argv:\n'
                               '    sys.exit(1)\n'
                               'command = '+repr(self.cc)+'\n'
                               'os.execvp(command[0], command + sys.argv[1:])\n')
            wrapper.chmod(0o700)
            self.build(base, str(wrapper))

    def test_explicit_system_include_override_needs_no_native_compiler_query(self):
        result = subprocess.run([*self.cc, '-E', '-x', 'c', '-'],
                                input='#include <asm/types.h>\n', env=self.env,
                                capture_output=True, text=True, check=True)
        match = re.search(r'^# \d+ "([^"]*/asm/types\.h)"', result.stdout, re.M)
        self.assertIsNotNone(match, result.stdout)
        include = Path(match.group(1)).parent.parent
        with tempfile.TemporaryDirectory(prefix='.bpf-headers-', dir=HERE) as directory:
            base = Path(directory)
            self.build(base, str(base/'unused-native-compiler'),
                       'BPF_SYS_INCLUDES=-idirafter '+str(include))


if __name__ == '__main__':
    unittest.main(verbosity=2)
