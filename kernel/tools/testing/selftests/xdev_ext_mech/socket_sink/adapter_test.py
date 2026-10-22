#!/usr/bin/env python3
"""Compile production socket adapter functions against a userspace socket shim.

The shim only substitutes allocation, socket and common-core boundaries. The
admission, span validation, submit classification and completion code is real.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent

class SocketAdapter(unittest.TestCase):
    def test_socket_class_is_admitted_by_production_registry(self):
        text = (ROOT / 'io_uring/xdev_ext_mech_core.h').read_text()
        function = re.search(r'static inline bool xdev_ext_mech_class_known\([^{}]+\)\n\{.*?\n\}', text, re.S)[0]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'class.c'
            exe = Path(tmp) / 'class'
            source.write_text('#include <stdbool.h>\n#include "include/uapi/linux/xdev_ext_mech.h"\n' + function + '\nint main(void) {return !xdev_ext_mech_class_known(7);}\n')
            subprocess.run(['cc', '-Wall', '-Werror', '-I'+str(ROOT), str(source), '-o', str(exe)], check=True)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 0,
                             'ordinary socket class 7 must enter the common mechanism registry')

    def test_socket_never_retries_accepted_native_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'retry.c'
            exe = Path(tmp) / 'retry'
            source.write_text('#include <string.h>\n#include "io_uring/xdev_ext_mech_core.h"\n'
                              'int main(void) {int e; for(e=-4095;e<65536;e++) '
                              'if(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_SOCKET,0,e))return 1; return 0;}\n')
            subprocess.run(['cc', '-Wall', '-Werror', '-I'+str(ROOT), str(source), '-o', str(exe)], check=True)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 0)

    def test_production_adapter_with_real_connected_udp(self):
        source = ROOT / 'io_uring/xdev_ext_mech_socket.c'
        self.assertTrue(source.exists(), 'new mechanism ordinary socket adapter is missing')
        text = source.read_text()
        text = re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)
        text = text[:text.index('static const struct xdev_ext_mech_class_ops')]
        with tempfile.TemporaryDirectory() as tmp:
            cfile = Path(tmp) / 'adapter.c'
            exe = Path(tmp) / 'adapter'
            cfile.write_text((HERE/'shim.h').read_text() + '\n' + text + '\n' + (HERE/'fixture.c').read_text())
            subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                            '-I'+str(ROOT), str(cfile), '-o', str(exe)], check=True)
            run = subprocess.run([str(exe)], text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('PASS socket sink production adapter', run.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)
