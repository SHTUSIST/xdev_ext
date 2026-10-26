#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NIC-boundary copy adapter, receive direction, and copy-mode accounting.

Compiles the production socket class text (everything before its class table)
against socket_sink/shim.h and runs rx_fixture.c cases over real loopback UDP
sockets: bind/unbind rules, FIFO placement of datagrams into armed batches,
short and truncated datagrams, native errors, wakeup by the socket data_ready
callback without busy polling (two explicit lost-wakeup interleavings),
depth-many receives per worker pass, STOP and dead-stage cancellation,
creator credentials, a callback-versus-unbind race under AddressSanitizer,
and NIC copy counters in both directions. Contract: results/S/API.md of
wave 2 track S (sections 1.2, 1.3, 2.1, 2.2, 3.x). Host correctness only:
no kernel file references, DMA, verifier or VM.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from adapter_test import socket_family_declarations, socket_family_reference

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
CASES = ('bind_rules', 'fifo_exact4', 'fifo_exact6', 'short_datagram', 'truncation',
         'zero_length', 'native_error', 'no_polling', 'queued_before_arm',
         'ready_during_progress', 'drain_all_in_one_pass', 'duplicate_arm',
         'submit_guards', 'stop_cancels', 'dead_cancels', 'credentials',
         'teardown_race', 'teardown_interleaved', 'tx_accounting')


def production_text():
    text = (ROOT / 'io_uring/xdev_ext_mech_socket.c').read_text()
    text = re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)
    return text[:text.index('static const struct xdev_ext_mech_class_ops')]


class SocketReceiveAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='socket-rx-')
        source = Path(cls.tmp.name) / 'rx.c'
        cls.binary = Path(cls.tmp.name) / 'rx'
        source.write_text((HERE / 'shim.h').read_text() + '\n' + socket_family_declarations(ROOT) +
                          production_text() + socket_family_reference() + '\n' +
                          (HERE / 'rx_fixture.c').read_text())
        cc = os.environ.get('CC', 'cc')
        cls.build = subprocess.run([cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                    '-pthread', '-I' + str(ROOT), str(source), '-o', str(cls.binary)],
                                   capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_class_table_wires_both_directions(self):
        text = (ROOT / 'io_uring/xdev_ext_mech_socket.c').read_text()
        table = text[text.index('static const struct xdev_ext_mech_class_ops'):]
        table = table[:table.index('};')]
        for member, function in (('bind', 'xdev_ext_socket_class_bind'),
                                 ('unbind', 'xdev_ext_socket_class_unbind'),
                                 ('submit', 'xdev_ext_socket_class_submit'),
                                 ('fill_cqe', 'xdev_ext_socket_class_fill_cqe'),
                                 ('mark_dead', 'xdev_ext_socket_class_mark_dead'),
                                 ('progress', 'xdev_ext_socket_progress'),
                                 ('validate', 'xdev_ext_socket_validate'),
                                 ('fill_info', 'xdev_ext_socket_fill_info')):
            with self.subTest(member=member):
                self.assertRegex(table, r'\.' + member + r'\s*=\s*' + function + r'\b',
                                 'class table must route .%s to %s' % (member, function))

    def test_cqe_uapi_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'cqe.c'
            exe = Path(tmp) / 'cqe'
            source.write_text('#include <stddef.h>\n#include "include/uapi/linux/xdev_ext_mech.h"\n'
                              '_Static_assert(sizeof(struct xdev_ext_socket_mech_cqe) == 16, "size");\n'
                              '_Static_assert(offsetof(struct xdev_ext_socket_mech_cqe, status) == 0, "status");\n'
                              '_Static_assert(offsetof(struct xdev_ext_socket_mech_cqe, bytes_sent) == 4, "sent");\n'
                              '_Static_assert(offsetof(struct xdev_ext_socket_mech_cqe, bytes_received) == 8, "received");\n'
                              '_Static_assert(offsetof(struct xdev_ext_socket_mech_cqe, flags) == 12, "flags");\n'
                              '_Static_assert(XDEV_EXT_SOCKET_CQE_F_TRUNC == 1U, "trunc");\n'
                              'int main(void) { return 0; }\n')
            r = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Werror',
                                '-I' + str(ROOT), str(source), '-o', str(exe)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_receive_cases(self):
        self.assertEqual(self.build.returncode, 0,
                         'production socket adapter with receive path did not compile:\n' +
                         self.build.stdout + self.build.stderr)
        for case in CASES:
            with self.subTest(case=case):
                r = subprocess.run([str(self.binary), case], capture_output=True, text=True,
                                   timeout=120)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn('PASS socket', r.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
