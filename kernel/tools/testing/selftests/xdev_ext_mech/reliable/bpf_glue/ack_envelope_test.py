#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real bind -> RX callback -> BPF ACK -> guarded sender control regression.

Compile unchanged production bodies with the existing host primitive boundary.
Exercise initialized release publication for both directions, native completion
before ACK construction, receive offsets, wire checks and sender custody. Kernel
allocation/locking, reliable resource registration and invocation admission are
host shims; this does not replace verifier or guest validation.
"""
import re
import unittest

import glue_common as G


def source():
    xsk = G.default_text(G.XSK)
    inc = G.default_text(G.INC)
    header = (G.ROOT / 'include/linux/xdev_ext_mech.h').read_text()

    def declaration(name):
        start = header.index('struct ' + name + ' {')
        return header[start:header.index('\n};', start) + 3]

    functions = []
    for where, text, names in [
        ('xsk', xsk, [
            'xsk_xdev_ext_mech_rx_call', 'xsk_xdev_ext_mech_fill_info',
            'xsk_xdev_ext_mech_bind', 'xsk_rel_call_state', 'xsk_rel_call_rx',
            'bpf_xdev_ext_rel_rx_view', 'bpf_xdev_ext_rel_rx_data',
            'bpf_xdev_ext_rel_rx_control', 'bpf_xdev_ext_rel_policy']),
        ('reliable', inc, [
            'xsk_rel_info', 'xsk_rel_owe', 'xsk_rel_batch_end',
            'xsk_rel_decode', 'xsk_rel_rx', 'xsk_rel_packet_check']),
    ]:
        functions.extend(G.require(text, name, where) for name in names)
    prototypes = '\n'.join(body[:body.index('{')].strip() + ';' for body in functions)
    fixture = (G.HERE / 'ack_envelope_fixture.c').read_text()
    fixture = fixture.replace('/* ACTUAL_CALL_STRUCTS */', '\n'.join(
        declaration(name) for name in ['xdev_ext_mech_call', 'xdev_ext_mech_call_args']))
    fixture = fixture.replace('/* ACTUAL_PROTOTYPES */', prototypes)
    return fixture.replace('/* ACTUAL_FUNCTIONS */', '\n'.join(functions))


class AckEnvelope(unittest.TestCase):
    def test_bind_to_actual_bpf_ack_and_control(self):
        _, run = G.build_and_run(self, source(), name='ack_envelope', extra=[
            '-I', str(G.HERE / 'host'), '-I', str(G.CREF_HOST),
            '-DPROGRAM="%s"' % G.BPF])
        match = re.search(r'checks=(\d+) failures=(\d+)', run.stdout)
        self.assertIsNotNone(match, run.stdout)
        self.assertGreaterEqual(int(match[1]), 80, run.stdout)
        self.assertEqual(int(match[2]), 0, run.stdout)
        self.assertIn('PASS TX_ACK_confirms_real_sender', run.stdout)
        self.assertIn('PASS wrong_session_cannot_control_or_confirm', run.stdout)
        self.assertIn('PASS failed_bind_no_publication', run.stdout)


if __name__ == '__main__':
    unittest.main()
