#!/usr/bin/env python3
import unittest
from xdev_ext_mech_zc_compat_validate import extract_logs, validate_socket, validate_peer


class CompatibilityConsole(unittest.TestCase):
    def test_extract_exact_logs(self):
        text = ''.join(f'XDEV_EXT_PRELOAD_LOG_BEGIN name={n}\nbody\nXDEV_EXT_PRELOAD_LOG_END name={n}\n' for n in self.names())
        self.assertEqual(set(extract_logs(text)), set(self.names()))
        for bad in (text.replace('END name=compat-udp.log', 'END name=wrong.log'),
                    text+text, text.replace('name=compat-udp.log','name=../compat-udp.log'),
                    text.replace('XDEV_EXT_PRELOAD_LOG_BEGIN name=compat-udp.log\nbody\nXDEV_EXT_PRELOAD_LOG_END name=compat-udp.log\n','')):
            with self.subTest(text=bad[:80]), self.assertRaises(ValueError):
                extract_logs(bad)

    @staticmethod
    def names():
        return ('compat-udp.log','compat-dio-off.log','compat-dio-on.log',
                'mech-socket-base.log','mech-socket-lifecycle.log',
                'mech-ce-socket-base.log','mech-ce-socket-lifecycle.log')

    def test_socket_missing_or_corrupt_evidence_rejected(self):
        with self.assertRaises(ValueError):
            validate_socket('PASS socket_guest groups=257\n')
        with self.assertRaises(ValueError):
            validate_socket('')

    def test_peer_requires_all_counts_and_lifetime(self):
        line = ('XDEV_EXT_PEER_NATIVE=PASS reads=259 writes=257 groups=257 batches=5 max_desc=64 '
            'native_depth=1 source_whole_disk_unchanged=1 destination_whole_disk=1 allocation_guards=1 '
            'maps=2 pins=2 live_maps=0 live_pins=0 memory=host-RAM-standin\n')
        console = line + '# software provider cleanly unloaded after exact reference drain\n' + \
            'XDEV_EXT_PEER_SOFTWARE_GUEST=PASS native=NVMe-SGL memory=host-RAM-standin gpu=none\n'
        validate_peer(console)
        for token in line.split()[1:]:
            with self.subTest(token=token), self.assertRaises(ValueError):
                validate_peer(console.replace(token, token.split('=')[0]+'=wrong', 1))
        for bad in (console+line, line, '', console.replace('exact reference drain','incomplete')):
            with self.assertRaises(ValueError):
                validate_peer(bad)


if __name__ == '__main__':
    unittest.main(verbosity=2)
