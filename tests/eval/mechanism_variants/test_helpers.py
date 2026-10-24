# SPDX-License-Identifier: GPL-2.0
"""Runner helpers use real subprocesses and UDP; never guest evidence."""
import hashlib
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def crc32c(data):
    c = 0xffffffff
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ (0x82f63b78 if c & 1 else 0)
    return c ^ 0xffffffff


def packet(generation, offset, payload, index, count):
    h = struct.pack('!IBBBBQIHHIIII', 0x4e585032, 2, 40, 2, 0,
                    270019, generation, index, count, 4096, offset, len(payload), 0)
    h = h[:36] + struct.pack('!I', crc32c(h + payload))
    return h + payload


class Helpers(unittest.TestCase):
    def test_trace_control_requires_explicit_private_guest(self):
        env = dict(os.environ)
        env.pop('E2_PRIVATE_GUEST', None)
        proc = subprocess.run(['sh', str(HERE / 'trace_ctl.sh'), 'begin', 'reverse', '/nonexistent'],
                              env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('private guest', proc.stderr)

    def test_seed_and_independent_oracle(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'source'
            subprocess.run(['python3', str(HERE / 'image.py'), 'seed', str(out)], check=True)
            self.assertEqual(len(out.read_bytes()), 32768)
            first = b''.join(hashlib.sha256(b'xdev-ext-e2-lba-v1\0' +
                              struct.pack('<QI', 2048, p)).digest() for p in range(16))
            self.assertEqual(out.read_bytes()[:512], first)
            image = out.read_bytes()
            # Literal external table, independent of either production BPF.
            slots = [0, 4, 2, 6, 1, 5, 3, 7]
            sink = Path(td) / 'sink'
            sink.write_bytes(b''.join(image[slots[r & 7]*4096:slots[r & 7]*4096+4096]
                                     for r in range(1, 17)))
            cmd = ['python3', str(HERE / 'image.py'), 'verify', str(sink),
                   '--variant', 'reverse', '--first-request-id', '1']
            subprocess.run(cmd, check=True)
            b = bytearray(sink.read_bytes()); b[-1] ^= 1; sink.write_bytes(b)
            self.assertNotEqual(subprocess.run(cmd, capture_output=True).returncode, 0)

    def test_udp_sink_complete_and_bad_crc(self):
        sink_exe = HERE / '.build' / 'mv_sink'
        subprocess.run(['make', '-s', '-C', str(HERE), 'sink'], check=True)
        for bad in (False, True):
            with self.subTest(bad_crc=bad), tempfile.TemporaryDirectory() as td:
                out = Path(td) / 'sink'
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
                proc = subprocess.Popen([str(sink_exe), '127.0.0.1', str(port), str(out)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.assertEqual(proc.stdout.readline().strip(), 'E2_SINK_READY')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        for g in range(1, 17):
                            for i in range(4):
                                pkt = packet(g, i*1024, bytes([g])*1024, i, 4)
                                if bad:
                                    pkt = pkt[:-1] + bytes([pkt[-1] ^ 1])
                                sock.sendto(pkt, ('127.0.0.1', port))
                                if bad:
                                    break
                            if bad:
                                break
                    stdout, stderr = proc.communicate(timeout=5)
                    self.assertEqual(proc.returncode == 0, not bad, stderr)
                    if not bad:
                        self.assertEqual(out.read_bytes(), b''.join(bytes([g])*4096 for g in range(1,17)))
                    else:
                        self.assertFalse(out.exists(), 'invalid capture must not publish a sink')
                finally:
                    if proc.poll() is None:
                        proc.kill(); proc.communicate()


if __name__ == '__main__':
    unittest.main()
