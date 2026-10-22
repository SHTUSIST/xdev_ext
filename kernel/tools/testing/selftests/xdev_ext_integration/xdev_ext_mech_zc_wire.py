#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Private QEMU stream cable; CPU copying here is not device performance."""
import argparse
import json
import os
import signal
import socket
import struct
import threading
from pathlib import Path


class FaultInjector:
    def __init__(self, fault='none'):
        if fault not in ('none', 'drop-middle', 'duplicate-middle', 'reliable-drop-data',
                         'reliable-drop-ack', 'reliable-duplicate-ack',
                         'reliable-replay-group', 'reliable-reorder-group',
                         'reliable-budget-unknown'):
            raise ValueError('unknown wire fault')
        self.fault = fault
        self.stats = dict(matched=0, dropped=0, duplicated=0)
        self._lock = threading.Lock()
        self._replay = {}
        self._replay_attempt = None
        self.stats['reordered'] = 0
        self._reorder_done = False

    @staticmethod
    def _matches(frame):
        if (len(frame) < 82 or
                frame[:14] != bytes.fromhex('0200000000020200000000010800')):
            return False
        ip = frame[14:]
        # Match only complete, unfragmented IPv4 UDP datagrams.
        ihl = (ip[0] & 15) * 4
        if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl + 48:
            return False
        total = int.from_bytes(ip[2:4], 'big')
        if total > len(ip) or total < ihl + 48 or ip[9] != 17:
            return False
        if int.from_bytes(ip[6:8], 'big') & 0x3fff:
            return False
        if ip[12:20] != socket.inet_aton('192.0.2.1') + socket.inet_aton('192.0.2.2'):
            return False
        udp = ip[ihl:total]
        src, dst, size = struct.unpack('!HHH', udp[:6])
        if (src, dst) != (54321, 12345) or size != len(udp) or size < 48:
            return False
        nxp = udp[8:48]
        if nxp[:8] != b'NXP2\x02\x28\x02\x00':
            return False
        session, generation, index, count, length = struct.unpack('!QIHHI', nxp[8:28])
        offset = int.from_bytes(nxp[28:32], 'big')
        payload = int.from_bytes(nxp[32:36], 'big')
        return ((session, generation, index, count, length) ==
                (270019, 2, 2, 6, 8192) and offset == 2 * 1432 and
                payload == 1432 and payload == size - 48)

    @staticmethod
    def _reliable(frame):
        if len(frame) < 106:
            return None
        ip = frame[14:]
        if frame[12:14] != b'\x08\x00' or ip[0] != 0x45 or ip[9] != 17:
            return None
        total = int.from_bytes(ip[2:4], 'big')
        if total < 92 or total > len(ip) or int.from_bytes(ip[6:8], 'big') & 0x3fff:
            return None
        checksum = sum(struct.unpack('!10H', ip[:20]))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        if checksum != 0xffff:
            return None
        udp = ip[20:total]
        src, dst, size = struct.unpack('!HHH', udp[:6])
        if size != len(udp) or udp[6:8] != bytes(2):
            return None
        hdr = udp[8:72]
        if hdr[:6] != b'NXP3\x03\x40' or hdr[7] or hdr[44:48] != bytes(4) or hdr[60:64] != bytes(4):
            return None
        typ = hdr[6]
        session, group, attempt, length, index, count, offset, payload = struct.unpack('!QQIIHHII', hdr[8:44])
        if session != 270019 or group != 2 or not attempt:
            return None
        if typ == 1:
            if (frame[:12] != bytes.fromhex('020000000002020000000001') or
                ip[12:20] != socket.inet_aton('192.0.2.1') + socket.inet_aton('192.0.2.2') or
                (src, dst) != (54321, 12345) or (length, count) != (8192, 6) or
                index >= count or offset != index * 1408 or
                payload != min(1408, 8192-offset) or len(udp) != 72+payload or
                hdr[48:56] != bytes(8)):
                return None
        elif typ == 2:
            if (frame[:12] != bytes.fromhex('020000000001020000000002') or
                ip[12:20] != socket.inet_aton('192.0.2.2') + socket.inet_aton('192.0.2.1') or
                (src, dst) != (12345, 54321) or length or index or count or offset or payload or
                len(udp) != 72 or not int.from_bytes(hdr[48:56], 'big')):
                return None
        else:
            return None
        raw = bytearray(hdr + udp[72:])
        expected = int.from_bytes(raw[56:60], 'big')
        raw[56:60] = bytes(4)
        crc = 0xffffffff
        for byte in raw:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
        if crc ^ 0xffffffff != expected:
            return None
        return typ, index, count, attempt

    def _process_reliable(self, frame):
        msg = self._reliable(frame)
        if msg is None:
            return [frame]
        typ, index, count, attempt = msg
        with self._lock:
            if self.fault == 'reliable-budget-unknown':
                if typ == 2:
                    self.stats['matched'] += 1
                    self.stats['dropped'] += 1
                    return []
                return [frame]
            if self.fault == 'reliable-reorder-group':
                if typ != 1 or self._reorder_done:
                    return [frame]
                if self._replay_attempt is None:
                    self._replay_attempt = attempt
                if attempt != self._replay_attempt:
                    return [frame]
                self._replay.setdefault(index, frame)
                if len(self._replay) < count:
                    return []
                self._reorder_done = True
                self.stats['matched'] += 1
                self.stats['reordered'] = count
                return [self._replay[i] for i in reversed(range(count))]
            if self.stats['dropped'] or self.stats['duplicated']:
                return [frame]
            if self.fault == 'reliable-replay-group':
                if typ != 1:
                    return [frame]
                if self._replay_attempt is None:
                    self._replay_attempt = attempt
                if attempt != self._replay_attempt:
                    return [frame]
                self._replay.setdefault(index, frame)
                if len(self._replay) != count:
                    return [frame]
                self.stats['matched'] += 1
                self.stats['duplicated'] += count
                return [frame] + [self._replay[i] for i in range(count)]
            if ((self.fault == 'reliable-drop-data' and (typ, index) != (1, 2)) or
                (self.fault in ('reliable-drop-ack', 'reliable-duplicate-ack') and typ != 2)):
                return [frame]
            self.stats['matched'] += 1
            if self.fault in ('reliable-drop-data', 'reliable-drop-ack'):
                self.stats['dropped'] += 1
                return []
            self.stats['duplicated'] += 1
            return [frame, frame]

    def process_frame(self, frame):
        if self.fault.startswith('reliable-'):
            return self._process_reliable(frame)
        if self.fault == 'none' or not self._matches(frame):
            return [frame]
        with self._lock:
            if self.stats['dropped'] or self.stats['duplicated']:
                return [frame]
            self.stats['matched'] += 1
            if self.fault == 'drop-middle':
                self.stats['dropped'] += 1
                return []
            self.stats['duplicated'] += 1
            return [frame, frame]


def _read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            if result:
                raise ValueError('truncated QEMU stream record')
            return None
        result.extend(part)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--left', required=True)
    parser.add_argument('--right', required=True)
    parser.add_argument('--stats', required=True)
    parser.add_argument('--fault', default='none', choices=('none', 'drop-middle', 'duplicate-middle', 'reliable-drop-data',
                         'reliable-drop-ack', 'reliable-duplicate-ack',
                         'reliable-replay-group', 'reliable-reorder-group',
                         'reliable-budget-unknown'))
    args = parser.parse_args()
    injector = FaultInjector(args.fault)
    listeners, peers, errors = [], [], []
    stopped = threading.Event()

    def stop(*_):
        stopped.set()
        for peer in peers:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def pump(source, destination):
        try:
            while not stopped.is_set():
                header = _read_exact(source, 4)
                if header is None:
                    break
                size, = struct.unpack('!I', header)
                if not 14 <= size <= 65536:
                    raise ValueError('invalid QEMU stream frame length')
                frame = _read_exact(source, size)
                if frame is None:
                    raise ValueError('missing QEMU stream frame')
                for output in injector.process_frame(frame):
                    destination.sendall(struct.pack('!I', len(output)) + output)
        except (OSError, ValueError) as exc:
            if not stopped.is_set():
                errors.append(str(exc))
        finally:
            stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for path in (args.left, args.right):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(path)  # Never unlink another process's socket.
            os.chmod(path, 0o600)
            listener.listen(1)
            listener.settimeout(0.2)
            listeners.append(listener)
        for listener in listeners:
            while not stopped.is_set():
                try:
                    peer, _ = listener.accept()
                    peers.append(peer)
                    break
                except socket.timeout:
                    continue
        if len(peers) == 2:
            threads = [threading.Thread(target=pump, args=pair) for pair in
                       ((peers[0], peers[1]), (peers[1], peers[0]))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
    finally:
        stop()
        for sock in peers + listeners:
            sock.close()
        for path, listener in zip((args.left, args.right), listeners):
            Path(path).unlink(missing_ok=True)
        stats = dict(injector.stats, mode=args.fault, errors=errors)
        Path(args.stats).write_text(json.dumps(stats) + '\n')
        print('XDEV_EXT_ZC_FAULT_COUNTS mode=%s matched=%d dropped=%d duplicated=%d reordered=%d '
              'session=270019 generation=2 index=2 count=6' %
              (args.fault, injector.stats['matched'], injector.stats['dropped'],
               injector.stats['duplicated'], injector.stats['reordered']), flush=True)
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
