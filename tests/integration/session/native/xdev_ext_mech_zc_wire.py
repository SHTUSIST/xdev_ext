#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Private QEMU stream cable; CPU copying here is not device performance.

reliable-random applies seeded, independent per-frame loss and adjacent-pair
reordering to every valid NXP v3 frame of the campaign session (DATA, ACK and
HELD), and can delay each DATA frame toward the receiver (a slow receiver).
Timing of a software cable is not a network measurement.
"""
import argparse
import json
import os
import random
import select
import signal
import socket
import struct
import threading
import time
from pathlib import Path

FAULTS = ('none', 'drop-middle', 'duplicate-middle', 'reliable-drop-data',
          'reliable-drop-ack', 'reliable-duplicate-ack',
          'reliable-replay-group', 'reliable-reorder-group',
          'reliable-budget-unknown', 'reliable-random')
SESSION = 270019
LEFT_MAC, RIGHT_MAC = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
LEFT_IP, RIGHT_IP = socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2')


def _crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


class FaultInjector:
    def __init__(self, fault='none', *, loss=0.0, reorder=0.0, seed=0, slow_receiver_us=0):
        if fault not in FAULTS:
            raise ValueError('unknown wire fault')
        if not (0.0 <= loss < 1.0 and 0.0 <= reorder <= 1.0) or slow_receiver_us < 0 or seed < 0:
            raise ValueError('invalid random wire parameters')
        if (loss or reorder or slow_receiver_us) and fault != 'reliable-random':
            raise ValueError('loss/reorder/slow receiver require reliable-random')
        self.fault = fault
        self.loss, self.reorder, self.seed = float(loss), float(reorder), int(seed)
        self.slow_receiver_us = int(slow_receiver_us)
        self.stats = dict(matched=0, dropped=0, duplicated=0)
        self._lock = threading.Lock()
        self._replay = {}
        self._replay_attempt = None
        self.stats['reordered'] = 0
        self._reorder_done = False
        if fault == 'reliable-random':
            self.stats.update(dropped_data=0, dropped_control=0, delayed=0,
                              forwarded_data=0, forwarded_control=0)
            # One stream per frame class: decisions do not depend on how
            # the two pump threads interleave.
            self._rng = [random.Random(self.seed * 2 + kind) for kind in (0, 1)]
            self._pending = {}

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

    @staticmethod
    def _reliable_any(frame):
        """(type, group, index, count, attempt) of a valid campaign v3 frame."""
        if len(frame) < 106 or frame[12:14] != b'\x08\x00':
            return None
        ip = frame[14:]
        if ip[0] != 0x45 or ip[9] != 17:
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
        credit = int.from_bytes(hdr[48:56], 'big')
        if session != SESSION or not group or not attempt:
            return None
        forward = (frame[:12] == RIGHT_MAC + LEFT_MAC and ip[12:20] == LEFT_IP + RIGHT_IP and
                   (src, dst) == (54321, 12345))
        reverse = (frame[:12] == LEFT_MAC + RIGHT_MAC and ip[12:20] == RIGHT_IP + LEFT_IP and
                   (src, dst) == (12345, 54321))
        if typ == 1:
            if (not forward or not count or index >= count or not payload or credit or
                    len(udp) != 72 + payload or offset + payload > length):
                return None
        elif typ in (2, 3):
            if (not reverse or length or index or count or offset or payload or
                    len(udp) != 72 or not credit):
                return None
        else:
            return None
        raw = bytearray(hdr + udp[72:])
        expected = int.from_bytes(raw[56:60], 'big')
        raw[56:60] = bytes(4)
        if _crc32c(raw) != expected:
            return None
        return typ, group, index, count, attempt

    def _process_random(self, frame, direction):
        msg = self._reliable_any(frame)
        if msg is None:
            return [frame]
        kind = 0 if msg[0] == 1 else 1
        key = kind if direction is None else direction
        with self._lock:
            rng = self._rng[kind]
            lost, swap = rng.random() < self.loss, rng.random() < self.reorder
            self.stats['matched'] += 1
            if lost:
                self.stats['dropped'] += 1
                self.stats['dropped_control' if kind else 'dropped_data'] += 1
                return []
            held = self._pending.pop(key, None)
            if held is None and swap:
                self._pending[key] = (frame, kind)
                return []
            out = [(frame, kind)] + ([held] if held is not None else [])
            self.stats['reordered'] += held is not None
            return self._forward(out)

    def _forward(self, items):
        for _, kind in items:
            self.stats['forwarded_control' if kind else 'forwarded_data'] += 1
        return [frame for frame, _ in items]

    def flush(self, direction=None):
        """Release a frame still held for reordering (idle wire or shutdown)."""
        if self.fault != 'reliable-random':
            return []
        with self._lock:
            keys = sorted(self._pending) if direction is None else [direction]
            return self._forward([self._pending.pop(key) for key in keys if key in self._pending])

    def delay_us(self, frame):
        """Slow receiver: hold back each DATA frame on its way to the receiver."""
        # Only frames this cable already forwarded reach here; a header check
        # suffices and keeps a second CRC pass out of the delay decision.
        if (not self.slow_receiver_us or len(frame) < 106 or
                frame[:12] != RIGHT_MAC + LEFT_MAC or frame[42:49] != b'NXP3\x03\x40\x01'):
            return 0
        with self._lock:
            self.stats['delayed'] += 1
        return self.slow_receiver_us

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

    def process_frame(self, frame, direction=None):
        if self.fault == 'reliable-random':
            return self._process_random(frame, direction)
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
    parser.add_argument('--fault', default='none', choices=FAULTS)
    parser.add_argument('--loss', type=float, default=0.0,
                        help='reliable-random: per-frame loss probability, [0, 1)')
    parser.add_argument('--reorder', type=float, default=0.0,
                        help='reliable-random: probability that a frame swaps with the next one')
    parser.add_argument('--seed', type=int, default=0, help='reliable-random: decision seed')
    parser.add_argument('--slow-receiver-us', type=int, default=0,
                        help='reliable-random: delay of each DATA frame toward the receiver')
    args = parser.parse_args()
    try:
        injector = FaultInjector(args.fault, loss=args.loss, reorder=args.reorder,
                                 seed=args.seed, slow_receiver_us=args.slow_receiver_us)
    except ValueError as exc:
        parser.error(str(exc))
    listeners, peers, errors = [], [], []
    stopped = threading.Event()

    def stop(*_):
        stopped.set()
        for peer in peers:
            try:
                peer.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def send(destination, frames):
        for output in frames:
            delay = injector.delay_us(output)
            if delay:
                time.sleep(delay / 1e6)
            destination.sendall(struct.pack('!I', len(output)) + output)

    def pump(source, destination, direction):
        try:
            while not stopped.is_set():
                # An idle wire releases a frame held back for reordering.
                if (args.fault == 'reliable-random' and
                        not select.select([source], [], [], 0.05)[0]):
                    send(destination, injector.flush(direction))
                    continue
                header = _read_exact(source, 4)
                if header is None:
                    break
                size, = struct.unpack('!I', header)
                if not 14 <= size <= 65536:
                    raise ValueError('invalid QEMU stream frame length')
                frame = _read_exact(source, size)
                if frame is None:
                    raise ValueError('missing QEMU stream frame')
                send(destination, injector.process_frame(frame, direction))
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
            threads = [threading.Thread(target=pump, args=triple) for triple in
                       ((peers[0], peers[1], 0), (peers[1], peers[0], 1))]
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
        if args.fault == 'reliable-random':
            stats.update(loss=args.loss, reorder=args.reorder, seed=args.seed,
                         slow_receiver_us=args.slow_receiver_us)
        Path(args.stats).write_text(json.dumps(stats) + '\n')
        print('XDEV_EXT_ZC_FAULT_COUNTS mode=%s matched=%d dropped=%d duplicated=%d reordered=%d '
              'session=270019 generation=2 index=2 count=6' %
              (args.fault, injector.stats['matched'], injector.stats['dropped'],
               injector.stats['duplicated'], injector.stats['reordered']), flush=True)
        if args.fault == 'reliable-random':
            print('XDEV_EXT_ZC_WIRE_RANDOM mode=reliable-random loss=%s reorder=%s seed=%d '
                  'slow_receiver_us=%d matched=%d dropped_data=%d dropped_control=%d reordered=%d '
                  'delayed=%d forwarded_data=%d forwarded_control=%d' %
                  (repr(args.loss), repr(args.reorder), args.seed, args.slow_receiver_us,
                   injector.stats['matched'], injector.stats['dropped_data'],
                   injector.stats['dropped_control'], injector.stats['reordered'],
                   injector.stats['delayed'], injector.stats['forwarded_data'],
                   injector.stats['forwarded_control']), flush=True)
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
