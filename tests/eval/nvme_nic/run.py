#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NVMe<->NIC eval (reviewer E3): direction x size x queue-depth sweeps over posix, uring, splice and session arms.

Measured runs need a physical producer (strict kernel for the session arm) and
a remote nnb_peer; they refuse with exit 4 before any workload otherwise.
--correctness-only runs the same arms without emitting any timing (loopback
or KVM).  Exit: 0 every record validated, 1 failure, 2 usage, 4 refused.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import subprocess
import sys
import tempfile

import gate
import results

HERE = Path(__file__).resolve().parent
ARMS = ('posix', 'uring', 'splice', 'session')
MIN_SIZE, MAX_SIZE = 4096, 4 << 20


def decimal(text):
    if not re.fullmatch('[0-9]+', text, flags=re.ASCII):
        raise argparse.ArgumentTypeError('ASCII unsigned decimal required')
    value = int(text)
    if value >= 2 ** 64:
        raise argparse.ArgumentTypeError('u64 overflow')
    return value


def power_list(text, low, high, what):
    """'a..b' (every power of two in [a, b]) or 'a,b,c'; each a power of two in [low, high]."""
    values = []
    for part in text.split(','):
        bounds = part.split('..')
        if len(bounds) > 2 or not all(re.fullmatch('[0-9]+', b or 'x', flags=re.ASCII) for b in bounds):
            raise argparse.ArgumentTypeError(f'{what}: N, N,M or N..M')
        lo, hi = int(bounds[0]), int(bounds[-1])
        for v in (lo, hi):
            if v < low or v > high or v & (v - 1):
                raise argparse.ArgumentTypeError(f'{what} {v}: power of two in {low}..{high} required')
        if lo > hi:
            raise argparse.ArgumentTypeError(f'{what}: empty range')
        v = lo
        while v <= hi:
            values.append(v)
            v <<= 1
    if len(set(values)) != len(values):
        raise argparse.ArgumentTypeError(f'{what}: duplicate value')
    return values


def endpoint(text):
    ip, sep, port = text.rpartition(':')
    try:
        socket.inet_pton(socket.AF_INET, ip)
        value = decimal(port)
    except (OSError, argparse.ArgumentTypeError) as error:
        raise argparse.ArgumentTypeError('IPv4:PORT required') from error
    if not sep or not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError('IPv4:PORT required')
    return ip, value


def ipv4(text):
    try:
        socket.inet_pton(socket.AF_INET, text)
    except OSError as error:
        raise argparse.ArgumentTypeError('IPv4 address required') from error
    return text


def mac(text):
    if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', text):
        raise argparse.ArgumentTypeError('MAC address required')
    return text.lower()


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--direction', choices=('fwd', 'rev'), default='fwd')
    p.add_argument('--sizes', type=lambda t: power_list(t, MIN_SIZE, MAX_SIZE, 'size'))
    p.add_argument('--qd', type=lambda t: power_list(t, 1, 128, 'qd'))
    p.add_argument('--arms')
    for name, default in (('pairs', 5), ('warmup', 1), ('order-seed', 1), ('units', 0), ('seed', 1),
                          ('queue', 0), ('local-port', 47000), ('peer-port', 0), ('slba', 0), ('nlb', 0),
                          ('rate-mbps', 0), ('window-mib', 8)):
        p.add_argument('--' + name, type=decimal, default=default)
    p.add_argument('--ifname', default='')
    p.add_argument('--peer', dest='peer_control', type=endpoint, help='peer control endpoint IPv4:PORT')
    p.add_argument('--peer-ip', type=ipv4)
    p.add_argument('--local-ip', type=ipv4)
    p.add_argument('--peer-mac', type=mac)
    p.add_argument('--local-mac', type=mac)
    p.add_argument('--source', default='', help='NVMe block device (or a file with --correctness-only)')
    p.add_argument('--ng', default='', help='NVMe generic char device of the same namespace (session)')
    p.add_argument('--bpf-object', default=str(HERE / '.build/bpf/nnb_bench.bpf.o'))
    p.add_argument('--build-dir', type=Path, default=HERE / '.build')
    p.add_argument('--prepare-window', action='store_true', help='forward: write the generator into the window first')
    p.add_argument('--allow-window-write', action='store_true', help='required for --prepare-window and reverse runs on devices')
    p.add_argument('--correctness-only', action='store_true', help='no timing is emitted; loopback/KVM allowed')
    p.add_argument('--loopback', action='store_true', help='with --correctness-only: temp file window and local peer')
    p.add_argument('--fault', choices=('skip-datagram', 'duplicate-datagram', 'corrupt-payload', 'skip-write',
                                       'thread-create'))
    p.add_argument('--directory', type=Path)
    seen = set()
    for arg in argv:
        if arg.startswith('--'):
            key = arg.split('=', 1)[0]
            if key in seen:
                p.error('duplicate option: ' + key)
            seen.add(key)
    args = p.parse_args(argv)
    default_arms = 'posix,uring,splice,session' if args.direction == 'fwd' else 'posix,uring,session'
    args.arms = (args.arms or default_arms).split(',')
    if any(a not in ARMS for a in args.arms) or len(set(args.arms)) != len(args.arms) or not args.arms:
        p.error('--arms: subset of ' + ','.join(ARMS))
    if args.direction == 'rev' and 'splice' in args.arms:
        p.error('splice has no reverse arm: a UDP socket cannot splice into a file')
    if args.loopback and not args.correctness_only:
        p.error('--loopback requires --correctness-only (no timing on loopback)')
    if args.loopback and 'session' in args.arms:
        p.error('the session arm needs an AF_XDP NIC; it has no loopback form')
    if args.fault and not args.correctness_only:
        p.error('--fault is a negative correctness check only')
    if args.sizes is None:
        args.sizes = [4096, 1 << 20] if args.correctness_only else power_list('4096..4194304', MIN_SIZE, MAX_SIZE, 'size')
    if args.qd is None:
        args.qd = [1, 4] if args.correctness_only else [1, 8, 32, 128]
    if args.pairs > 1000 or args.warmup > 100 or args.units > 1 << 20 or args.queue >= 2 ** 32:
        p.error('pairs<=1000, warmup<=100, units<=2^20')
    if args.local_port < 1 or args.local_port > 65535 - 1024 or args.peer_port > 65535 or args.rate_mbps > 1000000:
        p.error('port/rate range')
    if not args.window_mib or args.window_mib % 4 or args.window_mib > 1024:
        p.error('--window-mib: multiple of 4, at most 1024')
    if not args.loopback and (args.direction == 'rev' or args.prepare_window) and not args.allow_window_write:
        p.error('reverse runs and --prepare-window write the NVMe window: pass --allow-window-write')
    return args


def units_for(args, size, qd):
    """The producer's own rule, stated independently for validation."""
    units = args.units or (qd if args.correctness_only else max(qd, (64 << 20) // size))
    if args.direction == 'rev':
        units = -(-units // qd) * qd
    return units


def producer(args):
    return args.build_dir / 'nnb_producer'


def features(args):
    out = subprocess.run([str(producer(args)), '--features'], text=True, capture_output=True, timeout=30)
    if out.returncode:
        raise gate.Refused('not_run_capability', 'producer unavailable: ' + out.stderr.strip())
    return json.loads(out.stdout)


def lba_bytes(path):
    if not stat.S_ISBLK(os.stat(path).st_mode):
        return 512
    return int(Path('/sys/class/block', Path(path).resolve().name, 'queue/logical_block_size').read_text())


def direct_ok(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
        os.close(fd)
        return True
    except OSError:
        return False


def start_peer(args):
    peer = subprocess.Popen([str(args.build_dir / 'nnb_peer'), '--control-bind', '127.0.0.1:0',
                             '--data-bind', '127.0.0.1:0'], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not select.select([peer.stdout], [], [], 10)[0]:
        peer.kill()
        raise RuntimeError('peer readiness timeout')
    ready = json.loads(peer.stdout.readline())
    if ready.get('status') != 'ready':
        raise RuntimeError('peer not ready')
    return peer, ready


def command(args, size, qd, mtu, extra=()):
    cmd = [str(producer(args)), '--direction', args.direction, '--size', size, '--qd', qd,
           '--source', args.source, '--slba', args.slba, '--nlb', args.nlb, '--mtu', mtu,
           '--seed', args.seed]
    if not args.prepare_only:
        cmd += ['--arms', ','.join(args.arms), '--local-ip', args.local_ip, '--peer-ip', args.peer_ip,
                '--local-port', args.local_port, '--peer-port', args.peer_port,
                '--control', '%s:%d' % args.peer_control, '--pairs', args.pairs, '--warmup', args.warmup,
                '--order-seed', args.order_seed, '--units', units_for(args, size, qd),
                '--run-id', args.run_id, '--session-base', args.session_base, '--rate-mbps', args.rate_mbps]
        if 'session' in args.arms:
            cmd += ['--ifname', args.ifname, '--queue', args.queue, '--ng', args.ng,
                    '--bpf-object', args.bpf_object, '--local-mac', args.local_mac, '--peer-mac', args.peer_mac]
        if args.correctness_only:
            cmd.append('--correctness')
        if args.fault:
            cmd += ['--fault', args.fault]
    if args.buffered:
        cmd.append('--buffered')
    return [str(c) for c in (*cmd, *extra)]


def campaign(args, mtu, receipt):
    window = args.nlb * lba_bytes(args.source)
    measured = not args.correctness_only
    if args.direction == 'fwd' and args.prepare_window:
        args.prepare_only = True
        out = subprocess.run(command(args, args.sizes[0], 1, mtu, ['--prepare-window']),
                             text=True, capture_output=True, timeout=3600)
        args.prepare_only = False
        if out.returncode:
            raise RuntimeError('prepare window: ' + out.stderr.strip())
    configs = []
    for size in args.sizes:
        for qd in args.qd:
            args.run_id = secrets.randbelow(2 ** 63) + 1
            args.session_base = secrets.randbelow(2 ** 63) + 1
            out = subprocess.run(command(args, size, qd, mtu), text=True, capture_output=True, timeout=7200)
            if out.returncode == 4:
                # Refused before this configuration's first trial; earlier ones stand.
                raise gate.Refused('not_run_capability', f'size {size} qd {qd}: ' + out.stderr.strip(),
                                   completed=len(configs))
            if out.returncode:
                raise RuntimeError(f'size {size} qd {qd}: producer exit {out.returncode}: ' + out.stderr.strip())
            expect = dict(direction=args.direction, size=size, qd=qd, units=units_for(args, size, qd),
                          pairs=args.pairs, warmup=args.warmup, arms=args.arms,
                          geometry=results.geometry(mtu, size, window))
            trials, integrity = results.validate(out.stdout.splitlines(), expect, measured)
            config = dict(status='ok', mode='measured' if measured else 'correctness', direction=args.direction,
                          size=size, qd=qd, arms=args.arms, direct_io=not args.buffered,
                          integrity={r['arm']: True for r in integrity}, geometry=expect['geometry'])
            if args.direction == 'fwd':
                # Peer receive buffers against datagrams (UDP GRO coalescing); not timing.
                config['peer_buffers'] = {a: sum(r['peer_buffers'] for r in trials if r['arm'] == a) for a in args.arms}
                config['peer_datagrams'] = {a: sum(r['peer_datagrams'] for r in trials if r['arm'] == a)
                                            for a in args.arms}
            if measured:
                config['summary'] = results.summarize(trials, args.direction)
                config['records'] = trials
            print(json.dumps(config, sort_keys=True))
            sys.stdout.flush()
            configs.append(config)
    print(json.dumps(dict(status='ok', mode='measured' if measured else 'correctness', configs=len(configs),
                          admission=receipt), sort_keys=True))


def run(args):
    args.prepare_only = False
    args.buffered = False
    if not producer(args).is_file() or not (args.build_dir / 'nnb_peer').is_file():
        if args.build_dir != HERE / '.build' or not args.correctness_only:
            raise gate.Refused('not_run_capability', 'build first: make -C tests/eval/nvme_nic [ENABLE_URING=1 ENABLE_SESSION=1]')
        built = subprocess.run(['make', '-s', '-C', str(HERE), 'all'], text=True, capture_output=True)
        if built.returncode:
            raise gate.Refused('not_run_capability', 'build failed: ' + built.stderr)
    feats = features(args)
    if args.loopback:
        parent = args.directory or Path(tempfile.gettempdir())
        with tempfile.TemporaryDirectory(prefix='nnb-', dir=parent) as tmp:
            os.chmod(tmp, 0o700)
            args.source = str(Path(tmp) / 'window.bin')
            with open(args.source, 'wb') as out:
                out.truncate(args.window_mib << 20)
            args.nlb = (args.window_mib << 20) // 512
            args.slba = 0
            args.buffered = not direct_ok(args.source)
            args.prepare_window = args.direction == 'fwd'
            peer, ready = start_peer(args)
            try:
                args.local_ip = args.peer_ip = '127.0.0.1'
                args.peer_control = ('127.0.0.1', ready['control_port'])
                args.peer_port = ready['data_port']
                campaign(args, 1500, None)
            finally:
                peer.terminate()
                peer.communicate(timeout=10)
        return 0
    if args.correctness_only:
        for name in ('source', 'local_ip', 'peer_ip', 'peer_control', 'peer_port', 'nlb'):
            if not getattr(args, name):
                raise gate.Refused('not_run_capability', 'correctness run needs --' + name.replace('_', '-'))
        mtu = int(Path('/sys/class/net', args.ifname, 'mtu').read_text()) if args.ifname else 1500
        campaign(args, mtu, None)
        return 0
    receipt = gate.admit(args, feats)
    campaign(args, receipt['environment']['mtu'], receipt)
    return 0


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    try:
        return run(args)
    except gate.Refused as error:
        print(json.dumps(dict(status=error.status, completed_configurations=error.completed,
                              diagnostic=error.message)), file=sys.stderr)
        return 4
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status='error', diagnostic=str(error))), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
