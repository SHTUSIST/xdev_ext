#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host CPU core-seconds between two markers, and the host-1 marker agent.

busy = user + nice + system + irq + softirq + steal of the aggregate "cpu"
line of /proc/stat (USER_HZ ticks). Guest time is already counted in user
and nice (kernel/sched/cputime.c account_guest_time), so the guest columns
are not added. Kernel workers, interrupts and every process of an arm are
included; the orchestrator also measures an idle window so the background
rate can be reported next to each run, never silently subtracted.

  python3 kv_cpu.py agent --listen HOST:PORT --token-file F [--allow-drop-caches]
The agent answers one line per request: PING, BEGIN run, END run, DROP_CACHES,
each followed by the token; replies are one JSON object per line.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socketserver
import subprocess
import sys
import threading
import time

RUN_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')


class CpuError(ValueError):
    pass


def parse_stat(text):
    cpus, total = 0, None
    for line in text.splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith('cpu'):
            continue
        if len(fields) < 9 or not all(f.isdigit() for f in fields[1:]):
            raise CpuError(f'malformed /proc/stat line: {line[:80]!r}')
        if fields[0] == 'cpu':
            total = [int(f) for f in fields[1:]]
        elif fields[0][3:].isdigit():
            cpus += 1
    if total is None or not cpus:
        raise CpuError('no aggregate cpu line in /proc/stat')
    user, nice, system, idle, iowait, irq, softirq, steal = total[:8]
    return dict(busy_ticks=user + nice + system + irq + softirq + steal,
                idle_ticks=idle + iowait, cpus=cpus)


def snapshot(proc_root='/proc'):
    snap = parse_stat(Path(proc_root, 'stat').read_text())
    snap['mono_ns'] = time.monotonic_ns()
    return snap


def delta(a, b, hz=None):
    hz = hz or os.sysconf('SC_CLK_TCK')
    if b['mono_ns'] <= a['mono_ns']:
        raise CpuError('markers are not in time order')
    busy = b['busy_ticks'] - a['busy_ticks']
    if busy < 0 or b['idle_ticks'] < a['idle_ticks'] or a['cpus'] != b['cpus']:
        raise CpuError('CPU counters went backwards or CPUs changed between markers')
    return dict(busy_ticks=busy, hz=hz, busy_core_seconds=busy / hz,
                wall_seconds=(b['mono_ns'] - a['mono_ns']) / 1e9, cpus=b['cpus'])


def drop_caches(proc_root='/proc'):
    """sync, then free page cache, dentries and inodes (Documentation/admin-guide/sysctl/vm.rst)."""
    subprocess.run(['sync'], check=True)
    with open(Path(proc_root, 'sys/vm/drop_caches'), 'w') as f:
        f.write('3\n')


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server
        for raw in self.rfile:
            parts = raw.decode(errors='replace').split()
            try:
                reply = server.answer(parts)
            except (CpuError, OSError, subprocess.CalledProcessError) as error:
                reply = dict(ok=False, error=str(error))
            self.wfile.write((json.dumps(reply) + '\n').encode())
            self.wfile.flush()


class AgentServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, token, proc_root='/proc', allow_drop_caches=False):
        super().__init__(address, _Handler)
        self.token, self.proc_root = token, proc_root
        self.allow_drop_caches = allow_drop_caches
        self.open = {}
        self.lock = threading.Lock()

    def answer(self, parts):
        if not parts or parts[-1] != self.token:
            raise CpuError('bad or missing token')
        cmd, args = parts[0], parts[1:-1]
        if cmd == 'PING' and not args:
            return dict(ok=True, pid=os.getpid())
        if cmd == 'DROP_CACHES' and not args:
            if not self.allow_drop_caches:
                raise CpuError('agent started without --allow-drop-caches')
            drop_caches(self.proc_root)
            return dict(ok=True)
        if cmd in ('BEGIN', 'END') and len(args) == 1 and RUN_RE.match(args[0]):
            run = args[0]
            snap = snapshot(self.proc_root)
            with self.lock:
                if cmd == 'BEGIN':
                    self.open[run] = snap
                    return dict(ok=True, run=run)
                start = self.open.pop(run, None)
            if start is None:
                raise CpuError(f'no BEGIN for run {run}')
            return dict(ok=True, run=run, **delta(start, snap))
        raise CpuError(f'unknown request {parts[:-1]}')


class AgentClient:
    def __init__(self, address, token, timeout=10.0):
        import socket
        self.address = tuple(address)
        self.token = token
        self.sock = socket.create_connection(self.address, timeout=timeout)
        self.file = self.sock.makefile('rwb')

    def _ask(self, *words):
        self.file.write((' '.join(words + (self.token,)) + '\n').encode())
        self.file.flush()
        line = self.file.readline()
        if not line:
            raise CpuError('agent closed the connection')
        reply = json.loads(line)
        if not reply.get('ok'):
            raise CpuError(f'agent refused {words[0]}: {reply.get("error")}')
        return reply

    def ping(self):
        return self._ask('PING')

    def begin(self, run):
        return self._ask('BEGIN', run)

    def end(self, run):
        return self._ask('END', run)

    def drop_caches(self):
        return self._ask('DROP_CACHES')

    def close(self):
        self.file.close()
        self.sock.close()


def parse_address(text):
    host, _, port = text.rpartition(':')
    if not host or not port.isdigit():
        raise CpuError(f'address must be HOST:PORT: {text!r}')
    return host, int(port)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    a = sub.add_parser('agent')
    a.add_argument('--listen', required=True)
    a.add_argument('--token-file', required=True)
    a.add_argument('--allow-drop-caches', action='store_true')
    s = sub.add_parser('snapshot')
    s.add_argument('--proc-root', default='/proc')
    args = parser.parse_args()
    if args.action == 'snapshot':
        print(json.dumps(snapshot(args.proc_root)))
        return 0
    token = Path(args.token_file).read_text().strip()
    if not RUN_RE.match(token):
        raise SystemExit('token must match ' + RUN_RE.pattern)
    server = AgentServer(parse_address(args.listen), token,
                         allow_drop_caches=args.allow_drop_caches)
    print(json.dumps(dict(agent='ready', address=server.server_address)), flush=True)
    server.serve_forever()
    return 0


if __name__ == '__main__':
    sys.exit(main())
