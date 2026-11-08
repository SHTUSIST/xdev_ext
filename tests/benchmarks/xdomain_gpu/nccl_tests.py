#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""E4 baseline 2 bandwidth: nccl-tests sendrecv_perf over NET/Socket (TODO.77).

    nccl_tests.py --binary PATH/sendrecv_perf --ifname thunderbolt0
                  [--launcher 'mpirun -np 2 -H a,b ...'] [--out REC.json]
                  [--log RAW.log] [--dry-run]

Runs `sendrecv_perf -b 64 -e 4M -f 2 -g 1` (one GPU per node, both nodes
started by the launcher) with NCCL defaults: only NCCL_SOCKET_IFNAME and
NCCL_DEBUG=INFO are set.  The NCCL INFO lines show which transport each
channel used; the run is accepted only when every channel went "via
NET/Socket" and no row reports wrong data (nccl-tests validates by
default).  sendrecv_perf sends in both directions at once; the ping-pong
latency comes from nccl_pingpong.  The raw log is kept next to the record.

Exit: 0 accepted, 1 command failed, wrong transport, wrong data or no rows,
2 usage.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

SCHEMA = 'xdev-eval-nccl-sendrecv-v1'
ARGS = ['-b', '64', '-e', '4M', '-f', '2', '-g', '1']
_VIA = re.compile(r'NCCL INFO Channel .* via (\S+)')
_VERSION = re.compile(r'NCCL INFO NCCL version (\S+)')


def _num(text):
    return float(text) if '.' in text else int(text)


def parse_output(text):
    rows, transports, version = [], [], None
    for line in text.splitlines():
        m = _VIA.search(line)
        if m and m.group(1) not in transports:
            transports.append(m.group(1))
        m = _VERSION.search(line)
        if m:
            version = m.group(1)
        f = line.split()
        if len(f) >= 13 and f[0].isdigit() and f[1].isdigit():
            def half(a):
                return dict(time_us=float(f[a]), algbw_gbs=float(f[a + 1]),
                            busbw_gbs=float(f[a + 2]), wrong=_num(f[a + 3]) if f[a + 3] != 'N/A' else None)
            rows.append(dict(size=int(f[0]), count=int(f[1]), type=f[2], redop=f[3], root=f[4],
                             out_of_place=half(5), in_place=half(9)))
    return dict(rows=rows, transports=transports, nccl_version=version)


def verdict(parsed):
    if not parsed['rows']:
        return 'no_rows'
    if not parsed['transports'] or any(not t.startswith('NET/Socket') for t in parsed['transports']):
        return 'not_net_socket'
    for r in parsed['rows']:
        for half in (r['out_of_place'], r['in_place']):
            if half['wrong'] not in (0, None):
                return 'wrong_data'
    return 'ok'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--binary', required=True)
    p.add_argument('--ifname', required=True)
    p.add_argument('--launcher', default='')
    p.add_argument('--out')
    p.add_argument('--log')
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args(argv)
    command = shlex.split(args.launcher) + [args.binary] + ARGS
    env_set = dict(NCCL_SOCKET_IFNAME=args.ifname, NCCL_DEBUG='INFO')
    if args.dry_run:
        print(json.dumps(dict(dry_run=True, argv=command, env=env_set)))
        return 0
    env = dict(os.environ, **env_set)
    r = subprocess.run(command, env=env, capture_output=True, text=True)
    text = r.stdout + r.stderr
    log = Path(args.log) if args.log else (Path(args.out).with_suffix('.log') if args.out
                                           else None)
    if log:
        log.write_text(text)
    parsed = parse_output(text)
    v = 'command_failed' if r.returncode else verdict(parsed)
    nccl_env = {k: v_ for k, v_ in env.items() if k.startswith('NCCL_')}
    record = dict(schema=SCHEMA, arm='nccl-sendrecv', verdict=v, argv=command, exit=r.returncode,
                  env=nccl_env, raw_log=str(log) if log else None, **parsed)
    text = json.dumps(record, indent=1)
    if args.out:
        Path(args.out).write_text(text + '\n')
    else:
        print(text)
    return 0 if v == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
