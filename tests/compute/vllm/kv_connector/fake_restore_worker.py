#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""A stand-in of `kv_restore restore|local-verify --dst ce-vmm` for host tests.

It speaks the worker line protocol (KV_READY, GO -> KV_RESULT, QUIT -> KV_BYE)
and "restores" by copying bytes [object_slba * lba, + bytes) of --source into
--stage at dst_frame0 * frame_bytes, so a host test can check what the
connector scatters. It moves no data through any device.

--mode: ok | fail-started (KV_RESULT ok=false after START) | refuse (ok=false,
started=false) | hang (never answers GO) | exit-on-go | bad-ready | short
(reports fewer bytes) | wrong-dst | retained (KV_BYE retained) | error-ready
--fail-after N: mode applies only from the (N+1)th GO; earlier GOs are ok.
"""
import argparse
import json
import os
import sys
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', default='ok')
    p.add_argument('--fail-after', type=int, default=0)
    p.add_argument('--source')
    p.add_argument('--stage')
    p.add_argument('--log')
    p.add_argument('--lba-bytes', type=int, default=512)
    p.add_argument('--frame-bytes', type=int, default=4096)
    p.add_argument('--group-bytes', type=int, default=131072)
    p.add_argument('--pool-bytes', type=int, default=1 << 24)
    p.add_argument('--export-fd', type=int, default=7)
    a = p.parse_args()
    log = open(a.log, 'a') if a.log else None
    if a.mode == 'error-ready':
        print('KV_ERROR {"where": "setup: CUDA VMM allocation", "error": -12}', flush=True)
        return 1
    ready = {'role': 'restore', 'dry_run': False, 'session_id': 1,
             'pool_frames': a.pool_bytes // a.frame_bytes, 'frame_bytes': a.frame_bytes,
             'group_bytes': a.group_bytes, 'depth': 32, 'window': 32, 'early': True,
             'private_xdomain': False, 'memlock_bytes': -1, 'dst': 'ce-vmm',
             'ring_frames': 1024, 'vmm_export_fd': a.export_fd, 'vmm_bytes': a.pool_bytes}
    if a.mode == 'bad-ready':
        ready['dst'] = 'peer'
    print('KV_READY ' + json.dumps(ready), flush=True)
    gos = 0
    for line in sys.stdin:
        if log:
            log.write(line)
            log.flush()
        words = line.split()
        if not words:
            continue
        if words[0] == 'QUIT':
            break
        kv = dict(w.split('=', 1) for w in words[1:])
        gos += 1
        mode = a.mode if gos > a.fail_after else 'ok'
        if mode == 'hang':
            time.sleep(3600)
        if mode == 'exit-on-go':
            return 3
        nbytes, dst0 = int(kv['bytes']), int(kv['dst_frame0'])
        t0 = time.monotonic_ns()
        ok, started, error = True, True, 0
        if mode == 'fail-started':
            ok, error = False, -5
        elif mode == 'refuse':
            ok, started, error = False, False, -114
        elif a.source and a.stage:
            with open(a.source, 'rb') as src, open(a.stage, 'r+b') as dst:
                src.seek(int(kv['object_slba']) * a.lba_bytes)
                data = src.read(nbytes)
                dst.seek(dst0 * a.frame_bytes)
                dst.write(data)
        t1 = time.monotonic_ns()
        result = {'run': kv['run'], 'role': 'restore', 'ok': ok, 'error': error, 'dry_run': False,
                  'bytes': nbytes if ok else 0, 'dst': 'peer' if mode == 'wrong-dst' else 'ce-vmm',
                  'payload_path': 'xdomain-rx>host-frame>ce-h2d', 'cpu_copy_bytes': 0,
                  'plan': {'groups': nbytes // a.group_bytes, 'host2_dst_frame0': dst0},
                  'started': started, 't0_ns': t0, 't1_ns': t1,
                  'latency_ns': t1 - t0 if started else 0, 'worker_cpu_us': 1, 'wait_err': 0,
                  'verified': None}
        if mode == 'short' and ok:
            result['bytes'] = nbytes - a.group_bytes
        print('KV_RESULT ' + json.dumps(result), flush=True)
    print('KV_BYE ' + json.dumps({'error': 0, 'stop_error': 0,
                                  'retained': a.mode == 'retained', 'restores': gos}), flush=True)
    return 1 if a.mode == 'retained' else 0


if __name__ == '__main__':
    sys.exit(main())
