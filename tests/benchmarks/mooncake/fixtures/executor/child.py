"""Harmless process fixture: ordinary temporary files, raw bytes and sleeps only."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument('--behavior', default='success')
p.add_argument('--payload')
p.add_argument('--result_output_jsonl')
p.add_argument('--literal', default='')
p.add_argument('--log', default='')
p.add_argument('--segment', default='opaque:fresh-segment')
a, _ = p.parse_known_args()
Path('fixture-observation.json').write_text(json.dumps({
    'pid': os.getpid(), 'pgid': os.getpgrp(), 'cwd': os.getcwd(),
    'literal': a.literal, 'environment': dict(os.environ), 'argv': sys.argv,
    'stdin_eof': os.read(0, 1) == b'',
}))
if a.behavior in ('target', 'target-ignore-term', 'target-exit'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN if a.behavior == 'target-ignore-term'
                  else lambda *_: sys.exit(0))
    print('\x1b[32mTo start initiators, run\n  ./tebench --target_seg_name=' + a.segment +
          ' --seg_type=VRAM --backend=tent\nPress Ctrl-C to terminate\x1b[0m', flush=True)
    if a.behavior == 'target-exit':
        sys.exit(17)
    while True:
        os.write(2, b'target still owned\n')
        time.sleep(.03)
if a.behavior in ('ignore-term', 'descendant'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if a.behavior == 'descendant':
    descendant = subprocess.Popen([sys.executable, '-c',
        'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(300)'],
        stdin=subprocess.DEVNULL)
    Path('descendant.pid').write_text(str(descendant.pid))
if a.behavior in ('sleep', 'ignore-term', 'descendant'):
    time.sleep(300)
if a.behavior == 'native-flood':
    Path(a.result_output_jsonl).write_bytes(b'x' * (1024 * 1024 + 4096))
    time.sleep(300)
if a.behavior == 'flood':
    # Alternate complete writes to both pipes, enough to exceed each 64 MiB cap.
    chunk = b'x' * 65536
    for _ in range(1056):
        os.write(1, chunk)
        os.write(2, chunk)
    sys.exit(0)
if a.behavior != 'missing':
    payload = Path(a.payload).read_bytes()
    if a.behavior == 'partial':
        payload = payload[:len(payload) // 2]
    Path(a.result_output_jsonl).write_bytes(payload)
os.write(1, b'fixture stdout raw \xff\n')
os.write(2, b'fixture stderr raw \xfe\n')
if a.log:
    os.write(2, a.log.encode())
if a.behavior == 'physical-looking':
    print('status=completed execution=physical performance_claim=standalone-baseline-only')
sys.exit(17 if a.behavior == 'exit17' else 0)
