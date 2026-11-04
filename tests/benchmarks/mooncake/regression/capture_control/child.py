"""Harmless owned-pipe child; never executes a benchmark or contacts a device."""
import os
from pathlib import Path
import signal
import sys
import time

mode = sys.argv[1]
root = Path.cwd()

def stop(_number, _frame):
    if mode == 'termwait':
        (root / 'term-entered').touch()
        while not (root / 'exit-now').exists():
            time.sleep(.002)
    os.write(1, b'TERM-stdout\n')
    os.write(2, b'TERM-stderr\n')
    raise SystemExit(0)

signal.signal(signal.SIGTERM, signal.SIG_IGN if mode == 'ignore' else stop)
os.write(1, b'  ./tebench --target_seg_name=owned-control --seg_type=VRAM --backend=tent\n')
(root / 'child-ready').touch()
if mode == 'busy':
    for _ in range(8192):
        os.write(1, b'B' * 1024)
        os.write(2, b'C' * 1024)
while True:
    if (root / 'drain-now').exists() and not (root / 'drain-written').exists():
        for _ in range(128):
            os.write(1, b'D' * 1024)
            os.write(2, b'E' * 1024)
        (root / 'drain-written').touch()
    time.sleep(.005)
