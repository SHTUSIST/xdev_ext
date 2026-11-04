"""Owned local child for a publication-interruption correctness test."""
import os
from pathlib import Path
import signal
import time

root = Path.cwd()
def stop(_number, _frame):
    os.write(1, b'publication-TERM-stdout\n')
    os.write(2, b'publication-TERM-stderr\n')
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
os.write(1, b'publication-ready\n')
(root / 'child-ready').touch()
while True:
    if (root / 'write-now').exists() and not (root / 'child-wrote').exists():
        os.write(1, b'publication-after-interrupt-stdout\n')
        os.write(2, b'publication-after-interrupt-stderr\n')
        (root / 'child-wrote').touch()
    time.sleep(.002)
