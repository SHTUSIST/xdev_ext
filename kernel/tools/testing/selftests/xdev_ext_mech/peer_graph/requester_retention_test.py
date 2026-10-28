#!/usr/bin/env python3
"""Exercise the actual built-in requester quota core with host pthread adapters."""
import pathlib
import subprocess
import tempfile
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[5]
CORE = ROOT / 'kernel/io_uring/family/xdev_ext_requester_retention.c'
HEADER = ROOT / 'kernel/include/linux/xdev_ext_requester_retention.h'
CASES = ('balanced', 'per_device', 'retain_once', 'retained_release', 'new_session',
         'global_limit', 'overflow', 'distinct_devices', 'race_device', 'race_global',
         'race_retain')

def main():
    if not CORE.is_file():
        print('FAIL: missing production requester retention core: ' + str(CORE))
        return 1
    with tempfile.TemporaryDirectory(prefix='requester-retention-test-', dir=ROOT) as tmp:
        work = pathlib.Path(tmp)
        (work / 'linux').mkdir()
        # Kernel facilities only; reservation/retention logic comes exclusively from CORE.
        for name in ('types.h', 'pci.h', 'err.h', 'errno.h', 'kernel.h', 'module.h',
                     'export.h', 'mutex.h', 'slab.h', 'list.h', 'overflow.h', 'sizes.h',
                     'spinlock.h', 'device.h', 'limits.h', 'string.h'):
            (work / 'linux' / name).write_text('#include "requester_retention_host.h"\n')
        (work / 'linux/xdev_ext_requester_retention.h').write_text(HEADER.read_text())
        binary = work / 'retention'
        command = ['gcc', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-pthread', '-I' + str(work), '-I' + str(HERE),
                   '-DRETENTION_CORE="' + str(CORE) + '"',
                   str(HERE / 'requester_retention_cases.c'), '-o', str(binary)]
        subprocess.run(command, check=True)
        for case in CASES:
            subprocess.run([str(binary), case], check=True, timeout=30)
    return 0

if __name__ == '__main__':
    sys.exit(main())
