#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run isolated software-device correctness campaigns using the existing KVM image builder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import xdev_ext_mech_zc_fault_validate as oracle


def qemu_command(scratch, readonly=False):
    p = str(scratch)
    return ['/usr/local/bin/qemu-system-x86_64', '-machine', 'q35,accel=kvm',
            '-cpu', 'host', '-smp', '4', '-m', '4096', '-nographic', '-no-reboot',
            '-kernel', p + '/build/arch/x86/boot/bzImage', '-initrd', p + '/initramfs.cpio.gz',
            '-append', 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1',
            '-nic', 'none', '-netdev', 'hubport,id=wire0,hubid=0',
            '-netdev', 'hubport,id=wire1,hubid=0',
            '-device', 'virtio-net-pci,netdev=wire0,mac=02:00:00:00:00:01,iommu_platform=on,disable-legacy=on,rx_queue_size=1024',
            '-device', 'virtio-net-pci,netdev=wire1,mac=02:00:00:00:00:02,iommu_platform=on,disable-legacy=on,rx_queue_size=1024',
            '-drive', f'file={p}/source.raw,if=none,id=src,format=raw,cache=none,aio=threads',
            '-device', 'nvme,drive=src,serial=UBRZCSRC01',
            '-drive', f'file={p}/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads' +
                      (',readonly=on' if readonly else ''),
            '-device', 'nvme,drive=dst,serial=UBRZCDST01']


def snapshot_other_qemu():
    """Record identities only; do not expose command lines or act on foreign processes."""
    rows = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            exe = (proc / 'exe').resolve(strict=True)
            if not exe.name.startswith('qemu-system-'):
                continue
            stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
            start = stat[19]
            rows.append(f'{proc.name} {start} {hashlib.sha256(exe.read_bytes()).hexdigest()} '
                        f'{hashlib.sha256((proc / "cmdline").read_bytes()).hexdigest()}')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return '\n'.join(sorted(rows)) + ('\n' if rows else '')


def plan(args, name, reuse):
    settings = oracle.host_settings(name)
    cmd = ['bash', str(Path(args.source) / 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'),
           '--scratch', args.scratch, '--source', args.source, '--ce-sim',
           '--groups', str(args.groups), '--depth', str(args.depth), '--ce-slots', str(args.depth),
           '--fault-campaign', name]
    if reuse:
        cmd.append('--run-only')
    if args.debug_locking:
        cmd.append('--debug-locking')
    return dict(campaign=name, expectation=oracle.expectation_line(name),
                groups=args.groups, depth=args.depth, performance_claim='none',
                readonly_destination=bool(settings['destination_readonly']),
                harness_command=cmd, qemu_command=qemu_command(args.scratch,
                                      bool(settings['destination_readonly'])))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', choices=['all', *oracle.CAMPAIGNS], default='all')
    parser.add_argument('--groups', type=int, default=64)
    parser.add_argument('--depth', type=int, default=8)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--run-only', action='store_true')
    parser.add_argument('--debug-locking', action='store_true')
    parser.add_argument('scratch')
    parser.add_argument('source')
    args = parser.parse_args(argv)
    try:
        oracle.fault_layout(args.groups)
        if not 1 <= args.depth <= min(8, args.groups):
            raise ValueError('depth must be 1..min(8, groups)')
        if not re.fullmatch(r'/tmp/xdev-ext-e2e\.[A-Za-z0-9]+', args.scratch):
            raise ValueError('scratch must be a private /tmp/xdev-ext-e2e.<id> directory')
        if not Path(args.source).is_absolute():
            raise ValueError('source must be absolute')
    except ValueError as error:
        parser.error(str(error))
    names = list(oracle.CAMPAIGNS) if args.campaign == 'all' else [args.campaign]
    plans = [plan(args, name, args.run_only or i > 0) for i, name in enumerate(names)]
    if args.dry_run:
        for item in plans:
            print(item['expectation'])
            print(json.dumps(item, sort_keys=True))
        return 0
    scratch = Path(args.scratch)
    if scratch.is_symlink() or not scratch.is_dir() or scratch.stat().st_mode & 0o777 != 0o700:
        parser.error('scratch must already exist, mode 0700, and not be a symlink')
    os.umask(0o077)
    results = scratch / 'fault-campaigns'
    results.mkdir(exist_ok=True)
    for item in plans:
        output = results / item['campaign']
        if output.exists():
            parser.error(f'campaign evidence already exists: {output}')
        output.mkdir()
        (output / 'plan.json').write_text(json.dumps(item, indent=2) + '\n')
        before = snapshot_other_qemu()
        (output / 'other-qemu-before.txt').write_text(before)
        print(item['expectation'], flush=True)
        # The harness validates exact source/build identity and boots one guest.
        status = subprocess.run(item['harness_command'], check=False).returncode
        after = snapshot_other_qemu()
        (output / 'other-qemu-after.txt').write_text(after)
        evidence = scratch / 'evidence'
        if evidence.is_dir():
            shutil.copytree(evidence, output / 'harness', symlinks=True)
        for name in ('guest.log', 'qemu.exit'):
            if (evidence / name).is_file():
                shutil.copyfile(evidence / name, output / name)
        for name in ('source-before.raw', 'source.raw', 'destination-before.raw', 'destination.raw'):
            if (scratch / name).is_file():
                shutil.copyfile(scratch / name, output / name)
        (output / 'harness.exit').write_text(str(status) + '\n')
        if before != after:
            print('FAIL foreign QEMU process identities changed during campaign', file=sys.stderr)
            return 1
        verdict = oracle.main(['check', '--campaign', item['campaign'], '--dir', str(output),
                               '--groups', str(args.groups), '--depth', str(args.depth)])
        (output / 'matrix.exit').write_text(str(verdict) + '\n')
        if status or verdict:
            return verdict or 1
    print(f'XDEV_EXT_ZC_FAULT_MATRIX=PASS campaigns={len(plans)} performance_claim=none')
    return 0


if __name__ == '__main__':
    sys.exit(main())
