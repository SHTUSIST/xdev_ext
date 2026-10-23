#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build and run setup_cost over a size range, devices and BPF plans.

    run.py [--sizes 1M..96G] [--devices nvme,nic,gpu] [--plans all|none|NAME,...]
           [--nvme-ng DEV --nvme-window SLBA:NLB] [--cuda-root SDK] [--reps N]
    run.py --counts-only [--plans all] [--bpf-dir DIR]	(may run in a guest)
    run.py --prog-stats [--prog-prefix NAME] -- WORKLOAD ARGV...

A range A..B steps by --size-step (4) and always includes B.  Devices add
measures to the host ones (umem, iou): nvme -> mech (session CREATE/STOP),
nic -> xdp (AF_XDP UMEM), gpu -> cuda and cufile (needs --cuda-root).
--plans picks *.bpf.o files from --bpf-dir, by default the mechanism build
directory of kernel/tools/xdev_ext_mech.  The mech measure needs an NVMe
plan attached first, for example
    xdev_ext_mech_ctl attach --obj nxp_mech.bpf.o --map nxp_nvme_ops --pin P
Timed modes refuse a hypervisor (exit 4) before building anything; exit
status otherwise is that of setup_cost.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEFAULT_BPF_DIR = ROOT / 'kernel/tools/xdev_ext_mech/.xdev_ext-mech-build'
UNITS = {'': 1, 'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30}
DEVICE_MEASURES = {'nvme': ['mech'], 'nic': ['xdp'], 'gpu': ['cuda', 'cufile']}
FRAME = 4096


def size(text):
    m = re.fullmatch(r'(\d+)([KMG]?)', text)
    if not m or not int(m.group(1)):
        raise ValueError('bad size %r' % text)
    value = int(m.group(1)) * UNITS[m.group(2)]
    if value % FRAME:
        raise ValueError('size %r is not a multiple of %d' % (text, FRAME))
    return value


def expand_sizes(text, step=4):
    if '..' not in text:
        return [size(t) for t in text.split(',')]
    parts = text.split('..')
    if len(parts) != 2:
        raise ValueError('bad range %r' % text)
    lo, hi = size(parts[0]), size(parts[1])
    if hi < lo:
        raise ValueError('descending range %r' % text)
    out, v = [], lo
    while v < hi:
        out.append(v)
        v *= step
    return out + [hi]


def measures(devices):
    out = ['umem', 'iou']
    for d in filter(None, devices.split(',')):
        if d not in DEVICE_MEASURES:
            raise ValueError('unknown device %r' % d)
        out += DEVICE_MEASURES[d]
    return out


def plan_objects(plans, directory):
    if plans == 'none':
        return []
    found = sorted(Path(directory).glob('*.bpf.o'))
    if plans == 'all':
        return found
    by_name = {p.name[:-len('.bpf.o')]: p for p in found}
    missing = [n for n in plans.split(',') if n not in by_name]
    if missing:
        raise ValueError('no %s.bpf.o in %s' % (','.join(missing), directory))
    return [by_name[n] for n in plans.split(',')]


def hypervisor(root):
    if (root / 'sys/hypervisor/type').exists():
        return True
    try:
        text = (root / 'proc/cpuinfo').read_text()
    except OSError:
        return False
    return any('hypervisor' in l.split() for l in text.splitlines() if l.startswith('flags'))


def parse_args(argv):
    if '--' in argv:
        split = argv.index('--')
        argv, cmd = argv[:split], argv[split + 1:]
    else:
        cmd = []
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--sizes', default='1M')
    parser.add_argument('--size-step', type=int, default=4)
    parser.add_argument('--devices', default='')
    parser.add_argument('--plans', default='all')
    parser.add_argument('--bpf-dir', default=str(DEFAULT_BPF_DIR))
    parser.add_argument('--nvme-ng')
    parser.add_argument('--nvme-window')
    parser.add_argument('--cuda-root')
    parser.add_argument('--cuda-device', type=int, default=0)
    parser.add_argument('--reps', type=int, default=5)
    parser.add_argument('--umem-cap', type=size, help='skip umem/mech above this size, e.g. 1G')
    parser.add_argument('--mem-margin', type=size, help='MemAvailable to leave free (default '
                        'max(4G, MemAvailable/8))')
    parser.add_argument('--counts-only', action='store_true')
    parser.add_argument('--prog-stats', action='store_true')
    parser.add_argument('--prog-prefix')
    parser.add_argument('--host-root', default='/', help='filesystem root (tests)')
    parser.add_argument('--out')
    args = parser.parse_args(argv)
    args.cmd = cmd
    try:
        args.size_list = expand_sizes(args.sizes, args.size_step)
        args.measure_list = measures(args.devices)
    except ValueError as e:
        parser.error(str(e))
    if bool(args.nvme_ng) != bool(args.nvme_window):
        parser.error('--nvme-ng and --nvme-window go together')
    if args.counts_only and args.plans == 'none':
        parser.error('--counts-only reports BPF plans; --plans none leaves nothing')
    if args.prog_stats and not cmd:
        parser.error('--prog-stats needs a workload after --')
    if not 1 <= args.reps <= 64:
        parser.error('--reps must be 1..64')
    return args


def command(args, binary, objects):
    argv = [str(binary)]
    if args.prog_stats:
        argv.append('--prog-stats')
        if args.prog_prefix:
            argv += ['--prog-prefix', args.prog_prefix]
        return argv + ['--'] + args.cmd
    if args.counts_only:
        argv.append('--counts-only')
    else:
        argv += ['--sizes', ','.join(map(str, args.size_list)), '--reps', str(args.reps),
                 '--frame-size', str(FRAME), '--measure', ','.join(args.measure_list)]
        if args.nvme_ng:
            argv += ['--nvme-ng', args.nvme_ng, '--nvme-window', args.nvme_window]
        if 'cuda' in args.measure_list:
            argv += ['--cuda-device', str(args.cuda_device)]
        if args.umem_cap:
            argv += ['--umem-cap', str(args.umem_cap)]
        if args.mem_margin:
            argv += ['--mem-margin', str(args.mem_margin)]
    for obj in objects:
        argv += ['--bpf-obj', str(obj)]
    return argv


def build(args, directory):
    make = ['make', '-s', '-C', str(HERE), 'BUILD=' + str(directory),
            str(Path(directory) / 'setup_cost')]
    if args.cuda_root and 'cuda' in args.measure_list:
        make.append('CUDA_ROOT=' + args.cuda_root)
    p = subprocess.run(make, capture_output=True, text=True)
    if p.returncode:
        sys.stderr.write(p.stderr)
        return None
    return Path(directory) / 'setup_cost'


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not args.counts_only and hypervisor(Path(args.host_root)):
        print('not_run: hypervisor detected; timed setup costs are physical-host only '
              '(use --counts-only)', file=sys.stderr)
        return 4
    try:
        objects = [] if args.prog_stats else plan_objects(args.plans, args.bpf_dir)
    except ValueError as e:
        print('not_run: ' + str(e), file=sys.stderr)
        return 4
    if args.counts_only and not objects:
        print('not_run: no BPF object under ' + args.bpf_dir, file=sys.stderr)
        return 4
    with tempfile.TemporaryDirectory(prefix='xdev-setup-cost-') as work:
        binary = build(args, work)
        if binary is None:
            print('not_run: setup_cost could not be built (libbpf development files?)',
                  file=sys.stderr)
            return 4
        done = subprocess.run(command(args, binary, objects), stdout=subprocess.PIPE,
                              text=True)
    try:
        document = json.loads(done.stdout) if done.stdout.strip() else None
    except json.JSONDecodeError:
        print('setup_cost printed malformed JSON', file=sys.stderr)
        return 1
    if document is not None:
        document['devices'] = args.devices
        text = json.dumps(document, indent=1)
        if args.out:
            Path(args.out).write_text(text + '\n')
        print(text)
    return done.returncode


if __name__ == '__main__':
    sys.exit(main())
