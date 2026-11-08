#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""fio O_DIRECT read ceiling of the NVMe used by E3 (plan TODO.68, control C1).

    fio_ceiling.py --file F --window-bytes N --sizes LIST --qd LIST
                   [--repeats R] [--engine io_uring|libaio] [--fill]
                   [--sweep [--sweep-repeats R]] [--drop-caches]
                   [--fio PATH] --out DIR [--dry-run]

Every cell reads the same window [0, N) of the same file the E3 arms read,
once per run, with the request size and queue depth of that E3 cell:
  fio --name=ceiling --filename=F --direct=1 --ioengine=io_uring --rw=read
      --bs=S --iodepth=Q --numjobs=1 --offset=0 --size=N --output-format=json
Repeats go round-robin over the grid, so drift (an SSD warming up) is spread
over all cells instead of landing on one.  --sweep additionally measures
4 MiB reads at iodepth 1..256 (powers of two), numjobs 1/2/4 (the window
split between the jobs: --size=N/J --offset_increment=N/J --group_reporting)
and engines io_uring/libaio, and reports the configuration with the highest
median bandwidth: the single best-fio number the plan writes in the text
(ServerlessLLM tried "various settings of FIO" the same way).

Reading unallocated blocks makes a ceiling too high, so the window must be
written: a file whose first N bytes contain a hole is refused, and --fill
first writes the window with fio (bs=4M, direct, end_fsync).  Block devices
are refused: the ceiling reads the same file as the arms.  The fio binary
must report fio-3.x.

Each run keeps fio's own JSON under DIR/raw; DIR/summary.json holds the fio
version, the exact argv of every run, io_bytes/bw_bytes/runtime per run and
the median per cell.  A run that read fewer than the window's bytes fails
the summary (short_read).  Nothing is tuned for the arms; the ceiling is a
grey reference line.  A run inside a virtual machine is recorded with
performance_claim none.

Exit: 0 every run complete, 1 a run failed or read short, 2 usage,
4 refused (fio missing or not fio-3.x, holes, window larger than the file).
"""
import argparse
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys

SCHEMA = 'xdev-eval-fio-ceiling-v1'
SWEEP_BS = 4 << 20
SWEEP_ENGINES = ('io_uring', 'libaio')
SWEEP_DEPTHS = tuple(1 << i for i in range(9))	# 1..256
SWEEP_JOBS = (1, 2, 4)
_VERSION = re.compile(r'^fio-3\.[0-9]+')


class Refused(RuntimeError):
    pass


def check_version(text):
    text = text.strip()
    if not _VERSION.match(text):
        raise Refused(f'expected fio-3.x, the binary reports {text!r}')
    return text.split()[0]


def read_totals(doc):
    jobs = doc.get('jobs') or []
    reads = [j['read'] for j in jobs]
    pct = (reads[0].get('clat_ns') or {}).get('percentile') or {} if len(reads) == 1 else {}
    return dict(io_bytes=sum(r['io_bytes'] for r in reads),
                bw_bytes=sum(r['bw_bytes'] for r in reads),
                runtime_ms=max((r['runtime'] for r in reads), default=0),
                clat_p50_ns=pct.get('50.000000'), clat_p99_ns=pct.get('99.000000'))


def sweep_grid():
    return [(e, d, j) for e in SWEEP_ENGINES for d in SWEEP_DEPTHS for j in SWEEP_JOBS]


def hypervisor():
    if Path('/sys/hypervisor/type').exists():
        return True
    try:
        return any('hypervisor' in l.split() for l in Path('/proc/cpuinfo').read_text().splitlines()
                   if l.startswith('flags'))
    except OSError:
        return False


def check_window(path, window):
    st = os.stat(path)
    if not os.path.isfile(path):
        raise Refused(f'{path} is not a regular file (the ceiling reads the arms\' file)')
    if st.st_size < window:
        raise Refused(f'window {window} exceeds the file size {st.st_size}')
    with open(path, 'rb') as f:
        hole = os.lseek(f.fileno(), 0, os.SEEK_HOLE)
    if hole < window or st.st_blocks * 512 < window:
        raise Refused(f'{path} has a hole inside the window (first hole at {hole}); '
                      'write it first (--fill)')


def job(args, name, bs, depth, jobs, engine, raw, rw='read'):
    size = args.window_bytes // jobs
    argv = [args.fio, f'--name={name}', f'--filename={args.file}', '--direct=1',
            f'--ioengine={engine}', f'--rw={rw}', f'--bs={bs}', f'--iodepth={depth}',
            f'--numjobs={jobs}', '--offset=0', f'--size={size}']
    if jobs > 1:
        argv += [f'--offset_increment={size}', '--group_reporting']
    if rw == 'write':
        argv += ['--end_fsync=1']
    return argv + ['--output-format=json', f'--output={raw}']


def plan(args):
    runs = []
    for rep in range(args.repeats):
        for size in args.sizes:
            for qd in args.qd:
                runs.append(dict(kind='cell', bs=size, iodepth=qd, numjobs=1,
                                 engine=args.engine, repeat=rep,
                                 raw=f'raw/cell-bs{size}-qd{qd}-r{rep}.json'))
    if args.sweep:
        for rep in range(args.sweep_repeats):
            for engine, depth, jobs in sweep_grid():
                runs.append(dict(kind='sweep', bs=SWEEP_BS, iodepth=depth, numjobs=jobs,
                                 engine=engine, repeat=rep,
                                 raw=f'raw/sweep-{engine}-qd{depth}-j{jobs}-r{rep}.json'))
    for r in runs:
        r['argv'] = job(args, 'ceiling', r['bs'], r['iodepth'], r['numjobs'], r['engine'],
                        Path(args.out) / r['raw'])
    return runs


def drop_caches():
    subprocess.run(['sync'], check=True)
    Path('/proc/sys/vm/drop_caches').write_text('3\n')


def summarize(runs, key):
    cells = {}
    for r in runs:
        cells.setdefault(tuple(r[k] for k in key), []).append(r)
    out = []
    for k, rs in cells.items():
        bws = [r['bw_bytes'] for r in rs if r.get('ok')]
        out.append(dict(zip(key, k), repeats=len(rs),
                        median_bw_bytes=statistics.median(bws) if bws else None,
                        min_bw_bytes=min(bws) if bws else None,
                        max_bw_bytes=max(bws) if bws else None))
    return out


def execute(args):
    version = subprocess.run([args.fio, '--version'], capture_output=True, text=True)
    fio_version = check_version(version.stdout)
    check_window(args.file, args.window_bytes) if not args.fill else None
    out = Path(args.out)
    (out / 'raw').mkdir(parents=True, exist_ok=False)
    fill = None
    if args.fill:
        raw = out / 'raw/fill.json'
        argv = job(args, 'fill', SWEEP_BS, 1, 1, args.engine, raw, rw='write')
        r = subprocess.run(argv)
        if r.returncode:
            raise Refused(f'fill failed with exit {r.returncode}')
        fill = dict(argv=[str(a) for a in argv], raw='raw/fill.json')
        check_window(args.file, args.window_bytes)
    runs = plan(args)
    for r in runs:
        if args.drop_caches:
            drop_caches()
        res = subprocess.run([str(a) for a in r['argv']])
        r['argv'] = [str(a) for a in r['argv']]
        r['exit'] = res.returncode
        if res.returncode:
            r['ok'] = False
            continue
        r.update(read_totals(json.loads((out / r['raw']).read_text())))
        expected = (args.window_bytes // r['numjobs']) * r['numjobs']
        r['ok'] = r['io_bytes'] == expected
        r['short_read'] = r['io_bytes'] < expected
    cells = summarize([r for r in runs if r['kind'] == 'cell'], ('bs', 'iodepth', 'engine'))
    sweep = None
    if args.sweep:
        configs = summarize([r for r in runs if r['kind'] == 'sweep'],
                            ('engine', 'iodepth', 'numjobs'))
        best = max((c for c in configs if c['median_bw_bytes'] is not None),
                   key=lambda c: c['median_bw_bytes'], default=None)
        sweep = dict(bs=SWEEP_BS, configs=configs, best=best)
    if any(r.get('short_read') for r in runs):
        verdict = 'short_read'
    elif not all(r['ok'] for r in runs):
        verdict = 'run_failed'
    else:
        verdict = 'ok'
    vm = hypervisor()
    summary = dict(schema=SCHEMA, verdict=verdict, fio_version=fio_version,
                   file=str(args.file), window_bytes=args.window_bytes,
                   engine=args.engine, filled_by_tool=bool(args.fill), fill=fill,
                   drop_caches=args.drop_caches, execution='vm' if vm else 'bare-metal',
                   performance_claim='none' if vm else 'fio-read-ceiling',
                   runs=[{k: v for k, v in r.items()} for r in runs], cells=cells, sweep=sweep)
    (out / 'summary.json').write_text(json.dumps(summary, indent=1) + '\n')
    return 0 if verdict == 'ok' else 1


def int_list(text):
    values = [int(v) for v in text.split(',') if v]
    if not values or any(v <= 0 for v in values):
        raise argparse.ArgumentTypeError('positive integers separated by commas')
    return values


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--file', required=True)
    p.add_argument('--window-bytes', type=int, required=True)
    p.add_argument('--sizes', type=int_list, required=True)
    p.add_argument('--qd', type=int_list, required=True)
    p.add_argument('--repeats', type=int, default=5)
    p.add_argument('--engine', choices=SWEEP_ENGINES, default='io_uring')
    p.add_argument('--fill', action='store_true')
    p.add_argument('--sweep', action='store_true')
    p.add_argument('--sweep-repeats', type=int, default=3)
    p.add_argument('--drop-caches', action='store_true')
    p.add_argument('--fio', default='fio')
    p.add_argument('--out', required=True)
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args(argv)
    if args.window_bytes <= 0 or args.repeats <= 0 or args.sweep_repeats <= 0:
        p.error('--window-bytes, --repeats and --sweep-repeats must be positive')
    if any(args.window_bytes % s for s in args.sizes) or (args.sweep and args.window_bytes % (4 * SWEEP_BS)):
        p.error('the window must be a multiple of every size (and of 16 MiB with --sweep)')
    return args


def main(argv=None):
    args = parse(argv)
    if args.dry_run:
        print(json.dumps(dict(dry_run=True, commands=[[str(a) for a in r['argv']]
                                                      for r in plan(args)])))
        return 0
    try:
        return execute(args)
    except (Refused, OSError, FileNotFoundError) as error:
        print(f'fio_ceiling: refused: {error}', file=sys.stderr)
        return 4


if __name__ == '__main__':
    sys.exit(main())
