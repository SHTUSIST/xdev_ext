#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Rank-local E4 runner: the same arms on both hosts, alternated per pair.

    run.py --rank 0|1 --addr HOST:PORT --arms tcp-cuda,nccl,xdev-ext
           [--mode pingpong|stream] [--pairs N] --bin-dir DIR --out DIR
           [--link-check 'LINK_CHECK ARGS'] [--xdev-args 'ARGS']
           [--dry-run] [-- ARGS FOR EVERY TOOL]

Start it on both hosts with the same options (rank 0 connects to ADDR,
rank 1 listens on it).  Pair k runs every arm once, in an order rotated by
k, so a drifting link or GPU clock is spread over the arms; both ranks
derive the same order and meet in each tool's own connection.  Arms:
  tcp-cuda  tcp_cuda      (TCP over thunderbolt-net + cudaMemcpy)
  nccl      nccl_pingpong (ncclSend/ncclRecv; ping-pong only, its bandwidth
                           comes from nccl_tests.py running sendrecv_perf)
  xdev-ext  xdomain_gpu   (our XDOMAIN session with host frames and the CE)
With --link-check, every tool runs under tools/analysis/link_check.py (or
tests/eval/common/link_check.py in the source view) with those arguments,
so the link is sampled while the arm runs and a degraded link fails it.
Each step keeps the tool's JSON lines under DIR/raw and the link record
under DIR/link; DIR/runs.json lists every step with its exit status.
Nothing is tuned; arguments after -- go to every tool unchanged.

Exit: 0 every step passed, 1 a step failed, 2 usage.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys

SCHEMA = 'xdev-eval-e4-runs-v1'
TOOLS = {'tcp-cuda': 'tcp_cuda', 'nccl': 'nccl_pingpong', 'xdev-ext': 'xdomain_gpu'}
HERE = Path(__file__).resolve().parent


def link_check_path():
    for candidate in (HERE.parents[2] / 'tools/analysis/link_check.py',
                      HERE.parent / 'common/link_check.py'):
        if candidate.is_file():
            return candidate
    return None


def steps(args):
    out = []
    for pair in range(args.pairs):
        k = pair % len(args.arms)
        for arm in args.arms[k:] + args.arms[:k]:
            tool = str(Path(args.bin_dir) / TOOLS[arm])
            argv = [tool, '--rank', str(args.rank),
                    '--peer' if args.rank == 0 else '--listen', args.addr]
            if arm != 'nccl':
                argv += ['--mode', args.mode]
            if arm == 'xdev-ext':
                argv += shlex.split(args.xdev_args)
            argv += args.tool_args
            step = dict(pair=pair, arm=arm, argv=argv,
                        raw=f'raw/p{pair}-{arm}-rank{args.rank}.jsonl')
            if arm == 'nccl' and args.mode == 'stream':
                step['not_run'] = 'nccl bandwidth comes from nccl_tests.py (sendrecv_perf)'
            out.append(step)
    return out


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--rank', type=int, choices=(0, 1), required=True)
    p.add_argument('--addr', required=True)
    p.add_argument('--arms', required=True)
    p.add_argument('--mode', choices=('pingpong', 'stream'), default='pingpong')
    p.add_argument('--pairs', type=int, default=5)
    p.add_argument('--bin-dir', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--link-check', default='')
    p.add_argument('--xdev-args', default='')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('tool_args', nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    if args.tool_args[:1] == ['--']:
        args.tool_args = args.tool_args[1:]
    args.arms = [a for a in args.arms.split(',') if a]
    if not args.arms or any(a not in TOOLS for a in args.arms) or len(set(args.arms)) != len(args.arms):
        p.error(f'--arms is a list of {",".join(TOOLS)}')
    if args.pairs <= 0:
        p.error('--pairs must be positive')
    plan = steps(args)
    if args.dry_run:
        print(json.dumps(dict(dry_run=True, rank=args.rank, steps=plan)))
        return 0
    out = Path(args.out)
    (out / 'raw').mkdir(parents=True, exist_ok=False)
    (out / 'link').mkdir()
    checker = link_check_path() if args.link_check else None
    if args.link_check and not checker:
        print('run.py: link_check.py not found', file=sys.stderr)
        return 2
    failed = False
    for step in plan:
        if 'not_run' in step:
            continue
        argv = step['argv']
        if checker:
            step['link'] = f'link/p{step["pair"]}-{step["arm"]}-rank{args.rank}.json'
            argv = [sys.executable, str(checker), *shlex.split(args.link_check),
                    '--out', str(out / step['link']), '--', *argv]
        with open(out / step['raw'], 'w') as raw:
            r = subprocess.run(argv, stdout=raw)
        step['exit'] = r.returncode
        failed = failed or r.returncode != 0
        (out / 'runs.json').write_text(json.dumps(dict(schema=SCHEMA, rank=args.rank,
                                                       mode=args.mode, steps=plan), indent=1) + '\n')
    (out / 'runs.json').write_text(json.dumps(dict(schema=SCHEMA, rank=args.rank, mode=args.mode,
                                                   steps=plan), indent=1) + '\n')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
