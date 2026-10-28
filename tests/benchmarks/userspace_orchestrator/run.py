#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""User-space shared-region baseline campaigns (reviewer E2).

  run.py --rig RIG.json --chain nvme-nic,nvme-gpu-nic --wait poll,eventfd \\
         --depth 1..64 --sizes 4096..4194304 [--with-session]

A thin front end of ../chains/run.py with arm "userspace-shared" (uo_bench)
and, with --with-session, the session arm on the same cases, so each record
size and depth has both.  --depth takes a power-of-two list or range; the
first value is the base, the rest form a depth sweep.  The same hardware
admission, pairing, oracle and exit codes apply.  --loc prints the
application lines of code each arm needs and exits.
"""
import argparse
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'chains'))
import run as chains  # noqa: E402

# The code an application writes for each arm: this baseline's whole data
# path, and the session arm's configure/START/wait/teardown.
LOC_FILES = {
    'userspace-shared': [HERE / 'uo_bench.c', HERE / 'uo_core.h', HERE.parent / 'chains/chain_nxp.h',
                         HERE.parent / 'chains/uring_min.h'],
    'session': [HERE.parent / 'chains/chain_session.c'],
}


def code_lines(path):
    """Lines that are neither blank nor only comment text."""
    count, block = 0, False
    for line in Path(path).read_text().splitlines():
        text = line.strip()
        if block:
            if '*/' not in text:
                continue
            block = False
            text = text.split('*/', 1)[1].strip()
        while text.startswith('/*'):
            if '*/' not in text:
                block = True
                text = ''
                break
            text = text.split('*/', 1)[1].strip()
        if text and not text.startswith('//'):
            count += 1
    return count


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0], allow_abbrev=False)
    p.add_argument('--cpu-set')
    p.add_argument('--cpu-output')
    p.add_argument('--rig')
    p.add_argument('--chain', default='nvme-nic')
    p.add_argument('--wait', default='poll,eventfd')
    p.add_argument('--depth', default='8')
    p.add_argument('--sizes', default='4096')
    p.add_argument('--with-session', action='store_true')
    p.add_argument('--loc', action='store_true')
    a, rest = p.parse_known_args(argv)
    if a.loc:
        return a, None
    if not a.rig:
        raise chains.Usage('--rig is required')
    if not re.fullmatch(r'[0-9KMG.,]+', a.depth):
        raise chains.Usage('--depth: a power-of-two list or range')
    depths = chains.powers(a.depth)
    arms = 'userspace-shared' + (',session' if a.with_session else '')
    out = ['--rig', a.rig, '--chain', a.chain, '--wait', a.wait, '--sizes', a.sizes,
           '--arms', arms, '--depth', str(depths[0]), *rest]
    if a.cpu_set is not None:
        out += ['--cpu-set', a.cpu_set]
    if a.cpu_output is not None:
        out += ['--cpu-output', a.cpu_output]
    if len(depths) > 1:
        out += ['--sweep', 'qd=' + ','.join(str(d) for d in depths[1:])]
    return a, out


def main(argv):
    try:
        a, forwarded = parse(argv)
    except chains.Usage as error:
        print('run.py: %s' % error, file=sys.stderr)
        return chains.EXIT_USAGE
    if a.loc:
        for arm, files in LOC_FILES.items():
            print('%s %d %s' % (arm, sum(code_lines(f) for f in files),
                                ' '.join(f.name for f in files)))
        return chains.EXIT_PASS
    return chains.main(forwarded)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
