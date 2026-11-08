#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mutants of the XDOMAIN RX -> CE TARGET_RANGE admission row.

Copies the current canonical sources once through the layout reader, then for
each mutant rewrites only xdev_ext_family_core.h in that private view,
recompiles stage1.c and class_table_diff_test.c and runs their checks. A
mutant is killed only by a compiled assertion failure (exit 1); a compile
error or another exit is SETUP (2). The unmutated control must pass first.
"""
import argparse
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

HEADER = 'include/linux/xdev_ext_family_core.h'
FILL = ('\t\treturn (cap & XDEV_EXT_CE_RANGE_FILLS_BEFORE) &&\n'
        '\t\t       u->direction == XDEV_EXT_MECH_DIR_TO_DEVICE &&\n'
        '\t\t       peer->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&\n'
        '\t\t       (!(cap & XDEV_EXT_CE_RANGE_FILL_UMEM_ONLY) ||\n'
        '\t\t\tc->pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM) ? 0 : -EOPNOTSUPP;\n')
# ASK.91: the row is the partner capability, read by the CE range rule.
BRANCH = FILL
XDOMAIN_CAP = ('\t\t.ce_range_partner = XDEV_EXT_CE_RANGE_FILLS_BEFORE | '
               'XDEV_EXT_CE_RANGE_FILL_UMEM_ONLY,\n')
MUTANTS = (
    ('no-pool-rule', ' &&\n\t\t       (!(cap & XDEV_EXT_CE_RANGE_FILL_UMEM_ONLY) ||\n'
     '\t\t\tc->pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM) ?', ' ?'),
    ('no-ce-direction', '\t\t       u->direction == XDEV_EXT_MECH_DIR_TO_DEVICE &&\n',
     '\t\t       1 &&\n'),
    ('no-xdomain-direction',
     '\t\t       peer->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&\n',
     '\t\t       1 &&\n'),
    ('ce-any-position', '\tif (i == 1)\n\t\treturn (cap', '\tif (1)\n\t\treturn (cap'),
    ('any-non-nvme-partner', '\t\treturn (cap & XDEV_EXT_CE_RANGE_FILLS_BEFORE) &&',
     '\t\treturn 1 &&'),
    ('xdomain-always-admitted', FILL, '\t\treturn 0;\n'),
    ('xdomain-row-removed', XDOMAIN_CAP, ''),
    ('nvme-row-removed',
     '\t\t.ce_range_partner = XDEV_EXT_CE_RANGE_FILLS_BEFORE | '
     'XDEV_EXT_CE_RANGE_DRAINS_AFTER,\n', ''),
)


def canonical_root():
    for parent in Path(__file__).resolve().parents:
        if (parent / 'source-layout.json').is_file():
            return parent
    raise SystemExit('SETUP: no canonical source root')


def run(argv, log):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=120)
    log.write('$ ' + shlex.join(argv) + '\n' + result.stdout)
    log.flush()
    return result.returncode


def assess(root, view, out, name, cc, log):
    flags = ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(view / 'kernel')]
    stage1, table = out / (name + '-stage1'), out / (name + '-table')
    sources = ((root / 'tests/compute/ce/random_target/stage1.c', stage1),
               (root / 'tests/core/family/class_table_diff_test.c', table))
    for source, binary in sources:
        if run(cc + flags + [str(source), '-o', str(binary)], log):
            return 'setup'
    codes = [run([str(stage1), cohort], log)
             for cohort in ('controls', 'flags', 'topology', 'xdomain')]
    codes.append(run([str(table)], log))
    if any(code not in (0, 1) for code in codes):
        return 'setup'
    return 'failed' if any(codes) else 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='new evidence directory')
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    root = canonical_root()
    if args.output:
        out = args.output.absolute()
        out.mkdir(parents=True, exist_ok=False)
    else:
        parent = root / 'build/ce-random-xdomain-mutants'
        parent.mkdir(parents=True, exist_ok=True)
        out = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    print('BUILD ' + str(out), flush=True)
    sys.path.insert(0, str(root / 'tools'))
    from layout import materialize_view
    view = materialize_view(root, out / 'view').root
    header = view / 'kernel' / HEADER
    original = header.read_text()
    if original.count(BRANCH) != 1:
        print('SETUP: XDOMAIN range row not found once in ' + str(header))
        return 2
    cc = shlex.split(args.cc)
    verdicts = {}
    with (out / 'mutants.log').open('w') as log:
        verdicts['control'] = assess(root, view, out, 'control', cc, log)
        if verdicts['control'] != 'passed':
            print('SETUP: unmutated control ' + verdicts['control'])
            return 2
        for name, old, new in MUTANTS:
            if original.count(old) != 1:
                print('SETUP: mutant target not unique: ' + name)
                return 2
            header.write_text(original.replace(old, new, 1))
            try:
                verdicts[name] = assess(root, view, out, name, cc, log)
            finally:
                header.write_text(original)
            if verdicts[name] == 'setup':
                print('SETUP: mutant did not compile or report: ' + name)
                return 2
    (out / 'verdicts.json').write_text(json.dumps(verdicts, indent=2) + '\n')
    survivors = [name for name, _, _ in MUTANTS if verdicts[name] != 'failed']
    for name, _, _ in MUTANTS:
        print('XDOMAIN_CE_MUTANT name=%s verdict=%s' % (
            name, 'killed' if verdicts[name] == 'failed' else 'SURVIVED'))
    print('XDOMAIN_CE_MUTANTS=%s killed=%d total=%d' % (
        'PASS' if not survivors else 'FAIL', len(MUTANTS) - len(survivors), len(MUTANTS)))
    return 0 if not survivors else 1


if __name__ == '__main__':
    raise SystemExit(main())
