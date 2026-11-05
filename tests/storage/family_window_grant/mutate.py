#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Each grant-rule mutant must make test_window_grant.c fail (prototype for ASK.69).

mutate.py SOURCE_ROOT OUTPUT_DIR. A mutant whose anchor is not found exactly
once, or that does not compile, is SETUP (exit 2), never a kill.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HEADER = 'src/storage/include/linux/xdev_ext_storfam_core.h'
MUTANTS = [
    # (name, exact anchor in the header, replacement); parameters stay used so
    # every mutant compiles with -Werror.
    ('admit-no-direction',
     '\tif (!(grant->access & (write ?', '\tif (0 && !(grant->access & (write ?'),
    ('admit-no-range',
     '\tif (xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))',
     '\tif (0 && xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))'),
    ('admit-one-past-end',
     'xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb)',
     'xdev_ext_stor_window_check(grant->slba, grant->nlb + 1, slba, nlb)'),
    ('admit-range-before-direction',
     '\tif (!(grant->access & (write ? XDEV_EXT_STOR_GRANT_WRITE :\n'
     '\t\t\t\t       XDEV_EXT_STOR_GRANT_READ)))\n\t\treturn -EBADF;\n'
     '\tif (xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))\n\t\treturn -EACCES;\n',
     '\tif (xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))\n\t\treturn -EACCES;\n'
     '\tif (!(grant->access & (write ? XDEV_EXT_STOR_GRANT_WRITE :\n'
     '\t\t\t\t       XDEV_EXT_STOR_GRANT_READ)))\n\t\treturn -EBADF;\n'),
    ('conflict-read-read',
     '\tif (!((a->access | b->access) & XDEV_EXT_STOR_GRANT_WRITE))\n\t\treturn false;\n', ''),
    ('conflict-both-must-write',
     '(a->access | b->access) & XDEV_EXT_STOR_GRANT_WRITE',
     '(a->access & b->access) & XDEV_EXT_STOR_GRANT_WRITE'),
    ('conflict-adjacent-counts',
     '\t\treturn a->slba - b->slba < b->nlb;', '\t\treturn a->slba - b->slba <= b->nlb;'),
    ('conflict-one-order',
     '\treturn b->slba - a->slba < a->nlb;\n}', '\treturn false && a->nlb;\n}'),
    ('make-no-capacity',
     '\tif (slba > capacity_lbas || nlb > capacity_lbas - slba)\n\t\treturn -ERANGE;\n'
     '\t*out = (struct xdev_ext_stor_grant)',
     '\tif (0 && (slba > capacity_lbas || nlb > capacity_lbas - slba))\n\t\treturn -ERANGE;\n'
     '\t*out = (struct xdev_ext_stor_grant)'),
    ('make-empty-allowed',
     'XDEV_EXT_STOR_GRANT_WRITE)))\n\t\treturn -EINVAL;\n\tif (!nlb)',
     'XDEV_EXT_STOR_GRANT_WRITE)))\n\t\treturn -EINVAL;\n\tif (0 && !nlb)'),
    ('make-unknown-bits',
     '\t    (access & ~(XDEV_EXT_STOR_GRANT_READ | XDEV_EXT_STOR_GRANT_WRITE)))',
     '\t    0)'),
    ('make-publish-first',
     'XDEV_EXT_STOR_GRANT_WRITE)))\n\t\treturn -EINVAL;\n\tif (!nlb)',
     'XDEV_EXT_STOR_GRANT_WRITE)))\n\t\treturn -EINVAL;\n'
     '\t*out = (struct xdev_ext_stor_grant) { .slba = slba, .nlb = nlb, .access = access, };\n'
     '\tif (!nlb)'),
]


def main():
    root = Path(sys.argv[1]).resolve()
    out = Path(sys.argv[2]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    test = root / 'tests/storage/family_window_grant/test_window_grant.c'
    original = (root / HEADER).read_text()
    results, rc = [], 0
    for name, old, new in MUTANTS:
        record = {'mutant': name}
        if original.count(old) != 1:
            record['verdict'] = 'SETUP anchor count %d' % original.count(old)
            results.append(record)
            rc = 2
            continue
        work = out / name
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir()
        (work / 'xdev_ext_storfam_core.h').write_text(original.replace(old, new, 1))
        build = subprocess.run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                                '-I' + str(work), str(test), '-o', str(work / 'probe')],
                               capture_output=True, text=True)
        if build.returncode:
            record['verdict'] = 'SETUP compile'
            record['compile'] = build.stderr[-2000:]
            results.append(record)
            rc = 2
            continue
        run = subprocess.run([str(work / 'probe')], capture_output=True, text=True)
        failed = [line for line in run.stderr.splitlines() if line.startswith('FAIL ')]
        record['exit'] = run.returncode
        record['first_failures'] = failed[:3]
        record['verdict'] = 'DETECTED' if run.returncode == 1 and failed else 'SURVIVED'
        if record['verdict'] != 'DETECTED':
            rc = rc or 1
        results.append(record)
        (work / 'probe').unlink()
        print(record['verdict'], name, failed[:1])
    (out / 'mutants.json').write_text(json.dumps(results, indent=2) + '\n')
    detected = sum(r['verdict'] == 'DETECTED' for r in results)
    print('%s window-grant mutants detected=%d of %d' %
          ('PASS' if detected == len(MUTANTS) else 'FAIL', detected, len(MUTANTS)))
    return rc


if __name__ == '__main__':
    sys.exit(main())
