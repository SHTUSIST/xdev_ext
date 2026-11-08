#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host test: four tenants sharing one NVMe namespace through window handles.

host_tenant_matrix_test.py [SOURCE_ROOT]. Compiles host_tenant_matrix.c
against the unmodified product headers under gcc and UBSan and requires a
PASS, then requires every listed mutant of those headers (registry conflict,
bind admission, per-descriptor window and owned-field checks) to make the
matrix fail. A mutant whose anchor is not found exactly once, or that does not
compile, is SETUP (exit 2), never a kill. No devices, no DMA.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parents[3]
FIXTURE = HERE / 'host_tenant_matrix.c'
STORFAM = 'src/storage/include/linux/xdev_ext_storfam_core.h'
PASSTHRU = 'src/storage/include/linux/nvme_xdev_ext_passthru.h'

MUTANTS = [
    # (name, header, exact anchor, replacement); every mutant keeps -Werror happy.
    ('descriptor-window-is-whole-namespace', PASSTHRU,
     '.slba = bounds->window_slba, .nlb = bounds->window_nlb,',
     '.slba = 0 * bounds->window_slba, .nlb = bounds->capacity_lbas + 0 * bounds->window_nlb,'),
    ('descriptor-skips-window-check', STORFAM,
     'ret = xdev_ext_stor_window_check(window->slba, window->nlb, slba, nlb);',
     'ret = 0 * xdev_ext_stor_window_check(window->slba, window->nlb, slba, nlb);'),
    ('window-end-one-lba-more', STORFAM,
     'if (offset >= window_nlb || nlb > window_nlb - offset)',
     'if (offset >= window_nlb || nlb > window_nlb - offset + 1)'),
    ('descriptor-nsid-writable', PASSTHRU,
     '[0] = 0xffU, [10] = ~(__u32)0,', '[0] = 0xffU, [1] = ~(__u32)0, [10] = ~(__u32)0,'),
    ('descriptor-dptr-writable', PASSTHRU,
     '[0] = 0xffU, [10] = ~(__u32)0,', '[0] = 0xffU, [6] = ~(__u32)0, [10] = ~(__u32)0,'),
    ('descriptor-flags-writable', PASSTHRU,
     '[0] = 0xffU, [10] = ~(__u32)0,', '[0] = 0xffffU, [10] = ~(__u32)0,'),
    ('registry-adjacent-conflicts', STORFAM,
     '\t\treturn a->slba - b->slba < b->nlb;', '\t\treturn a->slba - b->slba <= b->nlb;'),
    ('registry-reader-ignores-writer', STORFAM,
     '(a->access | b->access) & XDEV_EXT_STOR_GRANT_WRITE',
     '(a->access & b->access) & XDEV_EXT_STOR_GRANT_WRITE'),
    ('registry-read-overlap-conflicts', STORFAM,
     '\tif (!((a->access | b->access) & XDEV_EXT_STOR_GRANT_WRITE))\n\t\treturn false;\n', ''),
    ('bind-ignores-direction', STORFAM,
     '\tif (!(grant->access & (write ?', '\tif (0 && !(grant->access & (write ?'),
    ('bind-ignores-range', STORFAM,
     '\tif (xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))\n\t\treturn -EACCES;',
     '\tif (0 && xdev_ext_stor_window_check(grant->slba, grant->nlb, slba, nlb))\n\t\treturn -EACCES;'),
]


def build_and_run(include_root, out, profile):
    flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror']
    if profile == 'ubsan':
        flags += ['-fsanitize=undefined', '-fno-sanitize-recover=all']
    binary = out / profile
    compile_cmd = ['gcc', *flags, '-I', str(include_root / 'src/storage/include/linux'),
                   '-I', str(include_root / 'src/core/include/linux'), str(FIXTURE), '-o', str(binary)]
    built = subprocess.run(compile_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if built.returncode:
        return None, built.stdout
    ran = subprocess.run([str(binary)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=120)
    return ran.returncode, ran.stdout


def copy_headers(dest):
    for part in ('src/storage/include', 'src/core/include'):
        shutil.copytree(ROOT / part, dest / part)


def main():
    with tempfile.TemporaryDirectory(prefix='tenant-matrix-') as tmp:
        tmp = Path(tmp)
        for profile in ('gcc', 'ubsan'):
            rc, log = build_and_run(ROOT, tmp, profile)
            if rc is None:
                print(log)
                print('SETUP baseline %s does not compile' % profile)
                return 2
            last = log.strip().splitlines()[-1] if log.strip() else ''
            print('baseline %s: %s' % (profile, last))
            if rc or not last.startswith('PASS tenant matrix:'):
                print(log)
                print('FAIL baseline %s' % profile)
                return 1
        survivors = []
        for name, header, anchor, replacement in MUTANTS:
            work = tmp / ('mutant-' + name)
            copy_headers(work)
            path = work / header
            text = path.read_text()
            if text.count(anchor) != 1:
                print('SETUP mutant %s: anchor found %d times' % (name, text.count(anchor)))
                return 2
            path.write_text(text.replace(anchor, replacement))
            rc, log = build_and_run(work, work, 'gcc')
            if rc is None:
                print(log)
                print('SETUP mutant %s does not compile' % name)
                return 2
            killed = rc != 0
            first = next((line for line in log.splitlines() if line.startswith('FAIL ')), '')
            print('mutant %-40s %s %s' % (name, 'killed' if killed else 'SURVIVED', first[:120]))
            if not killed:
                survivors.append(name)
        if survivors:
            print('FAIL surviving mutants: %s' % ', '.join(survivors))
            return 1
        print('PASS host tenant matrix: baseline gcc+ubsan, %d/%d mutants killed'
              % (len(MUTANTS), len(MUTANTS)))
        return 0


if __name__ == '__main__':
    sys.exit(main())
