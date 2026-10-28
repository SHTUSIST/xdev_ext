#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production ring CRC input -> production read-only stats counter."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from xdomain_review_lifecycle_test import ring_unit
HERE=Path(__file__).resolve().parent
def stats_show(text):
    match=re.search(r'(?m)^static ssize_t xdev_ext_link_stats_show\(',text)
    if not match:
        return 'struct device_attribute;\nstatic ssize_t (*review_stats_show)(struct device *,struct device_attribute *,char *) = NULL;\n'
    begin=text.index('{',match.start());depth=1;end=begin+1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return 'struct device_attribute;\n'+text[match.start():end]+'\nstatic ssize_t (*review_stats_show)(struct device *,struct device_attribute *,char *) = xdev_ext_link_stats_show;\n'
def main():
    p=argparse.ArgumentParser();p.add_argument('--kernel',type=Path,default=HERE.parents[4]);p.add_argument('--keep-build',type=Path);a=p.parse_args();k=a.kernel.resolve()
    unit=ring_unit(k);cases=(HERE/'xdomain_review_lifecycle_ring_cases.c').read_text()
    assert unit.endswith(cases);cases=cases[:cases.index('int main(int argc')]
    diag=(HERE/'xdomain_review_stats_ring_cases.c').read_text().replace('/* @PRODUCTION_STATS_SHOW@ */',stats_show((k/'io_uring/xdomain/xdev_ext_xdomain_main.c').read_text()))
    unit=unit[:-len((HERE/'xdomain_review_lifecycle_ring_cases.c').read_text())]+cases+diag
    with tempfile.TemporaryDirectory(prefix='xdomain-review-crc-stats-') as temp:
        src=Path(temp)/'crc.c';binary=Path(temp)/'crc';src.write_text(unit)
        if a.keep_build:a.keep_build.mkdir(parents=True,exist_ok=True);(a.keep_build/'crc-stats-unit.c').write_text(unit)
        build=subprocess.run(['gcc','-std=gnu11','-O0','-g','-Wno-unused-function','-Werror=implicit-function-declaration','-pthread','-I',str(k),str(src),'-o',str(binary)],capture_output=True,text=True,timeout=60)
        if build.returncode:print('# SETUP_COMPILE_ERROR; not behavioral RED\n'+build.stdout+build.stderr);return 2
        print('TAP version 13\n1..1',flush=True);run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=8)
        print(run.stdout+run.stderr,end='');print(('ok' if run.returncode==0 else 'not ok')+' 1 - actual_ring_crc_error_observable_in_public_stats')
        return int(run.returncode!=0)
if __name__=='__main__':sys.exit(main())
