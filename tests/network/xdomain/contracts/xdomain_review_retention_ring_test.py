#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real ring glue + actual built-in ledger; native DMA stays an OS boundary."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import sys
from xdomain_review_lifecycle_test import ring_unit,HERE
NAMES=['healthy_reservation_until_real_free','unknown_exact_bytes_survive_new_link','partial_start_descriptor_only_unknown','actual_requester_hop_capacity_bound','actual_shared_64MiB_bound']
def main():
    p=argparse.ArgumentParser();p.add_argument('--kernel',type=Path,default=HERE.parents[4]);p.add_argument('--keep-build',type=Path);a=p.parse_args()
    unit=ring_unit(a.kernel.resolve());old=(HERE/'xdomain_review_lifecycle_ring_cases.c').read_text()
    assert unit.endswith(old)
    unit=unit[:-len(old)]+old[:old.index('int main(int argc')]+(HERE/'xdomain_review_retention_ring_cases.c').read_text()
    with tempfile.TemporaryDirectory(prefix='xdomain-retention-ring-') as temp:
        c=Path(temp)/'joint.c';b=Path(temp)/'joint';c.write_text(unit)
        if a.keep_build:a.keep_build.mkdir(parents=True,exist_ok=True);(a.keep_build/'joint-unit.c').write_text(unit)
        build=subprocess.run(['gcc','-std=gnu11','-O0','-g','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-Werror=implicit-function-declaration','-pthread','-I',str(a.kernel.resolve()),str(c),'-o',str(b)],capture_output=True,text=True,timeout=60)
        if build.returncode:print('# SETUP_COMPILE_ERROR; no behavior verdict\n'+build.stdout+build.stderr);return 2
        print('TAP version 13\n1..5',flush=True);failed=False
        for i,name in enumerate(NAMES,1):
            run=subprocess.run([str(b),str(i)],capture_output=True,text=True,timeout=20)
            print(run.stdout+run.stderr,end='');ok=run.returncode==0;failed|=not ok
            print(('ok ' if ok else 'not ok ')+str(i)+' - '+name,flush=True)
        return int(failed)
if __name__=='__main__':sys.exit(main())
