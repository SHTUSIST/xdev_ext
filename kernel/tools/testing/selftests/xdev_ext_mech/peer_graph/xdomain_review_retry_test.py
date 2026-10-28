#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent setup-retry/public-diagnostic contract; unchanged production main."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
from xdomain_ring_test import no_includes
from xdomain_retention_fixture import retention_unit
HERE=Path(__file__).resolve().parent
NAMES=['setup_failure_exponential_backoff_caps_60s','changing_candidates_cannot_reset_failure_budget','candidate_cannot_bypass_cooldown','public_readonly_stats_schema_keeps_old_state','stats_count_real_login_version_setup_errors','stats_count_actual_up_once_and_truthful_e2e']
def main():
    p=argparse.ArgumentParser();p.add_argument('--kernel',type=Path,default=HERE.parents[4]);p.add_argument('--keep-build',type=Path);a=p.parse_args();k=a.kernel.resolve()
    compat=(HERE/'xdomain_login_compat.h').read_text()
    clock='''
static unsigned long jiffies;
#define HZ 1000
#define time_before(a,b) ((long)((a)-(b))<0)
#define time_after(a,b) time_before(b,a)
#define time_before_eq(a,b) ((long)((a)-(b))<=0)
#define time_after_eq(a,b) time_before_eq(b,a)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
static unsigned long jiffies_to_msecs(unsigned long n){return n;}
'''
    boundaries=(HERE/'xdomain_login_boundaries.c').read_text().replace('trace[512]','trace[16384]')
    try:
        unit=compat+clock+'\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n'+no_includes((k/'io_uring/xdomain/xdev_ext_xdomain.h').read_text())+boundaries+retention_unit(k)+no_includes((k/'io_uring/xdomain/xdev_ext_xdomain_main.c').read_text())+(HERE/'xdomain_review_retry_cases.c').read_text()
    except (OSError,ValueError) as e:print('# SETUP_EXTRACTION; no behavioral run: '+str(e));return 2
    with tempfile.TemporaryDirectory(prefix='xdomain-review-retry-') as temp:
        c=Path(temp)/'retry.c';binary=Path(temp)/'retry';c.write_text(unit)
        if a.keep_build:a.keep_build.mkdir(parents=True,exist_ok=True);(a.keep_build/'retry-unit.c').write_text(unit)
        build=subprocess.run(['gcc','-std=gnu11','-O0','-g','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-variable','-Werror=implicit-function-declaration','-I',str(k),str(c),'-o',str(binary)],capture_output=True,text=True,timeout=60)
        if build.returncode:print('# SETUP_COMPILE_ERROR; not behavioral RED\n'+build.stdout+build.stderr);return 2
        print('TAP version 13\n1..'+str(len(NAMES)),flush=True);failed=False
        for i,name in enumerate(NAMES,1):
            try:
                run=subprocess.run([str(binary),str(i)],capture_output=True,text=True,timeout=8)
                print(run.stdout+run.stderr,end='',flush=True);ok=run.returncode==0
            except subprocess.TimeoutExpired:ok=False;print('# timeout')
            failed|=not ok;print(('ok ' if ok else 'not ok ')+str(i)+' - '+name,flush=True)
        return int(failed)
if __name__=='__main__':sys.exit(main())
