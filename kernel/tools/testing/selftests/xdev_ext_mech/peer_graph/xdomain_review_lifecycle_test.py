#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent lifecycle regressions; execute production bodies unchanged.

Host API recorders do not certify hardware DMA. Build/setup errors exit 2;
behavioral failures exit 1. --keep-build preserves exact executed source.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
from xdomain_ring_test import no_includes, declaration
from xdomain_retention_fixture import retention_unit, descriptor_unit

HERE = Path(__file__).resolve().parent

def ring_unit(kernel):
    peer=(kernel/'include/linux/xdev_ext_peer.h').read_text()
    net=(kernel/'include/linux/xdev_ext_netfam.h').read_text()
    lease=declaration(peer,'struct xdev_ext_peer_lease')+declaration(peer,'struct xdev_ext_peer_fd_lease')
    family=declaration(net,'enum xdev_ext_net_hdr_policy')+'\n'.join(line for line in net.splitlines() if line.startswith('#define XDEV_EXT_NET_DEV_AREA') or line.startswith('#define XDEV_EXT_NETFAM_MAX_ELEMS'))+'\n'+declaration(net,'struct xdev_ext_net_elem')+declaration(net,'struct xdev_ext_net_dev_ops')
    boundaries=(HERE/'xdomain_ring_boundaries.c').read_text()
    # Recorder capacity only. Existing tests and production source stay intact.
    for old,new in [('all_rings[16]','all_rings[1024]'),('stop_hop[32]','stop_hop[2048]'),('dma_records[64]','dma_records[1024]'),('hops[16]','hops[1024]')]:
        assert old in boundaries
        boundaries=boundaries.replace(old,new)
    return ((HERE/'xdomain_ring_compat.h').read_text()+'\n#include "include/uapi/linux/xdev_ext_mech.h"\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n'+lease+family+no_includes((kernel/'io_uring/xdomain/xdev_ext_xdomain.h').read_text())+boundaries+retention_unit(kernel)+descriptor_unit(kernel)+no_includes((kernel/'io_uring/xdomain/xdev_ext_xdomain_ring.c').read_text())+(HERE/'xdomain_review_lifecycle_ring_cases.c').read_text())

def function(text, name):
    import re
    match=re.search(r'(?m)^static (?:int|void) '+re.escape(name)+r'\(',text)
    if not match: raise ValueError('missing production function '+name)
    begin=text.index('{',match.start());depth=1;pos=begin+1
    while depth:
        if text[pos]=='{':depth+=1
        elif text[pos]=='}':depth-=1
        pos+=1
    return text[match.start():pos]+'\n'

def lock_unit(kernel):
    tb_path=kernel/'drivers/thunderbolt/tb.c'
    tb=tb_path.read_text()
    names=['tb_approve_xdomain_paths','__tb_disconnect_xdomain_paths','tb_disconnect_xdomain_paths']
    print('# production TB source: '+str(tb_path),flush=True)
    print('# unchanged TB bodies: '+', '.join(names),flush=True)
    print('# unchanged project full TU: io_uring/xdomain/xdev_ext_xdomain_main.c',flush=True)
    return ((HERE/'xdomain_review_lifecycle_lock_compat.h').read_text()+
            '\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n'+
            no_includes((kernel/'io_uring/xdomain/xdev_ext_xdomain.h').read_text())+
            (HERE/'xdomain_review_lifecycle_lock_environment.h').read_text()+
            ''.join(function(tb,name) for name in names)+
            (HERE/'xdomain_review_lifecycle_lock_boundaries.c').read_text()+retention_unit(kernel)+
            no_includes((kernel/'io_uring/xdomain/xdev_ext_xdomain_main.c').read_text())+
            (HERE/'xdomain_review_lifecycle_lock_cases.c').read_text())

def main():
    p=argparse.ArgumentParser();p.add_argument('--kernel',type=Path,default=HERE.parents[4]);p.add_argument('--keep-build',type=Path);p.add_argument('--group',choices=['ring','locks','all'],default='all');a=p.parse_args();kernel=a.kernel.resolve()
    groups=[]
    try:
        if a.group in ('ring','all'):
            groups.append(('ring',ring_unit(kernel),['healthy_idle_100_restart_reuses_backing','healthy_tx_cancel_100_restart_reuses_backing','unknown_full_allocation_retained_and_no_reuse','same_nhi_quarantine_hard_admission']))
        if a.group in ('locks','all'):
            groups.append(('locks',lock_unit(kernel),['connect_approve_vs_synchronous_remove','disconnect_false_check_to_remove_TOCTOU']))
    except (OSError, ValueError) as exc:
        print("# SETUP_EXTRACTION; not behavioral RED: "+str(exc),file=sys.stderr)
        return 2
    failed=False
    print('TAP version 13\n1..'+str(sum(len(names) for _,_,names in groups)),flush=True);number=0
    with tempfile.TemporaryDirectory(prefix='xdomain-review-lifecycle-') as tmp:
        for group,unit,names in groups:
            source=Path(tmp)/(group+'.c');binary=Path(tmp)/group;source.write_text(unit)
            if a.keep_build:
                a.keep_build.mkdir(parents=True,exist_ok=True);(a.keep_build/(group+'-unit.c')).write_text(unit)
            build=subprocess.run(['gcc','-std=gnu11','-O0','-g','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-Wno-unused-variable','-Werror=implicit-function-declaration','-pthread','-I',str(kernel),str(source),'-o',str(binary)],text=True,capture_output=True,timeout=60)
            if build.returncode:
                print('# SETUP_COMPILE_ERROR; not behavioral RED\n'+build.stdout+build.stderr,file=sys.stderr);return 2
            for index,name in enumerate(names,1):
                number+=1
                try:
                    run=subprocess.run([str(binary),str(index)],capture_output=True,text=True,timeout=8)
                    output=run.stdout+run.stderr
                    print(output,end='',flush=True)
                    ok=run.returncode==0
                except subprocess.TimeoutExpired as exc:
                    output=(exc.stdout or b'').decode()+(exc.stderr or b'').decode();print(output,end='');ok=False
                    print('# software deadlock deadline exceeded after explicit barrier',flush=True)
                print(('ok ' if ok else 'not ok ')+str(number)+' - '+name,flush=True);failed|=not ok
    return int(failed)

if __name__=='__main__':sys.exit(main())
