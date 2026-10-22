#!/usr/bin/env python3
"""Strict final-log validation; the guest app compares every datagram byte."""
from pathlib import Path
import argparse
import re

def records(text, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in text.splitlines() if line.startswith(prefix+' ')]

def validate_mech(text, stages, lifecycle):
    apps=records(text,'XDEV_EXT_MECH_APP=PASS')
    reports=records(text,'XDEV_EXT_PRELOAD_MECH_REPORT')
    assert len(apps)==(5 if lifecycle else 1), 'missing/duplicate app campaign'
    assert len(reports)==(4 if lifecycle else 1), 'missing/duplicate runtime report'
    assert len({(r['pid'],r['tid']) for r in reports})==len(reports), 'duplicate thread report'
    assert sum(int(a['calls']) for a in apps)==(315 if lifecycle else 257)
    assert all(int(a['fallback'])==3 for a in apps), 'fallback datagrams were not checked'
    calls=sum(int(r['calls']) for r in reports)
    assert calls==sum(int(a['calls']) for a in apps), 'silent fallback or duplicated call'
    assert sum(int(r['bytes']) for r in reports)==sum(int(a['bytes']) for a in apps), 'capacity/actual-byte mismatch'
    assert sum(int(r['creates']) for r in reports)==len(apps), 'session not reused or identity not renewed'
    assert all(int(r['errors'])==0 for r in reports), 'runtime reported error'
    assert all(int(r['stop_errors'])==0 and int(r['stops'])==int(r['creates']) for r in reports), 'session did not stop cleanly'
    for stage in range(3):
        for kind in ('submitted','completed'):
            assert sum(int(r[f'{kind}{stage}']) for r in reports)==(calls if stage<stages else 0), 'stage count mismatch'
    if lifecycle:
        assert 'XDEV_EXT_MECH_APP_LIFECYCLE=PASS fork=1 threads=2 fd_reuse=PASS' in text

def validate(directory, ce):
    for arm, stages in [('socket',1)]+([('ce-socket',3)] if ce else []):
        for mode in ('base','lifecycle'):
            validate_mech((directory/f'mech-{arm}-{mode}.log').read_text(),stages,mode=='lifecycle')
    udp=(directory/'compat-udp.log').read_text()
    assert 'XDEV_EXT_TRANSPARENT_SOCKET_PAYLOAD=PASS sends=3 bytes=25' in udp
    rows=records(udp,'XDEV_EXT_PRELOAD_REPORT')
    assert len(rows)==1 and all(int(rows[0][k])==v for k,v in [('custom_send_count',3),('custom_send_bytes',25),('custom_send_errors',0)])
    off=(directory/'compat-dio-off.log').read_text()
    on=(directory/'compat-dio-on.log').read_text()
    offrows=records(off,'XDEV_EXT_DB_WORKLOAD_RESULT=PASS')
    onrows=records(on,'XDEV_EXT_DB_WORKLOAD_RESULT=PASS')
    assert len(offrows)==len(onrows)==1 and offrows==onrows, 'O_DIRECT behavior differs'
    want=onrows[0]
    reports=records(on,'XDEV_EXT_PRELOAD_REPORT')
    assert reports and int(want['eligible_reads']) and int(want['eligible_writes'])
    for kind in ('read','write'):
        count=sum(int(r[f'{kind}_count']) for r in reports)
        errors=sum(int(r[f'{kind}_errors']) for r in reports)
        assert count+errors==int(want[f'eligible_{kind}s']), 'O_DIRECT silent fallback'
        assert errors==int(want[f'eligible_{kind}_errors']), 'O_DIRECT error mismatch'
    print(f'XDEV_EXT_PRELOAD_VM_VALIDATION=PASS socket=1 ce_socket={int(ce)} dio=1')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('directory',type=Path)
    p.add_argument('--ce',action='store_true')
    args=p.parse_args()
    validate(args.directory,args.ce)
