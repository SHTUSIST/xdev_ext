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

def validate_concurrency(text, stages, threads, processes, rounds=65):
    """Match every actor to its own runtime; totals cannot hide fallback."""
    actors=records(text,'XDEV_EXT_MECH_ACTOR=PASS')
    reports=records(text,'XDEV_EXT_PRELOAD_MECH_REPORT')
    finals=records(text,'XDEV_EXT_MECH_CONCURRENCY=PASS')
    fds=records(text,'XDEV_EXT_MECH_FDS=PASS')
    count=threads*processes
    assert len(actors)==len(reports)==count, 'missing/duplicate actor or runtime'
    assert len(finals)==1, 'missing/duplicate concurrency verdict'
    final=finals[0]
    for key,value in dict(processes=processes,threads=threads,actors=count,rounds=rounds,
                          per_round_gate=1,fd_leaks=0).items():
        assert int(final[key])==value, 'concurrency shape or gate mismatch'
    assert int(final['overlap_pairs'])>0, 'no actual overlapping send calls'
    cross_process=int(final['cross_process_overlap_pairs'])
    assert (cross_process>0 if processes>1 else cross_process==0), 'no cross-process send overlap'
    assert {int(a['actor']) for a in actors}==set(range(count)), 'actor identity missing'
    keys=lambda rows: {(r['pid'],r['tid']) for r in rows}
    assert len(keys(actors))==count and keys(actors)==keys(reports), 'per actor runtime identity mismatch'
    assert len({a['pid'] for a in actors})==processes, 'independent process count mismatch'
    assert all(sum(a['pid']==pid for a in actors)==threads for pid in {a['pid'] for a in actors}), 'thread distribution mismatch'
    assert len(fds)==processes and {int(f['process']) for f in fds}==set(range(processes)), 'FD audit missing'
    assert {f['pid'] for f in fds}=={a['pid'] for a in actors}, 'FD audit process mismatch'
    assert all(int(f['before'])==int(f['after']) and int(f['before'])>0 for f in fds), 'FD leak'
    want_bytes=sum((31,257,1023)[i%3] for i in range(rounds))
    by_key={(r['pid'],r['tid']):r for r in reports}
    for actor in actors:
        runtime=by_key[(actor['pid'],actor['tid'])]
        for key,value in dict(calls=rounds,bytes=want_bytes,ready=rounds,entered=rounds,
                              exited=rounds,full_compare=1,guards=1,extra_datagrams=0).items():
            assert int(actor[key])==value, 'incomplete data/round/guard comparison'
        for key,value in dict(creates=1,calls=rounds,bytes=want_bytes,errors=0,stops=1,stop_errors=0).items():
            assert int(runtime[key])==value, 'actor fallback, error, or teardown mismatch'
        for stage in range(3):
            for kind in ('submitted','completed'):
                assert int(runtime[f'{kind}{stage}'])==(rounds if stage<stages else 0), 'actor stage count mismatch'

def validate_ordinary_fork(text):
    """Require real proc resources, every byte verdict, and per-thread takeover."""
    assert '=FAIL' not in text and 'XDEV_EXT_ORDINARY_FORK_CHILD_ERROR' not in text
    assert 'XDEV_EXT_ORDINARY_FORK_SELFTEST=' not in text
    finals=records(text,'XDEV_EXT_ORDINARY_FORK=PASS')
    want=dict(XDEV_EXT_ORDINARY_FORK='PASS',workers='2',forks='3',main_eligible='0',
        parent_reads='16',parent_writes='8',child_reads='6',child_writes='3',bytes='49152',
        source='unchanged',received='complete',guards='complete',
        first_child_call='observed-real-proc',exit='normal')
    assert len(finals)==1 and finals[0]==want, 'ordinary fork bytes or completion missing'
    live=records(text,'XDEV_EXT_ORDINARY_FORK_LIVE')
    allowed=records(text,'XDEV_EXT_ORDINARY_FORK_ALLOWED')
    rings=records(text,'XDEV_EXT_ORDINARY_FORK_RING')
    maps=records(text,'XDEV_EXT_ORDINARY_FORK_MAP')
    children=records(text,'XDEV_EXT_ORDINARY_FORK_CHILD')
    assert len(live)==1 and live[0]['workers']=='2' and live[0]['rings']=='2'
    assert live[0]['allowed']=='baseline+2-rings'
    assert len(allowed)==int(live[0]['baseline_fds']) and len(allowed)>=3
    baseline={int(row['fd']) for row in allowed}
    assert len(baseline)==len(allowed) and min(baseline)>=0, 'duplicate allowed FD'
    assert all(set(row)=={'fd','dev','ino','flags','target'} and
        int(row['dev'])>=0 and int(row['ino'])>=0 and int(row['flags'])>=0 for row in allowed)
    ring_fds={int(row['fd']) for row in rings}
    assert len(rings)==len(ring_fds)==2 and not baseline & ring_fds
    assert all(row['target']=='anon_inode:[io_uring]' and
        row['fdinfo']=='SqMask:0x1,CqMask' and int(row['ino'])>=0 for row in rings)
    assert len(maps)==int(live[0]['maps']) and 4<=len(maps)<=6
    ranges=[]
    offsets=[]
    for row in maps:
        lo,hi=(int(value,16) for value in row['range'].split('-'))
        assert lo<hi and all(hi<=oldlo or oldhi<=lo for oldlo,oldhi in ranges), 'overlapping or invalid ring VMA'
        ranges.append((lo,hi))
        offsets.append(int(row['offset'],16))
        assert int(row['ino'])>=0
    assert offsets.count(0)==offsets.count(0x10000000)==2
    assert all(offset in (0,0x8000000,0x10000000) for offset in offsets)
    assert offsets.count(0x8000000)<=2
    assert len(children)==3 and {row['round'] for row in children}=={'0','1','2'}
    assert all(row['before_rings']=='0' and row['after_rings']=='1' and
        int(row['inherited_maps_removed'])==len(maps) and row['allowed']=='exact-baseline'
        for row in children), 'inherited ordinary ring FD/VMA survived first child call'
    reports=records(text,'XDEV_EXT_PRELOAD_REPORT')
    assert len(reports)==5 and len({(row['pid'],row['tid']) for row in reports})==5
    by_pid={}
    for row in reports:
        assert int(row['pid'])>0 and int(row['tid'])>0
        by_pid.setdefault(row['pid'],[]).append(row)
        assert all(int(row[key])==0 for key in ('read_errors','write_errors',
            'custom_send_count','custom_send_bytes','custom_send_errors'))
        for kind in ('read','write'):
            assert int(row[kind+'_bytes'])==int(row[kind+'_count'])*4096, 'takeover bytes mismatch'
    assert sorted(len(rows) for rows in by_pid.values())==[1,1,1,2], 'parent/child report identity mismatch'
    for rows in by_pid.values():
        parent=len(rows)==2
        for row in rows:
            assert (row['tid']!=row['pid']) if parent else (row['tid']==row['pid'])
            assert int(row['read_count'])==(8 if parent else 2), 'ordinary read silent fallback'
            assert int(row['write_count'])==(4 if parent else 1), 'ordinary write silent fallback'

def validate(directory, ce):
    for arm, stages in [('socket',1)]+([('ce-socket',3)] if ce else []):
        for mode in ('base','lifecycle'):
            validate_mech((directory/f'mech-{arm}-{mode}.log').read_text(),stages,mode=='lifecycle')
        for mode, threads, processes in [('threads',4,1),('processes',2,4)]:
            validate_concurrency((directory/f'mech-{arm}-{mode}.log').read_text(),stages,threads,processes)
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
    validate_ordinary_fork((directory/'compat-ordinary-fork.log').read_text())
    print(f'XDEV_EXT_PRELOAD_VM_VALIDATION=PASS socket=1 ce_socket={int(ce)} dio=1')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('directory',type=Path)
    p.add_argument('--ce',action='store_true')
    args=p.parse_args()
    validate(args.directory,args.ce)
