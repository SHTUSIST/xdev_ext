#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real TP executable and account its raw observations on one rank."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

_ACCOUNTING = Path(__file__).with_name('accounting.py')
_spec = importlib.util.spec_from_file_location('xdev_tp_accounting', _ACCOUNTING)
accounting = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(accounting)


def qualify_nccl_route(environment, log, interfaces):
    """Qualify saved Socket route evidence without changing NCCL scheduling.

    Interface byte counters are observed positive run deltas, not capacities.
    This checks supplied evidence; it does not certify hardware or provenance.
    """
    if environment.get('NCCL_NET') != 'Socket' or environment.get('NCCL_SOCKET_IFNAME') != '=thunderbolt0':
        raise ValueError('exact NCCL Socket/thunderbolt0 selection required')
    tuning = {'NCCL_ALGO','NCCL_PROTO','NCCL_NCHANNELS','NCCL_MIN_NCHANNELS',
              'NCCL_MAX_NCHANNELS','NCCL_BUFFSIZE','NCCL_P2P_NET_CHUNKSIZE',
              'NCCL_SOCKET_NTHREADS','NCCL_NSOCKS_PERTHREAD'}
    if tuning.intersection(environment):
        raise ValueError('baseline must retain actual NCCL defaults')
    used = set()
    for line in log.splitlines():
        if 'NET/Socket' in line and 'Using' in line:
            used.update(re.findall(r'\[[0-9]+\]([A-Za-z0-9_.-]+):',line))
    if used != {'thunderbolt0'}:
        raise ValueError('actual NET/Socket route is missing or uses other interfaces')
    route = interfaces.get('thunderbolt0',{})
    if not route.get('addresses') or route.get('rx_bytes',0)<=0 or route.get('tx_bytes',0)<=0:
        raise ValueError('interface addresses and positive observed byte deltas required')
    return dict(qualified=True, interface='thunderbolt0', net='Socket')


def analyze_file(path):
    groups = {key:[] for key in ('event','validation','interval','metadata')}
    with Path(path).open() as stream:
        for line in stream:
            if len(line)>16384:
                raise ValueError('unexpected oversized raw observation')
            record=json.loads(line)
            kind=record.pop('record')
            if kind not in groups:
                raise ValueError('unknown raw observation')
            groups[kind].append(record)
    if len(groups['metadata'])!=1:
        raise ValueError('one complete native final statistics record required')
    metadata=groups['metadata'][0]
    # This identifies the native handoff primitive, not an E6 experiment arm.
    native_mode=metadata.get('native_mode')
    if (type(native_mode) is not int or native_mode not in (1,2) or
            metadata.get('handoff_mode') != {1:'cpu',2:'gpu'}[native_mode]):
        raise ValueError('native_mode and matching cpu/gpu handoff_mode required')
    if metadata.get('execution_kind')=='echo':
        durations=accounting.local_durations(groups['interval'])
        expected_kind='rtt' if metadata['rank']==0 else 'echo_reply'
        if (not durations or len(durations)!=metadata['completed'] or
                any(d['rank']!=metadata['rank'] or d['clock']!=1 or d['kind']!=expected_kind for d in durations) or
                len({v['sequence'] for v in groups['validation']})!=metadata['completed'] or
                any(v['rank']!=metadata['rank'] or v['valid'] is not True for v in groups['validation'])):
            raise ValueError('incomplete local echo/GPU validation')
        return dict(metadata=metadata,host_intervals=durations,
                    latency_definition='rank0 full echo RTT; rank1 local reply completion',
                    one_way_latency='not measured',payload_bytes_by_direction={})
    result=accounting.analyze(groups['event'],groups['validation'],metadata)
    if result['logical_inflight_high_water']!=metadata['native_high_water']:
        raise ValueError('trace and final native high-water disagree')
    if (len({v['sequence'] for v in groups['validation']})!=metadata['completed'] or
            not metadata['completed'] or not groups['event']):
        raise ValueError('each completed operation requires GPU validation')
    # Host E6 intervals and GPU E7 traces deliberately remain separate clocks.
    result['host_intervals']=accounting.local_durations(groups['interval'])
    if (not result['host_intervals'] or
            any(i['rank']!=metadata['rank'] or i['clock']!=1 for i in result['host_intervals'])):
        raise ValueError('host intervals must use the local rank monotonic clock')
    result['metadata']=metadata
    result['direction_definition']='rank-local rx; rank0 rx is rank1->rank0, rank1 rx is rank0->rank1'
    result['bidirectional_aggregation']='none: retain separate rank-local direction denominators'
    result['transport_retry_bytes']=None
    result['transport_retry_note']='not exposed by TP API; never included as unique tensor payload'
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--driver',type=Path)
    p.add_argument('--raw',type=Path,required=True)
    p.add_argument('--summary',type=Path,required=True)
    p.add_argument('--analyze-only',action='store_true')
    p.add_argument('driver_arguments',nargs=argparse.REMAINDER)
    args=p.parse_args(argv)
    if not args.analyze_only:
        if not args.driver:
            p.error('--driver is required to execute')
        library_path=os.environ.get('LD_LIBRARY_PATH','')
        if any(Path(s).name=='stubs' for s in library_path.split(':') if s):
            p.error('CUDA link stubs must never be used for execution')
        command=[str(args.driver.resolve()),*args.driver_arguments]
        if args.driver_arguments[:1]==['--']:
            command=[str(args.driver.resolve()),*args.driver_arguments[1:]]
        # Exclusive output keeps a failed or negative original intact.
        with args.raw.open('x') as stream:
            completed=subprocess.run(command,stdout=stream,check=False)
        if completed.returncode:
            raise SystemExit(completed.returncode)
    result=analyze_file(args.raw)
    args.summary.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(summary=str(args.summary),rank=result['metadata']['rank'],
                          execution='real-native-driver',hardware_qualification='external-required')))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
