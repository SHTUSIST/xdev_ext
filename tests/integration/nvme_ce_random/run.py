#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Native NVMe<->CE correctness only; immutable requests and whole-image oracle."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

PAYLOAD=1048576


def requests(args):
    if args.depth<2 or args.depth>64 or args.batches<args.depth or args.phases<2:
        raise ValueError('depth>=2, batches>=depth and phases>=2 required')
    if args.batches*args.phases>0xffffffff or args.gpu_bytes<PAYLOAD*args.batches+1 or args.disk_bytes<PAYLOAD+args.lba_bytes:
        raise ValueError('request count/window cannot preserve payload and depth')
    if args.lba_bytes<512 or args.lba_bytes&(args.lba_bytes-1) or PAYLOAD%args.lba_bytes:
        raise ValueError('invalid actual LBA size')
    rng=random.Random(args.seed)
    rows=[]
    for phase in range(args.phases):
        group=[]
        for index in range(args.batches):
            for attempt in range(100000):
                gpu=(1 if phase==0 else rows[0]['gpu_offset']) if index==0 else rng.randrange(args.gpu_bytes-PAYLOAD+1)
                nvme=rng.randrange((args.disk_bytes-PAYLOAD)//args.lba_bytes+1)*args.lba_bytes
                if phase and index==0:
                    if nvme==rows[0]['nvme_offset']: continue
                    if args.direction=='save' and nvme<rows[0]['nvme_offset']+PAYLOAD and rows[0]['nvme_offset']<nvme+PAYLOAD:
                        continue
                if phase and index==1:
                    nvme=rows[0]['nvme_offset']
                    gpu=args.gpu_bytes-PAYLOAD
                overlap=lambda offset,name:any(offset<p[name]+PAYLOAD and p[name]<offset+PAYLOAD for p in group)
                if overlap(gpu,'gpu_offset') or (args.direction=='save' and overlap(nvme,'nvme_offset')):
                    continue
                break
            else:
                raise ValueError('cannot generate disjoint random phase without shrinking/serializing')
            row=dict(key=100+len(rows),phase=phase,nvme_offset=nvme,gpu_offset=gpu,bytes=PAYLOAD)
            group.append(row);rows.append(row)
    return rows


def oracle(output,rows,args):
    spec=importlib.util.spec_from_file_location('random_native_expected',Path(__file__).with_name('expected.py'))
    expected=importlib.util.module_from_spec(spec);spec.loader.exec_module(expected)
    metadata=json.loads((output/'allocation.json').read_text())
    for key,value in [('gpu_bytes',args.gpu_bytes),('disk_bytes',args.disk_bytes),('guard_bytes',args.guard_bytes),('depth',args.depth),('direction',args.direction)]:
        if metadata[key]!=value: raise ValueError('actual allocation input mismatch: '+key)
    gpu=(output/'gpu-initial.bin').read_bytes();disk=(output/'disk-initial.bin').read_bytes()
    if len(gpu)!=metadata['allocation_bytes'] or len(disk)!=metadata['disk_full_bytes']:
        raise ValueError('whole initial image length mismatch')
    if gpu!=expected.gpu_initial(len(gpu)) or disk!=expected.disk_initial(len(disk)):
        raise AssertionError('frozen input image differs from independent absolute-position specification')
    phases=[]
    for phase in range(args.phases):
        cumulative=[r for r in rows if r['phase']<=phase]
        bounds=dict(window_length=args.gpu_bytes,disk_guard=args.guard_bytes,disk_window_length=args.disk_bytes)
        want_gpu=expected.load_image(gpu,disk,cumulative,args.guard_bytes,**bounds) if args.direction=='load' else gpu
        want_disk=expected.save_image(disk,gpu,cumulative,args.guard_bytes,**bounds) if args.direction=='save' else disk
        actual_gpu=(output/f'phase-{phase}-gpu.bin').read_bytes()
        actual_disk=(output/f'phase-{phase}-disk.bin').read_bytes()
        phases.append(dict(phase=phase,gpu=expected.compare(actual_gpu,want_gpu),disk=expected.compare(actual_disk,want_disk)))
    return phases


def main():
    root=next(p for p in Path(__file__).resolve().parents if (p/'source-layout.json').is_file())
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--ng',required=True);parser.add_argument('--block',required=True);parser.add_argument('--ce',required=True)
    parser.add_argument('--direction',choices=('load','save'),required=True)
    parser.add_argument('--scratch-slba',type=int,required=True);parser.add_argument('--scratch-nlb',type=int,required=True)
    parser.add_argument('--lba-bytes',type=int,required=True)
    parser.add_argument('--gpu-bytes',type=int,default=16777216);parser.add_argument('--disk-bytes',type=int,default=16777216)
    parser.add_argument('--guard-bytes',type=int,default=2097152)
    parser.add_argument('--depth',type=int,default=2);parser.add_argument('--batches',type=int,default=8)
    parser.add_argument('--phases',type=int,default=2);parser.add_argument('--seed',type=int,default=42)
    parser.add_argument('--timeout-ms',type=int,default=60000);parser.add_argument('--deadline-seconds',type=int,default=300)
    args=parser.parse_args()
    for name in ('gpu_bytes','disk_bytes','guard_bytes','scratch_slba','scratch_nlb','lba_bytes','seed','timeout_ms','deadline_seconds'):
        if not 0<=getattr(args,name)<1<<64: raise ValueError('invalid unsigned input: '+name)
    if not args.guard_bytes or not args.timeout_ms or not args.deadline_seconds:
        raise ValueError('nonzero guard/deadline required')
    rows=requests(args)
    sys.path.insert(0,str(root/'tests/compute/ce/random_target'))
    from runtime_validate import load
    helper=load('random_native_controller_helper',root/'tests/compute/ce/random_target/run.py')
    output=helper.build_directory(root,args.output)
    result=dict(schema=1,status='setup',exit_code=2,performance=False,execution='native-nvme-ce',phases=[])
    helper.write_json(output/'result.json',result)
    helper.write_json(output/'requests.json',dict(schema=1,seed=args.seed,requests=rows,inputs={k:v for k,v in vars(args).items() if not isinstance(v,Path)}))
    table=output/'requests.tsv'
    table.write_text(''.join(f"{r['key']} {r['phase']} {r['nvme_offset']} {r['gpu_offset']} {r['bytes']}\n" for r in rows))
    build=args.build.resolve()
    provenance=json.loads((build/'build-result.json').read_text())
    if provenance.get('status')!='build-only' or provenance.get('exit_code')!=0:
        raise ValueError('successful build-only receipt required')
    for name in ('nvme-ce-random','nvme_ce_request.bpf.o'):
        if hashlib.sha256((build/name).read_bytes()).hexdigest()!=provenance['artifacts'][name]:
            raise ValueError('frozen build artifact changed: '+name)
    for name in ('run.py','expected.py','contract.h'):
        relative='tests/integration/nvme_ce_random/'+name
        if hashlib.sha256((root/relative).read_bytes()).hexdigest()!=provenance['inputs'][relative]:
            raise ValueError('runtime input changed after build: '+name)
    helper.write_json(output/'build-receipt.json',provenance)
    command=[str(build/'nvme-ce-random'),'--object',str(build/'nvme_ce_request.bpf.o'),'--requests',str(table),
             '--ng',args.ng,'--block',args.block,'--ce',args.ce,'--output',str(output),'--direction',args.direction]
    for key in ('gpu_bytes','disk_bytes','guard_bytes','depth','lba_bytes','scratch_slba','scratch_nlb','timeout_ms'):
        command+=['--'+key.replace('_','-'),str(getattr(args,key))]
    helper.write_json(output/'native.argv.json',command)
    helper.write_json(output/'result.json',result)
    child=None
    try:
        with (output/'native.log').open('w') as log:
            child=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            deadline=time.monotonic()+args.deadline_seconds
            while child.poll() is None:
                state_path=output/'driver-state.json'
                state=json.loads(state_path.read_text()) if state_path.exists() else {}
                if state.get('state')=='retained' or time.monotonic()>=deadline:
                    os.kill(child.pid,signal.SIGSTOP)
                    result.update(status='retained',exit_code=1,pid=child.pid,reason=state.get('reason','controller deadline; resources preserved'))
                    helper.write_json(output/'result.json',result)
                    print('RETAINED: PID',child.pid,'resources preserved; evidence',output)
                    return 1
                time.sleep(0.05)
        helper.write_json(output/'native.exit.json',dict(returncode=child.returncode,pid=child.pid))
        if child.returncode:
            code=child.returncode if child.returncode in (1,2,4) else 2
            result.update(status='unqualified' if code==4 else ('failed' if code==1 else 'setup'),exit_code=code)
        else:
            state=json.loads((output/'driver-state.json').read_text())
            if state.get('state')!='captured': raise ValueError('driver did not capture safe complete images')
            result['phases']=oracle(output,rows,args)
            passed=all(p['gpu']['equal'] and p['disk']['equal'] for p in result['phases'])
            result.update(status='passed' if passed else 'failed',exit_code=0 if passed else 1)
        helper.write_json(output/'result.json',result)
        print(result['status'],output)
        return result['exit_code']
    except Exception as error:
        result.update(error=str(error),status='setup',exit_code=2)
        if isinstance(error,AssertionError) and child is not None and child.returncode==0:
            result.update(status='failed',exit_code=1)
        if child is not None and child.poll() is None:
            os.kill(child.pid,signal.SIGSTOP)
            result.update(status='retained',pid=child.pid,reason='controller exception; resources preserved')
        helper.write_json(output/'result.json',result)
        print('SETUP:',error,file=sys.stderr)
        return result['exit_code']


if __name__=='__main__':
    try: status=main()
    except Exception as error:
        print('SETUP:',error,file=sys.stderr);status=2
    raise SystemExit(status)
