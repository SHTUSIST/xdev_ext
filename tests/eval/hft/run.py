#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""HFT-shaped read-only replay microbenchmark (correctness only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import secrets
import socket
import subprocess
import sys
import tempfile
import oracle

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BIN=HERE/'.build'/'hft_replay'


class Failure(Exception):
    def __init__(self,status,message,code=4):
        self.status,self.message,self.code=status,message,code


def decimal(text):
    if not re.fullmatch('[0-9]+',text,flags=re.ASCII):
        raise argparse.ArgumentTypeError('ASCII unsigned decimal required')
    value=int(text)
    if value>=2**64: raise argparse.ArgumentTypeError('u64 overflow')
    return value


def parse():
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('--backend',choices=('posix','uring-fixed-zc','session'),default='posix')
    parser.add_argument('--mode',choices=('correctness','performance'),default='correctness')
    for name,default in (('records',64),('payload',512),('burst',32),('depth',8),('bursts',8),('actors',1),('seed',1)):
        parser.add_argument('--'+name,type=decimal,default=default)
    parser.add_argument('--directory',type=Path)
    for name in ('source-block','source-ng','ifname','local-mac','peer-mac','local-ip','peer-ip','bpf-object','kernel-config'):
        parser.add_argument('--'+name,default='')
    for name in ('slba','nlb','queue','local-port','peer-port'):
        parser.add_argument('--'+name,type=decimal,default=0)
    parser.add_argument('--control-ip',default='127.0.0.1')
    parser.add_argument('--control-port',type=decimal,default=0)
    seen=set()
    for arg in sys.argv[1:]:
        if arg.startswith('--'):
            key=arg.split('=',1)[0]
            if key in seen: parser.error('duplicate option: '+key)
            seen.add(key)
    args=parser.parse_args()
    p=dict(schema=1,record_bytes=args.records,payload_bytes=args.payload,
        burst_packets=args.burst,depth=args.depth,bursts=args.bursts,
        actors=args.actors,seed=args.seed,session_base=1)
    if (args.records not in (64,128,256) or args.payload not in (512,1024,4096)
        or args.payload%args.records or args.actors not in (1,4)
        or not 1<=args.burst<=32 or not 1<=args.depth<=8 or not 1<=args.bursts<=32
        or args.burst*args.bursts*args.actors>1048576
        or args.burst*args.bursts*args.actors*args.payload>2**30): parser.error('invalid profile')
    if args.directory is not None and not args.directory.is_dir(): parser.error('directory must exist')
    if any(n>65535 for n in (args.local_port,args.peer_port,args.control_port)) or args.queue>=2**32: parser.error('port/queue range')
    for ip in (args.local_ip,args.peer_ip,args.control_ip):
        if ip:
            try: socket.inet_pton(socket.AF_INET,ip)
            except OSError: parser.error('IPv4 address required')
    for mac in (args.local_mac,args.peer_mac):
        if mac and not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac): parser.error('MAC address required')
    p['session_base']=secrets.randbelow(2**64-args.actors)+1
    return args,p


def checked_result(p,backend,raw,validated,source_sha):
    count=p['actors']*p['burst_packets']*p['bursts']
    expected={'read_submissions','send_submissions','read_cqes','send_result_cqes','send_notif_cqes','zc_copied_packets','registration_calls','guards_ok','local_release_complete'}
    if backend=='session': expected|={'session_stats','stop_ret'}
    if type(raw) is not dict or set(raw)!=expected: raise ValueError('producer result schema')
    for key in expected-{'guards_ok','local_release_complete','session_stats'}:
        if type(raw[key]) is not int or raw[key]<0: raise ValueError('producer counter type')
    if raw['guards_ok'] is not True or raw['local_release_complete'] is not True: raise ValueError('producer release/guards')
    if raw['read_submissions']!=count or raw['send_submissions']!=count: raise ValueError('incomplete submissions')
    if validated!=dict(status='ok',validated_packets=count,validated_bytes=count*p['payload_bytes']): raise ValueError('oracle totals')
    result=dict(schema=1,status='ok',scenario='hft_replay',mode='correctness',backend=backend,transport='udp',
        record_bytes=p['record_bytes'],payload_bytes=p['payload_bytes'],burst_packets=p['burst_packets'],depth=p['depth'],
        bursts=p['bursts'],actors=p['actors'],expected_packets=count,validated_packets=count,
        validated_bytes=count*p['payload_bytes'],read_bytes=count*p['payload_bytes'],send_bytes=count*(p['payload_bytes']+40),
        unexpected_packets=0,duplicates=0,missing=0,byte_mismatches=0,local_release_complete=True,receiver_receipt=True,
        guards_ok=True,read_submissions=raw['read_submissions'],send_submissions=raw['send_submissions'],source_sha=source_sha,
        registration_calls=None,read_cqes=None,send_result_cqes=None,send_notif_cqes=None,zc_copied_packets=None,session_stats=None,stop_ret=None,
        scope='physical-native-correctness' if backend=='session' else 'buffered-host-correctness')
    if backend=='uring-fixed-zc':
        if raw['registration_calls']!=p['actors'] or raw['read_cqes']!=count or raw['send_result_cqes']!=count or not 0<=raw['zc_copied_packets']<=raw['send_notif_cqes']<=count:
            raise ValueError('registered completion accounting')
        for key in ('registration_calls','read_cqes','send_result_cqes','send_notif_cqes','zc_copied_packets'): result[key]=raw[key]
    if backend=='session':
        # C adapter emits these only after exact per-stage STATS and STOP0.
        wanted=dict(batches_done=count,read_submitted=count,read_completed=count,send_submitted=count,send_completed=count,
            state='ACTIVE',batches_abort=0,rejects=0,sequestered=0,timeouts=0,protocol_err=0,last_err=0,inflight=0)
        if type(raw['stop_ret']) is not int or raw['stop_ret']!=0 or type(raw['session_stats']) is not dict or set(raw['session_stats'])!=set(wanted): raise ValueError('native release/stats schema')
        if any(type(raw['session_stats'][k]) is not type(v) or raw['session_stats'][k]!=v for k,v in wanted.items()): raise ValueError('native incomplete stage/lifetime')
        result['stop_ret']=raw['stop_ret'];result['session_stats']=raw['session_stats']
    return result


def execute(args,p):
    if args.mode=='performance': raise Failure('not_run_capability','performance entry disabled; no workload or measurements issued')
    if args.backend=='session' or args.source_block:
        raise Failure('not_run_hardware','physical session/raw-source execution uses hardware_measure.py measure with pinned producer/peer admission')
    offset=0
    if not BIN.is_file():
        built=subprocess.run(['make','-s','-C',str(HERE)],text=True,capture_output=True)
        if built.returncode: raise Failure('not_run_capability','producer build failed: '+built.stderr)
    parent=args.directory or ROOT
    with tempfile.TemporaryDirectory(prefix='.hft-replay-',dir=parent) as directory:
        directory=Path(directory);os.chmod(directory,0o700)
        manifest=directory/'manifest.json';reference=directory/'reference.bin';capture=directory/'capture.bin'
        with oracle.exclusive(manifest) as out: out.write(json.dumps(p).encode())
        oracle.generate(p,reference)
        digest=hashlib.sha256(reference.read_bytes()).hexdigest()
        if args.source_block:
            with open(args.source_block,'rb',buffering=0) as src,reference.open('rb') as ref:
                src.seek(offset)
                while True:
                    expected=ref.read(65536)
                    if not expected: break
                    if src.read(len(expected))!=expected: raise Failure('not_run_capability','source bytes differ from immutable reference')
        # For physical native runs the receiver is local to the configured peer IP;
        # binding fails if this process is not running on that peer namespace.
        bind_ip=args.peer_ip or '127.0.0.1'
        receiver=subprocess.Popen([sys.executable,str(HERE/'oracle.py'),'receive','--manifest',str(manifest),
            '--bind',f'{bind_ip}:{args.peer_port}','--control',f'{args.control_ip}:{args.control_port}','--capture',str(capture)],
            text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            if not select.select([receiver.stdout],[],[],10)[0]: raise ValueError('receiver readiness timeout')
            line=receiver.stdout.readline()
            if not line: raise ValueError('receiver exited before readiness: '+receiver.stderr.read())
            ready=json.loads(line)
            if ready.get('status')!='ready': raise ValueError('receiver not ready')
            command=[str(BIN),args.backend,str(reference),str(args.records),str(args.payload),str(args.burst),str(args.depth),
                str(args.bursts),str(args.actors),str(args.seed),*map(str,ready['bind']),*map(str,ready['control']),
                args.source_block,args.source_ng,str(args.slba),str(args.nlb),args.ifname,str(args.queue),args.local_ip,
                args.local_mac,args.peer_mac,str(args.local_port),args.bpf_object,args.kernel_config,str(offset),'correctness',str(p['session_base'])]
            producer=subprocess.Popen(command,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                import time
                deadline=time.monotonic()+180
                while producer.poll() is None:
                    if receiver.poll() is not None:
                        raise ValueError('receiver exited during producer execution: '+receiver.stderr.read())
                    if time.monotonic()>deadline: raise ValueError('producer deadline')
                    time.sleep(0.01)
                produced_stdout,produced_stderr=producer.communicate()
                produced=subprocess.CompletedProcess(command,producer.returncode,produced_stdout,produced_stderr)
            finally:
                if producer.poll() is None: producer.terminate()
                producer.communicate(timeout=10)
            if produced.returncode:
                if produced.returncode==4: raise Failure('not_run_capability','backend unavailable before START: '+produced.stderr)
                raise ValueError('producer failed: '+produced.stderr)
            if len(produced.stdout.splitlines())!=1: raise ValueError('producer result count')
            if produced.stderr: print(produced.stderr,end='',file=sys.stderr)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ctl:
                ctl.settimeout(20);ctl.connect(tuple(ready['control']))
                ctl.send(b'{"op":"finish"}')
                receipt=json.loads(ctl.recv(4096))
            stdout,stderr=receiver.communicate(timeout=10)
            if receiver.returncode or len(stdout.splitlines())!=1 or json.loads(stdout)!=receipt:
                raise ValueError('receiver failure: '+stderr)
            validated=oracle.verify(p,capture)
            if receipt!=validated: raise ValueError('receipt/capture mismatch')
            return checked_result(p,args.backend,json.loads(produced.stdout),validated,digest)
        finally:
            if receiver.poll() is None: receiver.terminate()
            receiver.communicate(timeout=10)


def main():
    args,p=parse()
    try:
        print(json.dumps(execute(args,p),separators=(',',':')))
        return 0
    except Failure as error:
        print(json.dumps(dict(status=error.status,start_issued=False,diagnostic=error.message)),file=sys.stderr)
        return error.code
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps(dict(status='error',diagnostic=str(error))),file=sys.stderr)
        return 1
if __name__=='__main__': sys.exit(main())
