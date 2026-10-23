#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Physical paired HFT replay measurement and preprovisioned remote UDP peer."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import re
import select
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import oracle
import run as correctness

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
ARMS=('posix','uring-fixed-zc','session')
PROFILE_KEYS=set('schema record_bytes payload_bytes burst_packets depth bursts actors seed'.split())
TRIAL_KEYS=set('pair order backend session_base source_sha profile setup_started_ns setup_completed_ns teardown_started_ns teardown_completed_ns registration_calls stop_ret correctness_verified samples'.split())
SAMPLE_KEYS=set('burst first_generation packet_count validated_packets validated_bytes read_submissions send_submissions started_ns local_release_ns peer_receipt_ns completed_ns elapsed_ns local_release_complete receiver_receipt guards_ok'.split())
MAX_FRAME=1048576


def require(test,message):
    if not test: raise ValueError(message)


def fields(value,keys):
    require(type(value) is dict and set(value)==set(keys),'schema fields')


def integer(value,minimum=0,maximum=2**64-1):
    require(type(value) is int and minimum<=value<=maximum,'integer range/type')
    return value


def digest(value,length=64):
    require(type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None,'digest')


def text(value):
    require(type(value) is str and bool(value.strip()),'nonempty string')


def validate_profile(p):
    fields(p,PROFILE_KEYS)
    for value in p.values(): integer(value)
    require(p['schema']==1 and p['record_bytes'] in (64,128,256) and p['payload_bytes'] in (512,1024)
        and p['payload_bytes']%p['record_bytes']==0 and p['actors']==1
        and 1<=p['burst_packets']<=32 and 1<=p['depth']<=8 and 1<=p['bursts']<=32,'hardware profile')


def paired_order(pairs,seed):
    integer(pairs,1,100);integer(seed)
    rng=random.Random(seed);result=[]
    for _ in range(pairs):
        row=list(ARMS);rng.shuffle(row);result.append(row)
    return result


def validate_admission(receipt,role):
    require(role in ('producer','peer'),'role')
    keys=set('schema role product_sha environment kernel nic'.split())
    if role=='producer': keys|={'source','bpf'}
    fields(receipt,keys)
    require(type(receipt['schema']) is int and receipt['schema']==1 and receipt['role']==role,'admission identity')
    digest(receipt['product_sha'],40)
    e=receipt['environment'];fields(e,('kind','verified','hypervisor','evidence'))
    require(e['kind']=='physical' and e['verified'] is True and e['hypervisor'] is False,'physical proof')
    require(type(e['evidence']) is list and bool(e['evidence']),'physical evidence')
    for observation in e['evidence']: text(observation)
    k=receipt['kernel'];fields(k,('release','config_release','config_sha256','strict_zero_copy'))
    text(k['release']);require(k['release']==k['config_release'],'running config release');digest(k['config_sha256'])
    require(type(k['strict_zero_copy']) is bool and (role=='peer' or k['strict_zero_copy'] is True),'strict zero-copy kernel')
    nic=receipt['nic'];fields(nic,('ifname','pci_bdf','driver','mtu','queue','zero_copy','copy_mode'))
    for key in ('ifname','pci_bdf','driver'):text(nic[key])
    integer(nic['mtu'],1);integer(nic['queue'],0,2**32-1)
    require(type(nic['zero_copy']) is bool and (role=='peer' or nic['zero_copy'] is True) and nic['copy_mode'] is False,'native NIC mode')
    if role=='peer':return
    s=receipt['source'];fields(s,'block_namespace ng_namespace read_only slba nlb lba_bytes capacity_bytes dio_mem_align dio_offset_align payload_bytes groups observed_sha256 reference_sha256'.split())
    text(s['block_namespace']);require(s['block_namespace']==s['ng_namespace'] and s['read_only'] is True,'source identity/read-only')
    for key in ('slba','nlb','lba_bytes','capacity_bytes','dio_mem_align','dio_offset_align','payload_bytes','groups'):integer(s[key],0 if key=='slba' else 1)
    require(s['lba_bytes'] in (512,1024,2048,4096) and s['payload_bytes'] in (512,1024),'source geometry')
    require(s['payload_bytes']%s['lba_bytes']==0 and s['slba']<=s['capacity_bytes']//s['lba_bytes']
        and s['nlb']<=s['capacity_bytes']//s['lba_bytes']-s['slba']
        and s['nlb']*s['lba_bytes']>=s['groups']*s['payload_bytes'],'source window')
    require(512%s['dio_mem_align']==0 and s['payload_bytes']%s['dio_offset_align']==0
        and (s['slba']*s['lba_bytes'])%s['dio_offset_align']==0 and s['payload_bytes']+68<=nic['mtu'],'DIO/MTU geometry')
    digest(s['observed_sha256']);digest(s['reference_sha256']);require(s['observed_sha256']==s['reference_sha256'],'source/reference bytes')
    b=receipt['bpf'];fields(b,('object_sha256','btf_sha256','source_sha256','target_matches'))
    for key in ('object_sha256','btf_sha256','source_sha256'):digest(b[key])
    require(b['target_matches'] is True,'BPF build/target binding')


def validate_trial(t,profile,warmup):
    fields(t,TRIAL_KEYS);validate_profile(profile);integer(warmup,0,32);require(warmup+profile['bursts']<=32,'warmup bound');require(t['profile']==profile,'unequal profile')
    integer(t['pair']);integer(t['order'],0,2);require(t['backend'] in ARMS,'backend')
    integer(t['session_base'],1,2**64-profile['actors']);digest(t['source_sha'])
    require(t['correctness_verified'] is True,'fresh complete correctness')
    require(t['registration_calls'] is None if t['backend']=='posix' else type(t['registration_calls']) is int and t['registration_calls']==1,'once registration')
    require((type(t['stop_ret']) is int and t['stop_ret']==0) if t['backend']=='session' else t['stop_ret'] is None,'STOP/release')
    for key in ('setup_started_ns','setup_completed_ns','teardown_started_ns','teardown_completed_ns'):integer(t[key])
    require(t['setup_started_ns']<=t['setup_completed_ns'] and t['teardown_started_ns']<=t['teardown_completed_ns'],'setup/teardown order')
    samples=t['samples'];require(type(samples) is list and len(samples)==profile['bursts'],'sample count')
    previous=t['setup_completed_ns']
    for index,s in enumerate(samples):
        fields(s,SAMPLE_KEYS)
        for key in SAMPLE_KEYS-{'local_release_complete','receiver_receipt','guards_ok'}:integer(s[key])
        for key in ('local_release_complete','receiver_receipt','guards_ok'):require(s[key] is True,'incomplete release/receipt/guards')
        count=profile['burst_packets']
        require(s['burst']==index and s['first_generation']==(warmup+index)*count+1,'warmup/generation window')
        require(all(s[key]==count for key in ('packet_count','validated_packets','read_submissions','send_submissions'))
            and s['validated_bytes']==count*profile['payload_bytes'],'sample complete bytes/counts')
        require(previous<=s['started_ns']<=s['local_release_ns']<=s['completed_ns']
            and s['started_ns']<=s['peer_receipt_ns']<=s['completed_ns']
            and s['elapsed_ns']==s['completed_ns']-s['started_ns'] and s['elapsed_ns']>0,'timer endpoints')
        previous=s['completed_ns']
    require(t['teardown_started_ns']>=previous,'early teardown')


def paired_summary(trials):
    require(type(trials) is list and bool(trials) and len(trials)%3==0,'unpaired trials')
    for trial in trials:fields(trial,TRIAL_KEYS)
    profile=trials[0]['profile'];validate_profile(profile);source=trials[0]['source_sha'];result=[];nonces=set();first_generation=None
    for pair in range(len(trials)//3):
        rows=trials[pair*3:pair*3+3]
        require({t['backend'] for t in rows}==set(ARMS),'duplicate/missing arm')
        for order,t in enumerate(rows):
            require(t['pair']==pair and t['order']==order and t['profile']==profile and t['source_sha']==source,'unequal paired source/profile/order')
            require(t['session_base'] not in nonces,'reused nonce');nonces.add(t['session_base'])
            require(type(t['samples']) is list and len(t['samples'])==profile['bursts'],'sample count')
            fields(t['samples'][0],SAMPLE_KEYS)
            count=profile['burst_packets'];first=t['samples'][0]['first_generation'];integer(first,1)
            if first_generation is None:first_generation=first
            require(first==first_generation,'unequal warmup window')
            require((first-1)%count==0,'generation alignment')
            validate_trial(t,profile,(first-1)//count)
            require(len(t['samples'])==len(trials[0]['samples']),'unequal sample count')
        totals={t['backend']:sum(s['elapsed_ns'] for s in t['samples']) for t in rows}
        result.append(dict(pair=pair,order=[t['backend'] for t in rows],total_completion_ns=totals,
            ratio_posix_over_session=totals['posix']/totals['session'],ratio_fixed_over_session=totals['uring-fixed-zc']/totals['session']))
    return result


def validate_result(result):
    fields(result,'schema status scenario mode scope profile order_seed pairs warmup_bursts admission trials paired_summary'.split())
    require(type(result['schema']) is int and result['schema']==1 and result['status']=='ok' and result['scenario']=='hft_replay'
        and result['mode']=='performance' and result['scope']=='physical-paired-roundtrip','result identity')
    p=result['profile'];validate_profile(p);integer(result['warmup_bursts'],0,32);require(result['warmup_bursts']+p['bursts']<=32,'combined burst bound')
    schedule=paired_order(result['pairs'],result['order_seed']);fields(result['admission'],('producer','peer'))
    for role in ('producer','peer'):validate_admission(result['admission'][role],role)
    a=result['admission'];require(a['producer']['product_sha']==a['peer']['product_sha'],'peer product mismatch')
    source=a['producer']['source'];require(source['payload_bytes']==p['payload_bytes'] and source['groups']==(result['warmup_bursts']+p['bursts'])*p['burst_packets'],'admitted profile/window')
    require(type(result['trials']) is list and len(result['trials'])==result['pairs']*3,'trial count')
    for index,t in enumerate(result['trials']):
        validate_trial(t,p,result['warmup_bursts'])
        require(t['backend']==schedule[index//3][index%3] and t['source_sha']==source['observed_sha256'],'paired schedule/source')
    require(result['paired_summary']==paired_summary(result['trials']),'paired summary')


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
    return h.hexdigest()


def endpoint(value):
    try:
        ip,port=value.rsplit(':',1);socket.inet_pton(socket.AF_INET,ip)
        require(re.fullmatch('[0-9]+',port) is not None and 0<int(port)<=65535,'port')
        return ip,int(port)
    except (ValueError,OSError) as error:raise argparse.ArgumentTypeError('IPv4:port required') from error


def parse():
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    parser.add_argument('action',choices=('measure','peer','qualify'))
    parser.add_argument('--directory',type=Path)
    parser.add_argument('--qualification',type=Path)
    parser.add_argument('--measurement-policy',default='benchmark-policy-v1',choices=('benchmark-policy-v1',))
    for key in ('ifname','kernel-config','product-sha','source-block','source-ng','local-ip','peer-ip','local-mac','peer-mac','bpf-object','reference'):
        parser.add_argument('--'+key,default='')
    for key in ('bind','data-bind','peer-control'):parser.add_argument('--'+key,type=endpoint)
    defaults=dict(records=64,payload=512,burst=32,depth=8,bursts=8,actors=1,seed=1,warmup_bursts=1,pairs=5,order_seed=1,
        slba=0,nlb=0,queue=0,local_port=0,peer_port=0)
    for key,value in defaults.items():parser.add_argument('--'+key.replace('_','-'),type=correctness.decimal,default=value)
    seen=set()
    for arg in sys.argv[1:]:
        if arg.startswith('--'):
            key=arg.split('=',1)[0]
            if key in seen:parser.error('duplicate option '+key)
            seen.add(key)
    args=parser.parse_args()
    common={'--help','--directory','--ifname','--kernel-config','--product-sha','--measurement-policy'}
    if args.action=='peer' and not seen<=common|{'--bind','--data-bind'}:parser.error('measure options are not peer options')
    if args.action!='peer' and seen&{'--bind','--data-bind'}:parser.error('peer bind options are not measure options')
    if args.directory is not None and not args.directory.is_dir():parser.error('directory must exist')
    if args.product_sha and re.fullmatch('[0-9a-f]{40}',args.product_sha) is None:parser.error('product SHA must be lowercase40hex')
    if (args.records not in (64,128,256) or args.payload not in (512,1024,4096) or args.payload%args.records
        or args.actors not in (1,4) or not 1<=args.burst<=32 or not 1<=args.depth<=8 or not 1<=args.bursts<=32
        or not 0<=args.warmup_bursts<=32 or args.warmup_bursts+args.bursts>32 or not 1<=args.pairs<=100
        or args.local_port>65535 or args.peer_port>65535 or args.queue>=2**32):parser.error('profile/port range')
    for value in (args.local_ip,args.peer_ip):
        if value:
            try:socket.inet_pton(socket.AF_INET,value)
            except OSError:parser.error('IPv4 required')
    for value in (args.local_mac,args.peer_mac):
        if value and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',value) is None:parser.error('MAC required')
    return args


def refusal(message,status='not_run_hardware'):raise correctness.Failure(status,message)


def main():
    args=parse()
    try:
        if args.action=='peer':serve_benchmark_peer(args)
        elif args.action=='qualify':print(json.dumps(qualify_benchmark(args),separators=(',',':')))
        else:print(json.dumps(measure(args),separators=(',',':')))
        return 0
    except correctness.Failure as error:
        print(json.dumps(dict(status=error.status,start_issued=False,diagnostic=error.message)),file=sys.stderr);return 4
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps(dict(status='error',diagnostic=str(error))),file=sys.stderr);return 1


def send_message(stream,value):
    data=canonical(value);require(0<len(data)<=MAX_FRAME,'control frame bound')
    stream.sendall(struct.pack('!I',len(data))+data)


def exact_read(stream,n):
    out=bytearray()
    while len(out)<n:
        chunk=stream.recv(n-len(out))
        if not chunk:raise ValueError('early peer control exit')
        out.extend(chunk)
    return bytes(out)


def receive_message(stream):
    n=struct.unpack('!I',exact_read(stream,4))[0];require(0<n<=MAX_FRAME,'control receive bound')
    value=json.loads(exact_read(stream,n));require(type(value) is dict,'control object');return value


def rpc(stream,request,op):
    send_message(stream,request);reply=receive_message(stream)
    require(type(reply.get('version')) is int and reply['version']==1 and reply.get('op')==op,'peer protocol operation/version')
    if reply.get('status')!='ok':raise ValueError('peer error: '+str(reply.get('diagnostic','negative receipt')))
    return reply


def identity_for(p,source_sha,product_sha):
    return dict(token=secrets.token_hex(16),manifest_sha256=hashlib.sha256(canonical(p)).hexdigest(),
        session_base=p['session_base'],source_sha=source_sha,product_sha=product_sha)


def same_identity(reply,identity):
    require(canonical(reply.get('identity'))==canonical(identity),'stale/foreign run control receipt')


def producer_command(args,p,backend,broker,mode='correctness'):
    from hardware_gate import BIN
    command=[str(getattr(args,'_binary_fd_path',BIN)),backend,args.reference,str(p['record_bytes']),str(p['payload_bytes']),str(p['burst_packets']),str(p['depth']),
        str(p['bursts']),str(p['actors']),str(p['seed']),args.peer_ip,str(args.peer_port),broker[0],str(broker[1]),
        args.source_block,args.source_ng,str(args.slba),str(args.nlb),args.ifname,str(args.queue),args.local_ip,
        args.local_mac,args.peer_mac,str(args.local_port),args.bpf_object,args.kernel_config,
        str(args.slba*args._source_lba),mode,str(p['session_base'])]
    if mode in ('hardware','benchmark-probe'):command.append(str(args.warmup_bursts) if mode=='hardware' else '0')
    return command


class BurstBroker:
    """Run-owned local UDP to nonce-checked remote TCP; no payload transfer."""
    def __init__(self,stream,p,identity):
        self.stream,self.p,self.identity=stream,p,identity
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.socket.bind(('127.0.0.1',0));self.socket.settimeout(0.1)
        self.address=self.socket.getsockname();self.stop=threading.Event();self.error=None
        self.thread=threading.Thread(target=self.work,daemon=True);self.thread.start()
    def work(self):
        expected_first=0;client=None
        try:
            while not self.stop.is_set():
                try:data,client=self.socket.recvfrom(4096)
                except socket.timeout:continue
                request=json.loads(data);fields(request,('op','actor','first','count','session_base'))
                require(request['op']=='receipt' and type(request['actor']) is int and request['actor']==0
                    and type(request['first']) is int and request['first']==expected_first
                    and type(request['count']) is int and request['count']==self.p['burst_packets']
                    and type(request['session_base']) is int and request['session_base']==self.p['session_base'],'local broker nonce/sequence')
                reply=rpc(self.stream,dict(version=1,op='BURST',identity=self.identity,actor=0,
                    first_generation=expected_first+1,packet_count=self.p['burst_packets']),'BURST_RECEIPT')
                same_identity(reply,self.identity)
                fields(reply,('version','op','status','identity','actor','first_generation','packet_count','validated_packets','validated_bytes'))
                for key in ('version','actor','first_generation','packet_count','validated_packets','validated_bytes'):integer(reply[key])
                require(reply.get('actor')==0 and reply.get('first_generation')==expected_first+1
                    and reply.get('packet_count')==self.p['burst_packets']
                    and reply.get('validated_packets')==self.p['burst_packets']
                    and reply.get('validated_bytes')==self.p['burst_packets']*self.p['payload_bytes'],'remote burst complete receipt')
                response=dict(status='ok',actor=0,first=expected_first,count=self.p['burst_packets'],
                    validated_bytes=reply['validated_bytes'],session_base=self.p['session_base'])
                self.socket.sendto(json.dumps(response,separators=(',',':')).encode(),client)
                expected_first+=self.p['burst_packets']
        except (OSError,ValueError,KeyError,TypeError) as error:
            self.error=error
            if client is not None:
                try:self.socket.sendto(b'{"status":"error"}',client)
                except OSError:pass
    def close(self):
        self.stop.set();self.thread.join(timeout=25)
        if self.thread.is_alive():raise ValueError('burst broker failed to stop')
        self.socket.close()
        if self.error:raise ValueError('burst broker: '+str(self.error))


class PeerRun:
    def __init__(self,args,hello,admission):
        fields(hello,('version','op','identity','profile','producer_admission','warmup_bursts','measured_bursts'))
        require(type(hello['version']) is int and hello['version']==1 and hello['op']=='HELLO','HELLO protocol')
        p=hello['profile'];fields(p,PROFILE_KEYS|{'session_base'});validate_profile({k:v for k,v in p.items() if k!='session_base'})
        integer(p['session_base'],1,2**64-1);integer(hello['warmup_bursts'],0,32);integer(hello['measured_bursts'],1,32)
        require(hello['warmup_bursts']+hello['measured_bursts']==p['bursts'],'HELLO burst window')
        self.identity=hello['identity'];fields(self.identity,('token','manifest_sha256','session_base','source_sha','product_sha'))
        require(type(self.identity['token']) is str and re.fullmatch('[0-9a-f]{32}',self.identity['token']) is not None,'run token')
        require(self.identity['manifest_sha256']==hashlib.sha256(canonical(p)).hexdigest()
            and self.identity['session_base']==p['session_base'] and self.identity['product_sha']==admission['product_sha'],'HELLO manifest/product/session')
        validate_admission(hello['producer_admission'],'producer')
        source=hello['producer_admission']['source']
        require(hello['producer_admission']['product_sha']==admission['product_sha']
            and self.identity['source_sha']==source['observed_sha256']
            and source['groups']==p['bursts']*p['burst_packets'] and source['payload_bytes']==p['payload_bytes'],'HELLO admitted source')
        if p['payload_bytes']+68>admission['nic']['mtu']:raise ValueError('peer MTU/profile')
        self.p=p;self.first=1;self.validator=oracle.Validator(p);self.condition=threading.Condition();self.error=None
        self.stop=threading.Event();self.finished=False;self.capture_streamed=False;self.acknowledged=False;self.capture_bytes=0
        self.directory=Path(tempfile.mkdtemp(prefix='.hft-peer-',dir=args.directory or ROOT))
        os.chmod(self.directory,0o700);self.capture=self.directory/'capture.bin';self.output=oracle.exclusive(self.capture)
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            self.udp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024);self.udp.bind(args.data_bind);self.udp.settimeout(0.1)
            self.thread=threading.Thread(target=self.receive,daemon=True);self.thread.start()
        except BaseException:self.udp.close();self.output.close();raise
    def receive(self):
        try:
            while not self.stop.is_set():
                try:data,_,flags,_=self.udp.recvmsg(self.p['payload_bytes']+40,0)
                except socket.timeout:continue
                with self.condition:
                    if flags&socket.MSG_TRUNC:raise ValueError('peer MSG_TRUNC')
                    self.validator.add(data);self.output.write(struct.pack('!I',len(data))+data)
                    self.capture_bytes+=len(data)+4
                    require(self.capture_bytes<=self.validator.count*(self.p['payload_bytes']+44),'peer capture bound')
                    self.condition.notify_all()
        except (OSError,ValueError) as error:
            with self.condition:self.error=error;self.condition.notify_all()
    def burst(self,request):
        fields(request,('version','op','identity','actor','first_generation','packet_count'));same_identity(request,self.identity)
        require(type(request['version']) is int and request['version']==1 and request['op']=='BURST' and type(request['actor']) is int and request['actor']==0
            and type(request['first_generation']) is int and request['first_generation']==self.first
            and type(request['packet_count']) is int and request['packet_count']==self.p['burst_packets'],'peer burst request sequence')
        first=self.first;count=self.p['burst_packets'];deadline=time.monotonic()+20
        with self.condition:
            while not all((0,g) in self.validator.seen for g in range(first-1,first-1+count)):
                if self.error:raise ValueError('peer receive: '+str(self.error))
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ValueError('peer missing burst')
                self.condition.wait(min(remaining,0.1))
            if self.error:raise ValueError(str(self.error))
        self.first+=count
        return dict(version=1,op='BURST_RECEIPT',status='ok',identity=self.identity,actor=0,
            first_generation=first,packet_count=count,validated_packets=count,validated_bytes=count*self.p['payload_bytes'])
    def finish(self,request):
        fields(request,('version','op','identity'));same_identity(request,self.identity)
        require(type(request['version']) is int and request['version']==1 and request['op']=='FINISH' and not self.finished,'FINISH state')
        require(self.first==self.validator.count+1,'missing burst receipts')
        # A bounded quiet interval allows queued extras to reach the same parser.
        with self.condition:
            self.condition.wait(0.15)
            if self.error:raise ValueError(str(self.error))
        self.stop.set();self.thread.join(timeout=2);require(not self.thread.is_alive(),'peer receiver stop')
        if self.error:raise ValueError(str(self.error))
        self.output.flush();self.output.close();self.udp.close()
        validated=oracle.verify(self.p,self.capture);require(validated==self.validator.finish(),'peer capture/full-set mismatch')
        self.finished=True
        return dict(version=1,op='FINISH_RECEIPT',status='ok',identity=self.identity,actor=0,first_generation=1,
            packet_count=self.validator.count,**{k:v for k,v in validated.items() if k!='status'},capture_bytes=self.capture.stat().st_size,capture_sha256=sha(self.capture))
    def close(self):
        self.stop.set();self.thread.join(timeout=2)
        if not self.output.closed:self.output.close()
        self.udp.close()
        directory=getattr(self,'directory',self.capture.parent)
        if self.finished and getattr(self,'acknowledged',False) and not self.error:
            shutil.rmtree(directory)
        else:
            failure=dict(status='error',diagnostic=str(self.error or 'peer run ended before producer capture acknowledgement'))
            path=directory/'failure.json'
            if not path.exists():
                with oracle.exclusive(path) as out:out.write(canonical(failure))


def serve_peer(args):
    from hardware_gate import collect
    admission=collect(args,'peer');validate_admission(admission,'peer')
    # Actual local admission above precedes even socket creation/listening.
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.bind(args.bind);listener.listen(1)
        while True:
            connection,_=listener.accept()
            with connection:
                connection.settimeout(30);state=None;used=set()
                try:
                    send_message(connection,dict(version=1,op='ADMISSION',status='ok',admission=admission,data_bind=list(args.data_bind)))
                    while True:
                        request=receive_message(connection);op=request.get('op')
                        if op=='HELLO':
                            try:observed=collect(args,'peer')
                            except correctness.Failure as error:raise ValueError('peer admission changed: '+error.message) from error
                            require(canonical(observed)==canonical(admission),'peer software/device tuple changed')
                            require(state is None,'concurrent peer run')
                            nonce=request.get('identity',{}).get('session_base');require(nonce not in used,'earlier run wire nonce')
                            state=PeerRun(args,request,admission);used.add(nonce)
                            send_message(connection,dict(version=1,op='READY',status='ok',identity=state.identity,admission=admission,data_bind=list(args.data_bind)))
                        elif op=='BURST':
                            require(state is not None,'BURST before HELLO');send_message(connection,state.burst(request))
                        elif op=='FINISH':
                            require(state is not None,'FINISH before HELLO');send_message(connection,state.finish(request))
                        elif op=='CAPTURE':
                            fields(request,('version','op','identity'));require(state is not None and state.finished,'capture before FINISH');same_identity(request,state.identity)
                            with state.capture.open('rb') as stream:
                                sequence=0
                                for data in iter(lambda:stream.read(65536),b''):
                                    send_message(connection,dict(version=1,op='CAPTURE_CHUNK',status='ok',identity=state.identity,sequence=sequence,data=base64.b64encode(data).decode()));sequence+=1
                            send_message(connection,dict(version=1,op='CAPTURE_END',status='ok',identity=state.identity,chunks=sequence,bytes=state.capture.stat().st_size,sha256=sha(state.capture)))
                            state.capture_streamed=True
                        elif op=='CAPTURE_ACK':
                            fields(request,('version','op','identity','capture_sha256'))
                            require(state is not None and state.finished and state.capture_streamed,'ACK before capture transfer')
                            same_identity(request,state.identity)
                            require(type(request['version']) is int and request['version']==1 and request['capture_sha256']==sha(state.capture),'capture ACK digest')
                            state.acknowledged=True
                            send_message(connection,dict(version=1,op='CAPTURE_STORED',status='ok',identity=state.identity))
                            state.close();state=None
                        elif op=='CLOSE':
                            fields(request,('version','op'));require(type(request['version']) is int and request['version']==1 and state is None,'CLOSE state')
                            send_message(connection,dict(version=1,op='CLOSED',status='ok'));break
                        else:raise ValueError('unknown peer operation')
                except (OSError,ValueError,KeyError,TypeError) as error:
                    if state is not None:state.error=error
                    try:send_message(connection,dict(version=1,op='ERROR',status='error',diagnostic=str(error)))
                    except OSError:pass
                finally:
                    if state is not None:state.close()


def run_producer(command,broker=None,artifact_dir=None,pass_fds=()):
    """Execute the admitted binary; never replay an accepted failed trial."""
    process=None;out=b'';err=b'';diagnostic=None
    try:
        process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=pass_fds)
        deadline=time.monotonic()+180
        while True:
            try:
                out,err=process.communicate(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                # communicate drains verifier diagnostics while the backend
                # runs, so a full stderr pipe cannot deadlock native setup.
                if time.monotonic()>deadline:raise ValueError('producer timeout; no release certificate')
        if broker is not None and broker.error:raise ValueError('peer/broker failed; producer completed its cleanup: '+str(broker.error)+'; '+err.decode('utf-8',errors='replace'))
        if process.returncode==4:refusal('native/registered capability refused before START: '+err.decode('utf-8',errors='replace'),'not_run_capability')
        require(process.returncode==0,'producer runtime/ownership failure: '+err.decode('utf-8',errors='replace'))
        require(len(out.splitlines())==1,'producer result count')
        return json.loads(out)
    except BaseException as error:
        diagnostic=str(error)
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                # Termination never becomes a release/STOP certificate.
                process.terminate()
            out,err=process.communicate(timeout=15)
        if artifact_dir is not None:
            artifact_dir=Path(artifact_dir)
            for name,data in (('producer.stdout',out),('producer.stderr',err)):
                with oracle.exclusive(artifact_dir/name) as output:output.write(data)
            with oracle.exclusive(artifact_dir/'producer-exit.json') as output:
                output.write(canonical(dict(status='error' if diagnostic else 'ok',
                    returncode=process.returncode if process is not None else None,diagnostic=diagnostic)))


def native_probe(args,p,directory):
    """Real setup/CREATE/STATS/STOP, never START, before network measurement."""
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as control:
        control.bind(('127.0.0.1',0))
        result=run_producer(producer_command(args,p,'session',control.getsockname(),'probe'),artifact_dir=directory)
    require(result.get('read_submissions')==0 and result.get('send_submissions')==0 and result.get('stop_ret')==0,'probe performed workload or failed STOP')
    probe=result.get('probe');fields(probe,('xdp_zero_copy','strict_create','nvme_map_id','afxdp_map_id'))
    require(probe['xdp_zero_copy'] is True and probe['strict_create'] is True,'actual native XSK/CREATE admission')
    integer(probe['nvme_map_id'],1);integer(probe['afxdp_map_id'],1)
    with oracle.exclusive(directory/'native-admission.json') as out:out.write(canonical(result))
    return result


def capture_from_peer(stream,p,identity,finish,destination):
    count=p['burst_packets']*p['bursts'];maximum=count*(p['payload_bytes']+44)
    fields(finish,('version','op','status','identity','actor','first_generation','packet_count','validated_packets','validated_bytes','capture_bytes','capture_sha256'))
    for key in ('version','actor','first_generation','packet_count','validated_packets','validated_bytes','capture_bytes'):integer(finish[key])
    require(finish.get('actor')==0 and finish.get('first_generation')==1 and finish.get('packet_count')==count
        and finish.get('validated_packets')==count and finish.get('validated_bytes')==count*p['payload_bytes']
        and finish.get('capture_bytes')==maximum,'incomplete FINISH byte/packet receipt')
    digest(finish.get('capture_sha256'))
    send_message(stream,dict(version=1,op='CAPTURE',identity=identity));size=0;sequence=0
    with oracle.exclusive(destination) as output:
        while True:
            reply=receive_message(stream);same_identity(reply,identity)
            require(type(reply.get('version')) is int and reply['version']==1 and reply.get('status')=='ok','capture status/version')
            if reply.get('op')=='CAPTURE_END':
                fields(reply,('version','op','status','identity','chunks','bytes','sha256'))
                require(type(reply['chunks']) is int and reply['chunks']==sequence and type(reply['bytes']) is int and reply['bytes']==size
                    and reply['sha256']==finish['capture_sha256'],'capture terminal receipt');break
            fields(reply,('version','op','status','identity','sequence','data'))
            require(reply['op']=='CAPTURE_CHUNK' and type(reply['sequence']) is int and reply['sequence']==sequence,'capture chunk sequence')
            require(type(reply['data']) is str and len(reply['data'])<=90000,'capture encoded chunk bound')
            data=base64.b64decode(reply['data'],validate=True);require(0<len(data)<=65536,'capture chunk bound')
            size+=len(data);require(size<=maximum,'capture total bound');output.write(data);sequence+=1
    require(size==maximum and sha(destination)==finish['capture_sha256'],'capture digest/size mismatch')
    validated=oracle.verify(p,destination)
    require(validated==dict(status='ok',validated_packets=count,validated_bytes=count*p['payload_bytes']),'producer full-capture byte validation')
    return validated


def execute_remote(args,stream,admissions,p,backend,directory,measured=False):
    identity=identity_for(p,admissions['producer']['source']['observed_sha256'],args.product_sha)
    ready=rpc(stream,dict(version=1,op='HELLO',identity=identity,profile=p,
        producer_admission=admissions['producer'],warmup_bursts=args.warmup_bursts,measured_bursts=args.bursts),'READY')
    same_identity(ready,identity)
    require(canonical(ready.get('admission'))==canonical(admissions['peer']) and canonical(ready.get('data_bind'))==canonical([args.peer_ip,args.peer_port]),'peer readiness/admission/address changed')
    broker=BurstBroker(stream,p,identity)
    try:
        try:
            raw=run_producer(producer_command(args,p,backend,broker.address,'hardware' if measured else 'correctness'),broker,artifact_dir=directory)
        except correctness.Failure as error:
            if getattr(args,'_workload_issued',False):raise ValueError('capability loss after earlier accepted trial; partial comparison retained: '+error.message) from error
            raise
        args._workload_issued=True
    finally:broker.close()
    finish=rpc(stream,dict(version=1,op='FINISH',identity=identity),'FINISH_RECEIPT');same_identity(finish,identity)
    validated=capture_from_peer(stream,p,identity,finish,directory/'capture.bin')
    stored=rpc(stream,dict(version=1,op='CAPTURE_ACK',identity=identity,capture_sha256=finish['capture_sha256']),'CAPTURE_STORED')
    same_identity(stored,identity)
    if backend=='session':
        native=raw.get('native_runtime');fields(native,('xdp_zero_copy','strict_create','nvme_map_id','afxdp_map_id'))
        require(native['xdp_zero_copy'] is True and native['strict_create'] is True,'trial native admission changed')
        integer(native['nvme_map_id'],1);integer(native['afxdp_map_id'],1)
    counts={k:v for k,v in raw.items() if k not in ('measurements','probe','native_runtime')}
    correctness.checked_result(p,backend,counts,validated,admissions['producer']['source']['observed_sha256'])
    # Preserve actual completion facts, binary hash, admission and raw clock
    # observations in private artifacts without expanding the frozen schemas.
    with oracle.exclusive(directory/'observations.json') as out:
        out.write(canonical(dict(identity=identity,producer=raw,peer_finish=finish,
            binary_sha256=sha(correctness.BIN),cache_policy='O_DIRECT-read-only-same-window')))
    return raw


def select_measurement_policy(name):
    if name!='benchmark-policy-v1':raise ValueError('explicit benchmark-policy-v1 required')
    return dict(measurement_policy=name,wire_version=1,map_names=['hftb_nvme_ops','hftb_afxdp_ops'],
        bpf_source=str(ROOT/'kernel/tools/xdev_ext_mech/hft_benchmark.bpf.c'))


class BenchmarkCapture:
    """Preallocated immutable-slot capture; online code inspects only 40 header bytes."""
    def __init__(self,profile,identity,capacity_bytes,observer=None,reserved_storage=None):
        from campaign_oracle import profile as check_profile
        self.p=dict(profile);self.count=check_profile(self.p);self.identity=dict(identity)
        require(self.identity.get('session_base')==self.p['session_base'] and bool(self.identity.get('token')),'capture identity')
        self.stride=self.p['payload_bytes']+40
        require(type(capacity_bytes) is int and capacity_bytes>=self.count*self.stride,'capture capacity before READY')
        self.storage=bytearray(self.count*self.stride) if reserved_storage is None else reserved_storage
        require(len(self.storage)==self.count*self.stride,"actual reserved storage size")
        self.arrivals=[None]*self.count;self.seen=set();self.used=0;self.poisoned=False;self.observer=observer
    @property
    def packets(self):
        return [bytes(self.storage[i*self.stride:(i+1)*self.stride]) for i in range(self.used)]
    def capture_receive(self,data,truncation=False,arrival_metadata=None):
        from campaign_oracle import header
        try:
            require(not self.poisoned and not truncation and len(data)==self.stride,'truncated/poisoned capture')
            generation=int.from_bytes(data[16:20],'big')
            require(1<=generation<=self.count and generation not in self.seen and self.used<self.count,'capture generation set')
            require(bytes(data[:40])==header(self.p['session_base'],generation,self.p['payload_bytes']),'capture header identity')
            slot=self.used;offset=slot*self.stride
            self.storage[offset:offset+self.stride]=data
            # Publish identity only after the complete copy into the reserved slot.
            self.arrivals[slot]=(generation,arrival_metadata);self.seen.add(generation);self.used+=1
            if self.observer:self.observer('capture_commit',dict(slot=slot,generation=generation))
            return slot
        except (ValueError,TypeError,OverflowError):
            self.poisoned=True
            raise ValueError('rejected receive poisons campaign capture')
    def received_receipt(self,first,count,identity):
        require(not self.poisoned and dict(identity)==self.identity,'receipt identity/poison')
        require(type(first) is int and type(count) is int and first>=1 and count>=1 and first+count-1<=self.count,'receipt range')
        require(all(g in self.seen for g in range(first,first+count)),'receipt before complete capture commit')
        receipt=dict(version=2,op='BURST_RECEIPT',status='received',identity=dict(self.identity),
            first_generation=first,packet_count=count,received_packets=count,received_bytes=count*self.p['payload_bytes'])
        if self.observer:self.observer('received_receipt',dict(first_generation=first,packet_count=count))
        return receipt


def finalize_campaign(manifest,captures,guards,source_reference,observer=None,wire_frames=None):
    require(manifest.get('workload_complete') is True and manifest.get('local_release_complete') is True,'campaign is not drained')
    for trial in manifest.get('trials',[]):
        require(trial.get('backend')!='session' or trial.get('stop_ret')==0,'native STOP failed')
    if observer:observer('oracle_begin',{})
    from campaign_oracle import verify_campaign
    result=verify_campaign(manifest,captures,guards,source_reference)
    if wire_frames is not None:_strict_final_wire(manifest,wire_frames,captures)
    if observer:observer('oracle_done',result);observer('success_publish',result)
    return result


class BenchmarkPeerRun:
    """HFT1 peer. Receipt certifies RAM capture, never payload validation."""
    def __init__(self,args,profile,identity,storage,wire_storage):
        self.p=dict(profile);self.identity=dict(identity);self.first=1
        self.capture=BenchmarkCapture(profile,identity,len(storage),reserved_storage=storage)
        self.wire_storage=wire_storage;self.wire_stride=profile['payload_bytes']+82
        self.wire_arrivals=[None]*self.capture.count;self.wire_seen=set();self.wire_used=0
        self.condition=threading.Condition();self.error=None;self.stop=threading.Event();self.finished=False
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
        try:
            self.raw.bind((args.ifname,0));self.raw.settimeout(0.1)
            self.udp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
            self.udp.bind(args.data_bind);self.udp.settimeout(0.1)
            self.thread=threading.Thread(target=self.receive,daemon=True)
            self.raw_thread=threading.Thread(target=self.receive_wire,daemon=True)
            self.raw_thread.start();self.thread.start()
        except BaseException:self.udp.close();self.raw.close();raise
    def receive(self):
        try:
            while not self.stop.is_set():
                try:data,_,flags,_=self.udp.recvmsg(self.p['payload_bytes']+40,0)
                except socket.timeout:continue
                with self.condition:
                    self.capture.capture_receive(data,bool(flags&socket.MSG_TRUNC))
                    self.condition.notify_all()
        except (OSError,ValueError) as error:
            with self.condition:self.error=error;self.condition.notify_all()
    def receive_wire(self):
        try:
            while not self.stop.is_set():
                try:data,_,flags,_=self.raw.recvmsg(self.wire_stride+1,0)
                except socket.timeout:continue
                # Ignore unrelated traffic using only fixed headers. All candidate
                # HFT1 frame bytes are retained, including malformed candidates.
                if len(data)<82 or data[12:14]!=b'\x08\x00' or data[23]!=17 or data[42:46]!=b'HFT1':continue
                if int.from_bytes(data[50:58],'big')!=self.p['session_base']:continue
                with self.condition:
                    require(not flags&socket.MSG_TRUNC and len(data)==self.wire_stride,'raw wire truncation/geometry')
                    generation=int.from_bytes(data[58:62],'big')
                    require(1<=generation<=self.capture.count and generation not in self.wire_seen,'wire generation set')
                    off=self.wire_used*self.wire_stride
                    self.wire_storage[off:off+self.wire_stride]=data
                    self.wire_arrivals[self.wire_used]=generation;self.wire_seen.add(generation);self.wire_used+=1
                    self.condition.notify_all()
        except (OSError,ValueError) as error:
            with self.condition:self.error=error;self.condition.notify_all()
    def burst(self,request):
        same_identity(request,self.identity)
        require(request.get('version')==2 and request.get('op')=='BURST' and request.get('first_generation')==self.first and request.get('packet_count')==self.p['burst_packets'],'strict burst sequence')
        first=self.first;count=self.p['burst_packets'];deadline=time.monotonic()+20
        with self.condition:
            while not all(g in self.capture.seen and g in self.wire_seen for g in range(first,first+count)):
                if self.error:raise ValueError(str(self.error))
                remaining=deadline-time.monotonic();require(remaining>0,'missing UDP/raw-wire burst')
                self.condition.wait(min(remaining,0.1))
            if self.error:raise ValueError(str(self.error))
            reply=self.capture.received_receipt(first,count,self.identity)
        self.first+=count;return reply
    def finish(self):
        require(self.first==self.capture.count+1,'missing burst receipt')
        with self.condition:self.condition.wait(0.15)
        self.stop.set();self.thread.join(timeout=2);self.raw_thread.join(timeout=2)
        require(not self.thread.is_alive() and not self.raw_thread.is_alive(),'strict receiver stop')
        if self.error:raise ValueError(str(self.error))
        require(self.capture.used==self.capture.count and self.wire_used==self.capture.count,'complete receive set')
        self.finished=True;self.udp.close();self.raw.close()
    def close(self):
        self.stop.set();self.thread.join(timeout=2);self.raw_thread.join(timeout=2);self.udp.close();self.raw.close()


def benchmark_rpc(stream,request,op,status='ok'):
    send_message(stream,request);reply=receive_message(stream)
    require(type(reply.get('version')) is int and reply['version']==2 and reply.get('op')==op and reply.get('status')==status,'strict peer operation/status')
    return reply


def serve_benchmark_peer(args):
    from hardware_gate import collect
    admission=collect(args,'peer')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.bind(args.bind);listener.listen(1)
        connection,_=listener.accept()
        with connection:
            connection.settimeout(30);states={};active=None
            try:
                send_message(connection,dict(version=2,op='ADMISSION',status='ok',admission=admission,data_bind=list(args.data_bind)))
                request=receive_message(connection)
                require(request.get('version')==2 and request.get('op')=='CAMPAIGN' and request.get('measurement_policy')=='benchmark-policy-v1','explicit strict campaign')
                plans=request['trials'];require(type(plans) is list and 3<=len(plans)<=300,'campaign trial bound')
                total=0;wire_total=0;seen=set();trial_ids=set();geometry=None
                from campaign_oracle import profile as check_profile
                for row in plans:
                    count=check_profile(row['profile']);p=row['profile'];identity=row['identity']
                    require(row['trial_id'] not in trial_ids and identity.get('session_base')==p['session_base'] and identity.get('token') not in seen,'fresh campaign identity')
                    require(type(identity.get('token')) is str and re.fullmatch('[0-9a-f]{32}',identity['token']) is not None,'fresh token format')
                    require(p['session_base'] not in seen,'fresh wire session');seen.update((identity['token'],p['session_base']));trial_ids.add(row['trial_id'])
                    shape={k:v for k,v in p.items() if k!='session_base'};require(geometry is None or shape==geometry,'campaign source/profile');geometry=shape
                    total+=count*(p['payload_bytes']+40);wire_total+=count*(p['payload_bytes']+82)
                # Actual reservations before CAMPAIGN_READY; no START has occurred.
                require(total+wire_total<=1024*1024*1024,'campaign RAM bound')
                storage=bytearray(total);wire_storage=bytearray(wire_total);off=0;wire_off=0
                for row in plans:
                    count=row['profile']['burst_packets']*row['profile']['bursts'];size=row['profile']['payload_bytes']
                    row['storage']=memoryview(storage)[off:off+count*(size+40)];off+=count*(size+40)
                    row['wire_storage']=memoryview(wire_storage)[wire_off:wire_off+count*(size+82)];wire_off+=count*(size+82)
                send_message(connection,dict(version=2,op='CAMPAIGN_READY',status='ok',capture_bytes=total,wire_bytes=wire_total))
                for row in plans:
                    request=receive_message(connection);same_identity(request,row['identity'])
                    require(request.get('op')=='HELLO' and request.get('version')==2 and request.get('trial_id')==row['trial_id'],'strict HELLO order')
                    active=BenchmarkPeerRun(args,row['profile'],row['identity'],row['storage'],row['wire_storage']);states[row['trial_id']]=active
                    send_message(connection,dict(version=2,op='READY',status='ok',identity=active.identity))
                    while True:
                        request=receive_message(connection);same_identity(request,active.identity)
                        if request.get('op')=='BURST':send_message(connection,active.burst(request))
                        elif request.get('op')=='FINISH':
                            require(request.get('version')==2,'strict FINISH version');active.finish()
                            send_message(connection,dict(version=2,op='FINISH_RECEIPT',status='received',identity=active.identity,packet_count=active.capture.count));active=None;break
                        else:raise ValueError('unknown strict active operation')
                request=receive_message(connection);require(request.get('version')==2 and request.get('op')=='CAMPAIGN_CAPTURE','capture after whole campaign')
                for trial_id,state in states.items():
                    for i,data in enumerate(state.capture.packets):
                        off=i*state.wire_stride
                        # Wire and UDP arrival order may differ; generation binds them
                        # in the final byte oracle, never an online payload compare.
                        wire=bytes(state.wire_storage[off:off+state.wire_stride])
                        send_message(connection,dict(version=2,op='CAPTURE',status='received',trial_id=trial_id,data=base64.b64encode(data).decode(),wire=base64.b64encode(wire).decode()))
                send_message(connection,dict(version=2,op='CAPTURE_END',status='received',packets=sum(s.capture.count for s in states.values())))
                request=receive_message(connection);require(request.get('version')==2 and request.get('op')=='CLOSE','strict close')
                send_message(connection,dict(version=2,op='CLOSED',status='ok'))
            except (OSError,ValueError,KeyError,TypeError) as error:
                try:send_message(connection,dict(version=2,op='ERROR',status='error',diagnostic=str(error)))
                except OSError:pass
                raise
            finally:
                for state in states.values():state.close()
                evidence=Path(tempfile.mkdtemp(prefix='.hft-strict-peer-capture-',dir=args.directory or ROOT));os.chmod(evidence,0o700)
                with oracle.exclusive(evidence/'raw-campaign.json') as output:
                    output.write(canonical(dict(trials=[dict(trial_id=k,profile=v.p,identity=v.identity,error=str(v.error) if v.error else None,packets=[x.hex() for x in v.capture.packets],wire_frames=[bytes(v.wire_storage[i*v.wire_stride:(i+1)*v.wire_stride]).hex() for i in range(v.wire_used)]) for k,v in states.items()])))


class BenchmarkBurstBroker(BurstBroker):
    def work(self):
        expected_first=0;client=None
        try:
            while not self.stop.is_set():
                try:data,client=self.socket.recvfrom(4096)
                except socket.timeout:continue
                request=json.loads(data);fields(request,('op','actor','first','count','session_base'))
                require(request==dict(op='receipt',actor=0,first=expected_first,count=self.p['burst_packets'],session_base=self.p['session_base']),'strict broker nonce/sequence')
                reply=benchmark_rpc(self.stream,dict(version=2,op='BURST',identity=self.identity,first_generation=expected_first+1,packet_count=self.p['burst_packets']),'BURST_RECEIPT','received')
                same_identity(reply,self.identity)
                require(reply.get('first_generation')==expected_first+1 and reply.get('packet_count')==self.p['burst_packets'] and reply.get('received_packets')==self.p['burst_packets'] and reply.get('received_bytes')==self.p['burst_packets']*self.p['payload_bytes'] and not any(k.startswith('validated_') for k in reply),'received-only remote receipt')
                response=dict(status='received',actor=0,first=expected_first,count=self.p['burst_packets'],received_bytes=reply['received_bytes'],session_base=self.p['session_base'])
                self.socket.sendto(json.dumps(response,separators=(',',':')).encode(),client);expected_first+=self.p['burst_packets']
        except (OSError,ValueError,KeyError,TypeError) as error:
            self.error=error
            if client is not None:
                try:self.socket.sendto(b'{"status":"error"}',client)
                except OSError:pass


def legacy_measure(args):
    from hardware_gate import collect
    # Missing provisioning refuses before subprocesses, sockets or artifacts.
    p=dict(schema=1,record_bytes=args.records,payload_bytes=args.payload,burst_packets=args.burst,depth=args.depth,
        bursts=args.bursts,actors=args.actors,seed=args.seed)
    manifest=dict(p,bursts=args.warmup_bursts+args.bursts,session_base=secrets.randbelow(2**64-1)+1)
    producer=collect(args,'producer',manifest)
    args._source_lba=producer['source']['lba_bytes']
    # Evidence artifacts are private, exclusive and retained for audit. This
    # occurs only after actual local physical/source/software preflight.
    directory=Path(tempfile.mkdtemp(prefix='.hft-physical-',dir=args.directory or ROOT));os.chmod(directory,0o700)
    native_probe(args,manifest,directory)
    producer['nic']['zero_copy']=True  # observed OPTIONS+strict CREATE above
    validate_admission(producer,'producer')
    with socket.create_connection(args.peer_control,timeout=30) as stream:
        stream.settimeout(30);remote=receive_message(stream)
        fields(remote,('version','op','status','admission','data_bind'))
        require(type(remote['version']) is int and remote['version']==1 and remote['op']=='ADMISSION' and remote['status']=='ok','peer admission handshake')
        peer=remote['admission'];validate_admission(peer,'peer')
        require(peer['product_sha']==args.product_sha and canonical(remote['data_bind'])==canonical([args.peer_ip,args.peer_port]),'peer SHA/data endpoint')
        require('observed NIC MAC='+args.peer_mac.lower() in peer['environment']['evidence'],'peer MAC differs from actual physical interface')
        admissions=dict(producer=producer,peer=peer)
        with oracle.exclusive(directory/'admission.json') as out:out.write(canonical(admissions))
        trials=[];nonces={manifest['session_base']}
        def fresh():
            while True:
                value=secrets.randbelow(2**64-1)+1
                if value not in nonces:nonces.add(value);return value
        def recheck_producer():
            try:observed=collect(args,'producer',manifest)
            except correctness.Failure as error:
                if getattr(args,'_workload_issued',False):raise ValueError('producer admission changed after accepted work: '+error.message) from error
                raise
            # Current collector reports pre-probe native state as false; the
            # actual per-trial C setup repeats OPTIONS/CREATE observations.
            baseline=dict(producer,nic=dict(producer['nic'],zero_copy=False))
            require(canonical(observed)==canonical(baseline),'producer software/device/source tuple changed')
        for pair,order in enumerate(paired_order(args.pairs,args.order_seed)):

            for position,backend in enumerate(order):
                # Reobserve all required source bytes for the identical tuple.
                recheck_producer()
                check_dir=directory/f'pair-{pair}-order-{position}-correctness';check_dir.mkdir(mode=0o700)
                check_p=dict(manifest,session_base=fresh())
                execute_remote(args,stream,admissions,check_p,backend,check_dir,False)
                recheck_producer()
                trial_dir=directory/f'pair-{pair}-order-{position}-measured';trial_dir.mkdir(mode=0o700)
                trial_p=dict(manifest,session_base=fresh())
                raw=execute_remote(args,stream,admissions,trial_p,backend,trial_dir,True)
                times=raw.get('measurements');fields(times,('clock','setup_started_ns','setup_completed_ns','teardown_started_ns','teardown_completed_ns','samples'))
                require(times['clock']=='CLOCK_MONOTONIC_RAW','producer single monotonic clock')
                trial=dict(pair=pair,order=position,backend=backend,session_base=trial_p['session_base'],
                    source_sha=producer['source']['observed_sha256'],profile=dict(p),
                    **{k:times[k] for k in ('setup_started_ns','setup_completed_ns','teardown_started_ns','teardown_completed_ns','samples')},
                    registration_calls=None if backend=='posix' else raw['registration_calls'],
                    stop_ret=raw['stop_ret'] if backend=='session' else None,correctness_verified=True)
                validate_trial(trial,p,args.warmup_bursts);trials.append(trial)
        rpc(stream,dict(version=1,op='CLOSE'),'CLOSED')
    result=dict(schema=1,status='ok',scenario='hft_replay',mode='performance',scope='physical-paired-roundtrip',
        profile=p,order_seed=args.order_seed,pairs=args.pairs,warmup_bursts=args.warmup_bursts,
        admission=admissions,trials=trials,paired_summary=paired_summary(trials))
    validate_result(result)
    with oracle.exclusive(directory/'result.json') as out:out.write(canonical(result))
    return result


STRICT_SESSION_STATS=('batches_done','read_submitted','read_completed','send_submitted','send_completed','state',
    'batches_abort','rejects','sequestered','timeouts','protocol_err','last_err','inflight')


def _strict_completion_accounting(raw,backend,count):
    """Per-arm completion evidence from the actual producer counters, checked online.

    Counters only; no payload is read. Native arms also need the terminal stage
    STATS the C adapter observed before STOP, and their own zero-copy/map proof.
    """
    def counter(value):return type(value) is int and value>=0
    done=raw.get('completion')
    require(type(done) is dict and set(done)=={'read_cqes','send_result_cqes','send_notif_cqes','zc_copied_packets'} and all(counter(v) for v in done.values()),'producer completion accounting')
    require(type(raw.get('copied_packets')) is int and raw['copied_packets']==done['zc_copied_packets'],'copied-usage notifications reported')
    if backend=='uring-fixed-zc':
        require(done['read_cqes']==count and done['send_result_cqes']==count and done['zc_copied_packets']<=done['send_notif_cqes']<=count,'registered completion accounting')
    else:
        require(not any(done.values()),'no ring completions outside the registered arm')
    if backend!='session':
        require('session_stats' not in raw,'native statistics only for the native arm');return
    stats=raw.get('session_stats')
    wanted=dict(batches_done=count,read_submitted=count,read_completed=count,send_submitted=count,send_completed=count,
        state='ACTIVE',batches_abort=0,rejects=0,sequestered=0,timeouts=0,protocol_err=0,last_err=0,inflight=0)
    require(type(stats) is dict and set(stats)==set(STRICT_SESSION_STATS),'native stage statistics schema')
    require(all(type(stats[k]) is type(v) and stats[k]==v for k,v in wanted.items()),'native terminal stage statistics')
    native=raw.get('native')
    require(type(native) is dict and native.get('xdp_zero_copy') is True and native.get('strict_create') is True and
        type(native.get('nvme_map_id')) is int and native['nvme_map_id']>0 and type(native.get('afxdp_map_id')) is int and native['afxdp_map_id']>0,
        'native zero-copy CREATE and map evidence')


def _strict_trial_observations(raw,trial,p):
    require(raw.get('measurement_policy')=='benchmark-policy-v1' and raw.get('wire_version')==1,'producer policy dispatcher')
    count=p['burst_packets']*p['bursts']
    require(raw.get('read_submissions')==count and raw.get('send_submissions')==count and raw.get('local_release_complete') is True,'producer terminal count')
    require(raw.get('registration_calls')==(0 if trial['backend']=='posix' else 1),'strong baseline registration count')
    require(raw.get('stop_ret')==0,'native STOP/release evidence')
    _strict_completion_accounting(raw,trial['backend'],count)
    history=raw['guard_history'];require(type(history) is list and len(history)==count,'producer complete raw guard history')
    guards=[]
    for row in history:
        item=dict(row);item.pop('payload_bytes',None)
        item['raw_prefix']=bytes.fromhex(item['raw_prefix']);item['raw_tail']=bytes.fromhex(item['raw_tail']);item['trial_id']=trial['trial_id'];guards.append(item)
    trial['frame_slots']=raw['frame_slots'];trial['stop_ret']=0 if trial['backend']=='session' else None
    times=raw['measurements'];require(times['clock']=='CLOCK_MONOTONIC_RAW' and len(times['samples'])==p['bursts'],'all warmup/measured samples retained')
    for b,row in enumerate(times['samples']):
        require(row['burst']==b and row['first_generation']==b*p['burst_packets']+1 and row['packet_count']==p['burst_packets'],'timed sample identity')
        require(times['setup_started_ns']<=times['setup_completed_ns']<=row['started_ns']<=row['local_release_ns']<=row['peer_receipt_ns']<=row['completed_ns']<=times['teardown_started_ns']<=times['teardown_completed_ns'],'timer covers terminal release and received receipt')
        require(row['read_submissions']==p['burst_packets'] and row['send_submissions']==p['burst_packets'],'timed submissions')
    return guards


def _strict_final_wire(manifest,wire_frames,captures):
    # This is part of the final oracle phase, never an online checksum/scan.
    index={t['trial_id']:t for t in manifest['trials']};actual={}
    for row in captures:
        data=row['datagram'];actual[(row['trial_id'],int.from_bytes(data[16:20],'big'))]=data
    require(len(wire_frames)==len(actual),'complete actual wire observation')
    seen=set()
    for row in wire_frames:
        frame=row['frame'];trial=index.get(row['trial_id']);require(trial is not None and type(frame) is bytes,'actual wire trial')
        network=trial['network'];p=trial['profile'];require(len(frame)==p['payload_bytes']+82,'actual wire length')
        generation=int.from_bytes(frame[58:62],'big');key=(row['trial_id'],generation)
        require(key in actual and key not in seen,'actual wire generation set');seen.add(key)
        require(frame[:6]==bytes.fromhex(network['peer_mac'].replace(':','')) and frame[6:12]==bytes.fromhex(network['local_mac'].replace(':','')) and frame[12:14]==b'\x08\x00','actual wire Ethernet tuple')
        require(frame[14]==0x45 and frame[23]==17 and int.from_bytes(frame[16:18],'big')==len(frame)-14 and int.from_bytes(frame[20:22],'big')&0x3fff==0,'actual wire IPv4 geometry')
        require(frame[26:30]==socket.inet_aton(network['local_ip']) and frame[30:34]==socket.inet_aton(network['peer_ip']),'actual wire IP tuple')
        require(frame[34:36]==struct.pack('!H',network['local_port']) and frame[36:38]==struct.pack('!H',network['peer_port']) and int.from_bytes(frame[38:40],'big')==len(frame)-34 and frame[40:42]==b'\0\0','actual wire UDP tuple/checksum zero')
        require(frame[42:]==actual[key],'actual wire application bytes')
    require(seen==set(actual),'all trial wire frames')


def _strict_campaign_impl(args,producer,p,plans,directory,retained):
    from hardware_gate import BIN
    all_guards=retained['guards'];captures=retained['captures'];wire_frames=retained['wire_frames'];observations=retained['observations']
    # Full source reference is reserved once before CAMPAIGN_READY. No digest.
    source_reference=Path(args.reference).read_bytes()
    required=sum(t['profile']['burst_packets']*t['profile']['bursts'] for t in plans)
    require(required*(p['payload_bytes']+40+82)+len(source_reference)<=1024*1024*1024,'producer campaign RAM bound')
    # Fixed source/artifact metadata is rechecked between trials without
    # payload comparisons or hashing; complete final readback follows drain.
    watched=[Path(args.reference),Path(args.bpf_object),BIN,Path(args.kernel_config)]
    snapshots=[x.stat() for x in watched]
    def unchanged():
        for path,before in zip(watched,snapshots):
            after=path.stat();require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'campaign source/artifact metadata changed')
    with socket.create_connection(args.peer_control,timeout=30) as stream:
        stream.settimeout(30);remote=receive_message(stream)
        require(remote.get('version')==2 and remote.get('op')=='ADMISSION' and remote.get('status')=='ok','strict peer admission protocol')
        peer=remote['admission'];validate_admission(peer,'peer')
        require(peer['product_sha']==args.product_sha and remote.get('data_bind')==[args.peer_ip,args.peer_port],'strict peer SHA/endpoint')
        require('observed NIC MAC='+args.peer_mac.lower() in peer['environment']['evidence'],'strict peer physical MAC')
        prepared=benchmark_rpc(stream,dict(version=2,op='CAMPAIGN',measurement_policy='benchmark-policy-v1',trials=[{k:t[k] for k in ('trial_id','profile','identity')} for t in plans]),'CAMPAIGN_READY')
        require(prepared.get('capture_bytes')==required*(p['payload_bytes']+40) and prepared.get('wire_bytes')==required*(p['payload_bytes']+82),'actual peer RAM reservations')
        for t in plans:
            unchanged();profile=t['profile'];identity=t['identity']
            ready=benchmark_rpc(stream,dict(version=2,op='HELLO',trial_id=t['trial_id'],identity=identity),'READY');same_identity(ready,identity)
            broker=BenchmarkBurstBroker(stream,profile,identity)
            try:
                trial_directory=directory/t['trial_id'];trial_directory.mkdir(mode=0o700)
                raw=run_producer(producer_command(args,profile,t['backend'],broker.address,'hardware'),broker,artifact_dir=trial_directory,pass_fds=args._held_fds)
                args._workload_issued=True
            except correctness.Failure as error:
                if getattr(args,'_workload_issued',False):raise ValueError('partial campaign capability loss: '+error.message) from error
                raise
            finally:broker.close()
            finish=benchmark_rpc(stream,dict(version=2,op='FINISH',identity=identity),'FINISH_RECEIPT','received');same_identity(finish,identity)
            require(finish.get('packet_count')==profile['burst_packets']*profile['bursts'],'complete received set')
            observations.append(dict(trial_id=t['trial_id'],raw=raw))
            all_guards.extend(_strict_trial_observations(raw,t,profile));unchanged()
        send_message(stream,dict(version=2,op='CAMPAIGN_CAPTURE'))
        while True:
            reply=receive_message(stream)
            require(reply.get('version')==2 and reply.get('status')=='received','raw campaign capture status')
            if reply.get('op')=='CAPTURE_END':require(reply.get('packets')==required and len(captures)==required,'campaign terminal packet count');break
            require(reply.get('op')=='CAPTURE' and len(captures)<required,'campaign capture bounds')
            data=base64.b64decode(reply['data'],validate=True);wire=base64.b64decode(reply['wire'],validate=True)
            captures.append(dict(trial_id=reply['trial_id'],datagram=data,truncated=False));wire_frames.append(dict(trial_id=reply['trial_id'],frame=wire))
        benchmark_rpc(stream,dict(version=2,op='CLOSE'),'CLOSED')
    unchanged()
    manifest=dict(schema=1,measurement_policy='benchmark-policy-v1',workload_complete=True,local_release_complete=True,trials=plans)
    # Final source readback is complete and outside all samples. Preserve raw
    # source bytes; the independent oracle also checks the specified source.
    with Path(args.source_block).open('rb',buffering=0) as stream:
        stream.seek(args.slba*args._source_lba);readback=stream.read(len(source_reference))
    require(readback==source_reference and Path(args.reference).read_bytes()==source_reference,'final complete source readback')
    validated=finalize_campaign(manifest,captures,all_guards,source_reference,wire_frames=wire_frames)
    # A single final artifact/source manifest. No per-trial/background digest.
    artifact_manifest=dict(source_sha256=hashlib.sha256(source_reference).hexdigest(),binary_sha256=sha(BIN),bpf_sha256=sha(args.bpf_object),config_sha256=sha(args.kernel_config))
    unchanged()
    # All summaries derive only from fully retained and validated actual trials.
    trials=[]
    for t,ob in zip(plans,observations):
        samples=ob['raw']['measurements']['samples'][args.warmup_bursts:]
        trials.append(dict(trial_id=t['trial_id'],backend=t['backend'],pair=t['pair'],order=t['order'],total_completion_ns=sum(s['completed_ns']-s['started_ns'] for s in samples)))
    paired=[]
    for pair in range(args.pairs):
        times={t['backend']:t['total_completion_ns'] for t in trials if t['pair']==pair};require(set(times)==set(ARMS) and all(v>0 for v in times.values()),'complete paired observations')
        paired.append(dict(pair=pair,ratio_posix=times['session']/times['posix'],ratio_fixed=times['session']/times['uring-fixed-zc']))
    result=dict(schema=2,status='ok',scenario='hft-style-scenario-microbenchmark',measurement_policy='benchmark-policy-v1',wire_version=1,scope='physical-paired-received-completion',validated=validated,trials=trials,paired_summary=paired,manifest=artifact_manifest)
    with oracle.exclusive(directory/'result.json') as output:output.write(canonical(result))
    return result




def _strict_campaign(args,producer,p,plans,directory):
    retained=dict(guards=[],captures=[],wire_frames=[],observations=[]);error=None
    try:return _strict_campaign_impl(args,producer,p,plans,directory,retained)
    except BaseException as failure:error=str(failure);raise
    finally:
        # Raw observations remain available on final-oracle failure and on
        # partial/non-beneficial campaigns. No payload hash or comparison.
        evidence=dict(measurement_policy='benchmark-policy-v1',trials=plans,diagnostic=error,observations=retained['observations'],
            captures=[dict(trial_id=r['trial_id'],datagram=r['datagram'].hex(),truncated=r['truncated']) for r in retained['captures']],
            guards=[dict(r,raw_prefix=r['raw_prefix'].hex(),raw_tail=r['raw_tail'].hex()) for r in retained['guards']],
            wire_frames=[dict(trial_id=r['trial_id'],frame=r['frame'].hex()) for r in retained['wire_frames']])
        with oracle.exclusive(directory/'campaign.json') as output:output.write(canonical(evidence))


def _artifact_metadata(path):
    st=Path(path).stat()
    return dict(device=st.st_dev,inode=st.st_ino,bytes=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)


def qualify_benchmark(args):
    """Separate physical asset preparation, never a campaign or START trial.

    Digests generated here are reused verbatim. Qualification is invalidated
    by changed held-file metadata/product/config/device/profile. It does not
    claim resistance to an untested concurrent malicious rewrite.
    """
    from hardware_gate import collect,BIN
    import hardware_build as build
    select_measurement_policy(args.measurement_policy)
    p=dict(schema=1,record_bytes=args.records,payload_bytes=args.payload,burst_packets=args.burst,depth=args.depth,bursts=args.warmup_bursts+args.bursts,actors=args.actors,seed=args.seed)
    validate_profile(p);require(args.qualification is not None,'explicit qualification output path required')
    producer=collect(args,'producer',dict(p,session_base=secrets.randbelow(2**64-1)+1));args._source_lba=producer['source']['lba_bytes']
    directory=Path(tempfile.mkdtemp(prefix='.hft-asset-qualification-',dir=args.directory or ROOT));os.chmod(directory,0o700)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as control:
        control.bind(('127.0.0.1',0))
        native=run_producer(producer_command(args,dict(p,session_base=secrets.randbelow(2**64-1)+1),'session',control.getsockname(),'benchmark-probe'),artifact_dir=directory)
    require(native.get('read_submissions')==0 and native.get('send_submissions')==0 and native.get('stop_ret')==0,'qualification issued work or failed STOP')
    observed=native.get('native',{})
    require(observed.get('xdp_zero_copy') is True and observed.get('strict_create') is True and observed.get('nvme_map_id',0)>0 and observed.get('afxdp_map_id',0)>0,'strict new-policy native build/map/CREATE qualification')
    paths=dict(binary=str(BIN),bpf=str(Path(args.bpf_object).resolve()),config=str(Path(args.kernel_config).resolve()),reference=str(Path(args.reference).resolve()))
    files={name:dict(path=path,metadata=_artifact_metadata(path),sha256=sha(path)) for name,path in paths.items()}
    result=dict(schema=1,status='qualified-assets-only',measurement_policy='benchmark-policy-v1',wire_version=1,product_sha=args.product_sha,profile=p,
        producer=producer,native_probe=observed,files=files,source_sha256=build.binary_source_sha(),bpf_source_sha256=build.benchmark_bpf_source_sha(),start_issued=False)
    with oracle.exclusive(args.qualification) as out:out.write(canonical(result))
    return result


def _qualified_assets(args,p):
    from hardware_gate import physical,source,BIN,required
    required(args,'producer')
    if args.qualification is None:refusal('separate strict asset qualification receipt required before campaign','not_run_capability')
    receipt=json.loads(args.qualification.read_text())
    require(receipt.get('schema')==1 and receipt.get('status')=='qualified-assets-only' and receipt.get('measurement_policy')=='benchmark-policy-v1' and receipt.get('wire_version')==1 and receipt.get('product_sha')==args.product_sha and receipt.get('profile')==p and receipt.get('start_issued') is False,'strict asset qualification binding')
    # Physical environment is freshly observed without digesting payload or
    # artifacts. Exact compiled/source hashes come from the preparation phase.
    require(physical(args.ifname)==receipt['producer']['environment'],'physical environment changed after qualification')
    require(receipt['producer']['kernel']['release']==os.uname().release and receipt['producer']['kernel']['strict_zero_copy'] is True,'qualified running kernel')
    expected=dict(binary=str(BIN),bpf=str(Path(args.bpf_object).resolve()),config=str(Path(args.kernel_config).resolve()),reference=str(Path(args.reference).resolve()))
    held=[]
    try:
        for name,path in expected.items():
            row=receipt['files'][name];require(row['path']==path and row['metadata']==_artifact_metadata(path),'qualified artifact changed')
            fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC);held.append(fd)
            # Pin identity of the bytes used by producer across the campaign.
            st=os.fstat(fd);require(row['metadata']==dict(device=st.st_dev,inode=st.st_ino,bytes=st.st_size,mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns),'qualified held artifact identity')
            if name=='binary':args._binary_fd_path=f'/proc/self/fd/{fd}'
            elif name=='bpf':args.bpf_object=f'/proc/self/fd/{fd}'
            elif name=='config':args.kernel_config=f'/proc/self/fd/{fd}'
            else:args.reference=f'/proc/self/fd/{fd}'
        args._held_fds=tuple(held)
        # The setup source admission remains a complete byte comparison.
        observed=source(args,dict(p,session_base=1));require(observed==receipt['producer']['source'],'qualified source/window changed')
        args._source_lba=observed['lba_bytes']
        return receipt,held
    except BaseException:
        for fd in held:os.close(fd)
        raise


def measure(args):
    select_measurement_policy(args.measurement_policy)
    p=dict(schema=1,record_bytes=args.records,payload_bytes=args.payload,burst_packets=args.burst,depth=args.depth,bursts=args.warmup_bursts+args.bursts,actors=args.actors,seed=args.seed)
    validate_profile(p)
    receipt,held=_qualified_assets(args,p)
    try:
        plans=[];nonces=set()
        for pair,order in enumerate(paired_order(args.pairs,args.order_seed)):
            for position,backend in enumerate(order):
                while True:
                    nonce=secrets.randbelow(2**64-1)+1
                    if nonce not in nonces:nonces.add(nonce);break
                trial_profile=dict(p,session_base=nonce);trial_id=f'pair-{pair}-order-{position}-{backend}'
                identity=dict(token=secrets.token_hex(16),session_base=nonce)
                plans.append(dict(trial_id=trial_id,profile=trial_profile,identity=identity,backend=backend,pair=pair,order=position,network={k:getattr(args,k) for k in ('local_mac','peer_mac','local_ip','peer_ip','local_port','peer_port')}))
        directory=Path(tempfile.mkdtemp(prefix='.hft-strict-campaign-',dir=args.directory or ROOT));os.chmod(directory,0o700)
        return _strict_campaign(args,receipt['producer'],p,plans,directory)
    finally:
        for fd in held:os.close(fd)


if __name__=='__main__':sys.exit(main())
