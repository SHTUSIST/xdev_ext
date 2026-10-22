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
    parser.add_argument('action',choices=('measure','peer'))
    parser.add_argument('--directory',type=Path)
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
    common={'--help','--directory','--ifname','--kernel-config','--product-sha'}
    if args.action=='peer' and not seen<=common|{'--bind','--data-bind'}:parser.error('measure options are not peer options')
    if args.action=='measure' and seen&{'--bind','--data-bind'}:parser.error('peer bind options are not measure options')
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
        if args.action=='peer':serve_peer(args)
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
    command=[str(BIN),backend,args.reference,str(p['record_bytes']),str(p['payload_bytes']),str(p['burst_packets']),str(p['depth']),
        str(p['bursts']),str(p['actors']),str(p['seed']),args.peer_ip,str(args.peer_port),broker[0],str(broker[1]),
        args.source_block,args.source_ng,str(args.slba),str(args.nlb),args.ifname,str(args.queue),args.local_ip,
        args.local_mac,args.peer_mac,str(args.local_port),args.bpf_object,args.kernel_config,
        str(args.slba*args._source_lba),mode,str(p['session_base'])]
    if mode=='hardware':command.append(str(args.warmup_bursts))
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


def run_producer(command,broker=None,artifact_dir=None):
    """Execute the admitted binary; never replay an accepted failed trial."""
    process=None;out=b'';err=b'';diagnostic=None
    try:
        process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
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


def measure(args):
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


if __name__=='__main__':sys.exit(main())
