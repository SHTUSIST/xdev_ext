#!/usr/bin/env python3
"""Compile contract-derived HOST mutants against unchanged independent tests.

Reads the frozen production input opaquely through run.py; only API names and
known operations select mutation sites. Never treats an anchor/build failure as
behavioral discrimination. Production and original extracted controls stay intact.
"""
import argparse
import json
import pathlib
import re
import shlex
import subprocess
import sys

HERE=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser()
p.add_argument('--source',type=pathlib.Path,required=True)
p.add_argument('--out',type=pathlib.Path,required=True)
a=p.parse_args();a.source=a.source.resolve();a.out.mkdir(parents=True,exist_ok=True)

class Setup(Exception):
    pass

def function_bounds(text,name):
    # Match a definition rather than its prototype or a call expression.
    m=re.search(r'^[\w \t*]+\n?'+re.escape(name)+r'\([^;]*?\n\{',text,re.M)
    if not m:raise Setup('definition absent: '+name)
    start=m.start();brace=text.index('{',m.start());i=brace+1;depth=1
    while depth:
        if text[i]=='{':depth+=1
        elif text[i]=='}':depth-=1
        i+=1
    return start,i

def scoped(text,name,transform):
    lo,hi=function_bounds(text,name)
    old=text[lo:hi];new=transform(old)
    if old==new:raise Setup('operation anchor absent: '+name)
    return text[:lo]+new+text[hi:]

def replace_once(body,pattern,replacement,label):
    result,n=re.subn(pattern,replacement,body,count=1,flags=re.S)
    if n!=1:raise Setup('operation anchor absent: '+label)
    return result

def mutate(name,net,socket):
    if name=='host-frame-substitution':
        net=scoped(net,'xdev_ext_netfam_lease_host',lambda b:replace_once(b,
            r'(xdev_ext_mech_batch_frame\s*\(\s*slot->batch\s*,\s*)frame_pos(\s*,)',
            r'\g<1>0\2',name))
    elif name=='host-wrong-offset':
        net=scoped(net,'xdev_ext_netfam_lease_host',lambda b:replace_once(b,
            r'((?:\.|->)addr\s*=\s*)([^;,\n]+)',
            lambda m:m.group(1)+'((u8 *)('+m.group(2)+') + 1)',name))
    elif name=='host-failed-output-write':
        net=scoped(net,'xdev_ext_netfam_lease_host',lambda b:replace_once(b,
            r'\breturn\s+-EPROTO\s*;',
            '{ slot->elem[0].len = 0x13579U; return -EPROTO; }',name))
    elif name=='host-skip-kind':
        net=scoped(net,'xdev_ext_netfam_lease_host',lambda b:replace_once(b,
            r'(\.kind\s*=\s*)XDEV_EXT_NET_LEASE_HOST_CPU\b',
            r'\1XDEV_EXT_NET_LEASE_NONE',name))
    elif name=='host-unknown-clears-borrow':
        def unknown(body):
            host=body.find('XDEV_EXT_NET_LEASE_HOST_CPU')
            if host<0:raise Setup('HOST release arm absent')
            # Only the quiescence guard following the HOST discriminator, never
            # the final slot-free guard or a PEER arm, is mutated.
            rest=body[host:]
            guard=re.search(r'if\s*\(\s*quiesced\s*\)',rest)
            peer=rest.find('XDEV_EXT_NET_LEASE_PEER_DMA')
            if not guard or (peer>=0 and guard.start()>peer):
                raise Setup('HOST quiescence guard absent')
            lo=host+guard.start();hi=host+guard.end()
            return body[:lo]+'if (true)'+body[hi:]
        net=scoped(net,'xdev_ext_netfam_release',unknown)
    elif name=='host-pointer-unpublished':
        request=re.search(r'struct\s+xdev_ext_socket_request\s*\{(.*?)\n\};',socket,re.S)
        if not request:raise Setup('request shape absent')
        fields=re.findall(r'struct\s+xdev_ext_net_slot\s*\*\s*(\w+)\s*;',request.group(1))
        if len(fields)!=1:raise Setup('unique request TX slot pointer absent')
        field=fields[0]
        def unpublished(body):
            post=body.find('xdev_ext_netfam_post(')
            if post<0:raise Setup('family post call absent')
            assignments=list(re.finditer(r'(\br->'+re.escape(field)+r'\s*=\s*)(\w+)(\s*;)',body[:post]))
            assignments=[m for m in assignments if m.group(2)!='NULL']
            if not assignments:raise Setup('pre-post TX publication absent')
            m=assignments[-1]
            return body[:m.start()]+m.group(1)+'NULL'+m.group(3)+body[m.end():]
        socket=scoped(socket,'xdev_ext_socket_submit',unpublished)
    elif name=='host-callback-before-cred-restore':
        # Omit the native caller-credential restore. The unchanged callback
        # observer must fail at entry, before tracker publication or teardown.
        socket,n=re.subn(r'revert_creds\(\s*(\w+)\s*\)\s*;',r'(void)\1; /* mutant: restore delayed past callback */',socket)
        if not n:raise Setup('credential restore operation absent')
    elif name in ('host-eagain-callback','host-plain-eagain-callback'):
        posts=re.findall(r'\.post_tx\s*=\s*(\w+)',socket)
        if len(posts)!=1:raise Setup('unique socket TX native consumer absent')
        def eagain(body):
            params=re.search(r'\([^)]*struct\s+xdev_ext_net_elem\s*\*\s*(\w+)\s*,\s*u32\s+(\w+)\s*\)',body)
            if not params:raise Setup('post_tx ABI parameters absent')
            elem=params.group(1)
            pattern=r'(if\s*\(\s*(\w+)\s*==\s*-EAGAIN\s*\)\s*(?:\{\s*)?)return\s+\2\s*;'
            def replacement(m):
                return m.group(1)+'{ xdev_ext_net_elem_done(&'+elem+'[0], -EAGAIN, 0, 0, true); return '+m.group(2)+'; }'
            matches=list(re.finditer(pattern,body,re.S))
            index=1 if name=='host-plain-eagain-callback' else 0
            if len(matches)<=index:raise Setup('distinct EAGAIN return anchor absent: '+name)
            match=matches[index]
            return body[:match.start()]+replacement(match)+body[match.end():]
        socket=scoped(socket,posts[0],eagain)
    else:raise Setup('unknown mutation')
    return net,socket

controls={}
for suite in ['consumer','host']:
    out=a.out/('control-'+suite)
    result=subprocess.run([sys.executable,str(HERE/'run.py'),'--source',str(a.source),'--out',str(out),'--suite',suite],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
    (a.out/('control-'+suite+'.log')).write_text(result.stdout)
    controls[suite]=out
    if result.returncode:
        print('SETUP candidate control '+suite+' exit='+str(result.returncode));print(result.stdout)
        raise SystemExit(2)

names=['host-frame-substitution','host-wrong-offset','host-failed-output-write','host-skip-kind',
       'host-unknown-clears-borrow','host-pointer-unpublished','host-callback-before-cred-restore','host-eagain-callback','host-plain-eagain-callback']
results=[]
for name in names:
    suite='host' if name in names[:5] else 'consumer'
    control=controls[suite];out=a.out/name;out.mkdir(parents=True,exist_ok=True)
    record={'name':name,'suite':suite,'status':'SETUP'}
    try:
        for path in control.glob('*.inc'):(out/path.name).write_bytes(path.read_bytes())
        net=(out/'netfam.inc').read_text();socket=(out/'socket.inc').read_text()
        net,socket=mutate(name,net,socket)
        (out/'netfam.inc').write_text(net);(out/'socket.inc').write_text(socket)
        (out/'mutation.txt').write_text(name+'\ncontract-derived mutation of extracted actual production body only\n')
        cmd=shlex.split((control/'command.txt').read_text())
        cmd=[arg.replace(str(control),str(out)) for arg in cmd]
        (out/'command.txt').write_text(shlex.join(cmd)+'\n')
        built=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        (out/'build.log').write_text(built.stdout)
        if built.returncode:raise Setup('compile failed; see build.log')
        run=subprocess.run([str(out/'socket_cases'),suite],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10)
        (out/'observations.log').write_text(run.stdout);record['exit']=run.returncode
        semantic=run.returncode!=0 and ('FAIL line ' in run.stdout or 'Assertion ' in run.stdout)
        if semantic and name=='host-callback-before-cred-restore':
            semantic='observe_element_callback' in run.stdout and 'current_cred==&worker_cred' in run.stdout
        if semantic:
            record['status']='KILLED'
            record['reason']='compiled mutant rejected by unchanged semantic assertion'
        elif run.returncode==0:
            record['status']='SURVIVED';record['reason']='coverage gap; original expectation unchanged'
        else:
            record['status']='UNRESOLVED';record['reason']='nonsemantic runtime failure'
    except (Setup,subprocess.TimeoutExpired) as err:
        record['reason']=str(err)
    results.append(record)
    print(name+': '+record['status']+' '+record['reason'])
(a.out/'verdict.json').write_text(json.dumps({'controls':'PASS consumer and direct HOST','results':results},indent=2)+'\n')
raise SystemExit(0 if all(r['status']=='KILLED' for r in results) else 1)
