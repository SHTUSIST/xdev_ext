#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual TP parser/owner/handshake/runner EARLY caller selection contracts."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

HERE=Path(__file__).resolve().parent


def function(text,name):
    import re
    match=re.search(r'^[^\n;#{}]*\b'+re.escape(name)+r'\s*\([^;]*?\)\s*\{',text,re.M)
    if not match:raise ValueError('missing actual '+name)
    start=match.start();brace=text.index('{',start);depth=0
    for at in range(brace,len(text)):
        depth+={'{':1,'}':-1}.get(text[at],0)
        if depth==0:return text[start:at+1]
    raise ValueError('unbalanced actual '+name)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv);root=args.source_root.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    result={'cases':[],'scope':'actual TP caller code at native/process/socket boundaries; no device or performance'}
    try:
        spec=importlib.util.spec_from_file_location('early_owner_test_support',HERE/'test_selection.py');support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)
        support.build_owner(root,out)
        driver=(root/'tests/benchmarks/tp/driver.cc').read_text();owner=(root/'tests/benchmarks/tp/owner.h').read_text()
        numbers='\n'.join(function(driver,name) for name in ('now_ns','number','small'))
        parser_start=driver.index('for(int i=1;i<argc;++i)');parser_end=driver.index('NATIVE(tp_eval_geometry(o));',parser_start)+len('NATIVE(tp_eval_geometry(o));')
        owner_start=owner.index('xdev_ext_cuda_peer_owner_opts options{};');owner_end=owner.index('NATIVE(rc);',owner_start)+len('NATIVE(rc);')
        preflight_start=driver.index('control.open(o.rank,address,port,o.timeout_ns);');preflight_end=driver.index('owner.open(o,node,bpf,user_bpf,oracle,tp_ptx);',preflight_start)+len('owner.open(o,node,bpf,user_bpf,oracle,tp_ptx);')
        chunks={'NUMBERS':numbers,'HANDSHAKE':function(driver,'handshake'),'PARSER':driver[parser_start:parser_end],
                'BARRIER':driver[driver.index('struct barrier {'):driver.index('\nstatic std::string handshake')].replace('struct barrier {','struct actual_barrier {',1),
                'OWNER_PREFIX':owner[owner_start:owner_end],'PREFLIGHT':driver[preflight_start:preflight_end]}
        statements=[];offset=0;marker=r'printf("{\"record\":\"metadata\"'
        while True:
            start=driver.find(marker,offset)
            if start<0:break
            depth=0;quoted=False;escaped=False
            for at in range(driver.index('(',start),len(driver)):
                char=driver[at]
                if quoted:
                    if escaped:escaped=False
                    elif char=='\\':escaped=True
                    elif char=='"':quoted=False
                elif char=='"':quoted=True
                elif char=='(':depth+=1
                elif char==')':
                    depth-=1
                    if depth==0:break
            statements.append(driver[start:at+1]+';');offset=at+1
        if len(statements)!=2:raise RuntimeError('metadata statement extraction setup failure')
        chunks['METADATA']=('static void actual_metadata(const tp_eval_options &o,bool echo) { '
            'struct { unsigned long long trace_dropped=0,logical_inflight_high_water=1,completed=2,'
            'gpu_invocations=2,host_control_calls=0; } stats; '
            'if(echo){'+statements[0]+'}else{'+statements[1]+'}}')
        paths={}
        for name,body in chunks.items():
            path=out/(name.lower()+'.inc');path.write_text(body);paths['EARLY_TP_'+name]=path
        paths['EARLY_TP_OPTIONS']=root/'tests/benchmarks/tp/options.h'
        command=[os.environ.get('CXX','g++'),'-std=c++17','-O0','-g','-Wall','-Wextra','-Wno-unused-function','-pthread',
                 '-I'+str(out/'boundary'),'-I'+str(root/'src/compute/cuda'),'-I'+str(out/'headers/kernel/include/uapi'),'-I'+str(out/'headers/kernel/tools/xdev_ext_mech/lib'),
                 str(HERE/'driver_selection.cc'),'-o',str(out/'driver-selection')]
        command+=['-D'+name+'="'+str(path)+'"' for name,path in paths.items()]
        built=subprocess.run(command,capture_output=True,text=True,timeout=60);(out/'driver-compile.log').write_text(built.stdout+built.stderr)
        if built.returncode:raise RuntimeError('actual driver fixture compilation/setup failure, not behavior RED')
        result.update(compile_exit=0,compile_command=command)
        cases=[]
        for mode in (1,2):
            cases.append(['parse','0','driver','--mode','d'+str(mode)])
            for selection in (0,1):
                cases.append(["parse",str(selection),"driver","--mode","d"+str(mode),"--early-cts",str(selection)])
                for partial in (0,1):cases.append(['owner',str(mode),str(selection),str(partial)])
            for case in ('ordinary','selected','mixed'):cases.append([case,str(mode)])
        cases.append(['geometry'])
        for invalid in ('2','-1','4294967296','1x','+1'):cases.append(['invalid','driver','--early-cts',invalid])
        for index,case in enumerate(cases):
            run=subprocess.run([str(out/'driver-selection'),*case],capture_output=True,text=True,timeout=10)
            (out/(f'driver-{index}.log')).write_text(run.stdout+run.stderr);print(run.stdout+run.stderr,end='')
            if run.returncode not in (0,1):raise RuntimeError(str(case)+' crash/setup, not behavior RED')
            result['cases'].append({'argv':case,'exit':run.returncode})
        for mode in (1,2):
            for selected in (0,1):
                for branch in ('echo','collective'):
                    case=['metadata',str(mode),str(selected),branch]
                    run=subprocess.run([str(out/'driver-selection'),*case],capture_output=True,text=True,timeout=5)
                    try:
                        record=json.loads(run.stdout)
                        passed=(run.returncode==0 and type(record['early_cts_requested']) is bool
                                and record['early_cts_requested'] is bool(selected)
                                and record['native_mode']==mode)
                    except (KeyError,ValueError):passed=False
                    (out/(f'metadata-d{mode}-{selected}-{branch}.log')).write_text(run.stdout+run.stderr)
                    result['cases'].append({'argv':case,'exit':0 if passed else 1})
        spec=importlib.util.spec_from_file_location('actual_early_tp_runner',root/'tests/benchmarks/tp/run.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        for selected in (None,'0','1'):
            command=['--rank','0']+([] if selected is None else ['--early-cts',selected]);seen=[]
            with tempfile.TemporaryDirectory(prefix='passthrough-',dir=out) as temporary:
                raw=Path(temporary)/'raw.jsonl';summary=Path(temporary)/'summary.json'
                def child(argv,**kwargs):seen.append(argv);return subprocess.CompletedProcess(argv,7)
                with mock.patch.object(runner.subprocess,'run',side_effect=child):
                    try:runner.main(['--driver','/nonexistent/native-driver','--raw',str(raw),'--summary',str(summary),'--',*command])
                    except SystemExit as error:status=error.code
                    else:status=0
                passed=status==7 and seen==[['/nonexistent/native-driver',*command]] and not summary.exists()
                result['cases'].append({'runner_passthrough':selected,'exit':0 if passed else 1})
        result['exit']=int(any(c['exit'] for c in result['cases']));result['state']='BEHAVIOR_RED' if result['exit'] else 'SCOPED_PASS'
    except Exception as error:
        result.update(exit=2,state='SETUP_ERROR',error=str(error));print(error)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result['exit']


if __name__=='__main__':raise SystemExit(main())
