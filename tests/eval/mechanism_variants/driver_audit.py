#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Correlate actual XSK session-zero driver rows through descriptor_bind pools.

The kernel's driver journal has pool/descriptor identity, not a session ID.
Only real in-scope descriptor_bind observations associate it with a record.
Other pools remain explicit exclusions; no native event is reconstructed.
"""
from collections import defaultdict
import re
from decode_trace import parse


def audit(raw,session_id,final_stage=1):
    tokens=[]
    for number,line in enumerate(raw.splitlines(),1):
        if 'native_event:' not in line: continue
        f=dict(re.findall(r'(\w+)=([^\s]+)',line.split('native_event:',1)[1]))
        tokens.append((number,line,f))
    binds=[];terminal={}
    for number,line,f in tokens:
        if f.get('session_id')!=str(session_id):continue
        if f.get('phase') not in ('descriptor_bind','downstream_complete') or f.get('stage')!=str(final_stage):continue
        r=parse(line)[0];r['raw_line']=number
        if r['origin']!='K' or r['class_id']!=2 or r['status'] or r['accepted']!=1:
            raise ValueError('failed/invalid actual terminal binding/completion')
        if r['phase']=='descriptor_bind':
            if not r['cookie'] or not r['ticket'] or not r['generation'] or not r['bytes']:
                raise ValueError('descriptor binding lacks actual immutable record/pool identity')
            binds.append(r)
        else:
            terminal.setdefault(r['batch_id'],[]).append(r)
    if not binds:raise ValueError('no actual in-scope descriptor_bind pool observations')
    pools={b['cookie'] for b in binds}
    journal=[];excluded=[]
    for number,line,f in tokens:
        if f.get('session_id')!='0' or f.get('class_id')!='2':continue
        try: pool=int(f.get('cookie','-1'))
        except ValueError as exc:raise ValueError('invalid driver pool identity') from exc
        if pool not in pools:
            excluded.append(dict(raw_line=number,pool=pool,phase=f.get('phase'),reason='no in-scope descriptor binding for this pool'))
            continue
        r=parse(line)[0];r['raw_line']=number
        if r['origin']!='K' or r['phase'] not in ('native_submit','native_complete') or r['status'] or r['accepted']!=1:
            raise ValueError('failed/unknown measured driver event on the bound pool')
        journal.append(r)
    journal.sort(key=lambda r:(r['ts_ns'],r['raw_line']))
    pending=defaultdict(list)
    for bind in sorted(binds,key=lambda b:(b['ts_ns'],b['raw_line'])):
        pending[(bind['cookie'],bind['address'],bind['bytes'])].append(bind)
    submitted={};completed={};next_sequence={pool:1 for pool in pools};binding_report=[]
    for r in journal:
        identity=(r['cookie'],r['sequence'])
        if r['phase']=='native_submit':
            if identity in submitted or r['sequence']!=next_sequence[r['cookie']]:
                raise ValueError('duplicate/missing driver submission sequence')
            key=(r['cookie'],r['address'],r['bytes'])
            if not pending[key]:raise ValueError('native descriptor has no actual validated binding')
            binding=pending[key].pop(0)
            if r['ts_ns']<binding['ts_ns']:raise ValueError('native driver submit precedes descriptor binding')
            submitted[identity]=(r,binding);next_sequence[r['cookie']]+=1
        else:
            if identity not in submitted or identity in completed:
                raise ValueError('native driver completion has no unique accepted descriptor')
            accepted,binding=submitted[identity]
            if any(r[k]!=accepted[k] for k in ('cookie','address','bytes','sequence')) or r['ts_ns']<accepted['ts_ns']:
                raise ValueError('native descriptor completion changed actual accepted span/identity')
            ends=terminal.get(binding['batch_id'],[])
            if not ends or r['ts_ns']>min(end['ts_ns'] for end in ends):
                raise ValueError('terminal record completion precedes actual driver completion')
            completed[identity]=r
            binding_report.append(dict(pool=r['cookie'],sequence=r['sequence'],batch_id=binding['batch_id'],
                frame_id=binding['frame_id'],frame_generation=binding['generation'],ticket=binding['ticket'],
                wire_address=r['address'],wire_bytes=r['bytes'],bind_raw_line=binding['raw_line'],
                submit_raw_line=accepted['raw_line'],complete_raw_line=r['raw_line']))
    if len(submitted)!=len(binds) or set(submitted)!=set(completed) or any(pending.values()):
        raise ValueError('incomplete actual driver accept/complete cohort')
    return dict(scope='actual descriptor_bind pools',session_id=session_id,pools=sorted(pools),
        native_submits=len(submitted),native_completes=len(completed),bindings=binding_report,
        excluded_other_pool_rows=excluded)
