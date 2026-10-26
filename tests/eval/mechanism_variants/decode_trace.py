#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Decode audited E1 hook rows; never synthesize missing lifecycle events.

Parser selfchecks may supply synthetic rows. Only actual target tracefs format,
loss statistics, raw trace and producer-hook audit establish collection origin.
This adapter does not certify verifier loading or create configuration.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

ABI = 'xdev-native-v1-nvme-xsk-batch'
NUMERIC = ('session_id','batch_id','batch_key','frame_id','generation','stage',
           'ticket','class_id','accepted','status','cookie','address','bytes',
           'aux','sequence','ts_ns')
PHASES = ('class_validate','provider_accept','native_complete',
          'downstream_complete','frame_recycle')


def infer_session(raw):
    candidates=set()
    for line in raw.splitlines():
        if 'native_event:' not in line: continue
        f=dict(re.findall(r'(\w+)=([^\s]+)',line.split('native_event:',1)[1]))
        if f.get('origin')=='K' and f.get('phase')=='class_validate' and f.get('class_id')=='3' and f.get('stage')=='0':
            try: candidates.add(int(f['session_id']))
            except (KeyError,ValueError): pass
    if len(candidates)!=1: raise ValueError('ambiguous/missing CREATE session; supply actual session scope')
    return candidates.pop()


def parse(raw,session_id=None,audit=None):
    rows=[]
    for line_number,line in enumerate(raw.splitlines(),1):
        if 'native_event:' not in line:
            continue
        fields=dict(re.findall(r'(\w+)=([^\s]+)',line.split('native_event:',1)[1]))
        try: row_session=int(fields['session_id'])
        except (KeyError,ValueError) as exc: raise ValueError('missing/invalid row session') from exc
        if session_id is not None and row_session!=session_id:
            if audit is not None: audit.setdefault('excluded',[]).append(dict(raw_line=line_number,reason='different CREATE session',session_id=row_session))
            continue
        if fields.get('abi') != ABI:
            raise ValueError(f'line {line_number}: unsupported trace ABI')
        if not fields.get('phase') or not fields.get('origin'):
            raise ValueError(f'line {line_number}: missing phase/origin')
        try:
            for field in NUMERIC:
                fields[field]=int(fields[field],10)
        except (KeyError,ValueError) as exc:
            raise ValueError(f'line {line_number}: missing/invalid native fields') from exc
        widths={f:(32 if f in ('frame_id','stage','class_id','bytes') else 64) for f in NUMERIC}
        if any(not 0<=fields[f]<(1<<widths[f]) for f in NUMERIC if f not in ('status','accepted')):
            raise ValueError('out-of-range native unsigned field')
        if not -(1<<31)<=fields['status']<(1<<31) or fields['accepted'] not in (0,1):
            raise ValueError('out-of-range native status/acceptance')
        fields['raw_line']=line_number
        rows.append(fields)
    if not rows:
        raise ValueError('no actual native_event rows for CREATE session')
    return sorted(rows,key=lambda r:(r['ts_ns'],r['raw_line']))


KNOWN_PHASES={'class_validate','native_submit','native_complete','downstream_complete',
              'frame_recycle','record_admit','record_terminal','descriptor_bind'}


def exclude_session_bind(rows,audit=None):
    binds=[r for r in rows if r['phase']=='session_bind']
    if not binds:
        return rows
    if len(binds)!=1:
        raise ValueError('duplicate session bind diagnostic')
    bind=binds[0]
    zero=('batch_id','batch_key','frame_id','generation','stage','ticket',
          'class_id','status','address','aux','sequence')
    if (bind['origin']!='K' or bind['accepted']!=1 or
            any(bind[f] for f in zero) or not bind['cookie'] or
            not 1<=bind['bytes']<=32):
        raise ValueError('invalid session bind diagnostic')
    optional_widths={'origin_tgid':32,'process_start_ticks':64,
                     'native_user_data':64,'frame_ordinal':32,
                     'frame_offset':32,'frame_length':32}
    for field,width in optional_widths.items():
        if field not in bind:
            continue
        try: value=int(bind[field],10)
        except ValueError as exc:
            raise ValueError('invalid session bind optional field') from exc
        if not 0<=value<(1<<width) or (field=='origin_tgid' and not value):
            raise ValueError('out-of-range session bind optional field')
        if field not in ('origin_tgid','process_start_ticks') and value:
            raise ValueError('nonzero session bind optional field')
    cohorts=defaultdict(set)
    for r in rows:
        if r['phase']=='class_validate' and r['stage']==0:
            cohorts[r['batch_id']].add(r['frame_id'])
    if any(len(frames)!=bind['bytes'] for frames in cohorts.values()):
        raise ValueError('session bind frame count differs from validation cohort')
    if audit is not None:
        audit.setdefault('excluded',[]).append(dict(raw_line=bind['raw_line'],
            phase='session_bind',reason='audited diagnostic/intermediate stage, retained in raw'))
    return [r for r in rows if r['phase']!='session_bind']


def validate_scoped(rows,final_stage,positive=True):
    expected_class={0:3,final_stage:2}
    for stage in range(1,final_stage): expected_class[stage]=5
    for r in rows:
        if r['origin']!='K' or r['phase'] not in KNOWN_PHASES:
            raise ValueError('unknown measured origin/phase in CREATE session')
        if r['stage'] not in expected_class or r['class_id']!=expected_class[r['stage']]:
            raise ValueError('measured phase has wrong configured class/stage')
        if r['phase']=='class_validate' and (r['stage']!=0 or r['class_id']!=3):
            raise ValueError('class validation is not at NVMe stage zero')
        if positive and (r['status'] or r['accepted']!=1):
            raise ValueError('failed measured operation in positive CREATE session')


def groups(rows, final_stage,audit=None):
    selected=defaultdict(list)
    for r in rows:
        phase=r['phase']
        if r['class_id']==3 and r['stage']==0 and phase in (
                'class_validate','native_submit','native_complete'):
            phase='provider_accept' if phase=='native_submit' else phase
        elif phase in ('downstream_complete','frame_recycle') and r['stage']==final_stage:
            pass
        else:
            if audit is not None: audit.setdefault('excluded',[]).append(dict(raw_line=r['raw_line'],phase=r['phase'],reason='audited diagnostic/intermediate stage, retained in raw'))
            continue
        key=(r['session_id'],r['batch_id'],phase)
        selected[key].append(r)
    events=[]
    consistent=('batch_key','stage','ticket','class_id','accepted','status','cookie','aux')
    for (session,batch,phase),rr in selected.items():
        first=rr[0]
        keys=consistent + (('address','bytes') if phase in PHASES[:3] else ())
        if any(any(r[k] != first[k] for k in keys) for r in rr):
            raise ValueError('inconsistent rows within native phase')
        frames=[r['frame_id'] for r in rr]
        if len(frames) != len(set(frames)):
            raise ValueError('duplicate frame in native phase')
        event=dict(event=phase,session_id=session,batch_id=batch,request_id=batch,
                   stage=first['stage'],ticket=first['ticket'],cookie=first['cookie'],batch_key=first['batch_key'],
                   native_aux=first['aux'],
                   frames=frames,frame_generations=[r['generation'] for r in rr],
                   raw_lines=[r['raw_line'] for r in rr],trace_ts_ns=first['ts_ns'],
                   frame_addresses=[r['address'] for r in rr],frame_bytes=[r['bytes'] for r in rr])
        if phase in ('class_validate','provider_accept'):
            opcode=first['aux'] & 0xff
            if opcode not in (1,2):
                raise ValueError('unsupported NVMe opcode in actual trace')
            event.update(slba=first['address'],nlb=((first['aux']>>8)&0xffff)+1,
                         bytes=first['bytes'],direction='read' if opcode==2 else 'write')
        if phase=='class_validate':
            event['result']=first['status']
        if first['status'] != 0 or first['accepted'] != 1:
            raise ValueError('positive run contains failed native/class operation')
        events.append(event)
    events.sort(key=lambda e:(e['trace_ts_ns'],e['raw_lines'][0]))
    for index,event in enumerate(events,1):
        event['seq']=index
    return events


def decode(raw, chain,session_id=None,audit=None):
    final_stage={'nvme_nic':1,'nvme_ce_ce_nic':3}[chain]
    session_id=infer_session(raw) if session_id is None else session_id
    rows=exclude_session_bind(parse(raw,session_id,audit),audit)
    validate_scoped(rows,final_stage)
    events=groups(rows,final_stage,audit)
    if not events or len({e['session_id'] for e in events}) != 1:
        raise ValueError('capture must contain exactly one real session')
    by_record=defaultdict(list)
    for e in events:
        by_record[e['request_id']].append(e)
    for rid,record in by_record.items():
        if tuple(e['event'] for e in record) != PHASES:
            raise ValueError(f'request {rid}: missing/duplicate/reordered lifecycle phase')
        validation,accepted,completed,downstream,recycled=record
        if validation['ticket'] != 0:
            raise ValueError('validation borrowed future native ticket')
        for key in ('session_id','batch_id','request_id','stage','batch_key','slba','nlb','bytes','direction','frames'):
            if validation[key] != accepted[key]:
                raise ValueError('native operation differs from validated plan')
        for key in ('session_id','batch_id','request_id','stage','ticket','cookie','batch_key','native_aux','frames','frame_generations','frame_addresses','frame_bytes'):
            if accepted[key] != completed[key]:
                raise ValueError('native completion differs from accepted claim')
        if not accepted['ticket'] or not accepted['cookie'] or not all(accepted['frame_generations']):
            raise ValueError('missing immutable native identity')
        if any(e['frames'] != accepted['frames'] for e in record):
            raise ValueError('frame cohort changed in fixed non-transform chain')
        if not downstream['ticket'] or not recycled['ticket']:
            raise ValueError('missing terminal stage ticket')
    return events


def decode_negative(raw,session_id=None,audit=None):
    session_id=infer_session(raw) if session_id is None else session_id
    rows=exclude_session_bind(parse(raw,session_id,audit),audit)
    validate_scoped(rows,1,positive=False)
    accepts={(r['session_id'],r['batch_id'],r['ticket'],r['cookie']) for r in rows
             if r['origin']=='K' and r['phase']=='native_submit' and r['class_id']==3}
    validates=[r for r in rows if r['origin']=='K' and r['phase']=='class_validate' and r['class_id']==3]
    identities={(r['session_id'],r['batch_id'],r['stage'],r['status']) for r in validates}
    if accepts or len(identities)!=1 or not validates or any(r['accepted'] or r['ticket'] for r in validates):
        raise ValueError('negative has native acceptance, no rejection, or ambiguous validation')
    if len({r['frame_id'] for r in validates})!=len(validates):
        raise ValueError('duplicate rejected validation frame')
    if any(r['phase'] not in ('class_validate','record_admit','record_terminal') for r in rows):
        raise ValueError('negative contains unexpected measured operation')
    stable=('batch_key','stage','ticket','cookie','address','bytes','aux','accepted','status')
    if any(any(row[key]!=validates[0][key] for key in stable) for row in validates):
        raise ValueError('rejected validation rows disagree on actual plan')
    result=validates[0]['status']
    if any(r['status'] not in (0,result) for r in rows):
        raise ValueError('negative diagnostic carries another measured failure')
    if result not in (-34,-1):
        raise ValueError('unexpected actual full-class rejection')
    return dict(entry='class_validate',result=result,accepted_during_capture=len(accepts),
                session_id=validates[0]['session_id'],batch_id=validates[0]['batch_id'],
                raw_lines=[r['raw_line'] for r in validates])


def audit_collection(format_text, stats):
    required=NUMERIC+('phase','origin')
    if ABI not in format_text or any(f' {f};' not in format_text for f in required):
        raise ValueError('actual target event format is missing the required ABI/fields')
    blocks=re.split(r'^.*?/per_cpu/cpu[0-9]+/stats\s*$',stats,flags=re.M)
    blocks=[block for block in blocks if block.strip()]
    if not blocks: raise ValueError('trace statistics absent')
    for block in blocks:
        losses=re.findall(r'^(overrun|commit overrun|dropped events):\s*(\d+)\s*$',block,re.M)
        if len(losses)!=3 or {k for k,_ in losses}!={'overrun','commit overrun','dropped events'} or any(int(v) for _,v in losses):
            raise ValueError('incomplete trace loss counters or events lost')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('trace',type=Path)
    p.add_argument('output',type=Path)
    p.add_argument('--format',required=True,type=Path)
    p.add_argument('--stats',required=True,type=Path)
    p.add_argument('--chain',choices=('nvme_nic','nvme_ce_ce_nic'),default='nvme_nic')
    p.add_argument('--negative',action='store_true')
    p.add_argument('--create-prefix',required=True,type=Path)
    a=p.parse_args()
    try:
        audit_collection(a.format.read_text(),a.stats.read_text())
        raw=a.trace.read_text()
        from inspect_create import inspect
        session=inspect(a.create_prefix)['actual_session_id']
        audit=dict(create_session=session,excluded=[])
        result=decode_negative(raw,session,audit) if a.negative else decode(raw,a.chain,session,audit)
        sessions={result['session_id']} if a.negative else {e['session_id'] for e in result}
        if sessions!={session}:
            raise ValueError('trace does not match the actual successful CREATE session')
        with a.output.open('x') as out:
            json.dump(result,out,indent=2); out.write('\n')
        with Path(str(a.output)+'.audit.json').open('x') as out:
            json.dump(audit,out,indent=2); out.write('\n')
    except (OSError,ValueError,KeyError) as exc:
        p.exit(1,f'E2 trace decode FAIL: {exc}\n')
    print(f'E2_TRACE_DECODED sha256={hashlib.sha256(a.trace.read_bytes()).hexdigest()} performance_claim=none')

if __name__=='__main__':
    main()
