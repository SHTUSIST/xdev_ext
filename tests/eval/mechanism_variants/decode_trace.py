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


def parse(raw):
    rows=[]
    for line_number,line in enumerate(raw.splitlines(),1):
        if 'native_event:' not in line:
            continue
        fields=dict(re.findall(r'(\w+)=([^\s]+)',line.split('native_event:',1)[1]))
        if fields.get('abi') != ABI:
            raise ValueError(f'line {line_number}: unsupported trace ABI')
        if not fields.get('phase') or not fields.get('origin'):
            raise ValueError(f'line {line_number}: missing phase/origin')
        try:
            for field in NUMERIC:
                fields[field]=int(fields[field],10)
        except (KeyError,ValueError) as exc:
            raise ValueError(f'line {line_number}: missing/invalid native fields') from exc
        if any(fields[f] < 0 for f in NUMERIC if f not in ('status',)):
            raise ValueError('negative unsigned native field')
        fields['raw_line']=line_number
        rows.append(fields)
    if not rows:
        raise ValueError('no actual native_event rows')
    return sorted(rows,key=lambda r:(r['ts_ns'],r['raw_line']))


def groups(rows, final_stage):
    selected=defaultdict(list)
    for r in rows:
        if r['origin'] != 'K':
            continue
        phase=r['phase']
        if r['class_id']==3 and r['stage']==0 and phase in (
                'class_validate','native_submit','native_complete'):
            phase='provider_accept' if phase=='native_submit' else phase
        elif phase in ('downstream_complete','frame_recycle') and r['stage']==final_stage:
            pass
        else:
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
                   stage=first['stage'],ticket=first['ticket'],cookie=first['cookie'],
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


def decode(raw, chain):
    final_stage={'nvme_nic':1,'nvme_ce_ce_nic':3}[chain]
    events=groups(parse(raw),final_stage)
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
        for key in ('session_id','batch_id','request_id','stage','slba','nlb','bytes','direction','frames'):
            if validation[key] != accepted[key]:
                raise ValueError('native operation differs from validated plan')
        for key in ('session_id','batch_id','request_id','stage','ticket','cookie','frames','frame_generations'):
            if accepted[key] != completed[key]:
                raise ValueError('native completion differs from accepted claim')
        if not accepted['ticket'] or not accepted['cookie'] or not all(accepted['frame_generations']):
            raise ValueError('missing immutable native identity')
        if any(e['frames'] != accepted['frames'] for e in record):
            raise ValueError('frame cohort changed in fixed non-transform chain')
        if not downstream['ticket'] or not recycled['ticket']:
            raise ValueError('missing terminal stage ticket')
    return events


def decode_negative(raw):
    rows=parse(raw)
    accepts={(r['session_id'],r['batch_id'],r['ticket'],r['cookie']) for r in rows
             if r['origin']=='K' and r['phase']=='native_submit' and r['class_id']==3}
    validates=[r for r in rows if r['origin']=='K' and r['phase']=='class_validate' and r['class_id']==3]
    identities={(r['session_id'],r['batch_id'],r['stage'],r['status']) for r in validates}
    if accepts or len(identities)!=1 or not validates or any(r['accepted'] or r['ticket'] for r in validates):
        raise ValueError('negative has native acceptance, no rejection, or ambiguous validation')
    result=validates[0]['status']
    if result not in (-34,-1):
        raise ValueError('unexpected actual full-class rejection')
    return dict(entry='class_validate',result=result,accepted_during_capture=len(accepts),
                session_id=validates[0]['session_id'],batch_id=validates[0]['batch_id'],
                raw_lines=[r['raw_line'] for r in validates])


def audit_collection(format_text, stats):
    if ABI not in format_text or any(f' {f};' not in format_text for f in ('ticket','cookie','generation','ts_ns')):
        raise ValueError('actual target event format is missing the required ABI/fields')
    values=re.findall(r'^(?:overrun|commit overrun|dropped events):\s*(\d+)\s*$',stats,re.M)
    if not values or any(int(value) for value in values):
        raise ValueError('trace statistics absent or events lost')


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
        result=decode_negative(raw) if a.negative else decode(raw,a.chain)
        from inspect_create import inspect
        session=inspect(a.create_prefix)['actual_session_id']
        sessions={result['session_id']} if a.negative else {e['session_id'] for e in result}
        if sessions!={session}:
            raise ValueError('trace does not match the actual successful CREATE session')
        with a.output.open('x') as out:
            json.dump(result,out,indent=2); out.write('\n')
    except (OSError,ValueError,KeyError) as exc:
        p.exit(1,f'E2 trace decode FAIL: {exc}\n')
    print(f'E2_TRACE_DECODED sha256={hashlib.sha256(a.trace.read_bytes()).hexdigest()} performance_claim=none')

if __name__=='__main__':
    main()
