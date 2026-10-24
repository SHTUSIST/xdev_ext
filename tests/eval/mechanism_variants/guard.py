#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent check of complete actual UMEM bytes outside traced write spans."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

MAX_UMEM=32*1024*1024


def raw_snapshot(prefix,suffix):
    path=Path(str(prefix)+'.umem.'+suffix)
    if path.is_file():
        with path.open("rb") as stream: raw=stream.read(MAX_UMEM+1)
        if len(raw)>MAX_UMEM: raise ValueError("oversized UMEM snapshot")
        return raw
    with gzip.open(str(path)+'.gz','rb') as stream:
        raw=stream.read(MAX_UMEM+1)
    if len(raw)>MAX_UMEM: raise ValueError('oversized decompressed UMEM')
    return raw


def verify(prefix,events,session,layout):
    meta=json.loads(Path(str(prefix)+'.umem.json').read_text())
    if meta['registration_return'] or meta['registration_errno'] or meta['stop_syscall_return'] or meta['stop_errno']:
        raise ValueError('UMEM registration/STOP did not actually succeed')
    if meta['session_id']!=session or meta['layout']!=layout:
        raise ValueError('guard snapshot does not match actual CREATE')
    size=meta['registered_bytes']; chunk=meta['chunk_size']
    if not 0<size<=MAX_UMEM or chunk!=layout['frame_size'] or size%chunk or chunk%256:
        raise ValueError('unsupported actual UMEM geometry')
    before=raw_snapshot(prefix,'before'); after=raw_snapshot(prefix,'after')
    if len(before)!=size or len(after)!=size:
        raise ValueError('missing complete registered-memory snapshots')
    allowed={}
    for e in events:
        if e['event']!='downstream_complete': continue
        if not (len(e['frames'])==len(e['frame_addresses'])==len(e['frame_bytes'])):
            raise ValueError('incomplete traced frame spans')
        for frame,address,count in zip(e['frames'],e['frame_addresses'],e['frame_bytes']):
            base=frame*chunk; offset=address-base
            if not (0<=frame<size//chunk and offset==layout['hdr_room'] and 0<count<=layout['seg_len'] and offset+count<=chunk):
                raise ValueError('traced native span is outside its actual frame')
            # NXP2 writes 82 bytes immediately before the traced payload.
            allowed.setdefault(frame,[]).append((offset-82,offset+count))
    if not allowed: raise ValueError('no actual downstream write spans for guard audit')
    checked=0
    for frame in range(size//chunk):
        # Independent byte oracle, with no import of the C initializer.
        cycle=bytes((0xa7+position*131+frame*17)&255 for position in range(256))
        expected=(cycle*((chunk+255)//256))[:chunk]
        begin=frame*chunk
        if before[begin:begin+chunk]!=expected:
            raise ValueError(f'UMEM was not initialized/read back as specified: frame {frame}')
        ranges=sorted(allowed.get(frame,[])); cursor=0
        for low,high in ranges+[(chunk,chunk)]:
            if low<0: raise ValueError('header outside actual frame')
            if low>cursor:
                checked+=low-cursor
                if after[begin+cursor:begin+low]!=expected[cursor:low]:
                    raise ValueError(f'actual UMEM guard corruption in frame {frame}, range {cursor}:{low}')
            cursor=max(cursor,high)
    generic_checked=(size//chunk)*(chunk-82-layout['seg_len'])
    if meta['checked_bytes']!=generic_checked or meta['mismatches'] or meta['first_mismatch']!=-1:
        raise ValueError('frontend guard observation disagrees with actual guard bytes')
    return dict(evidence_kind='actual-umem-snapshots',registered_bytes=size,
                independently_checked_guard_bytes=checked,session_id=session,
                before_sha256=hashlib.sha256(before).hexdigest(),after_sha256=hashlib.sha256(after).hexdigest())


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('prefix',type=Path);p.add_argument('events',type=Path);p.add_argument('create_prefix',type=Path)
    a=p.parse_args()
    try:
        from inspect_create import inspect
        create=inspect(a.create_prefix)
        result=verify(a.prefix,json.loads(a.events.read_text()),create['actual_session_id'],create['create']['layout'])
    except (OSError,ValueError,KeyError) as exc: p.exit(1,f'E2 UMEM guard FAIL: {exc}\n')
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__': main()
