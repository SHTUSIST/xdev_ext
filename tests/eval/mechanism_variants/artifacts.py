#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify bounded guest serial artifact frames, hashes and complete manifest."""
import argparse
import base64
import hashlib
from pathlib import Path
import re
import tempfile
import os

MAX_FILE=8*1024*1024
MAX_TOTAL=32*1024*1024
MAX_FILES=96
NAME=r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}'
BEGIN=re.compile(rf'E2_ARTIFACT_BEGIN name=({NAME}) bytes=(\d+) sha256=([a-f0-9]{{64}})$')
END=re.compile(rf'E2_ARTIFACT_END name=({NAME})$')
TOTAL=re.compile(r'E2_ARTIFACT_SET_END files=(\d+) bytes=(\d+) manifest_sha256=([a-f0-9]{64})$')


def extract(console,out):
    if len(console)>72*1024*1024:
        raise ValueError('oversized serial transcript')
    files={}; current=None; chunks=[]; total=None; length=0
    for line in console.splitlines():
        if line.startswith('E2_ARTIFACT_BEGIN'):
            match=BEGIN.fullmatch(line)
            if not match or current is not None or total is not None:
                raise ValueError('invalid/nested artifact begin')
            name,size,digest=match.groups(); size=int(size)
            if name in files or size>MAX_FILE or len(files)>=MAX_FILES:
                raise ValueError('duplicate or oversized artifact')
            current=(name,size,digest); chunks=[]
        elif line.startswith('E2_ARTIFACT_DATA'):
            if current is None or total is not None or not line.startswith('E2_ARTIFACT_DATA '):
                raise ValueError('data outside artifact frame')
            chunk=line[len('E2_ARTIFACT_DATA '):]
            if len(chunk)>76 or not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',chunk):
                raise ValueError('invalid artifact base64 line')
            chunks.append(chunk)
            if sum(map(len,chunks))>((current[1]+2)//3)*4:
                raise ValueError('artifact exceeds declared size')
        elif line.startswith('E2_ARTIFACT_END'):
            match=END.fullmatch(line)
            if not match or current is None or match[1]!=current[0]:
                raise ValueError('missing/mismatched artifact end')
            name,size,digest=current
            try:
                payload=base64.b64decode(''.join(chunks),validate=True)
            except ValueError as exc:
                raise ValueError('invalid artifact encoding') from exc
            if len(payload)!=size or hashlib.sha256(payload).hexdigest()!=digest:
                raise ValueError('artifact length/hash mismatch')
            files[name]=payload; length+=size
            if length>MAX_TOTAL:
                raise ValueError('artifact set exceeds limit')
            current=None
        elif line.startswith('E2_ARTIFACT_SET_END'):
            match=TOTAL.fullmatch(line)
            if not match or total is not None or current is not None:
                raise ValueError('invalid/duplicate artifact set end')
            total=match.groups()
    if current is not None or total is None or 'export.manifest' not in files:
        raise ValueError('incomplete exported artifact set')
    count,size,digest=total
    if int(count)!=len(files) or int(size)!=length or hashlib.sha256(files['export.manifest']).hexdigest()!=digest:
        raise ValueError('artifact set total mismatch')
    entries={}
    try:
        for line in files['export.manifest'].decode('ascii').splitlines():
            name,size,sha=line.split(' ')
            if not re.fullmatch(NAME,name) or name in entries or name=='export.manifest':
                raise ValueError('invalid/duplicate manifest path')
            entries[name]=(int(size),sha)
    except (UnicodeError,ValueError) as exc:
        raise ValueError('invalid exported manifest') from exc
    if set(entries)!=(set(files)-{'export.manifest'}):
        raise ValueError('missing/unlisted exported file')
    for name,(size,sha) in entries.items():
        if len(files[name])!=size or hashlib.sha256(files[name]).hexdigest()!=sha:
            raise ValueError('manifest does not match artifact bytes')
    out=Path(out)
    if out.exists():
        raise ValueError('refuse to overwrite an existing capture')
    out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.e2-extract-',dir=out.parent) as temporary:
        staging=Path(temporary)/'capture'; staging.mkdir(mode=0o700)
        for name,payload in files.items():
            path=staging/name; path.write_bytes(payload); path.chmod(0o600)
        os.rename(staging,out)
    return files


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('console',type=Path); p.add_argument('output',type=Path)
    a=p.parse_args()
    try:
        files=extract(a.console.read_text(errors='strict'),a.output)
    except (OSError,ValueError) as exc:
        p.exit(1,f'E2 artifact extraction FAIL: {exc}\n')
    print(f'E2_ARTIFACTS=PASS files={len(files)} bytes={sum(map(len,files.values()))}')
if __name__=='__main__': main()
