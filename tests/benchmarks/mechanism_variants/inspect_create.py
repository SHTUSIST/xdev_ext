#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compare actual 200-byte CREATE snapshots and bound fd resource identity.

The C producer statically asserts this x86_64 ABI size. All bytes except
explicit descriptor numbers are retained; every resource snapshot is delivered
alongside the raw request. Only the successful syscall's output session ID is
excluded from the input comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def inspect(prefix):
    def artifact(suffix):
        return Path(str(prefix)+'.'+suffix)
    raw=artifact('before').read_bytes()
    after=bytearray(artifact('after').read_bytes())
    if len(raw)!=200 or len(after)!=200:
        raise ValueError('unsupported actual CREATE ABI size')
    abi,nr,pool_kind,pool_fd=struct.unpack_from('<IIIi',raw)
    depth,eventfd=struct.unpack_from('<Ii',raw,32)
    input_session=struct.unpack_from('<Q',raw,192)[0]
    session=struct.unpack_from('<Q',after,192)[0]
    result=json.loads(artifact('result.json').read_text())
    if not 1<=nr<=4 or input_session:
        raise ValueError('invalid input CREATE request')
    if result['syscall_return']<0 or result['errno'] or not session or session!=result['session_id']:
        raise ValueError('actual CREATE syscall did not return the recorded session')
    struct.pack_into('<Q',after,192,0)
    if bytes(after)!=raw:
        raise ValueError('CREATE changed an input field beyond output session ID')
    roles={'pool':pool_fd,'eventfd':eventfd}
    offsets={'pool':12,'eventfd':36}
    stages=[]
    for index in range(nr):
        cls,direction,fd,flags,arg0,arg1=struct.unpack_from('<IIiIQQ',raw,64+index*32)
        roles[f'stage{index}']=fd; offsets[f'stage{index}']=72+index*32
        stages.append(dict(class_id=cls,direction=direction,flags=flags,arg0=arg0,arg1=arg1))
    resources=json.loads(artifact('resources.json').read_text())
    if set(resources)!=set(roles):
        raise ValueError('missing bound fd resource evidence')
    normalized_resources={}
    normalized=bytearray(raw)
    for role,fd in roles.items():
        if resources[role]['fd']!=fd:
            raise ValueError('actual fd resource metadata differs from raw request')
        for field in ('file_type','rdev_major','rdev_minor','inode','socket_family'):
            if not isinstance(resources[role][field],int):
                raise ValueError('invalid resource metadata')
        normalized_resources[role]={k:v for k,v in resources[role].items() if k not in ('fd','inode')}
        struct.pack_into('<i',normalized,offsets[role],0)
    aliases={role:sorted(k for k,v in roles.items() if fd>=0 and v==fd) for role,fd in roles.items()}
    layout=dict(zip(('frame_size','hdr_room','seg_len','group_bytes'),struct.unpack_from('<4I',raw,16)))
    create=dict(abi_version=abi,nr_stages=nr,pool_kind=pool_kind,depth=depth,layout=layout,
                peer_raw_hex=raw[40:64].hex(),stages=stages,resources=normalized_resources,
                fd_aliases=aliases,normalized_raw_hex=normalized.hex())
    return dict(create=create,actual_session_id=session,syscall_return=result['syscall_return'],
                errno=result['errno'],raw_before_sha256=hashlib.sha256(raw).hexdigest())


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('prefix',type=Path); p.add_argument('output',type=Path)
    p.add_argument('--compare',type=Path)
    a=p.parse_args()
    try:
        data=inspect(a.prefix)
        if a.compare is not None and data['create']!=inspect(a.compare)['create']:
            raise ValueError('A/B actual CREATE bytes or bound resources differ')
        with a.output.open('x') as out:
            json.dump(data,out,indent=2); out.write('\n')
    except (OSError,ValueError,KeyError) as exc:
        p.exit(1,f'E2 CREATE audit FAIL: {exc}\n')
    print(f'E2_CREATE_AUDITED actual_session_id={data["actual_session_id"]} performance_claim=none')
if __name__=='__main__': main()
