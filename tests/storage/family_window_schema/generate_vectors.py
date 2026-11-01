#!/usr/bin/env python3
"""Contract-only arbitrary-precision oracle; emits literal expected C vectors.
No production source, existing tests or candidate implementation is opened.
"""
from pathlib import Path
import errno
import random
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
rng = random.Random(0x53544F523435)

def bind(cap, shift, start, count, group):
    if shift < 9: return -errno.EINVAL
    if shift >= 32: return -errno.EOVERFLOW
    if group == 0: return -errno.EINVAL
    if group % (1 << shift) or group // (1 << shift) > 65536:
        return -errno.EMSGSIZE
    if count == 0: return -errno.EINVAL
    if start >= cap or count > cap - start or group // (1 << shift) > count:
        return -errno.ERANGE
    return 0

def admit(cap, shift, start, count, slba, nlb, data):
    if nlb == 0: return -errno.EINVAL
    if slba < start or slba - start >= count or nlb > count - (slba - start):
        return -errno.ERANGE
    if nlb * (1 << shift) > U64: return -errno.EOVERFLOW
    if data == 0: return -errno.EINVAL
    if nlb * (1 << shift) > U32 or nlb * (1 << shift) != data:
        return -errno.EMSGSIZE
    if slba * (1 << shift) > U64: return -errno.EOVERFLOW
    if slba >= cap or nlb > cap - slba: return -errno.ERANGE
    return 0

def validate(cap, shift, start, count, slba, nlb, data, write, opcode, bad_dw, bad_bit, control, allow):
    if shift < 9: return -errno.EINVAL
    if shift >= 32: return -errno.EOVERFLOW
    if opcode != (1 if write else 2): return -errno.EOPNOTSUPP
    if bad_dw != 16: return -errno.EPERM
    if control & ~allow: return -errno.EPERM
    return admit(cap, shift, start, count, slba, nlb, data)

def lit(v):
    return f'UINT64_C({v})'

def row(values):
    return '{' + ','.join(str(x) if isinstance(x, int) and x < 0 else lit(x) for x in values) + '},'

text=['/* Generated with fixed seed 0x53544f523435 from CONTRACT sections4/5. */']
text.append('static const struct bind_vector random_bind[] = {')
for _ in range(512):
    shift=rng.choice([0,8,9,12,16,31,32,63])
    cap=rng.choice([0,1,8,1000,(1<<32),U64])
    start=rng.choice([0,1,100,992,1000,max(0,cap-1),cap,U64])
    count=rng.choice([0,1,2,8,65536,U64])
    group=rng.choice([0,1,512,513,4096,8192,33554432,33554944,U32])
    text.append(row([cap,shift,start,count,group,bind(cap,shift,start,count,group)]))
text.append('};')
text.append('static const struct validate_vector random_validate[] = {')
for _ in range(768):
    shift=rng.choice([8,9,12,16,31,32,63])
    cap=rng.choice([8,1000,(1<<32),U64])
    start=rng.choice([0,1,100,992,max(0,cap-8),U64-8])
    count=rng.choice([0,1,8,65536,U64])
    slba=rng.choice([0,max(0,start-1),start,min(U64,start+1),min(U64,start+7),min(U64,start+8),U64])
    nlb=rng.choice([1,2,8,65535,65536])
    nbytes=nlb*(1<<shift)
    data=rng.choice([0,1,512,4096,U32,nbytes if nbytes<=U32 else U32])
    write=rng.randrange(2);opcode=rng.choice([1,2,2,2,0,255])
    bad_dw=rng.choice([16,16,16,0,2,14]);bad_bit=8 if bad_dw==0 else rng.randrange(32)
    control=rng.choice([0,0,1,0x8000]);allow=rng.choice([0,0,1,0xffff])
    want=validate(cap,shift,start,count,slba,nlb,data,write,opcode,bad_dw,bad_bit,control,allow)
    text.append(row([cap,shift,start,count,slba,nlb,data,write,opcode,bad_dw,bad_bit,control,allow,want]))
# Deliberately reach decoded output and late checks, rather than allowing
# boundary-biased malformed cases to mask all successful random requests.
for _ in range(128):
    shift=rng.choice([9,12,16,31])
    nlb=rng.randint(1,min(65536,U32>>shift))
    start=rng.randint(1,(U64>>shift)-65540)
    count=nlb+4;slba=start+2;cap=start+count+10;data=nlb*(1<<shift)
    write=rng.randrange(2);opcode=1 if write else 2
    for request,length,want in [(slba,data,0),(start-1,data,-errno.ERANGE),(slba,data+1,-errno.EMSGSIZE)]:
        text.append(row([cap,shift,start,count,request,nlb,length,write,opcode,16,0,0,0,want]))
text.append('};')
text.append('static const struct admit_vector random_admit[] = {')
for _ in range(512):
    shift=rng.choice([9,12,16,31]);cap=rng.choice([1000,(1<<32),U64])
    start=rng.choice([0,1,100,max(0,cap-8),(U64>>shift)+1 if cap==U64 else 0])
    count=rng.choice([1,8,min(65536,cap-start),cap-start])
    slba=rng.choice([0,max(0,start-1),start,min(U64,start+1),min(U64,start+count-1),min(U64,start+count),U64])
    nlb=rng.choice([0,1,2,8,65536,(U64>>shift)+1])
    nbytes=nlb*(1<<shift)
    data=rng.choice([0,512,4096,U32,nbytes if nbytes<=U32 else U32])
    want=admit(cap,shift,start,count,slba,nlb,data)
    text.append(row([cap,shift,start,count,slba,nlb,data,want]))
text.append('};')
Path(__file__).with_name('vectors.inc').write_text('\n'.join(text)+'\n')
