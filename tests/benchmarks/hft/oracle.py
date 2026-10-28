#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent receiver and full-byte replay oracle. Uses no producer code."""
import argparse
import json
import os
import select
import socket
import struct
import sys
import time

KEYS = {'schema','record_bytes','payload_bytes','burst_packets','depth','bursts','actors','seed','session_base'}
FMT = '!IBBBBQIHHIIII'


def profile(path):
    with open(path, encoding='utf-8') as stream:
        p = json.load(stream)
    if type(p) is not dict or set(p) != KEYS or any(type(v) is not int for v in p.values()):
        raise ValueError('manifest fields/types')
    if (p['schema'] != 1 or p['record_bytes'] not in (64,128,256)
        or p['payload_bytes'] not in (512,1024,4096)
        or p['payload_bytes'] % p['record_bytes'] or p['actors'] not in (1,4)
        or not 1 <= p['burst_packets'] <= 32 or not 1 <= p['depth'] <= 8
        or not 1 <= p['bursts'] <= 32 or not 0 <= p['seed'] < 2**64
        or not 0 <= p['session_base'] <= 2**64-p['actors']):
        raise ValueError('manifest geometry')
    groups=p['actors']*p['burst_packets']*p['bursts']
    if groups > 1048576 or groups*p['payload_bytes'] > 2**30:
        raise ValueError('manifest bound')
    return p


def payload(p,a,g):
    out=bytearray()
    for r in range(p['payload_bytes']//p['record_bytes']):
        out.extend(struct.pack('!IHHIHH',0x4846544d,a,p['record_bytes'],g,r,0))
        out.extend((p['seed']+29*a+17*g+11*r+7*j)&255 for j in range(16,p['record_bytes']))
    return bytes(out)


def crc32c(data):
    crc=0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc=(crc>>1) ^ (0x82f63b78 if crc&1 else 0)
    return crc ^ 0xffffffff


class Validator:
    def __init__(self,p):
        self.p=p
        self.seen=set()
        self.groups=p['burst_packets']*p['bursts']
        self.count=p['actors']*self.groups
    def add(self,data):
        p=self.p
        if len(data) != p['payload_bytes']+40:
            raise ValueError('datagram size')
        h=struct.unpack(FMT,data[:40])
        a=h[5]-p['session_base']; g=h[6]-1
        if h[:5] != (0x4e585032,2,40,2,0) or h[7:12] != (0,1,p['payload_bytes'],0,p['payload_bytes']):
            raise ValueError('wire header')
        if not 0<=a<p['actors'] or not 0<=g<self.groups or (a,g) in self.seen:
            raise ValueError('foreign/duplicate/stale/extra packet')
        if crc32c(data[:36]+bytes(4)+data[40:]) != h[12]:
            raise ValueError('CRC32C')
        if data[40:] != payload(p,a,g):
            raise ValueError('payload bytes')
        self.seen.add((a,g))
    def finish(self):
        if len(self.seen) != self.count:
            raise ValueError('missing packets')
        return dict(status='ok',validated_packets=self.count,validated_bytes=self.count*self.p['payload_bytes'])


def exclusive(path):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        os.fchmod(fd,0o600)
        return os.fdopen(fd,'wb')
    except BaseException:
        os.close(fd)
        raise


def generate(p,path):
    with exclusive(path) as stream:
        for a in range(p['actors']):
            for g in range(p['burst_packets']*p['bursts']):
                stream.write(payload(p,a,g))


def verify(p,path):
    v=Validator(p)
    with open(path,'rb') as stream:
        while True:
            length=stream.read(4)
            if not length: break
            if len(length)!=4: raise ValueError('capture prefix truncated')
            n=struct.unpack('!I',length)[0]
            if n != p['payload_bytes']+40: raise ValueError('capture bound')
            data=stream.read(n)
            v.add(data)
    return v.finish()


def address(value):
    ip,port=value.rsplit(':',1)
    socket.inet_aton(ip)
    return ip,int(port)


def receive(p,bind,control,capture):
    v=Validator(p)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as ctl, exclusive(capture) as output:
        udp.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
        udp.bind(address(bind)); ctl.bind(address(control))
        print(json.dumps(dict(status='ready',bind=list(udp.getsockname()),control=list(ctl.getsockname()))),flush=True)
        pending=[]; end=time.monotonic()+60
        while True:
            if time.monotonic()>end: raise ValueError('receiver timeout/missing producer')
            ready,_,_=select.select([udp,ctl],[],[],0.1)
            if udp in ready:
                data,_,flags,_=udp.recvmsg(p['payload_bytes']+40,0)
                if flags&socket.MSG_TRUNC: raise ValueError('MSG_TRUNC')
                v.add(data)
                output.write(struct.pack('!I',len(data))+data)
            if ctl in ready:
                data,peer=ctl.recvfrom(4096)
                req=json.loads(data)
                if req.get('op')=='receipt':
                    a,first,n=req['actor'],req['first'],req['count']
                    if req.get('session_base')!=p['session_base']:raise ValueError('foreign receipt session')
                    if (type(a) is not int or type(first) is not int or type(n) is not int
                        or not 0<=a<p['actors'] or n!=p['burst_packets']
                        or first<0 or first+n>v.groups or first%n):
                        raise ValueError('receipt geometry')
                    pending.append((peer,a,first,n))
                elif req.get('op')=='finish':
                    result=v.finish()
                    # Reject packets queued after the last expected packet, including extras.
                    if select.select([udp],[],[],0.1)[0]:
                        data,_,flags,_=udp.recvmsg(p['payload_bytes']+40,0)
                        if flags&socket.MSG_TRUNC: raise ValueError('extra truncated packet')
                        v.add(data)
                    output.flush()
                    ctl.sendto(json.dumps(result).encode(),peer)
                    print(json.dumps(result),flush=True)
                    return
                else: raise ValueError('control operation')
            for item in list(pending):
                peer,a,first,n=item
                if all((a,g) in v.seen for g in range(first,first+n)):
                    ctl.sendto(json.dumps(dict(status='ok',actor=a,first=first,count=n,validated_bytes=n*p['payload_bytes'],session_base=p['session_base'])).encode(),peer)
                    pending.remove(item)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('generate','verify','receive'))
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--reference'); parser.add_argument('--capture')
    parser.add_argument('--bind'); parser.add_argument('--control')
    args=parser.parse_args()
    try:
        p=profile(args.manifest)
        if args.action=='generate': generate(p,args.reference)
        elif args.action=='verify': print(json.dumps(verify(p,args.capture)))
        else: receive(p,args.bind,args.control,args.capture)
        return 0
    except (OSError,ValueError,TypeError,KeyError,struct.error) as error:
        print(json.dumps(dict(status='error',diagnostic=str(error))),file=sys.stderr)
        return 1
if __name__=='__main__': sys.exit(main())
