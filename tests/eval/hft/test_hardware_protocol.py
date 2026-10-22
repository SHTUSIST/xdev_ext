#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Pure framed-peer protocol/capture checks; no sockets, clocks or native work."""
import base64
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

import hardware_measure as hardware
from test_oracle import packet

HERE=Path(__file__).resolve().parent
PROFILE=dict(schema=1,record_bytes=64,payload_bytes=512,burst_packets=2,depth=2,
             bursts=2,actors=1,seed=9,session_base=1234)
IDENTITY=dict(token='1'*32,manifest_sha256=hashlib.sha256(hardware.canonical(PROFILE)).hexdigest(),
              session_base=1234,source_sha='a'*64,product_sha='d'*40)


class FramedBytes:
    def __init__(self,values):
        self.incoming=b''.join(struct.pack('!I',len(hardware.canonical(v)))+hardware.canonical(v) for v in values)
        self.sent=bytearray()
    def recv(self,n):
        # Fragment frames to exercise exact_read rather than one-shot reads.
        out=self.incoming[:min(n,7)];self.incoming=self.incoming[len(out):];return out
    def sendall(self,data):self.sent.extend(data)


def capture():
    return b''.join(struct.pack('!I',len(p))+p for p in
        (packet(PROFILE,0,g) for g in range(PROFILE['burst_packets']*PROFILE['bursts'])))


def transfer(data=None):
    data=capture() if data is None else data
    digest=hashlib.sha256(data).hexdigest();count=PROFILE['burst_packets']*PROFILE['bursts']
    finish=dict(version=1,op='FINISH_RECEIPT',status='ok',identity=dict(IDENTITY),
        actor=0,first_generation=1,packet_count=count,validated_packets=count,
        validated_bytes=count*PROFILE['payload_bytes'],capture_bytes=len(data),capture_sha256=digest)
    chunk=dict(version=1,op='CAPTURE_CHUNK',status='ok',identity=dict(IDENTITY),
        sequence=0,data=base64.b64encode(data).decode())
    end=dict(version=1,op='CAPTURE_END',status='ok',identity=dict(IDENTITY),chunks=1,bytes=len(data),sha256=digest)
    return finish,[chunk,end]


class PureHardwareProtocolTests(unittest.TestCase):
    def test_rpc_rejects_bad_operation_version_negative_status_and_early_exit(self):
        valid=dict(version=1,op='READY',status='ok',identity=dict(IDENTITY))
        self.assertEqual(hardware.rpc(FramedBytes([valid]),{},'READY'),valid)
        for key,value in [('version',True),('version',2),('op','BURST_RECEIPT'),('status','error')]:
            bad=dict(valid);bad[key]=value
            with self.subTest(field=key),self.assertRaises(ValueError):
                hardware.rpc(FramedBytes([bad]),{},'READY')
        with self.assertRaises(ValueError):hardware.receive_message(FramedBytes([]))
        stream=FramedBytes([]);stream.incoming=struct.pack('!I',hardware.MAX_FRAME+1)
        with self.assertRaises(ValueError):hardware.receive_message(stream)
    def test_identity_rejects_each_foreign_run_field_and_bool_session(self):
        hardware.same_identity(dict(identity=dict(IDENTITY)),IDENTITY)
        for key in IDENTITY:
            bad=copy.deepcopy(IDENTITY);bad[key]=True if key=='session_base' else 'foreign'
            with self.subTest(field=key),self.assertRaises(ValueError):
                hardware.same_identity(dict(identity=bad),IDENTITY)
    def test_capture_stream_full_bytes_reparse_and_semantic_mutants(self):
        with tempfile.TemporaryDirectory(prefix='.protocol-test-',dir=HERE) as directory:
            directory=Path(directory)
            finish,values=transfer()
            actual=hardware.capture_from_peer(FramedBytes(values),PROFILE,IDENTITY,finish,directory/'valid')
            self.assertEqual(actual,dict(status='ok',validated_packets=4,validated_bytes=2048))
            mutants=[]
            f,v=transfer();v[0]['identity']['session_base']+=1;mutants.append((f,v))
            f,v=transfer();v[0]['sequence']=True;mutants.append((f,v))
            f,v=transfer();v[1]['chunks']=2;mutants.append((f,v))
            f,v=transfer();f['validated_packets']=3;mutants.append((f,v))
            f,v=transfer();v[1]['bytes']=False;mutants.append((f,v))
            f,v=transfer();v[0]['data']='!!!';mutants.append((f,v))
            wrong=bytearray(capture());wrong[-1]^=1
            mutants.append(transfer(bytes(wrong)))  # matching stream hash cannot defeat payload oracle.
            mutants.append((finish,values[:-1]))
            for index,(bad_finish,bad_values) in enumerate(mutants):
                with self.subTest(mutant=index),self.assertRaises(ValueError):
                    hardware.capture_from_peer(FramedBytes(bad_values),PROFILE,IDENTITY,bad_finish,directory/('bad'+str(index)))


if __name__=='__main__':unittest.main()
