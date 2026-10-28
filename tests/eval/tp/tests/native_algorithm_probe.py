#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Thin request/observation adapter for actual production host/device helpers."""
import json
import os
from pathlib import Path
import subprocess
import sys
DTYPES={'f16':1,'bf16':2,'f32':3}
def payload(bits,dtype):
    n=4 if dtype=='f32' else 2
    return b''.join(int(b,16).to_bytes(n,'little') for b in bits).hex()
def shape(h,local=False):
    return list(map(str,[h['communicator_id'],h['epoch'],h['sequence'],h['rows'],h['local_width'],h['operation'],h['dtype'],h['rank']^int(local),h['world_size'],0]))
def spans(r):return ','.join(str(s['allocation_offset'])+':'+str(s['length']) for s in r['spans' if 'spans' in r else 'rx_spans'])
def main():
    data=json.load(sys.stdin);r=data['request'];a=r['action'];dtype=r.get('dtype','f32')
    exe=os.environ.get('XDEV_TP_ALGORITHM_PROBE')
    if not exe:
        print(json.dumps({'blocked':'XDEV_TP_ALGORITHM_PROBE is not a compiled production helper adapter'}));return 2
    if a=='sum':
        args=['sum',str(DTYPES[dtype]),payload(r['local_bits'],dtype),payload(r['peer_bits'],dtype)]
    elif a=='gather' and data['family']=='algorithm':
        args=['gather',str(DTYPES[dtype]),str(r['rank']),str(r['rows']),str(r['local_width']),payload(r['rank0_bits'],dtype),payload(r['rank1_bits'],dtype),'reserved']
    elif a=='pack':
        args=['pack',*shape(r['header']),r['payload_hex'],str(r['allocation_bytes']),str(r['initial_byte']),spans(r),'reserved']
    elif a=='receive_sum':
        h=r['expected_header'];guard='rx_wire_hex' in r
        local=payload(r.get('local_bits',['00000000']*h['local_width']),dtype)
        args=['receive',*shape(h,True),local,r['output_initial_hex'],r['rx_allocation_hex'],spans(r),str(r['actual_rx_key']),str(r['actual_tx_sequence']),str(int(guard))]
    else:
        print(json.dumps({'blocked':'This adapter covers same-source algorithms only; actual production library/bridge/runner required'}));return 2
    result=subprocess.run([str(Path(exe).resolve()),*args],text=True,capture_output=True)
    sys.stdout.write(result.stdout);sys.stderr.write(result.stderr);return result.returncode
if __name__=='__main__':sys.exit(main())
