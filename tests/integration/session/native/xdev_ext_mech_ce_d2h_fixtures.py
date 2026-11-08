# SPDX-License-Identifier: GPL-2.0
"""Synthetic protocol fixtures, never evidence of guest/device execution."""

def cli_fixture(chain,mode):
    bad=8192 if mode=='skip_d2h' else 0
    result='FAIL' if chain=='d' and bad else 'PASS'
    vector='1,1,1,1' if chain=='a' else '1,1,0,0'
    lines=[
      'XDEV_EXT_MECH_READY mode=source session=19 frames=6 seg_len=1408 xsk=none',
      'XDEV_EXT_MECH_NOTIFY mode=terminal eventfd_reads=1 stats_reads=1',
    ]
    if chain=='d':lines.append('XDEV_EXT_MECH_CE_HOST_DATA chain=d payload_bytes=8192 checked_bytes=24576 mismatches=%d guard_mismatches=0'%bad)
    lines += [
      'XDEV_EXT_MECH_CE_WINDOW=PASS chain=%s written=1 depth=1 poison=0xc3 reference=%s error=0'%(chain,'frames' if chain=='d' else 'none'),
      'XDEV_EXT_MECH_CE_SIM=%s chain=%s'%(result,chain),
      'XDEV_EXT_MECH_STATS session=19 state=ACTIVE last_err=0 batches_done=1 batches_abort=0 rejects=0 recycled=0 held=6 sequestered=0 timeouts=0 inflight=0 native_publish=0 protocol_err=0 published=6 submitted=%s completed=%s'%(vector,vector),
    ]
    return '\n'.join(lines)+'\n'

def d2h_fixture(delay_us=0):
    lines=[]
    for mode in ('none','skip_d2h'):
        for chain in ('a','d'):
            name=chain+'-'+mode;bad=8192 if mode=='skip_d2h' else 0
            lines += ['XDEV_EXT_ZC_D2H_BEGIN case='+name,
              'XDEV_EXT_ZC_D2H_MODULE case=%s phase=before accepted=0 completed=0 pending=0 refcnt=0 mode=%s poison=Y delay_us=%d'%(name,mode,delay_us)]
            lines += ['XDEV_EXT_ZC_D2H_RAW case=%s stream=cli %s'%(name,line) for line in cli_fixture(chain,mode).splitlines()]
            if chain=='a':lines += ['XDEV_EXT_ZC_D2H_RAW case=%s stream=verify XDEV_EXT_MECH_VERIFY_XFORM=%s xform=none bytes=8192 mismatches=%d'%(name,'FAIL' if bad else 'PASS',bad)]
            lines += ['XDEV_EXT_ZC_D2H_EXIT case=%s cli=%d verify=%d'%(name,int(chain=='d' and bad!=0),int(bad!=0) if chain=='a' else -1),
              'XDEV_EXT_ZC_D2H_MODULE case=%s phase=after accepted=2 completed=2 pending=0 refcnt=0 mode=%s poison=Y delay_us=%d'%(name,mode,delay_us),
              'XDEV_EXT_ZC_D2H_UNLOAD case=%s status=0'%name,
              'XDEV_EXT_ZC_D2H_END case='+name]
    lines.append('XDEV_EXT_ZC_CE_D2H_DIAGNOSTIC=PASS cases=4 groups=1 depth=1 group_bytes=8192 backend=CPU-memcpy-standin')
    return '\n'.join(lines)+'\n'
