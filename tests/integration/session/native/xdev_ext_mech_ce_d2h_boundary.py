#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Host test command boundary for the actual POSIX guest script; no devices."""
import json
import os
from pathlib import Path
import shutil
import sys
from xdev_ext_mech_ce_d2h_fixtures import cli_fixture

def main():
    root=Path(os.environ['D2H_SYSFS_ROOT']);fault=os.environ.get('D2H_BOUNDARY_FAULT','')
    action=Path(sys.argv[0]).name;args=sys.argv[1:]
    with (Path(os.environ['D2H_LOG_DIR'])/'commands.jsonl').open('a') as out:
        out.write(json.dumps([action,*args])+'\n')
    def read(name):return (root/'parameters'/name).read_text().strip()
    def write(name,val):(root/'parameters'/name).write_text(str(val)+'\n')
    if action=='insmod':
        values=dict(arg.split('=',1) for arg in args[1:])
        assert not root.exists(),'previous module was not unloaded'
        assert values['poison_after_h2d']=='1'
        (root/'parameters').mkdir(parents=True)
        for key,value in {'accepted':0,'completed':0,'pending':0,'delay_us':values['delay_us'],
                          'fail_mode':values['fail_mode'],'poison_after_h2d':'Y'}.items():write(key,value)
        if fault=='mode':write('fail_mode','ambiguous')
        if fault=='poison':write('poison_after_h2d','N')
        (root/'refcnt').write_text('0\n');return 0
    if action=='rmmod':
        if fault=='unload' or (root/'pin').exists():return 1
        shutil.rmtree(root);return 0
    command=args[0]
    if command=='attach':(root/'pin').touch();return 0
    if command=='detach':(root/'pin').unlink();return 0
    mode=read('fail_mode')
    if command=='verify-xform':
        opts=dict(zip(args[1::2],args[2::2]));assert opts['--bytes']=='8192'
        assert opts['--src-off']==str(2048*512) and opts['--dst-off']==str(8192*512)
        bad=8192 if mode=='skip_d2h' else 0
        if fault=='verify-bad':bad=1
        print('XDEV_EXT_MECH_VERIFY_XFORM=%s xform=none bytes=8192 mismatches=%d'%('FAIL' if bad else 'PASS',bad))
        return 3 if fault=='verify-exit' else int(bool(bad))
    assert command=='ce-chain'
    opts=dict(zip(args[1::2],args[2::2]));chain=opts['--chain']
    for key,value in {'--ce-len':'8192','--groups':'1','--depth':'1','--group-bytes':'8192','--timeout-ms':'60000'}.items():assert opts[key]==value
    if chain=='a':assert opts['--slba']=='2048' and opts['--dst-slba']=='8192' and opts['--nlb']==opts['--dst-nlb']=='16'
    text=cli_fixture(chain,mode)
    edits={
      'notify':('eventfd_reads=1','eventfd_reads=2'),
      'stage':('completed=1,1,1,1','completed=1,1,0,0'),
      'window':('CE_WINDOW=PASS','CE_WINDOW=FAIL'),
      'host-bad':('mismatches=8192','mismatches=8191'),
      'host-guard':('guard_mismatches=0','guard_mismatches=1'),
      'host-checked':('checked_bytes=24576','checked_bytes=8000'),
      'missing-field':('last_err=0 ','last_err= '),
    }
    if fault in edits:text=text.replace(*edits[fault])
    if fault=='duplicate':text += next(line+'\n' for line in text.splitlines() if line.startswith('XDEV_EXT_MECH_STATS '))
    print(text,end='')
    write('accepted',3 if fault=='count' else 2);write('completed',2)
    write('pending',1 if fault=='pending' else 0)
    if fault=='refs':(root/'refcnt').write_text('1\n')
    return 3 if fault=='cli-exit' else int(chain=='d' and mode=='skip_d2h')

if __name__=='__main__':raise SystemExit(main())
