#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host execution of the supplemental D2H guest evidence contract."""
import json
import os
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path
import unittest
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from xdev_ext_mech_zc_validate_test import console_fixture, GROUPS
from xdev_ext_mech_zc_validate import validate_console
from xdev_ext_mech_ce_d2h_validate import validate_d2h_console
from xdev_ext_mech_ce_d2h_fixtures import d2h_fixture

class D2hEvidence(unittest.TestCase):
    def test_summary_cannot_replace_four_raw_cases(self):
        text=console_fixture(include_d2h=False)+"XDEV_EXT_ZC_CE_D2H_DIAGNOSTIC=PASS cases=4 groups=1 depth=1 group_bytes=8192 backend=CPU-memcpy-standin\n"
        with self.assertRaises(ValueError):
            validate_console(text,groups=GROUPS,ce_sim=True,ce_delay_us=100000)


class RawEvidence(unittest.TestCase):
    def test_complete_raw_fixture(self):
        self.assertEqual(validate_d2h_console(d2h_fixture(10000),delay_us=10000),{'cases':4,'group_bytes':8192})

    def test_missing_duplicate_or_corrupt_each_case_record(self):
        base=d2h_fixture(10000);lines=base.splitlines()
        for index,line in enumerate(lines):
            if not line.startswith('XDEV_EXT_ZC_D2H_'):continue
            for change in ('remove','duplicate'):
                with self.subTest(index=index,change=change):
                    mutant=lines[:index]+([] if change=='remove' else [line,line])+lines[index+1:]
                    with self.assertRaises(ValueError):validate_d2h_console('\n'.join(mutant),delay_us=10000)
        changes=[('mismatches=8192','mismatches=8191'),('mismatches=0','mismatches=1'),
          ('guard_mismatches=0','guard_mismatches=1'),('accepted=2','accepted=3'),
          ('completed=2','completed=1'),('pending=0','pending=1'),('refcnt=0','refcnt=1'),
          ('poison=Y','poison=N'),('mode=skip_d2h','mode=none'),('status=0','status=1'),
          ('cli=1','cli=0'),('verify=1','verify=0'),('depth=1','depth=2'),
          ('bytes=8192','bytes=8191'),('eventfd_reads=1','eventfd_reads=2'),
          ('last_err=0','last_err=-5'),('submitted=1,1,0,0','submitted=1,2,0,0'),
          ('state=ACTIVE','state=STOPPED'),('checked_bytes=24576','checked_bytes=8192')]
        for old,new in changes:
            with self.subTest(old=old,new=new):
                self.assertIn(old,base)
                with self.assertRaises(ValueError):validate_d2h_console(base.replace(old,new,1),delay_us=10000)

class ActualGuestShell(unittest.TestCase):
    def run_guest(self,shell,fault=''):
        with tempfile.TemporaryDirectory(prefix='d2h-shell-') as temp:
            root=Path(temp);bins=root/'bin';bins.mkdir();logs=root/'logs';logs.mkdir()
            for name in ('insmod','rmmod','ctl'):(bins/name).symlink_to(HERE/'xdev_ext_mech_ce_d2h_boundary.py')
            for name in ('cat','mkdir','sleep'):(bins/name).symlink_to('/bin/busybox')
            # A bare awk command must not accidentally succeed on the host.
            (bins/'awk').write_text('#!/bin/sh\nexit 99\n');(bins/'awk').chmod(0o755)
            env=dict(os.environ,PATH=str(bins),D2H_SYSFS_ROOT=str(root/'module'),
                     D2H_LOG_DIR=str(logs),D2H_POLL_ROUNDS='1',D2H_BOUNDARY_FAULT=fault,
                     D2H_INSMOD=str(bins/'insmod'),D2H_RMMOD=str(bins/'rmmod'))
            command=[*shell,str(HERE/'xdev_ext_mech_ce_d2h_guest.sh'),str(bins/'ctl'),'sim.ko','plan.o',
                     'source-ng','source-block','dest-ng','dest-block','2048','8192','10000','60000']
            result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=20)
            self.assertTrue((logs/'commands.jsonl').is_file(),result.stdout+result.stderr)
            trace=[json.loads(line) for line in (logs/'commands.jsonl').read_text().splitlines()]
            if os.environ.get('D2H_TEST_LOG_DIR'):
                out=Path(os.environ['D2H_TEST_LOG_DIR']);out.mkdir(parents=True,exist_ok=True)
                tag=('busybox' if len(shell)>1 else 'sh')+'-'+(fault or 'positive')
                (out/(tag+'.log')).write_text(result.stdout+result.stderr+'\nexit=%d\n'%result.returncode)
            return result,trace

    def test_four_cases_execute_and_validate_under_both_shells(self):
        for shell in (('/bin/sh',),('/bin/busybox','sh')):
            with self.subTest(shell=shell):
                result,trace=self.run_guest(shell)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(validate_d2h_console(result.stdout,delay_us=10000)['cases'],4)
                self.assertEqual([x[0] for x in trace].count('insmod'),4)
                self.assertEqual([x[0] for x in trace].count('rmmod'),4)
                validate_console(console_fixture(include_d2h=False,delay_us=10000)+result.stdout,
                                 groups=GROUPS,ce_sim=True,ce_delay_us=10000)

    def test_failed_behavior_never_prints_summary(self):
        faults=('notify','stage','window','host-bad','host-guard','host-checked','duplicate','missing-field',
                'mode','poison','count','pending','refs','unload','cli-exit','verify-bad','verify-exit')
        for shell in (('/bin/sh',),('/bin/busybox','sh')):
            for fault in faults:
                with self.subTest(shell=shell,fault=fault):
                    result,_=self.run_guest(shell,fault)
                    self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertNotIn('XDEV_EXT_ZC_CE_D2H_DIAGNOSTIC=PASS',result.stdout)

class CliHostCounts(unittest.TestCase):
    def test_actual_host_checker_counts_every_payload_and_guard_byte(self):
        root=HERE.parents[3]
        source_path=root/'src/cli/xdev_ext_mech_ctl.c'
        if not source_path.is_file():source_path=root/'tools/xdev_ext_mech/xdev_ext_mech_ctl.c'
        source=source_path.read_text()
        def extract(name):
            pos=source.index(name+'(');start=source.rfind('\nstatic ',0,pos)+1
            opening=source.index('{',pos);end=opening+1;level=1
            while level:level+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[start:end]
        engine=extract('ctl_pattern')+'\n'+extract('ctl_pattern_check')
        prelude='#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\ntypedef uint8_t __u8; typedef uint32_t __u32; typedef uint64_t __u64;\nstruct xdev_ext_mech_layout {__u32 frame_size,hdr_room,seg_len,group_bytes;};\n'
        exercise='\nint main(void) {\n unsigned char frame[24576];\n struct xdev_ext_mech_layout l={4096,256,1408,8192};\n const unsigned offset[]={256,4352,8448,12544,16640,20736};\n const unsigned length[]={1408,1408,1408,1408,1408,1152};\n __u64 bad,guard;\n for(unsigned i=0;i<6;i++)for(unsigned j=0;j<4096;j++)frame[i*4096+j]=(unsigned char)(i*131+j*7+0x5a);\n ctl_pattern_check(frame,6,&l,&bad,&guard);\n if(bad || guard){puts("HOST_ASSERT correct data rejected");return 1;}\n for(unsigned i=0;i<6;i++)for(unsigned j=0;j<length[i];j++)frame[offset[i]+j]^=255;\n ctl_pattern_check(frame,6,&l,&bad,&guard);\n if(bad!=8192 || guard){puts("HOST_ASSERT whole payload count missing");return 1;}\n frame[24575]^=255;\n ctl_pattern_check(frame,6,&l,&bad,&guard);\n if(bad!=8192 || guard!=1){puts("HOST_ASSERT late guard error hidden");return 1;}\n puts("HOST_COUNTS PASS payload=8192 guard=1");return 0;\n}\n'
        with tempfile.TemporaryDirectory(prefix='d2h-cli-counts-') as temp:
            out=Path(temp)
            for variant,body in [('baseline',engine),('early-stop',engine.replace(
                    'for (i = 0; i < nr; i++)','for (i = 0; i < nr && !*payload_bad && !*guard_bad; i++)'))]:
                for profile,flags in [('ubsan',['-fsanitize=undefined','-fno-sanitize-recover=all']),
                                      ('asan',['-fsanitize=address','-fno-omit-frame-pointer'])]:
                    with self.subTest(variant=variant,profile=profile):
                        c=out/'test.c';c.write_text(prelude+body+exercise);binary=out/'test'
                        build=subprocess.run(['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',*flags,str(c),'-o',str(binary)],capture_output=True,text=True)
                        self.assertEqual(build.returncode,0,build.stdout+build.stderr)
                        run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
                        if os.environ.get('D2H_TEST_LOG_DIR'):
                            log=Path(os.environ['D2H_TEST_LOG_DIR']);log.mkdir(parents=True,exist_ok=True)
                            (log/('host-count-'+variant+'-'+profile+'.log')).write_text(run.stdout+run.stderr+'\nexit=%d\n'%run.returncode)
                        self.assertEqual(run.returncode,0 if variant=='baseline' else 1,run.stdout+run.stderr)
                        self.assertIn('HOST_COUNTS PASS' if variant=='baseline' else 'HOST_ASSERT ',run.stdout)

if __name__=='__main__':unittest.main()
