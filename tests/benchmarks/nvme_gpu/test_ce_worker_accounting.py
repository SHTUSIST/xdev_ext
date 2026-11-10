#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real compiled optional worker accounting controls; HOST fixtures, not GPU proof."""
import atexit
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HEADER = Path(os.environ.get('CE_WORKER_TEST_HEADER', HERE/'ce_worker_accounting.h'))
OUTPUT = Path(os.environ['CE_WORKER_TEST_OUTPUT']) if os.environ.get('CE_WORKER_TEST_OUTPUT') else None
RUNS = []
_REAL_RUN = subprocess.run
if OUTPUT:
    OUTPUT.mkdir(parents=True,exist_ok=False)
def run(argv, **kwargs):
    result = _REAL_RUN(argv, **kwargs)
    if OUTPUT:
        record = dict(argv=list(map(str,argv)),exit=result.returncode)
        for key in ['stdout','stderr']:
            value=getattr(result,key)
            record[key]=value.decode(errors='replace') if isinstance(value,bytes) else value
        RUNS.append(record)
        if str(argv[0]).endswith('gcc'):
            for arg in argv[1:]:
                if str(arg).endswith('.c'):
                    (OUTPUT/f'compiled-{len(RUNS)}.c').write_bytes(Path(arg).read_bytes())
    return result
def save_runs():
    if OUTPUT:
        (OUTPUT/'runs.json').write_text(json.dumps(dict(header=str(HEADER),header_sha256=hashlib.sha256(HEADER.read_bytes()).hexdigest() if HEADER.exists() else None,runs=RUNS),indent=2)+'\n')
atexit.register(save_runs)

class Modes(unittest.TestCase):
    def test_real_argument_loop(self):
        source = (HERE / 'ce_repeat_start_probe.c').read_text()
        start = source.index(' for (i = 1; i < (unsigned int)argc; i++)')
        end = source.index(' if (es_ce_is_sim(dev)', start)
        parser = source[start:end]
        code = '''#include <stdbool.h>\n#include <string.h>\n#define XG_EXIT_USAGE 3
int main(int argc, char **argv) {
 bool wait_aba=false, worker_accounting=false;
 const char *dev="/dev/nvidia0"; unsigned int i;
''' + parser + '\n (void)dev; return worker_accounting ? 70 : wait_aba ? 21 : 7;\n}\n'
        with tempfile.TemporaryDirectory(prefix='cwa-modes-') as tmp:
            c = Path(tmp) / 'modes.c'; binary = Path(tmp) / 'modes'; c.write_text(code)
            compile_run = run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(compile_run.returncode,0,compile_run.stderr)
            for args,expected in [([],7),(['--wait-aba'],21),(['--worker-accounting'],70),(['--worker-accounting','--wait-aba'],3),(['--wait-aba','--worker-accounting'],3),(['--worker-accounting','--worker-accounting'],3)]:
                with self.subTest(args=args):
                    self.assertEqual(run([str(binary),*args],capture_output=True).returncode,expected)


class Helper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='cwa-helper-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.work = Path(cls.tmp.name)
        code = r"""#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int inject;
static const char *replace_stat;
static ssize_t audited_read(int fd, void *buf, size_t len) {
 char link[64], path[4096]={0}; ssize_t n;
 static unsigned int sched_reads;
 snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
 n=readlink(link,path,sizeof(path)-1);
 if(n>=0) {
  path[n]=0;
  if(strstr(path,"/schedstat")) {
   sched_reads++;
   if(inject==1 || (inject==4 && sched_reads>1)) { errno=EIO;return -1; }
   if(inject==3 && len>2)len=2;
  }
 }
 n=read(fd,buf,len);
 if(n>0 && inject==2 && strstr(path,"/schedstat")) {
  int out,j,pos;char changed[256];inject=0;
  pos=snprintf(changed,sizeof(changed),"44 (xdev_ext_mech/2) S ");
  for(j=0;j<18;j++)pos+=snprintf(changed+pos,sizeof(changed)-(size_t)pos,"0 ");
  pos+=snprintf(changed+pos,sizeof(changed)-(size_t)pos,"999\n");
  out=open(replace_stat,O_WRONLY|O_TRUNC);
  if(out<0 || write(out,changed,(size_t)pos)!=pos)abort();
  close(out);
 }
 return n;
}
#define read audited_read
#include "HEADER"
int main(int argc,char **argv) {
 struct cwa_identity id={0};struct cwa_snapshot a={0},b={0};struct cwa_delta d={0};
 int ret=-EINVAL;uint64_t sid=2;
 if(argc<3)return 2;
 if(!strcmp(argv[1],"parse")) {
  ret=cwa_parse_schedstat(argv[2],strlen(argv[2]),&a);
  if(!ret)printf("raw=%llu,%llu,%llu\n",(unsigned long long)a.runtime_ns,(unsigned long long)a.run_delay_ns,(unsigned long long)a.pcount);
 } else if(!strcmp(argv[1],"discover")) {
  if(argc>3)sid=strtoull(argv[3],NULL,10);
  ret=cwa_discover(argv[2],sid,&id);
  if(!ret)printf("identity=%llu,%d,%llu,%s\n",(unsigned long long)id.session_id,id.pid,(unsigned long long)id.start_ticks,id.comm);
 } else if(!strcmp(argv[1],"snapshot")) {
  id.session_id=2;id.pid=44;id.start_ticks=77;ret=cwa_name(2,id.comm);
  if(argc>3)inject=atoi(argv[3]);
  if(argc>4)replace_stat=argv[4];
  if(!ret)ret=cwa_snapshot(argv[2],&id,&a);
  if(!ret)printf("snapshot=%d,%llu,%s,%llu,%llu,%llu,%llu,%llu\n",a.id.pid,(unsigned long long)a.id.start_ticks,a.id.comm,(unsigned long long)a.runtime_ns,(unsigned long long)a.run_delay_ns,(unsigned long long)a.pcount,(unsigned long long)a.read_begin_ns,(unsigned long long)a.read_end_ns);
 } else if(!strcmp(argv[1],"delta") && argc==5) {
  a.id.session_id=b.id.session_id=2;a.id.pid=b.id.pid=44;a.id.start_ticks=b.id.start_ticks=77;
  cwa_name(2,a.id.comm);cwa_name(2,b.id.comm);
  a.read_begin_ns=1;a.read_end_ns=2;b.read_begin_ns=3;b.read_end_ns=4;
  ret=cwa_parse_schedstat(argv[2],strlen(argv[2]),&a);
  if(!ret)ret=cwa_parse_schedstat(argv[3],strlen(argv[3]),&b);
  if(!strcmp(argv[4],"identity"))b.id.start_ticks++;
  if(!strcmp(argv[4],"clock"))b.read_begin_ns=1;
  if(!ret)ret=cwa_delta(&a,&b,&d);
  if(!ret || ret==-ENODATA)printf("delta=%llu,%llu,%llu\n",(unsigned long long)d.runtime_ns,(unsigned long long)d.run_delay_ns,(unsigned long long)d.pcount);
 }
 printf("error=%d\n",ret);return ret?1:0;
}
""".replace('HEADER',str(HEADER))
        c=cls.work/'helper.c';c.write_text(code);cls.binary=cls.work/'helper'
        cls.compile_argv=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(cls.binary)]
        cls.compiled=run(cls.compile_argv,capture_output=True,text=True,timeout=30)
    def call(self,*args,valid=True):
        self.assertEqual(self.compiled.returncode,0,self.compiled.stderr)
        result=run([str(self.binary),*map(str,args)],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0 if valid else 1,result.stdout+result.stderr)
        self.assertNotIn('runtime error:',result.stderr)
        return result.stdout
    def proc(self,pid=44,comm='xdev_ext_mech/2',ticks=77,sched='100 20 3\n'):
        root=Path(tempfile.mkdtemp(prefix='proc-',dir=self.work));self.addCleanup(lambda:__import__('shutil').rmtree(root))
        self.task(root,pid,comm,ticks,sched);return root
    def task(self,root,pid,comm,ticks,sched):
        d=root/str(pid);d.mkdir();(d/'comm').write_text(comm+'\n')
        (d/'stat').write_text(f'{pid} ({comm}) S '+' '.join(['0']*18)+f' {ticks} '+' '.join(['0']*30)+'\n')
        (d/'schedstat').write_text(sched)
    def test_schedstat_strict_unsigned_triple(self):
        self.assertIn('raw=0,0,0',self.call('parse','0 0 0\n'))
        self.assertIn('raw=18446744073709551615,2,3',self.call('parse','18446744073709551615\t2 3\n'))
        for text in ['', '1 2','1 2 3 4','-1 2 3','+1 2 3','18446744073709551616 2 3','1x 2 3','1 2 3 tail']:
            with self.subTest(text=text):self.call('parse',text,valid=False)
    def test_exact_unique_name_and_unrepresentable_session(self):
        root=self.proc();self.assertIn('identity=2,44,77,xdev_ext_mech/2',self.call('discover',root))
        self.call('discover',root,10,valid=False)
        self.task(root,45,'xdev_ext_mech/2',88,'1 2 3\n');self.call('discover',root,valid=False)
    def test_no_prefix_or_missing_worker(self):
        root=self.proc(comm='xdev_ext_mech/3');self.call('discover',root,valid=False)
        (root/'44'/'comm').write_text('xdev_ext_mech/\n');self.call('discover',root,valid=False)
    def test_snapshot_actual_files_and_brackets(self):
        out=self.call('snapshot',self.proc());values=out.split('snapshot=')[1].splitlines()[0].split(',')
        self.assertEqual(values[:6],['44','77','xdev_ext_mech/2','100','20','3'])
        self.assertGreater(int(values[6]),0);self.assertGreaterEqual(int(values[7]),int(values[6]))
    def test_pid_startticks_comm_and_stat_grammar(self):
        for replacement in ['45 (xdev_ext_mech/2) S '+'0 '*18+'77\n','44 (xdev_ext_mech/2) S '+'0 '*18+'78\n','44 (bad) S '+'0 '*18+'77\n','44 (xdev_ext_mech/2) S 0\n']:
            root=self.proc();(root/'44'/'stat').write_text(replacement);self.call('snapshot',root,valid=False)
        root=self.proc();(root/'44'/'comm').write_text('xdev_ext_mech/3\n');self.call('snapshot',root,valid=False)
    def test_byte_complete_reads_missing_overlong_nul_and_errors(self):
        for text in ['1 2 3\n'+' '*256,'1 2 3\0\n','1 2\n']:
            root=self.proc(sched=text);self.call('snapshot',root,valid=False)
        root=self.proc();(root/'44'/'schedstat').unlink();self.call('snapshot',root,valid=False)
        root=self.proc();(root/'44'/'schedstat').unlink();(root/'44'/'schedstat').mkdir();self.call('snapshot',root,valid=False)
        self.call('snapshot',self.proc(),1,valid=False)
        self.assertIn('snapshot=',self.call('snapshot',self.proc(),3))
        self.assertIn('error=-5',self.call('snapshot',self.proc(),4,valid=False))
    def test_identity_change_during_real_schedstat_read(self):
        root=self.proc();self.assertIn('error=-116',self.call('snapshot',root,2,root/'44'/'stat',valid=False))
    def test_zero_initial_zero_components_no_progress_and_regression(self):
        self.assertIn('delta=9,0,1',self.call('delta','0 0 0','9 0 1','ok'))
        self.assertIn('delta=0,0,0',self.call('delta','9 0 1','9 0 1','ok',valid=False))
        self.call('delta','0 0 0','0 0 0','ok',valid=False)
        self.assertIn('delta=18446744073709551615,18446744073709551615,18446744073709551615',self.call('delta','0 0 0','18446744073709551615 18446744073709551615 18446744073709551615','ok'))
        for post in ['8 0 1','9 1 0','9 0 1']:
            self.call('delta','9 1 1',post,'ok',valid=False)
        self.call('delta','1 1 1','2 2 2','identity',valid=False)
        self.call('delta','1 1 1','2 2 2','clock',valid=False)


class Placement(unittest.TestCase):
    def test_samples_stay_outside_original_timer_and_after_settle(self):
        source=(HERE/'ce_repeat_start_probe.c').read_text()
        self.assertIn('rp_worker_report(',source)
        main=source[source.index('int main('):]
        pre=main.index('cwa_snapshot("/proc", &worker, &worker_pre)')
        t0=main.index('t0 = es_now_ns();');t1=main.index('t1 = es_now_ns();')
        post=main.index('cwa_snapshot("/proc", &worker, &worker_post)')
        self.assertLess(main.index('rp_arm(&r,'),pre);self.assertLess(pre,t0)
        self.assertLess(t1,main.index('es_settle(&r,'));self.assertLess(main.index('es_settle(&r,'),post)
        self.assertLess(post,main.index('es_print_stats(&s)'))
        for token in ['cwa_', 'printf', 'rp_worker', 'open(', 'read(', 'clock_gettime']:
            self.assertNotIn(token,main[t0:t1])
        self.assertLess(main.index('rp_report(wait_aba'),main.index('rp_worker_report('))
        self.assertLess(main.index('eval_fd_check(fd_before)'),main.index('CE_WORKER_ACCOUNTING_DONE'))


class Reports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_ce_repeat_start import function
        source=(HERE/'ce_repeat_start_probe.c').read_text()
        cls.tmp=tempfile.TemporaryDirectory(prefix='cwa-report-');cls.addClassCleanup(cls.tmp.cleanup)
        work=Path(cls.tmp.name);cls.binary=work/'report'
        code='#include "'+str(HEADER)+'"\n#define CE_REPEAT_SOURCE "host-fixture"\n'
        code+='\n'.join(function(source,n) for n in ['rp_worker_snapshot','rp_worker_report'])
        code+=r"""
int main(int argc,char **argv) {
 struct cwa_identity id={.session_id=2,.pid=44,.start_ticks=77};
 struct cwa_snapshot a={.runtime_ns=100,.run_delay_ns=20,.pcount=3,.read_begin_ns=1000,.read_end_ns=1100},b=a;
 int discovery=0,pre=0,post=0,prior=0,result;
 if(argc!=2)return 2;
 cwa_name(2,id.comm);a.id=b.id=id;b.runtime_ns=400;b.run_delay_ns=25;b.pcount=5;b.read_begin_ns=1400;b.read_end_ns=1500;
 if(!strcmp(argv[1],"zero")){a.runtime_ns=a.run_delay_ns=a.pcount=0;}
 if(!strcmp(argv[1],"no-progress")){b.runtime_ns=a.runtime_ns;b.run_delay_ns=a.run_delay_ns;b.pcount=a.pcount;}
 if(!strcmp(argv[1],"regression"))b.pcount=2;
 if(!strcmp(argv[1],"identity"))post=-ESTALE;
 if(!strcmp(argv[1],"read-error"))pre=-EIO;
 if(!strcmp(argv[1],"read-order"))a.read_end_ns=1250;
 if(!strcmp(argv[1],"prior-regression"))prior=-ERANGE;
 if(!strcmp(argv[1],"unknown")){discovery=pre=post=-ENOENT;memset(&id,0,sizeof(id));}
 result=rp_worker_report(0,2,&id,&a,&b,discovery,pre,post,prior,1200,1300);
 printf("REPORT_HOLD=%d\n",result);return 0;
}
"""
        c=work/'report.c';c.write_text(code)
        cls.compiled=run(['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(c),'-o',str(cls.binary)],capture_output=True,text=True,timeout=30)
    def report(self,case):
        self.assertEqual(self.compiled.returncode,0,self.compiled.stderr)
        result=run([str(self.binary),case],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        lines=result.stdout.splitlines();self.assertEqual(len(lines),4)
        return [dict(x.split('=',1) for x in line.split()[1:]) for line in lines[:3]],lines[-1]
    def test_valid_and_zero_initial_keep_three_raw_and_deltas(self):
        for case in ['valid','zero']:
            rows,last=self.report(case);self.assertEqual(last,'REPORT_HOLD=0')
            self.assertEqual([r['edge'] for r in rows[:2]],['pre','post'])
            for r in rows[:2]:
                self.assertEqual((r['status'],r['error'],r['pid'],r['start_ticks'],r['comm']),('VALID','0','44','77','xdev_ext_mech/2'))
                for field in ['runtime_ns','run_delay_ns','pcount','read_begin_ns','read_end_ns']:self.assertIn(field,r)
            self.assertEqual(rows[2]['status'],'VALID');self.assertEqual(rows[2]['outer_begin_ns'],'1000');self.assertEqual(rows[2]['outer_end_ns'],'1500')
            self.assertEqual(rows[2]['runtime_delta_ns'],'300' if case=='valid' else '400')
    def test_holds_never_fabricate_raw_or_deltas(self):
        for case,reason,edge in [('identity','identity',1),('read-error','pre-read',0),('unknown','discovery',0)]:
            rows,last=self.report(case);self.assertEqual(last,'REPORT_HOLD=1');self.assertEqual(rows[2]['reason'],reason)
            self.assertEqual(rows[edge]['status'],'HOLD');self.assertLess(int(rows[edge]['error']),0)
            for field in ['runtime_ns','run_delay_ns','pcount','read_begin_ns','read_end_ns']:self.assertNotIn(field,rows[edge])
            self.assertNotIn('runtime_delta_ns',rows[2]);self.assertNotIn('outer_begin_ns',rows[2])
            if case=='unknown':self.assertEqual([rows[0][k] for k in ['pid','start_ticks','comm']],['UNKNOWN']*3)
    def test_no_progress_regression_and_read_order(self):
        for case,reason in [('no-progress','no-progress'),('regression','counter-regression'),('prior-regression','counter-regression'),('read-order','read-order')]:
            rows,last=self.report(case);self.assertEqual(last,'REPORT_HOLD=1');self.assertEqual(rows[2]['status'],'HOLD');self.assertEqual(rows[2]['reason'],reason)
            for r in rows[:2]:self.assertEqual(r['status'],'VALID')
            if case=='no-progress':self.assertEqual(rows[2]['runtime_delta_ns'],'0')
            else:self.assertNotIn('runtime_delta_ns',rows[2]);self.assertNotIn('outer_begin_ns',rows[2])

if __name__ == '__main__':
    unittest.main()
