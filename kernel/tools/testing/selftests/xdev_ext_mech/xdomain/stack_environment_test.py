#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Protect host FIFO/cancellation and first STOP storage boundaries.

This checks fixture OS/session behavior only. Actual core STOP work remains
covered by its independent production-core suite, not this host model.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
DRIVER = r'''
static unsigned order[8], nr;
struct environment_job { struct work_struct work; unsigned id; };
static void environment_run(struct work_struct *work)
{
 struct environment_job *job=container_of(work,struct environment_job,work);
 assert(nr<ARRAY_SIZE(order)); order[nr++]=job->id;
}
#define ENV_CHECK(c,n) do { if(!(c)){fprintf(stderr,"STACK_ENV_ASSERT %s\n",n);return 1;} }while(0)
int main(void)
{
 struct stack_world state={0};
 struct environment_job jobs[4]={0};
 struct stack_event records[32]={0};
 world=&state;state.log=records;
 for(unsigned i=0;i<4;i++){jobs[i].id=i;INIT_WORK(&jobs[i].work,environment_run);}
 for(unsigned i=0;i<4;i++)queue_work(NULL,&jobs[i].work);
 ENV_CHECK(stack_pump(&state,16,0)==0,"FIFO bounded execution");
 ENV_CHECK(nr==4&&order[0]==0&&order[1]==1&&order[2]==2&&order[3]==3,"FIFO enqueue order");
 nr=0;state.logs=0;
 for(unsigned i=0;i<4;i++)queue_work(NULL,&jobs[i].work);
 ENV_CHECK(cancel_work_sync(&jobs[1].work),"cancel was pending");
 ENV_CHECK(state.nwork==3&&state.work[0]==&jobs[0].work&&
           state.work[1]==&jobs[2].work&&state.work[2]==&jobs[3].work,"cancel preserves queued order");
 ENV_CHECK(stack_pump(&state,16,0)==0,"cancel bounded execution");
 ENV_CHECK(nr==3&&order[0]==0&&order[1]==2&&order[2]==3,"cancel execution order");
 struct xdev_ext_mech_session session={0};
 struct xdev_ext_mech_stage stage={.s=&session};
 xdev_ext_mech_sess_init(&session.ss);
 state.now=123456;
 xdev_ext_mech_stage_stop(&stage,-ECANCELED);
 ENV_CHECK(!xdev_ext_mech_session_admits(&session)&&session.stop_started_ns==123456,
           "first STOP closes admission and records actual now");
 state.now=234567;session.kicked=false;
 xdev_ext_mech_stage_stop(&stage,-ENOLINK);
 ENV_CHECK(session.stop_started_ns==123456&&!session.kicked,"repeated STOP preserves first timestamp");
 memset(&session,0,sizeof(session));xdev_ext_mech_sess_init(&session.ss);
 state.now=0;xdev_ext_mech_stage_stop(&stage,-ECANCELED);
 state.now=100;xdev_ext_mech_stage_stop(&stage,-ENOLINK);
 ENV_CHECK(session.stop_started_ns==0,"zero is a valid first STOP timestamp");
 puts("STACK_ENV_ASSERTIONS 9");return 0;
}
'''


def execute(out, legacy=False, legacy_cancel=False):
    kernel = HERE.parents[4]
    spec = importlib.util.spec_from_file_location('stack_environment_runner', HERE / 'stack_test.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    facade = out / 'facade'
    helper.facade(kernel, facade)
    boundary = (HERE / 'stack_boundary.c').read_text()
    if legacy:
        old = '''   w->nwork--;
   memmove(&w->work[work_index],&w->work[work_index+1],
           (w->nwork-work_index)*sizeof(w->work[0]));'''
        assert boundary.count(old) == 1
        boundary = boundary.replace(old, '   w->work[work_index]=w->work[--w->nwork];', 1)
    if legacy_cancel:
        old = '''\t\tworld->nwork--;
\t\tmemmove(&world->work[i],&world->work[i+1],
\t\t        (world->nwork-i)*sizeof(world->work[0]));'''
        assert boundary.count(old) == 1
        boundary = boundary.replace(old, '\t\tworld->work[i]=world->work[--world->nwork];', 1)
    # An exact private copy needs original relative production includes resolved
    # to their original files; no production body is changed or reimplemented.
    boundary = boundary.replace('"../../../../../', '"' + str(kernel) + '/')
    unit = out / 'environment.c'
    unit.write_text(boundary + '\n' + DRIVER)
    expected = json.loads((HERE / 'stack_expected.json').read_text())
    sources = [HERE / name for name in expected['wrappers'] if name != 'stack_boundary.c']
    command = ['gcc','-std=gnu11','-O0','-g','-Werror=implicit-function-declaration',
               '-pthread','-I',str(facade),'-I',str(HERE),'-I',str(kernel),
               '-idirafter',str(kernel/'include'),'-idirafter',str(kernel/'include/uapi'),
               '-I',str(kernel/'tools/xdev_ext_mech'),str(unit)]
    binary = out / 'stack-environment'
    command += [str(path) for path in sources] + ['-o',str(binary)]
    (out/'compile-command.json').write_text(json.dumps(command,indent=2)+'\n')
    compiled = subprocess.run(command,text=True,capture_output=True,timeout=120)
    (out/'compile.log').write_text(compiled.stdout+compiled.stderr)
    if compiled.returncode:
        print('STACK_ENV_COMPILE_FAILURE\n'+compiled.stdout+compiled.stderr)
        return 2
    result = subprocess.run([str(binary)],text=True,capture_output=True,timeout=30)
    (out/'runtime.log').write_text(result.stdout+result.stderr+'\nruntime_exit='+str(result.returncode)+'\n')
    print(result.stdout+result.stderr,end='')
    return result.returncode if result.returncode else (0 if 'STACK_ENV_ASSERTIONS 9' in result.stdout else 1)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep-build',type=Path)
    parser.add_argument('--legacy-swap-removal',action='store_true')
    parser.add_argument('--legacy-cancel-swap',action='store_true')
    args=parser.parse_args()
    if args.keep_build:
        args.keep_build.mkdir(parents=True,exist_ok=True)
        return execute(args.keep_build.resolve(),args.legacy_swap_removal,args.legacy_cancel_swap)
    with tempfile.TemporaryDirectory(prefix='stack-environment-') as directory:
        return execute(Path(directory),args.legacy_swap_removal,args.legacy_cancel_swap)


if __name__=='__main__':
    raise SystemExit(main())
