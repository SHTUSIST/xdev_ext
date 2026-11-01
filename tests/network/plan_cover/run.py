#!/usr/bin/env python3
"""NET29-2 actual-header contract tests. SETUP=2, assertion/structure FAIL=1."""
import argparse,json,pathlib,subprocess,tempfile,sys
HERE=pathlib.Path(__file__).resolve().parent
NET='src/network/io_uring/xdev_ext_mech_net_core.h'
FAMILY='src/network/include/linux/xdev_ext_netfam_core.h'
PEER='src/network/io_uring/xdev_ext_peer_net_core.h'
def execute(root,phase,out):
    out.mkdir(parents=True,exist_ok=True)
    for rel in [NET,FAMILY,PEER,'src/core/io_uring/xdev_ext_mech_core.h','src/core/include/uapi/linux/xdev_ext_mech.h']:
        if not (root/rel).is_file(): raise RuntimeError('missing required actual source '+rel)
    if phase=='shared':
        text=(root/NET).read_text()
        for sym in ['xdev_ext_net_plan_ctx','xdev_ext_net_plan_span','xdev_ext_net_plan_entry']:
            if sym not in text: print('SETUP: frozen adapter absent: '+sym); return 2
    cmd=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all','-MMD','-MF',str(out/'dependencies.d')]
    cmd+=['-I'+str(root/p) for p in ['src/network/io_uring','src/core/io_uring','src/network/include/linux','src/network/include','src/core/include/linux','src/core/include']]
    if phase in ['wiring','shared']: cmd+=['-DTEST_WIRING=1']
    if phase=='shared': cmd+=['-DTEST_SHARED=1']
    cmd += [str(HERE/'contract.c'),'-o',str(out/'contract')]
    compat=out/'include-compat.c'
    compat.write_text('#include "xdev_ext_mech_net_core.h"\n_Static_assert(XDEV_EXT_NET_PLAN_FRAMES == 1, "legacy plan marker");\nint compat(void) { return xdev_ext_peer_net_check(1500,14,128,0) + xdev_ext_mech_frame_edge_ok(0,1); }\n')
    compat_cmd=[x for x in cmd[:cmd.index('-MMD')] if x not in ['-fsanitize=undefined','-fno-sanitize-recover=all']]+['-I'+str(root/p) for p in ['src/network/io_uring','src/core/io_uring','src/network/include/linux','src/network/include','src/core/include/linux','src/core/include']]+['-fsyntax-only',str(compat)]
    (out/'include-command.json').write_text(json.dumps(compat_cmd,indent=2)+'\n')
    compat_result=subprocess.run(compat_cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (out/'include-compile.log').write_text(compat_result.stdout)
    if compat_result.returncode:print('SETUP: original include compatibility failed\n'+compat_result.stdout);return 2
    (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(out/'compile.log').write_text(p.stdout)
    if p.returncode:print('SETUP: actual source compilation failed\n'+p.stdout);return 2
    p=subprocess.run([str(out/'contract')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(out/'run.log').write_text(p.stdout);print(p.stdout,end='')
    if p.returncode: print('FAIL: '+('shared-consumer structure/behavior' if phase!='baseline' else 'baseline semantics')+' exit='+str(p.returncode)); return 1
    return 0

def main():
    p=argparse.ArgumentParser();p.add_argument('--source-root',type=pathlib.Path,required=True);p.add_argument('--phase',choices=['baseline','wiring','shared'],default='baseline');p.add_argument('--output',type=pathlib.Path)
    a=p.parse_args()
    try:
        if a.output:return execute(a.source_root.resolve(),a.phase,a.output.resolve())
        with tempfile.TemporaryDirectory(prefix='net-plan-') as t:return execute(a.source_root.resolve(),a.phase,pathlib.Path(t))
    except (OSError,RuntimeError) as e: print('SETUP:',e);return 2
if __name__=='__main__':sys.exit(main())
