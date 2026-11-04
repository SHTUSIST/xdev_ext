#!/usr/bin/env python3
"""Compile actual socket/family bodies; controlled boundaries live in host_shim.h."""
import argparse, pathlib, re, subprocess, sys
HERE = pathlib.Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('--source', type=pathlib.Path, default=HERE.parents[2])
p.add_argument('--out', type=pathlib.Path, required=True)
p.add_argument('--suite', choices=['consumer','host'], default='consumer')
p.add_argument('--compare-baseline', type=pathlib.Path)
p.add_argument('--mutant', choices=['short-success','credentials','cursor-skip','failed-cqe-bytes','rx-fifo','frame-alias'])
p.add_argument('--check-mutants', action='store_true')
a = p.parse_args(); a.source=a.source.resolve(); a.out.mkdir(parents=True, exist_ok=True)
if a.check_mutants:
    verdict=[]
    for name in ['short-success','credentials','cursor-skip','failed-cqe-bytes','rx-fifo','frame-alias']:
        out=a.out/name
        r=subprocess.run([sys.executable,str(pathlib.Path(__file__).resolve()),'--source',str(a.source),'--out',str(out),'--mutant',name],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        out.mkdir(parents=True,exist_ok=True);(out/'runner.log').write_text(r.stdout)
        semantic=r.returncode not in (0,2) and ('FAIL line ' in r.stdout or 'Assertion ' in r.stdout)
        verdict.append(f'{name}: '+('KILLED semantic assertion' if semantic else f'UNRESOLVED exit={r.returncode}'))
    report='\n'.join(verdict)+'\n';(a.out/'verdict.txt').write_text(report);print(report,end='')
    raise SystemExit(0 if all('KILLED' in s for s in verdict) else 1)
def read(path): return (a.source/path).read_text()
def noincludes(s): return re.sub(r'^#include[^\n]*\n', '', s, flags=re.M)
def block(s, token, terminator='}'):
    start=s.index(token); brace=s.index('{',start); depth=1; i=brace+1
    # Selected bodies have no braces inside strings; comments do not contain braces.
    while depth:
        if s[i]=='{': depth+=1
        elif s[i]=='}': depth-=1
        i+=1
    if terminator==';': i=s.index(';',i)+1
    return s[start:i]+'\n'
h=read('src/core/include/linux/xdev_ext_mech.h')
parts=['#include <uapi/linux/xdev_ext_mech.h>',
       '#include "'+str(a.source/'src/core/include/linux/xdev_ext_mech.h')+'"']
nh=read('src/network/include/linux/xdev_ext_netfam.h')
available='xdev_ext_netfam_lease_host(' in nh
parts.append('#define HOST_AVAILABLE '+str(int(available)))
for name in ['xdev_ext_mech_frame','xdev_ext_mech_stage','xdev_ext_mech_pool','xdev_ext_mech_call_args']:
    # Match definitions, avoiding forward declarations and _ops.
    m=re.search(r'struct '+name+r'\s*\{',h)
    parts.append(block(h[m.start():], 'struct '+name, ';'))
parts.append(block(h,'struct xdev_ext_family_hooks_hdr',';'))
(a.out/'types.inc').write_text('\n'.join(parts))
core=read('src/core/io_uring/xdev_ext_mech.c')
names=['xdev_ext_mech_pool_frame_state','xdev_ext_mech_session_layout',
'xdev_ext_mech_session_pool','xdev_ext_mech_session_depth','xdev_ext_mech_batch_session','xdev_ext_mech_batch_id',
'xdev_ext_mech_batch_key','xdev_ext_mech_batch_slot','xdev_ext_mech_batch_nr_frames',
'xdev_ext_mech_batch_bytes','xdev_ext_mech_batch_frame','xdev_ext_mech_batch_status',
'xdev_ext_mech_batch_produced','xdev_ext_mech_batch_ticket',
'xdev_ext_mech_batch_completion_claim','xdev_ext_mech_batch_complete',
'xdev_ext_mech_batch_complete_produced','xdev_ext_mech_batch_complete_cancelled']
funcs=[]
for n in names:
    m=re.search(r'^[\w *]+\n?'+n+r'\([^;]*?\n\{',core,re.M)
    if not m: raise RuntimeError('missing production function '+n)
    funcs.append(block(core[m.start():], n))
    # Include the actual declaration prefix before function name.
    funcs[-1]=core[m.start():m.start()+core[m.start():].index(n)]+funcs[-1]
primitive=read('src/core/io_uring/xdev_ext_mech_core.h')
(a.out/'core.inc').write_text(block(primitive,'static inline __u8 xdev_ext_mech_frame_state')+'\n'+'\n'.join(funcs))
(a.out/'netfam_core.inc').write_text(noincludes(read('src/network/include/linux/xdev_ext_netfam_core.h')))
(a.out/'netfam.inc').write_text(noincludes(read('src/network/include/linux/xdev_ext_netfam.h'))+'\n'+noincludes(read('src/network/io_uring/family/xdev_ext_netfam.c')))
(a.out/'socket.inc').write_text(noincludes(read('src/network/io_uring/xdev_ext_mech_socket.c')).split('static const struct xdev_ext_mech_class_ops xdev_ext_socket_class =')[0])
# A request field's spelling is not an assertion. Discover only the slot-pointer
# name to observe contract-required publication at the actual callback boundary.
socket=read('src/network/io_uring/xdev_ext_mech_socket.c')
request=block(socket,'struct xdev_ext_socket_request',';')
fields=re.findall(r'struct xdev_ext_net_slot\s*\*\s*(\w+)\s*;',request)
(a.out/'publication.inc').write_text('\n'.join('assert(ss->request[index].'+f+' == slot);' for f in fields) if available and fields else ('assert(!"HOST request TX slot pointer absent");' if available else '(void)slot;'))
members=re.findall(r'(?:static\s+)?const\s+struct xdev_ext_net_member\s+(\w+)\s*=',socket)
(a.out/'socket_member.inc').write_text('#define HOST_SOCKET_MEMBER '+members[0]+'\n' if available and len(members)==1 else '')
if a.mutant:
    mutations={
      'short-success':('socket.inc','err = (u32)err == r->bytes ? 0 : -EIO;','err = 0;'),
      'credentials':('socket.inc','revert_creds(old_cred);','(void)old_cred; /* mutant omits restore */'),
      'cursor-skip':('socket.inc','r->cursor++;','r->cursor += 2;'),
      'failed-cqe-bytes':('socket.inc','.bytes_sent = status ? 0 : xdev_ext_mech_batch_bytes(b)','.bytes_sent = xdev_ext_mech_batch_bytes(b)'),
      'rx-fifo':('socket.inc','(rx->head + rx->count) % ss->depth','(rx->head + rx->count + 1) % ss->depth'),
      'frame-alias':('core.inc','*f = b->f[pos];','*f = b->f[0];'),
    }
    name,old,new=mutations[a.mutant];target=a.out/name;body=target.read_text()
    if old not in body:
        print('SETUP mutation anchor unavailable: '+a.mutant);raise SystemExit(2)
    target.write_text(body.replace(old,new,1))
    (a.out/'mutation.txt').write_text(a.mutant+'\n'+old+'\n=>\n'+new+'\n')
# Extraction is a fixed baseline artifact in --out; no source rewriting.
cmd=['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-unused-variable',
'-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all',
'-I'+str(a.out),'-I'+str(HERE),'-I'+str(a.source/'src/core/include'),
'-I'+str(a.source/'src/network/include'),'-I'+str(a.source/'src/core/io_uring'),
str(HERE/'socket_cases.c'),'-o',str(a.out/'socket_cases')]
(a.out/'command.txt').write_text(' '.join(cmd)+'\n')
r=subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
(a.out/'build.log').write_text(r.stdout)
if r.returncode:
    print('SETUP build failed\n'+r.stdout); raise SystemExit(2)
r=subprocess.run([str(a.out/'socket_cases'),a.suite],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10)
(a.out/'observations.log').write_text(r.stdout); print(r.stdout,end='')
if not r.returncode and a.compare_baseline:
    expected=a.compare_baseline.read_text()
    if expected != r.stdout:
        print('FAIL differential consumer observations differ');raise SystemExit(1)
    print('PASS differential consumer observations equal frozen baseline')
raise SystemExit(r.returncode)
