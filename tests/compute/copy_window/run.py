#!/usr/bin/env python3
"""Compile selected actual source; SETUP (2) is distinct from semantic FAIL (1)."""
import argparse, json, pathlib, re, shutil, subprocess, sys, tempfile
HERE = pathlib.Path(__file__).resolve().parent
CE = 'src/compute/io_uring/xdev_ext_mech_ce.c'
DMA = 'src/core/io_uring/xdev_ext_mech_dma.c'
TYPED = 'src/compute/io_uring/xdev_ext_compfam_copy_core.h'

def block(text, name, struct=False):
    pat = (r'^struct\s+' + re.escape(name) + r'\s*\{' if struct else
           r'^(?:static\s+)?(?:inline\s+)?(?:[\w*]+\s+)+\**' + re.escape(name) + r'\s*\([^;]*?\)\s*\{')
    m = re.search(pat, text, re.M)
    if not m: raise RuntimeError('missing actual ' + name)
    start = text.index('{', m.start()); depth = 1; i = start+1
    while depth and i < len(text):
        if text[i] == '{': depth += 1
        elif text[i] == '}': depth -= 1
        i += 1
    if depth: raise RuntimeError('unbalanced actual ' + name)
    return text[m.start():i] + (';' if struct else '') + '\n'

def extract(root, out):
    mech=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
    generated=[]
    lines=mech.splitlines(); start=next(i for i,l in enumerate(lines) if l.startswith('#define XDEV_EXT_MECH_OPS_TYPE(')); end=start
    while lines[end].endswith('\\'): end+=1
    generated.append('\n'.join(lines[start:end+1])+'\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_ce_mech_ops);\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_dma_mech_ops);\n')
    for cls, src in [('ce',CE), ('dma',DMA)]:
        text=(root/src).read_text()
        for suffix in ['region','xfer','backend_ops' if cls=='ce' else 'provider_ops']:
            generated.append(block(mech,'xdev_ext_'+cls+'_'+suffix,True))
    # Real stage declarations include only opaque lease/scope pointers; use real key header.
    for cls, src in [('ce',CE), ('dma',DMA)]:
        text=(root/src).read_text()
        for suffix in ['stage','batch']: generated.append(block(text,'xdev_ext_'+cls+'_'+suffix,True))
    generated.append('#include "boundary_impl.h"\n')
    for cls, src in [('ce',CE), ('dma',DMA)]:
        text=(root/src).read_text()
        for suffix in (['copy_claim'] if (root/TYPED).is_file() else []) + ['bind','collect','validate','stage_xfers']:
            generated.append(block(text,'xdev_ext_'+cls+'_'+suffix))
    (out/'actual.h').write_text('\n'.join(generated))

def compile_run(root, phase, out):
    out.mkdir(parents=True,exist_ok=True)
    if phase=='typed' and not (root/TYPED).is_file():
        print('SETUP: typed COPY_WINDOW header absent; no behavioral RED claimed')
        return 2
    extract(root,out)
    source=out/'test.c'
    source.write_text('#include "boundary.h"\n#include "actual.h"\n#include "'+str(HERE/'baseline.c')+'"\n#include "'+str(HERE/'abi.c')+'"\n'+
                      ('#include "'+str(HERE/'typed.c')+'"\n#include "'+str(HERE/'consumers.c')+'"\n' if phase=='typed' else '')+
                      'int main(void) { abi(); fflush(stdout); baseline(); '+('typed(); consumers();' if phase=='typed' else '')+' puts("PASS: '+phase+' actual-source assertions"); return 0; }\n')
    inc=[HERE,out,root/'src/compute/io_uring',root/'src/core/io_uring',root/'src/compute/include/linux',root/'src/core/include/linux']
    cmd=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all','-MMD','-MF',str(out/'dependencies.d')]
    cmd += ['-I'+str(p) for p in inc]+[str(source),'-o',str(out/'test')]
    p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'compile.log').write_text(p.stdout)
    (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    if p.returncode: print('SETUP: compile failed\n'+p.stdout); return 2
    p=subprocess.run([str(out/'test')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (out/'run.log').write_text(p.stdout); print(p.stdout,end='')
    abi='\n'.join(line for line in p.stdout.splitlines() if line.startswith('ABI '))+'\n'
    (out/'abi.txt').write_text(abi)
    if p.returncode:
        print('FAIL: runtime assertion/exit',p.returncode,'(ABI comparison withheld)'); return 1
    golden=HERE/'abi.expected.txt'
    if golden.exists() and golden.read_text()!=abi:
        print('FAIL: affected ABI differs from independent baseline'); return 1
    return 0 if p.returncode==0 else 1

def main():
    a=argparse.ArgumentParser(); a.add_argument('--source-root',type=pathlib.Path,required=True); a.add_argument('--phase',choices=['baseline','typed'],default='baseline'); a.add_argument('--output',type=pathlib.Path)
    o=a.parse_args(); root=o.source_root.resolve()
    try:
        if o.output: return compile_run(root,o.phase,o.output.resolve())
        with tempfile.TemporaryDirectory(prefix='copy-window-') as tmp: return compile_run(root,o.phase,pathlib.Path(tmp))
    except (OSError,RuntimeError) as e: print('SETUP:',e); return 2
if __name__=='__main__': sys.exit(main())
