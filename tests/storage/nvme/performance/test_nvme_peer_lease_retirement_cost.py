#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""NVMe peer lease retirement: actual lifecycle contracts and list-traversal cost.

Extracts the selected Git revision's real acquire/release/storage-retire functions
at explicit OS/ref/provider seams. Reports traversal counts, not NVMe latency.
Functional PASS does not mean retirement scales linearly. No device is accessed.
"""
from pathlib import Path
import argparse,re,json,hashlib,subprocess,datetime,os
HERE=Path(__file__).resolve().parent

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--out',type=Path,required=True)
 parser.add_argument('--revision',default='HEAD',help='Commit whose production functions are executed')
 args=parser.parse_args()
 P=args.out.resolve();P.mkdir(parents=True,exist_ok=False)
 R=Path(os.environ.get('XDEV_EXT_CANONICAL_ROOT',HERE.parents[3])).resolve()
 V=subprocess.check_output(['git','rev-parse',args.revision+'^{commit}'],cwd=R,text=True).strip()
 paths={'core':'src/core/io_uring/xdev_ext_peer.c','fd':'src/core/io_uring/xdev_ext_peer_fd.c','api':'src/core/include/linux/xdev_ext_peer.h','stor':'src/storage/io_uring/family/xdev_ext_storfam.c'}
 s={k:subprocess.check_output(['git','show',V+':'+v],cwd=R).decode() for k,v in paths.items()}
 def definition(k,start):
  t=s[k];a=t.index(start);op=t.index('{',a);level=0
  for m in re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]',t[op:],re.S):
   if m[0]=='{':level+=1
   elif m[0]=='}':
    level-=1
    if not level:return t[a:op+m.end()]
  raise ValueError(start)
 types='enum dma_data_direction {DMA_BIDIRECTIONAL,DMA_TO_DEVICE,DMA_FROM_DEVICE,DMA_NONE};\n'
 for k,n in [('api','xdev_ext_peer_dma'),('api','xdev_ext_peer_provider_ops'),('api','xdev_ext_peer_lease'),('api','xdev_ext_peer_fd_lease'),('core','xdev_ext_peer_region'),('core','xdev_ext_peer_mapping'),('fd','xdev_ext_peer_fd'),('fd','xdev_ext_peer_authority'),('fd','xdev_ext_peer_fd_map')]:types+=definition(k,'struct '+n+' {')+';\n'
 # Referenced API pointer types need declarations before the exact definitions.
 types='struct xdev_ext_peer_mapping;struct xdev_ext_peer_region;struct xdev_ext_peer_authority;struct xdev_ext_peer_backing;struct module;struct xdev_ext_peer_provider;struct xdev_ext_peer_requester;\n'+types
 functions='\n'.join(definition(k,prefix+n+'(') for k,prefix,n in [('core','static bool ','xdev_ext_peer_stale'),('core','static bool ','xdev_ext_peer_direction_valid'),('core','int ','xdev_ext_peer_acquire'),('core','int ','xdev_ext_peer_release'),('fd','int ','xdev_ext_peer_file_acquire'),('fd','void ','xdev_ext_peer_fd_release'),('stor','void ','xdev_ext_stor_leases_retire')])
 anchor='cursor = &(*cursor)->next) { }';assert functions.count(anchor)==1
 base=(HERE/'nvme_peer_lease_retirement_harness.c').read_text().replace('/* PRODUCTION_TYPES */',types).replace('/* PRODUCTION_FUNCTIONS */',functions)
 (P/'lease-actual.c').write_text(base)
 (P/'lease-counted.c').write_text(base.replace(anchor,'cursor = &(*cursor)->next) { hops++; }'))
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();rows=[]
 for label,flags in [('lease-actual',[]),('lease-counted',['-DCOUNTED_LEASE'])]:
  b=P/('.'+label);argv=['gcc','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',*flags,str(P/(label+'.c')),'-o',str(b)]
  r=subprocess.run(argv,capture_output=True,text=True);(P/(label+'-compile.log')).write_text(' '.join(argv)+'\n'+r.stdout+r.stderr);r.check_returncode()
  try:
   r=subprocess.run([str(b)],capture_output=True,text=True,timeout=15);(P/(label+'.log')).write_text(r.stdout+r.stderr+'exit='+str(r.returncode)+'\n');r.check_returncode();rows.append(dict(argv=argv,exit=r.returncode))
  finally:b.unlink(missing_ok=True)
 (P/'lease-result.json').write_text(json.dumps(dict(status='PASS',scope='exact acquire/file-acquire/release/fd-release/storage-retire operation counts with OS boundary shims; not concurrent/kernel/DMA/CPU time',source_commit=V,started_utc=start,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_sha256={paths[k]:hashlib.sha256(v.encode()).hexdigest() for k,v in s.items()},extracted_functions_sha256=hashlib.sha256(functions.encode()).hexdigest(),commands=rows,generated_sha256={n:hashlib.sha256((P/n).read_bytes()).hexdigest() for n in ['lease-actual.c','lease-counted.c']}),indent=2)+'\n')
 print('PASS actual lease functions + counted loop; 40scenarios, no device/CPU timing; temporary executables deleted')

if __name__=='__main__':
 main()
