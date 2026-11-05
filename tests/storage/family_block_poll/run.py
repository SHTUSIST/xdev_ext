#!/usr/bin/env python3
"""Production poll endpoint bodies, literal oracle, public native boundaries."""
import argparse,hashlib,json,re,subprocess,runpy,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--new',action='store_true');a=p.parse_args()
root=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True);tests=Path(__file__).resolve().parent
_LAYOUT_FILE = next(p / 'tools/layout.py' for p in Path(__file__).resolve().parents
                    if (p / 'tools/layout.py').is_file())
_TOOL_ROOT = runpy.run_path(str(_LAYOUT_FILE))['canonical_root'](Path(__file__))
_LEGACY = runpy.run_path(str(_TOOL_ROOT / 'tests/storage/nvme/_legacy_storfam_fixture.py'))
LegacySelection, poll_fixture, COMMAND_BOUNDARY, N, B, R, I = (
 _LEGACY[name] for name in ('LegacySelection', 'poll_fixture', 'COMMAND_BOUNDARY', 'N', 'B', 'R', 'I'))
selected=LegacySelection(root)
root=selected.root
status=[]
def function(text,name,optional=False):
 m=re.search(r'\b'+re.escape(name)+r'\s*\([^;{}]*\)\s*\{',text)
 if not m:
  if optional:return ''
  raise ValueError('SETUP missing actual '+name)
 start=text.rfind('\n',0,m.start())+1;prev=text[text.rfind('\n',0,max(0,start-1))+1:max(0,start-1)]
 if prev.strip().startswith(('static ','int ','struct ','u32 ','u64 ','void ','bool ')) and not any(c in prev for c in '{}'):start-=len(prev)+1
 brace=text.index('{',m.start());depth=0;quote=None;escape=False;comment=None;i=brace
 while i<len(text):
  c=text[i];n=text[i+1:i+2]
  if comment=='line':
   if c=='\n':comment=None
  elif comment=='block':
   if c=='*' and n=='/':comment=None;i+=1
  elif quote:
   if escape:escape=False
   elif c=='\\':escape=True
   elif c==quote:quote=None
  elif c=='/' and n=='/':comment='line';i+=1
  elif c=='/' and n=='*':comment='block';i+=1
  elif c in ('"',"'"):quote=c
  elif c=='{':depth+=1
  elif c=='}':
   depth-=1
   if depth==0:return text[start:i+1]+'\n'
  i+=1
 raise ValueError('SETUP malformed actual '+name)
def run(cmd,name):
 (out/(name+'.command.json')).write_text(json.dumps([str(x) for x in cmd]));r=subprocess.run([str(x) for x in cmd],capture_output=True,text=True)
 (out/(name+'.log')).write_text(r.stdout+r.stderr);(out/(name+'.exit')).write_text(str(r.returncode)+'\n');status.append((name,r.returncode))
 if r.returncode:print(r.stdout+r.stderr)
 return r
try:
 # Small byte-exact excerpts from the locked target; no Linux assembly/network needed.
 upstream=tests/'upstream'
 provenance=json.loads((upstream/'provenance.json').read_text())
 pinned='89be9a83ccf1f88522317ce02f854f30d6115c41'
 locked=json.loads((root/'third_party/sources.lock.json').read_text())['components']['linux']['commit']
 if provenance['linux_commit']!=pinned or locked!=pinned:
  raise ValueError('SETUP native excerpts require linux lock commit '+pinned)
 excerpts={}
 for entry in provenance['excerpts']:
  name=entry['file']
  if Path(name).name!=name:raise ValueError('SETUP invalid native excerpt filename')
  raw=(upstream/name).read_bytes();start=entry['payload_byte_start'];size=entry['payload_bytes']
  payload=raw[start:start+size]
  if (hashlib.sha256(raw).hexdigest()!=entry['file_sha256'] or
      hashlib.sha256(payload).hexdigest()!=entry['payload_sha256'] or
      len(payload)!=size or len(raw)!=start+size):
   raise ValueError('SETUP native excerpt integrity mismatch: '+name)
  excerpts[name]=raw.decode()
 if set(excerpts)!={'hctx_type.inc','blk_features_t.inc','blk_feat_poll.inc','blk_rq_is_poll.inc'}:
  raise ValueError('SETUP native excerpt inventory mismatch')
 (out/'native-inputs.json').write_text(json.dumps({'linux_commit':pinned,'excerpts':provenance['excerpts']},indent=2)+'\n')
 native=selected.read(N)
 member_family='struct xdev_ext_stor_stage family;' in native
 current_common='return xdev_ext_storfam_submit(&p->family, b, &bp->family);' in native
 if current_common and not a.new:raise ValueError('SETUP current common source requires --new')
 blktypes=selected.read('include/linux/blk_types.h')
 def required(pattern,text):
  m=re.search(pattern,text,re.M|re.S)
  if not m:raise ValueError('SETUP missing actual native declaration '+pattern)
  return m.group(0)+'\n'
 flags=required(r'^typedef[^;\n]*\bblk_opf_t;',blktypes)+required(r'^#define REQ_OP_BITS[^\n]*',blktypes)+required(r'^enum req_flag_bits\s*\{.*?^\};',blktypes)
 flags+=required(r'^#define REQ_POLLED[^\n]*',blktypes)
 if current_common:flags+=required(r'^enum req_op\s*\{.*?^\};',blktypes)
 flags+=required(r'^enum hctx_type\s*\{.*?^\};',excerpts['hctx_type.inc'])
 flags+=required(r'^typedef[^;\n]*\bblk_features_t;',excerpts['blk_features_t.inc'])+required(r'^#define BLK_FEAT_POLL[^\n]*',excerpts['blk_feat_poll.inc'])
 for macro in ['REQ_FAILFAST_DEV','REQ_FAILFAST_TRANSPORT','REQ_FAILFAST_DRIVER','REQ_FAILFAST_MASK']:
  flags+=required(r'^#define '+macro+r'\b(?:[^\n]*\\\n)*[^\n]*',blktypes)
 (out/'actual_native_flags.inc').write_text(flags)
 def declaration(text,name):
  m=re.search(r'^struct '+re.escape(name)+r'\s*\{.*?^\};',text,re.M|re.S)
  if not m:raise ValueError('SETUP missing actual declaration '+name)
  return m.group(0)+'\n'
 if current_common:
  (out/'actual_command_boundary.inc').write_text(COMMAND_BOUNDARY)
  (out/'actual_member_types.inc').write_text(selected.poll_declarations())
  (out/'actual_old_poll.inc').write_text('')
  poll_member='\n'.join(selected.definition(N,n) for n in ('nvme_xdev_ext_member_queue','nvme_xdev_ext_member_poll'))
  poll_member+='\nstatic const struct xdev_ext_stor_dev_ops fixture_poll_ops={.queue=nvme_xdev_ext_member_queue,.poll=nvme_xdev_ext_member_poll};\n'
  (out/'actual_class_poll.inc').write_text(poll_member+selected.definition(N,'nvme_xdev_ext_class_poll'))
  for filename,consumer in [('test_poll.c',False),('test_consumers.c',True)]:
   raw=(tests/filename).read_text();generated,edits=poll_fixture(selected,raw,consumer)
   (out/filename).write_text(generated)
   (out/(filename+'.edits.json')).write_text(json.dumps(edits,indent=2)+'\n')
  (out/'actual_common.c').write_text(selected.poll_common_source())
 else:
  passthru=selected.read('include/linux/nvme_xdev_ext_passthru.h')
  uapi=selected.read('include/uapi/linux/xdev_ext_mech.h')
  types='' if member_family else declaration(passthru,'nvme_xdev_ext_identity')+declaration(uapi,'xdev_ext_nvme_mech_cqe')
  types+='\n'.join(declaration(native,n) for n in ['nvme_xdev_ext_mech_stage','nvme_xdev_ext_mech_batch','nvme_xdev_ext_mech_slot','nvme_xdev_ext_peer_slot','nvme_xdev_ext_peer_res'])
  (out/'actual_member_types.inc').write_text(types)
  for name in ['nvme_xdev_ext_class_bind','nvme_xdev_ext_peer_submit','nvme_xdev_ext_class_submit','nvme_xdev_ext_class_complete','nvme_xdev_ext_class_ready','nvme_xdev_ext_class_end_io','nvme_xdev_ext_peer_complete','nvme_xdev_ext_peer_end_io']:
   (out/(name+'.inc')).write_text(function(native,name))
  (out/'actual_old_poll.inc').write_text('\n'.join(function(native,n,optional=a.new) for n in ['nvme_xdev_ext_poll_capable','nvme_xdev_ext_poll_opf','nvme_xdev_ext_poll_check','nvme_xdev_ext_poll_arm']))
  poll_member=''
  if member_family:
   poll_member=function(native,'nvme_xdev_ext_member_queue')+function(native,'nvme_xdev_ext_member_poll')
   poll_member+='static const struct xdev_ext_stor_dev_ops fixture_poll_ops={.queue=nvme_xdev_ext_member_queue,.poll=nvme_xdev_ext_member_poll};\n'
  (out/'actual_class_poll.inc').write_text(poll_member+function(native,'nvme_xdev_ext_class_poll'))
  member_code=''
  if member_family:
   member_code=function(selected.read(I),'nvme_xdev_ext_capture_identity')
   member_code+=''.join(function(native,n) for n in ('nvme_xdev_ext_member_bind','nvme_xdev_ext_member_unbind','nvme_xdev_ext_member_requester','nvme_xdev_ext_member_queue','nvme_xdev_ext_member_identity','nvme_xdev_ext_member_decode','nvme_xdev_ext_member_poll','nvme_xdev_ext_class_resources_free','nvme_xdev_ext_peer_resources_free'))
   member_code+=required(r'^static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops = \{.*?^\};',native)
  (out/'actual_member_callbacks.inc').write_text(member_code)
 (out/'actual_stor_done.inc').write_text(selected.definition(R,'xdev_ext_stor_done'))
 # Actual target body, retained byte-exact in the local pinned excerpt.
 (out/'actual_blk_predicate.inc').write_text(function(excerpts['blk_rq_is_poll.inc'],'blk_rq_is_poll'))
 shim=out/'shim/linux';shim.mkdir(parents=True,exist_ok=True)
 for h in ['blk-mq.h','bio.h','blkdev.h','mm.h','export.h','module.h','xdev_ext_mech.h','atomic.h','dma-mapping.h','highmem.h','pci.h','sizes.h','slab.h','xdev_ext_requester.h']:(shim/h).write_text('#include "native_boundary.h"\n')
 (shim/'blk_types.h').write_text('#ifdef NO_BLOCK_TEST\n#error forbidden poll native include without CONFIG_BLOCK\n#endif\n#include "native_boundary.h"\n')
 portable=out/'portable';portable.mkdir(exist_ok=True)
 helpers=runpy.run_path(str(_TOOL_ROOT/'tests/integration/peer_graph/nvme_peer_async_test.py'))
 if current_common:selected.headers(portable)
 else:helpers['host_headers'](root,portable)
 (out/'assembly.json').write_text(json.dumps(selected.report(),indent=2)+'\n')
 inc=['-I',tests,'-I',out,'-I',out/'shim','-I',portable,'-I',portable/'include','-I',root/'src/storage/include','-I',root/'src/storage/include/linux','-I',root/'src/core/include/linux','-I',root/'src/storage/drivers/nvme/host']
 for profile in ['gcc','ubsan']:
  flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare','-ffunction-sections','-fdata-sections']
  if profile=='ubsan':flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
  run(['gcc',*flags,*inc,'-DNO_BLOCK_TEST=1',tests/'no_block.c','-o',out/(profile+'-no-block')],profile+'-no-block-compile')
  if status[-1][1]==0:run([out/(profile+'-no-block')],profile+'-no-block-run')
  mode=['-DCONFIG_BLOCK=1']+(['-DPOLL_NEW=1'] if a.new else [])+(['-DSTORAGE_MEMBER_FAMILY=1'] if member_family else [])
  if current_common:mode+=['-DSTORAGE_CURRENT_COMMON=1','-DCONFIG_XDEV_EXT_MECH_ZEROCOPY=1']
  binary=out/(profile+'-poll');cmd=['gcc',*flags,*mode,*inc,(out if current_common else tests)/'test_poll.c']
  if a.new:
   obj=out/(profile+'-runtime.o');r=run(['gcc',*flags,*mode,*(['-DSTORAGE_COMMON_TU=1'] if current_common else []),*inc,'-include',tests/'native_boundary.h','-c',(out/'actual_common.c' if current_common else selected._selection.file(B)),'-o',obj],profile+'-runtime-compile')
   if r.returncode:continue
   cmd +=[obj,'-Wl,--wrap=xdev_ext_stor_block_poll']
  r=run([*cmd,'-Wl,--gc-sections','-o',binary],profile+'-poll-compile')
  if r.returncode:continue  # Missing API/linkage is SETUP; do not emit behavior RED.
  r=run([binary],profile+'-poll-run');print(r.stdout.strip())
  binary=out/(profile+'-consumers');cmd=['gcc',*flags,*mode,*inc,(out if current_common else tests)/'test_consumers.c']
  if a.new:cmd +=[obj,'-Wl,--wrap=xdev_ext_stor_block_poll_capable','-Wl,--wrap=xdev_ext_stor_block_poll_check','-Wl,--wrap=xdev_ext_stor_block_poll_arm']
  r=run([*cmd,'-Wl,--gc-sections','-o',binary],profile+'-consumers-compile')
  if not r.returncode:r=run([binary],profile+'-consumers-run');print(r.stdout.strip())
 selected.verify()
 required_steps={profile+'-'+step for profile in ['gcc','ubsan'] for step in
                 ['no-block-compile','no-block-run','poll-compile','poll-run','consumers-compile','consumers-run']}
 if a.new:required_steps|={profile+'-runtime-compile' for profile in ['gcc','ubsan']}
 if not required_steps<={name for name,rc in status}:raise ValueError('SETUP incomplete compile/run stage inventory')
except Exception as e:
 (out/'status.json').write_text(json.dumps(status,indent=2))
 (out/'setup-error.txt').write_text(str(e));print(e);exit(2)
(out/'status.json').write_text(json.dumps(status,indent=2));exit(2 if any(rc and 'compile' in n for n,rc in status) else 1 if any(rc for n,rc in status) else 0)
