#!/usr/bin/env python3
"""Actual-source mutations: compilation refusal is SETUP, never detection."""
import argparse,contextlib,io,json,pathlib,re,shutil,sys
import run

def once(text,old,new):
 if text.count(old)!=1:raise RuntimeError('target not unique '+old[:100])
 return text.replace(old,new,1)
def prepend(body,line):
 i=body.index('{')+1;return body[:i]+'\n'+line+'\n'+body[i:]
def append(body,line):return body[:-2]+'\n'+line+'\n}\n' if body.endswith('}\n') else body[:-1]+'\n'+line+'\n}'
def shifted_dma(text,field):
 pat=re.escape('.'+field)+r'\s*=\s*(e\[i\]\.lease(?:\.u\.peer)?\.lease\.dma_address)'
 m=re.search(pat,text)
 if not m:raise RuntimeError('missing DMA assignment')
 return text[:m.start(1)]+m.group(1)+' + 1'+text[m.end(1):]
def moved_handle(body):
 pattern=r'&e->lease(?:\.u\.peer)?';found=re.findall(pattern,body)
 if len(found)!=1:raise RuntimeError('stable acquire target not unique')
 path=found[0][1:]
 body=prepend(body,'struct xdev_ext_peer_fd_lease transient_handle = {0};')
 body=once(body,found[0],'&transient_handle')
 return once(body,'if (ret)','if (!ret) '+path+' = transient_handle;\n\tif (ret)')
def none_member(body):
 return once(body,'XDEV_EXT_NET_LEASE_PEER_DMA','XDEV_EXT_NET_LEASE_NONE')

def main():
 p=argparse.ArgumentParser();p.add_argument('--source-root',type=pathlib.Path,required=True);p.add_argument('--phase',choices=['baseline','typed'],default='baseline');p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
 root=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 with contextlib.redirect_stdout(io.StringIO()) as log:status=run.execute(root,a.phase,out/'control')
 (out/'control.console.log').write_text(log.getvalue())
 if status:print('SETUP: mutation control failed',status);return 2
 selected=set(run.FILES.values())|{'src/core/include/linux/xdev_ext_requester.h','src/core/include/linux/xdev_ext_requester_core.h','src/core/include/linux/xdev_ext_mech.h'}
 for name in (out/'control/dependencies.d').read_text().replace('\\\n',' ').split()[1:]:
  f=pathlib.Path(name).resolve()
  if f.is_relative_to(root) and f.relative_to(root).parts[0]=='src':selected.add(str(f.relative_to(root)))
 (out/'selected-sources.json').write_text(json.dumps(sorted(selected),indent=2)+'\n')
 cases=[
 ('lease-bidirectional','family','xdev_ext_netfam_lease','function',lambda s:once(s,'ns->rx ? DMA_FROM_DEVICE : DMA_TO_DEVICE','DMA_BIDIRECTIONAL')),
 ('lease-uses-payload-not-buffer','family','xdev_ext_netfam_lease','function',lambda s:once(s,'generation(pool), off, buf_len,','generation(pool), off, len,')),
 ('lease-wrong-generation','family','xdev_ext_netfam_lease','function',lambda s:once(s,'xdev_ext_peer_mech_pool_generation(pool)','(xdev_ext_peer_mech_pool_generation(pool) + 1)')),
 ('lease-on-transient-stack-handle','family','xdev_ext_netfam_lease','function',moved_handle),
 ('duplicate-handle-cleared','fd','xdev_ext_peer_file_acquire','function',lambda s:prepend(s,'if (handle) memset(handle, 0, sizeof(*handle));')),
 ('skip-false-release','family','xdev_ext_netfam_release','function',lambda s:prepend(s,'if (!quiesced) return;')),
 ('skip-quarantine','peer','xdev_ext_peer_release','function',lambda s:once(s,'if (!quiesced) r->invalid = r->quarantined = true;','if (false) r->invalid = r->quarantined = true;')),
 ('reuse-unknown-slot','family','xdev_ext_netfam_release','function',lambda s:once(s,'if (quiesced)','if (true)')),
 ('read-current-not-saved-ticket','family','xdev_ext_netfam_handoff','function',lambda s:once(s,'xdev_ext_mech_batch_completion_claim(b, slot->ticket)','xdev_ext_mech_batch_completion_claim(b, xdev_ext_mech_batch_ticket(b))')),
 ('native-before-tracker-init','family','xdev_ext_netfam_post','function',lambda s:once(s,'int ret = xdev_ext_peer_net_track_init_max(&slot->track, slot->nr, ns->max_elems);','int ret = 0;')),
 ('NET-TX-wrong-DMA','net','xdev_ext_net_dev_post_tx','function',lambda s:shifted_dma(s,'dma_address')),
 ('NET-RX-wrong-DMA','net','xdev_ext_net_dev_post_rx','function',lambda s:shifted_dma(s,'dma_address')),
 ('XD-wrong-DMA','xd','xdev_ext_xd_post','function',lambda s:shifted_dma(s,'buffer_phy')),
 ('NET-prefix-not-released','net','xdev_ext_net_submit','function',lambda s:once(s,'xdev_ext_netfam_release(slot, true);','(void)slot;')),
 ('NET-slot-unpublished-before-post','net','xdev_ext_net_submit','function',lambda s:once(s,'bp->slot = slot;','bp->slot = NULL;')),
 ]
 if a.phase=='typed':cases += [
 ('NET-member-NONE','net','xdev_ext_net_member','variable',none_member),
 ('XD-member-NONE','xdc','xd_member','variable',none_member),
 ('clear-kind-on-stale-release','family','xdev_ext_netfam_release','function',lambda s:append(s,'for (i = 0; i < slot->nr; i++) slot->elem[i].lease.kind = XDEV_EXT_NET_LEASE_NONE;')),
 ('publish-kind-before-acquire','family','xdev_ext_netfam_lease','function',lambda s:prepend(s,'if (i < ns->max_elems) slot->elem[i].lease.kind = XDEV_EXT_NET_LEASE_PEER_DMA;')),
 ]
 results=[]
 for name,key,sym,kind,change in cases:
  d=out/name;src=d/'source';src.mkdir(parents=True,exist_ok=True)
  for rel in selected:
   target=src/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/rel,target)
  target=src/run.FILES[key]
  try:
   text=target.read_text();search=text[text.index("static void xdev_ext_net_tx_done"):] if key=="net" and sym=="xdev_ext_net_submit" else text;body=run.block(search,sym,kind);target.write_text(once(text,body,change(body)))
   with contextlib.redirect_stdout(io.StringIO()) as log:status=run.execute(src,a.phase,d/'build')
   (d/'console.log').write_text(log.getvalue());runtime=(d/'build/run.log').read_text() if (d/'build/run.log').exists() else ''
   detected=status==1 and ('ASSERT ' in runtime or 'Assertion ' in runtime)
   result={'name':name,'status':'DETECTED' if detected else 'SURVIVED' if status==0 else 'SETUP','compile_ok':(d/'build/compile.log').exists() and not (d/'build/compile.log').read_text(),'exit':status}
  except (OSError,RuntimeError) as e:result={'name':name,'status':'SETUP','reason':str(e)}
  results.append(result);print(name+': '+result['status'])
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 if any(r['status']=='SETUP' for r in results):return 2
 return int(any(r['status']!='DETECTED' for r in results))
if __name__=='__main__':sys.exit(main())
