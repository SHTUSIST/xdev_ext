#!/usr/bin/env python3
"""NET29-2 runnable mutants in compiler-selected source copies."""
import argparse,contextlib,io,json,pathlib,re,shutil,sys
import run

def once(text,old,new):
 if text.count(old)!=1:raise RuntimeError('mutation target not unique: '+old[:100])
 return text.replace(old,new,1)
def function(text,name):
 m=re.search(r'^static\s+inline\s+(?:int|void)\s+'+re.escape(name)+r'\s*\([^;]*?\)\s*\{',text,re.M)
 if not m:raise RuntimeError('missing actual function '+name)
 start=text.index('{',m.start());depth=1;i=start+1
 while depth and i<len(text):
  if text[i]=='{':depth+=1
  elif text[i]=='}':depth-=1
  i+=1
 if depth:raise RuntimeError('unbalanced function')
 return text[m.start():i]
def prepend(body,line):
 i=body.index('{')+1;return body[:i]+'\n'+line+'\n'+body[i:]
def append(body,line):return body[:-1]+'\n'+line+'\n}'
def entry_first(text):
 entry='''		if (entry) {
			ret = entry(ctx, i);
			if (ret)
				return ret;
		}
'''
 text=once(text,entry,'');needle='\t\tif ((__u64)f[cur].data_off + bytes != s.frame_off'
 return once(text,needle,entry+needle)

def main():
 p=argparse.ArgumentParser();p.add_argument('--source-root',required=True,type=pathlib.Path);p.add_argument('--phase',choices=['baseline','shared'],default='baseline');p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args()
 source=a.source_root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
 with contextlib.redirect_stdout(io.StringIO()) as log:status=run.execute(source,a.phase,out/'control')
 (out/'control.console.log').write_text(log.getvalue())
 if status:print('SETUP: control must pass, got',status);return 2
 deps=(out/'control/dependencies.d').read_text().replace('\\\n',' ').split()[1:]
 selected={run.NET,run.FAMILY,run.PEER}
 for name in deps:
  f=pathlib.Path(name).resolve()
  if f.is_relative_to(source) and f.relative_to(source).parts[0]=='src':selected.add(str(f.relative_to(source)))
 (out/'selected-sources.json').write_text(json.dumps(sorted(selected),indent=2)+'\n')
 cases=[
 ('entry-before-range',run.FAMILY,'xdev_ext_net_cover_check',entry_first),
 ('offset-truncated-to-u32',run.FAMILY,'xdev_ext_net_cover_check',lambda s:once(s,'(__u64)f[cur].data_off + bytes','(__u32)(f[cur].data_off + bytes)')),
 ('ignore-span-bad',run.FAMILY,'xdev_ext_net_cover_check',lambda s:once(s,' || s.bad)',')')),
 ('generic-forbid-zero-span',run.FAMILY,'xdev_ext_net_cover_check',lambda s:once(s,' || s.bad)',' || s.bad || !s.len)')),
 ('entry-errno-normalized',run.FAMILY,'xdev_ext_net_cover_check',lambda s:once(s,'return ret;','return -EINVAL;')),
 ('ignore-final-undercoverage',run.FAMILY,'xdev_ext_net_cover_check',lambda s:once(s,'return cur + 1 == nr_frames && bytes == f[cur].data_len ? 0 : -EMSGSIZE;','return 0;')),
 ('ignore-backward-position',run.FAMILY,'xdev_ext_net_cover_check',lambda s:once(s,'s.frame_pos < cur','false')),
 ('net-entry-capacity64',run.NET,'xdev_ext_net_plan_check',lambda s:once(s,'XDEV_EXT_NET_MAX_ENTRIES','64')),
 ('net-header-readiness-weakened',run.PEER,'xdev_ext_peer_net_check',lambda s:once(s,'header < 14','header < 13')),
 ('net-mtu-error-normalized',run.PEER,'xdev_ext_peer_net_check',lambda s:once(s,'return -EMSGSIZE;','return -EINVAL;')),
 ]
 if a.phase=='shared':cases += [
 ('adapter-drop-all-bad',run.NET,'xdev_ext_net_plan_span',lambda s:append(s,'out->bad = 0;')),
 ('adapter-entry-uses-desc-flags',run.NET,'xdev_ext_net_plan_entry',lambda s:prepend(s,'if (((const struct xdev_ext_net_plan_ctx *)ctx)->d[i].flags) return -EOPNOTSUPP;')),
 ('wrapper-bypass-family',run.NET,'xdev_ext_net_plan_check',lambda s:prepend(s,'if (info && d) return 0;')),
 ]
 results=[]
 for name,rel,sym,change in cases:
  dest=out/name;root=dest/'source';root.mkdir(parents=True,exist_ok=True)
  for relsrc in selected:
   p=root/relsrc;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source/relsrc,p)
  p=root/rel
  try:
   text=p.read_text();body=function(text,sym);p.write_text(once(text,body,change(body)))
   with contextlib.redirect_stdout(io.StringIO()) as log:status=run.execute(root,a.phase,dest/'build')
   (dest/'console.log').write_text(log.getvalue());runtime=(dest/'build/run.log').read_text() if (dest/'build/run.log').exists() else ''
   kill=status==1 and ('ASSERT ' in runtime or 'Assertion ' in runtime)
   result={'name':name,'status':'DETECTED' if kill else 'SURVIVED' if status==0 else 'SETUP','compile_ok':(dest/'build/compile.log').exists() and not (dest/'build/compile.log').read_text(),'exit':status}
  except (OSError,RuntimeError) as e:result={'name':name,'status':'SETUP','reason':str(e)}
  results.append(result);print(name+': '+result['status'])
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 if any(r['status']=='SETUP' for r in results):return 2
 return int(any(r['status']!='DETECTED' for r in results))
if __name__=='__main__':sys.exit(main())
