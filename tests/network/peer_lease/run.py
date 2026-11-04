#!/usr/bin/env python3
"""Execute actual NET family, peer and selected NET/XD adapter bodies."""
import argparse,json,pathlib,re,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent
FILES={'family':'src/network/io_uring/family/xdev_ext_netfam.c','types':'src/network/include/linux/xdev_ext_netfam.h','peer':'src/core/io_uring/xdev_ext_peer.c','fd':'src/core/io_uring/xdev_ext_peer_fd.c','net':'src/network/io_uring/xdev_ext_mech_net.c','xd':'src/network/io_uring/xdomain/xdev_ext_xdomain_ring.c','xdc':'src/network/io_uring/xdomain/xdev_ext_xdomain_class.c','xdh':'src/network/io_uring/xdomain/xdev_ext_xdomain_core.h','tb':'src/network/include/linux/thunderbolt.h'}
def block(text,name,kind='function'):
 if kind=='struct':pat=r'^struct\s+'+re.escape(name)+r'\s*\{'
 elif kind=='variable':pat=r'^static\s+const\s+struct\s+\w+\s+'+re.escape(name)+r'\s*=\s*\{'
 else:pat=r'^(?:static\s+)?(?:inline\s+)?(?:[\w*]+\s+)+\**'+re.escape(name)+r'\s*\([^;]*?\)\s*\{'
 m=re.search(pat,text,re.M)
 if not m:raise RuntimeError('missing actual '+name)
 i=text.index('{',m.start())+1;depth=1
 while depth and i<len(text):
  if text[i]=='{':depth+=1
  elif text[i]=='}':depth-=1
  i+=1
 if depth:raise RuntimeError('unbalanced actual '+name)
 return text[m.start():i]+(';' if kind!='function' else '')+'\n'
def without_includes(text):return re.sub(r'^#include[^\n]*\n','',text,flags=re.M)
def extract(root,out):
 t={k:(root/v).read_text() for k,v in FILES.items()}
 (out/'family_types.h').write_text(without_includes(t['types']))
 peer=[]
 req=(root/'src/core/include/linux/xdev_ext_requester.h').read_text();rc=(root/'src/core/include/linux/xdev_ext_requester_core.h').read_text()
 family=(root/'src/core/include/linux/xdev_ext_mech.h').read_text()
 peer.append(block(family,'xdev_ext_family_hooks_hdr','struct'))
 (out/'actual_frame.h').write_text(block(family,'xdev_ext_mech_frame','struct'))
 peer+=[block(rc,'xdev_ext_admission','struct'),block(req,'xdev_ext_requester','struct')]
 for name in ['xdev_ext_peer_provider','xdev_ext_peer_region','xdev_ext_peer_mapping']:peer.append(block(t['peer'],name,'struct'))
 for name in ['xdev_ext_peer_fd','xdev_ext_peer_authority','xdev_ext_peer_fd_map']:peer.append(block(t['fd'],name,'struct'))
 peer.append('static atomic64_t xdev_ext_peer_serial;\n')
 peer.append('#include "peer_native.h"\n')
 for name in ['xdev_ext_peer_stale','xdev_ext_peer_direction_valid','xdev_ext_peer_acquire','xdev_ext_peer_release']:peer.append(block(t['peer'],name))
 for name in ['xdev_ext_peer_file_acquire','xdev_ext_peer_fd_release']:peer.append(block(t['fd'],name))
 (out/'actual_peer.h').write_text('\n'.join(peer))
 (out/'actual_runtime.h').write_text(without_includes(t['family']))
 net=[block(t['net'].split('#else',1)[-1],'xdev_ext_net_batch','struct')]
 # Select the completion-driven branch declarations; legacy macro branch must not shadow them.
 n=t['net'][t['net'].index('static void xdev_ext_net_tx_done'):]
 for name in ['xdev_ext_net_tx_done','xdev_ext_net_rx_done','xdev_ext_net_dev_bind','xdev_ext_net_dev_unbind','xdev_ext_net_dev_requester','xdev_ext_net_dev_max_payload','xdev_ext_net_dev_post_tx','xdev_ext_net_dev_post_rx','xdev_ext_net_dev_rx_flush','xdev_ext_net_result']:net.append(block(n,name))
 net.extend([block(n,'xdev_ext_net_dev_ops','variable'),block(n,'xdev_ext_net_member','variable'),block(n,'xdev_ext_net_submit'),block(n,'xdev_ext_net_fill_cqe')])
 (out/'actual_net.h').write_text('\n'.join(net))
 xd=[block(t['tb'],'ring_frame','struct')]
 for name in ['XDEV_EXT_XD_PDF_START','XDEV_EXT_XD_PDF_END','XDEV_EXT_XD_DESC_CRC_ERROR','XDEV_EXT_XD_DESC_BUFFER_OVERRUN']:
  m=re.search(r'^#define '+name+r'[^\n]*',t['xdh'],re.M)
  if not m:raise RuntimeError('missing '+name)
  xd.append(m.group(0)+'\n')
 xd.append(block(t['xdh'],'xdev_ext_xd_rx_frame'))
 xd.append('#include "xd_native.h"\n')
 for name in ['xdev_ext_xd_closing','xdev_ext_xd_poll_wake_locked','xdev_ext_xd_frame','xdev_ext_xd_elem','xdev_ext_xd_tx_cb','xdev_ext_xd_rx_cb','xdev_ext_xd_post','xdev_ext_xd_post_tx','xdev_ext_xd_post_rx']:xd.append(block(t['xd'],name))
 xd.append('extern const struct xdev_ext_net_dev_ops xdev_ext_xd_dev_ops;\nextern void xd_result(struct xdev_ext_netfam_stage *,struct xdev_ext_mech_batch *,const struct xdev_ext_net_slot *,int,bool);\nextern void xd_local(struct xdev_ext_netfam_stage *,struct xdev_ext_net_slot *);\nextern int xd_withdraw(struct xdev_ext_netfam_stage *,struct xdev_ext_net_slot *);\nextern void xd_link_fail(struct xdev_ext_netfam_stage *,int);\n')
 xd.append(block(t['xdc'],'xd_member','variable'))
 (out/'actual_xd.h').write_text('\n'.join(xd))
def execute(root,phase,out):
 out.mkdir(parents=True,exist_ok=True)
 if phase=='typed' and 'XDEV_EXT_NET_LEASE_PEER_DMA' not in (root/FILES['types']).read_text():print('SETUP: typed PEER lease absent');return 2
 extract(root,out)
 cmd=['gcc','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-fsanitize=undefined','-fno-sanitize-recover=all','-MMD','-MF',str(out/'dependencies.d')]
 inc=[HERE,out]+[root/p for p in ['src/core/io_uring','src/core/include/linux','src/core/include','src/network/io_uring','src/network/include/linux','src/network/include']]
 cmd+=['-I'+str(x) for x in inc]
 if phase=='typed':cmd+=['-DTEST_TYPED=1']
 cmd+=[str(HERE/'contract.c'),'-o',str(out/'contract')]
 (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
 p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(out/'compile.log').write_text(p.stdout)
 if p.returncode:print('SETUP: actual-source compile failed\n'+p.stdout);return 2
 p=subprocess.run([str(out/'contract')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);(out/'run.log').write_text(p.stdout);print(p.stdout,end='')
 if p.returncode:print('FAIL: actual-runtime assertion exit='+str(p.returncode));return 1
 return 0

def main():
 p=argparse.ArgumentParser();p.add_argument('--source-root',required=True,type=pathlib.Path);p.add_argument('--phase',choices=['baseline','typed'],default='baseline');p.add_argument('--output',type=pathlib.Path);a=p.parse_args()
 try:
  if a.output:return execute(a.source_root.resolve(),a.phase,a.output.resolve())
  with tempfile.TemporaryDirectory(prefix='peer-lease-') as d:return execute(a.source_root.resolve(),a.phase,pathlib.Path(d))
 except (OSError,RuntimeError) as e:print('SETUP:',e);return 2
if __name__=='__main__':sys.exit(main())
