#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""An unquiesced native callback cannot publish a successful graph result.

Executes real native wait/finish/work functions. Existing OS-boundary adapters
provide one accepted callback with status zero but no DMA-quiescence proof.
No device, provider or physical DMA is created by this host check.
"""
# P4: this checks the one-at-a-time synchronous NET path, kept under XDEV_EXT_PEER_NET_SYNC_ONE.
from pathlib import Path
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[5]
BASE = runpy.run_path(str(ROOT/'tools/testing/selftests/xdev_ext_peer/independent_peer_net_completion.py'))
shim = BASE['SHIM'].replace('if(scenario==6)tx->complete(tx,-EIO,false);',
                            'if(scenario==6)tx->complete(tx,0,false);')
assert shim != BASE['SHIM']
source = (ROOT/'io_uring/xdev_ext_peer_net.c').read_text()
code = source[source.index('struct xdev_ext_peer_tx_wait {'):source.index('/* A configured native endpoint')]
main = r'''
int main(void)
{
 const struct net_device_ops ops={driver_tx};struct net_device dev={&ops};
 struct file f={};struct pci_dev peer={};bool accepted=false;
 struct xdev_ext_peer_net_desc d={.offset=4096,.bytes=512,.header_len=42,.header={0xAB}};
 reset(6);
 struct xdev_ext_peer_tx_wait *spare=NULL;
 int status=xdev_ext_peer_net_one(&dev,&peer,&f,5,2,&d,&accepted,&spare,NULL,NULL);
 kfree(spare); /* the endpoint drops its reusable context */
 assert(accepted&&submitted==1&&released==1&&!released_quiesced&&freed==1);
 if(!status){fprintf(stderr,"RED native accepted callback status=0 quiesced=false became successful result; generic NET would NEXT/recycle\n");free(live_context);return 1;}
 free(live_context);
 puts("ok 1 - actual native completion without quiescence fails closed even when native status is zero");
 return 0;
}
'''
# The shared helper contains reset() in its main section; reuse only reset,
# preserving the independent assertions above for the new callback outcome.
reset = BASE['MAIN'][BASE['MAIN'].index('static void reset('):BASE['MAIN'].index('int main(void)')]
with tempfile.TemporaryDirectory(prefix='quality-peer-unquiesced-') as tmp:
    path = Path(tmp)
    (path/'actual.c').write_text('#include "'+str(ROOT/'include/uapi/linux/xdev_ext_peer.h')+'"\n'+shim+code+reset+main)
    subprocess.run(['cc','-std=gnu11','-DXDEV_EXT_PEER_NET_SYNC_ONE','-Wall','-Wextra','-Werror','-fsanitize=undefined',str(path/'actual.c'),'-o',str(path/'actual')],check=True)
    raise SystemExit(subprocess.run([str(path/'actual')]).returncode)
