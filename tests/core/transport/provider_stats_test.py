#!/usr/bin/env python3
"""Count actual AF_XDP ACK journal state under its provider lock."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
HERE=Path(__file__).resolve().parent
class ProviderStats(unittest.TestCase):
 def test_pending_and_uncertain_window_entries(self):
  source=(ROOT/'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
  body=re.search(r'^static void xsk_rel_transport_stats\([^;{}]*\)\s*\{.*?^\}',source,re.M|re.S)[0]
  fixture=(HERE/'native_ack_fixture.c').read_text()
  fixture=fixture.replace('struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xsk_rel_data data[32]; };','struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xdev_ext_rel_rx rx; struct xsk_rel_data data[32]; struct xsk_rel_control control[32];u64 ack_pending[32]; };')
  fixture=fixture.replace('/* PRODUCTION_NATIVE_DONE */',body)+r'''
int main(void) {
 struct fake_xp xp={0};struct xsk_xdev_ext_mech_provider p={.xp=&xp};
 struct fake_session s={.pool={.priv=&p},.native_controls=4};
 struct xsk_mech_reliable r={.rx={.cfg={.window=3}}};
 struct xsk_xdev_ext_mech_stage xst={.rel=&r};struct xdev_ext_mech_stage st={.s=&s,.priv=&xst};
 u32 pending=0,uncertain=0;
 r.ack_pending[0]=11;r.ack_pending[2]=13;r.ack_pending[3]=14;
 r.control[1].uncertain=true;r.control[3].uncertain=true;
 xsk_rel_transport_stats(&st,&pending,&uncertain);
 if(pending!=2||uncertain!=1||s.native_controls!=4)return 1;
 xst.rel=NULL;pending=uncertain=0;xsk_rel_transport_stats(&st,&pending,&uncertain);
 return pending||uncertain;
}
'''
  with tempfile.TemporaryDirectory(prefix='transport-provider-') as tmp:
   p=Path(tmp);(p/'probe.c').write_text(fixture)
   subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(ROOT),str(p/'probe.c'),'-o',str(p/'probe')],check=True)
   subprocess.run([str(p/'probe')],check=True)
if __name__=='__main__':unittest.main(verbosity=2)
