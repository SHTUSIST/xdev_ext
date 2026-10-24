#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual RX post and representor/profile caller chain, host-only boundaries."""
from pathlib import Path
import ast
import os
import shutil
import subprocess
import tempfile
import unittest
from test_native_owner_teardown import MAIN, function
from native_rep_fixture import REP_SHIM, REP_MAIN

class RepRx(unittest.TestCase):
    def test_actual_rep_unload_retains_owned_profile_and_late_use(self):
        main=MAIN.read_text();rep=(MAIN.parent/'en_rep.c').read_text()
        code=REP_SHIM
        for source,name in [(main,'mlx5e_detach_netdev'),(main,'mlx5e_netdev_change_profile'),
            (main,'mlx5e_netdev_attach_nic_profile'),(rep,'mlx5e_vport_uplink_rep_unload'),
            (rep,'mlx5e_vport_rep_unload'),(rep,'mlx5e_is_uplink_rep')]:code+=function(source,name)+'\n'
        self.run_cases(code+REP_MAIN,[0,1],address=True)
    def test_existing_rx_endpoint_rejects_quarantined_owner(self):
        path=Path(__file__).with_name('mlx5_peer_rx_ring_test.py')
        node=next(n for n in ast.parse(path.read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SHIM' for t in n.targets))
        shim=ast.literal_eval(node.value)
        body=function((MAIN.parent/'en_rx.c').read_text(),'mlx5e_peer_recv')
        cases=r'''
int main(int argc,char**argv){
 u8 headers[8*128]={0},dest[42]={0};struct xdev_ext_peer_rx*posted[8]={0};
 struct mlx5e_peer_rq peer={.posted=posted,.headers=headers,.headers_dma=0x500000,.stride=64,.owner=1,.terminate_lkey_be=MLX5_TERMINATE_SCATTER_LIST_LKEY};
 struct channel ch={.rq={.peer=&peer,.state=1,.mkey_be=77}};struct channel*cp=&ch;
 struct mlx5e_priv priv={.state=1,.channels={1,&cp}};struct net_device dev={&priv,1500};
 struct xdev_ext_peer_rx rx={.dma_address=0x700000,.len=1472,.header_room=42,.header=dest,.complete=done};
 int mode=atoi(argv[1]);ch.peer_quarantined=mode==1;priv.peer_quarantined=mode==2;
 int ret=mlx5e_peer_recv(&dev,0,1,&rx);
 return mode ? ret!=-EIO||doorbells||posted[0]!=NULL : ret||doorbells!=1||posted[0]!=&rx;
}
'''
        self.run_cases(shim+'\n#include <stdlib.h>\n'+body+cases,[0,1,2])
    def test_actual_eswitch_parent_stops_after_existing_or_fresh_unknown(self):
        here=Path(__file__).parent
        offloads=(MAIN.parent/'eswitch_offloads.c').read_text()
        eswitch=(MAIN.parent/'eswitch.c').read_text()
        code=(here/'native_eswitch_fixture.h').read_text()
        for source,name in [(offloads,'esw_offloads_disable'),
            (eswitch,'mlx5_eswitch_disable_locked'),(offloads,'mlx5_devlink_eswitch_mode_set'),
            (offloads,'mlx5_esw_offloads_rep_cleanup')]:code+='\n'+function(source,name)
        self.run_cases(code+(here/'native_eswitch_cases.c').read_text(),[0,1,2])
    def test_actual_suspend_retains_inner_backing_after_fresh_unknown(self):
        from native_suspend_fixture import EXTENSION, MAIN as SUSPEND_MAIN
        shim=REP_SHIM.replace('static int disable_count,',
            'static int inject_unknown;\nstatic int disable_count,')
        shim=shim.replace('disable_count++;',
            'disable_count++;if(inject_unknown)p->peer_quarantined=true;')
        source=MAIN.read_text()
        code=shim+EXTENSION+function(source,'mlx5e_detach_netdev')
        code+=function(source,'_mlx5e_suspend')+SUSPEND_MAIN
        self.run_cases(code,[0,1,2,3],unused_shim=True)
    def run_cases(self,code,cases,address=False,unused_shim=False):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/'actual.c';source.write_text(code)
            for cc in ['gcc',shutil.which('clang') or 'clang-14']:
                binary=Path(td)/Path(cc).name
                command=[cc,'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
                    '-Wno-unused-variable','-Wno-sign-compare','-fno-omit-frame-pointer',
                    '-fsanitize='+('address,undefined' if address else 'undefined'),str(source),'-o',str(binary)]
                if unused_shim: command.insert(-3,"-Wno-unused-function")
                build=subprocess.run(command,text=True,capture_output=True)
                self.assertEqual(build.returncode,0,build.stdout+build.stderr)
                for mode in cases:
                    with self.subTest(compiler=cc,mode=mode):
                        run=subprocess.run([str(binary),str(mode)],capture_output=True,text=True)
                        self.assertEqual(run.returncode,0,run.stdout+run.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
