#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual RX binding/profile bodies over independent host-only boundaries."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_native_owner_teardown import MAIN, function
from native_admission_fixture import PROFILE, PROFILE_MAIN, RX, RX_MAIN

class NativeAdmissionProfile(unittest.TestCase):
    def test_actual_rx_and_profile_rejections_preserve_state(self):
        source=MAIN.read_text()
        cases=[('profile',PROFILE,['mlx5e_detach_netdev','mlx5e_netdev_change_profile'],PROFILE_MAIN,range(2)),
               ('rx',RX,['mlx5e_peer_rx_open'],RX_MAIN,range(6))]
        with tempfile.TemporaryDirectory() as td:
            for name,shim,functions,main,arms in cases:
                src=Path(td)/(name+'.c');src.write_text(shim+'\n'.join(function(source,n) for n in functions)+main)
                for cc in ['gcc',shutil.which('clang') or 'clang-14']:
                    binary=Path(td)/(name+'-'+Path(cc).name)
                    build=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',
                        '-Wno-unused-parameter','-Wno-unused-variable','-fsanitize=undefined',
                        str(src),'-o',str(binary)],capture_output=True,text=True)
                    self.assertEqual(build.returncode,0,build.stdout+build.stderr)
                    for arm in arms:
                        with self.subTest(compiler=cc,case=name,arm=arm):
                            run=subprocess.run([str(binary),str(arm)],capture_output=True,text=True)
                            self.assertEqual(run.returncode,0,run.stdout+run.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
