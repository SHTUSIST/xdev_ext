#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-only actual mlx5 parent lifetime tests, without device/DMA emulation."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[5]
MAIN=ROOT/'drivers/net/ethernet/mellanox/mlx5/core/en_main.c'
def function(text,name):
    m=re.search(r'(?m)^(?:static\s+)?(?:inline\s+)?(?:void|int|bool)\s+'+name+r'\s*\([^;{}]*\)\s*\{',text)
    if not m:raise AssertionError('missing production function '+name)
    start=m.start();i=m.end();depth=1
    while depth:
        if text.startswith('/*',i):i=text.index('*/',i+2)+2;continue
        if text.startswith('//',i):i=text.index('\n',i+2);continue
        if text[i] in '\"\'':
            q=text[i];i+=1
            while text[i]!=q:i+=2 if text[i]=='\\' else 1
            i+=1;continue
        depth+=(text[i]=='{')-(text[i]=='}');i+=1
    return text[start:i]

class OwnerTeardown(unittest.TestCase):
    def test_actual_parent_and_owner_functions_keep_failed_backing(self):
        text=MAIN.read_text()
        qos=(MAIN.parent/'en/qos.c').read_text()
        here=Path(__file__).parent
        code=(here/'native_owner_fixture.h').read_text()+'\n'
        for name in ['mlx5e_peer_channel_get','mlx5e_peer_channel_put',
                     'mlx5e_peer_quarantine_channel','mlx5e_peer_quarantine_txqsq',
                     'mlx5e_close_sqs','mlx5e_close_queues']:
            code+=function(text,name)+'\n'
        code+=function(qos,'mlx5e_close_qos_sq')+'\n'
        code+=function(qos,'mlx5e_qos_close_queues')+'\n'
        code+=function(text,'mlx5e_close_channel')+'\n'
        code+=(here/'native_owner_cases.c').read_text()
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/'actual-owner.c';src.write_text(code)
            for cc in ['gcc',shutil.which('clang') or 'clang-14']:
                binary=Path(td)/cc
                subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function',
                    '-fsanitize=undefined',str(src),'-o',str(binary)],check=True)
                for case in range(8):
                    with self.subTest(compiler=cc,case=case):
                        subprocess.run([str(binary),str(case)],check=True)
    def test_checked_parent_owner_and_allocation_free_quarantine(self):
        text=MAIN.read_text()
        for name in ['mlx5e_peer_channel_get','mlx5e_peer_channel_put','mlx5e_peer_quarantine_channel']:
            body=function(text,name)
            self.assertNotRegex(body,r'\b(?:kzalloc|kmalloc|kvcalloc)\s*\(')
        self.assertIn('devlink_try_get',function(text,'mlx5e_peer_channel_get'))
        self.assertIn('devlink_put',function(text,'mlx5e_peer_channel_put'))
        self.assertIn('mlx5e_peer_quarantine_channel',function(text,'mlx5e_close_channel'))

if __name__=='__main__':unittest.main(verbosity=2)
