#!/usr/bin/env python3
"""Execute CREATE admission using current or historical production headers.

The pre-class7 parent is expected to exit 1 (RED), current headers exit 0.
No worktree/index changes are needed for the historical experiment.
"""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[5]
p=argparse.ArgumentParser();p.add_argument('--revision');a=p.parse_args()
files=('io_uring/xdev_ext_mech_core.h','io_uring/xdev_ext_mech_step.h',
       'include/linux/xdev_ext_mech.h','include/uapi/linux/xdev_ext_mech.h',
       'include/uapi/linux/xdev_ext_binding.h')
with tempfile.TemporaryDirectory(prefix='independent-class7-') as temp:
    tree=Path(temp)
    for name in files:
        out=tree/name;out.parent.mkdir(parents=True,exist_ok=True)
        data=subprocess.check_output(['git','show',a.revision+':./'+name],cwd=ROOT) if a.revision else (ROOT/name).read_bytes()
        out.write_bytes(data)
    # Newer admission code uses the CPU contract; older revisions did not.
    if '"xdev_ext_mech_cpu_core.h"' in (tree/'io_uring/xdev_ext_mech_step.h').read_text():
        name = 'io_uring/xdev_ext_mech_cpu_core.h'
        data = subprocess.check_output(['git','show',a.revision+':./'+name],cwd=ROOT) if a.revision else (ROOT/name).read_bytes()
        (tree/name).write_bytes(data)
    source=tree/'admission.c';binary=tree/'admission'
    source.write_text(r'''
#include <stdio.h>
#include "io_uring/xdev_ext_mech_step.h"
int main(void){
 struct xdev_ext_mech_create c={.abi_version=1,.nr_stages=1,.pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM,.pool_fd=-1,.depth=8,.eventfd=-1,
 .layout={.frame_size=4096,.hdr_room=256,.seg_len=2048,.group_bytes=8192},
 .st={{.class_id=7,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=3}}};
 __u32 frames=0;int ret=xdev_ext_mech_create_check(&c,&frames);
 printf("actual_CREATE class=7 ret=%d frames=%u expected_ret=0 expected_frames=4\n",ret,frames);
 return ret || frames!=4;
}
''')
    subprocess.run([os.getenv('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-I',str(tree),str(source),'-o',str(binary)],check=True)
    raise SystemExit(subprocess.run([str(binary)]).returncode)
