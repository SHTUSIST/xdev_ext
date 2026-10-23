#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent graph admission oracle, executing the production pure rules.

POOL_PEER=3 is allocation-fd backed GPU memory: power-of-two frames of 4 KiB to
2 MiB, no host header room, any frames per group, and any order of NVMe
read/write and native NET TX/RX stages (the per-class capability table).
Updated for P1: 75b51c2 pinned 64 KiB, one frame and NVMe-read-first here.
Ordinary START must drive an arbitrarily longer bounded-window campaign.
"""
from pathlib import Path
import argparse
import subprocess
import sys
import tempfile
import unittest

KERNEL = Path(__file__).resolve().parents[5]
TEST_REVISION = None
C_SOURCE = r'''
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
#ifndef XDEV_EXT_MECH_PEER_CAPS
static __u32 xdev_ext_mech_peer_dirs(__u32 c){(void)c;return 0;}
#endif
enum { PEER=3, NET=8 };
static int want(const char *name,int actual,int expected)
{if(actual!=expected){fprintf(stderr,"%s: actual=%d expected=%d\n",name,actual,expected);return 1;}return 0;}
static struct xdev_ext_mech_create graph(void)
{
 struct xdev_ext_mech_create c={.abi_version=XDEV_EXT_MECH_ABI_VERSION,.nr_stages=2,.pool_kind=PEER,.pool_fd=7,
  .layout={.frame_size=65536,.hdr_room=0,.seg_len=4096,.group_bytes=4096},.depth=2,.eventfd=-1};
 c.st[0]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=8,.arg1=128};
 c.st[1]=(struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=9,.arg1=128};
 return c;
}
int main(int argc,char **argv)
{
 struct xdev_ext_mech_create c=graph();__u32 frames=0;int ret=0;
 if(argc!=2)return 2;
 if(!strcmp(argv[1],"peer_nvme")){
  ret=want("NVMe read -> GPU pool -> NVMe write",xdev_ext_mech_create_check(&c,&frames),0);
  if(!ret)ret=want("one GPU frame/group",frames,1);
 }else if(!strcmp(argv[1],"peer_net")){
  c.st[1].class_id=NET;
  ret=want("NVMe read -> GPU pool -> NET TX",xdev_ext_mech_create_check(&c,&frames),0);
 }else if(!strcmp(argv[1],"native_class")){
  ret=want("native NET class recognized",xdev_ext_mech_class_known(NET),1);
  ret|=want("class table spans id8",XDEV_EXT_MECH_CLASS_MAX,9);
 }else if(!strcmp(argv[1],"reject_host_stages")){
  const __u32 ids[]={XDEV_EXT_MECH_CLASS_CE,XDEV_EXT_MECH_CLASS_IAA,XDEV_EXT_MECH_CLASS_DMA,XDEV_EXT_MECH_CLASS_SOCKET,XDEV_EXT_MECH_CLASS_AFXDP};
  for(unsigned i=0;i<sizeof(ids)/sizeof(ids[0]);i++){c=graph();c.st[1].class_id=ids[i];ret|=want("GPU pool rejects a class without a peer capability",xdev_ext_mech_create_check(&c,&frames),ids[i]==XDEV_EXT_MECH_CLASS_CE&&(xdev_ext_mech_peer_dirs(ids[i])&XDEV_EXT_DMA_DIR_TO_DEVICE)?0:-EOPNOTSUPP);}
 }else if(!strcmp(argv[1],"native_rx")){
  c.st[1].class_id=NET;c.st[1].direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;
  ret=want("native NET RX into GPU frames",xdev_ext_mech_create_check(&c,&frames),0);
  c.st[0]=c.st[1];c.st[1]=graph().st[1];
  ret|=want("NIC RX -> GPU -> NVMe write",xdev_ext_mech_create_check(&c,&frames),0);
 }else if(!strcmp(argv[1],"gpu_first")){
  c.st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;
  ret=want("GPU -> NVMe write first (caller synchronized CUDA producers)",xdev_ext_mech_create_check(&c,&frames),0);
  c.st[0].class_id=NET;ret|=want("GPU -> NET TX first",xdev_ext_mech_create_check(&c,&frames),0);
 }else if(!strcmp(argv[1],"reject_geometry")){
  c.layout.frame_size=12288;ret|=want("GPU frame is a power of two",xdev_ext_mech_create_check(&c,&frames),-EOPNOTSUPP);
  c=graph();c.layout.frame_size=2048;c.layout.seg_len=2048;c.layout.group_bytes=2048;ret|=want("GPU frame at least 4 KiB",xdev_ext_mech_create_check(&c,&frames),-EOPNOTSUPP);
  c=graph();c.layout.frame_size=4u<<20;ret|=want("GPU frame at most 2 MiB",xdev_ext_mech_create_check(&c,&frames),-EOPNOTSUPP);
  c=graph();c.layout.hdr_room=16;ret|=want("GPU payload has no CPU header room",xdev_ext_mech_create_check(&c,&frames),-EOPNOTSUPP);
  c=graph();c.layout.seg_len=2048;ret|=want("GPU group of two frames",xdev_ext_mech_create_check(&c,&frames),0);
  if(!ret)ret|=want("two GPU frames per group",frames,2);
  c=graph();c.layout.frame_size=4096;ret|=want("4 KiB GPU frame",xdev_ext_mech_create_check(&c,&frames),0);
  c=graph();c.layout.frame_size=2u<<20;ret|=want("2 MiB GPU frame",xdev_ext_mech_create_check(&c,&frames),0);
 }else if(!strcmp(argv[1],"bounded_start")){
  struct xdev_ext_mech_start start={.session_id=10,.nr_batches=257};
  ret=want("one START longer than depth has no user continuation",xdev_ext_mech_start_check(&start,PEER,false,1,2),0);
  start.flags=XDEV_EXT_MECH_START_F_USER_FRAMES;start.nr_batches=1;start.nr_user_frames=1;start.user_frames=42;
  ret|=want("GPU frame cannot masquerade as registered host USER frame",xdev_ext_mech_start_check(&start,PEER,false,1,2),-EINVAL);
 }else if(!strcmp(argv[1],"legacy_unchanged")){
  c.pool_kind=XDEV_EXT_MECH_POOL_IOU_UMEM;c.pool_fd=-1;c.layout.frame_size=4096;
  ret=want("legacy UMEM NVMe graph still admitted",xdev_ext_mech_create_check(&c,&frames),0);
  c=graph();c.pool_fd=-1;ret|=want("peer pool needs an actual authority fd",xdev_ext_mech_create_check(&c,&frames),-EBADF);
 }else return 2;
 return ret;
}
'''


class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="independent-peer-graph-admission-")
        cls.addClassCleanup(cls.tmp.cleanup)
        source = Path(cls.tmp.name) / "actual.c"
        cls.binary = Path(cls.tmp.name) / "actual"
        include_root = KERNEL
        if TEST_REVISION:
            include_root = Path(cls.tmp.name) / "production"
            for filename in ("io_uring/xdev_ext_mech_step.h", "io_uring/xdev_ext_mech_core.h", "include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_binding.h"):
                target = include_root / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(subprocess.check_output(["git", "show", TEST_REVISION + ":./" + filename], cwd=KERNEL))
        source.write_text(C_SOURCE)
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-I" + str(include_root), str(source), "-o", str(cls.binary)], check=True)

    def test_actual_graph_admission(self):
        for case in ("peer_nvme", "peer_net", "native_class", "reject_host_stages", "native_rx", "gpu_first", "reject_geometry", "bounded_start", "legacy_unchanged"):
            with self.subTest(case=case):
                result = subprocess.run([str(self.binary), case], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--revision")
    args, rest = parser.parse_known_args()
    TEST_REVISION = args.revision
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)
