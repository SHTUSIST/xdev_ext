#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual NVMe peer ioctl admission/batch code with hostile fd reuse.

Software adapters certify admission, snapshots and native-call ownership only;
they do not issue physical storage I/O or certify physical GPU DMA.
"""
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[4]
SHIM = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
typedef uint32_t u32;
#define __user
#define cpu_to_le32(x) (x)
#define CAP_SYS_RAWIO 17
#define NVME_IOCTL_PARTITION 2
#define nvme_cmd_write 1
#define nvme_cmd_read 2
#define IS_ERR(p) (!(p))
#define PTR_ERR(p) (-EFAULT)
#define kfree free
struct file { int refs, identity; };
struct nvme_command { struct { unsigned char opcode; u32 nsid; } rw; };
struct nvme_ns;
struct ctrl_ops { int (*peer_rw)(struct nvme_ns *, const struct xdev_ext_peer_nvme_rw *, struct file *, bool *); };
struct ctrl { struct ctrl_ops *ops; };
struct head { u32 ns_id; };
struct nvme_ns { struct ctrl *ctrl; struct head *head; };
static bool has_rawio=true, cmd_allowed=true, bad_copyin, bad_copyout;
static struct file original={1,7}, replacement={1,9};
static struct file *fd_slot=&original;
static struct xdev_ext_peer_nvme_batch *user_batch;
static int calls, fail_at=-1, fail_status=-EIO, close_on_first, mutate_on_first, copyouts;
static u32 last_opcode, last_nsid;
static bool capable(int cap) { assert(cap==CAP_SYS_RAWIO); return has_rawio; }
static bool nvme_cmd_allowed(struct nvme_ns *ns, struct nvme_command *cmd, unsigned flags, bool write)
{ (void)ns;(void)flags;(void)write;last_opcode=cmd->rw.opcode;last_nsid=cmd->rw.nsid;return cmd_allowed; }
static int copy_from_user(void *dst,const void *src,size_t n)
{ if(bad_copyin)return 1;memcpy(dst,src,n);return 0; }
static int copy_to_user(void *dst,const void *src,size_t n)
{ copyouts++;if(bad_copyout)return 1;memcpy(dst,src,n);return 0; }
static void *memdup_user(const void *src,size_t n)
{ void *p;if(bad_copyin)return NULL;p=malloc(n);assert(p);memcpy(p,src,n);return p; }
static struct file *fget(int fd) { if(fd!=3 || !fd_slot)return NULL;fd_slot->refs++;return fd_slot; }
static void fput(struct file *f) { assert(f->refs>0);f->refs--; }
static int native(struct nvme_ns *ns,const struct xdev_ext_peer_nvme_rw *u,struct file *f,bool *accepted)
{
 (void)accepted;
 int i=calls++;
 assert(ns->head->ns_id==23 && f==&original && f->identity==7 && f->refs>=1);
 assert(u->generation==55 && u->offset==(uint64_t)i*65536 && u->slba==(uint64_t)i*8 && u->bytes==4096);
 if(i==0 && close_on_first) { fput(&original);fd_slot=&replacement; }
 if(i==0 && mutate_on_first) { user_batch->desc[1].offset=123;user_batch->desc[1].bytes=1;user_batch->generation=99; }
 return i==fail_at?fail_status:0;
}
'''
MAIN = r'''
static struct ctrl_ops ops={.peer_rw=native};
static struct ctrl ctrl={&ops}; static struct head head={23}; static struct nvme_ns ns={&ctrl,&head};
static struct xdev_ext_peer_nvme_batch b;
static void reset(void)
{
 memset(&b,0,sizeof(b)); b.allocation_fd=3;b.generation=55;b.nr=3;
 for(u32 i=0;i<b.nr;i++) {b.desc[i].offset=(uint64_t)i*65536;b.desc[i].slba=i*8;b.desc[i].bytes=4096;}
 calls=copyouts=0; fail_at=-1;fail_status=-EIO;close_on_first=mutate_on_first=0;
 has_rawio=cmd_allowed=true;bad_copyin=bad_copyout=false;original.refs=replacement.refs=1;
 fd_slot=&original;user_batch=&b;ops.peer_rw=native;
}
static int batch(void) { return nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_BATCH,&b,0,true); }
int main(void)
{
 struct xdev_ext_peer_nvme_rw u;
 reset();close_on_first=mutate_on_first=1;
 assert(batch()==0 && calls==3 && b.completed==3 && b.status==0 && original.refs==0 && replacement.refs==1);
 assert(b.generation==55 && b.desc[1].offset==65536 && b.desc[1].bytes==4096);
 puts("ok 1 - actual batch snapshots descriptors once and holds original allocation across concurrent close/fd reuse");
 reset();fail_at=1;fail_status=0x182;
 assert(batch()==0x182 && calls==2 && b.completed==1 && b.status==0x182 && original.refs==1);
 reset();fail_at=0;assert(batch()==-EIO && calls==1 && !b.completed && b.status==-EIO && original.refs==1);
 puts("ok 2 - actual batch stops at first native failure, preserves successful prefix and never resends accepted error");
 reset();has_rawio=false;assert(batch()==-EPERM && !calls && original.refs==1);
 reset();b.flags=2;assert(batch()==-EINVAL && !calls);
 reset();b.flags=XDEV_EXT_PEER_NVME_F_WRITE;
 assert(nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_BATCH,&b,0,false)==-EBADF && !calls);
 reset();assert(nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_BATCH,&b,NVME_IOCTL_PARTITION,true)==-EOPNOTSUPP && !calls);
 reset();cmd_allowed=false;assert(batch()==-EACCES && !calls);
 reset();ops.peer_rw=NULL;assert(batch()==-EOPNOTSUPP && !calls);
 puts("ok 3 - actual admission enforces RAWIO, write authority, partition exclusion, command permission and native capability");
 reset();b.desc[2].reserved=1;assert(batch()==-EINVAL && !calls && !copyouts);
 reset();b.nr=65;assert(batch()==-EINVAL && !calls);
 reset();b.nr=0;assert(batch()==-EINVAL && !calls);
 reset();b.completed=1;assert(batch()==-EINVAL && !calls);
 reset();b.status=-1;assert(batch()==-EINVAL && !calls);
 reset();b.reserved=1;assert(batch()==-EINVAL && !calls);
 reset();b.allocation_fd=-1;assert(batch()==-EBADF && !calls);
 reset();bad_copyin=true;assert(batch()==-EFAULT && !calls);
 reset();bad_copyout=true;assert(batch()==-EFAULT && calls==3 && original.refs==1);
 puts("ok 4 - actual batch validates full reserved list and bounded count before native work, handles raw-copy failures");
 reset();u=(struct xdev_ext_peer_nvme_rw){.allocation_fd=3,.generation=55,.bytes=4096};
 assert(nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_RW,&u,0,false)==0 && calls==1 && original.refs==1);
 assert(last_opcode==nvme_cmd_read && last_nsid==23);
 reset();u.flags=XDEV_EXT_PEER_NVME_F_WRITE;
 assert(nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_RW,&u,0,true)==0 && calls==1 && last_opcode==nvme_cmd_write);
 reset();u.reserved=1;assert(nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_RW,&u,0,true)==-EINVAL && !calls);
 reset();bad_copyin=true;assert(nvme_peer_ioctl(&ns,XDEV_EXT_PEER_NVME_RW,&u,0,true)==-EFAULT && !calls);
 puts("ok 5 - actual single request preserves namespace/opcode, allows read-only reads, rejects reserved/raw-copy errors");
 return 0;
}
'''


def execute(code, directory, name):
    source = directory / (name + ".c")
    source.write_text('#include "' + str(KERNEL / "include/uapi/linux/xdev_ext_peer.h") + '"\n' + SHIM + code + MAIN)
    binary = directory / name
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True)


def main():
    source = (KERNEL / "drivers/nvme/host/ioctl.c").read_text()
    start = source.index("static int nvme_peer_rw_allowed(")
    code = source[start:source.index("\n#endif", start)]
    mutations = [
        ("RAWIO bypass", code.replace("if (!capable(CAP_SYS_RAWIO))", "if (!capable(CAP_SYS_RAWIO) && false)")),
        ("write permission bypass", code.replace("if (write && !open_for_write)", "if (write && !open_for_write && false)")),
        ("partition escape", code.replace("if (flags & NVME_IOCTL_PARTITION)", "if ((flags & NVME_IOCTL_PARTITION) && false)")),
        ("accepted error retry", code.replace("if (ret) break;", "if (ret) { ret = nvme_peer_rw_allowed(ns, &u, flags, open_for_write, allocation); }\n  if (ret) break;")),
        ("missed descriptor snapshot", code.replace(".offset = batch->desc[i].offset", ".offset = ((struct xdev_ext_peer_nvme_batch *)argp)->desc[i].offset")),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-ioctl-") as tmp:
        directory = Path(tmp)
        result = execute(code, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed) in enumerate(mutations):
            assert changed != code, name
            result = execute(changed, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
