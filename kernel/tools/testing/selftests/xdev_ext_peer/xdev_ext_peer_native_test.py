#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real PCI native-submit function with a software queue adapter.
This certifies command construction/lifetime only, never physical DMA.
"""
from pathlib import Path
import subprocess
import tempfile
kernel = Path(__file__).resolve().parents[4]
source = (kernel / 'drivers/nvme/host/pci.c').read_text()
start = source.index('static int nvme_pci_peer_rw(')
end = source.index('\n#endif', start)
function = source[start:end]
shim = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "xdev_ext_peer_nvme_core.h"
#include "xdev_ext_peer.h"
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define NVME_CTRL_LIVE 1
#define NVME_NS_READY 1
#define NVME_NS_REMOVING 2
#define SECTOR_SHIFT 9
#define NVME_SGL_FMT_DATA_DESC 0
#define NVME_CMD_SGL_METABUF 0x40
#define NVME_REQ_USERCMD 2
#define REQ_FAILFAST_MASK 0x700
#define IS_ERR(p) (!(p))
#define PTR_ERR(p) (-ENOMEM)
#define to_pci_dev(p) (p)
#define nvme_req_op(c) ((c)->rw.opcode == 1)
#define nvme_req(r) (&(r)->nr)
struct pci_dev { int unused; };
struct file { int unused; };
struct nvme_sgl { u64 addr; u32 length; unsigned char reserved[3], type; };
struct nvme_command {
 union {
  struct { u8 opcode, flags; u16 cid; u32 nsid; u64 reserved[2]; union { struct nvme_sgl sgl; } dptr; u64 slba; u16 length; } rw;
  struct { u8 opcode, flags; } common;
 };
};
struct disk { u64 sectors; bool ro; };
struct queue { u32 max; };
struct head { u8 lba_shift; u16 ms; struct { u8 csi; } ids; u32 ns_id; };
struct nvme_dev { struct pci_dev *dev; };
struct ctrl { int state; bool sgl; struct nvme_dev *dev; };
struct nvme_ns { struct ctrl *ctrl; unsigned long flags; struct head *head; struct disk *disk; struct queue *queue; };
struct request { struct { struct nvme_command *cmd; u32 flags; } nr; u32 cmd_flags; struct nvme_command storage; };
struct xdev_ext_peer_fd_lease { struct { u64 dma_address; } lease; };
static int acquired, released, freed, executed, execute_result, acquire_result;
static bool last_quiesced;
static struct request request;
static struct nvme_command command;
static struct nvme_dev *to_nvme_dev(struct ctrl *c) { return c->dev; }
static int nvme_ctrl_state(struct ctrl *c) { return c->state; }
static bool test_bit(unsigned bit, unsigned long *p) { return (*p >> bit) & 1; }
static bool nvme_ctrl_sgl_supported(struct ctrl *c) { return c->sgl; }
static bool get_disk_ro(struct disk *d) { return d->ro; }
static u64 get_capacity(struct disk *d) { return d->sectors; }
static u32 queue_max_hw_sectors(struct queue *q) { return q->max; }
static int xdev_ext_peer_file_acquire(struct file *f, struct pci_dev *p, u64 gen, u64 offset, u32 len, int dir, struct xdev_ext_peer_fd_lease *h)
{ (void)f; (void)p; (void)gen; (void)offset; (void)len; (void)dir; acquired++; h->lease.dma_address = 0x700000; return acquire_result; }
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool q)
{ (void)h; released++; last_quiesced=q; }
#define DMA_TO_DEVICE 1
#define DMA_FROM_DEVICE 2
static struct request *blk_mq_alloc_request(struct queue *q, int op, int flags)
{ (void)q; (void)op; (void)flags; memset(&request,0,sizeof(request)); request.nr.cmd=&request.storage; return &request; }
static void nvme_init_request(struct request *r, struct nvme_command *c)
{ c->common.flags &= ~0xc0; *r->nr.cmd = *c; }
static int nvme_execute_rq(struct request *r, bool head)
{ (void)head; assert((r->cmd_flags & REQ_FAILFAST_MASK)==REQ_FAILFAST_MASK); command=*r->nr.cmd; executed++; return execute_result; }
static void blk_mq_free_request(struct request *r) { (void)r; freed++; }
'''
main = r'''
int main(void)
{
 struct pci_dev pci={0}; struct nvme_dev dev={&pci};
 struct ctrl ctrl={NVME_CTRL_LIVE,true,&dev};
 struct head head={.lba_shift=9,.ns_id=7}; struct disk disk={1000,false}; struct queue queue={128};
 struct nvme_ns ns={&ctrl,1UL<<NVME_NS_READY,&head,&disk,&queue}; struct file f={0};
 struct xdev_ext_peer_nvme_rw u={.allocation_fd=3,.generation=2,.offset=0,.slba=10,.bytes=4096};
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==0);
 assert(executed==1 && freed==1 && released==1 && last_quiesced);
 assert(command.rw.opcode==2 && command.rw.nsid==7 && command.rw.slba==10 && command.rw.length==7);
 assert(command.rw.dptr.sgl.addr==0x700000 && command.rw.dptr.sgl.length==4096 && command.common.flags==NVME_CMD_SGL_METABUF);
 puts("ok 1 - real PCI function submits pre-mapped GPU SGL through native queue without bio");
 u.flags=XDEV_EXT_PEER_NVME_F_WRITE; execute_result=-EIO;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO);
 assert(command.rw.opcode==1 && executed==2 && freed==2 && released==2 && !last_quiesced);
 puts("ok 2 - accepted failure is not resent and keeps peer DMA resources quarantined");
 ctrl.sgl=false; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EOPNOTSUPP && acquired==2);
 ctrl.sgl=true; disk.ro=true; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EROFS && acquired==2);
 disk.ro=false; head.ms=8; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EOPNOTSUPP && acquired==2);
 head.ms=0; u.slba=999; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-ERANGE && acquired==2);
 puts("ok 3 - native capability, read-only, metadata and namespace bounds reject before mapping");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev-peer-native-') as directory:
    p = Path(directory)
    (p / 'native.c').write_text(shim.replace('#include \"xdev_ext_peer.h\"', '#include \"'+str(kernel/'include/uapi/linux/xdev_ext_peer.h')+'\"') + function + main)
    subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined',
                    '-I'+str(kernel/'drivers/nvme/host'),
                    str(p/'native.c'),'-o',str(p/'native')],check=True)
    subprocess.run([str(p/'native')],check=True)
