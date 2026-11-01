#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real PCI native-submit function with a software queue adapter.
This certifies command construction/lifetime only, never physical DMA.
"""
from pathlib import Path
import os
import re
import resource
import signal
import subprocess
import tempfile
kernel = Path(__file__).resolve().parents[4]
source = (kernel / 'drivers/nvme/host/pci.c').read_text()
start = source.index('static int nvme_pci_peer_rw(')
end = source.index('\n#endif', start)
function = source[start:end]
def structure(source, name):
    match = re.search(r'^struct ' + name + r' \{\n.*?^};', source, re.M | re.S)
    if not match:
        raise RuntimeError('missing actual structure: ' + name)
    return match.group()

def definition(source, name):
    match = re.search(r'^(?:static )?(?:int|void) ' + name + r'\([^;{}]*\)\n\{.*?^}',
                      source, re.M | re.S)
    if not match:
        raise RuntimeError('missing actual function: ' + name)
    return match.group()

peer_core = (kernel / 'io_uring/xdev_ext_peer.c').read_text()
lease_types = '#define XDEV_EXT_PEER_HOST_TEST\n#include "' + str(kernel / 'include/linux/xdev_ext_peer.h') + '"\n'
lease_types += '\n'.join(structure(peer_core, name) for name in
    ('xdev_ext_peer_provider', 'xdev_ext_peer_region', 'xdev_ext_peer_mapping'))
release_functions = '\n'.join(definition(peer_core, name) for name in
    ('xdev_ext_peer_release', 'xdev_ext_peer_unmap', 'xdev_ext_peer_unpin'))
fd_release = definition((kernel / 'io_uring/xdev_ext_peer_fd.c').read_text(),
                        'xdev_ext_peer_fd_release').replace(
                            'void xdev_ext_peer_fd_release(', 'void actual_fd_release(', 1)
release_boundary = r'''void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool q)
{ released++; last_quiesced=q; actual_fd_release(h,q); }'''
old_release_boundary = r'''void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool q)
{ released++; last_quiesced=q; if(q) { h->file=NULL; h->lease.mapping=NULL; } }'''
event_type = structure((kernel / 'include/trace/events/xdev_ext.h').read_text(),
                       'xdev_ext_native_event')
trace_header = re.sub(r'^#include[^\n]*\n', '',
    (kernel / 'drivers/nvme/host/xdev_ext_native_peer_trace.h').read_text(), flags=re.M)
peer_flag = re.search(r'NVME_REQ_XDEV_EXT_PEER\s*=\s*([^,]+),',
    (kernel / 'drivers/nvme/host/nvme.h').read_text()).group(1)
shim = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "xdev_ext_peer_test_shim.h"
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
#define NVME_REQ_XDEV_EXT_PEER /* ACTUAL_PEER_FLAG */
#define REQ_FAILFAST_MASK 0x700
#define IS_ERR(p) (!(p))
#define PTR_ERR(p) (-ENOMEM)
#define to_pci_dev(p) (p)
#define nvme_req_op(c) ((c)->rw.opcode == 1)
#define nvme_req(r) (&(r)->nr)
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
struct nvme_xdev_ext_peer_trace;
struct request { struct { struct nvme_command *cmd; u32 flags; struct nvme_xdev_ext_peer_trace *peer_trace; } nr; u32 cmd_flags; struct nvme_command storage; };
/* ACTUAL_LEASE_TYPES */
/* ACTUAL_EVENT_TYPE */
static struct xdev_ext_native_event release_event;
static unsigned emitted;
static bool trace_enabled = true;
static bool trace_native_event_enabled(void) { return trace_enabled; }
static void trace_native_event(const struct xdev_ext_native_event *event)
{ release_event = *event; emitted++; }
/* ACTUAL_TRACE_HEADER */
static int acquired, released, freed, executed, execute_result, acquire_result;
static bool last_quiesced;
static DEFINE_MUTEX(xdev_ext_peer_registry_lock);
/* ACTUAL_RELEASE_FUNCTIONS */
/* ACTUAL_FD_RELEASE */
/* RELEASE_BOUNDARY */
static unsigned memory_unmaps, memory_unpins;
static int memory_unmap(void *allocation, struct pci_dev *peer, struct xdev_ext_peer_dma *dma)
{ (void)allocation; (void)peer; (void)dma; memory_unmaps++; return 0; }
static int memory_unpin(void *allocation)
{ (void)allocation; memory_unpins++; return 0; }
static struct module memory_owner={.refs=1};
static const struct xdev_ext_peer_provider_ops memory_ops={.owner=&memory_owner,.unmap=memory_unmap,.unpin=memory_unpin};
static struct file provider_file={.refs=2};
static struct xdev_ext_peer_region regions[3];
static struct xdev_ext_peer_mapping mappings[3];
static u64 allocation_tags[3];
static struct request request;
static struct nvme_command command;
static struct nvme_dev *to_nvme_dev(struct ctrl *c) { return c->dev; }
static int nvme_ctrl_state(struct ctrl *c) { return c->state; }
static bool test_bit(unsigned bit, unsigned long *p) { return (*p >> bit) & 1; }
static bool nvme_ctrl_sgl_supported(struct ctrl *c) { return c->sgl; }
static bool get_disk_ro(struct disk *d) { return d->ro; }
static u64 get_capacity(struct disk *d) { return d->sectors; }
static u32 queue_max_hw_sectors(struct queue *q) { return q->max; }
int xdev_ext_peer_file_acquire(struct file *f, struct pci_dev *p, u64 gen, u64 offset, u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h)
{ (void)p; (void)offset; (void)dir; acquired++; h->lease.dma_address = 0x700000;
  assert(acquired<=3);
  if (!acquire_result) {
   struct xdev_ext_peer_region *region=&regions[acquired-1];
   struct xdev_ext_peer_mapping *mapping=&mappings[acquired-1];
   mutex_init(&region->lock); INIT_LIST_HEAD(&region->maps);
   region->ops=&memory_ops; region->file=&provider_file; region->allocation=&allocation_tags[acquired-1];
   mapping->region=region; mapping->active=1; mapping->leases=&h->lease;
   mapping->dma.private=&allocation_tags[acquired-1]; list_add_tail(&mapping->node,&region->maps);
   h->file=f; get_file(f); h->lease.mapping=mapping; h->lease.ticket=gen; h->lease.len=len;
  }
  return acquire_result; }
#define DMA_TO_DEVICE 1
#define DMA_FROM_DEVICE 2
static struct request *blk_mq_alloc_request(struct queue *q, int op, int flags)
{ (void)q; (void)op; (void)flags; memset(&request,0,sizeof(request)); request.nr.cmd=&request.storage; return &request; }
static void nvme_init_request(struct request *r, struct nvme_command *c)
{ c->common.flags &= ~0xc0; *r->nr.cmd = *c; }
static int nvme_execute_rq(struct request *r, bool head)
{ (void)head; assert((r->cmd_flags & REQ_FAILFAST_MASK)==REQ_FAILFAST_MASK);
  assert((r->nr.flags & (NVME_REQ_USERCMD|NVME_REQ_XDEV_EXT_PEER))==(NVME_REQ_USERCMD|NVME_REQ_XDEV_EXT_PEER));
  const struct nvme_xdev_ext_peer_trace *trace=r->nr.peer_trace;
  assert(trace && trace->cookie==(u64)(uintptr_t)r && trace->nr_leases==1 && trace->bytes==4096 && !strcmp(trace->origin,"U"));
  assert(trace->leases->file && trace->leases->lease.mapping && trace->leases->lease.len==trace->bytes);
  command=*r->nr.cmd; executed++; return execute_result; }
static void blk_mq_free_request(struct request *r)
{ assert(!(r->nr.flags & NVME_REQ_XDEV_EXT_PEER) && !r->nr.peer_trace); freed++; }
'''
main = r'''
int main(void)
{
 struct pci_dev pci={0}; struct nvme_dev dev={&pci};
 struct ctrl ctrl={NVME_CTRL_LIVE,true,&dev};
 struct head head={.lba_shift=9,.ns_id=7}; struct disk disk={1000,false}; struct queue queue={128};
 struct nvme_ns ns={&ctrl,1UL<<NVME_NS_READY,&head,&disk,&queue}; struct file f={.refs=1};
 struct xdev_ext_peer_nvme_rw u={.allocation_fd=3,.generation=2,.offset=0,.slba=10,.bytes=4096};
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==0);
 assert(executed==1 && freed==1 && released==1 && last_quiesced);
 assert(command.rw.opcode==2 && command.rw.nsid==7 && command.rw.slba==10 && command.rw.length==7);
 assert(command.rw.dptr.sgl.addr==0x700000 && command.rw.dptr.sgl.length==4096 && command.common.flags==NVME_CMD_SGL_METABUF);
 assert(emitted==1 && !strcmp(release_event.phase,"peer_dma_release") && !strcmp(release_event.origin,"U"));
 assert(release_event.class_id==3 && release_event.cookie==(u64)(uintptr_t)&request && release_event.bytes==4096 && release_event.aux==1);
 assert(release_event.accepted && release_event.status==0);
 assert(f.refs==1 && !mappings[0].active && !mappings[0].leases && !regions[0].quarantined);
 puts("ok 1 - real PCI function submits pre-mapped GPU SGL through native queue without bio");
 u.flags=XDEV_EXT_PEER_NVME_F_WRITE; execute_result=-EIO;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO);
 assert(command.rw.opcode==1 && executed==2 && freed==2 && released==2 && !last_quiesced);
 assert(emitted==2 && !release_event.accepted && release_event.status==-EINPROGRESS);
 assert(regions[1].invalid && regions[1].quarantined);
 assert(f.refs==1 && !mappings[1].active && !mappings[1].leases);
 assert(xdev_ext_peer_unmap(&mappings[1])==-EIO && xdev_ext_peer_unpin(&regions[1])==-EIO);
 assert(!memory_unmaps && !memory_unpins && memory_owner.refs==1 && provider_file.refs==2);
 assert(mappings[1].region==&regions[1] && mappings[1].dma.private==&allocation_tags[1] && !list_empty(&regions[1].maps));
 puts("ok 2 - accepted failure is not resent and keeps peer DMA resources quarantined");
 ctrl.sgl=false; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EOPNOTSUPP && acquired==2);
 ctrl.sgl=true; disk.ro=true; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EROFS && acquired==2);
 disk.ro=false; head.ms=8; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EOPNOTSUPP && acquired==2);
 head.ms=0; u.slba=999; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-ERANGE && acquired==2);
 puts("ok 3 - native capability, read-only, metadata and namespace bounds reject before mapping");
 assert(emitted==2);
 /* The prior allocation is quarantined; disabled observation uses a fresh fd. */
 struct file fresh_allocation={.refs=1};
 trace_enabled=false; execute_result=0; u.slba=10;
 assert(nvme_pci_peer_rw(&ns,&u,&fresh_allocation,NULL)==0 && executed==3 && freed==3 && released==3 && last_quiesced && emitted==2);
 assert(fresh_allocation.refs==1 && regions[1].quarantined);
 puts("ok 4 - actual synchronous trace context and release preserve success, UNKNOWN retention and disabled observation");
 return 0;
}
'''
unknown_main = main[:main.index(' assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==0);')] + r'''
 execute_result=-EIO;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO);
 assert(regions[0].invalid && regions[0].quarantined);
 assert(f.refs==1 && !mappings[0].active && !mappings[0].leases);
 assert(release_event.status==-EINPROGRESS && !release_event.accepted);
 assert(xdev_ext_peer_unmap(&mappings[0])==-EIO && xdev_ext_peer_unpin(&regions[0])==-EIO);
 assert(!memory_unmaps && !memory_unpins && memory_owner.refs==1 && provider_file.refs==2);
 return 0;
}
'''
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='xdev-peer-native-') as directory:
    p = Path(directory)
    fixture = shim.replace('#include \"xdev_ext_peer.h\"', '#include \"'+str(kernel/'include/uapi/linux/xdev_ext_peer.h')+'\"')
    for marker, actual in (('ACTUAL_PEER_FLAG', peer_flag), ('ACTUAL_LEASE_TYPES', lease_types),
                          ('ACTUAL_EVENT_TYPE', event_type), ('ACTUAL_TRACE_HEADER', trace_header),
                          ('ACTUAL_RELEASE_FUNCTIONS', release_functions), ('ACTUAL_FD_RELEASE', fd_release),
                          ('RELEASE_BOUNDARY', release_boundary)):
        fixture = fixture.replace('/* ' + marker + ' */', actual)
    for name, boundary, entry in (('native', fixture, main), ('unknown', fixture, unknown_main),
            ('old-release-mock', fixture.replace(release_boundary, old_release_boundary), unknown_main)):
        path = p / (name + '.c')
        path.write_text(boundary + function + entry)
        binary = p / name
        subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=undefined',
                        '-pthread', '-I'+str(kernel/'drivers/nvme/host'),
                        '-I'+str(kernel/'tools/testing/selftests/xdev_ext_peer'),
                        str(path),'-o',str(binary)],check=True)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        if os.environ.get('XDEV_EXT_TEST_ARTIFACTS'):
            artifacts = Path(os.environ['XDEV_EXT_TEST_ARTIFACTS'])
            artifacts.mkdir(parents=True, exist_ok=True)
            (artifacts / (name + '.log')).write_text(result.stdout + result.stderr)
        if name == 'old-release-mock':
            assert result.returncode == -signal.SIGABRT, result.stderr
            assert 'regions[0].invalid && regions[0].quarantined' in result.stderr, result.stderr
            assert 'runtime error:' not in result.stderr, result.stderr
            print('ok 5 - original UNKNOWN release mock is rejected by actual quarantine/retirement contract')
        else:
            print(result.stdout, end='')
            if result.returncode:
                print(result.stderr, end='')
                raise subprocess.CalledProcessError(result.returncode, [str(binary)])
