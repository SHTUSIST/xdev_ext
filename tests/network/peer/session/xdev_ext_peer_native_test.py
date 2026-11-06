#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real PCI native-submit function with a software queue adapter.
This certifies command construction/lifetime only, never physical DMA.
The reset variant also runs the real nvme_dev_disable() over stub hardware
calls: it certifies which driver outcomes reach the peer DMA-stop evidence
API and in which order, not what any controller does.
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
    match = re.search(r'^(?:static )?(?:int|void|bool|u64) ' + name + r'\([^;{}]*\)\n\{.*?^}',
                      source, re.M | re.S)
    if not match:
        raise RuntimeError('missing actual function: ' + name)
    return match.group()

# The whole actual region core in host-test mode: lease retirement, UNKNOWN
# records, requester evidence and recovery work are all production code.
peer_core = (kernel / 'io_uring/xdev_ext_peer.c').read_text()
core_include = '#include "../include/linux/xdev_ext_peer.h"'
if peer_core.count(core_include) != 1:
    raise RuntimeError('missing actual host-test include of the peer core')
lease_types = '#define XDEV_EXT_PEER_HOST_TEST\n' + peer_core.replace(
    core_include, '#include "' + str(kernel / 'include/linux/xdev_ext_peer.h') + '"')
# The integrated submit path encodes through the shared NVMe builder and
# retires through the storage family helper; both are the actual sources.
build_cmd = definition((kernel / 'drivers/nvme/host/core.c').read_text(),
                       'nvme_xdev_ext_peer_build_cmd')
leases_retire = definition((kernel / 'io_uring/family/xdev_ext_storfam.c').read_text(),
                           'xdev_ext_stor_leases_retire')
fd_source = (kernel / 'io_uring/xdev_ext_peer_fd.c').read_text()
fd_release = definition(fd_source, 'xdev_ext_peer_fd_release').replace(
    'void xdev_ext_peer_fd_release(', 'void actual_fd_release(', 1)
fd_release += '\n' + definition(fd_source, 'xdev_ext_peer_fd_release_unknown').replace(
    'bool xdev_ext_peer_fd_release_unknown(', 'bool actual_fd_release_unknown(', 1)
release_boundary = r'''void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool q)
{ released++; last_quiesced=q; actual_fd_release(h,q); }
bool xdev_ext_peer_fd_release_unknown(struct xdev_ext_peer_fd_lease *h, struct xdev_ext_peer_requester *rq, u64 epoch)
{ bool q=actual_fd_release_unknown(h,rq,epoch); released++; last_quiesced=q; return q; }'''
old_release_boundary = r'''void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *h, bool q)
{ released++; last_quiesced=q; if(q) { h->file=NULL; h->lease.mapping=NULL; } }
bool xdev_ext_peer_fd_release_unknown(struct xdev_ext_peer_fd_lease *h, struct xdev_ext_peer_requester *rq, u64 epoch)
{ (void)h; (void)rq; (void)epoch; released++; last_quiesced=false; return false; }'''
# Actual PCI driver evidence: submit snapshot (all variants) and the reset
# path with its two helpers (reset variant only).
submit_hook = definition(source, 'nvme_pci_peer_note_submit')
reset_functions = '\n'.join(definition(source, name) for name in
    ('nvme_pci_peer_quiesce_begin', 'nvme_pci_peer_quiesce_end', 'nvme_dev_disable'))
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
enum nvme_ctrl_state { NVME_CTRL_LIVE = 1, NVME_CTRL_RESETTING = 2 };
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
#define NVME_SGL_FMT_LAST_SEG_DESC 3
#define NVME_CTRL_PAGE_SHIFT 12
#define NVME_CTRL_PAGE_SIZE 4096
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
enum { nvme_cmd_write = 1, nvme_cmd_read = 2 };
struct nvme_sgl_desc { u64 addr; u32 length; unsigned char rsvd[3], type; };
struct nvme_command {
 union {
  struct { u8 opcode, flags; u16 cid; u32 nsid; u64 reserved[2]; union { struct nvme_sgl_desc sgl; struct { u64 prp1, prp2; }; } dptr; u64 slba; u16 length; } rw;
  struct { u8 opcode, flags; } common;
 };
};
struct disk { u64 sectors; bool ro; };
struct queue { u32 max; };
struct head { u8 lba_shift; u16 ms; struct { u8 csi; } ids; u32 ns_id; };
struct nvme_queue { int unused; };
struct ctrl { enum nvme_ctrl_state state; bool sgl; int queue_count; void *admin_q; };
struct nvme_dev { struct pci_dev *dev; struct ctrl ctrl; struct mutex shutdown_lock;
                  struct nvme_queue *queues; struct xdev_ext_peer_requester *peer_requester; };
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
/* ACTUAL_FD_RELEASE */
/* RELEASE_BOUNDARY */
/* ACTUAL_LEASES_RETIRE */
/* ACTUAL_BUILD_CMD */
static unsigned memory_unmaps, memory_unpins;
static int memory_unmap(void *allocation, struct pci_dev *peer, struct xdev_ext_peer_dma *dma)
{ (void)allocation; (void)peer; (void)dma; memory_unmaps++; return 0; }
static int memory_unpin(void *allocation)
{ (void)allocation; memory_unpins++; return 0; }
static struct module memory_owner={.refs=1};
static const struct xdev_ext_peer_provider_ops memory_ops={.owner=&memory_owner,.unmap=memory_unmap,.unpin=memory_unpin};
static struct file provider_file={.refs=2};
static struct xdev_ext_peer_region *regions[8];
static struct xdev_ext_peer_mapping *mappings[8];
static u64 allocation_tags[8];
static struct request request;
static struct nvme_command command;
static struct nvme_dev *to_nvme_dev(struct ctrl *c) { return container_of(c, struct nvme_dev, ctrl); }
static enum nvme_ctrl_state nvme_ctrl_state(struct ctrl *c) { return c->state; }
static bool test_bit(unsigned bit, unsigned long *p) { return (*p >> bit) & 1; }
static bool nvme_ctrl_sgl_supported(struct ctrl *c) { return c->sgl; }
static bool get_disk_ro(struct disk *d) { return d->ro; }
static u64 get_capacity(struct disk *d) { return d->sectors; }
static u32 queue_max_hw_sectors(struct queue *q) { return q->max; }
int xdev_ext_peer_file_acquire(struct file *f, struct pci_dev *p, u64 gen, u64 offset, u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *h)
{ (void)offset; (void)dir; acquired++; h->lease.dma_address = 0x700000;
  assert(acquired<=8);
  if (!acquire_result) {
   struct xdev_ext_peer_region *region=regions[acquired-1]=calloc(1,sizeof(*region));
   struct xdev_ext_peer_mapping *mapping=mappings[acquired-1]=calloc(1,sizeof(*mapping));
   assert(region && mapping);
   mutex_init(&region->lock); INIT_LIST_HEAD(&region->maps);
   region->ops=&memory_ops; region->file=&provider_file; region->allocation=&allocation_tags[acquired-1];
   mapping->region=region; mapping->peer=p; mapping->users=1; mapping->active=1; mapping->leases=&h->lease;
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
/* ACTUAL_SUBMIT_HOOK */
static struct nvme_dev *submit_dev;
static int (*during_execute)(void);
static int nvme_execute_rq(struct request *r, bool head)
{ (void)head; assert((r->cmd_flags & REQ_FAILFAST_MASK)==REQ_FAILFAST_MASK);
  /* nvme_prep_rq: last step before the SQ copy and doorbell. */
  nvme_pci_peer_note_submit(submit_dev, r);
  assert((r->nr.flags & (NVME_REQ_USERCMD|NVME_REQ_XDEV_EXT_PEER))==(NVME_REQ_USERCMD|NVME_REQ_XDEV_EXT_PEER));
  const struct nvme_xdev_ext_peer_trace *trace=r->nr.peer_trace;
  assert(trace && trace->cookie==(u64)(uintptr_t)r && trace->nr_leases==1 && trace->bytes==4096 && !strcmp(trace->origin,"U"));
  assert(trace->leases->file && trace->leases->lease.mapping && trace->leases->lease.len==trace->bytes);
  command=*r->nr.cmd; executed++; return during_execute ? during_execute() : execute_result; }
static void blk_mq_free_request(struct request *r)
{ assert(!(r->nr.flags & NVME_REQ_XDEV_EXT_PEER) && !r->nr.peer_trace); freed++; }
'''
main = r'''
int main(void)
{
 struct pci_dev pci={0}; struct nvme_dev dev={.dev=&pci,.ctrl={NVME_CTRL_LIVE,true,2,NULL}};
 struct head head={.lba_shift=9,.ns_id=7}; struct disk disk={1000,false}; struct queue queue={128};
 struct nvme_ns ns={&dev.ctrl,1UL<<NVME_NS_READY,&head,&disk,&queue}; struct file f={.refs=1};
 submit_dev=&dev;
 struct xdev_ext_peer_nvme_rw u={.allocation_fd=3,.generation=2,.offset=0,.slba=10,.bytes=4096};
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==0);
 assert(executed==1 && freed==1 && released==1 && last_quiesced);
 assert(command.rw.opcode==2 && command.rw.nsid==7 && command.rw.slba==10 && command.rw.length==7);
 assert(command.rw.dptr.sgl.addr==0x700000 && command.rw.dptr.sgl.length==4096 && command.common.flags==NVME_CMD_SGL_METABUF);
 assert(emitted==1 && !strcmp(release_event.phase,"peer_dma_release") && !strcmp(release_event.origin,"U"));
 assert(release_event.class_id==3 && release_event.cookie==(u64)(uintptr_t)&request && release_event.bytes==4096 && release_event.aux==1);
 assert(release_event.accepted && release_event.status==0);
 assert(f.refs==1 && !mappings[0]->active && !mappings[0]->leases && !regions[0]->quarantined);
 puts("ok 1 - real PCI function submits pre-mapped GPU SGL through native queue without bio");
 u.flags=XDEV_EXT_PEER_NVME_F_WRITE; execute_result=-EIO;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO);
 assert(command.rw.opcode==1 && executed==2 && freed==2 && released==2 && !last_quiesced);
 assert(emitted==2 && !release_event.accepted && release_event.status==-EINPROGRESS);
 assert(regions[1]->invalid && regions[1]->quarantined);
 assert(f.refs==1 && !mappings[1]->active && !mappings[1]->leases);
 assert(xdev_ext_peer_unmap(mappings[1])==-EIO && xdev_ext_peer_unpin(regions[1])==-EIO);
 assert(!memory_unmaps && !memory_unpins && memory_owner.refs==1 && provider_file.refs==2);
 assert(mappings[1]->region==regions[1] && mappings[1]->dma.private==&allocation_tags[1] && !list_empty(&regions[1]->maps));
 puts("ok 2 - accepted failure is not resent and keeps peer DMA resources quarantined");
 dev.ctrl.sgl=false; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EOPNOTSUPP && acquired==2);
 dev.ctrl.sgl=true; disk.ro=true; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EROFS && acquired==2);
 disk.ro=false; head.ms=8; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EOPNOTSUPP && acquired==2);
 head.ms=0; u.slba=999; assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-ERANGE && acquired==2);
 puts("ok 3 - native capability, read-only, metadata and namespace bounds reject before mapping");
 assert(emitted==2);
 /* The prior allocation is quarantined; disabled observation uses a fresh fd. */
 struct file fresh_allocation={.refs=1};
 trace_enabled=false; execute_result=0; u.slba=10;
 assert(nvme_pci_peer_rw(&ns,&u,&fresh_allocation,NULL)==0 && executed==3 && freed==3 && released==3 && last_quiesced && emitted==2);
 assert(fresh_allocation.refs==1 && regions[1]->quarantined);
 puts("ok 4 - actual synchronous trace context and release preserve success, UNKNOWN retention and disabled observation");
 return 0;
}
'''
unknown_main = main[:main.index(' assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==0);')] + r'''
 execute_result=-EIO;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO);
 assert(regions[0]->invalid && regions[0]->quarantined);
 assert(f.refs==1 && !mappings[0]->active && !mappings[0]->leases);
 assert(release_event.status==-EINPROGRESS && !release_event.accepted);
 assert(xdev_ext_peer_unmap(mappings[0])==-EIO && xdev_ext_peer_unpin(regions[0])==-EIO);
 assert(!memory_unmaps && !memory_unpins && memory_owner.refs==1 && provider_file.refs==2);
 return 0;
}
'''
reset_env = r'''
/* Stub hardware boundary of the actual nvme_dev_disable(): a recorded order
 * and chosen outcomes, never a controller. */
#define NVME_IO_TIMEOUT 30
#define PCI_COMMAND 0x04
#define PCI_COMMAND_MASTER 0x4
static bool dead, bme_stays, config_error;
static int disable_result, disable_calls, cancel_calls;
static u16 command_register = PCI_COMMAND_MASTER;
static u64 epoch_at_quiesce, proven_at_cancel;
static bool nvme_pci_ctrl_is_dead(struct nvme_dev *d) { (void)d; return dead; }
static bool pci_is_enabled(struct pci_dev *p) { (void)p; return true; }
static void nvme_start_freeze(struct ctrl *c) { (void)c; }
static void nvme_wait_freeze_timeout(struct ctrl *c, int t) { (void)c; (void)t; }
static void nvme_quiesce_io_queues(struct ctrl *c)
{ epoch_at_quiesce = xdev_ext_peer_requester_epoch(to_nvme_dev(c)->peer_requester); }
static void nvme_delete_io_queues(struct nvme_dev *d) { (void)d; }
static int nvme_disable_ctrl(struct ctrl *c, bool shutdown)
{ (void)c; (void)shutdown; disable_calls++; return disable_result; }
static void nvme_poll_irqdisable(struct nvme_queue *q) { (void)q; }
static void nvme_suspend_io_queues(struct nvme_dev *d) { (void)d; }
static void nvme_suspend_queue(struct nvme_dev *d, int qid) { (void)d; (void)qid; }
static void pci_free_irq_vectors(struct pci_dev *p) { (void)p; }
static void pci_disable_device(struct pci_dev *p) { (void)p; if (!bme_stays) command_register &= ~PCI_COMMAND_MASTER; }
static int pci_read_config_word(struct pci_dev *p, int where, u16 *val)
{ (void)p; assert(where == PCI_COMMAND);
  if (config_error) { *val = 0xffff; return 0x86; } /* upstream: error response, PCIBIOS_DEVICE_NOT_FOUND */
  *val = command_register; return 0; }
static void nvme_reap_pending_cqes(struct nvme_dev *d) { (void)d; }
static void nvme_cancel_tagset(struct ctrl *c)
{ struct xdev_ext_peer_requester *rq = to_nvme_dev(c)->peer_requester;
  cancel_calls++; mutex_lock(&rq->lock); proven_at_cancel = rq->proven; mutex_unlock(&rq->lock); }
static void nvme_cancel_admin_tagset(struct ctrl *c) { (void)c; }
static void nvme_unquiesce_io_queues(struct ctrl *c) { (void)c; }
static void nvme_unquiesce_admin_queue(struct ctrl *c) { (void)c; }
static bool blk_queue_dying(void *q) { (void)q; return false; }
'''
reset_main = r'''
static int drain(void) { int n = 0; while (host_run_pending_work()) n++; return n; }
static int cancel_during_reset(void)
{ command_register = PCI_COMMAND_MASTER; nvme_dev_disable(submit_dev, false); return -EINTR; }
static void reset(struct nvme_dev *d, bool shutdown)
{ command_register = PCI_COMMAND_MASTER; cancel_calls = 0; nvme_dev_disable(d, shutdown); drain(); }
int main(void)
{
 static struct nvme_dev dev, dev2;
 struct pci_dev pci={0}, pci2={0}; struct nvme_queue queue0[1];
 struct head head={.lba_shift=9,.ns_id=7}; struct disk disk={1000,false}; struct queue queue={128};
 struct file f={.refs=1}; struct nvme_ns ns;
 struct xdev_ext_peer_nvme_rw u={.allocation_fd=3,.generation=2,.offset=0,.slba=10,.bytes=4096};
 unsigned unmaps0, unpins0; int file0, owner0; u64 e0, k;
 dev=(struct nvme_dev){.dev=&pci,.ctrl={NVME_CTRL_LIVE,true,2,NULL},.queues=queue0};
 dev2=(struct nvme_dev){.dev=&pci2,.ctrl={NVME_CTRL_LIVE,true,2,NULL},.queues=queue0};
 mutex_init(&dev.shutdown_lock); mutex_init(&dev2.shutdown_lock);
 dev.peer_requester=xdev_ext_peer_requester_register(&pci);
 dev2.peer_requester=xdev_ext_peer_requester_register(&pci2);
 assert(dev.peer_requester && dev2.peer_requester);
 ns=(struct nvme_ns){&dev.ctrl,1UL<<NVME_NS_READY,&head,&disk,&queue};
 submit_dev=&dev; memory_owner.refs=10; provider_file.refs=10;
 execute_result=-EIO;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO && !last_quiesced && f.refs==1);
 assert(regions[0]->quarantined && regions[0]->invalid && xdev_ext_peer_unmap(mappings[0])==-EIO);
 assert(!release_event.accepted && release_event.status==-EINPROGRESS);
 puts("ok 6 - accepted failure is held, bound to the epoch its controller received it in");
 disable_result=-ENODEV; reset(&dev,false); disable_result=0;
 assert(regions[0]->quarantined && disable_calls==1 && cancel_calls==1);
 bme_stays=true; reset(&dev,false); bme_stays=false;
 assert(regions[0]->quarantined && disable_calls==2);
 reset(&dev,true);
 assert(regions[0]->quarantined && disable_calls==3);
 dead=true; reset(&dev,false); dead=false;
 assert(regions[0]->quarantined && disable_calls==3 && cancel_calls==1);
 config_error=true; reset(&dev,false); config_error=false;
 assert(regions[0]->quarantined);
 reset(&dev2,false);
 assert(regions[0]->quarantined && !memory_unmaps && !memory_unpins);
 puts("ok 7 - failed CSTS.RDY wait, Bus Master left set, shutdown, dead controller, config error response and another controller's reset prove nothing");
 e0=xdev_ext_peer_requester_epoch(dev.peer_requester);
 command_register=PCI_COMMAND_MASTER; nvme_dev_disable(&dev,false);
 assert(epoch_at_quiesce==e0+1 && proven_at_cancel==e0+1);
 assert(regions[0]->quarantined && drain()==1 && !regions[0]->quarantined && regions[0]->invalid);
 unmaps0=memory_unmaps; unpins0=memory_unpins; file0=provider_file.refs; owner0=memory_owner.refs;
 assert(xdev_ext_peer_unmap(mappings[0])==0 && xdev_ext_peer_unpin(regions[0])==0);
 assert(memory_unmaps==unmaps0+1 && memory_unpins==unpins0+1 && provider_file.refs==file0-1 && memory_owner.refs==owner0-1);
 puts("ok 8 - completed Controller Reset with Bus Master clear: epoch begun before quiesce, proven before cancel, region released once, still invalid until then");
 during_execute=cancel_during_reset;
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EINTR && last_quiesced && f.refs==1);
 during_execute=NULL;
 assert(!regions[1]->quarantined && !regions[1]->invalid && !mappings[1]->active && !mappings[1]->leases);
 assert(release_event.accepted && release_event.status==0);
 puts("ok 9 - command cancelled inside a proven reset is released quiesced at its late completion");
 k=xdev_ext_peer_requester_begin(dev.peer_requester);
 assert(nvme_pci_peer_rw(&ns,&u,&f,NULL)==-EIO && !last_quiesced && regions[2]->quarantined);
 xdev_ext_peer_requester_quiesced(dev.peer_requester,k); drain();
 assert(regions[2]->quarantined);
 reset(&dev,false);
 assert(!regions[2]->quarantined && regions[2]->invalid);
 puts("ok 10 - a command submitted after an epoch began needs a later proven epoch");
 return 0;
}
'''
def function_body(name):
    match = re.search(r'^static [^;{}()]*\b' + name + r'\([^;{}]*\)\s*\{', source, re.M)
    if not match:
        raise RuntimeError('missing actual function: ' + name)
    i, depth = match.end(), 1
    while depth:
        depth += (source[i] == '{') - (source[i] == '}')
        i += 1
    return match.start(), source[match.start():i]

def submit_snapshot_precedes_every_request_sq_copy():
    """Source structure the reset variant relies on but cannot execute."""
    prep = function_body('nvme_prep_rq')[1]
    assert prep.index('nvme_pci_peer_note_submit(dev, req);') > prep.rindex('nvme_map_metadata(')
    assert prep.index('nvme_pci_peer_note_submit(dev, req);') < prep.index('nvme_start_request(req);')
    spans = {name: function_body(name) for name in
             ('nvme_queue_rq', 'nvme_submit_cmds', 'nvme_pci_submit_async_event', 'nvme_sq_copy_cmd',
              'nvme_queue_rqs', 'nvme_prep_rq_batch')}
    for site in re.finditer(r'\bnvme_sq_copy_cmd\(', source):
        owner = [n for n, (start, text) in spans.items() if start <= site.start() < start + len(text)]
        assert owner and owner[0] in ('nvme_queue_rq', 'nvme_submit_cmds', 'nvme_pci_submit_async_event',
                                      'nvme_sq_copy_cmd'), 'unexpected SQ copy site'
    queue_rq = spans['nvme_queue_rq'][1]
    assert queue_rq.index('nvme_prep_rq(dev, req)') < queue_rq.index('nvme_sq_copy_cmd(')
    assert 'return nvme_prep_rq(nvmeq->dev, req) == BLK_STS_OK;' in spans['nvme_prep_rq_batch'][1]
    assert 'if (nvme_prep_rq_batch(nvmeq, req))\n\t\t\trq_list_add_tail(&submit_list, req);' in spans['nvme_queue_rqs'][1]
    assert 'struct request' not in spans['nvme_pci_submit_async_event'][1]
    print('ok 11 - the peer submit snapshot is the last preparation step before every request SQ copy')

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='xdev-peer-native-') as directory:
    p = Path(directory)
    fixture = shim.replace('#include \"xdev_ext_peer.h\"', '#include \"'+str(kernel/'include/uapi/linux/xdev_ext_peer.h')+'\"')
    for marker, actual in (('ACTUAL_PEER_FLAG', peer_flag), ('ACTUAL_LEASE_TYPES', lease_types),
                          ('ACTUAL_EVENT_TYPE', event_type), ('ACTUAL_TRACE_HEADER', trace_header),
                          ('ACTUAL_FD_RELEASE', fd_release),
                          ('RELEASE_BOUNDARY', release_boundary),
                          ('ACTUAL_LEASES_RETIRE', leases_retire), ('ACTUAL_BUILD_CMD', build_cmd),
                          ('ACTUAL_SUBMIT_HOOK', submit_hook)):
        fixture = fixture.replace('/* ' + marker + ' */', actual)
    for name, boundary, code, entry in (('native', fixture, function, main),
            ('unknown', fixture, function, unknown_main),
            ('old-release-mock', fixture.replace(release_boundary, old_release_boundary), function, unknown_main),
            ('reset', fixture + reset_env, function + '\n' + reset_functions, reset_main)):
        path = p / (name + '.c')
        path.write_text(boundary + code + entry)
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
            assert 'regions[0]->invalid && regions[0]->quarantined' in result.stderr, result.stderr
            assert 'runtime error:' not in result.stderr, result.stderr
            print('ok 5 - original UNKNOWN release mock is rejected by actual quarantine/retirement contract')
        else:
            print(result.stdout, end='')
            if result.returncode:
                print(result.stderr, end='')
                raise subprocess.CalledProcessError(result.returncode, [str(binary)])
submit_snapshot_precedes_every_request_sq_copy()
