# SPDX-License-Identifier: GPL-2.0
"""Execute real SQ observers using software leases; no physical DMA evidence."""
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

hooks = load('peer_dma_hooks', HERE / 'test_dma_backing_hooks.py')
ROOT = hooks.ROOT


def artifact(name, content):
    directory = os.environ.get('XDEV_EXT_TEST_ARTIFACTS')
    if directory:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(content)

CONTEXT = r'''
#define NVME_REQ_XDEV_EXT_PEER 32
#define U64_MAX UINT64_MAX
struct xdev_ext_peer_lease { void *mapping; u64 ticket,dma_address; u32 len; };
struct xdev_ext_peer_fd_lease { struct xdev_ext_peer_lease lease; void *file; };
struct nvme_xdev_ext_peer_trace {
 const struct xdev_ext_peer_fd_lease *leases;
 u32 nr_leases,bytes;
 const char *origin;
 u64 cookie;
};
'''
SQ_PREFIX = r'''
#define unlikely(x) (x)
#define NVMEQ_ENABLED 0
#define BLK_STS_IOERR 5
#define BLK_STS_OK 0
#define spin_lock(x) ((void)(x))
#define spin_unlock(x) ((void)(x))
struct nvme_command { int value; };
struct bio_vec { struct page *bv_page; u32 bv_offset,bv_len; };
struct nvme_iod { u32 dma_len; dma_addr_t first_dma; struct sg_table sgt; struct nvme_command cmd; };
struct nvme_request { u32 flags; struct nvme_xdev_ext_peer_trace *peer_trace; };
struct request { struct nvme_request native; struct nvme_iod iod; struct bio_vec bv; u32 payload,nr_segments; bool integrity; struct request *next; };
struct nvme_dev { struct device *dev; int ctrl; };
struct nvme_queue { struct nvme_dev *dev; unsigned long flags; int sq_lock; };
struct blk_mq_hw_ctx { struct nvme_queue *driver_data; };
struct blk_mq_queue_data { struct request *rq; bool last; };
struct rq_list { struct request *head; };
typedef int blk_status_t;
static bool ready=true; static int prep_status, copies, doorbells;
static struct nvme_request *nvme_req(struct request *r) { return &r->native; }
static struct nvme_iod *blk_mq_rq_to_pdu(struct request *r) { return &r->iod; }
static struct bio_vec req_bvec(struct request *r) { return r->bv; }
static u32 blk_rq_payload_bytes(struct request *r) { return r->payload; }
static u32 blk_rq_nr_phys_segments(struct request *r) { return r->nr_segments; }
static bool blk_integrity_rq(struct request *r) { return r->integrity; }
static bool test_bit(int b,unsigned long *p) { return (*p>>b)&1; }
static bool nvme_check_ready(int *c,struct request *r,bool io) { (void)c;(void)r;(void)io;return ready; }
static int nvme_fail_nonready_command(int *c,struct request *r) { (void)c;(void)r;return 9; }
static int nvme_prep_rq(struct nvme_dev *d,struct request *r) { (void)d;(void)r;return prep_status; }
static void nvme_sq_copy_cmd(struct nvme_queue *q,struct nvme_command *c)
{ (void)q;(void)c;assert(emitted && !strcmp(events[emitted-1].phase,"peer_dma_seal"));copies++; }
static void nvme_write_sq_db(struct nvme_queue *q,bool last) { (void)q;(void)last;doorbells++; }
static bool rq_list_empty(struct rq_list *l) { return !l->head; }
static struct request *rq_list_pop(struct rq_list *l) { struct request *r=l->head;if(r)l->head=r->next;return r; }
'''
SQ_MAIN = r'''
int main(void)
{
 struct device device={0}; struct nvme_dev dev={.dev=&device};
 struct nvme_queue q={.dev=&dev,.flags=1}; struct blk_mq_hw_ctx hctx={&q};
 struct xdev_ext_peer_fd_lease leases[2]={{{(void*)1,101,0xa0000080,1024},(void*)2},{{(void*)1,102,0xb0000040,2048},(void*)2}};
 struct nvme_xdev_ext_peer_trace ctx={leases,2,3072,"K",0};
 struct request r={.native={NVME_REQ_USERCMD|NVME_REQ_XDEV_EXT_PEER,&ctx}};
 struct blk_mq_queue_data bd={&r,true}; ctx.cookie=(u64)(uintptr_t)&r;
 /* A preaccept resource failure is retried without claiming a native copy. */
 prep_status=7; assert(nvme_queue_rq(&hctx,&bd)==7 && !emitted && !copies);
 prep_status=0; q.flags=0; assert(nvme_queue_rq(&hctx,&bd)==BLK_STS_IOERR && !emitted);
 q.flags=1; ready=false; assert(nvme_queue_rq(&hctx,&bd)==9 && !emitted);
 ready=true; assert(!nvme_queue_rq(&hctx,&bd));
 assert(emitted==3 && copies==1 && doorbells==1);
 for(unsigned i=0;i<2;i++) {
  assert(!strcmp(events[i].phase,"peer_dma_span") && !strcmp(events[i].origin,"K"));
  assert(events[i].cookie==ctx.cookie && !events[i].address && events[i].ticket==101+i);
  assert(events[i].native_user_data==leases[i].lease.dma_address && events[i].bytes==leases[i].lease.len);
  assert(events[i].sequence==i && events[i].aux==(i ? 1024U:0) && events[i].accepted);
 }
 assert(!strcmp(events[2].phase,"peer_dma_seal") && events[2].accepted && !events[2].status);
 assert(events[2].bytes==3072 && events[2].aux==2 && !events[2].native_user_data && !events[2].ticket);
 for(unsigned i=0;i<emitted;i++) {
  struct xdev_ext_native_event *e=&events[i];
  printf("observer-1 [000] .... 1.0: native_event: phase=%s origin=%s class_id=3 cookie=%llu address=%llu bytes=%u aux=%llu sequence=%llu native_user_data=%llu ticket=%llu accepted=%d status=%d session_id=0 batch_id=0 batch_key=0 frame_id=0 generation=0 stage=0 origin_tgid=0 process_start_ticks=0 frame_ordinal=0 frame_offset=0 frame_length=0\n",
   e->phase,e->origin,(unsigned long long)e->cookie,(unsigned long long)e->address,e->bytes,
   (unsigned long long)e->aux,(unsigned long long)e->sequence,(unsigned long long)e->native_user_data,
   (unsigned long long)e->ticket,e->accepted,e->status);
 }
 struct rq_list list={&r}; nvme_submit_cmds(&q,&list);
 assert(emitted==6 && copies==2 && doorbells==2); /* One seal per real copy. */
 ctx.bytes++; emitted=0; nvme_native_dma_trace(&dev,&r); assert(!events[emitted-1].accepted);
 ctx.bytes--; leases[0].lease.mapping=0; emitted=0; nvme_native_dma_trace(&dev,&r); assert(!events[emitted-1].accepted);
 leases[0].lease.mapping=(void*)1; leases[0].lease.dma_address=UINT64_MAX-2;
 emitted=0; nvme_native_dma_trace(&dev,&r); assert(!events[emitted-1].accepted);
 leases[0].lease.dma_address=0xa0000080;
 r.native.flags=NVME_REQ_USERCMD; emitted=lookups=0; nvme_native_dma_trace(&dev,&r); assert(!emitted && !lookups);
 emitted=0; nvme_xdev_ext_peer_trace_release(&ctx,true);
 assert(emitted==1 && !events[0].accepted && events[0].status==-ESTALE);
 for(unsigned i=0;i<2;i++) { leases[i].file=0; leases[i].lease.mapping=0; }
 emitted=0; nvme_xdev_ext_peer_trace_release(&ctx,true);
 assert(emitted==1 && events[0].accepted && !events[0].status);
 emitted=0; nvme_xdev_ext_peer_trace_release(&ctx,false);
 assert(emitted==1 && !events[0].accepted && events[0].status==-EINPROGRESS);
 emitted=0; r.native.flags=NVME_REQ_XDEV_EXT_PEER|NVME_REQ_USERCMD; enabled=false;
 nvme_native_dma_trace(0,0); nvme_native_dma_unmap(0);
 nvme_xdev_ext_peer_trace_release(0,false); assert(!emitted && !lookups);
 return 0;
}
'''

class NVMePeerDMA(unittest.TestCase):
    def test_actual_peer_submit_completion_and_retirement_keep_lease_identity(self):
        peer = load('peer_trace_async', ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py')
        # The selected production and every common/native dependency belong to
        # this explicit canonical owner. No incomplete tree or foreign hint.
        path = ROOT / 'src/storage/drivers/nvme/host'
        production = peer.production_source(root=ROOT)
        text, code, fill, submit, have_res = peer.extract(production)
        shim = peer.positional_replace(peer.SHIM, '#include "drivers/nvme/host/xdev_ext_peer_nvme_core.h"',
                                 '#include "' + str(path / 'xdev_ext_peer_nvme_core.h') + '"')
        # This suite supplies the actual trace helper below instead of the
        # ownership-only suite's observation stub.
        shim = peer.positional_replace(shim, '/* PEER_TRACE_RELEASE */', '')
        event_prefix = hooks.TRACE_PREFIX[hooks.TRACE_PREFIX.index('struct xdev_ext_native_event {'):]
        event_prefix = peer.positional_replace(event_prefix, 'u64 cookie,address;', 'u64 cookie,address,ticket;')
        event_prefix = peer.positional_replace(event_prefix, 'events[64]', 'events[65536]')
        event_prefix = peer.positional_replace(event_prefix, 'emitted<64', 'emitted<65536')
        shim = peer.positional_replace(shim, 'struct request {', '#define U64_MAX UINT64_MAX\n' + event_prefix + 'struct request {', 1)
        shim = peer.positional_replace(shim, 'h->lease.dma_address = provider_dma(offset);',
                            'h->lease.ticket = acquire_calls; h->lease.dma_address = provider_dma(offset);', 1)
        shim = peer.positional_replace(shim, 'static void blk_execute_rq_nowait(', 'static void issue_trace(struct request *);\nstatic void blk_execute_rq_nowait(', 1)
        shim = peer.positional_replace(shim, 'r->executed = true; executes++;', 'issue_trace(r); r->executed = true; executes++;', 1)
        shim = peer.positional_replace(shim, 'r->allocated = false;\n}',
                            'assert(!(r->nr.flags & NVME_REQ_XDEV_EXT_PEER) && !r->nr.peer_trace); r->allocated = false;\n}', 1)
        helper = hooks.function((path / 'xdev_ext_native_peer_trace.h').read_text(),
                                'nvme_xdev_ext_peer_trace_release')
        shim = peer.positional_replace(shim, 'static struct request requests[NREQ];',
                            'static bool sync_mode; static int sync_status; static const char *expected_origin="K";\nstatic struct request requests[NREQ];', 1)
        shim = peer.positional_replace(shim, 'if (!(flags & BLK_MQ_REQ_NOWAIT))',
                            'if (!(flags & BLK_MQ_REQ_NOWAIT) && !sync_mode)', 1)
        shim = peer.positional_replace(shim, '(void)r; (void)at_head; blocked_worker++; return 0;',
                            'assert(sync_mode && !at_head); issue_trace(r); executes++; return sync_status;', 1)
        # The sync path binds an UNKNOWN release to this controller's DMA-stop
        # epochs; the fixture has no requester, so it stays unbound.
        code = ('struct xdev_ext_peer_requester;\n'
                'struct nvme_dev { struct device *dev; struct xdev_ext_peer_requester *peer_requester; };\n'
                'bool xdev_ext_peer_fd_release_unknown(struct xdev_ext_peer_fd_lease *h, '
                'struct xdev_ext_peer_requester *rq, u64 epoch)\n'
                '{ (void)rq; (void)epoch; xdev_ext_peer_fd_release(h, false); return false; }\n') + (
            'static struct nvme_dev *to_nvme_dev(struct nvme_ctrl *c) '
            '{ static struct nvme_dev dev; dev.dev=c->dev; return &dev; }\n') + helper + '\n' + code

        code += '\n' + hooks.function((path / 'pci.c').read_text(), 'nvme_native_peer_dma_trace')
        code += r"""
static void issue_trace(struct request *r)
{
 const struct nvme_xdev_ext_peer_trace *ctx=r->nr.peer_trace;
 assert((r->nr.flags & NVME_REQ_XDEV_EXT_PEER) && ctx && ctx->cookie==(u64)(uintptr_t)r);
 assert(ctx->leases && ctx->nr_leases && ctx->bytes && !strcmp(ctx->origin,expected_origin));
 unsigned first=emitted; nvme_native_peer_dma_trace(r);
 assert(emitted==first+ctx->nr_leases+1 && events[emitted-1].accepted);
 u64 offset=0;
 for(u32 i=0;i<ctx->nr_leases;i++) {
  const struct xdev_ext_peer_lease *lease=&ctx->leases[i].lease;
  const struct xdev_ext_native_event *e=&events[first+i];
  assert(lease->mapping && e->cookie==ctx->cookie && e->ticket==lease->ticket);
  assert(!e->address && e->native_user_data==lease->dma_address && e->bytes==lease->len);
  assert(e->sequence==i && e->aux==offset); offset+=e->bytes;
 }
 assert(offset==ctx->bytes);
}
"""
        code += '\n' + hooks.function((path / 'pci.c').read_text(), 'nvme_pci_peer_rw')
        peer.SHIM = shim
        peer.MAIN = peer.positional_replace(peer.MAIN, 'int main(void)', r"""
static void case_sync_trace(void)
{
 struct xdev_ext_peer_nvme_rw u={.generation=87,.offset=512,.bytes=4096,.slba=8};
 sync_mode=true; expected_origin="U";
 for(int i=0;i<2;i++) {
  sync_status=i ? -EIO:0; bool accepted=false; unsigned first=emitted;
  assert(nvme_pci_peer_rw(&ns,&u,&authority,&accepted)==sync_status && accepted);
  assert(!live_leases && emitted==first+3);
  assert(!strcmp(events[emitted-1].phase,"peer_dma_release"));
  assert(events[emitted-1].accepted==!i && events[emitted-1].status==(i ? -EINPROGRESS:0));
 }
 acquire_error=-ESTALE; bool accepted=true; unsigned first=emitted;
 assert(nvme_pci_peer_rw(&ns,&u,&authority,&accepted)==-ESTALE && !accepted && emitted==first);
 acquire_error=0; sync_mode=false; expected_origin="K";
}
int main(void)""", 1)
        peer.MAIN = peer.positional_replace(peer.MAIN, 'case_failures();', 'case_sync_trace(); case_failures();', 1)
        # Validate retirement in the existing actual worker consume boundary.
        peer.MAIN = peer.positional_replace(peer.MAIN, '{ struct xdev_ext_nvme_mech_cqe cqe;',
            '{ unsigned before=emitted; u64 cookie=bps[i].peer_slot->trace.cookie; bool zombie=session.state==XDEV_EXT_MECH_SESSION_ZOMBIE; struct xdev_ext_nvme_mech_cqe cqe;', 1)
        peer.MAIN = peer.positional_replace(peer.MAIN, 'assert(cqe.status == bps[i].cqe.status && cqe.err == bps[i].cqe.err);',
            'assert(cqe.status == bps[i].cqe.status && cqe.err == bps[i].cqe.err); '
            'assert(emitted==before+(zombie ? 0U:1U)); '
            'if(!zombie) { assert(!strcmp(events[emitted-1].phase,"peer_dma_release")); '
            'assert(events[emitted-1].cookie==cookie && events[emitted-1].bytes==bs[i].bytes); '
            'assert(events[emitted-1].accepted==!bs[i].sequester); }', 1)
        with tempfile.TemporaryDirectory() as temp:
            result = peer.build(text, code, fill, submit, have_res, Path(temp), 'peer_lifetime')
            artifact('peer-lifetime.c', (Path(temp) / 'peer_lifetime.c').read_text())
            artifact('peer-lifetime.stdout', result.stdout)
            artifact('peer-lifetime.stderr', result.stderr)
            for suffix in ('fixture-edits.json', 'source-owner.json'):
                report = Path(temp) / ('peer_lifetime.' + suffix)
                if report.is_file():
                    artifact('peer-lifetime.' + suffix, report.read_text())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_sq_sites_use_lease_extents_and_refused_prep_emits_nothing(self):
        pci = (ROOT / 'src/storage/drivers/nvme/host/pci.c').read_text()
        mapping = (ROOT / 'src/core/kernel/dma/mapping.c').read_text()
        names = ['nvme_native_dma_span', 'nvme_native_dma_sg']
        if 'static void nvme_native_peer_dma_trace(' in pci:
            names += ['nvme_native_peer_dma_trace']
        names += ['nvme_native_dma_enabled', 'nvme_native_dma_trace', 'nvme_native_dma_unmap',
                  'nvme_queue_rq', 'nvme_submit_cmds']
        code = hooks.function(mapping, 'dma_range_is_unbounced') + '\n'
        code += hooks.function((ROOT / 'src/storage/drivers/nvme/host/xdev_ext_native_peer_trace.h').read_text(),
                               'nvme_xdev_ext_peer_trace_release') + '\n'
        code += '\n'.join(hooks.function(pci, name) for name in names)
        prefix = hooks.TRACE_PREFIX.replace('u64 cookie,address;', 'u64 cookie,address,ticket;')
        source = hooks.PREFIX + prefix + CONTEXT + SQ_PREFIX + '#define NVME_REQ_USERCMD 2\n#define NVME_REQ_XDEV_EXT_ZC 16\n' + code + SQ_MAIN
        source = '#include <stdio.h>\n' + source
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'sq.c'
            binary = Path(temp) / 'sq'
            for name, candidate in (
                    ('production', source),
                    ('missing SQ observer', source.replace('nvme_native_dma_trace(dev, req);', '', 1)),
                    ('wrong lease DMA', source.replace('e.native_user_data = lease->dma_address;',
                                                        'e.native_user_data = lease->dma_address + 1;', 1))):
                with self.subTest(variant=name):
                    file.write_text(candidate)
                    compiled = subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                               '-Wno-unused-function', str(file), '-o', str(binary)],
                                              capture_output=True, text=True)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    result = subprocess.run([str(binary)], capture_output=True, text=True)
                    label = name.replace(' ', '-')
                    artifact('sq-' + label + '.c', candidate)
                    artifact('sq-' + label + '.stdout', result.stdout)
                    artifact('sq-' + label + '.stderr', result.stderr)
                    if name != 'production':
                        self.assertNotEqual(result.returncode, 0, 'mutation survived: ' + name)
                        continue
                    self.assertEqual(result.returncode, 0, result.stderr)
                    behavior = load('peer_raw_behavior', HERE / 'test_collector_behavior.py')
                    metadata = dict(clock='CLOCK_MONOTONIC', clock_domain='test-local', trace_dropped=0,
                                    abi='xdev-native-fixture-text-v0', evidence_kind='fixture',
                                    physical=False, performance_eligible=False)
                    rows = behavior.load().decode_trace(behavior.manifest(), result.stdout, metadata)
                    artifact('sq-production.decoded.json', json.dumps(rows, indent=2) + '\n')
                    self.assertEqual([r['event'] for r in rows],
                                     ['peer_dma_span', 'peer_dma_span', 'peer_dma_seal'])
                    self.assertEqual([r['native_user_data'] for r in rows], [0xa0000080, 0xb0000040, 0])
                    self.assertTrue(all(r['address_kind'] == 'device_dma' and r['observation_only']
                                        and not r['accepted'] and not r['address'] for r in rows))


if __name__ == '__main__':
    unittest.main()
