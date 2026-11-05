#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NVMe READ -> XDOMAIN TX in one session worker, with ACK-gated frame reuse.

One host executable joins, without editing production bodies:
  * the session core (io_uring/xdev_ext_mech.c, call-graph closure from the
    worker entry points, pasted verbatim) and the PEER pool;
  * the NVMe class with the storage family's block submit/complete path;
  * the XDOMAIN login/ring/class/network family code and the reference
    XDOMAIN protocol program, through the existing XDOMAIN stack fixture;
  * the Thunderbolt NHI ring section (drivers/thunderbolt/nhi.c).
Host boundaries: kthread/work scheduling, MMIO/IRQ of the NHI, the NVMe
controller and the Thunderbolt link (device models that move bytes only to
and from addresses named by real descriptors), the requester/lease provider
mapping and the BPF invocation of the reference programs. No kernel, no
hardware, no DMA, no performance. Exit 0 PASS, 1 behaviour FAIL, 2 SETUP.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
STACK = Path('tools/testing/selftests/xdev_ext_mech/xdomain')
BASE_CASES = ('chain_same_worker', 'reuse_waits_for_ack', 'ack_before_local_done',
              'consumer_holds_ack', 'stale_ack_after_reuse')
# NAME_early: both XDOMAIN stages in EARLY mode (paired receive grants).
CASES = BASE_CASES + tuple(c + '_early' for c in BASE_CASES) + ('no_link_enodev',)
# --pool host only: element synchronization, UNKNOWN custody, pool geometry,
# release of a settled stage.
HOST_CASES = ('host_sync_order', 'host_sync_order_early', 'host_unknown_retained',
              'host_misaligned_refused', 'host_destroy_unmaps')
# Worker entry points; their call-graph closure inside the core text is compiled.
CORE_ROOTS = (
    'xdev_ext_mech_kick_work', 'xdev_ext_mech_batch_drain', 'xdev_ext_mech_progress_work',
    'xdev_ext_mech_retry_work', 'xdev_ext_mech_stop_work', 'xdev_ext_mech_session_init',
    'xdev_ext_mech_session_buffers', 'xdev_ext_mech_session_bind',
    'xdev_ext_mech_batch_complete', 'xdev_ext_mech_batch_sequester',
    'xdev_ext_mech_batch_complete_cancelled', 'xdev_ext_mech_stage_kick',
    'xdev_ext_mech_stage_dead', 'xdev_ext_mech_stage_stop', 'xdev_ext_mech_stage_stop_error',
    'xdev_ext_mech_stage_native_get', 'xdev_ext_mech_stage_native_put',
    'xdev_ext_mech_batch_priv', 'xdev_ext_mech_batch_cookie', 'xdev_ext_mech_batch_ticket',
    'xdev_ext_mech_batch_key', 'xdev_ext_mech_batch_frame', 'xdev_ext_mech_batch_nr_frames',
    'xdev_ext_mech_batch_bytes', 'xdev_ext_mech_batch_id', 'xdev_ext_mech_batch_slot',
    'xdev_ext_mech_batch_stage', 'xdev_ext_mech_batch_session', 'xdev_ext_mech_batch_status',
    'xdev_ext_mech_session_pool', 'xdev_ext_mech_session_layout', 'xdev_ext_mech_session_depth',
    'xdev_ext_mech_session_id', 'xdev_ext_mech_session_state', 'xdev_ext_mech_session_admits',
    'xdev_ext_mech_session_stop_started_ns', 'xdev_ext_mech_count',
    'xdev_ext_mech_trace_native_submit', 'xdev_ext_mech_trace_native_complete',
    'xdev_ext_mech_trace_plan', 'xdev_ext_mech_trace_xdomain_enabled',
    'xdev_ext_mech_trace_xdomain', 'xdev_ext_mech_trace_descriptor_bind',
    'xdev_ext_mech_batch_completion_claim', 'xdev_ext_mech_batch_completion_publish',
    'xdev_ext_mech_frame_recycle', 'xdev_ext_mech_frame_publish',
    # --pool host: START lends the ring's UMEM frames through this function.
    'xdev_ext_mech_take_user_frames')
# Fixture-owned in this unit or chain_boundary.c: program invocation, per-stage
# program instances, and session teardown/report paths outside this scope.
CORE_STOP = ('xdev_ext_mech_call', 'xdev_ext_mech_stage_has_member', 'xdev_ext_mech_reap',
             'xdev_ext_mech_group_timeout', 'xdev_ext_mech_poll_work', 'xdev_ext_mech_create',
             'xdev_ext_mech_create_common', 'xdev_ext_mech_instance_get_from_fd')
REGISTRY = ('xdev_ext_mech_class_register', 'xdev_ext_mech_class_unregister',
            'xdev_ext_mech_class_get', 'xdev_ext_mech_class_put')


# Each mutant changes production (or reference-program) lines in the private
# assembled copy so one claim is false; the named case must fail by assertion.
MUTATIONS = {
    'publish-before-ack': dict(case='reuse_waits_for_ack', edits=[
        ('tools/xdev_ext_mech/xdomain_peer.bpf.c',
         '\t\t\t (info->remote == XDEV_EXT_MP_NET_REMOTE_ACKED &&\n\t\t\t  (facts & XDEV_EXT_MP_XDP_F_LOCAL_QUIESCED)));',
         '\t\t\t (facts & XDEV_EXT_MP_XDP_F_LOCAL_QUIESCED));'),
        ('tools/xdev_ext_mech/xdomain_peer.bpf.c',
         '\t    cqe->remote != XDEV_EXT_MP_NET_REMOTE_ACKED)\n\t\treturn XDEV_EXT_MP_ABORT;', '\t    0)\n\t\treturn XDEV_EXT_MP_ABORT;'),
        ('io_uring/xdomain/xdev_ext_xdomain_class.c',
         '\t\tif (!ns->rx && f->accepted && s->remote != XDEV_EXT_NET_REMOTE_ACKED &&\n'
         '\t\t    s->remote != XDEV_EXT_NET_REMOTE_FAILED && s->remote != XDEV_EXT_NET_REMOTE_LOST) { ret = -EPROTO; break; }\n', ''),
        ('include/linux/xdev_ext_netfam_core.h', '\tdefault:\n\t\treturn -EINPROGRESS;', '\tdefault:\n\t\treturn 0;')]),
    'publish-before-local-done': dict(case='ack_before_local_done', edits=[
        ('tools/xdev_ext_mech/xdomain_peer.bpf.c',
         '\tterminal = (facts & XDEV_EXT_MP_XDP_F_LOCAL_KNOWN) &&\n\t\t   !(facts & XDEV_EXT_MP_XDP_F_NATIVE_PENDING);',
         '\tterminal = 1;'),
        ('tools/xdev_ext_mech/xdomain_peer.bpf.c',
         '\t\t\t (info->remote == XDEV_EXT_MP_NET_REMOTE_ACKED &&\n\t\t\t  (facts & XDEV_EXT_MP_XDP_F_LOCAL_QUIESCED)));',
         '\t\t\t info->remote == XDEV_EXT_MP_NET_REMOTE_ACKED);'),
        ('io_uring/xdomain/xdev_ext_xdomain_class.c', '\t\t    !s->local_known || f->reserved) { ret = -EPROTO; break; }',
         '\t\t    f->reserved) { ret = -EPROTO; break; }'),
        ('io_uring/xdomain/xdev_ext_xdomain_class.c', ' || (!status && !s->local_quiesced)) { ret = -EPROTO; break; }',
         ') { ret = -EPROTO; break; }'),
        ('include/linux/xdev_ext_netfam_core.h',
         '\t*sequester = !local_quiesced;\n\tif (!local_quiesced)\n\t\treturn local_status ? local_status : -EIO;',
         '\t*sequester = false;')]),
    'ack-before-consumer': dict(case='consumer_holds_ack', edits=[
        ('io_uring/xdomain/xdev_ext_xdomain_class.c', '\t\tif (slot->local_status) f->reply->final = true;',
         '\t\tf->reply->final = true; f->reply->chain_done = true;')]),
    'stale-ack-matches-reused-slot': dict(case='stale_ack_after_reuse', edits=[
        ('io_uring/xdomain/xdev_ext_xdomain_class.c',
         '\t\tif (xs->ns.slots[i].busy && xs->ns.slots[i].group == group)\n\t\t\treturn &xs->ns.slots[i];',
         '\t\tif (xs->ns.slots[i].busy)\n\t\t\treturn &xs->ns.slots[i];')]),
    # The next stage is built in the NVMe completion context instead of the
    # session worker (completion-context continuation for storage only).
    'drain-in-completion-context': dict(case='chain_same_worker', edits=[
        ('io_uring/xdev_ext_mech.c',
         '\tif (llist_add(&b->inbox_node, &s->inbox))\n\t\tkthread_queue_work(worker, &s->drain_work);',
         '\tif (llist_add(&b->inbox_node, &s->inbox)) {\n'
         '\t\tif (s->st[b->bs.stage].class_id == XDEV_EXT_MECH_CLASS_NVME)\n'
         '\t\t\txdev_ext_mech_batch_drain(&s->drain_work);\n'
         '\t\telse\n\t\t\tkthread_queue_work(worker, &s->drain_work);\n\t}')]),
    # DMA-BUF pool only: a lease uses whichever attachment was made first.
    'dmabuf-lease-first-mapping': dict(case='chain_same_worker', pool='dmabuf', edits=[
        ('io_uring/xdev_ext_peer_fd.c', '  if (m->peer == peer) goto acquire;', '  goto acquire;')]),
    # --pool host (set automatically): each makes one host-page requirement false.
    'host-release-always-quiesced': dict(case='host_unknown_retained', pool='host', edits=[
        ('io_uring/family/xdev_ext_netfam.c', 'lease->u.hdma.len, quiesced);', 'lease->u.hdma.len, true);')]),
    'host-unbind-checked-passes': dict(case='host_unknown_retained', pool='host', edits=[
        ('io_uring/xdomain/xdev_ext_xdomain_class.c',
         'return xs && xs->ns.admitted ? xdev_ext_requester_host_settled(&xs->ns.rq) : 0;', 'return 0;')]),
    'host-no-device-sync': dict(case='host_sync_order', pool='host', edits=[
        ('io_uring/family/xdev_ext_requester.c',
         '\t\tdma_sync_single_for_device(&h->pdev->dev, addr, len, h->dir);\n', '\t\t;\n')]),
    'host-no-cpu-sync': dict(case='host_sync_order', pool='host', edits=[
        ('io_uring/family/xdev_ext_requester.c',
         '\t\tdma_sync_single_for_cpu(&h->pdev->dev, dma, len, DMA_FROM_DEVICE);\n', '\t\t;\n')]),
    'host-post-peer-address': dict(case='chain_same_worker', pool='host', edits=[
        ('io_uring/xdomain/xdev_ext_xdomain_ring.c',
         '\t\tif (e[i].lease.kind == XDEV_EXT_NET_LEASE_HOST_DMA)\n\t\t\tf->buffer_phy = e[i].lease.u.hdma.dma;\n',
         '')]),
    'host-lease-wrong-frame': dict(case='chain_same_worker', pool='host', edits=[
        ('io_uring/family/xdev_ext_netfam.c', 'err = xdev_ext_requester_host_lease(&ns->rq, off, buf_len,',
         'err = xdev_ext_requester_host_lease(&ns->rq, ns->rx ? off : off ^ 4096, buf_len,')]),
    'host-peer-member': dict(case='chain_same_worker', pool='host', edits=[
        ('io_uring/xdomain/xdev_ext_xdomain_class.c',
         'pool_kind == XDEV_EXT_MECH_POOL_PEER ? &xd_member : &xd_member_host', '&xd_member')]),
    # The family's fini forgets the host-page unbind, so a host-page stage takes
    # the PEER unbind and keeps its whole mapping (review of d3dced6).
    'review-fini-skips-host-unbind': dict(case='host_destroy_unmaps', pool='host', edits=[
        ('io_uring/family/xdev_ext_netfam.c',
         '\tif (ns->admitted && ns->m->lease_kind == XDEV_EXT_NET_LEASE_HOST_DMA) {\n'
         '\t\txdev_ext_requester_unbind_host(&ns->rq);\n\t\tns->admitted = false;\n\t}\n', '')]),
    'tx-wrong-frame': dict(case='chain_same_worker', edits=[
        ('io_uring/family/xdev_ext_netfam.c',
         '\t\t\t\t\t xdev_ext_peer_mech_pool_generation(pool), off, buf_len,',
         '\t\t\t\t\t xdev_ext_peer_mech_pool_generation(pool), ns->rx ? off : off ^ 4096, buf_len,')]),
}


class Setup(Exception):
    pass


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def replace(text, old, new, what):
    if text.count(old) != 1:
        raise Setup('anchor count %d for %s' % (text.count(old), what))
    return text.replace(old, new, 1)


def definitions(text):
    found = {}
    for match in re.finditer(r'^\w[^;{}]*?\b(\w+)\([^;{}]*\)\n\{\n.*?^\}', text, re.M | re.S):
        if match[1] in found:
            raise Setup('two definitions of ' + match[1])
        found[match[1]] = match[0]
    return found


def find_definition(text, name):
    matches = list(re.finditer(r'^\w[^;{}]*?\b' + re.escape(name) + r'\([^;{}]*\)\n\{\n.*?^\}',
                               text, re.M | re.S))
    if len(matches) != 1:
        raise Setup('expected one definition of %s, found %d' % (name, len(matches)))
    return matches[0][0]


def closure(defs, roots, stop):
    order, seen, pending = [], set(), list(roots)
    while pending:
        name = pending.pop(0)
        if name in seen or name in stop:
            continue
        if name not in defs:
            raise Setup('core entry point missing: ' + name)
        seen.add(name)
        order.append(name)
        body = defs[name]
        called = set(re.findall(r'\b(\w+)\s*\(', body))
        called |= set(re.findall(r'kthread_init_(?:delayed_)?work\([^,]+,\s*(\w+)\)', body))
        called |= set(re.findall(r'INIT_WORK\([^,]+,\s*(\w+)\)', body))
        called |= set(re.findall(r'timer_setup\([^,]+,\s*(\w+)', body))
        for name2 in sorted(called):
            if name2 in defs and name2 not in seen and name2 not in stop:
                pending.append(name2)
    return order


def assemble(root, out):
    sys.path.insert(0, str(root / 'tools'))
    layout = load('chain_layout', root / 'tools/layout.py').load_layout(root)
    kernel = out / 'source/kernel'
    if kernel.exists():
        shutil.rmtree(kernel)
    hashes = {}
    for (component, native), source in layout.by_native.items():
        if component != 'linux':
            continue
        destination = kernel / native
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, destination)
        hashes[native] = hashlib.sha256((root / source).read_bytes()).hexdigest()
    # The pinned upstream NHI register header, as tools/ci/check_xdomain_host.py admits it.
    lock = json.loads((root / layout.manifest['dependency_lock']).read_text())
    regs = root / ('tests/support/fixtures/upstream/linux-' + lock['components']['linux']['commit'] +
                   '/nhi_regs.h')
    shutil.copyfile(regs, kernel / 'drivers/thunderbolt/nhi_regs.h')
    hashes['drivers/thunderbolt/nhi_regs.h'] = hashlib.sha256(regs.read_bytes()).hexdigest()
    return kernel, hashes


def core_unit(kernel, build):
    core = (kernel / 'io_uring/xdev_ext_mech.c').read_text()
    transform = kernel / 'io_uring/xdev_ext_compfam_transform.c'
    text = core + ('\n' + transform.read_text() if transform.is_file() else '')
    defs = definitions(text)
    names = closure(defs, CORE_ROOTS, set(CORE_STOP))
    preamble = core[:core.index('\n', core.index('enum xdev_ext_mech_end {'))]
    types = [re.search(r'^enum xdev_ext_mech_end \{\n.*?^\};', core, re.M | re.S)[0]]
    for name in ('xdev_ext_mech_batch', 'xdev_ext_mech_session'):
        match = re.search(r'^struct ' + name + r' \{\n.*?^\};', core, re.M | re.S)
        if not match:
            raise Setup('core structure missing: ' + name)
        types.append(match[0])
    bodies = '\n'.join(defs[n] for n in names)
    globals_ = []
    for match in re.finditer(r'^static (?:const )?[\w ]+?\*?\s*\b(\w+)(?:\[[^\]]*\])?(?: = [^;]+)?;$', core, re.M):
        if re.search(r'\b' + match[1] + r'\b', bodies):
            globals_.append(match[0])
    for match in re.finditer(r'^static (?:LIST_HEAD|DEFINE_SPINLOCK|DEFINE_MUTEX)\((\w+)\);$', core, re.M):
        if re.search(r'\b' + match[1] + r'\b', bodies):
            globals_.append(match[0])
    ops = (kernel / 'io_uring/xdev_ext_mech_ops.c').read_text()
    opsdefs = definitions(ops)
    registry = [opsdefs[n] for n in REGISTRY]
    for decl in ('static DEFINE_MUTEX(xdev_ext_mech_class_lock);',
                 'static const struct xdev_ext_mech_class_ops *xdev_ext_mech_classes[XDEV_EXT_MECH_CLASS_MAX];'):
        if decl not in ops:
            raise Setup('registry storage changed: ' + decl)
        globals_.append(decl)
    functions = [defs[n] for n in names] + registry
    prototypes = []
    for body in functions:
        head = body[:body.index('\n{')]
        prototypes.append(head + ';')
    template = (HERE / 'chain_core.c.in').read_text()
    template = replace(template, '/* CORE_TYPES */', '\n\n'.join(types), 'core types')
    template = replace(template, '/* PROTOTYPES */', '\n'.join(prototypes), 'core prototypes')
    template = replace(template, '/* CORE_GLOBALS */', '\n'.join(globals_), 'core globals')
    template = replace(template, '/* PRODUCTION */', '\n\n'.join(functions), 'core bodies')
    path = build / 'chain_core.c'
    path.write_text(template)
    (build / 'core-functions.json').write_text(json.dumps(dict(
        core=names, registry=list(REGISTRY), stop=list(CORE_STOP)), indent=1) + '\n')
    del preamble
    return path, names


def facade(kernel, directory, units, search=()):
    """Empty kernel headers for every non-project include reached from units."""
    pending, seen, names = list(units), set(), set()
    pattern = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)
    while pending:
        path = pending.pop()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        for kind, name in pattern.findall(path.read_text(errors='replace')):
            if name == 'trace/events/xdev_ext.h':
                names.add(name)  # tracepoint machinery: replaced by a record-type stub
                continue
            candidates = [path.parent / name] if kind == '"' else []
            if kind == '"':
                candidates += [Path(d) / name for d in search]
            candidates.append(kernel / 'include' / name)
            local = next((c for c in candidates if c.is_file()), None)
            project = local is not None and ('xdev_ext' in name or name.startswith('uapi/'))
            if kind == '"' and local is not None:
                pending.append(local)
            elif project:
                pending.append(local)
            elif kind == '<' and name.split('/')[0] in ('linux', 'asm', 'uapi', 'trace', 'net', 'generated', 'vdso'):
                names.add(name)
    for name in names:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('/* kernel environment facade, no production bodies */\n')
    # Host errno.h reaches linux/errno.h: keep the real numeric constants.
    (directory / 'linux').mkdir(parents=True, exist_ok=True)
    (directory / 'linux/errno.h').write_text('#include <asm-generic/errno.h>\n')
    return sorted(names)


def nvme_units(kernel, build):
    """The NVMe class and storage family, unchanged, with the reduced host header."""
    quote = build / 'nvme-quote'
    quote.mkdir(parents=True)
    host = (kernel / 'drivers/nvme/host/nvme.h').read_text()
    capture = find_definition(host, 'nvme_xdev_ext_capture_identity')
    stub = (HERE / 'chain_nvme_host.h').read_text()
    (quote / 'nvme.h').write_text(replace(stub, '#define CHAIN_NVME_CAPTURE_IDENTITY', capture,
                                          'identity capture'))
    unit_dir = build / 'nvme'
    unit_dir.mkdir()
    shutil.copyfile(kernel / 'drivers/nvme/host/xdev_ext_mech_nvme.c', unit_dir / 'xdev_ext_mech_nvme.c')
    core = (kernel / 'drivers/nvme/host/core.c').read_text()
    ioctl = (kernel / 'drivers/nvme/host/ioctl.c').read_text()
    helpers = [find_definition(core, 'nvme_xdev_ext_peer_build_cmd'),
               find_definition(ioctl, 'nvme_xdev_ext_mech_cmd_allowed')]
    glue = replace((HERE / 'chain_nvme_glue.c.in').read_text(), '/* REAL_NVME_HELPERS */',
                   '\n\n'.join(helpers), 'nvme helpers')
    (unit_dir / 'chain_nvme_glue.c').write_text(glue)
    trace = (kernel / 'include/trace/events/xdev_ext.h').read_text()
    event = re.search(r'^struct xdev_ext_native_event \{\n.*?^\};', trace, re.M | re.S)
    if not event:
        raise Setup('native event structure missing')
    return quote, [unit_dir / 'xdev_ext_mech_nvme.c', kernel / 'io_uring/family/xdev_ext_storfam_block.c',
                   kernel / 'io_uring/family/xdev_ext_storfam.c', unit_dir / 'chain_nvme_glue.c'], event[0]


X6_CALL = r"""
/* Composite: run another reference program body with this unit's kfunc views. */
int chain_x6_program_call(struct xdev_ext_mech_stage *stage, const struct xdev_ext_mech_call_args *args,
			  const struct xdev_ext_mech_ctx *ctx,
			  s32 (*fn)(void *, const struct xdev_ext_mech_ctx *), s32 *result)
{
	assert(!active && !stack_spins && !stack_mutexes);
	active = args;
	active_ctx = ctx;
	active_endpoint = stack_endpoint_stage(stage);
	active_fault = 0;
	*result = fn(NULL, ctx);
	active = NULL;
	active_ctx = NULL;
	return 0;
}
"""


def xdomain_units(kernel, build, root, pool='provider'):
    """Existing XDOMAIN stack wrappers; only environment lines are adapted."""
    fixture = kernel / STACK
    env = build / 'xd-facade'
    sys.path.insert(0, str(fixture))
    load('chain_stack_test', fixture / 'stack_test.py').facade(kernel, env)
    load('chain_stack_nhi', fixture / 'stack_nhi_source.py').generate(kernel, env)
    edits = []

    def edit(name, old, new, what):
        path = fixture / name
        path.write_text(replace(path.read_text(), old, new, what))
        edits.append(dict(file=str(STACK / name), what=what))

    # The real core defines xdev_ext_mech_batch_session; the stack copy would duplicate it.
    edit('stack_family.c', '#include "stack_batch_session_source.inc"\n', '',
         'family unit uses the real core accessor')
    edit('stack_x6.c', '\tstruct xdev_ext_mech_ctx ctx = {\n\t\t.base = *args->base,\n'
         '\t\t.callsite = args->callsite,\n\t\t.batch_id = args->b ? args->b->ticket : args->batch_id,\n\t};',
         '\tstruct xdev_ext_mech_ctx chain_program_ctx(struct xdev_ext_mech_stage *,\n'
         '\t\tconst struct xdev_ext_mech_call_args *);\n'
         '\tstruct xdev_ext_mech_ctx ctx = chain_program_ctx(stage, args);',
         'program context built as xdev_ext_mech_invoke does, from real batch accessors')
    edit('stack_x6.c', '.session_id = stage->s->id,', '.session_id = xdev_ext_mech_session_id(stage->s),',
         'protocol record reads the real session id')
    path = fixture / 'stack_x6.c'
    path.write_text(path.read_text() + X6_CALL)
    edits.append(dict(file=str(STACK / 'stack_x6.c'), what='append chain_x6_program_call'))
    edit('stack_boundary.c', '\t\tn->generation=el->slot->ns->st->s->generation;\n'
         '\t\tn->session_id=el->slot->ns->st->s->id;',
         '\t\tn->generation=chain_real_pool_generation(el->slot->ns->st->s);\n'
         '\t\tn->session_id=chain_real_session_id(el->slot->ns->st->s);\n'
         '\t\tchain_note_data_post(r,f,el);',
         'data post identity from real session accessors')
    edit('stack_nhi_boundary.h', '\t\tunsigned endpoint = ring_info(rx->r)->endpoint;\n'
         '\t\tif (world->rx_length_set[endpoint]) rx->completion_len = world->rx_length[endpoint];',
         '\t\tchain_link_payload(ring_info(n->r)->endpoint, n->f->buffer_phy,\n'
         '\t\t\tring_info(rx->r)->endpoint, rx->f->buffer_phy, n->len);\n'
         '\t\tunsigned endpoint = ring_info(rx->r)->endpoint;\n'
         '\t\tif (world->rx_length_set[endpoint]) rx->completion_len = world->rx_length[endpoint];',
         'link model moves payload bytes between the two leased frame memories')
    edit('stack_x4.c', '#define xdev_ext_xd_class_ctl stack_record_dispatch\n',
         '#define xdev_ext_xd_class_ctl stack_record_dispatch\n'
         'struct xdev_ext_xd_msg_v2;\n'
         'void chain_record_dispatch_v2(struct xdev_ext_mech_stage *, const struct xdev_ext_xd_msg_v2 *);\n'
         '#define xdev_ext_xd_class_ctl_v2 chain_record_dispatch_v2\n',
         'EARLY (v2) control dispatch is recorded like the v1 dispatch')
    if pool == 'host':
        edit('stack_kernel_compat.h', 'struct pci_dev{struct device dev;unsigned refs;bool msix_enabled;};',
             'struct pci_bus{unsigned char number;};struct pci_dev{struct device dev;unsigned refs;'
             'bool msix_enabled;struct pci_bus*bus;unsigned int devfn;unsigned int untrusted:1;};',
             'pci_dev has the bus, devfn and untrusted fields the real requester unit reads')
        # The requester unit's Linux headers: empty, declarations in chain_host_env.h.
        for name in re.findall(r'^#include <(linux/[^>]+)>', (kernel / 'io_uring/family/xdev_ext_requester.c').read_text(), re.M):
            if 'xdev_ext' not in name and not (env / name).exists():
                (env / name).parent.mkdir(parents=True, exist_ok=True)
                (env / name).write_text('/* kernel environment facade, no production bodies */\n')
    probe = build / 'xd_probe.c'
    probe.write_text('#define STACK_INTERNAL\n#include "stack_kernel_compat.h"\n#include "stack_nhi_api.h"\n'
                     '#define tb_ring_tx stack_ring_tx\n#define tb_ring_rx stack_ring_rx\n'
                     '#include "' + str(kernel / 'io_uring/xdomain/xdev_ext_xdomain_probe.c') + '"\n')
    prog = build / 'nvme_prog.c'
    prog.write_text('#define STACK_INTERNAL\n#include "stack_kernel_compat.h"\n'
                    '#define LICENSE chain_nvme_s0_license\n#define mode chain_nvme_s0_mode\n'
                    '#include "' + str(kernel / 'tools/xdev_ext_mech/nvme_s0.bpf.c') + '"\n')
    units = [fixture / n for n in ('stack_x3.c', 'stack_x4.c', 'stack_x5.c', 'stack_family.c',
                                   'stack_x6.c', 'stack_nhi.c')] + [probe, prog, HERE / 'chain_boundary.c']
    if pool == 'host':
        requester_unit = build / 'host_requester.c'
        requester_unit.write_text('#define STACK_INTERNAL\n#include "stack_kernel_compat.h"\n'
                                  '#include "chain_host_env.h"\n#include "' +
                                  str(kernel / 'io_uring/family/xdev_ext_requester.c') + '"\n')
        units.append(requester_unit)
    requester = (kernel / 'io_uring/family/xdev_ext_requester.c').read_text()
    boundary = (HERE / 'chain_boundary.c').read_text()
    split = find_definition(requester, 'xdev_ext_peer_lease_split')
    generated = build / 'chain_boundary.c'
    # In DMA-BUF mode the real requester unit supplies xdev_ext_peer_lease_split.
    generated.write_text(replace(boundary, '/* LEASE_SPLIT */', split if pool == 'provider' else
                                 '/* xdev_ext_peer_lease_split: real requester unit */', 'lease split'))
    units[units.index(HERE / 'chain_boundary.c')] = generated
    flags = ['-DSTACK_STARTUP_EVENTS', '-DSTACK_REAL_NHI', '-I', str(env), '-I', str(fixture),
             '-I', str(kernel), '-idirafter', str(kernel / 'include'),
             '-idirafter', str(kernel / 'include/uapi'), '-I', str(kernel / 'tools/xdev_ext_mech'),
             '-I', str(HERE)] + (['-DCHAIN_REAL_PEER'] if pool == 'dmabuf' else [])
    # Per-unit flags: the family's host leases reach the device model through
    # chain_boundary.c, which calls the real requester (host mode) or aborts.
    extra = {fixture / 'stack_family.c': ['-Dxdev_ext_requester_host_lease=chain_host_lease',
                                         '-Dxdev_ext_requester_host_release=chain_host_release',
                                         '-Dxdev_ext_requester_bind_host=chain_host_bind',
                                         '-Dxdev_ext_requester_unbind_host=chain_host_unbind']}
    if pool == 'host':
        extra[units[-1]] = ['-Dxdev_ext_requester_bind=chain_real_requester_bind',
                            '-Dxdev_ext_requester_unbind=chain_real_requester_unbind']
    return [(u, extra.get(u, [])) for u in units], flags, edits


PEER_RENAMES = ['-Dxdev_ext_peer_file_claim=chain_real_peer_file_claim',
                '-Dxdev_ext_peer_file_acquire=chain_real_peer_file_acquire',
                '-Dxdev_ext_peer_fd_release=chain_real_peer_fd_release',
                '-Dxdev_ext_peer_control_file=chain_real_peer_control_file']
REQUESTER_RENAMES = ['-Dxdev_ext_requester_bind=chain_real_requester_bind',
                     '-Dxdev_ext_requester_unbind=chain_real_requester_unbind']


def peer_units(root, kernel, build, common):
    """--pool dmabuf: the real peer/importer/fd/requester units of host 1.

    Same inputs as tests/network/xdomain/dmabuf_requester, whose kernel shim
    edits, empty Linux headers and system-heap extraction are reused."""
    step1 = load('chain_dmabuf_requester', HERE.parent / 'dmabuf_requester/run.py')
    peer = build / 'peer'
    include = peer / 'include'
    for name in step1.BOUNDARY_HEADERS:
        path = include / 'linux' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('/* kernel boundary supplied by kernel_shim.h and boundary.h */\n')
    (include / 'linux/errno.h').write_text('#include <asm-generic/errno.h>\n')
    (include / 'asm').mkdir(parents=True, exist_ok=True)
    (include / 'asm/page.h').write_text('/* PAGE_* from kernel_shim.h */\n')
    shim = (root / step1.SHIM / 'kernel_shim.h').read_text()
    for old, new in step1.SHIM_EDITS:
        shim = replace(shim, old, new, 'kernel_shim edit')
    (peer / 'kernel_shim.h').write_text(shim)
    shutil.copyfile(root / step1.SHIM / 'kernel_shim.c', peer / 'kernel_shim.c')
    heap = (kernel / 'drivers/dma-buf/heaps/system_heap.c').read_text()
    (peer / 'heap_unit.c').write_text((HERE.parent / 'dmabuf_requester/heap_unit.c.in').read_text().replace(
        'SYSTEM_HEAP_DESCRIBE', step1.definition(heap, 'system_heap_xdev_ext_describe') + '\n' +
        step1.initializer(heap, 'system_heap_xdev_ext_desc')))
    (peer / 'fd_unit.c').write_text((HERE.parent / 'dmabuf_requester/fd_unit.c.in').read_text().replace(
        'PEER_FD_SOURCE', '"' + str(kernel / 'io_uring/xdev_ext_peer_fd.c') + '"'))
    flags = common + ['-include', str(peer / 'kernel_shim.h'),
                      '-include', str(HERE.parent / 'dmabuf_requester/boundary.h'),
                      '-I', str(include), '-I', str(peer), '-I', str(HERE.parent / 'dmabuf_requester'),
                      '-I', str(kernel / 'io_uring'), '-I', str(kernel / 'include'), '-I', str(kernel)]
    units = [(peer / 'kernel_shim.c', []), (kernel / 'io_uring/xdev_ext_peer.c', PEER_RENAMES),
             (kernel / 'io_uring/xdev_ext_peer_dmabuf.c', PEER_RENAMES), (peer / 'fd_unit.c', PEER_RENAMES),
             (peer / 'heap_unit.c', PEER_RENAMES),
             (kernel / 'io_uring/family/xdev_ext_requester.c', REQUESTER_RENAMES),
             (HERE / 'chain_peer_bridge.c', PEER_RENAMES + REQUESTER_RENAMES)]
    return flags, units


# Kernel-tree files this script extracts code or declarations from (the compiler
# then reads generated units, so its dependency files do not name these).
DIRECT_READS = ('io_uring/xdev_ext_mech.c', 'io_uring/xdev_ext_compfam_transform.c', 'io_uring/xdev_ext_mech_ops.c',
                'drivers/nvme/host/nvme.h', 'drivers/nvme/host/core.c', 'drivers/nvme/host/ioctl.c',
                'include/trace/events/xdev_ext.h', 'io_uring/family/xdev_ext_requester.c',
                # NHI ring section extracted by the stack fixture's generator, and the
                # stack fixture scripts this runner executes.
                'drivers/thunderbolt/nhi.c', 'drivers/thunderbolt/nhi_regs.h', 'include/linux/thunderbolt.h',
                str(STACK / 'stack_test.py'), str(STACK / 'stack_nhi_source.py'))
DMABUF_DIRECT_READS = ('drivers/dma-buf/heaps/system_heap.c',)
HOST_DIRECT_READS = ('io_uring/xdev_ext_umem.c',)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_inputs(root, out, kernel, hashes, pool):
    """Every input of this run: kernel-tree files the compiler opened (gcc -MD) or this
    script extracted from, keyed by native path with the hash of the source-tree file
    (before any mutation), and the test files and templates this script read."""
    production, tests = {}, {}

    def add(path):
        path = Path(path).resolve()
        for base, table in ((kernel, production), (root, tests)):
            try:
                key = str(path.relative_to(base))
            except ValueError:
                continue
            if table is tests and (out == path or out in path.parents):
                return  # generated from inputs recorded elsewhere
            table[key] = hashes.get(key) if table is production and key in hashes else sha256(path)
            return

    for dep in sorted((out / 'build').rglob('*.d')):
        for item in dep.read_text().replace('\\\n', ' ').split(':', 1)[-1].split():
            add(item)
    for native in DIRECT_READS + (DMABUF_DIRECT_READS if pool == 'dmabuf' else ()) + \
            (HOST_DIRECT_READS if pool == 'host' else ()):
        add(kernel / native)
    files = [f for f in HERE.iterdir() if f.is_file()]
    if pool == 'dmabuf':
        files += [f for f in (HERE.parent / 'dmabuf_requester').iterdir() if f.is_file()]
        files += [root / 'tests/core/peer_dmabuf' / name for name in ('kernel_shim.h', 'kernel_shim.c')]
    for f in files:
        add(f)
    return dict(sorted(production.items())), dict(sorted(tests.items()))


def compile_unit(cc, flags, unit, obj, log):
    result = subprocess.run([cc] + flags + ['-MD', '-MF', str(obj) + '.d', '-c', str(unit), '-o', str(obj)],
                            capture_output=True, text=True, timeout=300)
    log.append('$ %s -c %s\n%s%s' % (cc, unit, result.stdout, result.stderr))
    if result.returncode:
        errors = [l for l in result.stderr.splitlines() if ' error: ' in l or 'fatal error' in l]
        raise Setup('compile failed: %s\n%s' % (unit, '\n'.join(errors[:40]) or result.stderr[-6000:]))


def mutate(kernel, name):
    spec = MUTATIONS[name]
    for native, old, new in spec['edits']:
        path = kernel / native
        path.write_text(replace(path.read_text(), old, new, 'mutation %s in %s' % (name, native)))
    for native, text in spec.get('append', []):
        path = kernel / native
        path.write_text(path.read_text() + text)


def build_all(root, out, sanitize, only, mutation=None, pool='provider'):
    kernel, hashes = assemble(root, out)
    if mutation:
        mutate(kernel, mutation)
    build = out / 'build'
    if build.exists():
        shutil.rmtree(build)
    build.mkdir(parents=True)
    cc = os.environ.get('CC', 'gcc')
    common = ['-std=gnu11', '-O0', '-g', '-Wall', '-Wextra', '-Wno-unused-function',
              '-Wno-unused-parameter', '-Wno-missing-field-initializers',
              '-Werror=implicit-function-declaration', '-pthread'] + \
        (['-DCHAIN_HOST_POOL'] if pool == 'host' else [])
    if sanitize:
        common += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    log = []
    core, names = core_unit(kernel, build)
    core_env = build / 'core-facade'
    facade(kernel, core_env, [core, kernel / 'io_uring/xdev_ext_mech_peer_pool.c'],
           (HERE, kernel / 'io_uring'))
    core_flags = common + ['-I', str(core_env), '-I', str(HERE), '-I', str(kernel / 'io_uring'),
                           '-I', str(kernel / 'include')]
    compile_unit(cc, core_flags, core, build / 'core.o', log)
    objects = [build / 'core.o']
    if only != 'core':
        quote, units, event = nvme_units(kernel, build)
        nvme_env = build / 'nvme-facade'
        facade(kernel, nvme_env, units + [quote / 'nvme.h'], (quote, kernel / 'drivers/nvme/host'))
        trace = nvme_env / 'trace/events/xdev_ext.h'
        trace.parent.mkdir(parents=True, exist_ok=True)
        trace.write_text('/* tracepoints disabled: event record type only */\n' + event +
                         '\nstatic inline void trace_native_event(const struct xdev_ext_native_event *e)'
                         ' { (void)e; }\n')
        nvme_flags = common + ['-include', str(HERE / 'chain_core_env.h'),
                               '-include', str(HERE / 'chain_nvme_env.h'),
                               '-I', str(nvme_env), '-iquote', str(quote),
                               '-iquote', str(kernel / 'drivers/nvme/host'), '-I', str(HERE),
                               '-I', str(kernel / 'io_uring'), '-I', str(kernel / 'include')]
        for number, unit in enumerate(units):
            obj = build / ('nvme-%d.o' % number)
            compile_unit(cc, nvme_flags, unit, obj, log)
            objects.append(obj)
    if only not in ('core', 'nvme'):
        pool_flags = core_flags + ['-include', str(HERE / 'chain_core_env.h')]
        compile_unit(cc, pool_flags, kernel / 'io_uring/xdev_ext_mech_peer_pool.c', build / 'pool.o', log)
        objects.append(build / 'pool.o')
        if pool == 'host':
            umem = (kernel / 'io_uring/xdev_ext_umem.c').read_text()
            begin = umem.find('struct io_xdev_ext_umem_mech {')
            end = umem.find('#endif /* CONFIG_XDEV_EXT_MECH */', begin)
            if begin < 0 or end < 0 or 'int io_xdev_ext_umem_mech_pool_bind(' not in umem[begin:end]:
                raise Setup('IOU_UMEM pool provider block missing in io_uring/xdev_ext_umem.c')
            unit = build / 'chain_umem.c'
            unit.write_text(replace((HERE / 'chain_umem.c.in').read_text(), '/* REAL_UMEM_POOL */',
                                    umem[begin:end], 'umem pool'))
            compile_unit(cc, pool_flags, unit, build / 'umem.o', log)
            objects.append(build / 'umem.o')
        units, xd_flags, edits = xdomain_units(kernel, build, root, pool)
        if pool == 'dmabuf':
            peer_flags, peer_list = peer_units(root, kernel, build, common)
            for number, (unit, renames) in enumerate(peer_list):
                obj = build / ('peer-%d.o' % number)
                compile_unit(cc, peer_flags + renames, unit, obj, log)
                objects.append(obj)
        (out / 'fixture-edits.json').write_text(json.dumps(edits, indent=1) + '\n')
        for number, (unit, extra) in enumerate(units):
            obj = build / ('xd-%d.o' % number)
            compile_unit(cc, common + xd_flags + extra, unit, obj, log)
            objects.append(obj)
        compile_unit(cc, common + ['-I', str(HERE), '-I', str(kernel / 'include/uapi')], HERE / 'cases.c',
                     build / 'cases.o', log)
        objects.append(build / 'cases.o')
        binary = build / 'chain-cases'
        link = [cc, '-pthread'] + (['-fsanitize=address,undefined'] if sanitize else []) + \
            [str(o) for o in objects] + ['-o', str(binary)]
        result = subprocess.run(link, capture_output=True, text=True, timeout=300)
        log.append('$ link\n' + result.stdout + result.stderr)
        (out / 'compile.log').write_text('\n'.join(log))
        if result.returncode:
            raise Setup('link failed\n' + result.stderr[-6000:])
        return kernel, hashes, names, binary
    (out / 'compile.log').write_text('\n'.join(log))
    return kernel, hashes, names, None


def run_cases(binary, out, cases):
    results = []
    for name in cases:
        try:
            run = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=120)
            output, code = run.stdout + run.stderr, run.returncode
        except subprocess.TimeoutExpired as error:
            output, code = str(error.stdout or '') + '\nTIMEOUT\n', 124
        (out / (name + '.log')).write_text(output + '\nexit=%d\n' % code)
        marker = 'CHAIN_CASE ' + name + ' assertions='
        counted = [int(l[len(marker):]) for l in output.splitlines() if l.startswith(marker)]
        failed = next((l for l in output.splitlines() if l.startswith('CHAIN_ASSERT')), None)
        observe = [l for l in output.splitlines() if l.startswith('CHAIN_OBSERVE')]
        results.append(dict(case=name, exit=code, assertions=counted[-1] if counted else 0,
                            passed=code == 0 and bool(counted) and counted[-1] > 0,
                            failed_assertion=failed, observations=observe))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES + HOST_CASES)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--only', choices=('core', 'nvme', 'link'))
    parser.add_argument('--mutation', choices=sorted(MUTATIONS))
    parser.add_argument('--pool', choices=('provider', 'dmabuf', 'host'), default='provider',
                        help='host 1 frames: recording provider, or a system-heap DMA-BUF through '
                             'the real REGISTER/requester/importer/lease code; host: both '
                             'endpoints on the ring\'s IOU_UMEM host pages, NHIs mapped by the '
                             'real requester')
    args = parser.parse_args()
    if args.mutation and MUTATIONS[args.mutation].get('pool'):
        args.pool = MUTATIONS[args.mutation]['pool']
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    record = dict(scope='host composition of real core worker, PEER pool, NVMe class/storage family, '
                  'XDOMAIN X3/X4/X5/network family, reference programs and NHI ring section; '
                  'device models move bytes only at addresses named by real descriptors; '
                  'no kernel/hardware/DMA/performance', sanitize=args.sanitize, mutation=args.mutation,
                  pool=args.pool)
    try:
        record['head'] = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                        capture_output=True, text=True).stdout.strip()
        kernel, hashes, names, binary = build_all(root, out, args.sanitize, args.only, args.mutation, args.pool)
        production, tests = read_inputs(root, out, kernel, hashes, args.pool)
        record.update(core_functions=len(names), inputs_sha256=production, test_inputs_sha256=tests,
                      inputs_rule='inputs_sha256: kernel-tree files the compiler opened (gcc -MD) or the runner '
                                  'extracted from, hashed in the source tree before any mutation; '
                                  'test_inputs_sha256: test files and templates the runner read')
        if binary is None:
            record['verdict'] = 'COMPILED'
            code = 0
        else:
            if args.mutation:
                cases = [args.case or MUTATIONS[args.mutation]['case']]
            else:
                cases = [args.case] if args.case else list(CASES) + \
                    (list(HOST_CASES) if args.pool == 'host' else [])
            record['cases'] = run_cases(binary, out, cases)
            if args.mutation:
                killed = all(c['exit'] == 1 and c['failed_assertion'] for c in record['cases'])
                record['verdict'] = 'KILLED' if killed else 'SURVIVED'
                code = 0 if killed else 1
            else:
                record['verdict'] = 'PASS' if all(c['passed'] for c in record['cases']) else 'FAIL'
                code = 0 if record['verdict'] == 'PASS' else 1
    except (Setup, OSError, subprocess.SubprocessError) as error:
        record.update(verdict='SETUP_ERROR', error=str(error))
        code = 2
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    for case in record.get('cases', []):
        print(('ok' if case['passed'] else 'not ok') + ' - ' + case['case'] + ' assertions=%d exit=%d'
              % (case['assertions'], case['exit']) + ('' if case['passed'] else ' ' + str(case['failed_assertion'])))
        for line in case['observations']:
            print('# ' + line)
    print('CHAIN_VERDICT ' + record['verdict'] + ('' if code != 2 else '\n' + record.get('error', '')[-6000:]))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
