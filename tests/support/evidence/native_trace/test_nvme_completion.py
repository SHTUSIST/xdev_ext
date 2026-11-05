#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the production NVMe end_io body; this is not a DMA experiment.

Only Linux dependencies are supplied below. The completion decision and trace
placement come from the selected NVMe and storage-family production owners.
"""
from pathlib import Path
import shutil
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c'


def function_body(text, name):
    match = re.search(r'^[A-Za-z_][^;{}]*\b' + re.escape(name) + r'\(', text, re.M)
    if not match:
        raise AssertionError('production completion symbol missing: ' + name)
    start = match.start()
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def struct_definition(text, name):
    match = re.search(r'^struct ' + re.escape(name) + r'\s*\{', text, re.M)
    if not match:
        raise AssertionError('production completion type missing: ' + name)
    brace = text.index('{', match.start())
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():text.index(';', end) + 1]


def enum_definition(text, name):
    matches = re.findall(r'^enum ' + re.escape(name) + r'\s*\{[^{}]*\};', text, re.M)
    if len(matches) != 1:
        raise AssertionError('production completion enum count must be one: ' + name)
    return matches[0]


def adapt_fixture(original, replacements):
    """Change counted fixture spans and prove their complete byte inverse."""
    value, edits = original, []
    for old, new in replacements:
        if value.count(old) != 1:
            raise AssertionError('fixture anchor count must be one: ' + old)
        offset = value.index(old)
        value = value[:offset] + new + value[offset + len(old):]
        edits.append((offset, old, new))
    restored = value
    for offset, old, new in reversed(edits):
        if restored[offset:offset + len(new)] != new:
            raise AssertionError('fixture inverse span differs')
        restored = restored[:offset] + old + restored[offset + len(new):]
    if restored != original:
        raise AssertionError('fixture inverse differs from historical bytes')
    return value


def require_order(body, *anchors):
    offsets = []
    for anchor in anchors:
        if body.count(anchor) != 1:
            raise AssertionError('production owner anchor count must be one: ' + anchor)
        offsets.append(body.index(anchor))
    if offsets != sorted(offsets):
        raise AssertionError('production owner order changed: ' + repr(anchors))


PREFIX = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
typedef uint64_t u64;
typedef int blk_status_t;
enum rq_end_io_ret { RQ_END_IO_FREE };
#define NVME_REQ_CANCELLED 1
#define le64_to_cpu(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
struct xdev_ext_mech_batch { int claim; unsigned bytes; };
/* poll_*: stage polling record, retired by every end_io. */
struct xdev_ext_stor_completion {
    struct xdev_ext_mech_batch *b; u64 ticket; bool uncertain; bool poll_live; unsigned poll_queue;
};
struct nvme_xdev_ext_mech_batch { void *bio; int cqe; };
struct nvme_req_data { int flags, status; struct { u64 u64; } result; };
struct request { void *end_io_data, *bio; unsigned bytes; struct nvme_req_data nvme; };
static struct nvme_xdev_ext_mech_batch bp;
static unsigned traced, published, sequence, trace_order, publish_order;
static u64 seen_ticket;
static int seen_status;
static struct xdev_ext_mech_batch *seen_batch;
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { (void)b; return &bp; }
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b, u64 t)
{ (void)t; return b->claim; }
static struct nvme_req_data *nvme_req(struct request *r) { return &r->nvme; }
static int blk_status_to_errno(int e) { return e; }
static unsigned blk_rq_bytes(struct request *r) { return r->bytes; }
static unsigned xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { return b->bytes; }
static void nvme_xdev_ext_mech_cqe(int status, u64 result, int *cqe)
{ (void)result; *cqe = status; }
static void __attribute__((unused)) xdev_ext_mech_trace_native_complete(
    struct xdev_ext_mech_batch *b, u64 ticket, int status)
{ traced++; seen_batch = b; seen_ticket = ticket; seen_status = status; trace_order = ++sequence; }
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,
    u64 ticket, int status, bool uncertain)
{ (void)b; (void)ticket; (void)status; (void)uncertain;
  published++; publish_order = ++sequence; }
'''

SUFFIX = r'''
int main(int argc, char **argv)
{
    struct xdev_ext_mech_batch b = { .bytes = 4096 };
    struct xdev_ext_stor_completion done = { .b = &b, .ticket = 918 };
    int bio;
    struct request req = { .end_io_data = &done, .bio = &bio, .bytes = 4096 };
    int mode = argc == 2 ? atoi(argv[1]) : -1;
    bp.bio = &bio;
    if (mode == 0) b.claim = -ESTALE;
    if (mode == 2) req.nvme.status = 129;
    if (mode == 3) req.nvme.flags = NVME_REQ_CANCELLED;
    nvme_xdev_ext_class_end_io(&req, 0);
    if (mode == 0) {
        if (traced || published) { fputs("stale completion emitted/published\n", stderr); return 1; }
        return 0;
    }
    if (traced != 1) { fputs("accepted native completion missing exactly-one trace\n", stderr); return 1; }
    if (published != 1 || !(trace_order < publish_order)) {
        fputs("native trace must precede publication/worker visibility\n", stderr); return 1;
    }
    if (seen_batch != &b || seen_ticket != 918 || seen_status != bp.cqe) {
        fputs("trace lost immutable identity or resolved native status\n", stderr); return 1;
    }
    if (mode == 2 && seen_status != 129) return 1;
    if (mode == 3 && seen_status != -EINTR) return 1;
    return 0;
}
'''


CURRENT_DEPENDENCIES = r'''
/* Linux/session and payload-copy boundaries only; all completion/ready
 * decisions below are extracted whole from their production owners. */
static unsigned ready_count, ready_order;
static bool ready_bad;
static struct xdev_ext_mech_batch *current_batch;
static int session_state;
static struct xdev_ext_mech_stage stage = {
    .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .s = &session_state
};
static struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(struct xdev_ext_mech_batch *b)
{ if (b != current_batch) ready_bad = true; return &stage; }
static int xdev_ext_mech_session_state(void *s)
{ if (s != stage.s) ready_bad = true; return *(int *)s; }
static void xdev_ext_storfam_bounce_copy(struct xdev_ext_mech_batch *b,
    struct xdev_ext_stor_batch *sb, bool to_pages)
{
    if (b != current_batch || sb != &bp.family || to_pages) ready_bad = true;
    ready_count++; ready_order = ++sequence;
}
'''


def current_fixture(member, runtime, block, runtime_header, block_header, core_header,
                    mech_uapi, binding_uapi):
    """Exercise the real delegated owners, keeping historical assertions intact."""
    end_io = function_body(member, 'nvme_xdev_ext_class_end_io')
    compact_end_io = re.sub(r'\s+', ' ', end_io)
    if compact_end_io.count(
            'xdev_ext_stor_done(req->end_io_data, blk_status_to_errno(err), req, '
            'nvme_xdev_ext_class_complete, xdev_ext_storfam_host_ready);') != 1:
        raise AssertionError('NVMe end_io must delegate its typed context and callbacks')

    # These checks supplement, and never replace, the original runtime contracts.
    post = function_body(member, 'nvme_xdev_ext_member_post')
    require_order(post, 'req->end_io = nvme_xdev_ext_class_end_io;',
                  'req->end_io_data = &io->done;',
                  'xdev_ext_stor_block_poll_arm(', 'blk_execute_rq_nowait(')
    fill = function_body(member, 'nvme_xdev_ext_stage_fill_cqe')
    require_order(fill, 'xdev_ext_storfam_consume(&p->family, b, &bp->family);',
                  'memcpy(cqe, &bp->cqe, sizeof(bp->cqe));')
    host_put = function_body(block, 'xdev_ext_storfam_host_put')
    if not re.search(r'if \(!slot \|\| slot->done\.uncertain\)\s*return;', host_put):
        raise AssertionError('UNKNOWN host slot must remain retained')
    require_order(host_put, 'if (!slot || slot->done.uncertain)',
                  'xdev_ext_stor_slot_put(&p->pool, &slot->runtime, false);')
    slot_put = function_body(runtime, 'xdev_ext_stor_slot_put')
    if not re.search(r'if \(uncertain\)\s*return;', slot_put):
        raise AssertionError('UNKNOWN common slot must remain retained')
    require_order(slot_put, 'if (uncertain)', 'xdev_ext_stor_slot_add(pool, slot);')
    consume = function_body(block, 'xdev_ext_storfam_consume')
    for release in ('xdev_ext_storfam_peer_put(ss, sb);',
                    'xdev_ext_storfam_host_put(ss, sb);'):
        if not re.search(
                r'if \(xdev_ext_mech_session_state\(ss->st->s\) != '
                r'XDEV_EXT_MECH_SESSION_ZOMBIE\)\s*' + re.escape(release), consume):
            raise AssertionError('ZOMBIE resources must remain retained: ' + release)
    ready = function_body(block, 'xdev_ext_storfam_host_ready')
    if not re.search(
            r'if \(!status && !uncertain && sb->bounce &&\s*'
            r'st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&\s*'
            r'xdev_ext_mech_session_state\(st->s\) != XDEV_EXT_MECH_SESSION_ZOMBIE\)\s*'
            r'xdev_ext_storfam_bounce_copy\(b, sb, false\);', ready):
        raise AssertionError('ready must exclude errors, UNKNOWN, and ZOMBIE')

    # Real common declarations preserve the embedded completion and family types.
    types = '\n'.join(struct_definition(runtime_header, name) for name in
                      ('xdev_ext_stor_slot', 'xdev_ext_stor_pool',
                       'xdev_ext_stor_completion'))
    types += '\n' + struct_definition(core_header, 'xdev_ext_stor_rw')
    types += '\n' + '\n'.join(struct_definition(block_header, name) for name in
                              ('xdev_ext_stor_command', 'xdev_ext_stor_batch'))
    if not re.search(r'^\s*struct xdev_ext_stor_completion done;',
                     struct_definition(block_header, 'xdev_ext_stor_io'), re.M):
        raise AssertionError('native I/O must embed the typed common completion')
    enums = '\n'.join((
        enum_definition(binding_uapi, 'xdev_ext_binding_direction'),
        enum_definition(mech_uapi, 'xdev_ext_mech_dir'),
        enum_definition(mech_uapi, 'xdev_ext_mech_session_state')))
    prefix = adapt_fixture(PREFIX, [
        ('#include <errno.h>', '#include <errno.h>\n#include <linux/types.h>\n'
         '#define __aligned(n) __attribute__((aligned(n)))\n'
         '#define XDEV_EXT_STOR_BOUNCE_AVAILABLE\n' + enums + '\n'
         'struct bio { int fixture; };\nstruct page;\nstruct xdev_ext_stor_io;\n'
         'struct xdev_ext_mech_stage { int direction; void *s; };'),
        ('struct xdev_ext_stor_completion {\n'
         '    struct xdev_ext_mech_batch *b; u64 ticket; bool uncertain; bool poll_live; unsigned poll_queue;\n'
         '};', types),
        ('struct nvme_xdev_ext_mech_batch { void *bio; int cqe; };',
         'struct nvme_xdev_ext_mech_batch { struct xdev_ext_stor_batch family; int cqe; };'),
    ])
    suffix = adapt_fixture(SUFFIX, [
        ('struct xdev_ext_stor_completion done = { .b = &b, .ticket = 918 };',
         'struct xdev_ext_stor_completion done = { .b = &b, .ticket = 918, .poll_live = true };'),
        ('    int bio;', '    struct bio bio;\n    struct page *bounce = NULL;'),
        ('    bp.bio = &bio;', '    bp.family.bio = &bio;\n'
         '    bp.family.bounce = &bounce;\n    current_batch = &b;'),
        ('    nvme_xdev_ext_class_end_io(&req, 0);',
         '    nvme_xdev_ext_class_end_io(&req, 0);\n'
         '    if (done.poll_live || ready_bad) return 1;\n'
         '    if (mode == 1) {\n'
         '        if (ready_count != 1 || !(trace_order < ready_order && ready_order < publish_order)) {\n'
         '            fputs("common ready must run between trace and publication\\n", stderr); return 1;\n'
         '        }\n'
         '    } else if (ready_count) return 1;'),
    ])
    bodies = function_body(runtime, 'xdev_ext_stor_done') + '\n' + ready
    for name in ('nvme_xdev_ext_class_complete', 'nvme_xdev_ext_class_end_io'):
        bodies += '\n' + function_body(member, name)
    return prefix + CURRENT_DEPENDENCIES + bodies + suffix


class NativeCompletionHook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='native-completion-contract-')
        cls.binary = Path(cls.tmp.name) / 'end_io'
        src = cls.binary.with_suffix('.c')
        member = SOURCE.read_text()
        runtime = (ROOT / 'kernel/io_uring/family/xdev_ext_storfam.c').read_text()
        batch = struct_definition(member, 'nvme_xdev_ext_mech_batch')
        if re.search(r'^\s*struct xdev_ext_stor_batch family;', batch, re.M):
            source = current_fixture(
                member, runtime,
                (ROOT / 'kernel/io_uring/family/xdev_ext_storfam_block.c').read_text(),
                (ROOT / 'kernel/include/linux/xdev_ext_storfam_runtime.h').read_text(),
                (ROOT / 'kernel/include/linux/xdev_ext_storfam_block.h').read_text(),
                (ROOT / 'kernel/include/linux/xdev_ext_storfam_core.h').read_text(),
                (ROOT / 'kernel/include/uapi/linux/xdev_ext_mech.h').read_text(),
                (ROOT / 'kernel/include/uapi/linux/xdev_ext_binding.h').read_text())
        else:
            # Matching historical member profile: preserve every original body
            # and raw fixture assertion, including the member-owned ready body.
            bodies = function_body(runtime, 'xdev_ext_stor_done')
            for name in ('nvme_xdev_ext_class_complete', 'nvme_xdev_ext_class_ready',
                         'nvme_xdev_ext_class_end_io'):
                bodies += '\n' + function_body(member, name)
            source = PREFIX + bodies + SUFFIX
        src.write_text(source)
        cc = shutil.which('cc')
        if not cc:
            raise RuntimeError('a real C compiler is required')
        built = subprocess.run([cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                str(src), '-o', str(cls.binary)], capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('production body did not compile: ' + built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, mode):
        result = subprocess.run([str(self.binary), str(mode)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_ticket_emits_no_native_completion(self):
        self.run_case(0)

    def test_accepted_completion_traced_before_worker_publication(self):
        self.run_case(1)

    def test_native_nvme_status_preserved(self):
        self.run_case(2)

    def test_cancelled_native_completion_is_error_not_success(self):
        self.run_case(3)


if __name__ == '__main__':
    unittest.main()
