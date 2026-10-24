#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the production NVMe end_io body; this is not a DMA experiment.

Only Linux dependencies are supplied below. The completion decision and trace
placement come directly from xdev_ext_mech_nvme.c, never a copied model.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c'


def function_body(text, name):
    start = text.index('static enum rq_end_io_ret ' + name + '(')
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


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
struct xdev_ext_mech_batch { int claim; unsigned bytes; };
struct nvme_xdev_ext_mech_completion {
    struct xdev_ext_mech_batch *b; u64 ticket; bool uncertain;
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
    struct nvme_xdev_ext_mech_completion done = { .b = &b, .ticket = 918 };
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


class NativeCompletionHook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='native-completion-contract-')
        cls.binary = Path(cls.tmp.name) / 'end_io'
        src = cls.binary.with_suffix('.c')
        src.write_text(PREFIX + function_body(SOURCE.read_text(),
                       'nvme_xdev_ext_class_end_io') + SUFFIX)
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
