#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""F7: preserve SOCKET admission while using the network-family cover rule.

Requirement: exact ordered one-descriptor-per-frame plans retain their original
pool spans; malformed coverage remains -EINVAL and existing size/bounds rules
stay effective. The source contract separately requires actual family delegation
and INBAND/no-reliable-state registration. Draft: activate only after F6 acceptance.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get("XDEV_EXT_KERNEL_ROOT", Path(__file__).resolve().parents[5]))


def uncomment(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def block(text, pattern, terminator=""):
    match = re.search(pattern, text, re.M)
    if not match:
        raise AssertionError("missing production declaration: " + pattern)
    start = text.index("{", match.start())
    depth, end = 1, start + 1
    while depth and end < len(text):
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    if depth:
        raise AssertionError("unterminated production declaration")
    return text[match.start():end] + terminator


def function(text, name):
    return block(text, r"^static\s+(?:int|void)\s+" + name + r"\s*\(")


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "include/linux/xdev_ext_netfam_core.h"
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
struct kvec { void *iov_base; size_t iov_len; };
struct xdev_ext_mech_frame {
    void *kaddr;
    u64 umem_addr;
    u32 index, data_off, data_len;
};
struct xdev_ext_mech_pool { u32 frame_size, nr_frames; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; void *priv; };
struct xdev_ext_mech_batch {
    u32 nr, bytes, slot;
    u64 id;
    struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
    int fail_frame;
    u32 calls, seen[XDEV_EXT_MECH_MAX_FRAMES];
    bool out_of_bounds;
};
static struct xdev_ext_mech_pool *
xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static u32 xdev_ext_mech_batch_slot(struct xdev_ext_mech_batch *b) { return b->slot; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { return b->nr; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { return b->bytes; }
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b) { return b->id; }
/* Record and enforce the external frame lookup boundary; validation is real. */
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b, u32 i,
                                   struct xdev_ext_mech_frame *out)
{
    b->calls++;
    if (i >= b->nr || i >= XDEV_EXT_MECH_MAX_FRAMES ||
        b->calls > 2 * XDEV_EXT_MECH_MAX_FRAMES) {
        b->out_of_bounds = true;
        return -ERANGE;
    }
    b->seen[i]++;
    if ((int)i == b->fail_frame)
        return -EIO;
    *out = b->f[i];
    return 0;
}
'''

CASES = r'''
struct fixture {
    struct xdev_ext_mech_session session;
    struct xdev_ext_mech_stage stage;
    struct xdev_ext_mech_batch batch;
    struct xdev_ext_socket_stage socket;
    struct xdev_ext_socket_request request[2];
    struct xdev_ext_socket_send_desc desc[XDEV_EXT_MECH_MAX_FRAMES];
    u8 payload[XDEV_EXT_MECH_MAX_FRAMES][256];
};
static const char *current_case;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "FAIL case=%s line=%d: %s\n", current_case, __LINE__, #c); \
    return 1; } } while (0)

static void init(struct fixture *t, u32 nr)
{
    memset(t, 0, sizeof(*t));
    t->session.pool = (struct xdev_ext_mech_pool){256, XDEV_EXT_MECH_MAX_FRAMES};
    t->stage.s = &t->session;
    t->stage.priv = &t->socket;
    t->socket.request = t->request;
    t->socket.depth = 2;
    t->batch.nr = nr;
    t->batch.id = 91;
    t->batch.fail_frame = -1;
    for (u32 i = 0; i < nr; i++) {
        /* Deliberately distinct offsets, lengths, and pool indices. */
        u32 off = 7 + i, len = 40 + i;
        memset(t->payload[i], 0xa5, sizeof(t->payload[i]));
        t->batch.f[i] = (struct xdev_ext_mech_frame){
            .kaddr = t->payload[i], .umem_addr = (u64)(31 - i) * 256,
            .index = 31 - i, .data_off = off, .data_len = len,
        };
        t->desc[i] = (struct xdev_ext_socket_send_desc){i, off, len, 0};
        t->batch.bytes += len;
    }
}

static int expect(struct fixture *t, u32 n, int want)
{
    u8 snapshot[sizeof(t->payload)];
    memcpy(snapshot, t->payload, sizeof(snapshot));
    int got = xdev_ext_socket_validate(&t->stage, &t->batch,
                                      (const u8 *)t->desc, n);
    if (got != want)
        fprintf(stderr, "case=%s got=%d want=%d\n", current_case, got, want);
    CHECK(got == want);
    CHECK(!t->batch.out_of_bounds);
    CHECK(t->batch.calls <= 2 * XDEV_EXT_MECH_MAX_FRAMES);
    CHECK(!memcmp(snapshot, t->payload, sizeof(snapshot)));
    if (!want) {
        struct xdev_ext_socket_request *r = &t->request[t->batch.slot];
        CHECK(r->nr == n && r->bytes == t->batch.bytes);
        CHECK(r->batch_id == t->batch.id);
        for (u32 i = 0; i < n; i++) {
            const struct xdev_ext_mech_frame *f = &t->batch.f[i];
            CHECK(t->batch.seen[i] >= 1);
            CHECK(r->vec[i].iov_base == (u8 *)f->kaddr + f->data_off);
            CHECK(r->vec[i].iov_len == f->data_len);
            CHECK(r->frame[i].kaddr == f->kaddr);
            CHECK(r->frame[i].umem_addr == f->umem_addr);
            CHECK(r->frame[i].index == f->index);
            CHECK(r->frame[i].data_off == f->data_off);
            CHECK(r->frame[i].data_len == f->data_len);
        }
    }
    return 0;
}

static int run_case(const char *name)
{
    struct fixture t;
    u32 n = 2;
    int want = -EINVAL;
    current_case = name;
    init(&t, n);
    if (!strcmp(name, "exact")) want = 0;
    else if (!strcmp(name, "swapped")) {
        t.desc[0].frame_pos = 1; t.desc[1].frame_pos = 0;
    } else if (!strcmp(name, "short")) t.desc[1].len--;
    else if (!strcmp(name, "flags")) t.desc[0].flags = 1;
    else if (!strcmp(name, "wrong_offset")) t.desc[0].frame_off++;
    else if (!strcmp(name, "long")) t.desc[0].len++;
    else if (!strcmp(name, "missing_frame")) t.batch.fail_frame = 1;
    else if (!strcmp(name, "null_kaddr")) t.batch.f[1].kaddr = NULL;
    else if (!strcmp(name, "pool_index")) t.batch.f[1].index = 32;
    else if (!strcmp(name, "zero_span")) {
        t.batch.f[1].data_len = 0; t.desc[1].len = 0;
    } else if (!strcmp(name, "pool_offset")) {
        t.batch.f[0].data_off = 257; t.desc[0].frame_off = 257;
    } else if (!strcmp(name, "pool_end")) {
        t.batch.f[1].data_off = 250; t.desc[1].frame_off = 250;
    } else if (!strcmp(name, "batch_sum")) t.batch.bytes++;
    else if (!strcmp(name, "empty_batch")) {
        t.batch.bytes = 0; want = -EMSGSIZE;
    } else if (!strcmp(name, "plain_datagram_limit")) {
        t.batch.bytes = 65508; want = -EMSGSIZE;
    } else if (!strcmp(name, "invalid_slot")) t.batch.slot = 2;
    else if (!strcmp(name, "zero_count")) n = 0;
    else if (!strcmp(name, "too_many")) n = 33;
    else if (!strcmp(name, "count_mismatch")) n = 1;
    else if (!strcmp(name, "maximum_frames")) {
        n = XDEV_EXT_MECH_MAX_FRAMES; init(&t, n); want = 0;
    } else if (!strcmp(name, "second_slot")) {
        t.batch.slot = 1; want = 0;
    } else if (!strcmp(name, "same_batch_cursor")) {
        t.request[0].batch_id = 91; t.request[0].cursor = 3;
        CHECK(!expect(&t, n, 0)); CHECK(t.request[0].cursor == 3); return 0;
    } else if (!strcmp(name, "new_batch_cursor")) {
        t.request[0].batch_id = 90; t.request[0].cursor = 3;
        CHECK(!expect(&t, n, 0)); CHECK(t.request[0].cursor == 0); return 0;
    } else return 2;
    CHECK(!expect(&t, n, want));
    if (!strcmp(name, "invalid_slot") || !strcmp(name, "zero_count") ||
        !strcmp(name, "too_many") || !strcmp(name, "count_mismatch") ||
        !strcmp(name, "empty_batch") || !strcmp(name, "plain_datagram_limit"))
        CHECK(t.batch.calls == 0);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int result = run_case(argv[1]);
    if (!result) printf("PASS socket family case=%s\n", argv[1]);
    return result;
}
'''

REQUIRED_CASES = ("exact", "swapped", "short", "flags")
EDGE_CASES = ("wrong_offset", "long", "missing_frame", "null_kaddr", "pool_index",
              "zero_span", "pool_offset", "pool_end", "batch_sum", "empty_batch",
              "plain_datagram_limit", "invalid_slot", "zero_count", "too_many",
              "count_mismatch", "maximum_frames", "second_slot",
              "same_batch_cursor", "new_batch_cursor")


def declarations(text):
    return "\n".join(block(text, r"^struct " + name + r"\s*\{", ";") for name in
                     ("xdev_ext_socket_request", "xdev_ext_socket_stage"))


def fixture_source(text):
    # Optional before activation: baseline runtime stays executable, source
    # contract supplies the intended RED. Never substitute a fake family helper.
    adapter = ""
    if re.search(r"^struct xdev_ext_socket_cover\s*\{", text, re.M):
        adapter += block(text, r"^struct xdev_ext_socket_cover\s*\{", ";") + "\n"
    if re.search(r"^static\s+void\s+xdev_ext_socket_span\s*\(", text, re.M):
        adapter += function(text, "xdev_ext_socket_span") + "\n"
    return PRELUDE + declarations(text) + adapter + function(
        text, "xdev_ext_socket_validate") + CASES


class SocketFamily(unittest.TestCase):
    def test_existing_socket_admission_and_original_pool_vectors(self):
        text = (ROOT / "io_uring/xdev_ext_mech_socket.c").read_text()
        with tempfile.TemporaryDirectory(prefix="socket-family-") as tmp:
            source, binary = Path(tmp) / "actual.c", Path(tmp) / "actual"
            source.write_text(fixture_source(text))
            build = subprocess.run([os.environ.get("CC", "gcc"), "-std=gnu11", "-O1",
                                    "-Wall", "-Wextra", "-Werror",
                                    "-fsanitize=undefined", "-fno-sanitize-recover=all",
                                    "-I" + str(ROOT), str(source), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            for case in REQUIRED_CASES + EDGE_CASES:
                with self.subTest(case=case):
                    run = subprocess.run([str(binary), case], capture_output=True,
                                         text=True, timeout=10)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn("PASS socket family case=" + case, run.stdout)

    def test_actual_socket_delegates_coverage_and_registers_family(self):
        text = uncomment((ROOT / "io_uring/xdev_ext_mech_socket.c").read_text())
        validate = function(text, "xdev_ext_socket_validate")
        self.assertRegex(validate, r"\bxdev_ext_net_cover_check\s*\(",
                         "F7 missing actual SOCKET coverage delegation")
        table = block(text, r"^static const struct xdev_ext_mech_class_ops\s+"
                      r"xdev_ext_socket_class\s*=\s*\{")
        self.assertRegex(table, r"\.fam\.net\s*=\s*&xdev_ext_socket_net_hooks\b")
        hooks = block(text, r"^static const struct xdev_ext_net_hooks\s+"
                      r"xdev_ext_socket_net_hooks\s*=\s*\{")
        self.assertRegex(hooks, r"\.family\s*=\s*XDEV_EXT_FAMILY_NETWORK\b")
        self.assertRegex(hooks, r"\.hdr_policy\s*=\s*XDEV_EXT_NET_HDR_INBAND\b")
        rel = re.search(r"\.rel\s*=\s*([^,}\n]+)", hooks)
        if rel:
            self.assertIn(rel[1].strip(), ("NULL", "0"), "SOCKET must have no reliable view")


if __name__ == "__main__":
    unittest.main(verbosity=2)
