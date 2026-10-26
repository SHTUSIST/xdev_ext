#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production xdev_ext_peer_lease_split() with a recording acquire stub.

The stub rejects spans crossing a selected provider page with -ERANGE or
injects a chosen acquire error. This proves prefix selection, retry limits,
argument forwarding and error propagation. No provider, GPU or DMA exists.
"""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
SRC = KERNEL / "io_uring/family/xdev_ext_requester.c"
if not SRC.exists():
    print("not ok 1 - io_uring/family/xdev_ext_requester.c missing")
    sys.exit(1)
text = SRC.read_text()
try:
    body = text[text.index("int xdev_ext_peer_lease_split("):
                text.index("EXPORT_SYMBOL_GPL(xdev_ext_peer_lease_split);")]
except ValueError as exc:
    print(f"not ok 1 - production requester split/export missing: {exc}")
    sys.exit(1)

SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define XDEV_EXT_PEER_HOST_TEST
#include "include/linux/xdev_ext_peer.h"
#include "include/linux/xdev_ext_requester_core.h"
struct file { int unused; }; struct pci_dev { int unused; };
static struct file authority;
static struct pci_dev requester;
static struct xdev_ext_peer_fd_lease lease;
static const u64 generation = UINT64_C(0x123456789abcdef0);
static const u64 ticket = UINT64_C(0x1122334455667788);
static u64 expected_off, provider_page;
static enum dma_data_direction expected_dir;
static unsigned int calls;
static u32 tried[64];
static int error_call, error_value;

/* Only the external provider acquire is replaced. In particular the split
 * and its shrink helper are the actual production implementation. */
int xdev_ext_peer_file_acquire(struct file *f, struct pci_dev *p, u64 g,
                              u64 off, u32 len, enum dma_data_direction dir,
                              struct xdev_ext_peer_fd_lease *out)
{
 assert(f == &authority && p == &requester && g == generation);
 assert(off == expected_off && dir == expected_dir && out == &lease);
 assert(calls < sizeof(tried) / sizeof(tried[0]));
 tried[calls++] = len;
 if (error_call < 0 || calls == (unsigned int)error_call) return error_value;
 /* Subtraction avoids an overflowing off + len in this independent stub. */
 if (len > provider_page - off % provider_page) return -ERANGE;
 out->lease.len = len;
 out->lease.dma_address = UINT64_C(0x10000000) + off;
 out->lease.ticket = ticket;
 out->file = f;
 return 0;
}

static void reset(u64 off, enum dma_data_direction dir, u64 page)
{
 memset(&lease, 0, sizeof(lease));
 memset(tried, 0, sizeof(tried));
 calls = 0; error_call = 0; error_value = 0;
 expected_off = off; expected_dir = dir; provider_page = page;
}

static void success(u32 len)
{
 assert(lease.lease.len == len);
 assert(lease.lease.dma_address == UINT64_C(0x10000000) + expected_off);
 assert(lease.lease.ticket == ticket && lease.file == &authority);
}
'''

MAIN = r'''
static int split(u32 len)
{
 return xdev_ext_peer_lease_split(&authority, &requester, generation,
                                expected_off, len, expected_dir, &lease);
}

int main(void)
{
 static const int errors[] = { -EINVAL, -ENOMEM, -EACCES, -ESTALE, -ENODEV };
 static const u32 retry[] = { 0x30000, 0x10000, 0x8000, 0x4000, 0x2000, 0x1000 };
 unsigned int i;

 reset(0xf000, DMA_TO_DEVICE, 65536);
 assert(split(0x3000) == 0);
 success(0x1000);
 assert(calls == 2 && tried[0] == 0x3000 && tried[1] == 0x1000);
 reset(0x10000, DMA_FROM_DEVICE, 65536);
 assert(split(0x10000) == 0);
 success(0x10000);
 assert(calls == 1 && tried[0] == 0x10000);
 reset(0x1f000, DMA_TO_DEVICE, 65536);
 assert(split(0x20000) == 0);
 success(0x1000);
 assert(calls == 2 && tried[0] == 0x20000 && tried[1] == 0x1000);
 puts("ok 1 - production split leases longest prefix inside a 64 KiB provider page");

 /* Already fitting sub-page spans must not be rounded or shortened. */
 reset(0x10001, DMA_BIDIRECTIONAL, 65536);
 assert(split(511) == 0);
 success(511);
 assert(calls == 1 && tried[0] == 511);
 /* Multiple refusals exercise the persistent descending page cursor. */
 reset(0x10000, DMA_FROM_DEVICE, 4096);
 assert(split(0x30000) == 0);
 success(0x1000);
 assert(calls == sizeof(retry) / sizeof(retry[0]));
 for (i = 0; i < calls; i++) assert(tried[i] == retry[i]);
 puts("ok 2 - production split preserves small spans and visits each shorter page boundary");

 /* Only ERANGE is a page-shape refusal; all other errors stop immediately,
  * both on the original attempt and after a genuine crossing refusal. */
 for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
  reset(0xf000, DMA_TO_DEVICE, 65536);
  error_call = 1; error_value = errors[i];
  assert(split(0x3000) == errors[i]);
  assert(calls == 1 && tried[0] == 0x3000 && !lease.file && !lease.lease.len);
  reset(0xf000, DMA_FROM_DEVICE, 65536);
  error_call = 2; error_value = errors[i];
  assert(split(0x3000) == errors[i]);
  assert(calls == 2 && tried[1] == 0x1000 && !lease.file && !lease.lease.len);
 }
 puts("ok 3 - production split propagates non-ERANGE errors without retrying them");

 reset(0, DMA_TO_DEVICE, 4096);
 error_call = -1; error_value = -ERANGE;
 assert(split(0x4000) == -ERANGE);
 assert(calls == 3 && tried[0] == 0x4000 && tried[1] == 0x2000 && tried[2] == 0x1000);
 assert(!lease.file && !lease.lease.len);
 reset(0, DMA_TO_DEVICE, 4096);
 error_call = -1; error_value = -ERANGE;
 assert(split(0x1000) == -ERANGE && calls == 1 && tried[0] == 0x1000);
 reset(0xfff, DMA_FROM_DEVICE, 4096);
 error_call = -1; error_value = -ERANGE;
 assert(split(2) == -ERANGE);
 assert(calls == 2 && tried[0] == 2 && tried[1] == 1);
 puts("ok 4 - repeated provider refusal terminates at the last 4 KiB page boundary");
 return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="requester-split-") as tmp:
    source = Path(tmp) / "t.c"
    binary = Path(tmp) / "t"
    source.write_text(SHIM + body + MAIN)
    compiler = shlex.split(os.environ.get("CC", "gcc"))
    subprocess.run(compiler + ["-std=gnu11", "-Wall", "-Wextra", "-Werror",
                               "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                               "-I" + str(KERNEL), str(source), "-o", str(binary)],
                   check=True, timeout=30)
    subprocess.run([str(binary)], check=True, timeout=10)
