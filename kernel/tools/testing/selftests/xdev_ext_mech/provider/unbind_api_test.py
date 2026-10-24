#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Typecheck and execute CPU fixture teardown through the production callback ABI."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("KERNEL_SRC", HERE.parents[4]))


def function(text, name):
    match = re.search(r"^static [^;{}]*\b" + name + r"\([^;{}]*\)\s*\{", text, re.M)
    if not match:
        raise AssertionError("missing fixture callback " + name)
    depth = 1
    end = match.end()
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end]


class UnbindABI(unittest.TestCase):
    def test_checked_cpu_cleanup(self):
        abi = (ROOT / "include/linux/xdev_ext_mech.h").read_text()
        ops = re.search(r"^struct xdev_ext_dma_provider_ops \{\n.*?^\};", abi, re.M | re.S)[0]
        source = function((HERE / "xdev_ext_dma_provider_sim.c").read_text(), "sim_unbind_host")
        native = function((HERE / "faults/provider_fault_fixture.c").read_text(), "native_unbind_host")
        code = r"""
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
typedef uint64_t u64;
typedef uint32_t u32;
struct module; struct file_operations; struct file; struct page;
struct xdev_ext_dma_region; struct xdev_ext_dma_xfer; struct xdev_ext_dma_cookie;
/* OPS */
static unsigned unlocked, unmapped, freed, host_unbinds;
static void *expected_map;
static void mutex_lock(unsigned *lock) { assert(!*lock); *lock = 1; }
static void mutex_unlock(unsigned *lock) { assert(*lock); *lock = 0; unlocked++; }
static void vunmap(void *addr) { assert(addr == expected_map); unmapped++; }
static void kfree(void *ptr) { assert(unmapped == 1); freed++; free(ptr); }
struct sim_device { unsigned lock; struct { unsigned host_unbinds; } stats; };
struct sim_host { void *addr; u64 bytes; struct sim_device *dev; };
/* SIM */
/* NATIVE */
int main(void) {
 struct sim_device device = {0};
 struct sim_host *host = malloc(sizeof(*host));
 assert(host); expected_map = &device;
 *host = (struct sim_host){ .addr = expected_map, .dev = &device };
 const struct xdev_ext_dma_provider_ops sim = { .unbind_host = sim_unbind_host };
 assert(sim.unbind_host(host) == 0);
 assert(device.stats.host_unbinds == 1 && unlocked == 1 && unmapped == 1 && freed == 1);
 const struct xdev_ext_dma_provider_ops native = { .unbind_host = native_unbind_host };
 void *allocation = malloc(8); assert(allocation);
 assert(native.unbind_host(allocation) == 0 && host_unbinds == 1);
 return 0;
}
""".replace("/* OPS */", ops).replace("/* SIM */", source).replace("/* NATIVE */", native)
        with tempfile.TemporaryDirectory(prefix="xdev-ext-provider-unbind-") as temporary:
            path = Path(temporary)
            (path / "test.c").write_text(code)
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                str(path / "test.c"), "-o", str(path / "test")]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            run = subprocess.run([str(path / "test")], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
