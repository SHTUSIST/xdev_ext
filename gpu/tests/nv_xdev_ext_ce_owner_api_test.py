#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile-only ABSENCE gate for per-transfer frame ownership snapshots.

This is deliberately not labelled a behavioral RED: it compiles the actual
public transfer layout, and fails until owner/generation are distinct from
the callback ticket. Runtime ownership tests belong to the backend fixture.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex


class OwnerApi(unittest.TestCase):
    def test_each_xfer_carries_owner_and_generation(self):
        text = (ex.REPO / "kernel/include/linux/xdev_ext_mech.h").read_text()
        layout = ex.struct(text, "xdev_ext_ce_xfer")
        prototype = re.search(r"\bbool\s+xdev_ext_ce_owners_valid\s*\([^;]+;", text)
        build = ex.Build(".ce-owner-api-")
        try:
            src = build.write("owner-api.c", """
#include <stdint.h>
#include <stdbool.h>
typedef uint64_t u64;
typedef uint32_t u32;
struct xdev_ext_ce_cookie;
""" + layout + "\n" + (prototype.group() if prototype else "") + """
_Static_assert(__builtin_types_compatible_p(__typeof__(&xdev_ext_ce_owners_valid),
    bool (*)(struct xdev_ext_ce_cookie *, u64, const struct xdev_ext_ce_xfer *, u32)),
    "owner validation must include the immutable ticket and full transfer array");
/* Same-sized generations are required to preserve the full opaque token. */
_Static_assert(sizeof(((struct xdev_ext_ce_xfer *)0)->generation) == sizeof(u64),
               "per-transfer generation must be 64-bit");
static struct xdev_ext_ce_xfer records[2] = {
    { .host_byte_off = 0, .len = 4096, .owner = 1, .generation = 17 },
    { .host_byte_off = 4096, .len = 4096, .owner = 2, .generation = 99 },
};
int main(void) { return records[0].generation == records[1].generation; }
""")
            for cc in ex.compilers():
                with self.subTest(compiler=cc):
                    result, command = build.compile(src, "owner-api-" + Path(cc).name,
                                                    compiler=cc)
                    self.assertEqual(result.returncode, 0,
                        "ABSENCE (not semantic RED): per-xfer owner/generation API\n" +
                        " ".join(command) + "\n" + result.stderr)
        finally:
            build.cleanup()


if __name__ == "__main__":
    unittest.main(verbosity=2)
