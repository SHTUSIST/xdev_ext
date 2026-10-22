#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small integration guards; lifecycle behavior is in nv_xdev_ext_ce_async_test.c.

These guards intentionally scope native ASYNC to the new mechanism path. The
legacy synchronous ioctl remains supported and is not forbidden globally.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def code(path):
    text = (ROOT / path).read_text()
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def functions(source):
    """Find C function definitions, including the RM multiline signatures."""
    result = {}
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", source):
        name = match.group(1)
        if name in {"if", "for", "while", "switch"}:
            continue
        start = match.end() - 1
        depth = 1
        pos = start + 1
        while pos < len(source) and depth:
            depth += (source[pos] == "{") - (source[pos] == "}")
            pos += 1
        if depth == 0:
            result[name] = source[start:pos]
    return result


class AsyncNativeWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = code("kernel-open/nvidia/nv-xdev_ext-ce-backend.c")
        cls.backend_fns = functions(cls.backend)
        cls.rm = code("src/nvidia/src/kernel/mem_mgr/p2p_umem.c")
        cls.rm_fns = functions(cls.rm)

    def test_submit_uses_native_async_without_sync_request(self):
        body = self.backend_fns["nv_xdev_ext_ce_submit"]
        self.assertNotRegex(body, r"\bnv_p2p_vidmem_dma_request\s*\(",
                            "mechanism submit still blocks in synchronous RM request")
        self.assertRegex(body, r"\bnv_p2p_\w*(?:async|submit)\w*\s*\(",
                         "mechanism submit has no native asynchronous RM entry")

    def test_submit_has_no_request_allocation(self):
        self.assertNotRegex(self.backend_fns["nv_xdev_ext_ce_submit"],
                            r"\b(?:k[vz]?malloc(?:_array)?|kzalloc|kcalloc|vmalloc|"
                            r"nv_kmem_cache_alloc\w*)\s*\(",
                            "request storage must be preallocated during bind")

    def test_backend_reuses_tested_lifecycle_helper(self):
        self.assertIn('#include "nv-xdev_ext-ce-async.h"', self.backend)
        for operation in ("reserve", "submitted", "ready", "stop", "can_release"):
            with self.subTest(operation=operation):
                self.assertRegex(self.backend, rf"\bnv_xdev_ext_ce_async_{operation}\s*\(",
                                 "host tests must exercise the lifecycle actually used by backend")

    def test_persistent_host_handle_bound_once_outside_submit(self):
        bind = self.backend_fns["nv_xdev_ext_ce_bind_host"]
        submit = self.backend_fns["nv_xdev_ext_ce_submit"]
        calls = re.findall(r"\b(nv_p2p_\w*(?:host|umem)\w*bind)\s*\(", bind)
        calls = [name for name in calls if "unbind" not in name]
        self.assertEqual(len(calls), 1,
                         "bind_host must acquire one persistent RM host mapping")
        for name in calls:
            self.assertNotRegex(submit, rf"\b{re.escape(name)}\s*\(")

    def test_rm_calls_ceutils_async_without_rebuilding_host_memdesc(self):
        copies = [(name, body) for name, body in self.rm_fns.items()
                  if re.search(r"\bceutilsMemcopy\s*\(", body)]
        self.assertTrue(copies, "RM native ceutilsMemcopy ASYNC path is missing")
        for name, body in copies:
            with self.subTest(function=name):
                self.assertRegex(body, r"\bNV0050_CTRL_MEM(?:COPY|SET)_FLAGS_ASYNC\b")
                self.assertNotRegex(body, r"\b(?:memmgrMemCopy|_p2pCreateMemDesc|"
                                    r"memdescCreate|memdescDestroy|"
                                    r"channelWaitForFinishPayload)\s*\(",
                                    "native submit must reuse bound memdesc and return pending")


if __name__ == "__main__":
    unittest.main(verbosity=2)
