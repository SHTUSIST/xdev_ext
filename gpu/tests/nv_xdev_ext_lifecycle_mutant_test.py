#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Behavioural mutants for the actual-body lifecycle harnesses.

Each mutant edits the production text in memory only (never on disk), rebuilds
the corresponding harness and requires a named behavioral assertion to FAIL.
Missing anchors, compiler failures, crashes and sanitizer aborts are errors,
not successful mutant kills. Re-anchor after production refactoring explicitly.
"""
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402
import nv_xdev_ext_ce_backend_harness_test as backend  # noqa: E402
import nv_xdev_ext_ce_rm_event_test as rm_event  # noqa: E402
import nv_xdev_ext_direct_dma_test as direct  # noqa: E402
import nv_xdev_ext_native_peer_cleanup_test as peer  # noqa: E402
import nv_xdev_ext_vidmem_owner_test as owner  # noqa: E402

# (name, harness class, source path, anchor, replacement, case, variant or None)
MUTANTS = [
    ("addition-based host bounds", direct.DirectDma, direct.P2P_UMEM,
     "pXfers[i].umemOffset > bufferSize ||\n            pXfers[i].size > bufferSize - pXfers[i].umemOffset",
     "pXfers[i].umemOffset + pXfers[i].size > bufferSize",
     "refuse-before-push", None),
    ("release host descriptor after entered-copy error", direct.DirectDma, direct.P2P_UMEM,
     "            if (status != NV_OK)\n                goto quarantine;",
     "            if (status != NV_OK) {\n                if (0) goto quarantine;\n                break;\n            }",
     "refusal-vs-entered-copy", None),
    ("bridge forgets ambiguity", direct.DirectDma, direct.OSAPI,
     "g_xdev_ext_ce_poisoned = NV_TRUE;", "(void)0;", "bridge-poison", None),
    ("bypass memdesc identity", owner.VidmemOwner, owner.P2P_C,
     "status != NV_OK || pMemory->pMemDesc != pBinding->pMemDesc",
     "status != NV_OK", "resolve", None),
    ("accept watermark above submitted", rm_event.RmEventHarness, rm_event.P2P_UMEM,
     "if (*watermark > h->pCeUtils->lastSubmittedPayload) {",
     "if (0) {", "progress-watermark", None),
    ("push before validating the plan", rm_event.RmEventHarness, rm_event.P2P_UMEM,
     "            return NV_ERR_INVALID_ARGUMENT;\n    }\n    for (i = 0; i < n; i++) {\n        CEUTILS_MEMCOPY_PARAMS",
     "            break;\n    }\n    for (i = 0; i < n; i++) {\n        CEUTILS_MEMCOPY_PARAMS",
     "plan-before-push", None),
    ("report an issued failure as pre-submit", backend.BackendHarness, backend.BACKEND,
     "status ? nv_p2p_umem_errno(status) : -EIO,\n                        NV_TRUE, 0);",
     "status ? nv_p2p_umem_errno(status) : -EIO,\n                        NV_FALSE, 0);",
     "ambiguous-submit", "poll+phys"),
    ("free host state with live slots", backend.BackendHarness, backend.BACKEND,
     "if (WARN_ON_ONCE(!nv_xdev_ext_ce_async_can_release(&h->pool))) {",
     "if (0) {", "unbind-pending", "poll+phys"),
    ("unmap without the OS page inflation", peer.NativePeerCleanup, peer.NV_P2P,
     "os_dma_addresses[index] = os_dma_addresses[index - 1] + PAGE_SIZE;",
     "os_dma_addresses[index] = os_dma_addresses[index - 1];",
     "unmap-success", None),
]


class LifecycleMutants(unittest.TestCase):
    def run_mutant(self, harness, path, anchor, replacement, case, variant):
        original = ex.read
        text = original(path)
        if anchor not in text:
            self.fail("anchor not present in current source; re-anchor this mutant")

        def mutated(rel):
            content = original(rel)
            return content.replace(anchor, replacement, 1) if rel == path else content

        ex.read = mutated
        try:
            harness.setUpClass()
            try:
                keys = [k for k in harness.binaries
                        if variant is None or (isinstance(k, tuple) and k[1] == variant)]
                self.assertTrue(keys, "mutant did not compile: %s" %
                                str(getattr(harness, "errors", None) or
                                    getattr(harness, "compile_errors", None))[:2000])
                for key in keys:
                    result = harness.build.run(harness.binaries[key], case, timeout=120)
                    self.assertEqual(result.returncode, 1,
                        f"mutant did not fail by a behavioral assertion: {case} ({key})\n"
                        f"{result.stdout}\n{result.stderr}")
                    self.assertIn("FAIL ", result.stdout,
                                  f"no behavioral oracle fired for {case} ({key})")
                    self.assertNotIn("ERROR: AddressSanitizer", result.stderr)
                    self.assertNotIn("runtime error:", result.stderr)
            finally:
                harness.tearDownClass()
        finally:
            ex.read = original


def make(name, *args):
    def test(self):
        self.run_mutant(*args)
    test.__doc__ = name
    return test


for index, (name, *args) in enumerate(MUTANTS):
    setattr(LifecycleMutants, "test_%02d_%s" % (index, name.replace(" ", "_").replace("-", "_")),
            make(name, *args))


if __name__ == "__main__":
    unittest.main(verbosity=2)
