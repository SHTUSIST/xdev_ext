#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source guards for the two compile-time variants (G1, G2 keep-old-code rule).

Resolves only the #if/#ifdef blocks that test NV_XDEV_EXT_CE_POLL_COMPLETION or
NV_XDEV_EXT_CE_PHYS_ADDR (every other directive is kept as written) and checks:
the default text has no hrtimer poller and no CPU physical address handed to
the copy engine; the opt-in text still contains the previous implementation.
Behaviour of both variants is exercised by nv_xdev_ext_ce_backend_harness_test.py
and nv_xdev_ext_host_region_dma_test.py; this file only pins the variant split.
"""
from pathlib import Path
import re
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import nv_xdev_ext_extract as ex  # noqa: E402

POLL = "NV_XDEV_EXT_CE_POLL_COMPLETION"
PHYS = "NV_XDEV_EXT_CE_PHYS_ADDR"
BACKEND = "kernel-open/nvidia/nv-xdev_ext-ce-backend.c"
NV_P2P = "kernel-open/nvidia/nv-p2p.c"
NV_C = "kernel-open/nvidia/nv.c"


def strip_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: "\n" * m.group().count("\n"), text,
                  flags=re.S)


def _condition(directive, rest, macro):
    """True/False when the condition is exactly about macro, else None."""
    rest = rest.strip()
    if directive == "ifdef":
        return True if rest == macro else None
    if directive == "ifndef":
        return False if rest == macro else None
    if directive == "if":
        if re.fullmatch(r"defined\s*\(?\s*%s\s*\)?" % macro, rest) or rest == macro:
            return True
        if re.fullmatch(r"!\s*defined\s*\(?\s*%s\s*\)?" % macro, rest) or rest == "!" + macro:
            return False
    return None


def resolve(text, macro, defined):
    """Keep the branch selected by macro's state for blocks that test only it."""
    out, stack = [], []   # stack entries: (kind, keep_this_branch, decided)
    for line in strip_comments(text).splitlines():
        m = re.match(r"\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", line)
        active = all(keep for _, keep, _ in stack)
        if m:
            directive, rest = m.group(1), m.group(2)
            if directive in ("ifdef", "ifndef", "if"):
                cond = _condition(directive, rest, macro)
                if cond is None:
                    stack.append(("other", True, False))
                    out.append(line)
                else:
                    keep = cond if defined else not cond
                    stack.append(("ours", keep, keep))
                continue
            if not stack:
                out.append(line)
                continue
            kind, keep, decided = stack[-1]
            if kind == "other":
                out.append(line)
                if directive == "endif":
                    stack.pop()
                continue
            if directive == "else":
                stack[-1] = (kind, not decided, True)
            elif directive == "elif":
                stack[-1] = (kind, False, True)   # not used for these macros
            elif directive == "endif":
                stack.pop()
            continue
        if active:
            out.append(line)
    return "\n".join(out)


def case_block(text, label):
    start = text.index(label)
    end = text.index("case NV_ESC_", start + len(label))
    return text[start:end]


class VariantSplit(unittest.TestCase):
    def absent(self, pattern, text, message):
        hits = [line.strip() for line in text.splitlines() if re.search(pattern, line)]
        if hits:
            self.fail(f"{message}: {len(hits)} line(s), first: {hits[0]!r}")

    def present(self, pattern, text, message):
        if not re.search(pattern, text):
            self.fail(message)

    @classmethod
    def setUpClass(cls):
        cls.backend = ex.read(BACKEND)
        cls.p2p = ex.read(NV_P2P)
        cls.nvc = ex.read(NV_C)

    def test_g1_default_backend_has_no_hrtimer_poller(self):
        default = resolve(self.backend, POLL, False)
        self.absent(r"\bhrtimer\w*\b", default,
                    "G1: the default build still contains the hrtimer poller")
        self.present(re.escape(POLL), self.backend,
                     "G1: the previous poller must stay under #ifdef " + POLL)

    def test_g1_poll_variant_keeps_previous_implementation(self):
        poll = resolve(self.backend, POLL, True)
        for token in ("nv_xdev_ext_ce_poll_timer", "hrtimer_start", "hrtimer_cancel",
                      "nv_p2p_ce_progress"):
            with self.subTest(token=token):
                self.present(re.escape(token), poll, "G1: poll variant lost " + token)

    def test_g2_default_backend_passes_no_cpu_physical_address(self):
        default = resolve(self.backend, PHYS, False)
        self.absent(r"\bpage_to_phys\(", default,
                    "G2: default backend still hands page_to_phys() to the CE")
        self.absent(r"\bnv_p2p_umem_iommu_untranslated\(", default,
                    "G2: default backend still refuses translating IOMMU domains")
        self.present(r"\bdma_map_sgtable\s*\(", default, "G2: no DMA-API mapping")
        self.present(r"\bdma_unmap_sgtable\s*\(", default, "G2: no DMA-API unmapping")

    def test_g2_phys_variant_keeps_identity_gate(self):
        phys = resolve(self.backend, PHYS, True)
        self.present(r"\bpage_to_phys\(", phys, "G2: PHYS variant lost page_to_phys")
        self.present(r"\bnv_p2p_umem_iommu_untranslated\(", phys,
                     "G2: PHYS variant lost its identity gate")
        self.present(re.escape(PHYS), self.backend,
                     "G2: identity-only path must stay under #ifdef " + PHYS)

    def test_g2_nv_p2p_sites_feeding_the_ce_are_variant_gated(self):
        default = resolve(self.p2p, PHYS, False)
        phys = resolve(self.p2p, PHYS, True)
        self.absent(r"\bpage_to_phys\(", default,
                    "G2: nv-p2p.c default build still stores page_to_phys() addresses "
                    "for CE consumers")
        self.assertGreaterEqual(phys.count("page_to_phys("), 3,
                                "G2: the three previous page_to_phys sites must be kept "
                                "under #ifdef " + PHYS)

    def test_g2_pin_ioctl_maps_for_the_opened_gpu(self):
        label = "case NV_ESC_P2P_PIN_UMEM:"
        default = case_block(resolve(self.nvc, PHYS, False), label)
        phys = case_block(resolve(self.nvc, PHYS, True), label)
        self.absent(r"\bnv_p2p_umem_iommu_untranslated\(", default,
                    "G2: default pin ioctl still refuses translating IOMMU domains")
        self.present(r"\bnv_host_region_dma_map\s*\(\s*handle\s*,\s*nvl->dev\s*\)",
                     default, "G2: pin ioctl does not map the region for the opened GPU")
        self.present(r"\bnv_p2p_umem_iommu_untranslated\(", phys,
                     "G2: PHYS build lost its identity gate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
