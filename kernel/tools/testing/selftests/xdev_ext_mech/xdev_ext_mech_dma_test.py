#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the production DMA certification helper against model backends.

The function body is extracted unchanged from kernel/dma/mapping.c. Device
backend selection, SG traversal, DMA-to-physical translation and SWIOTLB
lookup use small deterministic fixtures. These tests exercise the helper's
decisions, not real DMA mappings, cache synchronization or hardware.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]


def production_helper(name="dma_sgtable_is_unbounced"):
    text = (ROOT / "kernel/dma/mapping.c").read_text()
    start = text.index("bool " + name + "(")
    brace = text.index("{", start)
    level = 1
    end = brace + 1
    while level:
        level += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


FIXTURES = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define PAGE_SIZE 4096U

struct dma_map_ops { unsigned int unused; };
typedef uintptr_t dma_addr_t;
typedef uintptr_t phys_addr_t;
struct page { phys_addr_t physical; };
struct iommu_domain { dma_addr_t iova; phys_addr_t physical; };
struct device {
    bool direct, arch_direct, iommu;
    uintptr_t dma_offset, bounce_start, bounce_end;
    dma_addr_t arch_page_end;
    struct iommu_domain *domain;
};
struct scatterlist { uintptr_t dma_address; bool bounced; };
struct sg_table { struct scatterlist *sgl; unsigned int nents, orig_nents; };

static inline const struct dma_map_ops *get_dma_ops(struct device *dev)
{
    (void)dev;
    return NULL;
}
static inline bool dma_map_direct(struct device *dev,
                                 const struct dma_map_ops *ops)
{
    (void)ops;
    return dev->direct;
}
static inline bool arch_dma_map_sg_direct(struct device *dev,
                                         struct scatterlist *sg,
                                         unsigned int nents)
{
    (void)sg;
    (void)nents;
    return dev->arch_direct;
}
static inline bool use_dma_iommu(struct device *dev) { return dev->iommu; }
static inline phys_addr_t page_to_phys(struct page *page) { return page->physical; }
static inline struct iommu_domain *iommu_get_domain_for_dev(struct device *dev)
{
    return dev->domain;
}
static inline phys_addr_t iommu_iova_to_phys(struct iommu_domain *domain,
                                            dma_addr_t addr)
{
    return domain->iova == addr ? domain->physical : 0;
}
static inline bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t addr)
{
    return dev->arch_direct && addr == dev->arch_page_end;
}
static inline bool sg_dma_is_swiotlb(struct scatterlist *sg)
{
    return sg->bounced;
}
static inline uintptr_t sg_dma_address(struct scatterlist *sg)
{
    return sg->dma_address;
}
static inline uintptr_t dma_to_phys(struct device *dev, uintptr_t addr)
{
    return addr - dev->dma_offset;
}
static inline void *swiotlb_find_pool(struct device *dev, uintptr_t addr)
{
    return addr >= dev->bounce_start && addr < dev->bounce_end ? dev : NULL;
}
#define for_each_sgtable_dma_sg(table, sg, i) \
    for ((i) = 0, (sg) = (table)->sgl; (i) < (table)->nents; ++(i), ++(sg))
"""


CASES = r"""
static unsigned int checks;
static int expect(const char *name, struct device dev,
                  struct scatterlist *sg, unsigned int nents,
                  unsigned int orig_nents, bool wanted)
{
    struct sg_table table = { sg, nents, orig_nents };
    bool actual = dma_sgtable_is_unbounced(&dev, &table);

    checks++;
    if (actual == wanted)
        return 0;
    fprintf(stderr, "%s: expected %d, got %d\n", name, wanted, actual);
    return 1;
}
int main(void)
{
    struct device direct = { .direct = true, .bounce_start = 0x8000,
                             .bounce_end = 0x9000 };
    struct device iommu = { .iommu = true, .bounce_start = 0x8000,
                            .bounce_end = 0x9000 };
    struct device arch_direct = direct;
    struct device translated = direct;
    struct device unknown = { 0 };
    struct scatterlist clean[] = { { 0x1000, false }, { 0x2000, false } };
    struct scatterlist second_bounce[] = {
        { 0x1000, false }, { 0x8100, false }
    };
    struct scatterlist flagged[] = { { 0x1000, true }, { 0x2000, false } };
    struct scatterlist translated_bounce[] = { { 0x18100, false } };
    struct scatterlist boundaries[] = { { 0x9000, false } };
    int failures = 0;

    arch_direct.direct = false;
    arch_direct.arch_direct = true;
    translated.dma_offset = 0x10000;
    failures += expect("empty", direct, NULL, 0, 0, false);
    failures += expect("direct clean", direct, clean, 2, 2, true);
    failures += expect("direct bounce second segment", direct,
                       second_bounce, 2, 2, false);
    failures += expect("arch direct clean", arch_direct, clean, 2, 2, true);
    failures += expect("arch direct bounce", arch_direct,
                       second_bounce, 2, 2, false);
    failures += expect("direct translated bounce", translated,
                       translated_bounce, 1, 1, false);
    failures += expect("bounce pool end exclusive", direct,
                       boundaries, 1, 1, true);
    failures += expect("direct flagged", direct, flagged, 2, 2, false);
    failures += expect("iommu clean coalesced", iommu, clean, 1, 2, true);
    failures += expect("iommu flagged", iommu, flagged, 2, 2, false);
    /* IOVAs resembling a physical pool address are not physical addresses. */
    failures += expect("iommu address not physical", iommu,
                       second_bounce, 2, 2, true);
    failures += expect("unknown backend", unknown, clean, 2, 2, false);
    if (failures)
        return 1;
    printf("DMA helper: %u model backend checks passed\n", checks);
    return 0;
}
"""


PAGE_CASES = r"""
static unsigned int checks;
static int expect(const char *name, struct device dev, struct page *page,
                  dma_addr_t address, bool wanted)
{
    bool actual = dma_single_page_is_unbounced(&dev, page, address);

    checks++;
    if (actual == wanted)
        return 0;
    fprintf(stderr, "%s: expected %d, got %d\n", name, wanted, actual);
    return 1;
}
int main(void)
{
    struct page original = { .physical = 0x12000 };
    struct iommu_domain domain = { .iova = 0xa0000, .physical = 0x12000 };
    struct device direct = { .direct = true, .dma_offset = 0x100000 };
    struct device arch_direct = { .arch_direct = true, .dma_offset = 0x100000,
                                  .arch_page_end = 0x113000 };
    struct device iommu = { .iommu = true, .domain = &domain };
    struct device missing_domain = { .iommu = true };
    struct device unknown = { 0 };
    int failures = 0;

    failures += expect("page direct translated clean", direct,
                       &original, 0x112000, true);
    failures += expect("page direct translated bounce", direct,
                       &original, 0x113000, false);
    failures += expect("page arch direct mapped endpoint", arch_direct,
                       &original, 0x112000, true);
    arch_direct.arch_page_end = 0x114000;
    failures += expect("page arch direct translated bounce", arch_direct,
                       &original, 0x113000, false);
    failures += expect("page iommu original mapping", iommu,
                       &original, 0xa0000, true);
    domain.physical = 0x13000;
    failures += expect("page iommu bounce mapping", iommu,
                       &original, 0xa0000, false);
    domain.physical = 0x12000;
    failures += expect("page iommu unmapped address", iommu,
                       &original, 0xb0000, false);
    failures += expect("page iommu missing domain", missing_domain,
                       &original, 0xa0000, false);
    failures += expect("page unknown backend", unknown,
                       &original, original.physical, false);
    if (failures)
        return 1;
    printf("DMA page helper: %u model backend checks passed\n", checks);
    return 0;
}
"""


class DmaHelperTest(unittest.TestCase):
    def compile_and_run(self, helper, cases=CASES):
        with tempfile.TemporaryDirectory(prefix="xdev_ext-mech-dma-") as directory:
            source = Path(directory) / "dma_test.c"
            executable = Path(directory) / "dma_test"
            # Each helper uses a different subset of OS boundary functions.
            # Omit only unused fixture definitions; keep the production helper
            # and strict compiler diagnostics unchanged.
            fixtures = FIXTURES
            for match in reversed(list(re.finditer(
                    r"^static inline [^;{}]*?\b(\w+)\([^;{}]*\)\s*\{", fixtures, re.M))):
                if re.search(r"\b" + match[1] + r"\b", helper + cases):
                    continue
                depth, end = 1, match.end()
                while depth:
                    depth += (fixtures[end] == "{") - (fixtures[end] == "}")
                    end += 1
                fixtures = fixtures[:match.start()] + fixtures[end:]
            source.write_text(fixtures + "\n" + helper + "\n" + cases)
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                str(source), "-o", str(executable),
            ]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            return subprocess.run([str(executable)], capture_output=True, text=True)

    def test_production_helper(self):
        result = self.compile_and_run(production_helper())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "DMA helper: 12 model backend checks passed\n")
        self.assertEqual(result.stderr, "")

    def test_production_single_page_helper(self):
        helper = production_helper("dma_single_page_is_unbounced")
        result = self.compile_and_run(helper, PAGE_CASES)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "DMA page helper: 9 model backend checks passed\n")
        self.assertEqual(result.stderr, "")

    def test_detects_removed_direct_bounce_check(self):
        # Mutate only the in-memory copy compiled into the temporary fixture.
        helper, count = re.subn(
            r"if \(swiotlb_find_pool\([^\n]+\)\)\s*return false;",
            "if (false) return false;", production_helper(),
        )
        self.assertEqual(count, 1, "production direct bounce check was not found")
        result = self.compile_and_run(helper)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("direct bounce second segment: expected 0, got 1", result.stderr)
        self.assertIn("arch direct bounce: expected 0, got 1", result.stderr)
        self.assertIn("direct translated bounce: expected 0, got 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
