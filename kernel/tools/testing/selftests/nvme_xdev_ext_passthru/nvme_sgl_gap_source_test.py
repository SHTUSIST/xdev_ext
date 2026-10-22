#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Source contract for the NVMe SGL virt-boundary backport.

On SGL-capable NVMe PCI controllers the I/O queues report no virt boundary,
so the block layer no longer splits or bounce-copies gapped vectors.  Such a
request must then go out as SGL: PRP can describe only page-aligned gaps.
These checks pin both halves (upstream 2f6b2565d43c, bc840b21a25a and the
follow-ups fd9ecd005252 and 96c8ea3c5add) and the transports that keep the
4 KiB boundary.
"""

import os
import re
import sys
import unittest
from pathlib import Path


def find_root() -> Path:
    candidates = []
    if os.environ.get("NVME_XDEV_EXT_SOURCE_ROOT"):
        candidates.append(Path(os.environ["NVME_XDEV_EXT_SOURCE_ROOT"]))
    candidates.extend([Path.cwd(), *Path.cwd().parents])
    candidates.extend(Path(__file__).resolve().parents)
    for candidate in candidates:
        if (candidate / "drivers/nvme/host/pci.c").is_file() and \
                (candidate / "block/blk-merge.c").is_file():
            return candidate
    raise unittest.SkipTest("kernel source tree unavailable")


ROOT = None
NVME_CTRL_PAGE_SIZE = 4096


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class SourceTestCase(unittest.TestCase):
    def body(self, relative: str, signature: str) -> str:
        """Return the brace-delimited body that follows @signature."""
        text = read(relative)
        start = text.find(signature)
        if start < 0:
            self.fail(f"{relative}: '{signature}' not found")
        opening = text.find("{", start)
        depth = 0
        for offset in range(opening, len(text)):
            if text[offset] == "{":
                depth += 1
            elif text[offset] == "}":
                depth -= 1
                if depth == 0:
                    return text[opening + 1:offset]
        self.fail(f"{relative}: unterminated body after '{signature}'")

    def assertOrdered(self, text: str, needles, message: str):
        position = -1
        for needle in needles:
            found = text.find(needle, position + 1)
            if found < 0:
                self.fail(f"{message}: '{needle}' missing or out of order")
            position = found

    # The assert*() helpers of unittest print the whole searched text on
    # failure; these print only what was expected.
    def assertStatement(self, text: str, pattern: str, message: str = ""):
        if not re.search(pattern, text, re.M):
            self.fail(f"{message or 'missing statement'}: /{pattern}/")

    def assertBodyIs(self, body: str, expected: str, message: str = ""):
        """Compare a function body with @expected, whitespace-normalised."""
        actual = " ".join(body.split())
        if actual != expected:
            self.fail(f"{message or 'unexpected body'}: '{actual}' != '{expected}'")

    def assertHas(self, needle: str, text: str, message: str = ""):
        if needle not in text:
            self.fail(f"{message or 'missing'}: '{needle}'")

    def assertLacks(self, needle: str, text: str, message: str = ""):
        if needle in text:
            self.fail(f"{message or 'unexpected'}: '{needle}'")


def req_phys_gap_mask(gap_bit: int) -> int:
    """Model of req_phys_gap_mask() on a 64-bit unsigned long."""
    value = ((1 << gap_bit) >> 1) - 1
    return ~value & ((1 << 64) - 1)


def ffs(value: int) -> int:
    return (value & -value).bit_length()


def layout_gap_bit(segments) -> int:
    """bio_split_rw_at(): OR of every next start and previous end offset."""
    gaps = 0
    for previous, current in zip(segments, segments[1:]):
        gaps |= current[0] | (previous[0] + previous[1])
    return ffs(gaps)


class GapMaskModelTest(SourceTestCase):
    def test_pipeline_layout_forces_sgl_and_aligned_layout_does_not(self):
        # Six AF_XDP frames, data at byte 104 of each: 5 x 1432 + 1032.
        pipeline = [(104, 1432)] * 5 + [(104, 1032)]
        self.assertEqual(sum(length for _, length in pipeline), 8192)
        mask = req_phys_gap_mask(layout_gap_bit(pipeline))
        self.assertNotEqual(mask & (NVME_CTRL_PAGE_SIZE - 1), 0,
                            "pipeline gaps must force SGL")
        aligned = [(0, 4096), (0, 4096)]
        self.assertEqual(req_phys_gap_mask(layout_gap_bit(aligned)) &
                         (NVME_CTRL_PAGE_SIZE - 1), 0,
                         "page-aligned gaps must still allow PRP")
        self.assertEqual(req_phys_gap_mask(0), 0, "no gap gives an empty mask")
        for bit in range(1, 64):
            hits_page = req_phys_gap_mask(bit) & (NVME_CTRL_PAGE_SIZE - 1)
            self.assertEqual(bool(hits_page), bit <= 12,
                             f"gap bit {bit} classified wrongly")

    def test_mask_expression_matches_the_model(self):
        text = read("include/linux/blk-mq.h")
        self.assertStatement(
            text,
            r"static inline unsigned long req_phys_gap_mask\(const struct request \*req\)\s*\{\s*"
            r"return ~\(\(\(1 << req->phys_gap_bit\) >> 1\) - 1\);\s*\}",
            "req_phys_gap_mask() differs from the modelled expression")


class NvmeBoundaryTest(SourceTestCase):
    def test_core_takes_boundary_from_transport_hook(self):
        body = self.body("drivers/nvme/host/core.c",
                         "static void nvme_set_ctrl_limits(")
        self.assertHas("lim->virt_boundary_mask = "
                      "ctrl->ops->get_virt_boundary(ctrl, is_admin);", body)
        self.assertLacks("NVME_CTRL_PAGE_SIZE - 1", body)
        text = read("drivers/nvme/host/core.c")
        self.assertStatement(text, r"static void nvme_set_ctrl_limits\(struct nvme_ctrl \*ctrl,\s*"
                         r"struct queue_limits \*lim, bool is_admin\)")
        calls = re.findall(r"nvme_set_ctrl_limits\(([^;]*)\);", text)
        self.assertEqual(sorted(calls),
                         sorted(["ctrl, &lim, true",
                                 "ns->ctrl, &lim, false",
                                 "ns->ctrl, &lim, false"]),
                         "only the admin queue may pass is_admin=true")
        identify = self.body("drivers/nvme/host/core.c",
                             "static int nvme_init_identify(")
        self.assertOrdered(identify,
                           ["lim = queue_limits_start_update(ctrl->admin_q);",
                            "nvme_set_ctrl_limits(ctrl, &lim, true);",
                            "queue_limits_commit_update(ctrl->admin_q, &lim);"],
                           "admin limits are not the is_admin=true call")

    def test_ctrl_ops_declares_hook_with_page_mask_default(self):
        text = read("drivers/nvme/host/nvme.h")
        ops = self.body("drivers/nvme/host/nvme.h", "struct nvme_ctrl_ops {")
        self.assertStatement(ops, r"unsigned long \(\*get_virt_boundary\)\(struct nvme_ctrl \*ctrl,\s*bool is_admin\);")
        default = self.body("drivers/nvme/host/nvme.h",
                            "static inline unsigned long nvme_get_virt_boundary(")
        self.assertBodyIs(default, "return NVME_CTRL_PAGE_SIZE - 1;")
        self.assertLess(text.index("nvme_get_virt_boundary("),
                        text.index("struct nvme_ctrl_ops {"))
        fabrics = self.body("drivers/nvme/host/fabrics.h",
                            "static inline unsigned long nvmf_get_virt_boundary(")
        self.assertBodyIs(fabrics, "return 0;")

    def test_pci_reports_zero_only_for_sgl_capable_io_queues(self):
        body = self.body("drivers/nvme/host/pci.c",
                         "static unsigned long nvme_pci_get_virt_boundary(")
        self.assertBodyIs(
            body,
            "if (!nvme_ctrl_sgl_supported(ctrl) || is_admin) "
            "return NVME_CTRL_PAGE_SIZE - 1; return 0;",
            "PCI boundary must stay 4095 for admin and non-SGL controllers")

    def test_every_transport_registers_its_boundary(self):
        expected = {
            "drivers/nvme/host/pci.c": "nvme_pci_get_virt_boundary",
            "drivers/nvme/host/apple.c": "nvme_get_virt_boundary",
            "drivers/nvme/host/rdma.c": "nvme_get_virt_boundary",
            "drivers/nvme/target/loop.c": "nvme_get_virt_boundary",
            "drivers/nvme/host/tcp.c": "nvmf_get_virt_boundary",
            "drivers/nvme/host/fc.c": "nvmf_get_virt_boundary",
        }
        found = {}
        for path in sorted((ROOT / "drivers/nvme").rglob("*.c")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for match in re.finditer(
                    r"(?:static )?const struct nvme_ctrl_ops \w+ = \{(.*?)\n\};",
                    text, re.S):
                relative = str(path.relative_to(ROOT))
                hook = re.search(r"\.get_virt_boundary\s*=\s*(\w+),",
                                 match.group(1))
                self.assertIsNotNone(
                    hook, f"{relative}: nvme_ctrl_ops lacks .get_virt_boundary")
                found[relative] = hook.group(1)
        self.assertEqual(found, expected)


class NvmePciSglSelectionTest(SourceTestCase):
    def test_gapped_request_is_never_given_to_the_prp_builder(self):
        body = self.body("drivers/nvme/host/pci.c",
                         "static inline bool nvme_pci_use_sgls(")
        self.assertOrdered(
            body,
            ["if (!nvme_ctrl_sgl_supported(&dev->ctrl))",
             "return false;",
             "if (!nvmeq->qid)",
             "return false;",
             "if (req_phys_gap_mask(req) & (NVME_CTRL_PAGE_SIZE - 1))",
             "return true;",
             "if (!sgl_threshold || avg_seg_size < sgl_threshold)"],
            "a gapped request must select SGL before the PRP threshold")
        self.assertHas("return nvme_req(req)->flags & NVME_REQ_USERCMD;", body)
        mapping = self.body("drivers/nvme/host/pci.c",
                            "static blk_status_t nvme_map_data(")
        self.assertOrdered(
            mapping,
            ["if (!strict_sgl && blk_rq_nr_phys_segments(req) == 1) {",
             "nvme_setup_prp_simple(",
             "if (strict_sgl || nvme_pci_use_sgls(dev, req, iod->sgt.nents))",
             "ret = nvme_pci_setup_sgls(nvmeq, req, &cmnd->rw);",
             "ret = nvme_pci_setup_prps(nvmeq, req, &cmnd->rw);"],
            "only a single-segment request may skip nvme_pci_use_sgls()")


class BlockGapAccountingTest(SourceTestCase):
    def test_bio_and_request_carry_the_lowest_gap_bit(self):
        bio = self.body("include/linux/blk_types.h", "struct bio {")
        self.assertStatement(bio, r"\bu8\s+bi_bvec_gap_bit;")
        request = self.body("include/linux/blk-mq.h", "struct request {")
        self.assertStatement(request, r"\bunsigned char\s+phys_gap_bit;")
        self.assertStatement(read("include/linux/bio.h"),
                         r"u8 bio_seg_gap\(struct request_queue \*q, struct bio \*prev, "
                         r"struct bio \*next,\s*u8 gaps_bit\);")
        self.assertHas("bio->bi_bvec_gap_bit = 0;",
                      self.body("block/bio.c", "void bio_init(struct bio *bio,"))

    def test_split_check_accumulates_every_segment_gap(self):
        gap = self.body("block/blk-merge.c",
                        "static inline unsigned int bvec_seg_gap(")
        self.assertStatement(gap, r"return bv->bv_offset \| \(bvprv->bv_offset \+ bvprv->bv_len\);")
        body = self.body("block/blk-merge.c", "int bio_split_rw_at(")
        self.assertOrdered(body,
                           ["if (bvprvp) {",
                            "if (bvec_gap_to_prev(lim, bvprvp, bv.bv_offset))",
                            "goto split;",
                            "gaps |= bvec_seg_gap(bvprvp, &bv);",
                            "*segs = nsegs;",
                            "bio->bi_bvec_gap_bit = ffs(gaps);",
                            "return 0;",
                            "split:",
                            "bio_clear_polled(bio);",
                            "bio->bi_bvec_gap_bit = ffs(gaps);",
                            "return bytes >> SECTOR_SHIFT;"],
                           "both bio_split_rw_at() exits must record the gaps")

    def test_merges_combine_gaps_and_skip_dataless_bios(self):
        body = self.body("block/blk-merge.c", "u8 bio_seg_gap(")
        self.assertOrdered(body,
                           ["if (!bio_has_data(prev))",
                            "return 0;",
                            "gaps_bit = min_not_zero(gaps_bit, prev->bi_bvec_gap_bit);",
                            "gaps_bit = min_not_zero(gaps_bit, next->bi_bvec_gap_bit);",
                            "bio_get_last_bvec(prev, &pb);",
                            "bio_get_first_bvec(next, &nb);",
                            "if (!biovec_phys_mergeable(q, &pb, &nb))",
                            "gaps_bit = min_not_zero(gaps_bit, ffs(bvec_seg_gap(&pb, &nb)));",
                            "return gaps_bit;"],
                           "bio_seg_gap() does not combine gaps safely")
        merge = self.body("block/blk-merge.c",
                          "static struct request *attempt_merge(")
        self.assertOrdered(merge,
                           ["req->phys_gap_bit = bio_seg_gap(req->q, req->biotail, next->bio,",
                            "req->biotail->bi_next = next->bio;"],
                           "request merge loses gaps")
        back = self.body("block/blk-merge.c",
                         "enum bio_merge_status bio_attempt_back_merge(")
        self.assertOrdered(back,
                           ["req->phys_gap_bit = bio_seg_gap(req->q, req->biotail, bio,",
                            "req->biotail = bio;"],
                           "back merge loses gaps")
        front = self.body("block/blk-merge.c",
                          "static enum bio_merge_status bio_attempt_front_merge(")
        self.assertOrdered(front,
                           ["req->phys_gap_bit = bio_seg_gap(req->q, bio, req->bio,",
                            "req->bio = bio;"],
                           "front merge loses gaps")

    def test_every_request_source_initialises_the_gap_bit(self):
        append = self.body("block/blk-map.c", "int blk_rq_append_bio(")
        self.assertOrdered(append,
                           ["bio_split_rw_at(bio, lim, &nr_segs, max_bytes);",
                            "if (rq->bio) {",
                            "rq->phys_gap_bit = bio_seg_gap(rq->q, rq->biotail, bio,",
                            "rq->biotail = bio;",
                            "rq->phys_gap_bit = bio->bi_bvec_gap_bit;"],
                           "passthrough requests lose the gaps of their bios")
        self.assertHas("rq->phys_gap_bit = bio->bi_bvec_gap_bit;",
                      self.body("block/blk-mq.c",
                                "static void blk_mq_bio_to_request("))
        for signature in ("void blk_rq_init(struct request_queue *q, struct request *rq)",
                          "struct request *blk_mq_alloc_request(",
                          "struct request *blk_mq_alloc_request_hctx("):
            self.assertHas("rq->phys_gap_bit = 0;",
                          self.body("block/blk-mq.c", signature), signature)
        self.assertHas("rq->phys_gap_bit = rq_src->phys_gap_bit;",
                      self.body("block/blk-mq.c", "int blk_rq_prep_clone("))

    def test_clone_and_split_keep_the_front_gaps(self):
        clone = self.body("block/bio.c", "static int __bio_clone(")
        self.assertHas("bio->bi_bvec_gap_bit = bio_src->bi_bvec_gap_bit;", clone)
        split = self.body("block/bio.c", "struct bio *bio_split(")
        self.assertOrdered(split,
                           ["split = bio_alloc_clone(bio->bi_bdev, bio, gfp, bs);",
                            "bio_advance(bio, split->bi_iter.bi_size);",
                            "bio->bi_bvec_gap_bit = 0;"],
                           "the split-off front bio must keep its gaps")
        submit = self.body("block/blk-merge.c",
                           "static struct bio *bio_submit_split(")
        self.assertOrdered(submit,
                           ["split = bio_split(bio, split_sectors,",
                            "return split;"],
                           "the front clone is no longer the request bio")

    def test_tree_has_no_iova_coalescing_path(self):
        # The 2f6b2565d43c blk-mq-dma.c hunk and a0750fae73c5 change the
        # 6.17 IOVA iterator.  This tree maps through scatterlists only; if
        # that iterator is ever backported, those hunks become mandatory.
        text = read("block/blk-mq-dma.c")
        for symbol in ("blk_can_dma_map_iova", "blk_dma_map_iter_start",
                       "dma_iova_try_alloc"):
            self.assertLacks(symbol, text)
        self.assertHas("int __blk_rq_map_sg(struct request *rq", text)


if __name__ == "__main__":
    try:
        ROOT = find_root()
    except unittest.SkipTest as skip:
        print(f"ok 1 - {skip} # SKIP")
        sys.exit(4)
    unittest.main(verbosity=2)
