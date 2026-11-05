#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mutation tests for validate.py: a correct synthetic run must pass and each
single wrong fact must be rejected. Boots nothing."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate as v  # noqa: E402

SRC_PCI, DST_PCI = "0000:00:03.0", "0000:00:04.0"


def guest_lines(mode, viommu=False):
    cmd = "console=ttyS0 rdinit=/init" + (" swiotlb=force" if mode == "refuse" else "") + \
        (" intel_iommu=on iommu.strict=1" if viommu else "")
    group = "3" if viommu else "none"
    lines = ["XDEV_EXT_UNDESCRIBED_CMDLINE=" + cmd,
             "XDEV_EXT_UNDESCRIBED_IOMMU_GROUP %s %s" % (SRC_PCI, group),
             "XDEV_EXT_UNDESCRIBED_IOMMU_GROUP %s %s" % (DST_PCI, "4" if viommu else "none"),
             "PLAN mode=%s export=65536 pages=16 range_a=2048 range_b=4096" % mode]
    status = {"normal": 0, "refuse": -18}[mode]
    done = {"normal": 16, "refuse": 0}[mode]
    for number, ident in enumerate(v.EXPECTED[mode], 1):
        if ident in ("batch-read", "batch-read-refused"):
            lines.append("OBSERVE read status=%d completed=%d" % (status, done))
        if ident in ("batch-write", "batch-write-refused"):
            lines.append("OBSERVE write status=%d completed=%d" % (status, done))
        lines.append("ok %d - %s" % (number, ident))
    lines += ["1..%d" % len(v.EXPECTED[mode]),
              "RESULT mode=%s checks=%d PASS" % (mode, len(v.EXPECTED[mode]))]
    return lines


def log_text(lines, exit_code="0", dmesg="[    0.000000] Linux version"):
    return ("boot\nXDEV_EXT_UNDESCRIBED_GUEST_BEGIN\n" + "\n".join(lines) +
            "\nXDEV_EXT_UNDESCRIBED_GUEST_EXIT=%s\nXDEV_EXT_UNDESCRIBED_DMESG_BEGIN\n%s\n"
            "XDEV_EXT_UNDESCRIBED_DMESG_END\n" % (exit_code, dmesg))


class Oracle(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.source = self.root / "source.raw"
        self.source.write_bytes(v.make_source())

    def tearDown(self):
        self.dir.cleanup()

    def run_case(self, mode, lines=None, dest=None, viommu=False, **log):
        src = self.source.read_bytes()
        (self.root / "dest.raw").write_bytes(dest if dest is not None else
                                             v.expected_destination(mode, src))
        (self.root / "guest.log").write_text(log_text(lines if lines is not None else
                                                      guest_lines(mode, viommu), **log))
        return v.validate(self.source, self.root / "dest.raw", self.root / "guest.log",
                          mode, viommu)

    def rejects(self, mode, reason, **kw):
        with self.assertRaisesRegex(ValueError, reason):
            self.run_case(mode, **kw)

    def test_correct_runs_pass(self):
        for mode in ("normal", "refuse"):
            for viommu in (False, True):
                with self.subTest(mode=mode, viommu=viommu):
                    self.assertEqual(self.run_case(mode, viommu=viommu)["verdict"], "PASS")

    def test_not_ok_rejected(self):
        lines = guest_lines("normal")
        i = lines.index("ok 19 - batch-write")
        lines[i] = "not ok 19 - batch-write errno=5 (Input/output error)"
        self.rejects("normal", "TAP failure", lines=lines)

    def test_missing_or_extra_or_swapped_id_rejected(self):
        lines = [l for l in guest_lines("normal") if not l.endswith(" - batch-read-bytes")]
        self.rejects("normal", "out of sequence|ids differ", lines=lines)
        lines = guest_lines("normal")
        lines.insert(-2, "ok %d - extra" % (len(v.EXPECTED["normal"]) + 1))
        self.rejects("normal", "ids differ", lines=lines)
        # A refuse-mode TAP stream cannot certify a normal run.
        self.rejects("normal", "ids differ", lines=guest_lines("refuse"))

    def test_skip_and_sequence_and_plan_rejected(self):
        lines = guest_lines("normal")
        lines[5] = lines[5] + " # SKIP"
        self.rejects("normal", "skip", lines=lines)
        lines = [l.replace("ok 3 - ", "ok 30 - ") for l in guest_lines("normal")]
        self.rejects("normal", "out of sequence", lines=lines)
        lines = [l for l in guest_lines("normal") if not l.startswith("1..")]
        self.rejects("normal", "plan line", lines=lines)
        lines = [l.replace("PASS", "FAIL") if l.startswith("RESULT") else l for l in guest_lines("normal")]
        self.rejects("normal", "RESULT line", lines=lines)

    def test_guest_exit_rejected(self):
        self.rejects("normal", "guest exit code", exit_code="1")

    def test_batch_observation_rejected(self):
        lines = [l.replace("read status=0 completed=16", "read status=0 completed=15")
                 for l in guest_lines("normal")]
        self.rejects("normal", "batch observations", lines=lines)
        lines = [l.replace("write status=-18", "write status=-5") for l in guest_lines("refuse")]
        self.rejects("refuse", "batch observations", lines=lines)
        lines = guest_lines("normal")
        lines.insert(4, "OBSERVE read status=0 completed=16")
        self.rejects("normal", "duplicate read", lines=lines)

    def test_boot_mode_rejected(self):
        lines = [l.replace(" swiotlb=force", "") for l in guest_lines("refuse")]
        self.rejects("refuse", "swiotlb=force", lines=lines)
        lines = [l + " swiotlb=force" if l.startswith("XDEV_EXT_UNDESCRIBED_CMDLINE=") else l
                 for l in guest_lines("normal")]
        self.rejects("normal", "swiotlb=force", lines=lines)
        self.rejects("normal", "intel_iommu", lines=guest_lines("normal", viommu=False), viommu=True)
        lines = [l.replace(" 3", " none") if "IOMMU_GROUP" in l else l
                 for l in guest_lines("normal", viommu=True)]
        self.rejects("normal", "outside an IOMMU group", lines=lines, viommu=True)
        lines = [l.replace(" none", " 7", 1) if "IOMMU_GROUP" in l else l for l in guest_lines("normal")]
        self.rejects("normal", "without vIOMMU", lines=lines)

    def test_destination_rejected(self):
        src = self.source.read_bytes()
        good = v.expected_destination("normal", src)
        for offset in (v.RANGE_A * v.LBA + 4095, v.RANGE_B * v.LBA + v.EXPORT - 1, 0, v.DISK - 1):
            with self.subTest(offset=offset):
                bad = bytearray(good)
                bad[offset] ^= 0x01
                self.rejects("normal", "differs from plan", dest=bytes(bad))
        self.rejects("refuse", "differs from plan", dest=good)
        self.rejects("normal", "image size", dest=good[:-v.LBA])

    def test_modified_source_rejected(self):
        data = bytearray(self.source.read_bytes())
        data[v.RANGE_B * v.LBA] ^= 0xff
        self.source.write_bytes(bytes(data))
        self.rejects("normal", "source image was modified")

    def test_console_report_rejected(self):
        for report in ("BUG: KASAN: use-after-free in xdev_ext_dmabuf_map",
                       "WARNING: possible circular locking dependency detected",
                       "WARNING: CPU: 1 PID: 1 at drivers/dma-buf/dma-buf.c:1053"):
            with self.subTest(report=report):
                self.rejects("normal", "kernel debug diagnostic", dmesg=report)


if __name__ == "__main__":
    unittest.main()
