#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host oracle for the undescribed-exporter guest test (prototype for ASK.70).

make-source writes the deterministic source image. validate checks one guest
run: the exact TAP id list for the mode, the plan line, the guest exit code,
the read/write observations, the boot mode (swiotlb=force or not, vIOMMU or
not), the whole destination image rebuilt from its own plan, and the kernel
console with the KVM harness's debug-report detector. Nothing is timed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "integration/session/native"))
from xdev_ext_mech_zc_debug import debug_reports  # noqa: E402

LBA = 512
PAGE = 4096
PAGES = 16
EXPORT = PAGE * PAGES
RANGE_A = 2048
RANGE_B = 4096
DISK = 8 << 20

COMMON_HEAD = ["open-control", "open-udmabuf", "open-source-namespace",
               "open-destination-namespace", "udmabuf-create", "bufinfo-exporter-udmabuf",
               "vmpin-baseline", "default-register-refused", "opt-in-alone-invalid",
               "reserved-bit-invalid", "refusals-charge-nothing", "undescribed-register",
               "allocation-fd-cloexec", "whole-export-charged", "duplicate-busy"]
COMMON_TAIL = ["allocation-close", "charge-returned", "buffer-released",
               "second-udmabuf-create", "second-register", "final-charge-baseline",
               "second-buffer-released"]
EXPECTED = {
    "normal": COMMON_HEAD + ["batch-read", "batch-read-bytes", "source-function-attached",
                             "batch-write", "one-attachment-per-function",
                             "exporter-fds-closed", "charge-kept-after-exporter-close",
                             "read-after-exporter-close", "write-after-exporter-close"]
    + COMMON_TAIL,
    "refuse": COMMON_HEAD + ["batch-read-refused", "region-untouched", "refused-before-attach",
                             "batch-write-refused", "still-no-attachment",
                             "exporter-fds-closed", "charge-kept-after-exporter-close"]
    + COMMON_TAIL,
}
# Exact native results of the two batches (status, completed).
BATCHES = {"normal": {"read": (0, PAGES), "write": (0, PAGES)},
           "refuse": {"read": (-18, 0), "write": (-18, 0)}}  # -EXDEV


# Byte j >= 8 of sector s is (s * 131 + j * 7 + 0x3d) & 0xff: one tail per
# value of (s * 131 + 0x3d) & 0xff.
_TAILS = [bytes((b + j * 7) & 0xff for j in range(8, LBA)) for b in range(256)]


def source_sector(sector):
    return sector.to_bytes(8, "little") + _TAILS[(sector * 131 + 0x3d) & 0xff]


def make_source():
    return b"".join(source_sector(s) for s in range(DISK // LBA))


def pattern():
    return bytes((((i * 29) + 0x5a) ^ (i >> 12)) & 0xff for i in range(EXPORT))


def expected_destination(mode, source):
    dest = bytearray(DISK)
    if mode == "normal":
        dest[RANGE_A * LBA:RANGE_A * LBA + EXPORT] = pattern()
        dest[RANGE_B * LBA:RANGE_B * LBA + EXPORT] = source[RANGE_B * LBA:RANGE_B * LBA + EXPORT]
    return bytes(dest)


def section(text, begin, end):
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ValueError("guest log must contain exactly one %s/%s pair" % (begin, end))
    return text.split(begin, 1)[1].split(end, 1)[0]


def check_tap(lines, mode):
    tap = [l for l in lines if re.match(r"^(not )?ok \d+ - ", l)]
    if any(l.startswith("not ok") for l in tap):
        raise ValueError("TAP failure: " + "; ".join(l for l in tap if l.startswith("not ok")))
    if any(re.search(r"#\s*(skip|todo)", l, re.I) for l in tap):
        raise ValueError("TAP skip/todo is not accepted")
    ids = []
    for number, line in enumerate(tap, 1):
        m = re.match(r"^ok (\d+) - (\S+)$", line)
        if not m or int(m.group(1)) != number:
            raise ValueError("TAP line out of sequence: " + line)
        ids.append(m.group(2))
    if ids != EXPECTED[mode]:
        raise ValueError("TAP ids differ from the %s plan: %s" % (mode, ids))
    plans = [l for l in lines if re.match(r"^1\.\.\d+$", l)]
    if plans != ["1..%d" % len(EXPECTED[mode])]:
        raise ValueError("TAP plan line mismatch: %s" % plans)
    results = [l for l in lines if l.startswith("RESULT ")]
    if results != ["RESULT mode=%s checks=%d PASS" % (mode, len(EXPECTED[mode]))]:
        raise ValueError("guest RESULT line mismatch: %s" % results)
    return ids


def check_batches(lines, mode):
    seen = {}
    for line in lines:
        m = re.match(r"^OBSERVE (read|write) status=(-?\d+) completed=(\d+)$", line)
        if m:
            if m.group(1) in seen:
                raise ValueError("duplicate %s observation" % m.group(1))
            seen[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    if seen != BATCHES[mode]:
        raise ValueError("batch observations %s != %s" % (seen, BATCHES[mode]))


def check_boot(lines, mode, viommu):
    cmdline = [l.split("=", 1)[1] for l in lines if l.startswith("XDEV_EXT_UNDESCRIBED_CMDLINE=")]
    if len(cmdline) != 1:
        raise ValueError("guest must report its kernel command line once")
    words = cmdline[0].split()
    if ("swiotlb=force" in words) != (mode == "refuse"):
        raise ValueError("swiotlb=force must be present exactly in refuse mode: " + cmdline[0])
    if ("intel_iommu=on" in words) != viommu:
        raise ValueError("intel_iommu=on must match the vIOMMU option: " + cmdline[0])
    groups = [l for l in lines if l.startswith("XDEV_EXT_UNDESCRIBED_IOMMU_GROUP ")]
    if len(groups) != 2:
        raise ValueError("guest must report the IOMMU group of both NVMe functions")
    grouped = [not l.endswith(" none") for l in groups]
    if viommu and not all(grouped):
        raise ValueError("vIOMMU run left an NVMe function outside an IOMMU group")
    if not viommu and any(grouped):
        raise ValueError("an NVMe function is in an IOMMU group without vIOMMU")


def validate(source, dest, log, mode, viommu=False):
    if mode not in EXPECTED:
        raise ValueError("unknown mode " + mode)
    text = log.read_text(errors="replace")
    guest = section(text, "XDEV_EXT_UNDESCRIBED_GUEST_BEGIN", "XDEV_EXT_UNDESCRIBED_GUEST_EXIT=")
    lines = [l.rstrip() for l in guest.splitlines()]
    exits = re.findall(r"XDEV_EXT_UNDESCRIBED_GUEST_EXIT=(\d+)", text)
    if exits != ["0"]:
        raise ValueError("guest exit code %s" % exits)
    ids = check_tap(lines, mode)
    check_batches(lines, mode)
    check_boot(lines, mode, viommu)
    src = source.read_bytes()
    if src != make_source():
        raise ValueError("source image was modified")
    want = expected_destination(mode, src)
    got = dest.read_bytes()
    if len(got) != len(want):
        raise ValueError("destination image size %d != %d" % (len(got), len(want)))
    if got != want:
        first = next(i for i in range(len(want)) if got[i] != want[i])
        raise ValueError("destination differs from plan at byte %d (LBA %d)" % (first, first // LBA))
    counts = debug_reports(text)
    if any(counts.values()):
        raise ValueError("kernel debug diagnostic: " + json.dumps(counts, sort_keys=True))
    return {"verdict": "PASS", "mode": mode, "viommu": viommu, "checks": len(ids),
            "destination_sha256": hashlib.sha256(got).hexdigest(), "console": counts}


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    make = sub.add_parser("make-source")
    make.add_argument("output", type=Path)
    check = sub.add_parser("validate")
    check.add_argument("--mode", required=True, choices=sorted(EXPECTED))
    check.add_argument("--viommu", action="store_true")
    for name in ("source", "dest", "log", "result"):
        check.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == "make-source":
        args.output.write_bytes(make_source())
        return 0
    try:
        record = validate(args.source, args.dest, args.log, args.mode, args.viommu)
    except ValueError as error:
        record = {"verdict": "FAIL", "mode": args.mode, "viommu": args.viommu, "reason": str(error)}
    args.result.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("XDEV_EXT_UNDESCRIBED_ORACLE=%s %s" % (record["verdict"], record.get("reason", "")))
    return 0 if record["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
