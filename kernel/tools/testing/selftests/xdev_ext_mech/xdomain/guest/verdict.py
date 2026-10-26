#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fail closed on the complete X7 software module/verifier record."""
import json
import re
import sys
from pathlib import Path

REQUIRED = frozenset(['module-load', 'reference-attach', 'link-1-enodev', 'link-0-einval', 'module-unload', 'rel-tx-state-nvme-deny', 'rel-tx-state-xdomain-allow', 'private-info-xdomain-build-deny', 'private-info-xdomain-prepare-deny', 'private-info-xdomain-complete-allow', 'private-info-nvme-complete-deny', 'private-info-net-complete-deny', 'private-info-af-xdp-complete-deny', 'private-info-socket-complete-deny', 'private-verdict-xdomain-build-deny', 'private-verdict-xdomain-prepare-deny', 'private-verdict-xdomain-complete-allow', 'private-verdict-nvme-complete-deny', 'private-verdict-net-complete-deny', 'private-verdict-af-xdp-complete-deny', 'private-verdict-socket-complete-deny', 'xdomain-complete-sleepable-deny', 'xdomain-complete-nonsleepable-allow', 'helper-map-lookup-allow', 'helper-timer-init-deny', 'helper-timer-start-deny', 'helper-tail-call-deny', 'helper-probe-read-kernel-deny', 'helper-probe-read-user-deny', 'helper-ringbuf-output-deny', 'helper-existing-class-control-allow', 'memory-ctx-write-deny', 'memory-oob-info-deny', 'memory-oob-verdict-deny', 'memory-uninit-info-deny', 'memory-uninit-verdict-deny', 'memory-readonly-map-info-deny', 'memory-readonly-map-verdict-deny', 'memory-initialized-local-info-allow', 'memory-initialized-local-verdict-allow'])
RECORD = re.compile(r"^XDEV_EXT_XDOMAIN_CASE=(PASS|FAIL) name=([a-z0-9-]+)$")
BAD = re.compile(r"(?:\bnot ok\b|\bskip(?:ped)?\b|WARNING:|BUG:|KASAN:|lockdep:|lockdep (?:warning|failure)|possible circular locking|XDOMAIN_SETUP_FAIL|XDEV_EXT_XDOMAIN_SETUP=FAIL|SETUP_FAILURE|failed to find valid kernel BTF|failed to open ELF object|clang: error:|modprobe: FATAL:|XDEV_EXT_XDOMAIN_GUEST_EXIT=[1-9]|Kernel panic)", re.I)


def validate(log: str) -> dict:
    if not isinstance(log, str) or BAD.search(log):
        raise ValueError("failed, skipped, setup or kernel diagnostic in guest log")
    seen = set()
    for line in log.splitlines():
        line = line.rstrip("\r")
        if "XDEV_EXT_XDOMAIN_CASE=" not in line:
            continue
        match = RECORD.fullmatch(line)
        if not match:
            raise ValueError("malformed case record")
        status, name = match.groups()
        if status != "PASS" or name not in REQUIRED or name in seen:
            raise ValueError("failed, unknown or duplicate case: " + name)
        seen.add(name)
    if seen != REQUIRED:
        raise ValueError("missing cases: " + ", ".join(sorted(REQUIRED - seen)))
    return {"status": "PASS", "cases": sorted(REQUIRED), "scope": "software-module-and-verifier"}


if __name__ == "__main__":
    try:
        result = validate(Path(sys.argv[1]).read_text(errors="replace"))
    except (ValueError, OSError) as error:
        print("XDEV_EXT_XDOMAIN_VERDICT=FAIL " + str(error), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))
