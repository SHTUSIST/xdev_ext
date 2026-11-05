#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent whole-disk oracle for the attacker/victim isolation test.

Given the source disk image (as written before boot) and the destination disk
image (read back after the guest ran), check that the victim window is an exact
copy of the source read window, that no byte outside the victim window changed
except the detach attacker window (which may hold completed source groups), and
therefore that no attacker byte reached the victim window. This repeats the
guest's own oracle with its own arithmetic. Prints JSON; exit 0 only on PASS.
"""
import json
import sys

LBA = 512
GROUP = 4096
GROUPS = 8
WIN_NLB = GROUPS * GROUP // LBA        # 64 LBAs
GUARD = 0x6b
SRC_SLBA = 0
VIC_SLBA = 1 * WIN_NLB
ATK6_SLBA = 6 * WIN_NLB
DISK_LBAS = 8 * WIN_NLB


def main(argv):
    if len(argv) != 3:
        print(json.dumps({"state": "SETUP_ERROR", "error": "usage: source.raw destination.raw"}))
        return 2
    source = open(argv[1], "rb").read()
    dest = open(argv[2], "rb").read()
    span = DISK_LBAS * LBA
    result = {"state": "ATTACK_ORACLE", "groups": GROUPS, "group_bytes": GROUP,
              "victim_slba": VIC_SLBA, "detach_slba": ATK6_SLBA}
    if len(source) < span or len(dest) < span:
        result.update(state="SETUP_ERROR", error="image shorter than checked span")
        print(json.dumps(result))
        return 2

    vic = VIC_SLBA * LBA
    src = SRC_SLBA * LBA
    for g in range(GROUPS):
        off = g * GROUP
        if dest[vic + off:vic + off + GROUP] != source[src + off:src + off + GROUP]:
            result.update(state="FAIL", reason="victim window group %d is not an exact source copy" % g)
            print(json.dumps(result))
            return 1

    detach_lo = ATK6_SLBA * LBA
    detach_hi = (ATK6_SLBA + WIN_NLB) * LBA
    vic_lo = VIC_SLBA * LBA
    vic_hi = (VIC_SLBA + WIN_NLB) * LBA
    for b in range(span):
        if vic_lo <= b < vic_hi:
            continue
        if detach_lo <= b < detach_hi:
            within = b - detach_lo
            if dest[b] == GUARD or dest[b] == source[SRC_SLBA * LBA + within]:
                continue
            result.update(state="FAIL", reason="detach window byte %d is neither guard nor its own source copy" % b)
            print(json.dumps(result))
            return 1
        if dest[b] != GUARD:
            result.update(state="FAIL", reason="byte %d outside the victim window changed to 0x%02x" % (b, dest[b]))
            print(json.dumps(result))
            return 1

    result["state"] = "PASS"
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
