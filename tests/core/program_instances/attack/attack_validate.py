#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent whole-disk oracle for the attacker/victim isolation test.

Inputs: the source disk image as written before boot, and the destination disk
image read back after the guest ran. Both are whole images; every byte is
checked.

The source image is position-unique: the 8-byte little-endian word at byte
offset o holds low32 = ((o / 512) << 7) | (((o % 512) / 8) << 1) | 1 and
high32 = a per-run seed. The oracle recovers the seed from word 0, regenerates
the whole expected source image from that formula and requires the given source
image to equal it, so a copy of bytes from any other source position, or in any
other order, cannot match.

Layout per case c (0..6, order below), in 64-LBA windows of 32 KiB:
  destination  A_c = 3c (attacker), V_c = 3c+1 (victim), S_c = 3c+2 (spare)
  source       victim reads window 2c, attacker reads window 2c+1
The OUTSIDE attackers are bound at A_c, so their refused SQEs (one window past
their own) target V_c. Expected destination: every V_c is an exact copy of its
victim's source window; every A_c is guard except the detach case's, which
holds exactly DETACH_DONE groups, each an exact copy of the attacker's source
group at the same slot, and guard elsewhere; all other bytes are guard.
Prints JSON; exit 0 only on PASS.
"""
import json
import struct
import sys

LBA = 512
GROUP = 4096
GROUPS = 8
WIN = GROUPS * GROUP
WIN_NLB = WIN // LBA                    # 64 LBAs
SPAN = 4 << 20
GUARD = 0x6B
DETACH_DONE = 2
CASES = ("reserved", "outside", "outside-after", "frame", "verdict", "user-stall", "detach")
DETACH = CASES.index("detach")


def regenerate_source(seed):
    out = bytearray(SPAN)
    for o in range(0, SPAN, 8):
        struct.pack_into("<II", out, o, ((o // LBA) << 7) | (((o % LBA) // 8) << 1) | 1, seed)
    return bytes(out)


def main(argv):
    if len(argv) != 3:
        print(json.dumps({"state": "SETUP_ERROR", "error": "usage: source.raw destination.raw"}))
        return 2
    with open(argv[1], "rb") as f:
        source = f.read()
    with open(argv[2], "rb") as f:
        dest = f.read()
    result = {"state": "ATTACK_ORACLE", "cases": list(CASES), "groups": GROUPS,
              "group_bytes": GROUP, "window_lbas": WIN_NLB, "detach_done": DETACH_DONE,
              "checked_bytes": len(dest)}

    def fail(state, reason):
        result.update(state=state, reason=reason)
        print(json.dumps(result))
        return 1 if state == "FAIL" else 2

    if len(source) != SPAN or len(dest) != SPAN:
        return fail("SETUP_ERROR", "images must be exactly %d bytes" % SPAN)
    seed = struct.unpack_from("<I", source, 4)[0]
    result["seed"] = "0x%08x" % seed
    if source != regenerate_source(seed):
        return fail("SETUP_ERROR", "source image does not follow the position-unique formula")

    expected = bytearray([GUARD]) * SPAN
    for c in range(len(CASES)):
        v, s = (3 * c + 1) * WIN, 2 * c * WIN
        expected[v:v + WIN] = source[s:s + WIN]

    detach_lo = 3 * DETACH * WIN
    detach_src = (2 * DETACH + 1) * WIN
    copied = []
    for g in range(GROUPS):
        got = dest[detach_lo + g * GROUP:detach_lo + (g + 1) * GROUP]
        own = source[detach_src + g * GROUP:detach_src + (g + 1) * GROUP]
        if got == own:
            copied.append(g)
            expected[detach_lo + g * GROUP:detach_lo + (g + 1) * GROUP] = own
        elif got != bytes([GUARD]) * GROUP:
            return fail("FAIL", "detach attacker group %d is neither guard nor its own source group" % g)
    result["detach_groups"] = copied
    if len(copied) != DETACH_DONE:
        return fail("FAIL", "detach attacker window holds %d groups, expected exactly %d" %
                    (len(copied), DETACH_DONE))

    if dest != bytes(expected):
        b = next(i for i in range(SPAN) if dest[i] != expected[i])
        window, c = b // WIN, b // WIN // 3
        role = ("attacker", "victim", "spare")[window % 3] if c < len(CASES) else "unused"
        where = "%s window of case %s" % (role, CASES[c]) if c < len(CASES) else "unused span"
        return fail("FAIL", "first mismatch at byte %d (LBA %d, %s): 0x%02x, expected 0x%02x" %
                    (b, b // LBA, where, dest[b], expected[b]))

    result["state"] = "PASS"
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
