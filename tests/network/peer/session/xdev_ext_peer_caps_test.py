#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""PEER-pool CREATE admission follows generic validity, then class capabilities.

Requirement P1: a device-memory pool admits any number of frames, a power-of-two
frame size in [4 KiB, 2 MiB], valid payload headroom and segment bounds, and any order of stages
whose class implements the peer contract in that stage's direction (NVMe read
and write, NET TX and RX; CE only if its table entry says so). Every other
class/direction in a valid topology fails CREATE with -EOPNOTSUPP.
Non-PEER pools keep the frozen 75b51c2 matrix except the explicit Track S
SOCKET RX admission changes below. In 75b51c2 socket bind accepted TO_DEVICE
only, so its pure CREATE successes for RX were never supported sessions.
S API 2.4 adds RX at stage 0 of at least two stages; other RX placements now
fail generic validation. The original golden is retained without regeneration.
"""
from pathlib import Path
import itertools
import os
import shlex
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[4]
BASE_REVISION = "75b51c2"
GOLDEN = Path(__file__).resolve().parent / "peer_caps_base.golden"
FILES = ("io_uring/xdev_ext_mech_step.h", "io_uring/xdev_ext_mech_core.h",
         "include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h",
         "include/uapi/linux/xdev_ext_binding.h")

DRIVER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
int main(int argc, char **argv)
{
 struct xdev_ext_mech_create c;
 __u32 frames = 0;
 int i, ret, fd_stage = -1, fd_value = 0;
 if (argc == 2 && !strcmp(argv[1], "table")) {
#ifdef XDEV_EXT_MECH_PEER_CAPS
  for (i = 0; i < 16; i++) printf("dirs %d %u\n", i, xdev_ext_mech_peer_dirs((__u32)i));
  return 0;
#else
  return 3;
#endif
 }
 /* Optional --fd stage value exercises argument-error precedence. */
 if (argc >= 4 && !strcmp(argv[1], "--fd")) {
  fd_stage = atoi(argv[2]); fd_value = atoi(argv[3]);
  argv += 3; argc -= 3;
 }
 /* argv: pool frame hdr seg group nr_stages (class dir)* */
 if (argc < 7) return 2;
 memset(&c, 0, sizeof(c));
 c.abi_version = XDEV_EXT_MECH_ABI_VERSION; c.pool_kind = (__u32)atoi(argv[1]);
 c.pool_fd = c.pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM ? -1 : 7;
 c.layout.frame_size = (__u32)strtoul(argv[2], NULL, 0); c.layout.hdr_room = (__u32)strtoul(argv[3], NULL, 0);
 c.layout.seg_len = (__u32)strtoul(argv[4], NULL, 0); c.layout.group_bytes = (__u32)strtoul(argv[5], NULL, 0);
 c.depth = 2; c.eventfd = -1; c.nr_stages = (__u32)atoi(argv[6]);
 if (argc != 7 + 2 * (int)c.nr_stages) return 2;
 for (i = 0; i < (int)c.nr_stages; i++) {
  c.st[i].class_id = (__u32)atoi(argv[7 + 2 * i]); c.st[i].direction = (__u32)atoi(argv[8 + 2 * i]);
  c.st[i].fd = 8 + i;
  /* Plain SOCKET bind requires flags/arg0/arg1 zero. */
  c.st[i].arg1 = c.st[i].class_id == XDEV_EXT_MECH_CLASS_SOCKET ? 0 : 128;
#ifdef XDEV_EXT_USER_F_STRICT_ASYNC
  if (c.st[i].class_id == XDEV_EXT_MECH_CLASS_USER) {
   c.st[i].flags = XDEV_EXT_USER_F_STRICT_ASYNC;
   c.st[i].arg0 = 1000; c.st[i].arg1 = 0;
  }
#endif
 }
 if (fd_stage >= 0 && fd_stage < (int)c.nr_stages) c.st[fd_stage].fd = fd_value;
 ret = xdev_ext_mech_create_check(&c, &frames);
 printf("%d %u\n", ret, ret ? 0U : frames);
 return 0;
}
'''

AFXDP, NVME, IAA, CE, DMA, SOCKET, NET, USER = 2, 3, 4, 5, 6, 7, 8, 10
NAMES = {AFXDP: "AF_XDP", NVME: "NVMe", IAA: "IAA", CE: "CE", DMA: "DMA", SOCKET: "SOCKET", NET: "NET", USER: "USER"}
TO, FROM = 1, 2
XSK, IOU, PEER = 1, 2, 3
PINNED_DIRS = {NVME: (1 << TO) | (1 << FROM), NET: (1 << TO) | (1 << FROM),
               AFXDP: 0, IAA: 0, DMA: 0, SOCKET: 0, USER: (1 << TO)}
EOPNOTSUPP, EINVAL, EBADF = -95, -22, -9

# Exact non-PEER exceptions to the old pure-check golden: SOCKET RX alone,
# or after one of these stages. Existing AF_XDP/NET pool refusals stay frozen.
# Two layouts yield 26 XSK + 22 IOU exceptions; all other 800 rows are unchanged.
SOCKET_RX_INVALID_NONPEER = {
    XSK: (((SOCKET, FROM),),) + tuple(((c, d), (SOCKET, FROM))
                                   for c in (AFXDP, NVME, IAA, CE, DMA, SOCKET)
                                   for d in (TO, FROM)),
    IOU: (((SOCKET, FROM),),) + tuple(((c, d), (SOCKET, FROM))
                                   for c in (NVME, IAA, CE, DMA, SOCKET)
                                   for d in (TO, FROM)),
}
# On PEER, these 15 invalid shapes fail generic admission before capabilities.
SOCKET_RX_INVALID_PEER = (((SOCKET, FROM),),) + tuple(
    ((c, d), (SOCKET, FROM)) for c in (AFXDP, NVME, IAA, CE, DMA, SOCKET, NET)
    for d in (TO, FROM))


def build(directory, include_root, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(DRIVER)
    result = subprocess.run(shlex.split(os.environ.get("CC", "cc")) +
                            ["-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                             "-I" + str(include_root), str(source), "-o", str(binary)],
                            capture_output=True, text=True)
    if result.returncode:
        raise SystemExit("not ok - admission driver does not compile against " + name + ":\n" + result.stderr)
    return binary


def run(binary, args, fd=None):
    options = [] if fd is None else ["--fd", *fd]
    out = subprocess.run([str(binary)] + [str(a) for a in options + args], capture_output=True, text=True, check=True)
    ret, frames = out.stdout.split()
    return int(ret), int(frames)


def base_headers(directory):
    root = directory / "base-headers"
    for filename in FILES:
        target = root / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(["git", "show", BASE_REVISION + ":./" + filename], cwd=KERNEL))
    return root


def layouts(pool):
    if pool == PEER:
        return [(65536, 0, 4096, 4096)]
    return [(4096, 0, 4096, 4096), (4096, 256, 2048, 8192)]


def stage_matrix():
    classes = [AFXDP, NVME, IAA, CE, DMA, SOCKET, NET]
    stages = [(c, d) for c in classes for d in (TO, FROM)]
    yield from ([s] for s in stages)
    yield from ([a, b] for a, b in itertools.product(stages, stages))
    yield [(NET, FROM), (NVME, TO), (NET, TO)]
    yield [(NVME, TO), (NET, FROM), (NVME, FROM), (NET, TO)]


def main():
    failures = []
    passed = 0
    with tempfile.TemporaryDirectory(prefix="peer-caps-") as tmp:
        directory = Path(tmp)
        new = build(directory, KERNEL, "current")
        if "--write-golden" in sys.argv:
            old = build(directory, base_headers(directory), "base")
            lines = []
            for pool in (XSK, IOU):
                for layout in layouts(pool):
                    for stages in stage_matrix():
                        args = [pool, *layout, len(stages)] + [x for s in stages for x in s]
                        lines.append(" ".join(map(str, args)) + " -> %d %d" % run(old, args))
            GOLDEN.write_text("\n".join(lines) + "\n")
            print("wrote %d 75b51c2 results to %s" % (len(lines), GOLDEN))
            return
        golden = dict(l.split(" -> ") for l in GOLDEN.read_text().splitlines())
        table = subprocess.run([str(new), "table"], capture_output=True, text=True)
        dirs = dict(PINNED_DIRS)
        if table.returncode:
            failures.append("PEER capability table xdev_ext_mech_peer_dirs()/XDEV_EXT_MECH_PEER_CAPS missing")
            ce_dirs = None
        else:
            reported = {int(l.split()[1]): int(l.split()[2]) for l in table.stdout.splitlines()}
            for cls, want in PINNED_DIRS.items():
                if reported[cls] != want:
                    failures.append("capability table %s=%#x, want %#x" % (NAMES[cls], reported[cls], want))
            for cls in (0, 1, 9, 15):
                if reported[cls]:
                    failures.append("capability table names unknown class %d" % cls)
            ce_dirs = reported[CE]
            if ce_dirs not in (0, (1 << TO) | (1 << FROM)):
                failures.append("CE peer directions must be none or both, got %#x" % ce_dirs)
            dirs[CE] = ce_dirs

        # 1. Non-PEER: frozen golden except exactly 48 newly invalid RX shapes.
        overridden = 0
        for pool in (XSK, IOU):
            for layout in layouts(pool):
                for stages in stage_matrix():
                    args = [pool, *layout, len(stages)] + [x for s in stages for x in s]
                    a = run(new, args)
                    b = tuple(int(x) for x in golden[" ".join(map(str, args))].split())
                    want = b
                    if tuple(stages) in SOCKET_RX_INVALID_NONPEER[pool]:
                        overridden += 1
                        if b != (0, layout[3] // layout[2]):
                            failures.append("SOCKET RX exception does not name an old pure-check success: " + str(args))
                        want = (EINVAL, 0)
                    if a != want:
                        failures.append("pool %d %s: now %s, want %s (75b51c2 %s)" % (pool, stages, a, want, b))
                    else:
                        passed += 1
        if overridden != 48:
            failures.append("SOCKET RX exception set changed: %d rows, want 48" % overridden)

        # 2. PEER: generic topology validity precedes the per-class capability table.
        for stages in stage_matrix():
            args = [PEER, 65536, 0, 4096, 4096, len(stages)] + [x for s in stages for x in s]
            got = run(new, args)
            if any(c == CE for c, _ in stages) and ce_dirs is None:
                continue
            ok = all(dirs[c] & (1 << d) for c, d in stages)
            want = (0, 1) if ok else (EOPNOTSUPP, 0)
            if tuple(stages) in SOCKET_RX_INVALID_PEER:
                want = (EINVAL, 0)
            label = " -> ".join("%s %s" % (NAMES[c], "TX/write" if d == TO else "RX/read") for c, d in stages)
            if got != want:
                failures.append("PEER %s: got %s, want %s" % (label, got, want))
            else:
                passed += 1

        # 3. Geometry: power-of-two frames in [4 KiB, 2 MiB], several frames
        # per group, and payload headroom subject to the generic frame bounds.
        chain = [NVME, FROM, NVME, TO]
        geometry = [
            ((4096, 0, 4096, 4096), (0, 1)), ((8192, 0, 8192, 8192), (0, 1)),
            ((65536, 0, 65536, 1 << 20), (0, 16)), ((65536, 0, 4096, 8192), (0, 2)),
            ((1 << 20, 0, 1 << 20, 1 << 20), (0, 1)), ((2 << 20, 0, 2 << 20, 4 << 20), (0, 2)),
            ((65536, 0, 65536, 32 * 65536), (0, 32)),
            ((2048, 0, 2048, 2048), (EOPNOTSUPP, 0)), ((12288, 0, 4096, 4096), (EOPNOTSUPP, 0)),
            ((65535, 0, 4096, 4096), (EOPNOTSUPP, 0)), ((4 << 20, 0, 4096, 4096), (EOPNOTSUPP, 0)),
            ((65536, 16, 4096, 4096), (0, 1)),
            # Ordered-frame payload offset is intentional: two 3072-byte
            # segments at offset 512 fit inside separate 4096-byte frames.
            ((4096, 512, 3072, 6144), (0, 2)),
            ((4096, 512, 3584, 7168), (0, 2)),
            ((4096, 512, 3072, 4608), (0, 2)),
            ((4096, 4096, 1, 1), (EINVAL, 0)),
            ((4096, 8192, 1, 1), (EINVAL, 0)),
            ((4096, 512, 3585, 7170), (EINVAL, 0)),
            ((4096, 0xffffffff, 1, 1), (EINVAL, 0)),
            ((65536, 0, 65536, 33 * 65536), (-7, 0)),
        ]
        for layout, want in geometry:
            got = run(new, [PEER, *layout, 2] + chain)
            if got != want:
                failures.append("PEER layout frame=%d hdr=%d seg=%d group=%d: got %s, want %s" % (layout + (got, want)))
            else:
                passed += 1

        # Exercise the actual ordered USER -> NVMe shape as well as the
        # device-to-device chain. USER is fixed-length STRICT_ASYNC here.
        for layout, want in (
                ((4096, 512, 3072, 6144), (0, 2)),
                ((4096, 4096, 1, 1), (EINVAL, 0)),
                ((4096, 512, 3585, 7170), (EINVAL, 0))):
            got = run(new, [PEER, *layout, 2, USER, TO, NVME, TO])
            if got != want:
                failures.append("PEER ordered USER -> NVMe layout %s: got %s, want %s" % (layout, got, want))
            else:
                passed += 1

        # 4. Real legal RX/consumer topologies still pass host-pool admission;
        # PEER refuses their host-page class with EOPNOTSUPP, not EINVAL.
        for stages in ([(SOCKET, FROM), (NVME, TO)],
                       [(SOCKET, FROM), (CE, TO)],
                       [(SOCKET, FROM), (SOCKET, TO)]):
            for pool in (XSK, IOU, PEER):
                for layout in layouts(pool):
                    got = run(new, [pool, *layout, len(stages)] + [x for s in stages for x in s])
                    want = (EOPNOTSUPP, 0) if pool == PEER else (0, layout[3] // layout[2])
                    if got != want:
                        failures.append("legal socket RX chain pool %d %s: got %s, want %s" % (pool, stages, got, want))
                    else:
                        passed += 1

        # 5. Argument errors stay -EINVAL / -EBADF, never masked as a capability refusal.
        for stages, want, label in (([(1, TO), (NVME, TO)], EINVAL, "unknown class id 1"),
                                    ([(0, TO), (NVME, TO)], EINVAL, "class id 0"),
                                    ([(NVME, 3), (NVME, TO)], EINVAL, "direction 3"),
                                    ([(NVME, 0), (NVME, TO)], EINVAL, "direction 0")):
            got = run(new, [PEER, 65536, 0, 4096, 4096, 2] + [x for s in stages for x in s])
            if got[0] != want:
                failures.append("PEER %s: got %d, want %d" % (label, got[0], want))
            else:
                passed += 1

        for stages, fd, want, label in (
                ([(SOCKET, FROM), (NVME, TO)], (0, -1), EBADF, "legal RX bad fd before capability"),
                ([(SOCKET, FROM)], (0, -1), EBADF, "bad fd before RX-only topology"),
                ([(NVME, TO), (SOCKET, FROM)], (1, -1), EBADF, "bad fd before late RX topology"),
                ([(SOCKET, FROM), (NVME, TO)], (1, -1), EBADF, "later bad fd before unsupported socket class"),
                ([(SOCKET, FROM), (1, TO)], None, EINVAL, "later unknown class before capability"),
                ([(SOCKET, FROM), (NVME, 3)], None, EINVAL, "later invalid direction before capability"),
                ([(SOCKET, 3), (NVME, TO)], (0, -1), EINVAL, "invalid direction before bad fd"),
                ([(1, TO), (NVME, TO)], (0, -1), EINVAL, "unknown class before bad fd")):
            args = [PEER, 65536, 0, 4096, 4096, len(stages)] + [x for s in stages for x in s]
            got = run(new, args, fd=fd)
            if got != (want, 0):
                failures.append("PEER %s: got %s, want %s" % (label, got, (want, 0)))
            else:
                passed += 1

    step = (KERNEL / "io_uring/xdev_ext_mech_step.h").read_text()
    body = step[step.index("static inline int xdev_ext_mech_create_check("):step.index("static inline int xdev_ext_mech_start_check(")]
    for pinned in ("c->st[0].class_id != XDEV_EXT_MECH_CLASS_NVME", "c->layout.frame_size != 65536", "nr != 1"):
        if pinned in body:
            failures.append("create_check still pins the chain shape: " + pinned)
        else:
            passed += 1

    for failure in failures:
        print("not ok - " + failure)
    print("# peer capability admission: %d passed, %d failed" % (passed, len(failures)))
    if failures:
        sys.exit(1)
    print("ok 1 - PEER generic validation precedes capabilities; 800 non-PEER golden rows unchanged, 48 explicit SOCKET RX refusals")


if __name__ == "__main__":
    main()
