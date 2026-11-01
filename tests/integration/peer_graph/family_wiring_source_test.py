#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source-only contract checks. These do not prove registration behavior.

The behavioral companion family/class_register_test.py executes registration.
"""
from pathlib import Path
import argparse
import re
import subprocess
import sys

KERNEL = Path(__file__).resolve().parents[5]

# Stage implementations and family runtimes only: vendor providers and native
# driver backends legitimately implement pin/map and include vendor headers.
BOUNDARY_GLOBS = (
    "src/compute/io_uring/**/*.[ch]",
    "src/network/io_uring/**/*.[ch]",
    "src/network/net/xdp/xsk_xdev_ext_mech*.[ch]",
    "src/storage/io_uring/**/*.[ch]",
    "src/storage/drivers/nvme/host/xdev_ext_mech_nvme*.[ch]",
    "src/core/io_uring/xdev_ext_mech_dma*.[ch]",
    "src/core/io_uring/xdev_ext_mech_user*.[ch]",
)
BOUNDARY_ANCHORS = (
    "src/compute/io_uring/xdev_ext_mech_ce.c",
    "src/compute/io_uring/xdev_ext_mech_cpu.c",
    "src/compute/io_uring/iaa/xdev_ext_mech_iaa.c",
    "src/network/io_uring/xdev_ext_mech_net.c",
    "src/network/io_uring/xdev_ext_mech_socket.c",
    "src/network/io_uring/xdomain/xdev_ext_xdomain_class.c",
    "src/network/net/xdp/xsk_xdev_ext_mech.c",
    "src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c",
    "src/core/io_uring/xdev_ext_mech_dma.c",
    "src/core/io_uring/xdev_ext_mech_user.c",
)
C_LITERAL_OR_COMMENT = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.S,
)


def boundary_violations(text):
    """Detect source dependencies, not mentions in comments or string literals."""
    text = text.replace("\\\n", "")
    comments_removed = C_LITERAL_OR_COMMENT.sub(
        lambda m: " " if m[0].startswith(("/*", "//")) else m[0], text)
    errors = []
    for header in re.findall(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]',
                             comments_removed, re.M):
        if Path(header).name.startswith(("nv-", "nvidia-")):
            errors.append(f"vendor header {header}")
    code = C_LITERAL_OR_COMMENT.sub(" ", text)
    # An operation is also a dependency when assigned to a function pointer or
    # used through &/typeof; requiring an immediate '(' would miss those uses.
    for symbol in re.findall(r'\bxdev_ext_peer_(?:pin|map|unpin|unmap)\b', code):
        errors.append(f"provider operation reference {symbol}")
    return errors


def provider_boundary(root):
    missing = [name for name in BOUNDARY_ANCHORS if not (root / name).is_file()]
    if missing:
        print(f"not ok - provider boundary missing stage sources: {missing}")
        return 1
    paths = sorted({path for pattern in BOUNDARY_GLOBS for path in root.glob(pattern)})
    failed = False
    for path in paths:
        for error in boundary_violations(path.read_text()):
            print(f"not ok - provider boundary: {path.relative_to(root)}: {error}")
            failed = True
    # Mutate an actual stage, so a weakened detector cannot pass the suite by
    # merely overlooking every forbidden dependency. No maintained source moves.
    stage = (root / BOUNDARY_ANCHORS[0]).read_text()
    controls = (
        ("direct pin", "\nvoid bad(void) { xdev_ext_peer_pin(0, 0, 0, 0); }\n",
         ["provider operation reference xdev_ext_peer_pin"]),
        ("direct map", "\nvoid bad(void) { xdev_ext_peer_map(0, 0, 0, 0); }\n",
         ["provider operation reference xdev_ext_peer_map"]),
        ("indirect map",
         "\nvoid bad(void) { typeof(xdev_ext_peer_map) *mapping = xdev_ext_peer_map; mapping(0, 0, 0, 0); }\n",
         ["provider operation reference xdev_ext_peer_map"] * 2),
        ("map address",
         "\nvoid bad(void) { typeof(xdev_ext_peer_map) *mapping = &xdev_ext_peer_map; mapping(0, 0, 0, 0); }\n",
         ["provider operation reference xdev_ext_peer_map"] * 2),
        ("vendor include", '\n# include "vendor/nv-p2p.h"\n',
         ["vendor header vendor/nv-p2p.h"]),
        ("comment/string mentions",
         '\n/* xdev_ext_peer_pin(0); */\nconst char *s = "xdev_ext_peer_map(";\n', []),
    )
    for label, addition, expected in controls:
        passed = boundary_violations(stage + addition) == expected
        print(f"{'ok' if passed else 'not ok'} - provider boundary control: {label}")
        failed |= not passed
    if not failed:
        print(f"ok - provider boundary ({len(paths)} stage/family source files)")
    return int(failed)


def canonical_root():
    # Both a canonical checkout and the materialized view carry tools/layout.py.
    for parent in Path(__file__).resolve().parents:
        if (parent / "tools/layout.py").is_file():
            sys.path.insert(0, str(parent / "tools"))
            import layout
            return layout.canonical_root(parent)
    raise RuntimeError("provider boundary needs the canonical layout contract")


def without_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def block(text, marker):
    match = re.search(marker, text)
    if not match:
        return ""
    begin = text.find("{", match.end())
    depth = 0
    for end in range(begin, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if depth == 0:
            return text[begin + 1:end]
    return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-boundary-only", action="store_true")
    parser.add_argument("--provider-boundary-root", type=Path,
                        help="explicit canonical source root for boundary mutation checks")
    args = parser.parse_args()
    boundary_result = provider_boundary(args.provider_boundary_root or canonical_root())
    if args.provider_boundary_only:
        return boundary_result
    mech = without_comments((KERNEL / "include/linux/xdev_ext_mech.h").read_text())
    ops = without_comments((KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text())
    contract = block(mech, r"struct\s+xdev_ext_mech_class_ops\s*(?=\{)")
    hdr = block(mech, r"struct\s+xdev_ext_family_hooks_hdr\s*(?=\{)")
    registration = block(ops, r"int\s+xdev_ext_mech_class_register\s*\([^;]+?\)\s*(?=\{)")
    union = re.search(r"union\s*\{([^{}]*)\}\s*fam\s*;\s*$", contract, re.S)
    members = union.group(1) if union else ""
    checks = [
        ("family header declares u32 family", bool(re.search(r"\bu32\s+family\s*;", hdr))),
        ("class contract ends with family hooks union", bool(union)),
    ]
    for name, member in (("hdr", "hdr"), ("net", "net"),
                         ("stor", "stor"), ("comp", "comp")):
        typename = f"xdev_ext_{name}_hooks" if name != "hdr" else "xdev_ext_family_hooks_hdr"
        checks.append((f"family union carries {member} pointer",
                       bool(re.search(rf"\bconst\s+struct\s+{typename}\s*\*\s*{member}\s*;", members))))
        if name != "hdr":
            checks.append((f"{name} hook type is forward declared",
                           bool(re.search(rf"\bstruct\s+{typename}\s*;", mech))))
    checks.append(("registration calls family compatibility rule",
                   bool(re.search(r"\bxdev_ext_family_hooks_ok\s*\(\s*ops\s*->\s*class_id\b", registration))))
    for index, (label, passed) in enumerate(checks, 1):
        print(f"{'ok' if passed else 'not ok'} {index} - source-only: {label}")
    print("# behavioral registration fixture (separate from source-only checks)", flush=True)
    behavior = subprocess.run([sys.executable, str(KERNEL / "tools/testing/selftests/xdev_ext_mech/family/class_register_test.py")])
    return int(boundary_result or not all(passed for _, passed in checks)
               or behavior.returncode != 0)


if __name__ == "__main__":
    sys.exit(main())
