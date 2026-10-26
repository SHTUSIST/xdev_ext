#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Tests descriptor plans, default event policy and final-CQE interpretation,
not verifier acceptance (Task X7) or NHI behavior (Phase H).

Compiles the selected actual BPF source, including xdomain_peer_choose. The
metadata-only fixture does not implement a policy or kernel checked-apply.
Missing artifacts fail explicitly; there are no skips or substitute programs.
"""
from pathlib import Path
import argparse
import re
import subprocess
import sys
import tempfile


def mirror_assertions(program: str, prog_header: str, netfam_header: str) -> str:
    """Pin mirrors to actual UAPI/private constants, never policy outputs."""
    direct = {
        "XDEV_EXT_MP_XDOMAIN_MAX_FRAME": "XDEV_EXT_XDOMAIN_MAX_FRAME",
        "XDEV_EXT_MP_NET_REMOTE_ACKED": "XDEV_EXT_NET_REMOTE_ACKED",
        "XDEV_EXT_MP_SITE_WORKER_PROTOCOL": "XDEV_EXT_MECH_SITE_WORKER_PROTOCOL",
        "XDEV_EXT_MP_XDOMAIN_PROTO_VERSION": "XDEV_EXT_XDOMAIN_PROTO_VERSION",
        "XDEV_EXT_MP_PROTO_VERSION": "XDEV_EXT_XDOMAIN_PROTO_VERSION",
        "XDEV_EXT_MP_MAX_FRAMES": "XDEV_EXT_MECH_MAX_FRAMES",
        "XDEV_EXT_MP_SITE_WORKER": "XDEV_EXT_MECH_SITE_WORKER",
        "XDEV_EXT_MP_DIR_TO_DEVICE": "XDEV_EXT_MECH_DIR_TO_DEVICE",
        "XDEV_EXT_MP_DIR_FROM_DEVICE": "XDEV_EXT_MECH_DIR_FROM_DEVICE",
    }
    declared = set(re.findall(r"^\s*#\s*define\s+(XDEV_EXT_MP_\w+)", prog_header, re.M))
    used = set(re.findall(r"\bXDEV_EXT_MP_\w+\b", program))
    selected = {
        name for name in declared | used
        if any(token in name for token in ("XDOMAIN", "_XDP_", "_RDV_", "WORKER_PROTOCOL", "NET_REMOTE"))
    }
    selected |= set(direct) - {"XDEV_EXT_MP_PROTO_VERSION", "XDEV_EXT_MP_XDOMAIN_PROTO_VERSION"}
    # The alternative version spelling is accepted only when actually declared.
    for version_name in ("XDEV_EXT_MP_PROTO_VERSION", "XDEV_EXT_MP_XDOMAIN_PROTO_VERSION"):
        if version_name in declared | used:
            selected.add(version_name)
    # RDV states are private, not UAPI. Copy only their actual enum declaration
    # so the compiler compares mirrors with source constants, not another table
    # of test-invented numbers or any production transition helper.
    rdv = re.search(r"\benum\s+xdev_ext_net_rdv\s*\{[^}]*\};", netfam_header)
    if rdv is None:
        raise ValueError("missing actual private xdev_ext_net_rdv enum")
    lines = [rdv.group(0)]
    for name in sorted(selected):
        uapi = direct.get(name)
        if uapi is None and name.startswith("XDEV_EXT_MP_XDP_F_"):
            uapi = name.replace("XDEV_EXT_MP_XDP_F_", "XDEV_EXT_XDP_F_", 1)
        if uapi is None and name.startswith("XDEV_EXT_MP_NET_REMOTE_"):
            uapi = name.replace("XDEV_EXT_MP_NET_REMOTE_", "XDEV_EXT_NET_REMOTE_", 1)
        if uapi is None and name.startswith("XDEV_EXT_MP_RDV_"):
            uapi = name.replace("XDEV_EXT_MP_RDV_", "XDEV_EXT_RDV_", 1)
        if uapi is None:
            raise ValueError(f"unmapped XDOMAIN mirror {name}; add an explicit UAPI mapping")
        # A missing macro intentionally fails compilation; no test-only define.
        lines.append(f'_Static_assert({name} == {uapi}, "mirror {name}");')
    # Pin the original ABI facts independently of either copied macro value.
    pins = {
        "XDEV_EXT_XDOMAIN_MAX_FRAME": "4096U",
        "XDEV_EXT_NET_REMOTE_ACKED": "2U",
        "XDEV_EXT_XDOMAIN_PROTO_VERSION": "1U",
        "XDEV_EXT_XDOMAIN_TAG_LEN": "24U",
    }
    facts = [
        "LINK_UP", "ADMITS", "STAGE_DEAD", "STOPPING", "LOCAL_KNOWN",
        "LOCAL_QUIESCED", "NATIVE_POSTED", "WITHDRAWN", "CHAIN_DONE",
        "CHAIN_SEQUESTERED", "RTS_CANCELED", "CTS_RECEIVED", "NATIVE_PENDING",
        "CTS_OWED", "FINAL_OWED",
    ]
    pins.update({f"XDEV_EXT_XDP_F_{name}": f"(1U << {bit})" for bit, name in enumerate(facts)})
    for name, value in pins.items():
        lines.append(f'_Static_assert({name} == {value}, "frozen {name}");')
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path,
                        help="exact kernel source directory to test (required outside activated tree)")
    parser.add_argument("--cc", default="gcc", help="host GCC executable")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    kernel = args.kernel.resolve() if args.kernel else here.parents[4]
    artifacts = {
        "actual X6 BPF source": kernel / "tools/xdev_ext_mech/xdomain_peer.bpf.c",
        "actual UAPI": kernel / "include/uapi/linux/xdev_ext_mech.h",
        "actual mirrored constants": kernel / "tools/xdev_ext_mech/xdev_ext_mech_prog.h",
        "actual kfunc declarations": kernel / "tools/xdev_ext_mech/xdev_ext_mech_kfunc.h",
        "actual private RDV constants": kernel / "include/linux/xdev_ext_netfam_core.h",
        "host fixture": here / "xdomain_program_fixture.c",
    }
    missing = [f"{label}: {path}" for label, path in artifacts.items() if not path.is_file()]
    if missing:
        print("X6 MISSING ARTIFACT (no behavioral test executed):\n  " + "\n  ".join(missing), file=sys.stderr)
        return 2
    source = artifacts["actual X6 BPF source"].read_text()
    uapi = artifacts["actual UAPI"].read_text()
    kfunc = artifacts["actual kfunc declarations"].read_text()
    required = [
        ("X1 info record", "struct xdev_ext_xdomain_proto_info", uapi),
        ("X1 verdict record", "struct xdev_ext_xdomain_proto_verdict", uapi),
        ("X1 info kfunc", "bpf_xdev_ext_xdomain_info", kfunc),
        ("X1 verdict kfunc", "bpf_xdev_ext_xdomain_verdict", kfunc),
        ("X6 actual policy", "xdomain_peer_choose", source),
    ]
    absent = [label for label, symbol, text in required if symbol not in text]
    if absent:
        print("X6 MISSING DECLARATION/ENTRY (no behavioral test executed): " + ", ".join(absent), file=sys.stderr)
        return 2
    # Only includes are removed. No function extraction/replacement or rewritten
    # protocol branch: the compiler sees the actual complete/build/choose bodies.
    body = "\n".join(line for line in source.splitlines()
                     if not re.match(r"^\s*#\s*include\b", line))
    fixture = artifacts["host fixture"].read_text()
    replacements = {
        "@MECH@": str(artifacts["actual UAPI"]),
        "@PROG@": str(artifacts["actual mirrored constants"]),
        "@MIRROR_ASSERTIONS@": mirror_assertions(
            source, artifacts["actual mirrored constants"].read_text(),
            artifacts["actual private RDV constants"].read_text()),
        "@BPF_SOURCE@": body,
    }
    for key, value in replacements.items():
        fixture = fixture.replace(key, value)
    with tempfile.TemporaryDirectory(prefix="xdev-xdomain-program-") as directory:
        root = Path(directory)
        c_file, binary = root / "test.c", root / "test"
        c_file.write_text(fixture)
        subprocess.run([args.cc, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", "-fno-sanitize-recover=all",
                        str(c_file), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"X6 FAIL: {error}", file=sys.stderr)
        sys.exit(1)
