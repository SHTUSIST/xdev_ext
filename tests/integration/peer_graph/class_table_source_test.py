#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source-only class-table wiring checks; the C companion proves old behavior.

Compatibility texts are pinned to main 713327e; the class-to-family getter
added by reviewed F1 (bc4fe23) must now read the same descriptor table.
These checks deliberately inspect function bodies after removing comments.
Seeing a table call in a comment or in an unrelated function is insufficient.
"""
from pathlib import Path
import re
import sys

KERNEL = Path(__file__).resolve().parents[5]


def without_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def body(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", text)
    if not match:
        return ""
    begin = text.index("{", match.start())
    depth = 1
    end = begin + 1
    while end < len(text) and depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[begin + 1:end - 1] if not depth else ""


def calls_table(text):
    return bool(re.search(r"\bxdev_ext_mech_class_desc\s*\(", text))


def main():
    core = without_comments((KERNEL / "io_uring/xdev_ext_mech_core.h").read_text())
    step = without_comments((KERNEL / "io_uring/xdev_ext_mech_step.h").read_text())
    mech = without_comments((KERNEL / "io_uring/xdev_ext_mech.c").read_text())
    family = without_comments((KERNEL / "include/linux/xdev_ext_family_core.h").read_text())
    checks = []
    # Public helpers keep their descriptor selection; role/CREATE/base now
    # delegate to the selected row rather than duplicating the class switch.
    for text, name, field in ((core, "xdev_ext_mech_class_known", "family"),
                              (step, "xdev_ext_mech_peer_dirs", "peer_dirs"),
                              (family, "xdev_ext_mech_class_family", "family")):
        function = body(text, name)
        checks.append((f"{name} reads the descriptor {field}",
                       calls_table(function) and bool(re.search(r"->\s*" + field + r"\b", function))))
        checks.append((f"{name} has no per-class conditions",
                       bool(function) and not re.search(r"\bXDEV_EXT_MECH_CLASS_[A-Z_]+\b", function)))
    role = body(step, "xdev_ext_mech_stage_role")
    role_desc = body(step, "xdev_ext_mech_stage_role_desc")
    checks.extend([
        ("stage role forwards the chosen descriptor and stage",
         bool(re.search(r"return\s+xdev_ext_mech_stage_role_desc\(xdev_ext_mech_class_desc\(u->class_id\),\s*u\);", role))),
        ("stage role invokes the descriptor role callback", "return d->role(u);" in role_desc),
        ("stage role has no per-class conditions",
         not re.search(r"\bXDEV_EXT_MECH_CLASS_[A-Z_]+\b", role + role_desc)),
    ])
    create = body(step, "xdev_ext_mech_create_check")
    create_desc = body(step, "xdev_ext_mech_create_check_desc")
    checks.extend([
        ("CREATE reads each class descriptor and delegates the same rows",
         "rows[i] = xdev_ext_mech_class_desc(c->st[i].class_id);" in create and
         "return xdev_ext_mech_create_check_desc(c, rows, frames);" in create),
        ("CREATE uses peer_only from the descriptor", bool(re.search(r"->\s*peer_only\b", create_desc))),
        ("CREATE uses the descriptor flag properties",
         all(re.search(r"->\s*" + name + r"\b", create_desc)
             for name in ("flags_later", "known_flags", "flags_ok"))),
        ("CREATE removes the NET-specific pool restriction",
         not re.search(r"u\s*->\s*class_id\s*==\s*XDEV_EXT_MECH_CLASS_NET\s*&&\s*c\s*->\s*pool_kind", create_desc)),
        ("CREATE removes the old IAA/SOCKET/AF_XDP flag allow-lists",
         not any(token in create_desc for token in ("XDEV_EXT_IAA_F_SOFTWARE", "~XDEV_EXT_SOCKET_F_NXP",
                                                    "XDEV_EXT_AFXDP_F_RELIABLE", "XDEV_EXT_AFXDP_F_FINITE",
                                                    "XDEV_EXT_AFXDP_F_POLICY"))),
    ])
    family_raw = (KERNEL / "include/linux/xdev_ext_family_core.h").read_text()
    rows = dict(re.findall(r"\{\s*/\*\s*XDEV_EXT_MECH_CLASS_(\w+)\s*\*/(.*?)\n\t}", family_raw, re.S))
    base = body(mech, "xdev_ext_mech_base")
    base_desc = body(family, "xdev_ext_mech_base_desc")
    checks.extend([
        ("base forwards the registered descriptor, direction, pool capabilities and bytes",
         "caps = st->s->pool.capabilities;" in base and
         "return xdev_ext_mech_base_desc(st->cls->decl, st->direction, caps, bytes);" in base),
        ("base invokes the descriptor context constructor", "return d->base(direction, caps, bytes);" in base_desc),
        ("GPU descriptor retains GPU context constructor",
         ".base = xdev_ext_decl_gpu_base" in rows.get("CE", "") and
         "xdev_ext_binding_make_gpu_ctx" in body(family, "xdev_ext_decl_gpu_base")),
        ("AF_XDP retains native capability and constructor",
         "caps & XDEV_EXT_BINDING_CAP_ZERO_COPY" in body(family, "xdev_ext_decl_afxdp_base") and
         "xdev_ext_binding_make_afxdp_native_tx_ctx" in body(family, "xdev_ext_decl_afxdp_base")),
    ])
    for name, callback in (("NVME", "nvme"), ("AFXDP", "afxdp"), ("CPU", "common"),
                           ("IAA", "common"), ("SOCKET", "common"), ("NET", "common"),
                           ("DMA", "common"), ("USER", "common")):
        checks.append((f"base retains existing {name} constructor",
                       bool(re.search(r"\.base\s*=\s*xdev_ext_decl_" + callback + r"_base\b", rows.get(name, "")))))

    bind = body(mech, "xdev_ext_mech_session_bind")
    checks.extend([
        ("session bind uses the registered descriptor no-file property",
         bool(re.search(r"if\s*\(!st->cls->decl->no_file\)\s*\{\s*st->file\s*=\s*fget\(c->st\[i\]\.fd\);", bind))),
        ("CPU and USER descriptors retain no-file admission",
         all(re.search(r"\.no_file\s*=\s*1\b", rows.get(name, "")) for name in ("CPU", "USER"))),
        ("session bind retains the pinned ops lookup", "xdev_ext_mech_ops_get(st->class_id," in bind),
        ("session bind retains the pinned class owner reference", "&s->c_owner[st->class_id]" in bind),
        ("session bind retains checked-unbind counting on failed bind",
         bool(re.search(r"if \(st->cls->unbind_checked && st->priv\)\s+s->nr_bound\+\+;", bind))),
    ])
    for index, (label, passed) in enumerate(checks, 1):
        print(f"{'ok' if passed else 'not ok'} {index} - source-only: {label}")
    return int(not all(passed for _, passed in checks))


if __name__ == "__main__":
    sys.exit(main())
