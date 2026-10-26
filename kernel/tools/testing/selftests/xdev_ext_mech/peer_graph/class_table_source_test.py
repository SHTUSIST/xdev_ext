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
    for text, name, field in ((core, "xdev_ext_mech_class_known", "family"),
                              (step, "xdev_ext_mech_peer_dirs", "peer_dirs"),
                              (step, "xdev_ext_mech_stage_role", "role_rule"),
                              (family, "xdev_ext_mech_class_family", "family")):
        function = body(text, name)
        checks.append((f"{name} reads the descriptor {field}",
                       calls_table(function) and bool(re.search(r"->\s*" + field + r"\b", function))))
        checks.append((f"{name} has no per-class conditions",
                       bool(function) and not re.search(r"\bXDEV_EXT_MECH_CLASS_[A-Z_]+\b", function)))

    create = body(step, "xdev_ext_mech_create_check")
    checks.extend([
        ("CREATE reads the class descriptor", calls_table(create)),
        ("CREATE uses peer_only from the descriptor", bool(re.search(r"->\s*peer_only\b", create))),
        ("CREATE uses the descriptor flag properties",
         all(re.search(r"->\s*" + name + r"\b", create)
             for name in ("flags_later", "known_flags", "flags_ok"))),
        ("CREATE removes the NET-specific pool restriction",
         not re.search(r"u\s*->\s*class_id\s*==\s*XDEV_EXT_MECH_CLASS_NET\s*&&\s*c\s*->\s*pool_kind", create)),
        ("CREATE removes the old IAA/SOCKET/AF_XDP flag allow-lists",
         not any(token in create for token in ("XDEV_EXT_IAA_F_SOFTWARE", "~XDEV_EXT_SOCKET_F_NXP",
                                               "XDEV_EXT_AFXDP_F_RELIABLE", "XDEV_EXT_AFXDP_F_FINITE",
                                               "XDEV_EXT_AFXDP_F_POLICY"))),
    ])
    base = body(mech, "xdev_ext_mech_base")
    default = base.rsplit("default:", 1)[-1] if "default:" in base else ""
    checks.extend([
        ("base default consults descriptor context rule",
         calls_table(default) and bool(re.search(r"->\s*ctx_rule\b", default))
         and "XDEV_EXT_CTX_RULE_COMMON" in default),
        ("base default retains GPU context fallback", "xdev_ext_binding_make_gpu_ctx" in default),
        ("base keeps USER case pinned by user-stage tests", "case XDEV_EXT_MECH_CLASS_USER:" in base),
        ("base keeps the native AF_XDP capability and constructor texts",
         "st->s->pool.capabilities" in base and "xdev_ext_binding_make_afxdp_native_tx_ctx" in base),
    ])
    for name in ("NVME", "AFXDP", "CPU", "IAA", "SOCKET", "NET", "DMA"):
        checks.append((f"base retains existing {name} case", f"case XDEV_EXT_MECH_CLASS_{name}:" in base))

    bind = body(mech, "xdev_ext_mech_session_bind")
    checks.extend([
        ("session bind retains the pinned CPU/USER no-file predicate",
         bool(re.search(r"class_id != XDEV_EXT_MECH_CLASS_CPU &&\s*st->class_id != XDEV_EXT_MECH_CLASS_USER", bind))),
        ("session bind extends the same no-file predicate through the table",
         bool(re.search(r"class_id != XDEV_EXT_MECH_CLASS_CPU &&\s*st->class_id != XDEV_EXT_MECH_CLASS_USER\s*&&\s*!\s*xdev_ext_mech_class_desc\s*\(\s*st->class_id\s*\)\s*->\s*no_file", bind))),
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
