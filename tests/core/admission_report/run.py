#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent failed-CREATE report probe: behavior=1; setup=2; success=0.

No missing symbol or failed build is accepted as behavior RED.
Numeric op 10 is executed through the real register dispatcher; failure to
deliver the accepted new-function report is behavioral RED.
The old-interface gap probe is separate from future CREATE_REPORT conformance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def function(text, name):
    # Preserve original bytes; strip comments/strings only for brace counting.
    match = re.search(r"^\w[^;{}]*\b" + re.escape(name) + r"\([^;{}]*\)\s*\{", text, re.M)
    if not match:
        raise RuntimeError("missing production function (SETUP): " + name)
    start = match.start()
    scan = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: " " * len(m[0]), text[start:], flags=re.S)
    opening = scan.index("{")
    depth = 0
    for i in range(opening, len(scan)):
        depth += scan[i] == "{"
        depth -= scan[i] == "}"
        if depth == 0:
            return text[start:start + i + 1]
    raise RuntimeError("unbalanced production function: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--controls-only", action="store_true")
    parser.add_argument("--frozen-input", type=Path, help="replay an earlier generated probe.c and exact header set")
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    verdict = {"schema": 1, "environment": "local host GCC extracted production control flow; no devices or DMA",
               "source_root": str(root), "behavior": [], "future_blocked": [
                   "Task2 dynamic observed diagnostics and real requester retention ledger composition",
                   "full kernel/device execution and asynchronous publication/remove interleavings"]}
    try:
        native = out / "headers"
        if args.frozen_input:
            import shutil
            frozen = args.frozen_input.resolve()
            if frozen == out:
                raise RuntimeError("frozen input and output must differ")
            shutil.copytree(frozen / "headers", native, dirs_exist_ok=True)
            core = requester = (frozen / "probe.c").read_text()
            verdict["frozen_input"] = str(frozen)
            verdict["frozen_receipt"] = json.loads((frozen / "result.json").read_text())
        else:
            # Consume canonical mapping without modifying it or any adapter.
            spec = importlib.util.spec_from_file_location("admission_layout", root / "tools/layout.py")
            layout = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = layout
            spec.loader.exec_module(layout)
            mapping = layout.load_layout(root)
            for (component, name), source in mapping.by_native.items():
                if component == "linux" and name.endswith(".h"):
                    dst = native / name
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    dst.write_bytes((root / source).read_bytes())
            core = (root / "src/core/io_uring/xdev_ext_mech.c").read_text()
            requester = (root / "src/core/io_uring/family/xdev_ext_requester.c").read_text()
        groups = {
            "ADMITS": (core, ("xdev_ext_mech_session_admits",)),
            "BATCH_GET": (core, ("xdev_ext_mech_batch_get_locked",)),
            "REQUESTER": (requester, ("xdev_ext_requester_bind", "xdev_ext_requester_unbind")),
            "BIND": (core, ("xdev_ext_mech_class_bind", "xdev_ext_mech_session_bind")),
            "RELEASE": (core, ("xdev_ext_mech_unbind_checked", "xdev_ext_mech_session_release_report", "xdev_ext_mech_session_release")),
            "CREATE": (core, ("xdev_ext_mech_create",)),
            "CAPS": (core, ("xdev_ext_mech_stage_caps_op",)),
            "DISPATCH": (core, ("io_xdev_ext_mech_register",)),
        }
        if "static int xdev_ext_mech_session_release_disposition(" in core:
            groups["RELEASE"] = (core, ("xdev_ext_mech_unbind_checked", "xdev_ext_mech_session_release_disposition", "xdev_ext_mech_session_release_report", "xdev_ext_mech_session_release"))
        if "static int xdev_ext_mech_create_common(" in core:
            groups["CREATE"] = (core, ("xdev_ext_mech_create_common", "xdev_ext_mech_create", "xdev_ext_mech_create_report_op"))
        exact_frozen = bool(args.frozen_input and not re.search(r"^\w[^;{}]*\bxdev_ext_mech_batch_get_locked\([^;{}]*\)\s*\{", core, re.M))
        if exact_frozen:
            # Old frozen probes predate the newly required real batch allocator.
            # Replay their exact original source/case list instead of silently
            # borrowing new production bodies or fabricating a test helper.
            generated = core
            groups = {}
            verdict["frozen_exact_replay"] = True
            verdict["extracted"] = verdict["frozen_receipt"].get("extracted", {})
        else:
            generated = (HERE / "fixture.c.in").read_text()
            verdict["extracted"] = {}
        for marker, (source, names) in groups.items():
            bodies = [function(source, name) for name in names]
            generated = generated.replace("/* " + marker + " */", "\n\n".join(bodies))
            for name, body in zip(names, bodies):
                verdict["extracted"][name] = hashlib.sha256(body.encode()).hexdigest()
        cfile, exe = out / "probe.c", out / "probe"
        cfile.write_text(generated)
        command = [os.environ.get("CC", "gcc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-unused-variable",
                   "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I" + str(native), "-I" + str(HERE), str(cfile), "-o", str(exe)]
        verdict["compile_command"] = command
        built = subprocess.run(command, text=True, capture_output=True, timeout=45)
        (out / "compile.log").write_text(built.stdout + built.stderr)
        if built.returncode:
            raise RuntimeError("compile failed; see compile.log (never behavior RED)")
        verdict["compile_exit"] = built.returncode
        cases = ("abi", "controls", "legacy_value_gap") if args.controls_only else ("abi", "controls", "legacy_value_gap",
                "report_bind0", "report_bind1", "report_prepare0", "report_prepare1",
                "report_swiotlb", "report_untrusted", "report_raw_iommu", "report_raw_dma_ops",
                "report_owner_missing", "report_non_bar", "report_unknown_backing", "report_external",
                "report_describe_unsupported", "report_success",
                "report_describe", "report_premap", "report_unknown", "report_released_error",
                "report_copyout_success", "report_copyout_failure", "report_check", "report_schema",
                "publication_success", "publication_copyfault", "publication_stop", "legacy_publication")
        if exact_frozen:
            cases = tuple(c["case"] for c in verdict["frozen_receipt"]["behavior"]
                          if not args.controls_only or not c["case"].startswith(("report_", "publication_")))
        for case in cases:
            run = subprocess.run([str(exe), case], text=True, capture_output=True, timeout=10)
            (out / (case + ".log")).write_text(run.stdout + run.stderr)
            verdict["behavior"].append({"case": case, "exit": run.returncode})
            print(run.stdout, end="")
            print(run.stderr, end="", file=sys.stderr)
            if run.returncode not in (0, 1):
                raise RuntimeError(f"{case} crashed or fixture invariant failed: exit={run.returncode}")
        verdict["exit"] = int(any(c["exit"] == 1 for c in verdict["behavior"]))
        verdict["state"] = "BEHAVIOR_RED" if verdict["exit"] else "SCOPED_PASS_FUTURE_BLOCKED"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        verdict.update(exit=2, state="SETUP_ERROR", error=str(exc))
        print("SETUP: " + str(exc), file=sys.stderr)
    (out / "result.json").write_text(json.dumps(verdict, indent=2) + "\n")
    print(f"state={verdict['state']} exit={verdict['exit']} future_blocked={len(verdict['future_blocked'])}")
    return verdict["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
