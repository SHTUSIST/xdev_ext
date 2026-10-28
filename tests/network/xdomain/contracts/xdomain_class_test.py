#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Executes the XDOMAIN class and the network family runtime end to end between
 two in-process stages, with the NHI vtable, link functions, leases and external
 mechanism boundaries stubbed; proves protocol order, custody, commitment,
 withdrawal and failure handling, not physical NHI/cable/GPU behavior.

Core end/native-control/settle bodies are sliced intact from actual source.
No generated policy, alternate transition implementation, or successful C fallback.
X4 is stubbed only at the external link/device boundary; no X4 source is required.
"""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def no_includes(source):
    return "\n".join(line for line in source.splitlines()
                     if not re.match(r"^\s*#\s*include\b", line))


def balanced(source, opening):
    """C brace scanner; ignores comments and quoted braces, refuses truncation."""
    depth, index, mode = 0, opening, "normal"
    while index < len(source):
        ch, pair = source[index], source[index:index + 2]
        if mode == "line":
            if ch == "\n": mode = "normal"
        elif mode == "comment":
            if pair == "*/": mode, index = "normal", index + 1
        elif mode in ('"', "'"):
            if ch == "\\": index += 1
            elif ch == mode: mode = "normal"
        elif pair == "//": mode, index = "line", index + 1
        elif pair == "/*": mode, index = "comment", index + 1
        elif ch in ('"', "'"): mode = ch
        elif ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0: return index + 1
        index += 1
    raise ValueError("unterminated selected C definition")


def struct(source, name):
    match = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{", source)
    if not match: raise ValueError(f"actual declaration missing: struct {name}")
    end = balanced(source, source.index("{", match.start()))
    return source[match.start():end] + ";\n"


def function(source, name):
    # Anchored line begins avoid calls/prototypes. Function body is retained byte-for-byte.
    match = re.search(r"(?m)^(?:static\s+)?(?:inline\s+)?(?:void|bool|int|u64|unsigned long)\s+" +
                      re.escape(name) + r"\s*\([^;]*?\)\s*\{", source)
    if not match: raise ValueError(f"actual function missing: {name}")
    end = balanced(source, source.index("{", match.start()))
    return source[match.start():end] + "\n"


def region(source, begin, end):
    if source.count(begin) != 1 or source.count(end) != 1:
        raise ValueError(f"missing/ambiguous runtime markers: {begin}")
    return source.split(begin, 1)[1].split(end, 1)[0]


def poll_unit(kernel, ring_source=None):
    """Retain real poll/custody bodies; IRQ-default cases exit before OS calls."""
    ring = (ring_source or (kernel / "io_uring/xdomain/xdev_ext_xdomain_ring.c")).read_text()
    enum = re.search(r"enum xdev_ext_xd_native_disposition\s*\{[^}]+\};", ring)
    if not enum:
        raise ValueError("actual native disposition enum missing")
    declarations = enum.group(0) + "\n"
    declarations += "".join(struct(ring, name) for name in (
        "xdev_ext_xd_native", "xdev_ext_xd_rings", "xdev_ext_xd_ctl_allocation"))
    limits = "\n".join(line for line in ring.splitlines()
                       if line.startswith("#define XDEV_EXT_XD_POLL_"))
    return declarations + limits + "\n" + "\n".join(function(ring, name) for name in (
        "xdev_ext_xd_closing", "xdev_ext_xd_poll", "xdev_ext_xd_ctl_tx_pending_locked"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=Path(__file__).resolve().parents[5])
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--x1-test-directory", type=Path, default=Path(__file__).resolve().parent,
                        help="activated independent X1 runners and supporting fixtures")
    parser.add_argument("--pressure-adapter", type=Path, default=Path(__file__).resolve().parent / "xdomain_pressure_adapter.c",
                        help="reviewed test-only actual X5 bounded-storage adapter; no replacement enqueue")
    parser.add_argument("--artifact-directory", type=Path, help="retain compiled actual-source TU and binary")
    parser.add_argument("--case", choices=tuple(f"P{i:02}" for i in range(5,27)) + ("U01", "U02", "B01", "B02", "B03", "U03", "U04"), help="run selected case; default original 45 plus U01/U02/B01/B02")
    args = parser.parse_args()
    kernel, here = args.kernel.resolve(), Path(__file__).resolve().parent
    files = {
        "class": kernel / "io_uring/xdomain/xdev_ext_xdomain_class.c",
        "link declarations": kernel / "io_uring/xdomain/xdev_ext_xdomain.h",
        "X2 pure rules": kernel / "io_uring/xdomain/xdev_ext_xdomain_core.h",
        "X6 policy": kernel / "tools/xdev_ext_mech/xdomain_peer.bpf.c",
        "family": kernel / "io_uring/family/xdev_ext_netfam.c",
        "core": kernel / "io_uring/xdev_ext_mech.c",
        "mech": kernel / "include/linux/xdev_ext_mech.h",
        "UAPI": kernel / "include/uapi/linux/xdev_ext_mech.h",
        "prog": kernel / "tools/xdev_ext_mech/xdev_ext_mech_prog.h",
        "X1 kfunc suite": args.x1_test_directory.resolve() / "xdomain_kfunc_test.py",
        "X1 identity suite": args.x1_test_directory.resolve() / "xdomain_identity_test.py",
    }
    if args.pressure_adapter:
        files["pressure adapter"] = args.pressure_adapter.resolve()
    for name in ("xdomain_host.h", "xdomain_boundaries.c", "xdomain_cases.c"):
        files[name] = here / name
    missing = [f"{label}: {path}" for label, path in files.items() if not path.is_file()]
    if missing:
        print("X5 MISSING DEPENDENCY (no behavioral test executed):\n" + "\n".join(missing), file=sys.stderr)
        return 2
    if not args.pressure_adapter:
        print("X5 SETUP: actual-storage P19 pressure adapter required; no behavioral test executed", file=sys.stderr)
        return 2
    # X1 production envelope/identity is not replaced by the X5 metadata bridge.
    for suite in ("X1 kfunc suite", "X1 identity suite"):
        subprocess.run([sys.executable, str(files[suite])],
                       env={**os.environ, "KERNEL_SRC": str(kernel)}, check=True)
    texts = {name: path.read_text() for name, path in files.items() if not name.startswith("X1 ")}
    mech = texts["mech"]
    declarations = "\n".join(struct(mech, name) for name in (
        "xdev_ext_mech_frame", "xdev_ext_family_hooks_hdr", "xdev_ext_mech_stage",
        "xdev_ext_mech_class_ops", "xdev_ext_xdomain_proto_result", "xdev_ext_mech_call_args"))
    for header in ("include/linux/xdev_ext_requester.h", "include/linux/xdev_ext_netfam.h"):
        declarations += no_includes((kernel / header).read_text()) + "\n"
    declarations += no_includes(texts["link declarations"])
    family = region(texts["family"], "/* xdev_ext_netfam runtime begin */", "/* xdev_ext_netfam runtime end */")
    end_enum = re.search(r"enum xdev_ext_mech_end\s*\{[^}]+\};", texts["core"])
    if not end_enum: raise ValueError("actual core end disposition enum missing")
    core = end_enum.group(0) + "\n" + "\n".join(function(texts["core"], name) for name in (
        "xdev_ext_mech_settled", "xdev_ext_mech_settle_locked", "xdev_ext_mech_progress_work", "xdev_ext_mech_session_stop", "xdev_ext_mech_session_stop_started_ns",
        "xdev_ext_mech_stage_native_get", "xdev_ext_mech_stage_native_put", "xdev_ext_mech_end") +
        (("xdev_ext_mech_stage_stop",) if "\nvoid xdev_ext_mech_stage_stop(" in texts["core"] else ()))
    # Diagnostic selection copies the selected original case byte-for-byte;
    # the default full-suite body and every oracle remain unchanged.
    selected_policy = args.case and args.case.startswith("P") and args.case != "P19"
    if selected_policy:
        body = function(texts["xdomain_cases.c"], "policy_safety")
        ends = list(re.finditer(r'\bok\("(P\d\d) [^"\n]*"\);', body))
        match_index = next(i for i, match in enumerate(ends) if match.group(1) == args.case)
        start = ends[match_index-1].end() if match_index else body.index("{")+1
        chunk = body[start:ends[match_index].end()]
        if args.case == "P20":
            chunk = chunk.split("pressure_case();", 1)[1]
        if args.case == "P17":
            chunk = chunk.replace("pair(1,2,8192);", "pair(1,2,8192);unsigned window=family_of(&sides[0])->tx.cfg.window;", 1)
        adapter = "static void diagnostic_policy_case(void) {\n" + chunk + "\n}\n"
        texts["xdomain_cases.c"] = texts["xdomain_cases.c"].replace("int main(void)", adapter+"int main(void)")
        texts["xdomain_cases.c"] = texts["xdomain_cases.c"].replace('if(!strcmp(selected,"P19"))pressure_case();', 'if(selected[0]==\'P\'&&strcmp(selected,"P19"))diagnostic_policy_case();else if(!strcmp(selected,"P19"))pressure_case();')
    # Complete actual class/BPF function bodies; only Linux/BPF includes removed.
    source = (texts["xdomain_host.h"].replace("@KERNEL@", str(kernel))
              .replace("@UAPI@", str(files["UAPI"]))
              .replace("@PROG@", str(files["prog"]))
              .replace("@DECLARATIONS@", declarations)
              .replace("@CORE@", core)
              .replace("@FAMILY@", family)
              .replace("@BPF@", no_includes(texts["X6 policy"]))
              .replace("@POLL@", poll_unit(kernel))
              .replace("@CLASS@", no_includes(texts["class"]))
              .replace("@BOUNDARIES@", texts["xdomain_boundaries.c"])
              .replace("@CASES@", texts["xdomain_cases.c"])
              .replace("@PRESSURE@", texts["pressure adapter"]))
    leftovers = re.findall(r"@[A-Z_]+@", source)
    if leftovers: raise ValueError(f"unexpanded adapter tokens: {leftovers}")
    if args.artifact_directory:
        args.artifact_directory.mkdir(parents=True, exist_ok=True)
    context = nullcontext(str(args.artifact_directory.resolve())) if args.artifact_directory else tempfile.TemporaryDirectory(prefix="xdev-x5-event-apply-")
    with context as directory:
        source_file, binary = Path(directory) / "test.c", Path(directory) / "test"
        source_file.write_text(source)
        command = [args.cc, "-std=gnu11", "-O1", "-pthread", "-Wall", "-Wextra", "-Werror",
                   "-Wno-unused-function", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                   "-I" + str(kernel), str(source_file), "-o", str(binary)]
        print("X5 actual-source GCC command:", " ".join(command), flush=True)
        subprocess.run(command, check=True)
        print("X5 scope:", args.case or "original 45 plus U01/U02/B01/B02 (49)", flush=True)
        runtime_env = dict(os.environ)
        runtime_env.pop("X5_CASE", None)  # CLI owns scope; inherited debug state cannot narrow a full run.
        if args.case:
            runtime_env["X5_CASE"] = args.case
        subprocess.run([str(binary)], check=True, timeout=60, env=runtime_env)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"X5 FAIL: {error}", file=sys.stderr)
        sys.exit(1)
