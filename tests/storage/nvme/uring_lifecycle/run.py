#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production NVMe uring issue/completion functions at host API boundaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "source-layout.json").is_file())
API = runpy.run_path(str(ROOT / "tests/integration/peer_graph/nvme_peer_async_test.py"))
BALANCED = runpy.run_path(str(ROOT / "tests/storage/nvme/_legacy_storfam_fixture.py"))["_balanced"]
IOCTL = "drivers/nvme/host/ioctl.c"
BINDING = "io_uring/xdev_ext_binding.c"


def struct_definition(source, name):
    start = source.index("struct " + name + " {")
    end = BALANCED(source, source.index("{", start))
    if source[end:end + 1] != ";":
        raise ValueError("incomplete struct " + name)
    return source[start:end + 1]


def assemble(selected, raw, binding):
    types = "\n".join(struct_definition(raw, name) for name in
                      ("nvme_uring_data", "nvme_xdev_ext_sidecar", "nvme_uring_cmd_pdu"))
    functions = [API["definition"](binding, name) for name in (
        "xdev_ext_binding_plan_fallback", "xdev_ext_binding_token_consume",
        "xdev_ext_binding_token_put", "xdev_ext_binding_dispatch", "xdev_ext_binding_complete")]
    functions += [API["definition"](raw, name) for name in (
        "nvme_xdev_ext_make_admission", "nvme_xdev_ext_initial_admit",
        "nvme_xdev_ext_dispatch_admitted", "nvme_xdev_ext_final_admit",
        "nvme_xdev_ext_build_put", "nvme_xdev_ext_preaccept_unwind",
        "nvme_uring_cmd_pdu", "nvme_xdev_ext_complete", "nvme_uring_task_cb",
        "nvme_uring_cmd_end_io", "nvme_uring_cmd_io")]
    fixture = (HERE / "host.c.in").read_text()
    for marker, value in (("/* PRODUCTION_TYPES */", types),
                          ("/* PRODUCTION_FUNCTIONS */", "\n\n".join(functions))):
        if fixture.count(marker) != 1:
            raise ValueError("fixture marker changed: " + marker)
        fixture = fixture.replace(marker, value)
    return fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    selected = API["SourceSelection"](args.source_root)
    raw, binding = selected.read(IOCTL), selected.read(BINDING)
    for native in ("include/linux/nvme_xdev_ext_passthru.h",
                   "include/linux/xdev_ext_cmd_lifecycle.h",
                   "include/linux/xdev_ext_binding.h", "include/linux/xdev_ext_binding_ctx.h",
                   "include/uapi/linux/io_uring.h"):
        selected.read(native)
    headers = API["host_headers"](selected.root, out / "headers")
    uapi = headers / "include/uapi/linux/io_uring.h"
    uapi.parent.mkdir(parents=True, exist_ok=True)
    uapi.write_text(selected.read("include/uapi/linux/io_uring.h"))
    source = assemble(selected, raw, binding)
    cases = [("production", source, None)]
    if args.mutations:
        mutations = (
            ("post_policy_eagain",
             "ret = nvme_xdev_ext_issue_errno(&xdev_ext_sidecar->resources, ret);",
             "ret = ret;", "FAIL policy EAGAIN: terminal errno"),
            ("repeat_vector_import",
             "if (!xdev_ext_sidecar->vector_imported)", "if (true)",
             "FAIL allocation EAGAIN twice: fixed vector snapshot retained"),
            ("repeat_submit",
             "blk_execute_rq_nowait(req, false);",
             "blk_execute_rq_nowait(req, false); blk_execute_rq_nowait(req, false);",
             "FAIL allocation EAGAIN twice: submit once"),
            ("omit_policy_complete",
             "nvme_xdev_ext_complete(sidecar, pdu->status);", "(void)nvme_xdev_ext_complete;",
             "FAIL allocation EAGAIN twice: done once after token release"),
        )
        for name, old, new, diagnostic in mutations:
            if source.count(old) != 1:
                raise ValueError("mutation anchor is not unique: " + name)
            cases.append((name, source.replace(old, new, 1), diagnostic))
    results = []
    for name, content, diagnostic in cases:
        cfile, binary = out / (name + ".c"), out / name
        cfile.write_text(content)
        command = shlex.split(os.environ.get("CC", "gcc")) + [
            "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            "-I" + str(headers), str(cfile), "-o", str(binary)]
        build = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=60)
        (out / (name + ".build.log")).write_text(build.stdout)
        if build.returncode:
            print(build.stdout, end="")
            raise RuntimeError("SETUP compile failed: " + name)
        run = subprocess.run([str(binary)], text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=30,
                             env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1"))
        (out / (name + ".run.log")).write_text(run.stdout)
        # A compiler failure, crash, sanitizer finding or wrong assertion is
        # never counted as a successful designated mutation.
        failures = [line for line in run.stdout.splitlines() if line.startswith("FAIL ")]
        sanitizer = any(marker in run.stdout for marker in
                        ("AddressSanitizer", "LeakSanitizer",
                         "UndefinedBehaviorSanitizer", "runtime error:"))
        accepted = (run.returncode == 0 and not failures and not sanitizer and
                    "HOST_LIFECYCLE_PASS cases=10" in run.stdout) if diagnostic is None else (
                        run.returncode == 1 and not sanitizer and len(failures) == 1 and
                        failures[0].startswith(diagnostic + " (fixture line "))
        results.append({"case": name, "compile_exit": build.returncode,
                        "run_exit": run.returncode, "accepted": accepted,
                        "command": command})
        print(name + ": " + ("PASS" if accepted else "FAIL"))
        if not accepted:
            print(run.stdout, end="")
            break
    selected.verify()
    report = {
        "status": "PASS" if len(results) == len(cases) and
                  all(row["accepted"] for row in results) else "FAIL",
        "scope": "production C host API boundaries; not kernel scheduling or physical DMA",
        "sources": {name: hashlib.sha256(value.encode()).hexdigest()
                    for name, value in selected.inputs.items()},
        "results": results,
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
