#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent importer contract harness; never substitutes an importer.

The fixture is first compiled against frozen declarations. If the requested
source root lacks the new component, verdict is NOT_IMPLEMENTED (exit 3).
Compiler/API setup errors use SETUP_ERROR (exit 2). Only an actual compiled
production importer can produce behavioral PASS or FAIL (exit 0 or 1).
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parent))
from provenance import PRODUCTION_INPUTS, capture, capture_fixture


HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parents[2]
CASES = ("geometry", "normal", "identity", "accounting", "unwind", "stale",
         "unknown", "host_guards", "requester_bound", "allocation",
         "registration_owner", "close_stale_idle", "close_stale_active", "close_unknown",
         # Prototype for ASK.70: opt-in import of an exporter without a descriptor.
         "undescribed_import", "undescribed_guards", "undescribed_move",
         "undescribed_unknown", "undescribed_allocation", "close_undescribed_idle",
         "close_undescribed_active", "close_undescribed_unknown",
         # Implicit-sync fences: refused on the undescribed path only.
         "undescribed_fences", "described_fences")
# These headers provide only declarations normally supplied by Linux. The
# fixture injects their small kernel API boundary from kernel_shim.h. The
# production peer/importer public headers themselves are never replaced.
BOUNDARY_HEADERS = (
    "atomic.h", "capability.h", "cred.h", "dma-buf.h", "dma-direction.h", "dma-map-ops.h", "dma-mapping.h",
    "dma-resv.h", "err.h", "errno.h", "export.h", "file.h", "fs.h", "gfp.h",
    "kernel.h", "limits.h", "list.h", "mm.h", "mm_types.h", "module.h", "mutex.h",
    "overflow.h", "pci.h", "refcount.h", "resource.h", "scatterlist.h", "sched.h",
    "sched/mm.h", "sched/signal.h", "sched/user.h", "slab.h", "swiotlb.h", "types.h", "uidgid.h", "user.h",
    "vmalloc.h", "stddef.h", "string.h",
)


def command(argv, logs, cwd):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=60)
    logs.append("$ " + " ".join(map(str, argv)) + "\n" + result.stdout + result.stderr)
    return result


def function_source(source, name):
    """Copy one real C function verbatim, respecting strings and comments."""
    start = re.search(r"^static int " + re.escape(name) + r"\(", source, re.M)
    if not start:
        raise RuntimeError("missing actual close entry " + name)
    brace = source.index("{", start.start())
    depth, index = 1, brace + 1
    mode = "code"
    while index < len(source):
        c = source[index]
        following = source[index:index + 2]
        if mode == "code":
            if following == "/*":
                mode = "comment"
                index += 1
            elif following == "//":
                mode = "line"
                index += 1
            elif c in "\"'":
                mode = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if not depth:
                    return source[start.start():index + 1]
        elif mode == "comment" and following == "*/":
            mode = "code"
            index += 1
        elif mode == "line" and c == "\n":
            mode = "code"
        elif mode in ("\"", "'"):
            if c == "\\":
                index += 1
            elif c == mode:
                mode = "code"
        index += 1
    raise RuntimeError("unclosed actual close entry " + name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--compile-only", action="store_true")
    args = parser.parse_args()
    root = args.source_root.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    logs = []
    record = {"environment": "local host GCC kernel-boundary adapters",
              "scope": "actual peer/importer behavior, no native DMA/performance",
              "source_root": str(root), "cases": []}
    try:
        record.update(capture(root, PRODUCTION_INPUTS, args.output / "source-snapshot"))
        compile_root = Path(record["compile_source_root"])
        compile_here, record["fixture_provenance"] = capture_fixture(
            HERE, args.output / "test-snapshot")
        with tempfile.TemporaryDirectory(prefix="fixture-", dir=args.output) as temp:
            build = Path(temp)
            include = build / "include"
            for name in BOUNDARY_HEADERS:
                path = include / "linux" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("/* Test kernel boundary supplied by -include kernel_shim.h. */\n")
            # glibc errno.h may itself include linux/errno.h. Preserve actual
            # errno constants rather than suppressing them with an empty file.
            (include / "linux/errno.h").write_text("#include <asm-generic/errno.h>\n")
            flags = ["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                     "-Wno-unused-parameter", "-pthread", "-fsanitize=undefined",
                     "-include", str(compile_here / "kernel_shim.h"),
                     "-I", str(include), "-I", str(compile_here),
                     "-I", str(compile_root / "src/core"),
                     "-I", str(compile_root / "src/core/include")]
            close_path = compile_root / "src/core/io_uring/xdev_ext_peer_fd.c"
            if close_path.stat().st_size > 1024 * 1024:
                raise RuntimeError("unexpected oversized peer fd source")
            close_source = close_path.read_text()
            functions = "\n\n".join(function_source(close_source, name) for name in
                                     ("xdev_ext_peer_fd_close", "xdev_ext_peer_authority_close"))
            fd_source = build / "actual_fd_close.c"
            fd_source.write_text((compile_here / "fd_boundary.c.in").read_text().replace(
                "ACTUAL_CLOSE_FUNCTIONS\n", functions + "\n"))
            # Compile both test TUs before looking for the implementation. This
            # catches broken assertions/types in the independent fixture.
            for source in (compile_here / "kernel_shim.c", compile_here / "importer_cases.c", fd_source):
                result = command(flags + ["-DSHIM_CONTRACT_ONLY", "-c", str(source),
                                          "-o", str(build / (source.name + ".o"))], logs, root)
                if result.returncode:
                    raise RuntimeError("frozen-contract fixture did not compile")
            record["fixture_compile"] = "PASS"
            if args.fixture_only:
                record["verdict"] = "FIXTURE_COMPILES"
                code = 0
            else:
                production = [compile_root / "src/core/io_uring/xdev_ext_peer.c",
                              compile_root / "src/core/io_uring/xdev_ext_peer_dmabuf.c"]
                header = compile_root / "src/core/include/linux/xdev_ext_peer_dmabuf.h"
                missing = [str(p.relative_to(compile_root)) for p in [*production, header]
                           if not p.is_file()]
                if missing:
                    record.update(verdict="NOT_IMPLEMENTED", missing=missing)
                    code = 3
                else:
                    # Compile the real component as separate TUs. The only
                    # source inputs to its interfaces are its own public headers.
                    objects = []
                    for number, source in enumerate([compile_here / "kernel_shim.c", *production, fd_source,
                                                     compile_here / "importer_cases.c"]):
                        obj = build / f"unit-{number}.o"
                        result = command(flags + ["-c", str(source), "-o", str(obj)], logs, root)
                        if result.returncode:
                            raise RuntimeError("production interface/kernel-boundary compile failed")
                        objects.append(str(obj))
                    binary = build / "importer-test"
                    result = command(["gcc", "-pthread", "-fsanitize=undefined", *objects,
                                      "-o", str(binary)], logs, root)
                    if result.returncode:
                        raise RuntimeError("production link failed")
                    if args.compile_only:
                        record["verdict"] = "PRODUCTION_COMPILES"
                        code = 0
                    else:
                        for case in CASES:
                            result = command([str(binary), case], logs, root)
                            record["cases"].append({"case": case, "exit": result.returncode})
                        record["verdict"] = "FAIL" if any(c["exit"] for c in record["cases"]) else "PASS"
                        code = 1 if record["verdict"] == "FAIL" else 0
    except (RuntimeError, subprocess.SubprocessError, OSError) as error:
        record.update(verdict="SETUP_ERROR", error=str(error))
        code = 2
    (args.output / "output.log").write_text("\n".join(logs))
    (args.output / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))
    if code == 2:
        print("\n".join(logs)[-12000:])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
