#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""System-heap DMA-BUF as the PEER frame pool of an XDOMAIN stage's NHI requester.

Compiles, unchanged, the production requester bind (family/xdev_ext_requester.c),
peer region core, DMA-BUF importer, peer fd unit (REGISTER, claim, describe,
premap, acquire, release), PEER pool bind, and the system heap's describe hook.
Kernel services come from tests/core/peer_dmabuf/kernel_shim.{h,c}; this runner
only extends that header's pci_dev and file_operations declarations. Exit 0 PASS,
1 behaviour FAIL, 2 SETUP_ERROR. Host software only: no DMA, NHI or kernel run.

--mutation NAME applies one documented source change to a private copy and runs
the case that must detect it; KILLED requires a named DMABUF_REQ_ASSERT.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
CASES = ("nhi_admitted", "shared_pool", "untrusted", "swiotlb", "noncoherent",
         "need_sync", "unregistered_exporter")
SHIM = "tests/core/peer_dmabuf"
# Linux headers the units include; each is an empty file and the shim supplies
# the declarations (same rule as tests/core/peer_dmabuf/importer_run.py).
BOUNDARY_HEADERS = (
    "anon_inodes.h", "atomic.h", "capability.h", "compat.h", "compiler.h", "container_of.h",
    "cred.h", "dma-buf.h", "dma-direction.h", "dma-map-ops.h", "dma-mapping.h", "dma-resv.h",
    "err.h", "export.h", "file.h", "fs.h", "gfp.h", "init.h", "iommu-dma.h", "kernel.h",
    "limits.h", "list.h", "miscdevice.h", "mm.h", "mm_types.h", "module.h", "mutex.h",
    "overflow.h", "pci.h", "pci-p2pdma.h", "refcount.h", "resource.h", "scatterlist.h",
    "sched.h", "sched/mm.h", "sched/signal.h", "sched/user.h", "slab.h", "swiotlb.h",
    "types.h", "uaccess.h", "uidgid.h", "user.h", "vmalloc.h", "stddef.h", "string.h",
    "build_bug.h", "bits.h", "bitops.h", "printk.h", "bug.h", "workqueue.h", "spinlock.h",
)
# One anchor each; a changed upstream shim fails SETUP rather than drifting.
SHIM_EDITS = (
    ("struct pci_dev { struct device dev; unsigned refs, id; unsigned int untrusted:1; };",
     "struct pci_bus { unsigned char number; };\n"
     "struct pci_dev { struct device dev; unsigned refs, id; unsigned int untrusted:1;\n"
     " struct pci_bus *bus; unsigned int devfn; };"),
    ("struct file_operations { int (*release)(struct inode *, struct file *); };",
     "struct module;\nstruct file_operations { struct module *owner;\n"
     " int (*release)(struct inode *, struct file *);\n"
     " long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);\n"
     " long (*compat_ioctl)(struct file *, unsigned int, unsigned long); };"),
)
MUTATIONS = {
    # Host RAM is admitted only through its HOST_SYSTEM branch.
    "admit-host-as-unknown": ("io_uring/family/xdev_ext_requester.c", "nhi_admitted",
        "f.backing = ret ? 0 : back.flags;", "f.backing = 0;"),
    # The data path needs the requester's mapping established at bind.
    "skip-premap": ("io_uring/family/xdev_ext_requester.c", "nhi_admitted",
        "ret = xdev_ext_peer_file_premap(rq->authority, pdev);", "ret = 0;"),
    # A mapping that needs CPU synchronisation is unusable for zero copy.
    "accept-need-sync": ("io_uring/xdev_ext_peer_dmabuf.c", "need_sync",
        "if (dma_need_sync(&peer->dev, sg_dma_address(sg))) {", "if (0) {"),
    # A lease must use the requester's own attachment.
    "lease-first-mapping": ("io_uring/xdev_ext_peer_fd.c", "shared_pool",
        "  if (m->peer == peer) goto acquire;", "  goto acquire;"),
}


class Setup(Exception):
    pass


def load_layout(root):
    sys.path.insert(0, str(root / "tools"))
    import layout  # noqa: E402
    return layout.load_layout(root)


def assemble(root, out, mutation):
    """Native linux paths for the units this test compiles."""
    layout = load_layout(root)
    kernel = out / "source/kernel"
    if kernel.exists():
        shutil.rmtree(kernel)
    hashes = {}
    for (component, native), source in layout.by_native.items():
        if component != "linux" or not native.startswith(("include/", "io_uring/", "drivers/dma-buf/")):
            continue
        destination = kernel / native
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, destination)
        hashes[native] = hashlib.sha256((root / source).read_bytes()).hexdigest()
    if mutation:
        native, _case, old, new = MUTATIONS[mutation]
        path = kernel / native
        text = path.read_text()
        if text.count(old) != 1:
            raise Setup("mutation anchor count for " + mutation)
        path.write_text(text.replace(old, new, 1))
    return kernel, hashes


def definition(text, name):
    match = re.search(r"^\w[^;{}]*\b" + re.escape(name) + r"\([^;{}]*\)\n\{\n.*?^\}", text, re.M | re.S)
    if not match:
        raise Setup("missing production definition " + name)
    return match[0]


def initializer(text, name):
    match = re.search(r"^static const struct \w+ " + re.escape(name) + r" = \{\n.*?^\};", text, re.M | re.S)
    if not match:
        raise Setup("missing production initializer " + name)
    return match[0]


# Kernel-tree files this script extracts code from (the compiler then reads the
# generated units, so its dependency files do not name these).
DIRECT_READS = ("drivers/dma-buf/heaps/system_heap.c", "io_uring/xdev_ext_mech.c")


def read_inputs(root, out, kernel, hashes):
    """Every input of this run: kernel-tree files the compiler opened (gcc -MD) or this
    script extracted from, keyed by native path with the hash of the source-tree file
    (before any mutation), and the test files and templates this script read."""
    production, tests = {}, {}

    def add(path):
        path = Path(path).resolve()
        for base, table in ((kernel, production), (root, tests)):
            try:
                key = str(path.relative_to(base))
            except ValueError:
                continue
            if table is tests and (out == path or out in path.parents):
                return  # generated from inputs recorded elsewhere
            table[key] = hashes[key] if table is production and key in hashes else \
                hashlib.sha256(path.read_bytes()).hexdigest()
            return

    for dep in sorted((out / "build").rglob("*.d")):
        for item in dep.read_text().replace("\\\n", " ").split(":", 1)[-1].split():
            add(item)
    for native in DIRECT_READS:
        add(kernel / native)
    for f in [f for f in HERE.iterdir() if f.is_file()] + [root / SHIM / "kernel_shim.h", root / SHIM / "kernel_shim.c"]:
        add(f)
    return dict(sorted(production.items())), dict(sorted(tests.items()))


def build(root, out, mutation, sanitize):
    kernel, hashes = assemble(root, out, mutation)
    build_dir = out / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    include = build_dir / "include"
    for name in BOUNDARY_HEADERS:
        path = include / "linux" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("/* kernel boundary supplied by kernel_shim.h and boundary.h */\n")
    (include / "linux/errno.h").write_text("#include <asm-generic/errno.h>\n")
    (include / "asm").mkdir(parents=True, exist_ok=True)
    (include / "asm/page.h").write_text("/* PAGE_* from kernel_shim.h */\n")
    shim_dir = build_dir / "shim"
    shim_dir.mkdir()
    shim = (root / SHIM / "kernel_shim.h").read_text()
    for old, new in SHIM_EDITS:
        if shim.count(old) != 1:
            raise Setup("kernel_shim.h anchor changed: " + old[:60])
        shim = shim.replace(old, new, 1)
    (shim_dir / "kernel_shim.h").write_text(shim)
    shutil.copyfile(root / SHIM / "kernel_shim.c", shim_dir / "kernel_shim.c")
    heap = (kernel / "drivers/dma-buf/heaps/system_heap.c").read_text()
    (build_dir / "heap_unit.c").write_text((HERE / "heap_unit.c.in").read_text().replace(
        "SYSTEM_HEAP_DESCRIBE", definition(heap, "system_heap_xdev_ext_describe") + "\n" +
        initializer(heap, "system_heap_xdev_ext_desc")))
    core = (kernel / "io_uring/xdev_ext_mech.c").read_text()
    (build_dir / "core_unit.c").write_text((HERE / "core_unit.c.in").read_text().replace(
        "CORE_FRAME_MOVE", definition(core, "xdev_ext_mech_pool_frame_move")))
    (build_dir / "fd_unit.c").write_text((HERE / "fd_unit.c.in").read_text().replace(
        "PEER_FD_SOURCE", '"' + str(kernel / "io_uring/xdev_ext_peer_fd.c") + '"'))
    cc = os.environ.get("CC", "gcc")
    flags = [cc, "-std=gnu11", "-g", "-O0", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
             "-Wno-missing-field-initializers", "-pthread",
             "-include", str(shim_dir / "kernel_shim.h"), "-include", str(HERE / "boundary.h"),
             "-I", str(include), "-I", str(shim_dir), "-I", str(HERE),
             "-I", str(kernel / "io_uring"), "-I", str(kernel / "include"),
             "-I", str(kernel)]
    if sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]
    units = [shim_dir / "kernel_shim.c", kernel / "io_uring/xdev_ext_peer.c",
             kernel / "io_uring/xdev_ext_peer_dmabuf.c", build_dir / "fd_unit.c",
             kernel / "io_uring/family/xdev_ext_requester.c",
             kernel / "io_uring/xdev_ext_mech_peer_pool.c", build_dir / "core_unit.c",
             build_dir / "heap_unit.c", HERE / "boundary.c", HERE / "cases.c"]
    objects, log = [], []
    for number, unit in enumerate(units):
        obj = build_dir / f"unit-{number}.o"
        result = subprocess.run(flags + ["-MD", "-MF", str(obj) + ".d", "-c", str(unit), "-o", str(obj)],
                                capture_output=True,
                                text=True, timeout=120)
        log.append("$ cc -c " + str(unit) + "\n" + result.stdout + result.stderr)
        if result.returncode:
            (out / "compile.log").write_text("\n".join(log))
            raise Setup("compile failed: " + str(unit) + "\n" + result.stderr[-4000:])
        objects.append(str(obj))
    binary = build_dir / "dmabuf-requester"
    link = [cc, "-pthread"] + (["-fsanitize=address,undefined"] if sanitize else []) + objects + ["-o", str(binary)]
    result = subprocess.run(link, capture_output=True, text=True, timeout=120)
    log.append("$ link\n" + result.stdout + result.stderr)
    (out / "compile.log").write_text("\n".join(log))
    if result.returncode:
        raise Setup("link failed\n" + result.stderr[-4000:])
    return binary, hashes, kernel


def run_cases(binary, out, cases):
    results = []
    for name in cases:
        run = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=60)
        (out / (name + ".log")).write_text(run.stdout + run.stderr + "\nexit=%d\n" % run.returncode)
        marker = "DMABUF_REQ_CASE " + name + " assertions="
        counted = [int(l[len(marker):]) for l in run.stdout.splitlines() if l.startswith(marker)]
        results.append(dict(case=name, exit=run.returncode,
                            assertions=counted[-1] if counted else 0,
                            passed=run.returncode == 0 and bool(counted) and counted[-1] > 0,
                            failed_assertion=next((l for l in run.stderr.splitlines()
                                                   if l.startswith("DMABUF_REQ_ASSERT")), None)))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--mutation", choices=sorted(MUTATIONS))
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    record = dict(scope="host software: real requester bind, peer region core, DMA-BUF importer, "
                  "peer fd unit, PEER pool bind and system-heap describe; kernel services and the "
                  "exporter are tests/core/peer_dmabuf kernel_shim stand-ins; no DMA/NHI/kernel run",
                  source_root=str(root), mutation=args.mutation, sanitize=args.sanitize)
    try:
        record["head"] = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                        capture_output=True, text=True).stdout.strip()
        binary, hashes, kernel = build(root, out, args.mutation, args.sanitize)
        record["inputs_sha256"], record["test_inputs_sha256"] = read_inputs(root, out, kernel, hashes)
        record["inputs_rule"] = ("inputs_sha256: kernel-tree files the compiler opened (gcc -MD) or the runner "
                                 "extracted from, hashed in the source tree before any mutation; "
                                 "test_inputs_sha256: test files and templates the runner read")
        cases = [MUTATIONS[args.mutation][1]] if args.mutation else ([args.case] if args.case else list(CASES))
        record["cases"] = run_cases(binary, out, cases)
        if args.mutation:
            killed = all(not c["passed"] and c["exit"] == 1 and c["failed_assertion"] for c in record["cases"])
            record["verdict"] = "KILLED" if killed else "SURVIVED"
            code = 0 if killed else 1
        else:
            record["verdict"] = "PASS" if all(c["passed"] for c in record["cases"]) else "FAIL"
            code = 0 if record["verdict"] == "PASS" else 1
    except (Setup, OSError, subprocess.SubprocessError) as error:
        record.update(verdict="SETUP_ERROR", error=str(error))
        code = 2
    (out / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    for case in record.get("cases", []):
        print(("ok" if case["passed"] else "not ok") + " - " + case["case"] +
              " assertions=%d exit=%d" % (case["assertions"], case["exit"]) +
              ("" if case["passed"] else " " + str(case["failed_assertion"])))
    print("DMABUF_REQ_VERDICT " + record["verdict"] + ("" if code != 2 else " " + record.get("error", "")[:3000]))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
