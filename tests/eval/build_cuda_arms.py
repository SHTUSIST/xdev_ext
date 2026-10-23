#!/usr/bin/env python3
"""Build every CUDA arm of tests/eval with one official CUDA SDK; run none.

  build_cuda_arms.py --cuda-home /usr/local/cuda-12.8 --out DIR [--arch sm_80]
                     [--only NAME,...]

Only CUDA_HOME/bin/nvcc is used (an nvcc elsewhere on PATH is ignored), so
the receipt names exactly one SDK.  Every .cu and .cc arm compiles and links
through that nvcc; bench_cuda_staging.c, which loads libcuda with dlopen,
builds with the host C compiler.  The driver entry points that the dlopen
users (chains/chain_cuda.h, bench_cuda_staging.c,
kernel/tools/xdev_ext_mech/xdev_ext_mech_cuda.h) look up by name are checked
against the SDK's driver stub CUDA_HOME/lib64/stubs/libcuda.so (exported
names only; prototypes are not compared).

DIR/cuda-arms-receipt.json records the nvcc version and hash, every command,
every source and output SHA-256 and every arm's status; the same status line
is printed on stdout.  Exit: 0 every arm built and every symbol found,
1 a build failed or a symbol is missing, 2 usage, 4 nvcc absent (nothing is
written) or an arm's SDK component (cuFile, liburing, libbpf) unavailable.
"""
import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[1] / "kernel"
SCHEMA = "cuda-arms-build-v1"
CU_HOST_FLAGS = "-O2,-Wall,-Wextra,-Wno-missing-field-initializers,-msse4.2"
CC_HOST_FLAGS = "-Wall,-Wextra,-Werror"
SYMBOL_SOURCES = (HERE / "chains/chain_cuda.h", HERE / "bench_cuda_staging.c",
                  KERNEL / "tools/xdev_ext_mech/xdev_ext_mech_cuda.h")


@dataclass
class Toolchain:
    cuda_home: Path
    nvcc: Path
    arch: str
    cc: list
    cufile_dir: Path = None		# directory holding libcufile.so, if any
    uring: list = None		# liburing flags, if available
    bpf: list = None		# libbpf link flags, if available


@dataclass
class Arm:
    name: str
    sources: tuple			# relative to tests/eval
    kind: str			# "cu", "cc" or "host-c"
    needs: tuple = ()		# "cufile", "uring", "bpf"
    headers: tuple = ("cuda_runtime_api.h",)
    defines: tuple = ()
    extra: tuple = field(default_factory=tuple)

    def unavailable(self, tc):
        for header in self.headers:
            if not (tc.cuda_home / "include" / header).is_file():
                return "official %s unavailable under %s/include" % (header, tc.cuda_home)
        if "cufile" in self.needs and not tc.cufile_dir:
            return "libcufile.so unavailable in this SDK"
        if "uring" in self.needs and tc.uring is None:
            return "liburing development files unavailable (pkg-config liburing)"
        if "bpf" in self.needs and tc.bpf is None:
            return "libbpf development files unavailable (pkg-config libbpf)"
        return None

    def commands(self, tc, out):
        output = str(out / self.name)
        srcs = [str(HERE / s) for s in self.sources]
        if self.kind == "host-c":
            return [[*tc.cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-D_FILE_OFFSET_BITS=64",
                     *srcs, "-o", output, "-ldl"]]
        steps, objects, libs = [], [], []
        if "bpf" in self.needs:
            obj = str(out / (self.name + ".xdev_ext_xsk_redirect.o"))
            steps.append([*tc.cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-c",
                          str(KERNEL / "tools/xdev_ext_xsk_redirect.c"), "-o", obj])
            objects.append(obj)
            libs += tc.bpf
        if "uring" in self.needs:
            libs += tc.uring
        if "cufile" in self.needs:
            libs += ["-L" + str(tc.cufile_dir), "-lcufile"]
        command = [str(tc.nvcc), "-std=c++17", "-O2", "--cudart=shared", *self.defines,
                   "-I" + str((HERE / self.sources[0]).parent)]
        if self.kind == "cu":
            command += ["-arch=" + tc.arch, "-Xcompiler", CU_HOST_FLAGS]
        else:
            command += ["-Xcompiler", CC_HOST_FLAGS]
        steps.append(command + srcs + objects + ["-o", output] + libs)
        return steps


ARMS = (
    Arm("afxdp_cuda", ("gpu_nic/afxdp_cuda.cu",), "cu", needs=("bpf",)),
    Arm("udp_pinned_cuda", ("gpu_nic/udp_pinned_cuda.cu",), "cu"),
    Arm("bench_uring_cuda", ("nvme_gpu/bench_uring_cuda.cc",), "cc", needs=("uring",)),
    Arm("bench_cufile_batch", ("nvme_gpu/bench_cufile_batch.cc",), "cc", needs=("cufile",),
        headers=("cuda_runtime_api.h", "cufile.h")),
    Arm("bench_cufile", ("gds/bench_cufile.cc",), "cc", needs=("cufile",),
        headers=("cuda.h", "cuda_runtime_api.h", "cufile.h"), defines=("-D_FILE_OFFSET_BITS=64",)),
    Arm("bench_host_compute", ("cuda_host_compute/bench_host_compute.cu",), "cu",
        headers=("cuda_runtime.h",)),
    Arm("bench_cuda_staging", ("bench_cuda_staging.c",), "host-c", headers=()),
)
# host_fixture.cpp (cuda_host_compute) is the SDK-free host twin of the CUDA
# arm and builds in its own host tests; it is not a CUDA arm.
NOT_ARMS = ("cuda_host_compute/host_fixture.cpp",)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def driver_symbols():
    names = set()
    for path in SYMBOL_SOURCES:
        names.update(re.findall(r'"(cu[A-Z][A-Za-z0-9_]*)"', path.read_text()))
    return sorted(names)


def pkg_flags(name):
    if not shutil.which("pkg-config"):
        return None
    out = subprocess.run(["pkg-config", "--cflags", "--libs", name], capture_output=True, text=True)
    return shlex.split(out.stdout) if not out.returncode else None


def find_lib(home, stem):
    for libdir in (home / "lib64", home / "lib", home / "targets/x86_64-linux/lib"):
        if any(p.is_file() for p in libdir.glob(stem + "*")):
            return libdir
    return None


def exported(library):
    if not shutil.which("nm"):
        return None
    out = subprocess.run(["nm", "-D", "--defined-only", str(library)], capture_output=True, text=True)
    if out.returncode:
        return None
    return {line.split()[-1] for line in out.stdout.splitlines() if line.split()}


def check_symbols(home):
    names = driver_symbols()
    stub = next((p for p in (home / "lib64/stubs/libcuda.so",
                             home / "targets/x86_64-linux/lib/stubs/libcuda.so") if p.is_file()), None)
    result = dict(sources=[dict(path=str(p.relative_to(HERE.parents[1])), sha256=sha256(p))
                           for p in SYMBOL_SOURCES], symbols=names, prototypes_compared=False)
    if not stub:
        return dict(result, status="unavailable", library=None, missing=names,
                    reason="driver stub lib64/stubs/libcuda.so unavailable")
    found = exported(stub)
    if found is None:
        return dict(result, status="unavailable", library=str(stub), missing=names,
                    reason="nm cannot read the driver stub")
    missing = [n for n in names if n not in found]
    return dict(result, status="failed" if missing else "found", library=str(stub),
                library_sha256=sha256(stub), missing=missing)


def build_arm(arm, tc, out):
    record = dict(name=arm.name, kind=arm.kind,
                  sources=[dict(path=s, sha256=sha256(HERE / s)) for s in arm.sources])
    reason = arm.unavailable(tc)
    if reason:
        return dict(record, status="unavailable", reason=reason)
    record["commands"] = arm.commands(tc, out)
    # Built into a private directory, renamed only when every step passed.
    with tempfile.TemporaryDirectory(prefix="." + arm.name + "-", dir=out) as tmp:
        for step in arm.commands(tc, Path(tmp)):
            try:
                result = subprocess.run(step, capture_output=True, text=True, timeout=600)
            except FileNotFoundError as error:
                return dict(record, status="unavailable", reason="tool unavailable: %s" % error.filename)
            if result.returncode:
                return dict(record, status="failed", log=(result.stdout + result.stderr)[-4000:])
        final = out / arm.name
        os.replace(Path(tmp) / arm.name, final)
    return dict(record, status="built", output=str(final), output_sha256=sha256(final))


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0], allow_abbrev=False)
    p.add_argument("--cuda-home", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--arch", default="sm_80")
    p.add_argument("--only", default="")
    a = p.parse_args(argv)
    if not re.fullmatch(r"sm_[0-9]{2,3}[af]?", a.arch):
        p.error("--arch takes an explicit sm_NN architecture")
    only = [x for x in a.only.split(",") if x]
    if set(only) - {arm.name for arm in ARMS}:
        p.error("--only takes: " + ",".join(arm.name for arm in ARMS))
    home = a.cuda_home.resolve()
    nvcc = home / "bin/nvcc"
    if not (nvcc.is_file() and os.access(nvcc, os.X_OK)):
        print(json.dumps(dict(schema=SCHEMA, status="unavailable", cuda_home=str(home),
                              reason="nvcc absent: %s is not an executable file" % nvcc)))
        return 4
    version = subprocess.run([str(nvcc), "--version"], capture_output=True, text=True)
    a.out.mkdir(parents=True, exist_ok=True)
    out = a.out.resolve()
    tc = Toolchain(cuda_home=home, nvcc=nvcc, arch=a.arch,
                   cc=shlex.split(os.environ.get("CC", "cc")),
                   cufile_dir=find_lib(home, "libcufile.so"),
                   uring=pkg_flags("liburing"), bpf=pkg_flags("libbpf"))
    if tc.bpf is not None:
        tc.bpf = tc.bpf + ["-lelf", "-lz"]
    arms = [build_arm(arm, tc, out) for arm in ARMS if not only or arm.name in only]
    symbols = check_symbols(home)
    statuses = {arm["status"] for arm in arms} | {symbols["status"]}
    status = "failed" if "failed" in statuses else "unavailable" if "unavailable" in statuses else "built"
    receipt = dict(schema=SCHEMA, status=status, execution="not-run", cuda_home=str(home),
                   nvcc=str(nvcc), nvcc_sha256=sha256(nvcc),
                   nvcc_version=(version.stdout + version.stderr).strip(), arch=a.arch,
                   host_cc=tc.cc, arms=arms, driver_symbols=symbols, not_arms=list(NOT_ARMS))
    (out / "cuda-arms-receipt.json").write_text(json.dumps(receipt, indent=1) + "\n")
    print(json.dumps(dict(schema=SCHEMA, status=status, receipt=str(out / "cuda-arms-receipt.json"),
                          built=sorted(x["name"] for x in arms if x["status"] == "built"),
                          not_built={x["name"]: x.get("reason", x["status"]) for x in arms
                                     if x["status"] != "built"},
                          missing_symbols=symbols.get("missing", []))))
    return {"built": 0, "failed": 1, "unavailable": 4}[status]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
