#!/usr/bin/env python3
"""Build the DPDK net_af_xdp baseline (dpdk_tb) against a pinned DPDK release.

  build.py --build-dir DIR --gpu cuda --cuda-root CUDA [--jobs N] [--output BIN]
  build.py --build-dir DIR --gpu none                    host-memory stand-in
  build.py --print-commands --build-dir DIR ...          the plan as JSON; no effect

The release tarball is downloaded from fast.dpdk.org (or taken from
--tarball), its SHA-256 is checked, and DPDK is configured with meson using
the release's defaults except that only the three drivers the baseline needs
are built (net/af_xdp, mempool/ring, bus/vdev), plus testpmd for sanity
checks, as a static library installed under DIR/install.  dpdk_tb.c is then
linked with `pkg-config --static libdpdk`, as the DPDK documentation
recommends for applications.  net_af_xdp needs libxdp >= 1.2.2 and libbpf
(doc/guides/nics/af_xdp.rst of the release); without them meson silently
skips the driver, so the build checks that librte_net_af_xdp.a exists.

It also compiles tb_xsk_redirect.bpf.c into DIR/tb_xsk_redirect.o (clang
-target bpf; CLANG overrides the compiler), the xdp_prog= object that devices without native XDP, such
as thunderbolt-net, need (see that file).

`--gpu none` replaces the CUDA copies with host memcpy into an ordinary
buffer.  That build is for correctness runs on machines without a GPU (VM
guests); its records say gpu="none" and are never performance data.

DIR must be an absolute path outside this repository, absent (created mode
0700) or an existing directory of this user with mode 0700.  Nothing is
installed system-wide.

Exit: 0 built (one JSON receipt line), 1 build failed, 2 invalid arguments,
4 a missing tool or prerequisite.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
DPDK_VERSION = "24.11.8"
DPDK_URL = "https://fast.dpdk.org/rel/dpdk-%s.tar.xz" % DPDK_VERSION
# sha256sum of the tarball downloaded 2026-11-08 (Last-Modified 2026-10-14);
# fast.dpdk.org publishes no checksum file for it.
DPDK_SHA256 = "f3dbfac841b2db8e53a97d68a5e14ebc943327a955f0afb97f8c14f544fbc4aa"
DPDK_TOPDIR = "dpdk-stable-%s" % DPDK_VERSION
DRIVERS = "net/af_xdp,mempool/ring,bus/vdev"
WARN = ("-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
PROG_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")


class Refusal(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


def meson_options():
    return ["-Ddefault_library=static", "-Dbuildtype=release",
            "-Denable_drivers=" + DRIVERS, "-Denable_apps=test-pmd", "-Dtests=false",
            "-Denable_docs=false", "--libdir=lib"]


def vdev_arg(iface, xdp_prog=None):
    """The EAL --vdev value: one AF_XDP socket on queue 0, every other PMD option default.

    xdp_prog (absolute path of tb_xsk_redirect.o) is for devices without
    native XDP, such as thunderbolt-net: see tb_xsk_redirect.bpf.c for why
    the PMD's default program cannot attach there.
    """
    if not IFACE_RE.match(iface):
        raise ValueError("bad interface name %r" % iface)
    arg = "net_af_xdp0,iface=%s,start_queue=0,queue_count=1" % iface
    if xdp_prog is not None:
        if not PROG_RE.match(xdp_prog):
            raise ValueError("xdp_prog must be an absolute path without commas: %r" % xdp_prog)
        arg += ",xdp_prog=" + xdp_prog
    return arg


def bpf_command(src, obj):
    # -target bpf drops the host's multiarch include dir, where asm/types.h lives
    multiarch = sysconfig.get_config_var("MULTIARCH") or "x86_64-linux-gnu"
    return [os.environ.get("CLANG", "clang"), "-O2", "-g", "-Wall", "-Werror", "-target", "bpf",
            "-I/usr/include/" + multiarch, "-c", str(src), "-o", str(obj)]


def check_dir(path):
    path = Path(path)
    if not path.is_absolute():
        raise Refusal(2, "--build-dir must be absolute: %s" % path)
    resolved = path.resolve()
    if resolved == REPO or REPO in resolved.parents:
        raise Refusal(2, "--build-dir must be outside the repository: %s" % path)
    if path.exists():
        st = path.stat()
        if not path.is_dir() or st.st_uid != os.getuid() or st.st_mode & 0o777 != 0o700:
            raise Refusal(2, "%s must be a mode-0700 directory of this user" % path)
    return path


def plan(args):
    d = Path(args.build_dir)
    tarball = Path(args.tarball) if args.tarball else d / ("dpdk-%s.tar.xz" % DPDK_VERSION)
    install = d / "install"
    if args.gpu == "cuda":
        backend = [str(HERE / "tb_gpu_cuda.c"), "-I" + str(Path(args.cuda_root) / "include")]
        extra_libs = ["-L" + str(Path(args.cuda_root) / "lib64"), "-lcudart",
                      "-Wl,-rpath," + str(Path(args.cuda_root) / "lib64")]
        default_out = d / "dpdk_tb"
    else:
        backend = [str(HERE / "tb_gpu_host.c")]
        extra_libs = []
        default_out = d / "dpdk_tb-host"
    output = Path(args.output) if args.output else default_out
    steps = []
    if not args.tarball:
        steps.append({"step": "download",
                      "argv": ["curl", "-fsSL", "--retry", "2", "-o", str(tarball), DPDK_URL]})
    else:
        steps.append({"step": "download", "argv": [], "note": "using --tarball"})
    steps += [
        {"step": "verify", "path": str(tarball), "sha256": DPDK_SHA256},
        {"step": "extract", "argv": ["tar", "-C", str(d), "-xf", str(tarball)]},
        {"step": "meson", "argv": ["meson", "setup", str(d / "build"), str(d / DPDK_TOPDIR),
                                   "--prefix=" + str(install), *meson_options()]},
        {"step": "ninja", "argv": ["ninja", "-C", str(d / "build"), "-j%d" % args.jobs,
                                   "install"]},
        {"step": "compile",
         "argv": [os.environ.get("CC", "cc"), *WARN, "-I" + str(HERE),
                  str(HERE / "dpdk_tb.c"), *backend, "-o", str(output)],
         "pkg_config": ["pkg-config", "--static", "--cflags", "--libs", "libdpdk"],
         "env": {"PKG_CONFIG_PATH": str(install / "lib" / "pkgconfig")},
         "extra_libs": extra_libs + ["-lbpf"]},
        {"step": "bpf", "argv": bpf_command(HERE / "tb_xsk_redirect.bpf.c",
                                            d / "tb_xsk_redirect.o")},
    ]
    return {"dpdk_version": DPDK_VERSION, "url": DPDK_URL, "sha256": DPDK_SHA256,
            "gpu": args.gpu, "output": str(output), "xdp_prog": str(d / "tb_xsk_redirect.o"),
            "steps": steps}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run_step(step, log):
    with open(log, "ab") as out:
        out.write(("$ %s\n" % shlex.join(step["argv"])).encode())
        out.flush()
        return subprocess.run(step["argv"], stdout=out, stderr=subprocess.STDOUT,
                              env=step.get("full_env")).returncode


def execute(p, args):
    d = Path(args.build_dir)
    for tool in ("meson", "ninja", "pkg-config", "tar", os.environ.get("CC", "cc")):
        if not shutil.which(tool):
            raise Refusal(4, "missing tool: %s" % tool)
    if not d.exists():
        d.mkdir(mode=0o700, parents=False)
        os.chmod(d, 0o700)
    log = d / "build.log"
    for step in p["steps"]:
        name = step["step"]
        if name == "download":
            if step["argv"] and not Path(step["argv"][5]).exists():
                if run_step(step, log):
                    raise Refusal(4, "download failed, see %s" % log)
        elif name == "verify":
            got = sha256(step["path"])
            if got != step["sha256"]:
                raise Refusal(4, "sha256 mismatch for %s: %s" % (step["path"], got))
        elif name == "extract":
            if not (d / DPDK_TOPDIR).is_dir() and run_step(step, log):
                raise Refusal(4, "extract failed, see %s" % log)
        elif name == "meson":
            if not (d / "build" / "build.ninja").exists() and run_step(step, log):
                raise Refusal(4, "meson setup failed (DPDK prerequisites?), see %s" % log)
        elif name == "ninja":
            if run_step(step, log):
                raise Refusal(4, "DPDK build failed, see %s" % log)
            if not (d / "install" / "lib" / "librte_net_af_xdp.a").exists():
                raise Refusal(4, "meson skipped net_af_xdp (needs libxdp >= 1.2.2 and "
                                 "libbpf); see %s" % (d / "build" / "meson-logs"))
        elif name == "compile":
            env = dict(os.environ, **step["env"])
            pc = subprocess.run(step["pkg_config"], capture_output=True, text=True, env=env)
            if pc.returncode:
                raise Refusal(4, "pkg-config libdpdk failed: %s" % pc.stderr.strip())
            argv = step["argv"] + shlex.split(pc.stdout) + step["extra_libs"]
            if run_step({"argv": argv, "full_env": env}, log):
                raise Refusal(1, "dpdk_tb failed to compile, see %s" % log)
        elif name == "bpf":
            if not shutil.which(step["argv"][0]):
                raise Refusal(4, "missing tool: %s (for tb_xsk_redirect.o; set CLANG)"
                              % step["argv"][0])
            if run_step(step, log):
                raise Refusal(1, "tb_xsk_redirect.bpf.c failed to compile, see %s" % log)
    out = Path(p["output"])
    return {"built": str(out), "sha256": sha256(out), "dpdk_version": DPDK_VERSION,
            "dpdk_sha256": DPDK_SHA256, "gpu": p["gpu"], "xdp_prog": p["xdp_prog"],
            "log": str(log)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--gpu", choices=("cuda", "none"), default="cuda")
    ap.add_argument("--cuda-root")
    ap.add_argument("--tarball")
    ap.add_argument("--output")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--print-commands", action="store_true")
    args = ap.parse_args()
    try:
        check_dir(args.build_dir)
        if args.gpu == "cuda" and not args.cuda_root:
            raise Refusal(2, "--gpu cuda needs --cuda-root")
        if args.jobs < 1:
            raise Refusal(2, "--jobs must be positive")
        p = plan(args)
        if args.print_commands:
            print(json.dumps(p, indent=1))
            return 0
        print(json.dumps(execute(p, args)))
        return 0
    except Refusal as e:
        print("dpdk_tb build: %s" % e, file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main())
