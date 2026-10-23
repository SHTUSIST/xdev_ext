#!/usr/bin/env python3
"""Build the SPDK pipeline: the offline host fixture, or the native arm.

  build.py --output BIN                        offline host fixture (no SPDK)
  build.py --output BIN --spdk-root DIR        native arm against an SPDK tree
                                               that is already built
  build.py --fetch-sdk --build-dir DIR [--jobs N] [--output BIN]
                                               clone the pinned official SPDK
                                               release into DIR/spdk, build it,
                                               then build the native arm
                                               (default BIN: DIR/bench_nvme_pipeline)
  build.py --print-commands --build-dir DIR    the commands, as JSON; no effect

DIR must be an absolute path outside this repository, absent (it is created
mode 0700) or an existing directory of this user with mode 0700.  Nothing is
installed system-wide: SPDK's scripts/pkgdep.sh and setup.sh are never run, so
the build needs SPDK's build prerequisites (meson, ninja, pyelftools, libnuma,
libuuid, ...) to be present already; a failed SDK build is reported as
unavailable (exit 4) with its log path.  Linking follows SPDK's own
doc/pkgconfig.md recipe for the static nvme library.

Exit: 0 built (native: one JSON receipt line on stdout), 1 the arm failed to
compile, 2 invalid arguments, 4 a missing tool, SDK or SDK prerequisite.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = HERE / "bench_nvme_pipeline.c"
SPDK_URL = "https://github.com/spdk/spdk"
SPDK_TAG = "v25.05.1"
# Peeled commit of the tag (git ls-remote --tags, 2026-10-22).
SPDK_COMMIT = "44b23be7c35469bc0aba4b942c08c935125e2315"
# configure requires ISA-L on x86_64; DPDK is the environment layer.
SPDK_SUBMODULES = ("dpdk", "isa-l")
CONFIGURE_FLAGS = ("--disable-tests", "--disable-unit-tests", "--disable-examples",
                   "--disable-apps", "--without-shared", "--without-crypto",
                   "--without-vhost", "--without-virtio", "--without-vfio-user",
                   "--without-xnvme", "--without-rbd", "--without-rdma", "--without-ublk",
                   "--without-iscsi-initiator")
PKG_MODULES = ("spdk_nvme", "spdk_env_dpdk")
WARN = ("-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror")


class Refusal(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


def clone_command(src):
    return ["git", "clone", "--quiet", "--depth", "1", "--branch", SPDK_TAG,
            "--config", "advice.detachedHead=false", SPDK_URL, str(src)]


def submodule_command(src):
    return ["git", "-C", str(src), "submodule", "update", "--init", "--depth", "1",
            *SPDK_SUBMODULES]


def configure_command(src):
    return [str(src / "configure"), *CONFIGURE_FLAGS]


def make_command(src, jobs):
    return ["make", "-C", str(src), "-j%d" % jobs]


def pkg_config_path(root):
    return str(root / "build/lib/pkgconfig")


def native_command(cc, root, output, spdk_libs, sys_libs):
    """The arm against the built tree, as doc/pkgconfig.md links static nvme."""
    return [*cc, *WARN, "-DXDEV_EXT_SPDK_NATIVE", "-I" + str(root / "include"),
            str(SOURCE), "-o", str(output), "-pthread",
            "-Wl,--whole-archive", "-Wl,-Bstatic", *shlex.split(spdk_libs),
            "-Wl,-Bdynamic", "-Wl,--no-whole-archive", *shlex.split(sys_libs)]


def offline_command(cc, output):
    return [*cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
            str(SOURCE), "-o", str(output)]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_dir(text):
    """An absolute directory outside the repository, absent or 0700 and ours."""
    path = Path(text)
    if not path.is_absolute():
        raise Refusal(2, "--build-dir must be an absolute path")
    resolved = path.resolve()
    if resolved == REPO or REPO in resolved.parents:
        raise Refusal(2, "--build-dir must be outside the repository (%s)" % REPO)
    if path.is_symlink():
        raise Refusal(2, "--build-dir must not be a symbolic link")
    if path.exists():
        info = path.stat()
        if not path.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refusal(2, "--build-dir exists but is not a private (0700) directory of this user")
    return path


def need_tools(names):
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise Refusal(4, "required tool unavailable: " + ", ".join(missing))


def run_logged(command, log, cwd=None):
    with open(log, "ab") as out:
        out.write(("$ " + shlex.join(command) + "\n").encode())
        out.flush()
        return subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, cwd=cwd).returncode


def git_head(src):
    head = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                          capture_output=True, text=True)
    return head.stdout.strip() if not head.returncode else None


def fetch_sdk(build_dir, jobs):
    """Clone (or reuse) the pinned release in build_dir/spdk and build it."""
    src = build_dir / "spdk"
    log = build_dir / "spdk-build.log"
    if src.exists():
        if git_head(src) != SPDK_COMMIT:
            raise Refusal(2, "%s exists and is not SPDK %s (%s)" % (src, SPDK_TAG, SPDK_COMMIT))
    else:
        if run_logged(clone_command(src), log):
            raise Refusal(4, "cannot fetch SPDK %s from %s; see %s" % (SPDK_TAG, SPDK_URL, log))
        head = git_head(src)
        if head != SPDK_COMMIT:
            raise Refusal(1, "fetched %s resolves to %s, not the pinned %s" % (SPDK_TAG, head, SPDK_COMMIT))
    if run_logged(submodule_command(src), log):
        raise Refusal(4, "cannot fetch SPDK submodules %s; see %s" % (", ".join(SPDK_SUBMODULES), log))
    if not (src / "build/lib/pkgconfig/spdk_nvme.pc").is_file():
        if run_logged(configure_command(src), log, cwd=src):
            raise Refusal(4, "SPDK configure failed (missing build prerequisites?); see %s" % log)
        if run_logged(make_command(src, jobs), log):
            raise Refusal(4, "SPDK build failed (missing build prerequisites?); see %s" % log)
    return src


def pkg_libs(root, static):
    env = dict(os.environ, PKG_CONFIG_PATH=pkg_config_path(root))
    command = ["pkg-config", "--libs", *(["--static", "spdk_syslibs"] if static else PKG_MODULES)]
    try:
        out = subprocess.run(command, env=env, capture_output=True, text=True)
    except FileNotFoundError:
        raise Refusal(4, "pkg-config unavailable")
    if out.returncode:
        raise Refusal(4, "SPDK pkg-config files unavailable under %s: %s"
                      % (pkg_config_path(root), out.stderr.strip()))
    return out.stdout.strip()


def build_native(root, output, cc):
    for header in ("env.h", "nvme.h", "stdinc.h"):
        if not (root / "include/spdk" / header).is_file():
            raise Refusal(4, "official SPDK header include/spdk/%s unavailable under %s" % (header, root))
    if not (Path(pkg_config_path(root)) / "spdk_nvme.pc").is_file():
        raise Refusal(4, "SPDK under %s is not built: no pkg-config file %s/spdk_nvme.pc"
                      % (root, pkg_config_path(root)))
    if not shutil.which("pkg-config"):
        raise Refusal(4, "pkg-config unavailable")
    command = native_command(cc, root, output, pkg_libs(root, False), pkg_libs(root, True))
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        raise Refusal(4, "C compiler unavailable")
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise Refusal(1, "native arm failed to compile or link against %s" % root)
    return command


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0], allow_abbrev=False)
    p.add_argument("--output", type=Path)
    p.add_argument("--spdk-root", type=Path)
    p.add_argument("--fetch-sdk", action="store_true")
    p.add_argument("--print-commands", action="store_true")
    p.add_argument("--build-dir")
    p.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    a = p.parse_args(argv)
    cc = shlex.split(os.environ.get("CC", "cc"))
    try:
        if a.fetch_sdk or a.print_commands:
            if a.spdk_root or not a.build_dir or (a.fetch_sdk and a.print_commands):
                raise Refusal(2, "--fetch-sdk/--print-commands take --build-dir and no --spdk-root")
            if not 1 <= a.jobs <= 256:
                raise Refusal(2, "--jobs 1..256")
            build_dir = private_dir(a.build_dir)
            src = build_dir / "spdk"
            output = a.output or build_dir / "bench_nvme_pipeline"
            if a.print_commands:
                print(json.dumps(dict(
                    spdk_url=SPDK_URL, spdk_tag=SPDK_TAG, spdk_commit=SPDK_COMMIT,
                    clone=clone_command(src), submodules=submodule_command(src),
                    configure=configure_command(src), make=make_command(src, a.jobs),
                    link=native_command(cc, src, output,
                                        "$(pkg-config --libs %s)" % " ".join(PKG_MODULES),
                                        "$(pkg-config --libs --static spdk_syslibs)"),
                    pkg_config_path=pkg_config_path(src))))
                return 0
            need_tools(["git", "make", "pkg-config", cc[0]])
            if not build_dir.exists():
                build_dir.mkdir(mode=0o700, parents=True)
                build_dir.chmod(0o700)
            src = fetch_sdk(build_dir, a.jobs)
        elif a.spdk_root:
            if not a.output:
                raise Refusal(2, "--output is required")
            src, output = a.spdk_root.resolve(), a.output
        else:
            if not a.output:
                raise Refusal(2, "--output is required")
            try:
                result = subprocess.run(offline_command(cc, a.output), capture_output=True, text=True)
            except FileNotFoundError:
                raise Refusal(4, "C compiler unavailable")
            if result.returncode:
                sys.stderr.write(result.stdout + result.stderr)
                return 1
            return 0
        command = build_native(src, output, cc)
    except Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return refusal.code
    head = git_head(src)
    print(json.dumps(dict(status="built", kind="native-spdk", execution="not-run",
                          spdk_root=str(src), spdk_commit=head,
                          spdk_tag=SPDK_TAG if head == SPDK_COMMIT else None,
                          command=command, source_sha256=sha256(SOURCE),
                          owner_sha256=sha256(HERE / "spdk_owner.h"),
                          binary=str(output), binary_sha256=sha256(output))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
