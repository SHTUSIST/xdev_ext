#!/usr/bin/env python3
"""Build and collect the NVMe<->GPU arms with explicit path contracts.

Arms: session (xdev_ext [NVMe READ, CE H2D] / [CE D2H, NVMe WRITE]),
uring-cuda (io_uring O_DIRECT READ_FIXED/WRITE_FIXED + cudaHostRegister +
cudaMemcpyAsync), gds-batch and gds-async (cuFile batch / stream async), and
gds-direct (synchronous cuFile, delegated to ../gds/run.py; qd 1, seq).

The session, staged and async/batch arms share one temporary file in --directory,
with O_DIRECT, the same payload/schedule and a post-pass destination oracle.
The synchronous gds-direct delegate creates its own file and guarded history;
its call-interval timer includes checkpoint fsync. These are separate contracts.
--destination slot-ring (default) gives the shared-file arms the session's
device layout, a ring of qd device slots; gds-direct is window-only.
Window places block b at device offset
b*size and leaves the session (and slot-ring-only cells) not_run, so unlike
layouts are never paired.  --completion-wait block (default) makes every
baseline sleep for completions, as the session sleeps on its eventfd; poll
records spin and their CPU fields are no CPU-cost data.  The
session arm reaches the file's blocks through the NVMe namespace (--ng) at
the LBA window derived from FIEMAP and the partition offset.  Cells run in
alternating order (pair i even: listed order; odd: reversed). The pair field is
only a repetition/order index, not proof of equivalent work; no ratio is emitted.
A missing SDK,
device or capability is reported as not_run (exit 4 if nothing ran); it is
never a pass.  VM timings are not performance data.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
_CPU_MODULES = HERE.parent / "native_trace"
if not _CPU_MODULES.is_dir():
    _CPU_MODULES = HERE.parents[1] / "support/evidence/native_trace"
sys.path.insert(0, str(_CPU_MODULES))
from timer_scope import TimerCpuRun, OptionalTimerCpuRun

REPO = HERE.parents[2]
KERNEL = REPO / "kernel"
ARMS = ("session", "uring-cuda", "gds-batch", "gds-async", "gds-direct")
CUDA_ARMS = ("uring-cuda", "gds-batch", "gds-async", "gds-direct")
ROUTES = {
    ("session", "load"): "nvme-read>shared-host-frame>ce-h2d",
    ("session", "save"): "ce-d2h>shared-host-frame>nvme-write",
    ("uring-cuda", "load"): "nvme-read-fixed>registered-host>cuda-h2d-async",
    ("uring-cuda", "save"): "cuda-d2h-async>registered-host>nvme-write-fixed",
    ("gds-batch", "load"): "nvme>gpu-direct", ("gds-batch", "save"): "gpu-direct>nvme",
    ("gds-async", "load"): "nvme>gpu-direct", ("gds-async", "save"): "gpu-direct>nvme",
}
MIN_SIZE, MAX_SIZE, MAX_QD = 4096, 4 << 20, 256
DESTINATIONS = ("slot-ring", "window")
WAITS = ("block", "poll")
SESSION_MAX_DEPTH = 64
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 1
FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_UNKNOWN, FIEMAP_EXTENT_ENCODED = 0x1, 0x2, 0x8
FIEMAP_EXTENT_UNWRITTEN, FIEMAP_EXTENT_NOT_ALIGNED = 0x800, 0x100
FIEMAP_EXTENT_DATA_INLINE, FIEMAP_EXTENT_SHARED = 0x200, 0x2000


def cpu_owner(args, clock="CLOCK_MONOTONIC", *, optional=False):
    import uuid
    output = args.cpu_output
    if output is None and not os.environ.get("XDEV_EXT_EVAL_CPU_OWNER"):
        parent = getattr(args, "build_dir", HERE / "build")
        output = Path(parent) / "cpu-measurements" / str(uuid.uuid4())
    elif output is not None:
        output = Path(output) / str(uuid.uuid4())
    capture = OptionalTimerCpuRun if optional else TimerCpuRun
    return capture(output, cpu_set=args.cpu_set, clock=clock)


def decimal(text):
    if not re.fullmatch(r"[0-9]{1,20}", text or ""):
        raise argparse.ArgumentTypeError("expected an ASCII decimal integer")
    return int(text)


def size_list(text):
    """"A..B" is every power of two from A to B; otherwise a comma list."""
    if ".." in text:
        low, high = (decimal(part) for part in text.split("..", 1))
        if low > high or low & (low - 1) or high & (high - 1):
            raise argparse.ArgumentTypeError("a range needs powers of two A <= B")
        values, value = [], low
        while value <= high:
            values.append(value)
            value *= 2
    else:
        values = [decimal(part) for part in text.split(",")]
    for value in values:
        if not MIN_SIZE <= value <= MAX_SIZE or value % 4096:
            raise argparse.ArgumentTypeError("sizes are 4 KiB multiples in 4 KiB..4 MiB")
    if len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("duplicate size")
    return values


def qd_list(text):
    values = [decimal(part) for part in text.split(",")]
    if not values or any(not 1 <= v <= MAX_QD for v in values) or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("queue depths are distinct values in 1..256")
    return values


def choice_list(allowed):
    def parse(text):
        values = text.split(",")
        if not values or any(v not in allowed for v in values) or len(set(values)) != len(values):
            raise argparse.ArgumentTypeError("choose distinct values from " + ",".join(allowed))
        return values
    return parse


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cpu-set")
    parser.add_argument("--cpu-output", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--arms", type=choice_list(ARMS), required=True)
    parser.add_argument("--directions", type=choice_list(("load", "save")), default=["load", "save"])
    parser.add_argument("--sizes", type=size_list, required=True)
    parser.add_argument("--qd", type=qd_list, required=True)
    parser.add_argument("--pattern", type=choice_list(("seq", "rand")), default=["seq"])
    parser.add_argument("--pairs", type=decimal, default=5)
    parser.add_argument("--passes", type=decimal, default=1)
    parser.add_argument("--window-bytes", type=decimal, default=256 << 20)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--cuda-root", type=Path, default=Path("/usr/local/cuda"))
    parser.add_argument("--ng", help="NVMe generic namespace of the directory's device")
    parser.add_argument("--ce-dev", help="GPU CE device (with --ce-alloc) or /dev/xdev_ext_ce_sim")
    parser.add_argument("--ce-alloc", action="store_true")
    parser.add_argument("--destination", choices=DESTINATIONS, default="slot-ring")
    parser.add_argument("--completion-wait", choices=WAITS, default="block")
    parser.add_argument("--streams", type=decimal, default=2)
    parser.add_argument("--timeout-ms", type=decimal, default=60000)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--build-dir", type=Path, default=HERE / "build")
    args = parser.parse_args(argv)
    if not 1 <= args.pairs <= 100 or not 1 <= args.passes <= 1000 or not 1 <= args.streams <= 16:
        parser.error("pairs 1..100, passes 1..1000, streams 1..16")
    if args.window_bytes % (4 << 20) or not args.window_bytes or args.window_bytes > 64 << 30:
        parser.error("--window-bytes is a positive multiple of 4 MiB up to 64 GiB")
    if args.window_bytes // max(args.sizes) < max(args.qd):
        parser.error("--window-bytes must hold max(qd) blocks of the largest size")
    if not args.build_only and not args.dry_run and (args.directory is None or not args.directory.is_dir()):
        parser.error("--directory must name an existing directory")
    if "session" in args.arms and not args.build_only and not args.dry_run and not (args.ng and args.ce_dev):
        parser.error("the session arm needs --ng and --ce-dev")
    return args


def skip(reason):
    print(json.dumps({"status": "not_run", "reason": reason}), file=sys.stderr)


# --- build ---------------------------------------------------------------


def sdk_library(sdk, stem):
    for libdir in (sdk / "lib64", sdk / "lib", sdk / "targets/x86_64-linux/lib"):
        found = sorted(p for p in libdir.glob(stem + "*") if p.is_file())
        if found:
            return found[0].resolve()
    return None


def compile_atomic(command, output):
    """Compile into a temporary name, then rename: never run a stale binary."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compile-", dir=output.parent) as temporary:
        binary = Path(temporary) / output.name
        result = subprocess.run(command + ["-o", str(binary)], text=True,
                                capture_output=True, timeout=300)
        if result.returncode:
            sys.stderr.write(result.stdout + result.stderr)
            return False
        os.replace(binary, output)
    return True


def build_arm(arm, args):
    """(entrypoint, None) after building, or (None, capability refusal).

    Fatal delegate errors raise RuntimeError; its script path is not a build.
    """
    out = args.build_dir / {"session": "session_nvme_ce", "uring-cuda": "bench_uring_cuda",
                            "gds-batch": "bench_cufile_batch", "gds-async": "bench_cufile_batch",
                            "gds-direct": "gds-direct"}[arm]
    if arm == "gds-direct":
        delegate = HERE.parent / "gds" / "run.py"
        directory = args.directory
        if directory is None or not directory.is_dir():
            directory = args.build_dir
            directory.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, str(delegate), "--mode", "cufile-direct",
                   "--workload", "llm-load", "--bytes", "4096", "--chunk", "4096",
                   "--iterations", "1", "--directory", str(directory.resolve()),
                   "--cuda-root", str(args.cuda_root), "--build-only"]
        result = subprocess.run(command, text=True, capture_output=True, timeout=120)
        sys.stderr.write(result.stdout + result.stderr)
        if result.returncode == 4:
            return None, "delegated synchronous cuFile builder unavailable"
        if result.returncode:
            raise RuntimeError("gds-direct builder exited %d" % result.returncode)
        return delegate, None
    if arm == "session":
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            return None, "C compiler unavailable"
        command = [compiler, "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                   str(HERE / "session_nvme_ce.c"),
                   str(KERNEL / "tools/xdev_ext_gpu_identity.c"), "-ldl"]
        return (out, None) if compile_atomic(command, out) else (None, "session build failed")
    include = args.cuda_root / "include"
    headers = ["cuda_runtime_api.h"] + (["cufile.h"] if arm.startswith("gds") else [])
    if not all((include / h).is_file() for h in headers):
        return None, "official CUDA%s development headers unavailable" % (
            "/cuFile" if arm.startswith("gds") else "")
    compiler = shutil.which(os.environ.get("CXX", "c++"))
    if not compiler:
        return None, "C++ compiler unavailable"
    libraries = []
    for stem in (["libcufile.so"] if arm.startswith("gds") else []) + ["libcudart.so"]:
        library = sdk_library(args.cuda_root, stem)
        if not library:
            return None, "official " + stem + " unavailable"
        libraries.append(library)
    extra = []
    if arm == "uring-cuda":
        probe = subprocess.run(["pkg-config", "--cflags", "--libs", "liburing"], text=True,
                               capture_output=True)
        if probe.returncode:
            return None, "liburing development package unavailable"
        extra = probe.stdout.split()
    command = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
               "-I" + str(include.resolve()), "-I" + str(HERE),
               str(HERE / ("bench_uring_cuda.cc" if arm == "uring-cuda" else "bench_cufile_batch.cc"))]
    command += [str(p) for p in libraries] + extra
    command += ["-Wl,-rpath," + str(p.parent) for p in libraries]
    return (out, None) if compile_atomic(command, out) else (None, "SDK/compiler build failed")


# --- the shared LBA window ----------------------------------------------


def merge_extents(extents):
    """Physically contiguous runs of (logical, physical, length, flags)."""
    runs = []
    for logical, physical, length, flags in sorted(extents):
        bad = FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_ENCODED | FIEMAP_EXTENT_UNWRITTEN | \
            FIEMAP_EXTENT_NOT_ALIGNED | FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_SHARED
        if flags & bad:
            raise ValueError("extent is not plain written data (flags 0x%x)" % flags)
        if runs and runs[-1][0] + runs[-1][2] == logical and runs[-1][1] + runs[-1][2] == physical:
            runs[-1][2] += length
        else:
            runs.append([logical, physical, length])
    return [tuple(run) for run in runs]


def single_run(extents, length):
    runs = merge_extents(extents)
    if len(runs) != 1 or runs[0][0] != 0 or runs[0][2] < length:
        raise ValueError("file window is not one physically contiguous run")
    return runs[0][1]


def fiemap(path, length):
    count = 512
    header = struct.pack("=QQIIII", 0, length, FIEMAP_FLAG_SYNC, 0, count, 0)
    buffer = bytearray(header + bytes(56 * count))
    with open(path, "rb") as handle:
        fcntl.ioctl(handle.fileno(), FS_IOC_FIEMAP, buffer)
    mapped = struct.unpack_from("=QQIIII", buffer)[3]
    extents = []
    for i in range(mapped):
        logical, physical, size, _, _, flags = struct.unpack_from("=QQQQQI", buffer, 32 + 56 * i)
        extents.append((logical, physical, size, flags & ~FIEMAP_EXTENT_LAST))
    return extents


def lba_window(path, length, ng):
    """(slba, lba_size) of the file's bytes on namespace @ng, or ValueError."""
    info = os.stat(path)
    sysdev = Path("/sys/dev/block/%d:%d" % (os.major(info.st_dev), os.minor(info.st_dev))).resolve()
    start = 0
    if (sysdev / "partition").is_file():
        start = int((sysdev / "start").read_text()) * 512
        sysdev = sysdev.parent
    match = re.fullmatch(r"nvme(\d+)n(\d+)", sysdev.name)
    if not match or Path(ng).name != "ng%sn%s" % match.groups():
        raise ValueError("--ng does not name the namespace that holds --directory")
    lba = int((sysdev / "queue/logical_block_size").read_text())
    physical = single_run(fiemap(path, length), length) + start
    if physical % lba:
        raise ValueError("window is not LBA aligned")
    return physical // lba, lba


# --- result validation ---------------------------------------------------


def validate(record, arm, direction, size, qd, pattern, window, passes,
             destination="slot-ring", completion_wait="block"):
    """Independent schema/count oracle of one arm record.

    @destination and @completion_wait are the campaign's: a record of
    another device layout or wait mode is refused, so a campaign never pairs
    unlike arms.  The session always uses the slot ring and blocks.
    """
    if type(record) is not dict or record.get("status") != "pass":
        raise ValueError("arm did not report a verified pass")
    if destination not in DESTINATIONS or completion_wait not in WAITS:
        raise ValueError("unknown campaign destination or completion wait")
    expected = {"schema_version": 1, "direction": direction, "size": size, "qd": qd,
                "pattern": pattern, "window_bytes": window, "passes": passes,
                "operations": window // size * passes, "io_bytes": window * passes}
    if arm == "gds-direct":
        if destination != "window":
            raise ValueError("the delegated cuFile arm fills the whole window")
        delegated = record.get("delegate_record")
        if type(delegated) is not dict or delegated.get("io_bytes") != window * passes or \
                delegated.get("verified_bytes") != window * passes:
            raise ValueError("delegated cuFile record does not cover the window")
        return record
    expected["arm"] = arm
    expected["destination"] = "slot-ring" if arm == "session" else destination
    expected["completion_wait"] = "block" if arm == "session" else completion_wait
    for key, value in expected.items():
        if type(record.get(key)) is not type(value) or record[key] != value:
            raise ValueError("invalid result field " + key)
    for key in ("io_ns", "cpu_us", "host_busy_us", "verified_bytes"):
        if type(record.get(key)) is not int or record[key] < (1 if key == "io_ns" else 0):
            raise ValueError("invalid measurement field " + key)
    route = ROUTES[(arm, direction)]
    if record.get("route") != route:
        raise ValueError("invalid result field route")
    if record.get("performance_claim") != ("none" if record.get("execution") == "kvm-ce-sim" else "physical"):
        raise ValueError("a CE stand-in run claims no performance; a physical run says so")
    if arm == "session":
        if record.get("execution") not in ("kvm-ce-sim", "physical-gpu-ce"):
            raise ValueError("unknown session execution")
        slots = min(window // size, qd)
        if record.get("slots_used") != slots or type(record["slots_used"]) is not int:
            raise ValueError("oracle did not see every device slot")
        if direction == "load" and record["verified_bytes"] != qd * size * passes:
            raise ValueError("load oracle did not cover every slot")
        if direction == "save" and record["verified_bytes"] != window * passes:
            raise ValueError("save oracle did not cover the file window")
    else:
        ring_load = destination == "slot-ring" and direction == "load"
        if record["verified_bytes"] != (qd * size if ring_load else window) * passes:
            raise ValueError("oracle did not cover the destination")
        if record.get("execution") not in ("physical-cuda", "physical-cuda-cufile"):
            raise ValueError("unknown execution")
        if arm.startswith("gds") and (record.get("compat_allowed") is not False or
                                      record.get("native_operations") != expected["operations"]):
            raise ValueError("cuFile record lacks native-path evidence")
    return record


def parse_record(stdout):
    if not stdout.endswith("\n") or len(stdout.splitlines()) != 1:
        raise ValueError("expected exactly one JSON result line")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate result key")
            result[key] = value
        return result
    return json.loads(stdout, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite")))


# --- campaign -------------------------------------------------------------


def arm_command(arm, binary, args, direction, size, qd, pattern, path, window, lba):
    common = ["--size", size, "--qd", qd, "--window-bytes", window, "--passes", args.passes,
              "--pattern", pattern, "--timeout-ms", args.timeout_ms, "--direction", direction]
    if arm == "session":
        slba, lba_size = lba
        command = [binary, "--ng", args.ng, "--slba", slba, "--lba-size", lba_size,
                   "--file", path, "--ce-dev", args.ce_dev]
        command += ["--ce-alloc"] if args.ce_alloc else ["--ce-va", 0]
        return [str(c) for c in command + common]
    baseline = ["--destination", args.destination, "--completion-wait", args.completion_wait]
    if arm == "uring-cuda":
        return [str(c) for c in [binary, "--file", path, "--streams", args.streams] + common +
                baseline]
    if arm in ("gds-batch", "gds-async"):
        return [str(c) for c in [binary, "--api", arm[4:], "--file", path] + common + baseline]
    return [sys.executable, str(binary), "--mode", "cufile-direct",
            "--workload", "llm-load" if direction == "load" else "checkpoint",
            "--bytes", str(window), "--chunk", str(size), "--iterations", str(args.passes),
            "--directory", str(Path(path).parent), "--cuda-root", str(args.cuda_root)]


def mapping_verified(binary, args, path, lba):
    """A small read-only session load through --ng must read the file's own bytes.

    The session arm seeds --file through the filesystem and the load oracle
    checks what NVMe READ returned, so a wrong slba or namespace fails here
    before any save cell writes raw LBAs.
    """
    size = 1 << 20
    command = arm_command("session", binary, args, "load", size, 1, "seq", path,
                          min(args.window_bytes, 4 * size), lba)
    command[command.index("--passes") + 1] = "1"
    result = subprocess.run(command, text=True, capture_output=True,
                            timeout=args.timeout_ms / 1000 + 600)
    sys.stderr.write(result.stderr)
    if result.returncode:
        return False
    try:
        validate(parse_record(result.stdout), "session", "load", size, 1, "seq",
                 min(args.window_bytes, 4 * size), 1)
    except ValueError:
        return False
    return True


def cell_supported(arm, qd, pattern, destination):
    if arm == "session" and destination != "slot-ring":
        return "the session lands blocks in a ring of qd device slots only"
    if arm == "session" and (pattern != "seq" or qd > SESSION_MAX_DEPTH):
        return "session plan is linear with depth <= 64"
    if arm == "gds-batch" and qd > 1 and qd % 2:
        return "two ceil(qd/2) batch waves can admit qd+1 I/Os; not an equal-QD cell"
    if arm == "gds-direct" and destination != "window":
        return "the delegated synchronous cuFile arm fills the whole window"
    if arm == "gds-direct" and (pattern != "seq" or qd != 1):
        return "synchronous cuFile arm is qd 1 sequential"
    return None


def main(argv=None):
    args = arguments(argv)
    if args.dry_run:
        print(json.dumps({"status": "planned", "arms": args.arms, "directions": args.directions,
                          "cpu_measurement_plan": cpu_owner(args).plan()}, sort_keys=True))
        return 0
    binaries, ran = {}, 0
    for arm in args.arms:
        try:
            binary, reason = build_arm(arm, args)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            print("nvme_gpu build failed: " + str(error), file=sys.stderr)
            return 1
        if reason:
            skip(arm + ": " + reason)
            continue
        binaries[arm] = binary
        if args.build_only:
            print("Built %s: %s" % (arm, binary), file=sys.stderr)
    if args.build_only:
        return 0 if len(binaries) == len(args.arms) else 4
    if any(a in binaries for a in CUDA_ARMS) and not Path("/dev/nvidiactl").exists():
        for arm in CUDA_ARMS:
            if binaries.pop(arm, None):
                skip(arm + ": NVIDIA control device unavailable")
    if not binaries:
        return 4
    try:
        with tempfile.TemporaryDirectory(prefix="xdev-nvme-gpu-", dir=args.directory.resolve()) as tmp:
            path = Path(tmp) / "window.bin"
            with open(path, "wb") as handle:
                zero = bytes(4 << 20)
                for _ in range(args.window_bytes // len(zero)):
                    handle.write(zero)
                handle.flush()
                os.fsync(handle.fileno())
            lba = None
            if "session" in binaries:
                try:
                    lba = lba_window(path, args.window_bytes, args.ng)
                except (OSError, ValueError) as error:
                    skip("session: " + str(error))
                    binaries.pop("session")
            if "session" in binaries and not mapping_verified(binaries["session"], args, path, lba):
                # A wrong LBA window would make a raw NVMe WRITE land outside the file.
                skip("session: the read-only load probe did not confirm the LBA window; "
                     "no session cell runs")
                binaries.pop("session")
            for direction in args.directions:
                for pattern in args.pattern:
                    for size in args.sizes:
                        for qd in args.qd:
                            order = [a for a in args.arms if a in binaries]
                            for pair in range(args.pairs):
                                for arm in (order if pair % 2 == 0 else order[::-1]):
                                    reason = cell_supported(arm, qd, pattern, args.destination)
                                    if reason:
                                        if pair == 0:
                                            skip("%s %s %s size=%d qd=%d: %s" % (
                                                arm, direction, pattern, size, qd, reason))
                                        continue
                                    command = arm_command(arm, binaries[arm], args, direction,
                                                          size, qd, pattern, path,
                                                          args.window_bytes, lba)
                                    with cpu_owner(args, optional=True) as cpu:
                                        result = cpu.run(command, text=True, capture_output=True,
                                                         timeout=args.timeout_ms / 1000 * (args.passes + 2) + 600)
                                    sys.stderr.write(result.stderr)
                                    if result.returncode == 4:
                                        skip("%s %s: capability refused" % (arm, direction))
                                        continue
                                    if result.returncode:
                                        raise RuntimeError("%s exited %d" % (arm, result.returncode))
                                    record = parse_record(result.stdout)
                                    if arm == "gds-direct":
                                        record = {"status": record.get("status"), "arm": arm,
                                                  "direction": direction, "size": size, "qd": 1,
                                                  "pattern": "seq", "delegate_record": record}
                                    validate(record, arm, direction, size, qd, pattern,
                                             args.window_bytes, args.passes, args.destination,
                                             args.completion_wait)
                                    raw = record["delegate_record"] if arm == "gds-direct" else record
                                    rows = args.passes if arm != "gds-direct" else args.passes * (
                                        (args.window_bytes + size - 1) // size + (direction == "save"))
                                    measurement = cpu.measurement([dict(arm=arm, identity={"pair": pair, "direction": direction},
                                        metric="io_ns", keys=list(range(rows)), expected_duration_ns=raw["io_ns"],
                                        endpoint_semantics=("settled-session" if arm == "session" else
                                            "chunk-completion-and-checkpoint-fsync" if arm == "gds-direct" else "retired-pass"),
                                        clock="CLOCK_MONOTONIC")])
                                    if measurement is not None:
                                        record["cpu_measurement"] = measurement
                                    record["pair"] = pair
                                    print(json.dumps(record, sort_keys=True))
                                    ran += 1
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("nvme_gpu eval failed: " + str(error), file=sys.stderr)
        return 1
    return 0 if ran else 4


if __name__ == "__main__":
    sys.exit(main())
