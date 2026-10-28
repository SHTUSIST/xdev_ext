#!/usr/bin/env python3
"""Build and run the GPU<->NIC comparison arms against one NXP peer.

Scenario microbenchmarks shaped like GPU-facing network services, not the
services.  Arms: session (xdev_ext [AF_XDP RX, CE H2D] / [CE D2H, AF_XDP TX]),
afxdp-cuda (AF_XDP UMEM registered with cudaHostRegister, async streams) and
udp-pinned-cuda (UDP socket into/out of cudaHostAlloc buffers, async copies).
Every arm speaks the session's NXP wire, so the same nxp_peer feeds ingest
(nic-gpu) and verifies egress (gpu-nic).  The peer runs locally, or behind
--peer-exec (for example an ssh prefix to the second host).

Shapes: --sizes A..B (powers of two, 64 B..4 MiB), or --shape ingest|egress
for the LoRA-microbatch and 4 MiB response messages of gpu_nic_core.h.  Cells
run in paired order.  --completion-wait block (default) makes the baselines
sleep for completions, as the session sleeps on its eventfd; poll records
spin and their CPU fields are no CPU-cost data.  Every baseline record
carries copies_per_group and copy_calls, the CUDA copy calls of the
campaign.  A missing SDK, device, interface or capability is
not_run (exit 4 if nothing ran), never a pass.  VM timings are not
performance data.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True  # the sibling runner is loaded as a module
HERE = Path(__file__).resolve().parent
_CPU_MODULES = HERE.parent / "native_trace"
if not _CPU_MODULES.is_dir():
    _CPU_MODULES = HERE.parents[1] / "support/evidence/native_trace"
sys.path.insert(0, str(_CPU_MODULES))
from timer_scope import TimerCpuRun, OptionalTimerCpuRun

REPO = HERE.parents[2]
KERNEL = REPO / "kernel"
_SPEC = importlib.util.spec_from_file_location("nvme_gpu_run", HERE.parent / "nvme_gpu" / "run.py")
NG = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(NG)

ARMS = ("session", "afxdp-cuda", "udp-pinned-cuda")
ROUTES = {
    ("session", "ingest"): "afxdp-rx>shared-host-frame>ce-h2d",
    ("session", "egress"): "ce-d2h>shared-host-frame>afxdp-tx",
    ("afxdp-cuda", "ingest"): "afxdp-rx>registered-umem>cuda-h2d-async",
    ("afxdp-cuda", "egress"): "cuda-d2h-async>registered-umem>afxdp-tx",
    ("udp-pinned-cuda", "ingest"): "udp-recvmmsg>pinned-host>cuda-h2d-async",
    ("udp-pinned-cuda", "egress"): "cuda-d2h-async>pinned-host>udp-sendmmsg",
}
CUDA_ARMS = ("afxdp-cuda", "udp-pinned-cuda")
SHAPES = {"ingest": 8 * 4096 * 4 * 3, "egress": 4 << 20}
MAX_DEPTH = 64
WAITS = ("block", "poll")


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


def size_list(text):
    if ".." in text:
        low, high = (NG.decimal(part) for part in text.split("..", 1))
        if low > high or low & (low - 1) or high & (high - 1):
            raise argparse.ArgumentTypeError("a range needs powers of two A <= B")
        values, value = [], low
        while value <= high:
            values.append(value)
            value *= 2
    else:
        values = [NG.decimal(part) for part in text.split(",")]
    if any(not 64 <= v <= 4 << 20 or v % 8 for v in values) or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("sizes are distinct multiples of 8 in 64 B..4 MiB")
    return values


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cpu-set")
    parser.add_argument("--cpu-output", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--arms", type=NG.choice_list(ARMS), required=True)
    parser.add_argument("--direction", choices=("nic-gpu", "gpu-nic"), required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sizes", type=size_list)
    group.add_argument("--shape", choices=sorted(SHAPES))
    parser.add_argument("--messages", type=NG.decimal, default=1000)
    parser.add_argument("--depth", type=NG.decimal, default=16)
    parser.add_argument("--pairs", type=NG.decimal, default=5)
    parser.add_argument("--ifname")
    parser.add_argument("--queue", type=NG.decimal, default=0)
    parser.add_argument("--copy-mode", action="store_true")
    parser.add_argument("--local-ip")
    parser.add_argument("--peer-ip")
    parser.add_argument("--local-port", type=NG.decimal, default=12345)
    parser.add_argument("--peer-port", type=NG.decimal, default=54321)
    parser.add_argument("--peer-mac")
    parser.add_argument("--wire-session", type=NG.decimal, default=270019)
    parser.add_argument("--peer-exec", default="", help="command prefix that runs nxp_peer on the peer host")
    parser.add_argument("--peer-binary", default=None, help="nxp_peer path on the peer host")
    parser.add_argument("--peer-gap-us", type=NG.decimal, default=0,
                        help="ingest sender pause between 64-datagram batches")
    parser.add_argument("--ce-dev")
    parser.add_argument("--ce-alloc", action="store_true")
    parser.add_argument("--streams", type=NG.decimal, default=2)
    parser.add_argument("--completion-wait", choices=WAITS, default="block")
    parser.add_argument("--timeout-ms", type=NG.decimal, default=60000)
    parser.add_argument("--cuda-root", type=Path, default=Path("/usr/local/cuda"))
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--build-dir", type=Path, default=HERE / "build")
    args = parser.parse_args(argv)
    if not 1 <= args.depth <= MAX_DEPTH or not 1 <= args.pairs <= 100 or \
            not 1 <= args.messages <= 1 << 24 or not 1 <= args.streams <= 16:
        parser.error("depth 1..64, pairs 1..100, messages 1..2^24, streams 1..16")
    if not 1 <= args.local_port <= 65535 or not 1 <= args.peer_port <= 65535:
        parser.error("ports are 1..65535")
    if not args.build_only and not args.dry_run and not (args.ifname and args.local_ip and args.peer_ip and args.peer_mac):
        parser.error("a campaign needs --ifname, --local-ip, --peer-ip and --peer-mac")
    if "session" in args.arms and not args.build_only and not args.dry_run and not args.ce_dev:
        parser.error("the session arm needs --ce-dev")
    return args


def skip(reason):
    print(json.dumps({"status": "not_run", "reason": reason}), file=sys.stderr)


def build(name, args):
    out = args.build_dir / name
    tools = KERNEL / "tools"
    if name in ("session_gpu_nic", "nxp_peer"):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            return None, "C compiler unavailable"
        command = [compiler, "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-msse4.2",
                   str(HERE / (name + ".c"))]
        if name == "session_gpu_nic":
            command += [str(tools / "xdev_ext_xsk_redirect.c"), str(tools / "xdev_ext_gpu_identity.c"),
                        "-lbpf", "-lelf", "-lz", "-ldl"]
        return (out, None) if NG.compile_atomic(command, out) else (None, name + " build failed")
    include = args.cuda_root / "include"
    if not (include / "cuda_runtime_api.h").is_file():
        return None, "official CUDA development headers unavailable"
    cudart = NG.sdk_library(args.cuda_root, "libcudart.so")
    if not cudart:
        return None, "official libcudart.so unavailable"
    nvcc = shutil.which("nvcc", path=str(args.cuda_root / "bin")) or shutil.which("nvcc")
    source = str(HERE / (name.replace("-", "_") + ".cu"))
    host_flags = ["-O2", "-Wall", "-Wextra", "-Wno-missing-field-initializers", "-msse4.2"]
    if nvcc:
        command = [nvcc, "-std=c++17", "-O2", "--cudart=shared", "-Xcompiler", ",".join(host_flags),
                   source]
    else:
        compiler = shutil.which(os.environ.get("CXX", "c++"))
        if not compiler:
            return None, "neither nvcc nor a C++ compiler is available"
        command = [compiler, "-std=c++17", "-x", "c++", "-Werror", "-I" + str(include)] + host_flags + \
            [source, "-x", "none"]
    if name == "afxdp-cuda":
        # The redirect helper is C: compile it with the C compiler, link the object.
        cc = shutil.which(os.environ.get("CC", "cc"))
        obj = args.build_dir / "xdev_ext_xsk_redirect.o"
        if not cc or not NG.compile_atomic([cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                                            "-c", str(tools / "xdev_ext_xsk_redirect.c")], obj):
            return None, "xdev_ext_xsk_redirect.c build failed"
        command += [str(obj), "-lbpf", "-lelf", "-lz"]
    command += [str(cudart), "-Wl,-rpath," + str(cudart.parent)] if not nvcc else \
        ["-L" + str(cudart.parent), "-lcudart"]
    return (out, None) if NG.compile_atomic(command, out) else (None, name + " build failed")


def expected_copies(record):
    """CUDA copy calls of one group: the 2D copy of full segments plus a short tail."""
    group, seg = record["group_bytes"], record["seg_len"]
    return (1 if group // seg else 0) + (1 if group % seg else 0)


def validate_copies(record, arm, direction):
    """Copy-call accounting of a CUDA baseline: never one copy per segment unless counted."""
    for key in ("seg_len", "frames", "copies_per_group", "copy_calls", "fallback_groups"):
        if type(record.get(key)) is not int or record[key] < (1 if key in ("seg_len", "frames") else 0):
            raise ValueError("invalid field " + key)
    groups, frames = record["groups"], record["frames"]
    if frames != -(-record["group_bytes"] // record["seg_len"]):
        raise ValueError("frames do not match the group plan")
    per_group = 1 if arm == "udp-pinned-cuda" else expected_copies(record)
    if record["copies_per_group"] != per_group:
        raise ValueError("copies_per_group does not match the arm's copy plan")
    # Only AF_XDP ingest may fall back to per-segment copies, when the NIC filled
    # a group's chunks out of pitch; the fallback is counted, not hidden.
    fallback = record["fallback_groups"]
    if fallback > groups or (fallback and (arm, direction) != ("afxdp-cuda", "ingest")):
        raise ValueError("invalid fallback_groups")
    if record["copy_calls"] != (groups - fallback) * per_group + fallback * frames:
        raise ValueError("copy_calls do not cover the groups")


def validate_arm(record, arm, direction, size, messages, depth, completion_wait="block"):
    if type(record) is not dict or record.get("status") != "pass" or record.get("arm") != arm:
        raise ValueError("arm did not report a verified pass")
    if completion_wait not in WAITS:
        raise ValueError("unknown campaign completion wait")
    wait = "block" if arm == "session" else completion_wait
    if record.get("completion_wait") != wait:
        raise ValueError("completion_wait differs from the campaign's")
    for key in ("io_ns", "cpu_us", "host_busy_us", "groups", "group_bytes", "slots_used"):
        if type(record.get(key)) is not int or record[key] < (1 if key in ("io_ns", "groups", "group_bytes") else 0):
            raise ValueError("invalid field " + key)
    expected = dict(schema_version=1, direction=direction, size=size, messages=messages, depth=depth,
                    route=ROUTES[(arm, direction)])
    for key, value in expected.items():
        if type(record.get(key)) is not type(value) or record[key] != value:
            raise ValueError("invalid field " + key)
    if size % record["group_bytes"] or record["groups"] != messages * (size // record["group_bytes"]):
        raise ValueError("group plan does not cover the messages")
    if record.get("io_bytes") != record["groups"] * record["group_bytes"]:
        raise ValueError("io_bytes does not cover the campaign")
    if direction == "ingest":
        if record.get("oracle") != "device-slot-group-images" or \
                record["slots_used"] != min(record["groups"], depth):
            raise ValueError("ingest slot oracle did not cover every used slot")
    elif record.get("oracle") != "peer-receipt-required":
        raise ValueError("egress needs the peer's receipt")
    executions = ("kvm-ce-sim", "physical-gpu-ce") if arm == "session" else ("physical-cuda",)
    if record.get("execution") not in executions:
        raise ValueError("unknown execution")
    if record.get("performance_claim") != ("none" if record["execution"] == "kvm-ce-sim" else "physical"):
        raise ValueError("a CE stand-in run claims no performance; a physical run says so")
    if arm != "session":
        validate_copies(record, arm, direction)
    return record


def validate_peer(record, role, groups, group_bytes):
    if type(record) is not dict or record.get("status") != "pass" or record.get("role") != role:
        raise ValueError("peer did not report a pass")
    if record.get("groups") != groups or record.get("group_bytes") != group_bytes or \
            record.get("io_bytes") != groups * group_bytes:
        raise ValueError("peer record does not match the campaign")
    if role == "recv" and record.get("verified_groups") != groups:
        raise ValueError("peer did not verify every group")
    return record


class NotReady(RuntimeError):
    """The listener ended or timed out before READY; .lines holds its stderr."""

    def __init__(self, lines):
        super().__init__("no READY line: " + "".join(lines)[-2000:])
        self.lines = lines


def wait_ready(process, deadline, *, cpu=None):
    """Read stderr lines until XDEV_EVAL_READY; returns the lines read."""
    lines = []
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stderr], [], [], 0.2)
        if ready:
            line = process.stderr.readline()
            if not line:
                break
            lines.append(line)
            if cpu is not None and line.startswith("XDEV_EXT_CPU_TIMER_REFUSED "):
                cpu.refuse_child(process.pid, "CPU timer child refused journaling")
            if line.startswith("XDEV_EVAL_READY"):
                return lines
        elif process.poll() is not None:
            break
    raise NotReady(lines)


def _run_cell(args, arm, binary, peer, size, pair, cpu):
    ingest = args.direction == "nic-gpu"
    direction = "ingest" if ingest else "egress"
    timeout = args.timeout_ms / 1000 + 120
    common = ["--size", size, "--messages", args.messages, "--wire-session", args.wire_session]
    arm_cmd = [binary, "--direction", direction, "--ifname", args.ifname, "--depth", args.depth,
               "--local-ip", args.local_ip, "--peer-ip", args.peer_ip,
               "--local-port", args.local_port, "--peer-port", args.peer_port,
               "--seed", 1, "--timeout-ms", args.timeout_ms] + common
    if arm != "udp-pinned-cuda":
        arm_cmd += ["--peer-mac", args.peer_mac, "--queue", args.queue]
        arm_cmd += ["--copy-mode"] if args.copy_mode else []
    if arm != "session":
        arm_cmd += ["--streams", args.streams, "--completion-wait", args.completion_wait]
    else:
        arm_cmd += ["--ce-dev", args.ce_dev] + (["--ce-alloc"] if args.ce_alloc else ["--ce-va", 0])
    peer_cmd = shlex.split(args.peer_exec) + [peer]
    peer_cmd += (["send", "--local-ip", args.peer_ip, "--local-port", args.peer_port,
                  "--peer-ip", args.local_ip, "--peer-port", args.local_port,
                  "--window-groups", args.depth, "--gap-us", args.peer_gap_us] if ingest else
                 ["recv", "--local-ip", args.peer_ip, "--local-port", args.peer_port,
                  "--expect", "slots:%d" % args.depth, "--timeout-ms", args.timeout_ms])
    peer_cmd += common + ["--mtu", Path("/sys/class/net/%s/mtu" % args.ifname).read_text().strip(),
                          "--seed", 1]
    first, second = (arm_cmd, peer_cmd) if ingest else (peer_cmd, arm_cmd)
    deadline = time.monotonic() + timeout
    peer_env = {k: v for k, v in os.environ.items() if not k.startswith("XDEV_EXT_EVAL_CPU_")}
    listener = subprocess.Popen([str(c) for c in first], text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=cpu.environment(os.environ) if ingest else peer_env)
    if ingest:
        cpu.watch_child(listener, [str(c) for c in first])
    try:
        try:
            early = wait_ready(listener, deadline, cpu=cpu if ingest else None)
        except NotReady as error:
            # An ingest arm that refuses (exit 4, SKIP) before READY is a not_run cell.
            try:
                _, rest = listener.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                raise error
            if ingest and listener.returncode == 4:
                sys.stderr.write("".join(error.lines) + rest)
                return None
            raise
        if ingest:
            talker = subprocess.run([str(c) for c in second], text=True, capture_output=True,
                                    timeout=timeout, env=peer_env)
        else:
            talker = cpu.run([str(c) for c in second], text=True, capture_output=True, timeout=timeout)
        out, err = listener.communicate(timeout=max(1, deadline - time.monotonic()))
    finally:
        if listener.poll() is None:
            listener.kill()
            listener.communicate()
    if ingest and any(line.startswith("XDEV_EXT_CPU_TIMER_REFUSED ") for line in err.splitlines()):
        cpu.refuse_child(listener.pid, "CPU timer child refused journaling")
    sys.stderr.write("".join(early) + err + talker.stderr)
    arm_rc, arm_out = (listener.returncode, out) if ingest else (talker.returncode, talker.stdout)
    peer_rc, peer_out = (talker.returncode, talker.stdout) if ingest else (listener.returncode, out)
    if arm_rc == 4:
        return None
    if arm_rc or peer_rc:
        raise RuntimeError("%s %s: arm exit %d, peer exit %d" % (arm, direction, arm_rc, peer_rc))
    record = validate_arm(NG.parse_record(arm_out), arm, direction, size, args.messages, args.depth,
                          args.completion_wait)
    receipt = validate_peer(NG.parse_record(peer_out), "send" if ingest else "recv",
                            record["groups"], record["group_bytes"])
    record.update(pair=pair, peer=receipt,
                  scenario=args.shape + "-shape" if args.shape else "size-sweep")
    return record


def run_cell(args, arm, binary, peer, size, pair):
    with cpu_owner(args, optional=True) as cpu:
        record = _run_cell(args, arm, binary, peer, size, pair, cpu)
    if record is not None:
        semantics = ("terminal-wake-before-settle" if arm == "session" else
                     "copy-completion" if args.direction == "nic-gpu" else
                     "tx-completion" if arm == "afxdp-cuda" else "local-socket-custody")
        measurement = cpu.measurement([dict(arm=arm, identity={"pair": pair, "direction": args.direction},
            metric="io_ns", keys=[0], expected_duration_ns=record["io_ns"],
            endpoint_semantics=semantics, clock="CLOCK_MONOTONIC")])
        if measurement is not None:
            record["cpu_measurement"] = measurement
    return record


def main(argv=None):
    args = arguments(argv)
    if args.dry_run:
        print(json.dumps({"status": "planned", "arms": args.arms, "direction": args.direction,
                          "cpu_measurement_plan": cpu_owner(args).plan()}, sort_keys=True))
        return 0
    binaries = {}
    for arm in args.arms:
        binary, reason = build("session_gpu_nic" if arm == "session" else arm, args)
        if reason:
            skip(arm + ": " + reason)
        else:
            binaries[arm] = binary
    peer, reason = build("nxp_peer", args)
    if reason:
        skip("nxp_peer: " + reason)
        return 4
    if args.build_only:
        for arm, binary in binaries.items():
            print("Built %s: %s" % (arm, binary), file=sys.stderr)
        print("Built nxp_peer: %s" % peer, file=sys.stderr)
        return 0 if len(binaries) == len(args.arms) else 4
    if not Path("/sys/class/net/%s" % args.ifname).exists():
        skip("interface %s unavailable" % args.ifname)
        return 4
    if not Path("/dev/nvidiactl").exists():
        for arm in CUDA_ARMS:
            if binaries.pop(arm, None):
                skip(arm + ": NVIDIA control device unavailable")
    if not binaries:
        return 4
    peer_binary = args.peer_binary or str(peer)
    sizes = [SHAPES[args.shape]] if args.shape else args.sizes
    ran = 0
    try:
        for size in sizes:
            order = [a for a in args.arms if a in binaries]
            for pair in range(args.pairs):
                for arm in (order if pair % 2 == 0 else order[::-1]):
                    record = run_cell(args, arm, binaries[arm], peer_binary, size, pair)
                    if record is None:
                        skip("%s size=%d: capability refused" % (arm, size))
                        continue
                    print(json.dumps(record, sort_keys=True))
                    ran += 1
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("gpu_nic eval failed: " + str(error), file=sys.stderr)
        return 1
    return 0 if ran else 4


if __name__ == "__main__":
    sys.exit(main())
