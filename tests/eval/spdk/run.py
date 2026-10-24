#!/usr/bin/env python3
"""SPDK NVMe->TCP QD1 pipeline: plan, offline file->TCP check, native modes.

Modes: plan (metadata only), offline-check (regular file -> loopback TCP,
no SPDK), native-correctness and native-performance (official SPDK against
an externally provisioned, userspace-bound NVMe namespace).
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
MAX64 = (1 << 64) - 1
FAULTS = {"send-eintr", "recv-eintr", "payload-first", "payload-middle",
          "payload-last", "guard-head", "guard-tail", "receiver-early-eof",
          "receiver-extra", "receiver-stall", "send-zero"}


def fail(reason, code=2):
    print(reason, file=sys.stderr)
    raise SystemExit(code)


def number(text):
    if not re.fullmatch(r"[0-9]+", text) or len(text) > 20:
        raise argparse.ArgumentTypeError("unsigned decimal integer required")
    value = int(text)
    if value > MAX64:
        raise argparse.ArgumentTypeError("unsigned integer overflow")
    return value


def parse(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--mode", required=True, choices=("plan", "offline-check",
                        "native-correctness", "native-performance"))
    parser.add_argument("--traddr", required=True)
    for name in ("nsid", "sector-size", "namespace-lbas", "start-lba", "window-lbas"):
        parser.add_argument("--" + name, required=True, type=number)
    for name, default in (("block-bytes", 4096), ("iterations", 8), ("warmup", 2),
                          ("calc-bytes", 0), ("deadline-ms", 1000)):
        parser.add_argument("--" + name, type=number, default=default)
    for name in ("reference", "capture", "spdk-root", "inject"):
        parser.add_argument("--" + name)
    for name in ("send-max", "recv-max"):
        parser.add_argument("--" + name, type=number)
    for name in ("ack-isolated-read-only", "allow-performance"):
        parser.add_argument("--" + name, action="store_true")
    seen = set()
    for token in argv:
        if token.startswith("--"):
            option = token.split("=", 1)[0]
            if option in seen:
                parser.error("duplicate singleton option: " + option)
            seen.add(option)
    a = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]", a.traddr):
        fail("canonical lower-case PCI BDF required")
    ranges = ((a.nsid, 1, (1 << 32) - 2), (a.namespace_lbas, 1, MAX64),
              (a.window_lbas, 1, MAX64), (a.block_bytes, 512, 1048576),
              (a.iterations, 1, 65536), (a.warmup, 0, 4096),
              (a.calc_bytes, 0, a.block_bytes), (a.deadline_ms, 1, 60000))
    if any(not lo <= x <= hi for x, lo, hi in ranges):
        fail("numeric option outside supported range")
    if a.sector_size not in (512, 4096) or a.block_bytes % a.sector_size or a.calc_bytes % 8:
        fail("unsupported sector/block/calculation alignment")
    if (a.start_lba + a.window_lbas > min(a.namespace_lbas, MAX64) or
            a.window_lbas * a.sector_size > MAX64 or
            a.window_lbas * a.sector_size < a.block_bytes or
            (a.warmup + a.iterations) * a.block_bytes > 64 * 1024 * 1024):
        fail("invalid/overflowing namespace window or stream budget")
    faults = a.inject.split(",") if a.inject else []
    if len(faults) != len(set(faults)) or set(faults) - FAULTS:
        fail("unknown or duplicate offline injection")
    if a.mode.startswith("native-"):
        if any(x is not None for x in (a.inject, a.send_max, a.recv_max)):
            fail("offline I/O options are invalid in native mode")
        if not a.ack_isolated_read_only:
            fail("native mode requires --ack-isolated-read-only")
        if a.mode == "native-performance" and not a.allow_performance:
            fail("performance requires --allow-performance")
        if not a.spdk_root:
            fail("native mode requires explicit --spdk-root")
    elif a.spdk_root or a.ack_isolated_read_only or a.allow_performance:
        fail("native options require a native mode")
    for value in (a.send_max, a.recv_max):
        if value is not None and not 1 <= value <= 1048576:
            fail("offline chunk cap outside supported range")
    return a


def slots(a):
    count = a.window_lbas * a.sector_size // a.block_bytes
    for i in range(a.warmup + a.iterations):
        x = i + 1
        x ^= x >> 12
        x ^= (x << 25) & MAX64
        x ^= x >> 27
        yield ((x * 2685821657736338717) & MAX64) % count


def native_prerequisites(bdf, sysfs=Path("/sys"), proc=Path("/proc"), dev=Path("/dev")):
    """None when @bdf is an NVMe function already bound to a userspace driver
    with free hugepages; otherwise the reason.  Read-only: this never binds,
    unbinds, allocates hugepages or loads a module."""
    function = sysfs / "bus/pci/devices" / bdf
    if not function.is_dir():
        return "PCI function %s not present" % bdf
    try:
        pci_class = int((function / "class").read_text().strip(), 16)
    except (OSError, ValueError):
        return "PCI function %s has no readable class" % bdf
    if pci_class >> 8 != 0x0108:
        return "PCI function %s is not an NVMe controller (class 0x%06x)" % (bdf, pci_class)
    driver = (function / "driver").resolve().name if (function / "driver").is_symlink() else None
    if driver not in ("vfio-pci", "uio_pci_generic"):
        return ("PCI function %s is bound to %s, not a userspace driver (vfio-pci or "
                "uio_pci_generic); this program never rebinds a device" % (bdf, driver or "no driver"))
    if driver == "vfio-pci":
        link = function / "iommu_group"
        node = dev / "vfio" / link.resolve().name if link.is_symlink() else None
        if node is None or not node.exists() or not os.access(node, os.R_OK | os.W_OK):
            return "vfio group node of %s unavailable or not accessible" % bdf
    else:
        nodes = sorted((function / "uio").glob("uio*")) if (function / "uio").is_dir() else []
        if not nodes or not os.access(dev / nodes[0].name, os.R_OK | os.W_OK):
            return "uio node of %s unavailable or not accessible" % bdf
    free = 0
    for counter in (sysfs / "kernel/mm/hugepages").glob("hugepages-*/free_hugepages"):
        try:
            free += int(counter.read_text())
        except (OSError, ValueError):
            pass
    if not free:
        return "no free hugepages (none are reserved by this program)"
    try:
        mounts = (proc / "mounts").read_text().split("\n")
    except OSError:
        mounts = []
    if not any(len(line.split()) > 2 and line.split()[2] == "hugetlbfs" for line in mounts):
        return "no hugetlbfs mount"
    return None


def virtual_machine():
    try:
        if Path("/sys/hypervisor/type").read_text().strip():
            return True
    except OSError:
        pass
    try:
        return any(line.startswith("flags") and " hypervisor" in line
                   for line in Path("/proc/cpuinfo").read_text().splitlines())
    except OSError:
        return False


def digest(fd):
    """Reference provenance, once, before any native command."""
    h = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(fd, 1 << 20, offset)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)
        offset += len(chunk)


def run_native(argv, ref):
    """Run the native binary.  When it reports an UNKNOWN command it stays
    alive as the quarantine owner of the DMA buffer, qpair and controller and
    closes its output; this returns 1 then without waiting for or killing it."""
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             pass_fds=(ref,), start_new_session=True)
    streams = {child.stdout: bytearray(), child.stderr: bytearray()}
    with selectors.DefaultSelector() as selector:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            for key, _ in selector.select():
                data = os.read(key.fileobj.fileno(), 65536)
                if data:
                    streams[key.fileobj] += data
                    if key.fileobj is child.stderr:
                        sys.stderr.buffer.write(data)
                        sys.stderr.flush()
                else:
                    selector.unregister(key.fileobj)
    child.stdout.close()
    child.stderr.close()
    if b"SPDK_PIPELINE_UNKNOWN" in streams[child.stderr]:
        print("native read UNKNOWN: pid %d keeps its DMA buffer, qpair and controller until the "
              "command completes; do not kill it" % child.pid, file=sys.stderr)
        return 1
    code = child.wait()
    if code == 0:
        sys.stdout.buffer.write(streams[child.stdout])
    return code


def main():
    a = parse(sys.argv[1:])
    if a.mode == "plan":
        print(json.dumps(dict(schema="spdk-pipeline-v1", mode=a.mode,
              execution="metadata-only", performance_measured=False,
              physical_execution=False, queue_depth=1, read_only=True,
              traddr=a.traddr, nsid=a.nsid,
              scheduled_lbas=[a.start_lba + s * (a.block_bytes // a.sector_size)
                              for s in slots(a)],
              stream_bytes=(a.warmup + a.iterations) * a.block_bytes)))
        return 0
    if not a.reference or not a.capture:
        fail("reference and new capture paths required")
    try:
        ref = os.open(a.reference, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        fail("cannot open regular no-follow reference: " + str(e))
    try:
        info = os.fstat(ref)
        if not stat.S_ISREG(info.st_mode) or info.st_size != a.window_lbas * a.sector_size:
            fail("reference must be a regular file exactly matching the window")
        if os.path.lexists(a.capture):
            fail("capture must be a new file")
        if not Path(a.capture).parent.is_dir():
            fail("capture parent directory unavailable")
        native = a.mode.startswith("native-")
        if native:
            sdk = Path(a.spdk_root)
            if not all((sdk / "include/spdk" / name).is_file()
                       for name in ("env.h", "nvme.h", "stdinc.h")) or \
                    not (sdk / "build/lib/pkgconfig/spdk_nvme.pc").is_file():
                fail("official SPDK SDK is unavailable: %s needs include/spdk/{env,nvme,stdinc}.h "
                     "and a built build/lib/pkgconfig/spdk_nvme.pc" % sdk, 4)
            if a.mode == "native-performance" and virtual_machine():
                fail("native performance refused inside a virtual machine", 4)
            reason = native_prerequisites(a.traddr)
            if reason:
                fail("native target unavailable: " + reason, 4)
            reference_sha256 = digest(ref)
        # Builds are outside any campaign/timing, in an invocation-owned directory.
        with tempfile.TemporaryDirectory(prefix=".spdk-pipeline-", dir=HERE) as tmp:
            binary = Path(tmp) / "pipeline"
            command = [sys.executable, str(HERE / "build.py"), "--output", str(binary)]
            if native:
                command += ["--spdk-root", str(sdk)]
            built = subprocess.run(command, capture_output=True, text=True)
            if built.returncode:
                sys.stderr.write(built.stderr)
                return built.returncode
            fields = (a.mode, a.traddr, a.nsid, a.sector_size, a.namespace_lbas,
                      a.start_lba, a.window_lbas, a.block_bytes, a.iterations,
                      a.warmup, a.calc_bytes, a.deadline_ms, ref, a.capture,
                      a.send_max or 1048576, a.recv_max or 1048576, a.inject or "")
            if not native:
                return subprocess.run([str(binary), *map(str, fields)], pass_fds=(ref,)).returncode
            return run_native([str(binary), *map(str, fields), reference_sha256], ref)
    finally:
        os.close(ref)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        fail(str(error), 1)
