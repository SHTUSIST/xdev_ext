# HFT-shaped replay microbenchmark

This read-only microbenchmark coalesces small market-data records into bounded
UDP replay bursts. It compares I/O, registration, submission, completion and
buffer ownership. It contains no trading strategy or complete HFT business system.

## Software correctness

```sh
make -C tests/eval/hft
make -C tests/eval/hft check
python3 tests/eval/hft/run.py --backend posix --mode correctness
python3 tests/eval/hft/run.py --actors 4 --burst 3 --bursts 2 --depth 4
make -C tests/eval/hft ENABLE_URING=1
python3 tests/eval/hft/run.py --backend uring-fixed-zc --mode correctness
```

`run.py` supports regular-file POSIX and optional registered-buffer software
correctness. It refuses session/raw-source requests and `--mode performance`
before workload execution, directing physical runs to `hardware_measure.py`.
The private C producer is internal; invoking it directly does not perform the
complete central hardware admission and cannot certify physical results.

Defaults are 64-byte records, 512-byte payloads, 32 packets per burst, depth8,
eight bursts, one actor and seed1. `--records` selects64/128/256 bytes;
`--payload` selects512/1024/4096; burst1..32, depth1..8, bursts1..32, actors1/4.
Unsigned decimal arguments are strict; duplicates/unknown options/invalid geometry
exit2 before artifacts or dependency discovery. `--directory` must already exist;
per-run0700 directories and exclusive0600 artifacts are cleaned normally. Existing
inputs are never truncated.

Every invocation chooses a fresh nonzero64-bit wire session with room for all
actors. The payload seed/reference remains reproducible. An independent Python
oracle validates every payload byte, CRC32C, NXP2 header and complete per-actor
generation set; stale, duplicate, missing, foreign, corrupt, extra and truncated
packets fail. Each burst needs a real receiver receipt and local buffer release;
final success also requires a full capture reparse. A positive send alone is not
delivery. Software output has one exact JSON record, scope
`buffered-host-correctness`, with no latency/throughput/timing fields.

The fixed arm allocates/registers its guarded slots once per actor, schedules
READ_FIXED up to the same depth, and passes the same slots to SEND_ZC without
payload flattening or an extra forced copy. MORE retains ownership until matching
NOTIF; terminal noMORE releases. Actual copied-usage notifications are counted;
SEND_ZC success alone does not prove native NIC zero-copy. Unsupported optional
capabilities exit4 with empty stdout and structured stderr. Runtime/oracle errors
exit1. Unknown accepted ownership is retained without replay or successful cleanup;
the error path does not claim cancellation/drain coverage.

`oracle.py generate --manifest M --reference F`, `receive --manifest M --bind
IP:PORT --control IP:PORT --capture C`, and `verify --manifest M --capture C`
provide independent reference, standalone software receiver and capture parsing.
Manifest schema1 contains `record_bytes,payload_bytes,burst_packets,depth,bursts,
actors,seed,session_base`. Software tests include four actors meeting inside their
first actual pread, valid-CRC constant-payload rejection, short-positive send
rejection, ownership MORE/NOTIF/token/UNKNOWN and external guards. These are
software checks, not simulated DMA or physical performance evidence.

## Physical paired measurement

`hardware_measure.py` is the sole supported physical execution entry. Provision
producer and peer independently from the same pinned product GitHub commit;
the tool never transports source/patches or changes host modules, NIC/route/sysctl,
raw devices or shared jobs. The peer is an ordinary UDP receiver on a physical NIC
and may run a standard kernel. Only the producer needs the strict custom kernel.

| Arm | Source and UDP transmission | Local release |
|---|---|---|
| `posix` | O_DIRECT pread and two-iovec sendmsg | exact syscall completion |
| `uring-fixed-zc` | O_DIRECT READ_FIXED and SEND_ZC from once-registered slots | result plus required NOTIF |
| `session` | native NVMe READ and AF_XDP ZC on shared UMEM host pages | exact stage STATS and final STOP0 |

Every arm reads the identical explicit namespace/window/reference, with equal
profile, warmup and peer completion. Native NVMe and NIC map the same host pages
separately for their devices/IOMMU domains; equal DMA addresses are not required.
There is no fallback copy/native substitution. This is a strong registered
network-stack baseline; it does not isolate DSL overhead against an unimplemented
common-UMEM userspace AF_XDP baseline.

Build the actual optional backends and existing NXP object against the running
producer BTF. Build receipts bind the exact artifact/source/product/BTF hashes:

```sh
make -C tests/eval/hft ENABLE_URING=1 ENABLE_SESSION=1
make -C tests/eval/hft hardware-bpf VMLINUX_BTF=/sys/kernel/btf/vmlinux
python3 tests/eval/hft/hardware_measure.py --help
```

`COMMIT` below is the same pinned40-hex product commit on both machines;
`RUNNING_CONFIG` identifies that machine's trusted running-release kernel config.
Start the predeployed peer with real control/data endpoints:

```sh
python3 tests/eval/hft/hardware_measure.py peer \
  --product-sha COMMIT --ifname PEER_IFACE --kernel-config RUNNING_CONFIG \
  --bind CONTROL_IP:CONTROL_PORT --data-bind PEER_IP:PEER_PORT \
  --directory EXISTING_PRIVATE_DIRECTORY
```

Then supply the producer's read-only namespace, intended physical NIC and peer:

```sh
python3 tests/eval/hft/hardware_measure.py measure \
  --product-sha COMMIT --ifname PRODUCER_IFACE --kernel-config RUNNING_CONFIG \
  --peer-control CONTROL_IP:CONTROL_PORT --source-block BLOCK --source-ng NG \
  --slba SLBA --nlb NLB --queue QUEUE --local-ip LOCAL_IP --peer-ip PEER_IP \
  --local-mac LOCAL_MAC --peer-mac PEER_MAC --local-port LOCAL_PORT \
  --peer-port PEER_PORT --bpf-object tests/eval/hft/.build/bpf/nxp_mech.bpf.o \
  --reference PREPARED_READ_ONLY_REFERENCE --records 64 --payload 512 \
  --burst 32 --depth 8 --bursts 8 --warmup-bursts 1 --pairs 5 --order-seed 1 \
  --directory EXISTING_PRIVATE_DIRECTORY
```

The immutable regular reference must have no write bits and contain exactly
`burst*(warmup_bursts+bursts)` payloads already present in the raw source window.
This entry compares all three arms with actors1 and admitted512/1024-byte
payloads. Native uses4096-byte frames, headroom512 and packet offset430; payload
must satisfy actual namespace LBA/DIO and MTU constraints. A512-byte profile on
4KiB-LBA storage refuses;4096-byte native payloads exceed this initial layout.
Four native actors also refuse because the existing struct_ops registry/global
NXP session is single-instance. Unsupported profiles are never silently changed.

Admission observes positive physical DMI/PCI evidence, actual NIC/address/MAC,
trusted running config, clean pinned GitHub source, executed binary hash, matching
block/NG identity, capacity/LBA/DIO, every required source/reference byte and BPF
source/build/running-BTF bindings. Unknown physical proof or DIO alignment refuses.
A real no-START native setup probe records XDP_OPTIONS_ZEROCOPY, map IDs and strict
CREATE/STATS0/STOP0; actual trials repeat runtime admission and record their own
map IDs. Producer software/device/source and peer metadata are rechecked between
runs. Caller-supplied metadata fixtures cannot unlock execution.

Bounded u32-length TCP JSON binds READY/BURST/FINISH to fresh run/session identity,
manifest/source/product digests and exact byte totals. Peer capture is reparsed,
streamed back and independently reparsed on producer; cleanup follows producer
capture acknowledgement. Peer failure retains the validated-prefix capture and
diagnostic; the rejected datagram itself is not included in that prefix. Producer
stdout/stderr and failures are retained privately. Private artifacts are exclusive
under0700 run directories and are not product source.

Each arm gets fresh full correctness before measurement. One-time setup/registration
and final teardown are separate from steady samples. The producer uses one
CLOCK_MONOTONIC_RAW clock, starting before first read/START and ending after both
local release and real remote byte receipt. Native STOP0 separately gates acceptance
of all samples. Warmup is equal and excluded. Each pair uses a recorded seeded
random permutation; raw samples and paired completion ratios retain slower and
no-benefit results. These are burst completion round-trip measurements, not
unsynchronized one-way NIC latency or statistical-significance claims. Building,
software tests, offline metadata fixtures and no-hardware refusals cannot certify
native DMA or physical performance; those require actual device execution.

Source promotion: `hft_send_zc.h` retains `prep_send_zc_fixed` from
`bench_nvme_pipeline_compare.c`307–319 and adapts `wait_zc_cqes`325–348, commit
`7937fd11cb5632f83376404fda7d2ea2a38426ff`, blob
`8a9f19cfd0636e29087c307ce8dd17856524eb1b`, full-file SHA256
`97092c1fd3a277b8fd91e3567d6304a9231ba4216b055577b9d1e4e44c05cb4a`.
No original notice was removed; the selected source had no separate license notice.
The obsolete surrounding benchmark/ABI is not imported. Preparation uses current
UAPI symbols and REPORT_USAGE; waiting dispatches stable tokens and explicit
NOTIF/MORE. Session setup derives from the current GPL-2.0 control tool; framing
uses its current pure encoder. Builds reference only active product sources.
