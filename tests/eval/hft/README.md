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

Build the actual optional backends and the independent benchmark BPF object
(`kernel/tools/xdev_ext_mech/hft_benchmark.bpf.c`, maps `hftb_nvme_ops` and
`hftb_afxdp_ops`) against the running producer BTF. Build receipts bind the exact
artifact/source/product/BTF hashes and, for this object, `measurement_policy`
`benchmark-policy-v1` and wire version1. `hardware-bpf` still builds the production
NXP object for correctness runs; it is not accepted by the strict campaign:

```sh
make -C tests/eval/hft ENABLE_URING=1 ENABLE_SESSION=1
make -C tests/eval/hft hardware-benchmark-bpf VMLINUX_BTF=/sys/kernel/btf/vmlinux
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

Qualify the producer assets once, without START or any workload. This runs a real
no-START native setup probe with the benchmark object (XDP zero-copy, strict CREATE,
both map IDs, STOP0) and records file identities, hashes and the admitted source
window in an exclusive receipt:

```sh
python3 tests/eval/hft/hardware_measure.py qualify --measurement-policy benchmark-policy-v1 \
  --qualification QUALIFICATION_RECEIPT ...same producer options as measure...
```

Then supply the producer's read-only namespace, intended physical NIC and peer:

```sh
python3 tests/eval/hft/hardware_measure.py measure --measurement-policy benchmark-policy-v1 \
  --qualification QUALIFICATION_RECEIPT \
  --product-sha COMMIT --ifname PRODUCER_IFACE --kernel-config RUNNING_CONFIG \
  --peer-control CONTROL_IP:CONTROL_PORT --source-block BLOCK --source-ng NG \
  --slba SLBA --nlb NLB --queue QUEUE --local-ip LOCAL_IP --peer-ip PEER_IP \
  --local-mac LOCAL_MAC --peer-mac PEER_MAC --local-port LOCAL_PORT \
  --peer-port PEER_PORT --bpf-object tests/eval/hft/.build/bpf/hft_benchmark.bpf.o \
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

### Strict campaign policy `benchmark-policy-v1`

`measure` accepts only the explicit `benchmark-policy-v1` selector; there is no
fallback to the production NXP2 object or encoder. Without a matching asset
qualification and physical environment it exits4 before any START with no stdout
and `start_issued=false`.

- Wire: every arm sends the same independent 40-byte HFT1 application header
  (magic `0x48465431`, version1, fixed fields, session, generation, payload length)
  followed by the unmodified source payload. The measured encoders never read the
  payload and compute no application CRC; the network template is built once at
  setup. POSIX and registered sockets set `SO_NO_CHECK`; the native template sends a
  zero UDP checksum. This covers the benchmark's own checksum only, not the whole
  network stack (the native provider still finishes the IPv4 header checksum).
- Capacity: the peer reserves RAM for every complete datagram and raw wire frame of
  every trial before `CAMPAIGN_READY`; the producer allocates one raw guard record
  per generation before its setup barrier (the native BPF history map holds up to
  1024 generations). Insufficient capacity refuses before READY/START.
- Online work is limited to header/identity/length/unique-generation checks and
  received-only receipts (`status=received`, never `validated_*`). A datagram is
  copied completely into its reserved slot before it can be receipted; a rejected
  datagram poisons the trial. Producer arms record the raw 430-byte prefix and
  full suffix guard of each frame at its terminal post-send point, before the slot
  is reused (native: in the `hftb_afxdp_complete` callback), without comparing them.
- Timing: one CLOCK_MONOTONIC_RAW sample per burst covers read/NOTIFY_ARM/START,
  submission, completion, history capture, local release and the fresh peer receipt.
  One-time registration and final teardown are recorded separately. The registered
  arm registers its slots once and reuses them; no copy or re-registration is added.
- Each trial reports actual submissions, registrations, completion counters
  (READ/SEND results, NOTIF and copied usage) and, for the native arm, the exact
  terminal stage STATS, zero-copy CREATE and map IDs plus STOP0; the controller
  checks these per arm as they arrive.
- After every trial has finished, drained and released, the controller reads the
  whole source window back once and calls `campaign_oracle.verify_campaign` exactly
  once. It compares every byte of every captured datagram (warmup included, all
  trials) against bytes generated from the specification formula and every raw guard
  record against the guard pattern, plus the complete generation sets, frame slots
  and STOP evidence. Earlier damage cannot be hidden by later clean reuse of the same
  slot. Only then is one artifact manifest written and the result, raw samples and
  paired ratios published; a failed campaign publishes no ratio. Raw observations
  are kept privately on success and failure.

These are burst completion round-trip measurements of an HFT-style scenario
microbenchmark, not a trading system, unsynchronized one-way NIC latency or
statistical-significance claims. Building, software tests, offline fixtures and
no-hardware refusals cannot certify native DMA or physical performance; those
require actual device execution, which has not been run for this policy.

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
