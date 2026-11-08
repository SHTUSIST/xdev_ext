# Two-rank TP E6/E7 driver

This executable uses the actual native collective library and two separately
admitted GPU allocations per rank. It implements E6 complete allreduce or
rowwise all-gather latency and E7 payload/lifetime accounting, plus real d1/d2 depth1 opaque-message echo RTT. It supplies no
fake backend, host-payload staging or hardware performance result. Follow
[the performance policy](../../../docs/reference/performance-policy.md).

Build the native PEER/CUDA and TP libraries first. Then compile this executable
and the independent GPU oracle with the same official SDK and GCC compiler:

```sh
python3 tools/build/tp_eval.py \
  --cuda-home "$CUDA_SDK" --native-receipt "$TP_BUILD/receipt.json" \
  --out "$EVAL_BUILD" --arch sm_80 --host-cxx g++
```

The builder requires real libbpf >= 1.0 through pkg-config, or explicit
`--libbpf-include` and `--libbpf-archive`, plus libelf and zlib. Its receipt
inventories the executable, oracle PTX/cubin, sources, native receipt and exact
compile/link commands. It does not execute any output. CUDA Driver stubs are
link inputs only; never place their directory in `LD_LIBRARY_PATH`.

Physical execution requires a firmware-booted qualified kernel (no kexec), real
NVIDIA driver/GPU and XDOMAIN modules, the actual per-host NVIDIA device node,
local never-reused link token, the XDOMAIN class BPF object, USER class BPF object and the native CUDA
control PTX. Each rank must use the same communicator, epoch, first sequence,
operation, dtype, shape, mode, logical depth and iteration count. The separate
TCP control socket carries configuration/barriers only. Rank 0 binds its
control address; rank 1 connects to that address. Barriers and GPU input fill
finish before E6 timing begins. The examples below are commands for a future
qualified physical run, not instructions to run on an unqualified host.

On both ranks set runtime library directories to actual compiled libraries and
set `XDEV_EXT_CUDA_PTX` to the base control kernels, then launch with each rank's
local `--rank`, `--link`, `--device` and `--nvidia-node` values:

```sh
python3 tests/benchmarks/tp/run.py \
  --driver "$EVAL_BUILD/tp_eval" --raw rank0.jsonl --summary rank0-summary.json -- \
  --rank 0 --link "$LOCAL_LINK" --device 0 --nvidia-node /dev/nvidia0 \
  --mode d1 --depth 1 --operation sum --dtype f32 --elements 1024 --rows 1 \
  --iterations 10 --first-sequence 1 --communicator 77 --epoch 1 \
  --control-address "$RANK0_CONTROL_IP" --control-port 24567 \
  --bpf-object "$PEER_BPF" --user-bpf-object "$USER_BPF" --tp-ptx "$TP_BUILD/xdev_tp.ptx" \
  --oracle-ptx "$EVAL_BUILD/tp_eval_verify.ptx"
```

To request EARLY endpoint admission, pass `--early-cts 1` among the driver
arguments after `--` on both ranks. The default is `--early-cts 0`; values above
1 are rejected before endpoint ownership or GPU work. Both ranks must request
the same value: the existing fixed-width control handshake rejects a mismatch
before either rank opens its owner. The rank-local runner passes these driver
arguments through unchanged. Final metadata records boolean
`early_cts_requested`, which describes the request and does not establish
observed transport, DMA or performance. Framework/vLLM EARLY selection is a
separate integration requirement.

Use a distinct raw filename for rank 1 and for every subsequent run. Raw output
is created exclusively so an original failed run cannot be overwritten. The
driver retains its process/context/resources on unknown native/GPU custody and
prints `TP_EVAL_RETAINED`; explicit recovery must establish quiescence before
those resources are reclaimed. Do not treat killing that process as proof of
successful drain.
The normal runner writes a summary only after the driver exits successfully;
a late close failure or timeout cannot qualify a run. Offline `--analyze-only`
checks saved observations and does not certify owner teardown.

D1 is explicitly host-synchronous and admits depth 1. D2 captures a real
`xdev_tp_submit_batch` template. For depth above 1 that API enqueues all TX
producers, then all receive/results, then all TX terminals. Every replay uses
fresh native ready tickets and the library's actual GPU sequence counter.
Each item has separate input/output storage held until the graph and graph
executable are destroyed and native work destruction succeeds. Inputs change
on every consecutive replay. The independent GPU kernel checks every item
before its output may be reused. F16/BF16/F32 fixtures use exactly representable
small integers; this driver does not claim arbitrary NCCL bit identity.

The native API may reject a requested depth for geometry, template or ring
budget. A request is never reported as observed depth. The summary recomputes
occupancy from acquisition through final native release, cross-checks the
native high-water value, and rejects missing/unreleased/failed traces or any
trace overflow. A partial-lifetime diagnostic helper separately observes held
resources without admitting their bytes as a physical throughput result.

Payload totals include only unique delivered messages independently validated
on the GPU. Rank 0 RX denotes rank1-to-rank0, and rank 1 RX denotes the opposite
direction. Preserve both rank-local denominators; this runner does not sum
rates from unsynchronized host clocks. Wire bytes include headers/padding and
are reported separately. The TP API does not expose transport retry bytes;
the summary leaves that counter unknown, never counts retries as unique
payload, and does not infer link utilization from the payload rate. Header
checking in the native library is not the independent payload check.

E6 starts a local host monotonic interval immediately before the native call
or graph launch and ends after real result/required custody completion. It
includes d1 host control, packing, visibility and reduction/unpack. D2 native
occupancy traces use one GPU globaltimer domain, retained separately from host
latency intervals. Use `--operation echo --mode d1 --depth 1` or
`--operation echo --mode d2 --depth 1` for the real opaque-message exchange.
Rank 0 creates and checks the payload on the GPU; rank 1 independently checks
its received message and copies it directly into its separately admitted TX
allocation on the GPU. Both ranks release RX only after actual CUDA last use
and complete TX terminal custody before the interval ends. After terminal
done publication, both local sessions must report cumulative kernel END
completion through that iteration. One monotonic timeout bounds the two-session
statistics poll; abort, held/sequestered custody and native errors reject the
interval. Future iteration in-flight work does not substitute for completion of
the measured iteration. Rank 0 reports
full RTT on its own host clock; rank 1 reports local reply completion. No
cross-host timestamp subtraction or measured one-way latency is implemented.
Half an RTT is only a symmetric estimate and is not emitted as a measurement.
D2 echo captures one graph outside the measured interval. Each replay obtains
fresh native tickets and keys; the GPU replay counter selects a new byte pattern.
Its three message controls reside in one retained device state. Graph completion,
independent host observation and both current END prefixes precede interval end.
The graph executable and graph are destroyed before final stream synchronization
and device state release. Any failed or unknown use retains the resources.
This benchmark-local echo uses the existing native GPU USER API; it adds no
collective operation. Every final record identifies `native_mode` (1 or 2) and
`handoff_mode` (`cpu` or `gpu` respectively); the summary rejects missing or
inconsistent pairs. These fields identify native handoff primitives.

## Host frames for a GPU without GPUDirect RDMA

The PEER route above needs GPUDirect RDMA: the XDOMAIN controller reads and
writes the GPU allocation directly. A GPU without it (for example an RTX 5090,
which reports `gpu_direct_rdma=0`) refuses the PEER owner. `--frames host`
selects the host-frame route instead; `--frames peer` is the default.

Each rank then owns two copy-engine windows: CUDA VMM allocations, each
exported as a POSIX fd and attached to its own `--nvidia-node` CE fd. One
collective:

1. posts the receive batch: session `[XDOMAIN RX, CE TO_DEVICE + TARGET_RANGE]`
   on the ring's host frames;
2. packs header and payload on the GPU into the send window;
3. posts the send batch: session `[CE FROM_DEVICE, XDOMAIN TX]`, so the copy
   engine copies the send window into host frames and XDOMAIN transmits them;
4. waits for the receive batch: XDOMAIN received the peer's group into host
   frames and the copy engine wrote it into the receive window at
   `(sequence % receive groups) * group bytes`;
5. runs the result kernels on that group, then waits for the send batch.

The CPU copies no payload byte. Payload still crosses host memory: one
GPU-to-host copy on the sender and one host-to-GPU copy on the receiver, by the
GPU copy engine.

`--ce-bpf-object` names the compiled `tp_ce_place.bpf.c` (PRIVATE, one
instance per CE stage); `--bpf-object` still names the XDOMAIN program and no
USER program is used. Build the program for the target kernel's BTF like the
K-KV programs:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86 \
  -I. -I"$VIEW/kernel/tools/xdev_ext_mech" -c tp_ce_place.bpf.c -o tp_ce_place.bpf.o
```

Host frames run d1 collectives only: every collective is driven by host START
and wait calls, so d2, CUDA graph capture and `--operation echo` refuse it, and
PRIVATE stage pins are not accepted. Metadata records `"frames": "host"`; the
handshake marks host frames in bit 30 of the mode word, so both ranks must
choose the same route.

Host checks: `tests/core/family/xdomain_create_test.c` (CREATE admits both
pairs on host frames), `tests/core/library/frame_endpoint_test.py`,
`tests/compute/tp/frames_test.py` (two ranks through loopback endpoints with the
production kernels run on the host), `tests/compute/tp/ce_place_test.py`,
`tests/compute/tp/frame_owner_test.py` and the driver tests under
`tests/compute/tp/eval`. None of them runs a GPU, a copy engine or XDOMAIN, and
none measures time.

## E6 configurations

The evaluation plan's E6 configurations are compositions of existing native
features, selected per run:

| Configuration | Driver flags | `xdev_ext_xdomain.poll_completions` |
| --- | --- | --- |
| b | `--mode d1 --early-cts 0` | N |
| c | `--mode d1 --early-cts 0` | Y |
| d1 | `--mode d1 --early-cts 1` | Y |
| d2 | `--mode d2 --early-cts 1` | Y |

All of them assume the kernel with the backported per-ring interrupt
throttle. NHI completion polling is the read-only module parameter
`poll_completions` of `xdev_ext_xdomain`, set at module load (for example
`xdev_ext_xdomain.poll_completions=1` on the kernel command line). Every
final metadata record carries `xdomain_poll_completions`, read from
`/sys/module/xdev_ext_xdomain/parameters/poll_completions`; it is `null` when
the parameter cannot be read. `pair.py` requires a boolean observation and the
same value in both arms. `early_cts_requested` remains a request; use the EARLY
trace procedure below for execution evidence.

In d2 no user thread sits between a native completion and the next stage. The
GPU publishes completions on the USER completion ring, and the session's kernel
worker reaps them because every USER stage of the PEER endpoint is created
`STRICT_ASYNC | POLL`. An XDOMAIN completion is processed by the same worker,
which hands the batch to the next USER stage through its ready ring, which the
GPU polls. Unless the device reports GPUDirect RDMA write ordering, the
receive side orders NHI writes before GPU reads with
`CU_STREAM_MEM_OP_FLUSH_REMOTE_WRITES` inside the stream or graph; a device
offering neither is rejected at open; such a GPU can run d1 with
`--frames host` (see "Host frames" above), not d2. Whether
these GPU-visibility and DMA paths hold on the target GPU and Thunderbolt
controller is a hardware question this driver cannot answer. The busy-polling
user-thread variant (d2-user) and the k=1 TCP attribution arm are not
implemented here.

## EARLY execution evidence

The request flag is not an execution verdict. Enable both
`xdev_ext:xdomain_event` and the existing `xdev_ext:native_event` before owner
open/START. The dedicated `abi=xdev-xdomain-v1` record carries local monotonic
time, session/stage/direction, admitted EARLY mode, both incarnations and bind
IDs, group/key/ticket/pool generation, status and quiescence. Key zero is valid.

The relevant boundaries are:

| Phase | Evidence |
| --- | --- |
| `stage_bound` | Class bind and reliable state initialization succeeded; whole CREATE may still fail later. |
| `tx_attempt` | Actual TX submit attempt, including an earlier attempt that returns EAGAIN. |
| `rx_reserved` | An admitted RX group/batch is reserved; native leases and post follow. |
| `cts_sent` / `cts_received` | Control enqueue accepted CTS / ingress validated CTS; receipt may repeat. |
| `grant_accepted` | The protocol accepted the grant, independently of mere receipt. |
| `native_accepted` / `native_rejected` | Payload post API accepted ownership / refused before acceptance. |
| `native_complete` | Final native callback, with status and quiescence. |
| `consumer_release` | Core completed the final frame disposition and invoked RX batch release. |
| `ack_sent` / `fail_sent` | Final disposition was accepted by the control enqueue API. |

EARLY reserves and posts a legal free RX group before the matching TX attempt;
ordinary mode waits for the per-group RTS. Neither path authorizes overwriting
a consumer-held frame. A later disjoint frame may be posted while the previous
consumer still holds its frame. RX `posted_groups == 0` excludes an earlier
unquiesced native RX post; it does not imply that every downstream consumer has
released. ACK requires the final successful, quiescent release.

`native_accepted` is the API-return boundary, not DMA first byte. A final
callback can precede that return. The analyzer accepts this causal order and
does not invent a positive native interval for it. `tx_attempt` is transport
readiness, not the GPU producer's exact timestamp.

On each qualified physical host, use a new private trace instance and output
directory for each run. Set `RUN_ID` to a unique simple name. The following
commands only configure that instance; they assume the events already exist
in the booted, matching kernel:

```sh
RUN_DIR="$RESULTS/$RUN_ID"
INSTANCE="/sys/kernel/tracing/instances/$RUN_ID"
mkdir -m 700 "$RUN_DIR"
sudo mkdir "$INSTANCE"
printf 'mono\n' | sudo tee "$INSTANCE/trace_clock" >/dev/null
printf '8192\n' | sudo tee "$INSTANCE/buffer_size_kb" >/dev/null
printf '1\n' | sudo tee "$INSTANCE/events/xdev_ext/xdomain_event/enable" >/dev/null
printf '1\n' | sudo tee "$INSTANCE/events/xdev_ext/native_event/enable" >/dev/null
sudo cat "$INSTANCE/events/xdev_ext/xdomain_event/format" > "$RUN_DIR/xdomain-format.txt"
sudo cat "$INSTANCE/events/xdev_ext/native_event/format" > "$RUN_DIR/native-format.txt"
printf '1\n' | sudo tee "$INSTANCE/tracing_on" >/dev/null
```

Run the rank-local driver command above with `--early-cts "$EARLY"`, writing
`--raw "$RUN_DIR/rank.jsonl" --summary "$RUN_DIR/summary.json"`. Start rank 0
first, then rank 1 with the same shared configuration and its own local device,
link and files. Capture from before owner open through successful driver exit,
including close. Then save the stopped buffers and every CPU's loss counters:

```sh
printf '0\n' | sudo tee "$INSTANCE/tracing_on" >/dev/null
sudo cat "$INSTANCE/trace" > "$RUN_DIR/trace.txt"
for cpu in "$INSTANCE"/per_cpu/cpu*; do
  printf '%s:\n' "${cpu##*/}"
  sudo cat "$cpu/stats"
done > "$RUN_DIR/trace-stats.txt"
python3 tests/benchmarks/tp/early_trace.py \
  --trace "$RUN_DIR/trace.txt" --stats "$RUN_DIR/trace-stats.txt" \
  --tp-summary "$RUN_DIR/summary.json" --output "$RUN_DIR/early-evidence.json"
```

The summary selects the actual local TX/RX session IDs. The analyzer requires
admission, immutable identity, the earliest TX attempt, quiescent completion,
RX release/ACK, complete native frame coverage and matching core
`record_terminal` records. It also checks all `iterations * depth` ordered TP
keys on both sessions against the finite START count and group geometry.
A completed prefix cannot qualify a truncated run. Missing/overwritten events,
nonzero overrun/commit-overrun/dropped counters, wrong identity and premature
frame reuse cannot produce success. Late ordinary CTS duplicates without a live
slot lack a reliable key correlation and are conservatively rejected. The frame
reuse check uses RX reservation time, so a late post return cannot hide a
reservation made before the previous consumer release.

Exit 0 means these local trace checks completed, exit 1 means incomplete
evidence, and exit 2 means rejected input. `--session-id TX RX` is available
without a TP summary, but its completeness is limited to observed groups.
Neither mode establishes hardware provenance, independent GPU payload
correctness or successful process teardown. Preserve those separately.

`grants_before_first_tx_attempt` counts actual accepted grants strictly earlier
than the first attempt for that key. `grant_lead_ns` is first attempt minus grant
acceptance; receipt alone cannot increase this count. Equal timestamps do not
prove a positive lead. The RX overlap measure intersects a later group's
accepted-post-to-callback interval with an older group's
callback-to-consumer-release interval, and requires disjoint native frame IDs
in the same session/stage. It is driver in-flight versus consumer custody,
not physical engine busy time or GPU compute overlap. Frame IDs do not rule out
aliasing across independently exported sessions; keep the owner's separate
admitted allocations and mapping/lifetime evidence. Do not subtract timestamps
between hosts, GPU globaltimer and kernel monotonic clocks.

## Matched EARLY off/on experiments

Use the same rebuilt driver/libraries, kernel/modules/BPF objects, GPUs, links,
dtype/shape, depth, iteration count, timeout and payload oracle in both arms.
Record hashes, build receipts, boot/kernel identity, topology and mapping
admission. Use fresh endpoint/link authority and epoch as required by the
existing lifecycle procedure, and preserve failed runs. Both ranks must agree
on EARLY for each run.

Run repeated paired blocks in ABBA order: off, on, on, off. Start with
`--mode d1 --depth 1`, then use `--mode d2 --depth 2` for the disjoint-frame
overlap question. Repeat each fixed shape separately, including the short-tail
case in the example. A native geometry/ring-budget rejection is an experimental
outcome, not permission to silently change a workload. Use at least 100 measured
iterations plus a declared warmup for performance cohorts; short traced
cohorts are useful for mechanism checks. Measure trace overhead with matched
tracing settings and preserve a separate untraced performance cohort.

Collective E6 intervals now end after CUDA/TP completion and the cumulative
kernel END prefix on both local sessions. USER done alone cannot close an
interval. Metadata records `completion_boundary="kernel-end-prefix"`,
configuration geometry and native session IDs. START, input fill and the rank
barrier precede E6; EARLY may have pregranted outside the interval. E6 therefore
measures operation-to-END service latency, not startup wall time. Report startup
and steady-state observations separately. At depth above one, E6 is a complete
batch/replay latency, not a per-message latency.

Compare each rank separately with:

```sh
python3 tests/benchmarks/tp/pair.py \
  --off "$OFF_DIR/summary.json" --on "$ON_DIR/summary.json" \
  --warmup 10 --output "$PAIR_DIR/rank0-pair.json"
```

The helper checks matching geometry/completion semantics and reports E6
p50/p95/p99/mean plus validated local RX bytes divided by the sum of selected E6
intervals. E7 retains its original whole-trace denominator, including
inter-replay gaps and warmup, and reports logical lifetime occupancy. It is not
DMA overlap. Echo comparisons report local RTT/reply latency without inventing
tensor payload totals. Report sample counts and the distribution of paired
run-level differences; do not infer benefit from one ratio, requested EARLY,
or greater logical occupancy.

For errors, first reuse `tests/network/xdomain/early/run.py --observe` and the
full default suite: held/disjoint frames, attempted reuse, duplicate CTS,
control pressure, callback ordering, downstream failure, sequester and UNKNOWN
STOP. Hardware fault injection needs a separately qualified recovery procedure.
A retained owner, failed oracle, nonquiescent native callback, trace loss or
incomplete terminal chain invalidates a performance arm. Save its diagnostics
and keep uncertain resources retained.


For a matched baseline use the normal official NCCL executable. Select
`NCCL_NET=Socket` and exact `NCCL_SOCKET_IFNAME='=thunderbolt0'`, retain NCCL
algorithm/protocol/channel/buffer/concurrency defaults, and save actual INIT/NET
logs plus interface addresses and before/after byte counters. Environment
settings alone do not qualify the route. `qualify_nccl_route` checks supplied
NET/Socket interface selection and positive observed counter deltas; it never
adjusts the baseline. A fair comparison also needs matched effective work,
dtype/layout, legal concurrency and result/custody timing. This driver does not
certify or run the NCCL baseline.

Software-only checks:

```sh
python3 -m unittest discover -s tests/compute/tp/eval -v
```

These arithmetic/admission checks and build-only receipts certify no physical
DMA, GPU execution, pipeline occupancy or performance advantage.

The shared owner explicitly attaches `xdomain_peer_ops` from `--bpf-object` and
`user_plan_ops` from `--user-bpf-object` before native CREATE. The normal USER
program source is `examples/compute/user_plan.bpf.c`. It retains both program
references until the native endpoints close; it does not rely on unrelated
processes having previously registered a class. A missing or conflicting class
program causes explicit admission failure, with partial resources retained for
safe cleanup.
