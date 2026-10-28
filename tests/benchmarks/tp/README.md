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
inconsistent pairs. These fields identify native handoff primitives. It does not implement the full E6 configuration d2, NHI
completion polling, early CTS or a/b/c attribution arms.

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
