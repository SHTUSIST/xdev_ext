# Performance evaluation and comparison policy

This contract applies to evaluation workloads, baselines, measurement tools and
their documentation. Correctness, build qualification and performance are
separate claims. A correctness-only workload does not become a performance
benchmark by linking this policy.

## Preserve the baseline

Preserve the original baseline implementation and record its source, supported
configuration and actual execution scope. By default, do not optimize or tune a
baseline: this includes adding fixed buffers, changing registration reuse,
pipelining, double buffering, caching, prefetching, concurrency or batching.
Existing optimizations in the selected implementation remain part of that
baseline. Do not remove or restrict them to manufacture an advantage either.
A new baseline optimization or a different baseline design requires an explicit
experiment scope; it is not an automatic fairness repair.

There is a narrow exception for a necessary native-path or zero-copy
qualification correction. Establish that the original path actually fails the
required qualification, retain the evidence, make the smallest correction, add
a regression that fails before the correction, and disclose the change and its
effect on the comparison. The evidence must distinguish a demonstrated failure
from an unsupported inference. In particular, absence of an io_uring `FIXED`
flag does not by itself establish a payload copy or disqualify zero-copy.
Conversely, a native API call or a pinned allocation alone does not establish
the actual device path.

Correcting a timer that stops before its required drain, requiring missing
native-path evidence, or making a build-only entry actually compile its declared
target can be measurement qualification work. Preserve the original evidence
and use a failing regression for a code correction. These changes do not
authorize a baseline redesign or demonstrate a performance gain.

## Decide whether a performance task is useful

Before adding an adaptation or performance experiment, record a decision:

| Decision | Required basis |
| --- | --- |
| GO | The workload exercises the mechanism, the comparison is meaningful, and measured or explicitly bounded critical-path costs support the proposed macro improvement. |
| HOLD | Device access, comparable outputs, path qualification or critical-path evidence is missing. Record the missing evidence without inventing a benefit. |
| NO-GO | The workload does not exercise the optimization, its upper bound cannot meet the objective, or the experiment would answer a different question. Explain the reason instead of adding the adaptation. |

For performance-driven additions, screen for at least **1.20 times macro
speedup** against the preserved baseline. This is a feasibility criterion, not a
promised result or permission to select a weak baseline. Define whether the
objective is throughput improvement or runtime reduction: 20% less time is
1.25 times speedup, not 1.20 times.

For a serial critical-path model, let `f` be the fraction of the original macro
runtime affected, `s` the speedup of that part, and `delta` the added cost as a
fraction of the original runtime:

```text
macro_speedup = 1 / ((1 - f) + f / s + delta)
macro_speedup >= 1.20 requires f * (1 - 1/s) - delta >= 1/6
```

Use actual critical-path evidence or label an optimistic bound explicitly.
Overlapping trace intervals and whole-machine CPU totals cannot be added to
derive `f`. If even the optimistic bound misses the objective, the proposed
performance justification is NO-GO. Missing inputs are unknown, not zero.
I/O volume alone does not establish that I/O is on the critical path.

Pipelined throughput also needs a resource bound: device service, available
credits, CPU, copy engines, host DRAM and shared PCIe links may limit different
arms. An additional DMA leg can overlap other work while still consuming those
resources. Once the baseline saturates the same storage bottleneck, reduced
coordination cost need not improve storage throughput. CPU savings can be a
separate measured result with its own stated objective.

Correctness fixes, ownership/lifetime checks, necessary qualification and build
validation **do not require a 20% speedup**. Preserve useful existing workloads
and negative results; a NO-GO decision is not a reason to erase their records.

## Compare actual contracts, not matching parameter names

Describe the useful input and output, placement, protocol, cache and durability
semantics, completion condition, timer endpoints, registration lifetime and CPU
budget of each arm before admitting a pair. Distinguish a controlled ablation
from a comparison of different complete data paths. Refuse an equivalent-work
ratio when the outputs or completion obligations differ; retain the individual
records and the refusal reason.

Queue depth is not a universal quantity. Record whether it bounds NVMe commands,
CUDA streams, stage-local operations, whole logical transfers or occupied
buffers, and report effective occupancy and in-flight bytes when available.
A double-buffered pipeline may legitimately contain work in multiple stages
while each stage respects its own depth. Do not impose a new global credit
limit merely to make its nominal QD match another arm. Such a change can remove
the baseline's original overlap and is not a default qualification correction.

If a batch API's existing wave geometry admits more work than a requested
comparison contract, reject that non-equivalent cell or report it separately.
Do not rewrite the baseline scheduler to force the contract. Use only settings
whose actual semantics meet the declared comparison, and disclose the selected
scope rather than silently relabeling concurrency.

Include poll cores, workers and IRQ work in the stated CPU budget. Matching a
blocking strategy can define a controlled experiment, but does not establish
that an existing polling implementation is invalid or that blocking is the
strongest alternative. Retain the original baseline strategy and distinguish
latency, throughput and CPU-cost questions.

Output residency matters: an unordered batch, a final slot ring, an ordered
device window and a checkpoint are different results. A final-slot readback
does not verify overwritten history. Streaming comparisons can be valid when
their real consumer or retained evidence supplies the required complete
correctness contract; do not forbid streaming merely because one existing
oracle only checks final slots. Do not remove an oracle guard without replacing
its missing evidence. Keep validation and integrity work outside the timed path
unless it is part of the same useful workload for every compared arm.

## Measurement and evidence

Time through the completion and drain actually required by the declared
operation. An event notification alone is insufficient when outstanding work or
a final verdict still remains. State separately whether setup, registration,
flush, release and validation are included. A write completion is not an
implicit power-loss durability guarantee. Submit-to-reap intervals may overlap
and include scheduling; do not describe their sum as a partition of wall time.

Native and zero-copy labels require evidence for the actual execution path.
Report fallback, unqualified routing or missing counters explicitly. Distinguish
logical payload legs, accepted commands and hardware transactions. A software
pointer, a successful registration or a build receipt does not prove DMA.

Host contracts, dependency substitutes and software guests establish only their
stated correctness or build scope. VM time is not physical-device performance
evidence. A real SDK build is build-only until execution is separately shown;
an entry that did not compile cannot claim a successful build. Missing
capabilities and unknown measurements produce no fabricated performance value.
Retain raw failures, partial results and comparable negative outcomes.

Use GCC/G++ by default for ordinary host and kernel builds. Do not introduce
general Clang compilation, test or CI runs without separate authorization.
Clang used to emit required BPF bytecode remains a necessary BPF build tool;
that exception does not authorize unrelated Clang host or kernel campaigns.
Use the declared official SDK toolchain for device compilation.

Record the fixed source and relevant configuration, dependencies, input and
oracle with each campaign. Compute hashes only at necessary version or key
artifact boundaries, once outside measurement; reuse verified evidence when its
inputs are unchanged. Do not hash each transfer, record or comparison cell, or
rehash historical results merely for documentation and routine transmission.
Evidence links locate retained artifacts; they do not make a metadata-only
archive a complete raw backup.
