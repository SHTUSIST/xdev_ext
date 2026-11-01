# Early CTS contract checks

`python3 tests/network/xdomain/early/run.py --source-root /path/to/product --output /path/to/new-output`

The bounded runner assembles mapped production sources and mechanically follows project includes. It composes actual NHI ring code, XDOMAIN transport/class, common family and reference BPF. The existing v1 safety, control custody and lease oracles remain unchanged. `--case NAME` selects one composition case; `--case wire` runs only the independent codec. `--sanitize` adds GCC address/undefined sanitizers to the composition. Some scenarios intentionally retain live or unknown backing at process exit; leak checking is a separate fixture concern, and callers may explicitly set `ASAN_OPTIONS=detect_leaks=0` for memory-access checks.

These checks are deterministic host composition. MMIO, IRQ/work delivery, registration mappings and core batch storage are the established test environment. Malformed and duplicate inputs write actual coherent control RX backing and complete actual NHI descriptors; they never call XDOMAIN callbacks or substitute protocol decisions. The v2 host invocation bridge only transports facts/verdicts for the actual reference program. Private kfunc identity/envelope enforcement, kernel verifier acceptance, physical DMA, IRQ concurrency and performance need separate evidence.

Independent tests cover the public opt-in, default v1, pair before payload post, grants before TX exists, nonconsecutive exact keys, disjoint second-batch storage, short-tail canonical lengths, ACK versus local completion ordering, delayed peer CREATE retries, missing confirm, hard timeout despite WAIT, malformed/stale control inputs, duplicate CTS and STOP, batch_end versus real consumer release, downstream errors/sequester, and unknown native STOP. The separate codec executable checks literal v2 wire offsets, CRC, strict lengths, all types and field whitelists, geometry and preserved 256/64 versus new320 byte ABI.

Compilation/setup failures, signals and timeout are not semantic RED. Baseline RED was a compiled real class bind returning `-EINVAL` for EARLY bit1, recorded separately. These tests do not constitute the complete Appendix D mutation/real-kernel gate.

## Production observation regression

Pass `--observe` to reuse sixteen existing scenarios with an independent recorder
at the actual class-to-core `xdev_ext_mech_trace_xdomain()` call boundary. The
recorder requires successful bind, exact transaction identity, initial TX
attempts including `-EAGAIN`, accepted CTS sends and receipts, grants, native
post acceptance, completion disposition, consumer release and final ACK/FAIL.
It compares control observations with the existing native control recorder;
failed CTS enqueue and duplicate receipts cannot manufacture success. The
existing disjoint-frame case requires the second CTS before the first consumer
release. Callback-before-post-return cases retain their true causal order.

```sh
python3 tests/network/xdomain/early/run.py \
  --source-root "$SOURCE_ROOT" --output "$PRIVATE_RESULTS" --observe
```

The trace sink and tracepoint implementation are outside this Host executable.
`EARLY_TRACE` lines use the deterministic Host clock and remain software test
evidence, even though their fields follow the production trace contract. They
cannot establish kernel tracepoint serialization, physical DMA or performance.

The post-return race adapter excludes progress and finalization of the same
session while its submit caller is active, matching the production per-session
kthread worker. Native callbacks, control delivery and the peer worker remain
eligible. The ACK race case also requires a successful final CQE; counting a
negative publication is insufficient.
