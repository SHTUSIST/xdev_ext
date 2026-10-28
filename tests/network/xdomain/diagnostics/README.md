# Stage diagnostic contracts

These independent correctness tests exercise the accepted stage diagnostic
contract. They do not run a kernel or physical device and produce no performance
measurements. The runner returns 0 for all selected cases passing, 1 for runtime
behavior failures, and 2 for setup, compile, crash, or timeout errors.

```sh
python3 tests/network/xdomain/diagnostics/run.py \
  --source-root "$SOURCE_ROOT" --output "$PRIVATE_RESULTS" \
  --nhi-regs "$PINNED_UPSTREAM/drivers/thunderbolt/nhi_regs.h"
```

Use `--suite core`, `--suite native`, or `--suite class` to isolate a component.
`--case NAME` selects one case within that suite. Build products and receipts
belong outside the public source tree. The upstream header is copied into the
private build directory and never modified at its source.

The core suite runs the real numeric-op-11 register dispatcher, registered query
handler when present, and ring-local session lookup. Its class hook is a fixed
observation boundary, so this suite verifies core validation, ownership,
stopped-session access and error/value forwarding. It cannot certify the class
sampler or link ownership. An unsupported old dispatcher is a runtime behavior
failure, not a compile failure.

The native suite includes the complete production NHI ring section with the
existing qualified host MMIO, IRQ, allocation and work boundaries. Snapshot
counts are compared both with literal transition states and independent walks
of the actual queue and in-flight lists. Cases cover oversubscribed descriptors,
deferred notification, IRQ refill, polling refill, RX membership, stop before
callback drain, restart and quarantined storage. A missing snapshot symbol uses
a weak declaration and an explicit runtime capability failure. That failure
certifies no transition or counter behavior; the runner records `samples=0`.

The class suite includes the full production class and family bodies. It uses
the previously qualified, already-bound X5 business precondition and seeds
existing protocol custody state. It does not prove production link startup.
The new link sampler is an explicit external boundary here; native membership,
link pair validation and requester retention require independent tests. Class
cases distinguish CTS, ACK, local/chain/sequester FAIL, admitted RTS rejection,
unadmitted RTS, final-chain wait and the local-quiescence conditions for downstream
release. Whole class, fact and slot comparisons reject mutation of epoch,
cursor, worker-event authority or waits during query. Allocation, admission,
lease, policy, data post and control post boundaries are observed.

Remaining composition coverage includes real control-buffer exhaustion and
callback return, decrement after real control send and chain release, live
stop/remove/reconnect exclusion at each query sampling boundary, two-link
requester retention, and UNKNOWN native-pointer disappearance. These tests must
not be described as complete Task 2 acceptance until that coverage runs.
