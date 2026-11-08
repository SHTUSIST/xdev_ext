# XDOMAIN RX to CE TARGET_RANGE runtime correctness

This composition exercises data movement and final ownership through the
actual XDOMAIN RX and CE runtime. It requires no Thunderbolt controller or
GPU. The native link and CE byte mover are software models; a passing run
does not establish physical DMA, CUDA visibility, kernel concurrency or
performance.

## Run

```sh
python3 tests/network/xdomain/chain/ce_run.py \
  --source-root . --output build/xdomain-ce
ASAN_OPTIONS=detect_leaks=0 \
python3 tests/network/xdomain/chain/ce_run.py \
  --source-root . --output build/xdomain-ce-sanitize --sanitize
```

`ce_run.py` selects `run.py --pool host --receiver ce`. `--case NAME` selects
one case. The default matrix runs every case with ordinary RTS/CTS and with
EARLY grants. The shared host CI runner has an explicit entry for this suite.
Outputs include compilation and case logs, `result.json`, source hashes,
the assembled source, the extracted core closure, and `ce-selection.json`.
Exit 0 requires positive assertions in every selected case, exit 1 means a
behavior failure, and exit 2 means setup or compilation failed. Sessions are
process-local and not destroyed at exit; sanitizer leak detection is disabled.
Checked native unbind and ambiguous retention are asserted explicitly.

## Runtime included

The existing chain supplies the sender's NVMe READ to XDOMAIN TX, the NHI
descriptor/IRQ model, actual XDOMAIN reference programs, the two IOU_UMEM
pools, actual requester mapping/sync code and the actual core worker closure.
The receiver replaces the NVMe WRITE consumer with CE TO_DEVICE TARGET_RANGE.

The CE unit compiles `xdev_ext_mech_ce.c`, `xdev_ext_compfam_copy.c` and
`xdev_ext_compfam_copy_lease.c`. It keeps CREATE binding, plan collection and
validation, Host frame claims, lease acquisition, transfer construction,
completion ticket checks and final batch release. The core's actual
`xdev_ext_mech_batch_ce_owners_valid()` is included and invoked before native
acceptance and before delayed native byte access.

The native CE boundary extracts region/Host bind, unbind, range validation
and copy functions unchanged from `tests/support/ce_sim/xdev_ext_ce_sim.c`.
Its `vmap` aliases the receiver's actual registered IOU_UMEM pages after
checking their identities. It does not initialize the received payload or
repair runtime cookie state. An immutable transfer snapshot and deterministic
queue replace the simulator's workqueue/hrtimer so tests can withhold, fail
and replay completions at exact lifecycle boundaries.

The fixture supplies a small placement policy at the BPF invocation boundary.
It splits frames at GPU segment and max-entry boundaries and submits ordinary
descriptors to the actual CE validator. This is not a test of the BPF verifier,
JIT, or the K-KV `kv_ce_place.bpf.c` program. The production CUDA/NVIDIA backend
is audited separately and is not executed here.

## Independent byte oracle

Each source group is 8192 bytes, held in two 4096-byte frames. The first
16 bytes encode a little-endian group ID and its complement; the remaining
bytes depend on both group ID and byte position. The sender's real NVMe
program reads this deterministic input. A link witness checks what the real
TX descriptors read before the model writes RX memory.

The four-group success case uses the explicit targets
`{3 * 8192 + 17, 3, 8 * 8192 + 31, 5 * 8192 + 7}`. This makes the ranges
non-monotonic, unaligned and separated by guards, and reuses batch slots and
Host frames. The entire 256 KiB device window starts with byte `0xa7`.
Readback is independent of the submitted descriptors: the expected window is
constructed solely from group IDs and the input target table. Every payload
byte, destination offset, gap and untouched byte is compared.

## Required cases

- `ce_data_ranges`: all four groups, sender witness, whole-window readback,
  exact stage and final completion counts, one final ACK per group, and
  checked CE unbind after release.
- `ce_host_hold`: two disjoint ranges accepted concurrently; withheld CE
  completion leaves all source Host frames unavailable and unchanged,
  emits no final ACK and cannot unbind mappings. After completion, both
  groups must match the independent oracle.
- `ce_submit_fail`: synchronous native refusal after lease acquisition;
  no native request, payload write or success ACK. Final disposition must
  release the range so checked unbind succeeds.
- `ce_plan_bounds`: RX succeeds but the selected range extends one byte past
  the bound device window. Actual runtime validation must return `-ERANGE`
  before CE submission, leave the window untouched, withhold success and
  return the quiesced Host frames. Checked CE unbind must succeed.
- `ce_range_overlap`: two received groups target the same bytes. Only one
  native request may be accepted. Even after its native completion, checked
  unbind must remain busy until the worker reaches final batch release.
  The waiting group then acquires the range and overwrites it in order.
- `ce_unknown_late`: an accepted request reports unknown completion; Host
  frames, range and native mappings remain quarantined. A late success with
  the old ticket must not revive success or clear that quarantine. A read-only
  snapshot under the actual lease-domain mutex verifies the active slot,
  generation, exact target range and quarantine before and after the late
  callback, independently of the common-copy ambiguous unbind gate.
- `ce_short_complete`: the model copies the bytes but reports success with
  one byte missing. Completion must remain ambiguous even when readback
  happens to match, and no success ACK may be emitted.
- `ce_stale_reuse`: after a slot and its Host frames are reused for the next
  group, replay the previous successful ticket. It may neither complete the
  new group nor release the new generation's source frames or range.
- `rx_partial_wait`: withhold the second of two real RX callbacks; the first
  callback alone cannot submit CE, report batch success or release frames.
  Delivering the final callback then permits exactly one verified copy.
- `rx_short`: inject a short NHI RX descriptor result. All callbacks drain,
  the batch aborts, no CE submission or ACK occurs, and quiesced Host frames
  return to user ownership with no live NHI lease.
- `rx_error`: inject a native RX CRC error and require the same failure and
  ownership properties as the short RX case.
- `rx_unknown_late`: withhold RX callbacks, STOP past the bounded wait, then
  deliver the real callbacks late. No CE submission or success is allowed;
  Host frames and NHI mappings remain retained throughout.

## Runtime mutation checks

Each mutation changes only a private assembled view and reruns the named
behavioral case. A mutation is KILLED only by exit 1 with a `CHAIN_ASSERT`;
a setup error, crash, timeout or absent pass marker does not count.

```sh
python3 tests/network/xdomain/chain/ce_run.py --source-root . \
  --output build/xdomain-ce-wrong-target --mutation ce-wrong-target
```

- `ce-wrong-target`: production CE translation shifts every destination by
  one byte; the independent whole-window oracle must fail.
- `ce-skipped-copy`: the device model reports H2D success without moving
  payload; the same independent oracle must fail. This mutates the simulator,
  not a production policy, and tests readback sensitivity explicitly.
- `ce-overlap-granted`: actual lease code admits an overlapping live range;
  the native-acceptance count must expose it.
- `ce-release-at-callback`: actual CE callback releases its range before
  final worker disposition; checked-unbind must expose the premature release.
- `ce-rx-error-as-success`: actual NHI RX callback suppresses short/error
  status; both `rx_short` and `rx_error` must catch a forbidden CE submission.
- `ce-unknown-range-released`: actual CE final release discards sequester and
  frees an uncertain range. Both protocols must detect the missing active
  quarantined owner through the independent lease snapshot.
- `ce-stale-ticket-accepted`: actual copy completion substitutes the current
  ticket for an old callback; the reused-generation test must fail.

## Shared-cookie regression

The original XDOMAIN-to-CE admission commit did not give serial stages
separate persistent cookies. The core allocates one batch cookie sized to
the maximum class requirement. XDOMAIN stored its group and final reply
state in that cookie, while the common CE runtime interpreted the same
address as its persistent native cookie, whose first member is a batch
pointer. For group 1, the real CE owner check dereferenced address `0x1`.
The integrated data case reproduces this on baseline
`b9d83bb328a05c55e0b8e16450372a38cb88b0af`; admission-only tests cannot.

XDOMAIN now keeps final status and the end/release markers in its existing
stage-owned reply records. Normal RX_ARM, like EARLY reservation, records the
batch pointer and immutable key. End/release lookups require a used reply,
matching pointer/key and an unfinished chain, while allowing a closed reply
whose native RX failed. A released reply cannot alias a reused batch slot.
The change adds no allocation or new teardown path and leaves CE's native
completion cookie intact.

## Hardware qualification still required

The host models provide deterministic lifecycle interleavings, not concurrent
kernel execution. They do not qualify physical Thunderbolt RX, the NVIDIA
copy engine, DMA coherency, real IOMMU mappings or CUDA VMM visibility.
The existing XDOMAIN KVM runner checks module lifecycle and verifier behavior;
the K-KV local-verify KVM runner checks QEMU NVMe with a software pool. Neither
provides a Thunderbolt-to-GPU data test. No KVM result may be reported as such.

Before collecting real KV restore performance, a physical two-host run must
exercise these properties on a matching patched kernel/driver build:

1. Restore distinct group patterns through real XDOMAIN RX into IOU_UMEM,
   then real CE into an exported CUDA VMM allocation. Select nonzero and
   non-monotonic targets and force slot/frame reuse.
2. Poison the entire allocation before restore, wait for final batch status,
   and independently read the full allocation through CUDA. Match the group
   payload, selected offsets and every untouched guard byte. The existing
   K-KV CUDA VMM allocation/readback code can supply the owner and oracle;
   its local-verify NVMe producer alone cannot qualify XDOMAIN.
3. Repeat bounded fault and concurrency cases with real native completions:
   partial/error RX, STOP with pending RX or CE, native submit failure,
   overlapping and disjoint ranges, late completions and repeated reuse.
   Require no CE after unsuccessful RX and no release while native access
   remains possible. Retained UNKNOWN resources are expected, not leaks to
   fix by forced unbind.
4. Require matching source/build provenance and clean kernel diagnostics.
   Only after the physical correctness gate passes should the same path
   produce timing or CPU-usage claims. The software suite contains no
   performance measurement and no proof of end-to-end physical zero copy.
