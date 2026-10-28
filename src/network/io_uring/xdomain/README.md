# XDOMAIN service and link lifetime

The `xdevext` Thunderbolt/USB4 XDomain service assigns a non-reused token to
one peer link. `xdev_ext_link` exposes that token. The separate read-only
`xdev_ext_link_state` attribute snapshots version, token, local and remote
incarnations, UP, closing, NHI-gone and channel count under `ctl_mutex` then
`xl->lock`. Closing means going-away, suspended or removed. A missing peer
incarnation stays zero; the observation grants no posting authority and
contains no addresses.

The two login directions must agree on the peer incarnation before UP is
published. One data channel is used; the wire format bounds all channel
arrays to four. A login advertises the local HopIDs actually allocated by
the ring layer, and path setup consumes the peer's separate advertised
HopIDs. Login requests are bounded to 60 attempts per handshake, including
successful replies whose incarnation conflicts with the accepted peer. Such
a reply schedules another login without waiting for an incoming LOGIN; a
later matching reply may publish UP. A response received before the peer
LOGIN waits for connect as usual. A failed connect stops
what it started and schedules a fresh login after one second. Repeated
LOGIN for the accepted peer incarnation does not restart rings. A changed
peer incarnation detaches every old endpoint and ends that incarnation
before starting another. LOGOUT affects only the accepted incarnation.

The module has one protocol handler. Its registry lookup and all handler
accesses hold `xdev_ext_xd_links_lock`; removal takes the link off the list
first, sets going-away, then synchronously cancels login, connect and down
work. Suspend sets its flag before the same cancellation barriers. Each
worker checks the flags under `ctl_mutex` before acting. Healthy resume
chooses a fresh local incarnation and logs in again. An NHI classified as
gone cannot restart.

Lock ordering is `xdev_ext_xd_links_lock` -> `xl->lock` for the handler, and
`ctl_mutex` -> `ep_mutex` -> stage family lock (`ns->lock`) -> `xl->lock` ->
ring lock for link teardown and data operations. The handler does not take
`ctl_mutex`: login requests wait for responses while holding that mutex.
`tb_ring_stop` is called with neither `ep_mutex` nor a spinlock held, and
never from a frame callback. Endpoint detachment is recorded under both
`ep_mutex` and `xl->lock`. Deferred down errors carry their local incarnation
under `xl->lock`; the worker checks it and tears down under one `ctl_mutex`
hold. An old endpoint or its already queued fault cannot fail a new
incarnation. A current-incarnation fault replaces any queued stale error.

Rings and HopIDs are relinquished inside service remove while the XDomain
and NHI still exist. Last-reference release only drops the cached PCI
device reference and link memory; it never reaches the service, XDomain,
native ring or MMIO. A bound stage may retain link memory, cached route and
UUIDs, and that PCI device reference after remove. The reference does not
pin NHI devres or prove DMA quiescence.

Task X3a supplies a synchronous `tb_unregister_protocol_handler` callback
barrier for both this service and the existing Thunderbolt network caller.
That prerequisite must be integrated before X7 module load/unload
acceptance; empty registry lookup alone is insufficient for module-text
lifetime.

The service declares the ring and class interfaces and Kbuild objects;
the separate ring and class files supply their implementations. X4 owns each
control allocation's accepted, normal-completed, unknown and callback
barrier facts, its preallocated quarantine record and independent PCI
reference. A healthy reconnect must use fresh backing for any allocation
with unknown accepted DMA. For a going-away NHI, X4 uses the opt-in NHI
software retirement primitive before service remove returns: it drains
IRQ/work/callback ownership while retaining unknown descriptor and control
backing. Software retirement is not physical DMA quiescence. These X4
requirements and the module's actual GCC link are verified in their own
tasks; X3's host recording fixtures establish no physical DMA or
performance result.

The class dispatches bounded protocol facts on the existing session worker.
`ctl[XD_EVENTS]`, where `XD_EVENTS = 4 * XDEV_EXT_REL_MAX_WINDOW`, holds owned
scalar CTS/HELD/ACK/FAIL records (`ctl_count` is the occupied prefix). The
separate `rts[XDEV_EXT_REL_MAX_WINDOW]` prefix (`rts_count`) stores owned RTS
messages and cancellation/sequence-consumption/control-admission facts.
`replies[2 * XDEV_EXT_REL_MAX_WINDOW]` retains group replies independently of
reusable native slots. A reply admission survives local CQE release and ends
only after final control acceptance or definite link resolution. Native
uncertainty retains its original leases and control pins.

For a host-only full-queue precondition, initialize every occupied `ctl` entry
as a distinct valid decoded control record for the stage's current incarnation
pair and endpoint channel, and set `ctl_count` to `XD_EVENTS`. Preserve the
entire occupied prefix. Deliver a further distinct record through the actual
`xdev_ext_xd_class_ctl` ingress: it must set `overflow` and `down_latched`
without writing beyond or overwriting that prefix. Do not replace the real
enqueue or capacity decision. STOP remains authoritative in the core session
admission state and is copied into `stop_latched` on the next worker pass.
The class reads the core's locked first-STOP timestamp, so worker delay and
repeated STOP cannot extend the one-second bound; timestamp zero is valid.
LINK_DOWN and overflow are sticky independently of queue occupancy. This
precondition is fixture setup, not a production API or evidence of NHI behavior.

The version-1 announcement window is fixed at
`XDEV_EXT_REL_MAX_WINDOW` (32), independently of payload batch depth. The
bounded RTS queue backs this announcement capacity; the single posted or
reserved RX group and its native leases remain separately enforced. A
pre-CTS FAIL with zero credit never increases peer credit. Reliable entries
count logical layout segments, while RTS and native posts count the actual
4096-byte NHI elements (at most 64); these counts are deliberately distinct.

Startup data verification requires LOGIN protocol version 3 and the mandatory
DATA_CHALLENGE capability. Version 2 peers are refused. The existing link `up`
state reports control login readiness; it does not report data verification.
Each channel preposts two private host scratch receive buffers, exchanges READY,
and transfers exactly one 128-byte PING and one 4096-byte PONG in each direction.
Actual receive length, descriptor errors, the deterministic payload, identity
and nonces are checked. Both local transmit completions and the peer's DONE are
required before a business endpoint can bind. A control-ready channel still
verifying returns `-EAGAIN`; callers may retry binding. The deadline is ten
seconds after control readiness and shares the bounded setup failure budget.

The read-only `xdev_ext_data_state` attribute reports control readiness,
per-channel data gates, startup results, actual RX lengths and flags, submitted
TX lengths and TX completions. Startup uses internal coherent host memory;
`backing_qualified=not_queried` remains explicit. This does not prove VRAM DMA,
GPU visibility or GPU last use. Business PEER admission is unchanged.
Successful startup hands over the same native rings and HopIDs without a reset.
Failed startup closes admission and stops through the existing native barriers;
unknown scratch DMA retains the entire allocation in the requester quota.

The read-only module parameter `poll_completions` defaults to false. Probe
snapshots it before allocating rings. When enabled, every control and data
TX/RX ring uses native `NO_INTERRUPT`; default links retain the IRQ/work
completion path. Existing process-context class progress collects at most
64 completions per pass, rotating after at most eight from one ring. It
runs the original callbacks after native ring locks are released. Native
poll also refills software-pending descriptors. The generic atomic `.poll`
interface is not used because control callbacks can sleep and repost.

A shared link work item runs the same bounded pass at a one-jiffy cadence
while polling is live, including startup verification before any session
exists and control traffic after a session unbinds. It keeps no stage
pointer and does not take `ctl_mutex`. A session with pending completions
or native/protocol commitments queues a further worker turn; idle sessions
retain their existing deadline schedule. The cadence is a scheduling
choice and gives no latency guarantee.

The polling mutex covers native poll return through the entire callback.
Stop closes UP, receive readiness, starting and the poll gate under
`xl->lock`, then cancels fallback and waits for the polling mutex without
holding `ep_mutex` or a spinlock. Only afterwards may native stop/free or
UNKNOWN retirement consume rings and allocations. Posts and callback
reposts schedule fallback under the same gate lock. Completed native
ownership and UNKNOWN backing follow the existing custody ledger.

Early CTS is an explicit opt-in: pass `XDEV_EXT_XDOMAIN_F_EARLY` to
`xdev_ext_stage_xdomain()`, or `XDEV_EXT_PEER_ENDPOINT_F_EARLY` in existing
endpoint options, on both endpoints. The updated reference BPF policy supports
ordinary and early sessions. Ordinary sessions keep the v1 RTS protocol.

Early endpoints bind fresh endpoint identities before batches, then grant one
actual posted RX batch to its exact future TX key. The ordered layout must use
one full-span descriptor per logical frame and the TX tag is the key as eight
big-endian bytes followed by sixteen zero bytes. Early and ordinary modes do
not negotiate an in-place fallback; close an uncommitted early session and
explicitly create an ordinary session when required. Pairing has a fixed
30-second deadline and bounded identical control retries. CRC and pair freshness
checks do not provide cryptographic authentication.
