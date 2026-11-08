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
ring lock for link teardown and data operations. `poll_irq_lock` is innermost:
it may be taken under `xl->lock` or under the NHI and ring locks. While it is
held, no lock of this module, the NHI or a ring is taken; queuing the poll work
takes only workqueue-internal locks. The handler does not take
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

A stage's in-flight window W comes from bits 32..63 of `arg1` (0 or 1: one
group, the behaviour without a window; at most `XDEV_EXT_XDOMAIN_MAX_WINDOW`,
32); the device layer sees only the channel. The class hands W to the core
(`order_window`) and implements `order_ready`. A TX group is ready, and the
next key may be announced behind it, once its data post was accepted (after
the CTS, or with an EARLY grant): its group number and data sequence were
taken in key order and the peer posted its buffers. Before that the
announcement can still be withdrawn or refused, and a later group already
announced would take the receive batch it leaves (an RTS goes to the oldest
ARMED batch). RX batches are never ready: one RX batch at a time is in the RX
stage, so the single posted group above and the binding of each RTS to the
next receive batch in key order are unchanged, while up to W received groups
are in the RX stage or its consumer (their ACK or FAIL follows the end of
their chain). An EARLY sender also waits for the next group's grant before
releasing the next key, so that key is not bounced to the core retry timer.
Give the receiving stage a window at least as large as the sending stage's:
otherwise the sender's next announced group waits at the receiver until the
receiver ends a group, and one that waits past the 15 s withdrawal point is
withdrawn and stops the sending session (no group is misplaced). The wire
format is unchanged; several data channels are a separate change.

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

The end with the larger host router UUID sends its PING first. A peer that
carries this host's own UUID is refused with `-EPROTO`. The read-only module
parameter `self_loop_test` (default false) is for testing only: it accepts such
a peer when it is the other end of a cable joining two ports of the same NHI,
that is, another link of this module on the same NHI, on a different local
port, with the same UUID pair, whose incarnation the accepted LOGIN carried.
The end with the larger incarnation then sends first. Any other same-UUID peer
is still refused. With such a cable the startup exchange above moves real
bytes through the NHI rings of both ports; it is a functional DMA check, not
a timing measurement.

A stage may also use the ring's IOU_UMEM pool (host pages) instead of a PEER
allocation, for TX and for RX at stage 0. At bind the requester maps every
pool page for the NHI, in the stage's DMA direction. A pool that does not
start and end on page boundaries is refused with `-EINVAL`, because each NHI
element is one contiguous buffer of at most 4096 bytes and could not cross a
page. Each element lease takes its page's address plus the offset, with a
sync for the NHI when the mapping needs one (a non-coherent or bounced NHI);
a received buffer is synced for the CPU when its element ends quiesced,
before the next stage reads it. The data ring still carries payload only, so
an element may be a full 4096 bytes (the tbnet limit of 4084 payload bytes
comes from its header inside each frame). An element that ends with unknown
device access keeps the whole mapping, as a PEER region is quarantined: the
mapping is never unmapped, the batch's frames are sequestered, and the
stage's checked unbind refuses release so the session keeps its UMEM pins.

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

The read-only module parameter `poll_on_interrupt` also defaults to false and
cannot be combined with `poll_completions`; module load fails with `-EINVAL`
when both are set. It follows upstream thunderbolt-net: control and data RX
rings pass a `start_poll` callback, while TX rings keep interrupt completion
through the native ring work. The NHI masks a ring's interrupt and then calls
`start_poll` with its NHI and ring spinlocks held. The callback only marks the
ring and queues the link poll work without delay; it never polls or runs a
frame callback.

The queued work runs the same bounded pass on the RX rings only. When the pass
ends below its 64-frame budget, every ring that `start_poll` marked gets one
`tb_ring_poll_complete()`, which re-enables its interrupt. A completion that
arrives between the last empty poll and that re-enable is found by
`tb_ring_poll_pending()` and queues another pass at once, whether or not the
controller raises an interrupt for it. A full budget leaves the interrupts
masked and queues the next pass. No delayed fallback exists in this mode, and
session progress does not poll.

Start opens the interrupt gate under `poll_irq_lock` after the poll gate and
queues a pass if an interrupt arrived before it. Stop closes both gates before
it cancels the work, and a later interrupt only marks its ring. Stopping a
ring whose interrupt `start_poll` masked raises no NHI warning: the NHI copy
carries the later upstream rule that a polled ring may already be masked when
it is disabled. These are host software composition results; they establish
no interrupt latency, timing or physical DMA behavior.

The polling mutex covers native poll return through the entire callback.
Stop closes UP, receive readiness, starting and the poll gate under
`xl->lock`, then cancels fallback and waits for the polling mutex without
holding `ep_mutex` or a spinlock. Only afterwards may native stop/free or
UNKNOWN retirement consume rings and allocations. Posts and callback
reposts schedule fallback under the same gate lock. Completed native
ownership and UNKNOWN backing follow the existing custody ledger.

`XDEV_EXT_XDOMAIN_F_EARLY`, passed to `xdev_ext_stage_xdomain()` (or
`XDEV_EXT_PEER_ENDPOINT_F_EARLY` in existing endpoint options) on both
endpoints, selects the version-2 envelope: 320-byte protocol facts, fresh
endpoint bind identities, and the pairing and grant actions. On such a stage
the attached program chooses the protocol. Both bindings keep one invariant,
checked by the post action of each: the sender posts only a group the
authenticated peer has posted and advertised by CTS credit (a version-1
TX_POST needs the CTS record of its group, an early post the grant accepted
for its key and group). `examples/network/xdomain_rts_cts.bpf.c` uses RTS/CTS
and declines pairing; `examples/network/xdomain_early.bpf.c` pairs and grants.
Both register `xdomain_peer_ops`, so a caller changes protocol by loading the
other object. Without the flag a stage keeps the version-1 envelope, where v1
programs run unchanged. The reference program chooses from the stage's mode
fact: RTS/CTS without the flag, pairing with it, and then it answers an RTS
only by refusal.

A stage keeps the first binding its program chose. When a receiver starts
pairing it drops the RTS records it holds (none was answered), and from then
on the link and the class drop version-1 control to a paired endpoint; an RTS
cannot be encoded, so no group is announced or posted on an RTS. Once the program
announced, posted on an RTS or declined pairing (IGNORE on PAIR_DUE or HELLO),
pairing and grant inputs are dropped and pairing actions refused. Such a
stage, and a receiver no peer has asked to pair, follow the version-1
deadline, STOP and terminal rules; a HELLO such a receiver still holds when it
stops or ends is dropped, never offered to its program.

A paired stage grants one actual posted RX batch to its exact future TX key.
The ordered layout must use one full-span descriptor per logical frame and the
TX tag is the key as eight big-endian bytes followed by sixteen zero bytes.
Neither binding falls back to the other in place; close an uncommitted session
and create one with the other program when required. Pairing has a fixed
30-second deadline, counted from the sender's first progress and from the
receiver's first CHALLENGE, and bounded identical control retries. CRC and pair
freshness checks do not provide cryptographic authentication.
