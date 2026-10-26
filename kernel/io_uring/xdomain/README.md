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

This task declares the X4 ring and X5 class interfaces and Kbuild objects;
it supplies no replacement ring or class implementations. X4 owns each
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
