# Native mlx5 peer teardown ownership

Performance comparisons follow the [evaluation policy](../reference/performance-policy.md).

Host TX/NAPI deactivation does not prove that an accepted DMA operation has
stopped. Peer-enabled SQ/RQ close therefore checks the actual native destroy
command result before completing descriptors with `quiesced=true` or freeing
WQ, CQ, coherent RX header, saved descriptor or peer lease backing. Firmware
errors, including a timeout, leave ownership unknown. They are sticky: later
close calls do not retry the destroy or replay accepted data.

Normal network queues retain the existing void destroy wrappers. A SQ becomes
peer-enabled only after successful owner acquisition and before its first peer
WQE. An RQ takes that path while its peer RX binding exists. A successful peer
RX reset/flush independently retires its peer binding; ordinary close behavior
then applies. PTP TX is already rejected at peer admission. QoS TX remains
supported, including both individual-QoS and channel-wide close callers.
Open-channel unwind cannot contain accepted peer WQEs: channels are unpublished
until opening succeeds and admission requires the live TX/RX queue and owner.
Its ordinary non-peer destroy behavior is retained.

The channel acquires references lazily before peer admission, without changing
the normal no-peer module lifecycle. These references cover the mlx5 module,
netdev, device, and the actual devlink object containing `mlx5_core_dev` private
storage. A device reference alone would not preserve that storage. The already
publicly declared devlink reference functions are exported for this module use.
Owner acquisition failure rejects submission before any WQE or doorbell.
RX shape eligibility is rejected before owner acquisition; a zero pin result
cannot turn an unsupported configuration into a successful unbound endpoint.

Successful final channel close releases all references and frees the channel.
Failed peer close propagates to the parent before related CQs or the embedding
channel can be freed. Embedded list nodes retain the complete failed channel
in a durable quarantine list; detached QoS SQ allocations have embedded nodes
in that retained channel too. This requires no closing-time allocation.
Unknown channels cannot admit new peer work. NAPI is removed once, and repeated
close does not destroy already closed queues again. Private cleanup, netdev
free and profile replacement cannot discard or overwrite quarantined owner
backing. Profile replacement rejects a previously quarantined owner before
detach or any cleanup. A second guard after detach covers newly discovered
unknown outcomes. The first quarantine emits a kernel diagnostic.

This repair does not invent a cancellation or firmware recovery guarantee.
Unknown resources remain retained until a separately proven device-wide DMA
stop could justify a future reclamation path. No such automatic reclamation
path is implemented here. Consequently an unknown outcome can retain module,
netdev, devlink, queue and peer-memory resources indefinitely, and can prevent
ordinary unload/profile replacement. Success paths reclaim normally. Physical
firmware behavior, device removal/reset, actual DMA safety and performance
remain physical validation requirements.

`test_native_owner_teardown.py` compiles the actual production owner helpers,
parent queue/channel close functions and both QoS close entry points against
host-only refcount/allocator/leaf-result boundaries. It tests normal reclamation,
RX and later-TC destroy failure, individual/group QoS failure, module/devlink
acquisition rejection and repeated close. The separate leaf contract executes
actual post/destroy/descriptor callbacks and common peer lease release/unmap
with injected firmware return values. The existing TX lifecycle test treats
owner acquisition as a declared boundary; it does not claim to test the real
owner functions.

Two newly overlaid files originate from the locked Linux v6.16-rc7 revision
`89be9a83ccf1f88522317ce02f854f30d6115c41`: `src/network/net/devlink/core.c` adds only
exports for existing `devlink_try_get`/`devlink_put`; `en/qos.c` checks peer
close errors before CQ/SQ reclamation. Their unmodified baselines were not
previous project contributions. The existing transobj wrappers and header
remain unchanged; peer close constructs the same native destroy command while
preserving its return status.

Representor mode changes propagate the failed profile switch instead of freeing
its still-owned private object. The sticky eswitch guard retains its rep,
steering/mapping/metadata and mode backing after existing or newly discovered
unknown teardown. These four new overlays use the same locked upstream revision:
`en_rep.c`, `eswitch.c`, `eswitch_offloads.c`, `eswitch.h`. Normal cleanup and mode
changes retain their original success behavior. A detach that discovers unknown
during disable stops before profile inner cleanup; suspend returns an error
before freeing the device resources used by that retained profile. Already
bound RX endpoints reject both channel and private-owner quarantine.

The five-second session drain wait is separate from these driver-owner pins.
Unknown driver resources can remain pinned indefinitely. The full STOP syscall
can additionally execute synchronous worker cancellation/native flush; the
drain constant does not certify a hard five-second wall-clock bound.

`test_native_rep_rx.py` extracts the actual RX post, profile/rep caller,
eswitch parent and suspend functions against declared host boundaries. It keeps
normal controls, failed and freshly failed paths, and an actual allocator/late
reader check. `test_native_teardown.py` preserves the independent native-leaf
and real peer lease-release assertions. Its two unchanged upstream command
wrappers are explicit licensed fixture inputs, not a substitute for checked
peer destroy. None of these tests certifies physical firmware stop or DMA.
