# Provider API

A device provider connects an admitted resource and bounded plan to the real device. Its responsibilities include authority checks, DMA mapping and reachability, synchronization, native submission, completion and invalidation.

See the [kernel mechanism interface](../../src/core/include/linux/xdev_ext_mech.h) and [peer-memory interface](../../src/core/include/linux/xdev_ext_peer.h) for exact declarations. Providers for different classes have distinct entry points; the registered DMA contract below illustrates the acceptance and lifetime rules.

## Registered DMA providers

A driver registers `xdev_ext_dma_provider_ops` using its device-file operations as the lookup key. A session binds an authorized device window and the shared host pool. Registration is dynamic; the interface does not depend on a fixed provider count.

The driver validates the caller's access to the window and the consuming device's reachability of each mapping. The kernel validates direction, bounds, alignment, entries and coverage before native submission. Native queues and doorbells remain provider responsibilities.

Device ranges of one batch may overlap; keeping them apart is the caller's responsibility. FROM_DEVICE reads are well defined. For TO_DEVICE, the final content of an overlapped byte is unspecified. The `bytes_done` of a complete transfer equals the sum of entry lengths. The kernel confines each CE/DMA batch to its admitted window slot. The device window must behave like memory; a provider that needs non-overlapping ranges checks them in its own `submit` callback.

`submit` accepts the plan by returning zero and completes it exactly once through `xdev_ext_dma_complete(cookie, ticket, status, hw_submitted, bytes)`. Completion may run inline. Retain the ticket by value so that later callbacks identify the submitted operation.

A negative submit result guarantees no native submission and no callback. In particular, preaccept `-EAGAIN` permits backpressure without replaying accepted work. Once accepted, only a successful submitted completion with the exact expected byte count establishes the complete transfer. Short, excess or uncertain failed accepted work requires conservative retention or quarantine according to the class contract.

### Backing scopes for window leases

Legacy `xdev_ext_dma_provider_register` compares configured numeric windows within one provider ops namespace. A provider can instead call `xdev_ext_dma_provider_register_scoped` with a version-1 `xdev_ext_dma_scope_ops` sidecar. Both entry points use the same registry; the original provider ops and region layouts and DMA/BPF ABI2 remain unchanged. The sidecar must be immutable static storage protected by the provider owner. Registration requires its exact size/version, zero flags/reserved and an acquire callback.

A KNOWN acquire result identifies a real backing space with an opaque scope created by `xdev_ext_dma_scope_create`. All aliases of the same backing bytes must use that same scope and the same canonical byte coordinates. The requested interval maps continuously in increasing byte order, with canonical length equal to requested length and no overflow. Mapping and identity must remain stable from acquire through the last scope reference; `bind_region` must bind that declared space. File pointers, user tags, virtual addresses and `region.priv` are not proofs of independence. Distinct trusted scopes permit independent address spaces to use equal numeric windows; overlapping canonical intervals in the same scope still conflict. Distinct ops retain the existing separate namespaces, so a provider must not register aliases under unrelated ops to evade retained leases.

Acquire runs in CREATE process context outside registry/lease locks, before native mapping or submission. It may acquire logical references but cannot leave resources requiring native unmap. Return UNKNOWN with NULL scope and zero coordinates when canonical identity cannot be proved; UNKNOWN and legacy/scoped mixtures conservatively conflict across the whole ops namespace. Invalid declarations fail before native bind. A non-NULL output scope on any return value transfers exactly one successful `xdev_ext_dma_scope_get` reference to the core, including callback errors; never transfer a borrowed pointer or the creator reference.

The backing owner holds one creator reference and returns it with `xdev_ext_dma_scope_owner_put`; that reference does not self-pin its module. Each external get independently pins the scope owner's module, even if it differs from the provider owner. The core retains one transferred reference per bound stage through normal batch completion, failed unbind and UNKNOWN. Only successful checked cleanup removes the lease and puts that stage reference. Final release runs outside registry/lease locks before the matching module put; it cannot fail and is not a replacement for native quiescence or unmap. A release callback cannot resurrect a zero-reference scope.

## Lifetimes and invalidation

Binding holds the required owner, mapping and allocation references. A generation identifies the bound allocation; a native ticket identifies the admitted operation. An old callback must not advance a new operation or release its resources.

Release mappings only after their native users are quiescent. A native completion whose quiescence flag is false remains unsafe even if its status value is zero; the common NET boundary converts that combination to failure and retains accepted resources. STOP, invalidation and module teardown must agree with in-flight ownership. Unknown completion must not permit early unpin, unmap, allocation destruction or module unload.

A peer-memory provider supplies actual device-memory authority and mappings. CPU-copy fixtures can exercise admission and ownership but do not implement physical peer DMA. A driver must reject unsupported directions or mapping combinations explicitly.

## Copy-engine window ownership

Before native CE submission, the kernel atomically claims all configured CE windows of a session. Overlapping windows held by another active session cause preaccept backpressure. Matching-base or disjoint windows retain their existing depth and slot parallelism. Shifted overlapping windows serialize batches to prevent different relative slots from naming the same bytes. The frontend can reuse its session across calls.

The claim remains until the batch's final frame disposition is known. Repeated stage cleanup releases it once; uncertainty retains the session's window claims. The range comparison uses backend identity and configured addresses. It does not establish physical equivalence between distinct GPU virtual aliases.

## Adding a capability

Implement the class's bind, map, submit, completion and teardown contract, then compose it through the existing kernel boundary. Test refusal before acceptance, synchronous and asynchronous completion, short/ambiguous accepted results, stale tickets, invalidation and STOP. For a physical-device claim, record actual device execution in addition to host tests and module builds.
