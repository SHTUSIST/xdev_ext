# Provider API

A device provider connects an admitted resource and bounded plan to the real device. Its responsibilities include authority checks, DMA mapping and reachability, synchronization, native submission, completion and invalidation.

See the [kernel mechanism interface](../../kernel/include/linux/xdev_ext_mech.h) and [peer-memory interface](../../kernel/include/linux/xdev_ext_peer.h) for exact declarations. Providers for different classes have distinct entry points; the registered DMA contract below illustrates the acceptance and lifetime rules.

## Registered DMA providers

A driver registers `xdev_ext_dma_provider_ops` using its device-file operations as the lookup key. A session binds an authorized device window and the shared host pool. Registration is dynamic; the interface does not depend on a fixed provider count.

The driver validates the caller's access to the window and the consuming device's reachability of each mapping. The kernel validates direction, bounds, alignment, entries, overlap and coverage before native submission. Native queues and doorbells remain provider responsibilities.

`submit` accepts the plan by returning zero and completes it exactly once through `xdev_ext_dma_complete(cookie, ticket, status, hw_submitted, bytes)`. Completion may run inline. Retain the ticket by value so that later callbacks identify the submitted operation.

A negative submit result guarantees no native submission and no callback. In particular, preaccept `-EAGAIN` permits backpressure without replaying accepted work. Once accepted, only a successful submitted completion with the exact expected byte count establishes the complete transfer. Short, excess or uncertain failed accepted work requires conservative retention or quarantine according to the class contract.

## Lifetimes and invalidation

Binding holds the required owner, mapping and allocation references. A generation identifies the bound allocation; a native ticket identifies the admitted operation. An old callback must not advance a new operation or release its resources.

Release mappings only after their native users are quiescent. STOP, invalidation and module teardown must agree with in-flight ownership. Unknown completion must not permit early unpin, unmap, allocation destruction or module unload.

A peer-memory provider supplies actual device-memory authority and mappings. CPU-copy fixtures can exercise admission and ownership but do not implement physical peer DMA. A driver must reject unsupported directions or mapping combinations explicitly.

## Adding a capability

Implement the class's bind, map, submit, completion and teardown contract, then compose it through the existing kernel boundary. Test refusal before acceptance, synchronous and asynchronous completion, short/ambiguous accepted results, stale tickets, invalidation and STOP. For a physical-device claim, record actual device execution in addition to host tests and module builds.
