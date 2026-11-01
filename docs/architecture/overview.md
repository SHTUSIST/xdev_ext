# Architecture

xdev_ext composes I/O stages around an explicit memory and ownership contract. A session binds a pool, a bounded layout, a maximum in-flight depth, and a sequence of device stages. Userspace supplies configuration and starts the work; the kernel drives normal batches and exposes final or exceptional outcomes.

## Responsibilities

| Layer | Owns |
|---|---|
| Userspace | Resource selection, registration, session configuration, starting work and observing results |
| eBPF | Bounded protocol decisions, device request/copy plans, and permitted completion interpretation |
| Kernel core | Descriptor admission, resource references, pool ownership, generations, backpressure and teardown |
| Driver/provider | Actual DMA mappings, cache synchronization, native queues, doorbells, completion and invalidation |

The kernel boundary and provider integration are part of the design. A BPF plan cannot supply an arbitrary physical address or operate MMIO. Drivers validate mapping reachability and device capability; the kernel validates each admitted plan against the bound resources.

## Device families and frame memory

The three device families are distinguished by the other end of a request,
besides its local frame:

- Storage requests address persistent device storage that is accessed through
  requests, such as an NVMe namespace's LBAs.
- Network requests deliver bytes to another party, such as a NIC peer or an
  XDomain peer on another host.
- Compute requests change or move bytes locally, such as a GPU copy engine,
  IAA transform or CPU stage.

Memory is a shared provider layer below these families. It supplies addressable
frames and their access and lifetime facts; it has no independent device request
and completion. Retaining bytes does not by itself make memory a storage-family
device. A physical device can serve both layers: GPU memory supplies frames,
while its copy engine performs compute-family requests. An NVMe CMB would be a
memory source, while its namespace provides storage requests; this distinction
does not claim that a CMB provider is implemented.

The current pool kinds are XSK, registered host memory (IOU_UMEM) and peer device
memory (PEER). The core's peer interface selects a registered memory provider,
pins an allocation and maps it for a requester. Stage implementations and family
runtimes use pools and core-issued leases. They do not call provider pin/map
operations directly or include NVIDIA-private headers. Vendor providers and
native device backends implement their respective hardware-facing hooks and
can use vendor interfaces within those implementations.

The pool interface in `xdev_ext_mech.h` and peer-provider interface in
`xdev_ext_peer.h` retain their distinct roles. Pool callbacks resolve, synchronize,
allocate and recycle frames; peer-provider callbacks pin, map and describe device
backing. Core admission, frame ownership and conservative retention still apply
to the resulting resources. These interfaces do not by themselves guarantee
producer visibility, device quiescence or physical DMA reachability.

A dma-buf importer is planned as another memory source behind the peer-provider
boundary. It is not implemented by this contract documentation. The plan does
not add a memory family or export the session's frame pool: an external consumer
of a whole buffer cannot be assumed to honor each frame's ownership or permanent
isolation. Host dma-buf admission and pin accounting remain separate design
decisions.

The source boundary check is part of
`tests/integration/peer_graph/family_wiring_source_test.py`. It checks stage and
family source files, excluding vendor providers and native driver backends; it
does not prove runtime mapping or lifetime correctness.

## Data route and control route

A shared host pool can connect storage, networking and copy-engine stages without requiring a CPU payload copy between every stage. GPU copy-engine transfers still move bytes between host memory and VRAM. An ordinary socket sink performs native socket copying. Peer-memory paths have a separate allocation and mapping contract; they must not be inferred from a staged example.

Control and completion follow the same ownership chain. Native acceptance transfers responsibility to the submitted operation. A refusal before acceptance can permit bounded backpressure or retry. An accepted operation is tracked through its terminal outcome instead of being resubmitted as new work.

## Lifetimes and errors

Generation and operation tickets distinguish the currently admitted resource or operation from stale callbacks. Backpressure limits outstanding work to configured capacity. Exact completion advances ownership to the next stage; short, failed or uncertain accepted operations can require quarantine.

A notification wakes the observer; it does not by itself prove that every device is quiescent. STOP follows drain rules and may retain a session and its mappings when completion is unknown. Code must use final status and the provider contract before recycling resources.

See the [session API](../reference/session-api.md), [BPF contract](../reference/bpf-contract.md), and [provider API](../reference/provider-api.md) for interface details.
