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

## Data route and control route

A shared host pool can connect storage, networking and copy-engine stages without requiring a CPU payload copy between every stage. GPU copy-engine transfers still move bytes between host memory and VRAM. An ordinary socket sink performs native socket copying. Peer-memory paths have a separate allocation and mapping contract; they must not be inferred from a staged example.

Control and completion follow the same ownership chain. Native acceptance transfers responsibility to the submitted operation. A refusal before acceptance can permit bounded backpressure or retry. An accepted operation is tracked through its terminal outcome instead of being resubmitted as new work.

## Lifetimes and errors

Generation and operation tickets distinguish the currently admitted resource or operation from stale callbacks. Backpressure limits outstanding work to configured capacity. Exact completion advances ownership to the next stage; short, failed or uncertain accepted operations can require quarantine.

A notification wakes the observer; it does not by itself prove that every device is quiescent. STOP follows drain rules and may retain a session and its mappings when completion is unknown. Code must use final status and the provider contract before recycling resources.

See the [session API](reference/session-api.md), [BPF contract](reference/bpf-contract.md), and [provider API](reference/provider-api.md) for interface details.
