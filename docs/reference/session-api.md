# Session API

The authoritative declarations are in [xdev_ext_mech.h](../../kernel/include/uapi/linux/xdev_ext_mech.h) and [io_uring.h](../../kernel/include/uapi/linux/io_uring.h). Compile against the headers from the same project revision as the target kernel.

Control operations use `io_uring_register(ring_fd, IORING_REGISTER_XDEV_EXT_MECH, &request, 1)` with `struct io_uring_xdev_ext_mech`. Its `op` selects the operation and `arg` identifies the corresponding request structure. STOP takes the session identity as specified by the header.

## Lifecycle

1. Load the class programs and register the required providers.
2. Register or bind the pool and open the stage resources.
3. CREATE with the ABI version, pool kind, bounded layout, depth and stage sequence. Keep the returned full session identity.
4. Optionally arm a final eventfd notification before starting work.
5. START with the source batch count, initial key and applicable user-frame flags.
6. Observe STATS, and TRANSPORT_STATS for applicable reliable transport paths, until the requested outcome or an error.
7. STOP and follow its drain/quarantine result before releasing resources.

CREATE validates the combination of pool, layout and stages. An allocated session does not grant arbitrary device-memory access. The kernel retains the references required for accepted work and checks generations and native operation tickets throughout its lifetime.

## Pools and source spans

| Pool kind | Bound resource |
|---|---|
| `XDEV_EXT_MECH_POOL_XSK` | An AF_XDP socket's registered UMEM |
| `XDEV_EXT_MECH_POOL_IOU_UMEM` | UMEM registered on this io_uring instance |
| `XDEV_EXT_MECH_POOL_PEER` | An authoritative device-allocation fd with a separate mapping contract |

Support for a pool kind depends on the stage classes and providers. A peer pool has no fabricated CPU pages; use the [peer UAPI](../../kernel/include/uapi/linux/xdev_ext_peer.h) for its exact allocation and mapping declarations.

For IOU UMEM, `USER_FRAMES` lends the listed frames to the kernel. `RECYCLE` permits the bounded initial frame groups to cycle during a single run; userspace must wait for the final outcome before touching them. It does not synthesize fresh payload. `USER_SPANS` supplies an actual byte length for its restricted one-frame, one-batch call shape and cannot be combined with RECYCLE. Consult the header for flag combinations and dimensions.

## USER stage

A USER stage (`XDEV_EXT_MECH_CLASS_USER`) hands each batch's frames to an application thread through two rings in a region mapped from a user stage fd, created with `XDEV_EXT_MECH_OP_USER_STAGE`. It is for functions a BPF program cannot express. Every batch has a required deadline; the frames keep the in-place lifecycle of a fixed CPU transform; releasing the user stage fd stops the session with `-EPIPE`. The protocol, limits and error codes are in [xdev_ext-user-stage.rst](../../kernel/Documentation/userspace-api/xdev_ext-user-stage.rst); the user-side helpers are in section 8 of the [library specification](../../kernel/tools/xdev_ext_mech/lib/SPEC.md).

## Observation and completion

Counters are cumulative except fields explicitly documented otherwise. Per-stage submitted/completed counters describe native operations; an observer must also inspect final state, `last_err`, in-flight work, sequestered resources and applicable transport state.

`NOTIFY_ARM` selects cumulative batch or publication targets and changes eventfd notification behavior. An error or stop can also signal it. A wakeup is an observation event, not a guarantee that accepted DMA drained.

ACTIVE, ERROR, STOPPING, STOPPED and ZOMBIE states distinguish normal execution, a sequestered batch, teardown and retained unresolved work. Accepted work is not replayed as a new native command. A resource whose completion or DMA quiescence is unknown stays retained under the provider's lifetime contract.
