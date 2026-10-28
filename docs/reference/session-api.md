# Session API

The authoritative declarations are in [xdev_ext_mech.h](../../src/core/include/uapi/linux/xdev_ext_mech.h) and [io_uring.h](../../src/core/include/uapi/linux/io_uring.h). Compile against the headers from the same project revision as the target kernel.

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

## Explicit CREATE_REPORT (operation 10)

`XDEV_EXT_MECH_OP_CREATE_REPORT` takes
`struct xdev_ext_mech_create_with_report` through `request.arg`. Set its
`size` to `sizeof` that envelope, its `version` to
`XDEV_EXT_MECH_CREATE_REPORT_VERSION` (1), and fill its embedded `create`
using the ordinary CREATE contract. `create.session_id` and every byte of
`report` must be zero on input. The frozen operation 1 CREATE request and its
return behavior remain available.

The kernel reuses the actual CREATE validation, bind, requester admission,
prepare, activation and rollback path. Reporting adds no second admission
decision, mapping attempt or BPF invocation. For a successful reported CREATE,
the complete envelope is copied out before the session is published and
progress is enabled. Ingress, command and native-control admission remains
closed until report delivery and list publication finish. A copyout failure
rolls back that unpublished session.

A syscall return of 0 means a complete report was delivered. Read
`report.result` for the CREATE result, either 0 or the original negative
errno; `rollback_errno` separately records rollback's return. For example,
syscall 0 with `report.result == -EXDEV` describes a failed CREATE with a
readable refusal report. Invalid size or nonzero output input is `-EINVAL`,
an unsupported report version is `-EOPNOTSUPP`, and a user copy fault is
`-EFAULT`; these errors supply no complete report. An older kernel can reject
operation 10 with `-EINVAL` or `-EOPNOTSUPP`.

`report` contains the following values:

- `size` and `version` identify the report schema.
- `result` and `rollback_errno` separate the primary CREATE outcome from
  cleanup errors.
- `phase` records the actual failed execution step, from CHECK through
  ACTIVATE as declared in the header. `failed_stage` is the applicable stage
  index or `UINT32_MAX` for a failure without a stage. Success has phase 0
  and `failed_stage == UINT32_MAX`.
- `session_id` is nonzero only on success. On failure the report and both
  embedded `caps` and `observed` session IDs are zero.
- `valid` gates the `REQUESTER`, `DESCRIBED`, `DECIDED`, `CAPS`, `OBSERVED` and
  `POST_ROLLBACK_RETENTION` observations. Zero fields without their valid bit
  do not establish a precondition.
- `requester` contains PCI domain, bus and devfn, plus a zero reserved word.
  Bus and devfn occupy the PCI 8-bit range. It contains no object or DMA
  address.
- `caps` copies the stage's actual CREATE capability and refusal record.
  Topology or established mapping records do not prove a physical transfer.
- `observed` reserves the value format for stage observations. This revision
  leaves `OBSERVED` and `observed.valid` clear. When
  `POST_ROLLBACK_RETENTION` is valid, `observed.retention` holds the requester
  ledger sampled after cleanup; its requester-wide and global totals can
  include other links. This sampling is separate from any stage capture.

`cleanup` is NONE (0) on success or when a failure formed no session,
RELEASED (1) after actual rollback release, or RETAINED (2) after quarantine. A nonzero rollback error
does not alone imply retention: release can return a final session error
after freeing the session. RETAINED preserves unresolved DMA resources and
the primary `result`. No failed-session identity is exposed for a later
query, and zero ledger counts do not authorize releasing unknown resources.
The report is an immutable value copy owned by the caller, not a kernel
last-error entry or a live status record.

The normal library exposes `xdev_ext_session_create_report()` and the raw
owning-ring form `xdev_ext_create_report_read()`, returning `report.result`
after validation. Each call clears non-NULL `out` first; `out->size == 0`
means no validated report was delivered, including syscall and `-EPROTO`
schema failures. A saved older report must be copied elsewhere before output
reuse. Neither API falls back to operation 1 or retries CREATE. See the
[library contract](library-contract.md#31-explicit-create-reports) for exact
signatures and ownership.

For a RETAINED failed CREATE the library keeps `created == false`, ID 0 and
the retained flag set. Further CREATE, STOP and close return `-EBUSY`, preserve
owner handles and allocation authority, and issue no STATS or STOP for ID 0.
The raw API caller retains responsibility for those owner resources.

Normal ctl selects this operation only with `--diagnostics`. Failure output
includes the primary and rollback errors, phase, stage, cleanup, valid bits,
requester, reachability and refusal mask. Unsupported or invalid report
delivery prints `diagnostics=unavailable`; the command still fails. RETAINED
output identifies kernel quarantine; fd close does not demonstrate DMA
release, and that report path skips explicit CUDA allocation destruction.
Dynamic STAGE_DIAG queries, `peer-diag` and diagnostic snapshots before timeout
STOP remain unimplemented in this revision. The report does not certify
physical device execution or performance.

## Pools and source spans

| Pool kind | Bound resource |
|---|---|
| `XDEV_EXT_MECH_POOL_XSK` | An AF_XDP socket's registered UMEM |
| `XDEV_EXT_MECH_POOL_IOU_UMEM` | UMEM registered on this io_uring instance |
| `XDEV_EXT_MECH_POOL_PEER` | An authoritative device-allocation fd with a separate mapping contract |

Support for a pool kind depends on the stage classes and providers. A peer pool has no fabricated CPU pages; use the [peer UAPI](../../src/core/include/uapi/linux/xdev_ext_peer.h) for its exact allocation and mapping declarations.

For IOU UMEM, `USER_FRAMES` lends the listed frames to the kernel. `RECYCLE` permits the bounded initial frame groups to cycle during a single run; userspace must wait for the final outcome before touching them. It does not synthesize fresh payload. `USER_SPANS` supplies an actual byte length for its restricted one-frame, one-batch call shape and cannot be combined with RECYCLE. Consult the header for flag combinations and dimensions.

## USER stage

A USER stage (`XDEV_EXT_MECH_CLASS_USER`) hands each batch's frames to an application thread through two rings in a region mapped from a user stage fd, created with `XDEV_EXT_MECH_OP_USER_STAGE`. It is for functions a BPF program cannot express. Every batch has a required deadline; the frames keep the in-place lifecycle of a fixed CPU transform; releasing the user stage fd stops the session with `-EPIPE`. The protocol, limits and error codes are in [xdev_ext-user-stage.rst](xdev_ext-user-stage.rst); the user-side helpers are in section 8 of the [library specification](library-contract.md).

## Observation and completion

Counters are cumulative except fields explicitly documented otherwise. Per-stage submitted/completed counters describe native operations; an observer must also inspect final state, `last_err`, in-flight work, sequestered resources and applicable transport state.

`NOTIFY_ARM` selects cumulative batch or publication targets and changes eventfd notification behavior. An error or stop can also signal it. A wakeup is an observation event, not a guarantee that accepted DMA drained.

ACTIVE, ERROR, STOPPING, STOPPED and ZOMBIE states distinguish normal execution, a sequestered batch, teardown and retained unresolved work. Accepted work is not replayed as a new native command. A resource whose completion or DMA quiescence is unknown stays retained under the provider's lifetime contract.

A batch that aborts before any device accepted it (for example a provider that refuses the map, so nothing was submitted or sequestered) does not change the session state. The session stays ACTIVE, records the first error in `last_err`, and still attempts the remaining batches of the same START. Such an abort stops the session only when START used `RECYCLE` or a remaining stage belongs to an ordered class (NET, AF_XDP, socket). Callers detect the failure from `batches_abort` and `last_err`; STOP returns `last_err`.
