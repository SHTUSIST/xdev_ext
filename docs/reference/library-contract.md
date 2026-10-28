# libxdev_ext specification (version 1)

libxdev_ext is a thin user-space C library over the XDEV_EXT session
control plane (`IORING_REGISTER_XDEV_EXT_MECH`, see
`src/core/include/uapi/linux/xdev_ext_mech.h` and `docs/reference/session-api.md`).
It packages the steps of one run: io_uring setup, frame pool registration,
class program attach, CREATE, optional NOTIFY_ARM, START, waiting on the
session eventfd, STATS, STOP and resource release. It adds no kernel
interface and changes no UAPI. Every session decision (admission,
generation checks, DMA mapping, drain and quarantine) stays in the kernel.

Public header: `src/lib/libxdev_ext.h`. Build from the repository root: `make lib`
produces `libxdev_ext.a`. The class program part links libbpf (>= 1.0);
the session part needs only libc.

## 1. Conventions

- Every function returns 0 or a negative errno. Kernel errors are passed
  through unchanged. No function prints.
- Every options struct starts with `size_t sz`, set to `sizeof` the struct
  the caller compiled against (`XDEV_EXT_OPTS_INIT(type, ...)` does this).
  A smaller `sz` than the version 1 layout is `-EINVAL`. A larger `sz` is
  accepted only when every byte past the known layout is zero; otherwise
  `-EOPNOTSUPP` (the caller asked for a feature this library lacks).
- `flags` fields: an unknown bit is `-EOPNOTSUPP`. The USER control and
  explicit-frame interfaces have the flags described in section 9.
- Library-reserved extension points (not implemented, reserved names only):
  appending batches to a running session, and NVMe completion polling. They
  will arrive as new `flags` bits or appended fields; a version 1 library
  rejects both with `-EOPNOTSUPP`, so a caller never silently runs without
  the requested behaviour. A second START on one session is `-EOPNOTSUPP`
  through the original start function for the same reason. The separate
  explicit-frame interface in section 9 permits a proven drained restart.

Error codes chosen by the library itself:

| code | meaning |
|---|---|
| `-EINVAL` | NULL pointer, out-of-range value, missing required field |
| `-EOPNOTSUPP` | unknown flag, nonzero unknown opts tail, reserved feature |
| `-ENOTCONN` | operation needs a created session; retained failed CREATE uses `-EBUSY` for stop |
| `-EALREADY` | the step already happened (second CREATE) |
| `-E2BIG` | the frame pool cannot hold what START would lend |
| `-ETIMEDOUT` | wait deadline passed without a notification |
| `-EBUSY` | a retained handle cannot create, stop or close without preserving its resources |
| `-EAGAIN` | STOP still refused after its bounded retry (own uring_cmds pending) |
| `-EPROTO` | a returned report has an invalid schema |

## 2. Class programs

```c
struct xdev_ext_prog_global { const char *name; __u64 value; };
struct xdev_ext_prog_opts {
	size_t sz;
	const char *obj_path;   /* BPF object */
	const char *map_name;   /* struct_ops map to attach */
	const char *pin_path;   /* optional: also pin the link */
	const struct xdev_ext_prog_global *globals;
	__u32 nr_globals;       /* <= XDEV_EXT_PROG_MAX_GLOBALS */
	__u32 flags;            /* 0 */
};
int  xdev_ext_prog_attach(const struct xdev_ext_prog_opts *o, struct xdev_ext_prog **out);
int  xdev_ext_prog_detach(struct xdev_ext_prog *p);
```

Attach opens the object, disables autocreate of every other struct_ops map
in it (as `xdev_ext_mech_ctl attach` does), sets the `.bss`/`.data`
globals before load, loads, and attaches the map. The returned handle owns
the link; detach destroys it, which unregisters the class programs. With
`pin_path` the link is also pinned and detach unpins it. Class programs are
system wide: a session uses whatever programs of its classes are attached.
Detaching while a session of that class is live stops that session (kernel
generation retraction), so the library never detaches programs that a
retained session (section 5) still owns.

## 3. Session steps

```c
struct xdev_ext_pool_opts {
	size_t sz;
	__u32 pool_kind;   /* XDEV_EXT_MECH_POOL_XSK or XDEV_EXT_MECH_POOL_IOU_UMEM */
	__u32 xsk_mode;    /* XSK: XDEV_EXT_XSK_ZEROCOPY (0) or XDEV_EXT_XSK_COPY */
	const char *ifname;/* XSK: required */
	__u32 queue;       /* XSK: queue id */
	__u32 nr_frames;   /* 0: 4096; frames are XDEV_EXT_FRAME_SIZE (4096) bytes */
	__u32 flags;       /* 0 */
};
int xdev_ext_session_open(const struct xdev_ext_pool_opts *o, struct xdev_ext_session **out);

struct xdev_ext_create_opts {
	size_t sz;
	__u32 group_bytes;     /* required; bytes per batch */
	__u32 depth;           /* required; batches in flight at most */
	__u32 mtu;             /* 0: XSK ifname MTU, IOU 1500 */
	__u32 nr_stages;       /* 1..XDEV_EXT_MECH_MAX_STAGES */
	struct xdev_ext_mech_layout layout;   /* all zero: computed (below) */
	struct xdev_ext_mech_peer peer;       /* local_mac all zero: XSK ifname's MAC */
	struct xdev_ext_mech_stage_uapi st[XDEV_EXT_MECH_MAX_STAGES];
	__u32 flags;           /* 0 */
};
int xdev_ext_session_create(struct xdev_ext_session *s, const struct xdev_ext_create_opts *o);
int xdev_ext_session_arm(struct xdev_ext_session *s, __u64 batches_target, __u64 published_target);

struct xdev_ext_start_opts {
	size_t sz;
	__u64 nr_batches;      /* required */
	__u64 first_seq;       /* 0: 1 */
	__u32 flags;           /* 0 */
};
int xdev_ext_session_start(struct xdev_ext_session *s, const struct xdev_ext_start_opts *o);
int xdev_ext_session_wait(struct xdev_ext_session *s, int timeout_ms, struct xdev_ext_mech_stats *out);
int xdev_ext_session_stats(struct xdev_ext_session *s, struct xdev_ext_mech_stats *out);
int xdev_ext_session_nic_accounting(struct xdev_ext_session *s, struct xdev_ext_mech_transport_stats_v3 *out);
int xdev_ext_session_stop(struct xdev_ext_session *s);
int xdev_ext_session_close(struct xdev_ext_session *s);

int   xdev_ext_session_eventfd(const struct xdev_ext_session *s);
int   xdev_ext_session_ring_fd(const struct xdev_ext_session *s);
int   xdev_ext_session_xsk_fd(const struct xdev_ext_session *s);  /* -1 unless XSK */
__u64 xdev_ext_session_id(const struct xdev_ext_session *s);      /* 0 before CREATE */
bool  xdev_ext_session_zero_copy(const struct xdev_ext_session *s);
bool  xdev_ext_session_retained(const struct xdev_ext_session *s);
```

open: io_uring_setup(8), a nonblocking CLOEXEC eventfd, then the pool.
XSK: an AF_XDP socket on `ifname`/`queue` with an aligned UMEM of
`nr_frames` 4096-byte chunks, fill/completion rings and a TX ring, bound
with exactly the requested mode (`XDP_ZEROCOPY` or `XDP_COPY`); a bound mode
different from the request is `-EOPNOTSUPP` (zero-copy refused) or
`-EPROTO`, never a silent downgrade. IOU_UMEM: an anonymous mapping of
`nr_frames` frames registered with `IORING_REGISTER_XDEV_EXT_UMEM`.

create: fills `struct xdev_ext_mech_create` with `XDEV_EXT_MECH_ABI_VERSION`,
the pool (`pool_fd` = XSK socket, or -1 for IOU_UMEM), the session eventfd,
`depth`, `peer`, and the stages. A zero layout is computed by the same NXP
rule as `xdev_ext_mech_ctl` (`xdev_ext_mech_ctl_layout()`: 4096-byte
frames, 360 bytes of header room, segment length from the MTU). For an XSK
pool, every AF_XDP stage whose `fd` is negative gets the pool socket.
Stage class, direction, flags, args and fds are otherwise passed through
for the kernel to validate. One CREATE per session handle.

arm: NOTIFY_ARM with the two absolute targets (at least one nonzero).

start: XSK copy mode first fills the fill ring with the pool's first 2048
chunks (the copy-mode kernel source takes frames from it); zero-copy uses the
kernel source and needs no fill. IOU_UMEM lends frames 0..k-1 with
`USER_FRAMES | RECYCLE`, k = min(nr_batches, depth) * frames-per-batch;
k > nr_frames is `-E2BIG`. One START per handle in version 1.

wait: polls the eventfd until one notification or `timeout_ms` (negative:
no deadline), then takes one STATS into `out` in both cases. Returns
`-ETIMEDOUT` on deadline, the kernel `last_err` when set, `-ESHUTDOWN` when
the state is no longer ACTIVE, `-EIO` when batches are short, aborted,
in flight or sequestered relative to the armed batch target, otherwise 0.
A wakeup is an observation, not proof that accepted DMA drained: callers
must still STOP (section 5).

nic_accounting: TRANSPORT_STATS version 3 (NIC copy/zero-copy op and byte
counters). It must be read before STOP, because STOP releases the session.

### 3.1. Explicit CREATE reports

```c
int xdev_ext_session_create_report(struct xdev_ext_session *s,
    const struct xdev_ext_create_opts *o,
    struct xdev_ext_mech_create_report *out);
int xdev_ext_create_report_read(int owning_ring_fd,
    const struct xdev_ext_mech_create *create,
    struct xdev_ext_mech_create_report *out);
```

`xdev_ext_session_create_report()` uses the same option packing as
`xdev_ext_session_create()` and explicitly selects `CREATE_REPORT` (operation
10). The raw form, `xdev_ext_create_report_read()`, submits a raw CREATE
request on the supplied owning ring; `create->session_id` must be zero. It
borrows the ring and request resources and does not create a library handle
or take over their cleanup. The original `xdev_ext_session_create()` continues
to select operation 1.

The kernel's syscall return and the CREATE result are separate. A syscall
return of 0 means the complete report was copied out; `report.result` carries
the actual CREATE result, either 0 or the original negative errno. Both
library functions validate that report, copy it to `out`, and return
`report.result`. Thus a library return of `-EXDEV` can accompany a valid
admission refusal report. On success the session function records the returned
nonzero ID and marks its handle created. A failed CREATE leaves its ID zero
and its handle uncreated.

Every call with non-NULL `out` first clears it. Only a fully delivered and
validated report has a nonzero `size` and version
`XDEV_EXT_MECH_CREATE_REPORT_VERSION` (1). Invalid arguments, syscall errors
and schema errors leave `out->size == 0`; callers must not consume other
report fields in that case. Schema errors return `-EPROTO`. A caller saving
an earlier report must copy it elsewhere before reusing the output object.
An older kernel can reject the new operation with `-EINVAL` or
`-EOPNOTSUPP`; the library returns the error and never retries legacy CREATE.

The report is a caller-owned value. Its `result` preserves the primary CREATE
error, while `rollback_errno` records cleanup's separate result. `phase`
identifies the failed execution step; `failed_stage` is the stage index or
`UINT32_MAX` when there is no stage. A successful report has `phase == 0` and
`failed_stage == UINT32_MAX`. The `valid` mask controls whether requester
identity, description, admission decision, caps and observations are available.
Requester identity is the PCI `domain`, `bus` and `devfn`, with bus and devfn
in the 8-bit PCI range. `caps` contains the recorded CREATE preconditions and
refusal mask. A failed report's `session_id`, `caps.session_id` and
`observed.session_id` are all zero. No field supplies an object query token.

`cleanup` describes the actual disposition:

- `XDEV_EXT_MECH_CREATE_CLEANUP_NONE` (0): no rollback was needed on success,
  or the failure formed no session to release.
- `XDEV_EXT_MECH_CREATE_CLEANUP_RELEASED` (1): rollback released the session.
  `rollback_errno` may still contain a final session error.
- `XDEV_EXT_MECH_CREATE_CLEANUP_RETAINED` (2): rollback quarantined unresolved
  resources. The primary CREATE error stays in `result`.

For RETAINED, the session function sets `xdev_ext_session_retained(s)` true
while keeping the handle uncreated with ID 0. Further CREATE, STOP and close
calls return `-EBUSY`. Close preserves the ring, allocation authority,
eventfd and other owned resources; it issues no STATS or STOP for ID 0 and
cannot use `STATS == -ENOENT` as release evidence. Keep this handle and its
owner resources alive. The raw API leaves the equivalent owner-resource
retention obligation with its caller. There is no failed-session query token
that can authorize later reclamation.

A saved report remains readable after ordinary released handles are closed.
It is the observation from that CREATE and cleanup, rather than a live status
record. A failed XDOMAIN bind captures `OBSERVED` before releasing its endpoint
when that endpoint still belongs to the bound incarnation. A later stage failure
also captures its diagnostic hook before rollback. Failure before an endpoint
exists, or a stale incarnation, leaves `OBSERVED` clear. If
`POST_ROLLBACK_RETENTION` is valid, `observed.retention` contains the requester
ledger sampled after rollback; this replaces the earlier retention sample and
clears its diagnostic RETENTION valid bit. Its totals can include other links
sharing that requester. Those totals do not certify DMA quiescence. Admission,
topology and mapping observations require separate physical device validation.

Normal `xdev_ext_mech_ctl` accepts `--diagnostics` on its CREATE paths. It calls
the same raw library API and prints failure `result`, `rollback_errno`,
`phase`, stage, cleanup, valid bits, requester identity, reachability and
refusal mask. An unavailable report prints `diagnostics=unavailable` and the
command remains failed. RETAINED output identifies kernel quarantine and
states that fd close does not release DMA; the command skips explicit CUDA
allocation destruction on that report path. Without the flag the command
uses legacy CREATE. This flag does not change wait deadlines.

## 4. One call: NVMe -> NIC

```c
struct xdev_ext_nvme_nic_opts {
	size_t sz;
	const char *nvme_path;  /* /dev/ngXnY, opened O_RDONLY by the library */
	__u64 slba, nlb;        /* source LBA window */
	const char *ifname; __u32 queue; __u32 xsk_mode;
	struct xdev_ext_mech_peer peer;
	__u32 group_bytes, depth;
	__u64 nr_batches;
	int timeout_ms;         /* wait bound; negative: none */
	__u32 nr_progs;         /* <= XDEV_EXT_MAX_PROGS */
	const struct xdev_ext_prog_opts *progs;  /* optional, attached in order */
	__u32 flags;            /* 0 */
};
struct xdev_ext_run_result {
	size_t sz;
	__u64 session_id;
	bool zero_copy;          /* the XSK pool bound in zero-copy mode */
	bool retained;           /* STOP could not release; see `session` */
	int wait_err, nic_err, stop_err;
	struct xdev_ext_mech_stats stats;              /* the wait snapshot */
	struct xdev_ext_mech_transport_stats_v3 nic;   /* read before STOP */
	struct xdev_ext_session *session;  /* non-NULL only when retained */
};
int xdev_ext_nvme_to_nic(const struct xdev_ext_nvme_nic_opts *o, struct xdev_ext_run_result *r);
```

It runs, with the step API above: attach the given class programs; open
an XSK pool on `ifname`; open `nvme_path`; CREATE stage 0 NVMe READ of the
window and stage 1 AF_XDP TX on the pool socket; NOTIFY_ARM for
`nr_batches`; START `nr_batches` from sequence 1; wait; read NIC accounting;
STOP; close; detach the programs in reverse order. The NVMe payload is
read by the device into the AF_XDP UMEM frames and the NIC transmits those
same frames; user space touches no payload byte. Return: 0 only when the
wait result is 0, NIC accounting was read and STOP released the session;
otherwise the first failure. With a retained session it returns `-EBUSY`,
`r->retained` is true and `r->session` owns every resource including the
attached programs; the caller later calls `xdev_ext_session_close()` on it.

## 5. Ownership and lifecycle

- The session handle owns: the ring fd, the eventfd, the XSK socket and its
  ring mappings and UMEM, or the IOU UMEM mapping, the library-opened stage
  fds (one-call), and adopted program handles (one-call). Stage fds the
  caller passes in `xdev_ext_create_opts.st[].fd` are borrowed: the caller
  keeps them open until close returns 0. The kernel takes its own
  references at CREATE, so this rule is about user-space reuse, not kernel
  safety.
- stop: STOP returning `-EAGAIN` (the kernel still runs this task's own
  uring_cmd completions) is retried after returning to user space, up to
  1000 times 1 ms apart, then `-EAGAIN` is returned and the session stays
  live. STOP returning 0 means released. `-EBUSY` means the kernel kept
  the session (drain bound passed with accepted commands in flight, or
  quarantine/ZOMBIE): the handle becomes retained. Any other error is
  returned unchanged, but it alone does not say whether the session is
  gone: the kernel returns the session's final error (`last_err`) after a
  full release, and an unbind error after quarantining it. stop then
  queries STATS: `-ENOENT` marks the handle released, anything else marks
  it retained.
- close on a live session issues stop first. On a retained handle with a
  successfully delivered nonzero session ID, close
  queries STATS (which also finds sessions no longer listed on the ring):
  `-ENOENT` means the kernel released it, and close then frees everything
  and returns 0; any snapshot means it is still held, and close returns
  `-EBUSY` leaving every resource in place: no munmap, no fd close, no
  program detach. Resources whose accepted DMA outcome is unknown are never
  released early. The caller may call close again later; a retained handle
  that is never closed is a deliberate leak.
- close on a handle that never reached CREATE frees immediately, except a
  retained failed CREATE_REPORT handle: section 3.1 preserves that handle and
  its authority without querying ID 0.
- After close returns 0 the handle pointer is invalid.

## 6. Threads and signals

There is no global mutable state in the library apart from the test hook
(section 7). Distinct handles may be used from distinct threads. Calls on
one handle must be serialized by the caller. The eventfd may be polled by
the caller's own event loop (`xdev_ext_session_eventfd()`); reading it
consumes the notification, so a caller that reads it itself should then
use `xdev_ext_session_stats()` rather than `wait`. No signal handler is
installed; EINTR in poll is retried against the original deadline.

## 7. Test hook

`libxdev_ext_internal.h` declares `struct xdev_ext_sys` (io_uring_setup,
io_uring_register, usleep, ioctl) and `xdev_ext__set_sys()`. Host unit tests use
it to observe the request structures the library builds and to inject
kernel returns, including the individual successes needed to reach the
step under test (for example a session id from CREATE or a STATS snapshot
to classify). The eventfd, poll and memory mappings stay real. The hook is
not part of the public API, and no host test asserts a device run; a
successful run is proven only by the guest test against the real kernel
(`tests/core/library/guest/lib_kvm.sh`).

## 8. USER stage

The user side of a USER stage
(`docs/reference/xdev_ext-user-stage.rst` in the kernel tree):
a stage whose work on each batch is done by an application thread. The
library adds no kernel interface; it wraps `XDEV_EXT_MECH_OP_USER_STAGE`,
the mapping and the two rings.

```c
struct xdev_ext_user_stage_opts {
	size_t sz;
	int ring_fd;       /* io_uring fd for the register call */
	void *umem;        /* pool UMEM base, for frame data pointers; NULL: none */
	__u32 entries;     /* power of two <= 256, >= CREATE depth; 0: 64 */
	__u32 flags;       /* 0 */
};
struct xdev_ext_user_batch {
	__u32 slot, nr_frames;
	__u64 ticket, batch_id, key, arg;
	struct xdev_ext_user_frame f[XDEV_EXT_MECH_MAX_FRAMES];  /* copy of the slot's frames */
	void *data[XDEV_EXT_MECH_MAX_FRAMES];
};
int xdev_ext_user_stage_open(const struct xdev_ext_user_stage_opts *o,
			     struct xdev_ext_user_stage **out);
int xdev_ext_user_stage_fd(const struct xdev_ext_user_stage *u);
int xdev_ext_user_stage_next(struct xdev_ext_user_stage *u, int timeout_ms,
			     struct xdev_ext_user_batch *b);
int xdev_ext_user_stage_complete(struct xdev_ext_user_stage *u,
				 const struct xdev_ext_user_batch *b, int status);
int xdev_ext_user_stage_close(struct xdev_ext_user_stage *u);
```

- open creates a nonblocking wakeup eventfd owned by the handle, makes the
  register call with it, and maps the region at the offsets the kernel
  returned. Pass `xdev_ext_user_stage_fd()` as the USER stage's `fd` in
  CREATE (`st[i]`, raw stage description, section 3). Kernel errors pass
  through; a region whose returned offsets do not fit the mapping is
  `-EPROTO`.
- next takes the next ready entry: 0 with `*b` filled; `-EAGAIN` with
  `timeout_ms` 0 and nothing ready; `-ETIMEDOUT` when a positive timeout
  passed; a negative timeout waits without a bound. Before waiting it sets
  the sleeping flag and checks the ring once more, so a batch the kernel
  hands out meanwhile wakes it. Once the kernel marked the stage stopped
  and no entry is left, next returns `-ESHUTDOWN` without waiting. An entry
  with a slot or frame count out of range is consumed and reported as
  `-EPROTO`. An entry whose slot no longer holds its ticket (the kernel
  cancelled the batch before it was read, and may already have reused the
  slot for a later batch with its own entry) is consumed and skipped.
- `f` is the library's copy of the slot's frame descriptions, taken while
  the slot held the entry's ticket; a later rewrite of the slot by the
  kernel does not change it. While holding `*b` the thread may read
  `f[i].data_len` bytes at `data[i]` and write up to `f[i].capacity` bytes
  there, and sets `f[i].out_len` to each frame's output length (preset to
  the input length). The kernel checks the lengths against the stage's
  rule.
- complete copies `f[i].out_len` into the slot only while the slot still
  holds `b->ticket`, then posts the completion entry with `status` (0 or a
  negative errno the batch fails with; positive, or `nr_frames` above
  `XDEV_EXT_MECH_MAX_FRAMES`, is `-EINVAL`) and kicks the kernel only when it
  asked for a kick. The entry of a batch the kernel already cancelled is
  still posted; the kernel refuses it. A full completion ring is `-ENOSPC`
  and posts nothing. A kick error (`-ENOTCONN`: the stage is no longer bound) is
  returned after the entry was posted.
- close unmaps and closes the fd and the eventfd. Closing the last
  reference to the user stage fd while its session runs stops that session
  with `-EPIPE` (kernel rule), so close only after STOP.
- Threads: one thread at a time may call next, and one thread at a time
  may call complete, on one handle (single consumer, single producer).
  After a batch was cancelled by the kernel (deadline or stop), writing its
  frames can corrupt a later batch's payload: the frames may already belong
  to a later batch. The library cannot stop a transform that is already
  running when the deadline fires, so the application must not write a
  batch's payload after its deadline (CREATE `arg0`), and should stop
  touching a batch when next has returned `-ESHUTDOWN` or the slot's ticket
  changed.

## 9. PEER and external-control extension

`xdev_ext_session_open_peer` accepts a previously registered allocation fd,
duplicates it using F_DUPFD_CLOEXEC, and creates only an io_uring and eventfd.
It does not register UMEM, map payload on the CPU or assume the authority's
range from a user VA. CREATE passes the duplicate as POOL_PEER pool_fd;
the kernel validates the allocation and stage geometry. Caller ownership of
the original fd is unchanged. Failed setup releases acquired resources.
STOP/close UNKNOWN and retained results keep the library handle and its
duplicate authority alive, using the same retained rules as other pools.

`xdev_ext_session_start_frames` accepts explicit frame indices in caller order.
It copies them until the synchronous syscall returns and sets
USER_FRAMES|ORDERED_FRAMES. It adds RECYCLE only when explicitly requested.
It never substitutes allocator-selected or lowest-numbered frames.
After an accepted START, another START requires STATS to prove the prior
cumulative goal is done, with no inflight, abort, sequestered or session error.
Before each START it installs a cumulative batch NOTIFY_ARM target, replacing
any previously installed batch or published target. A failed START does not
advance local started/count state; a retry installs the same new target.
The original start/arm API keeps its existing behavior.

`xdev_ext_user_batch_peer_span` converts one copied frame into an allocation
offset and GPU address. It checks frame alignment, index width, data offset,
capacity, valid length, whole-frame allocation bounds and VA arithmetic.
Every error leaves the output unchanged. The returned address does not itself
prove allocation authority, DMA qualification, visibility or last use.
PEER USER objects are opened with umem=NULL and batch.data[] stays NULL.

USER open accepts XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL. `stage_control` exposes
only the control mapping plus exact negotiated offsets; it rejects legacy
objects. `ctl_attach`/`ctl_detach` forward the explicit lifetime ioctls. A
duplicate attach returns -EALREADY; detach without attachment returns -ENOENT.
An ioctl failure preserves local attachment state, and close of an attached
object returns -EBUSY. In particular a bound detach failure does not unmap or
close the region. GPU controllers must attach before CREATE and detach after
native STOP/unbind and proven GPU completion.

`xdev_ext_stage_xdomain` constructs a channel0 strict XDOMAIN stage from a
control fd, never-reused link token and direction. The only accepted flag is
generic POLL; the helper does not enable ALLOW_UNVERIFIED.
`xdev_ext_session_stage_caps` returns the kernel's actual post-CREATE
STAGE_CAPS record without interpreting topology as executed DMA evidence.

`xdev_ext_link_read` reads bounded version1 sysfs records and returns their
structural state, including down state for discovery output. `link_discover`
requires a unique matching token with nonzero local/remote incarnation,
channel count, up=1 and closing=nhi_gone=0. A missing or malformed state is
an error. These read-only APIs do not register memory, submit I/O or establish
GPU/NHI capabilities. Normal ctl exposes `peer-discover`, `peer-preflight
--link TOKEN` and `peer-caps --ring-fd FD --session ID --stage N`; the last
requires the inherited owning ring fd rather than querying a different ring.

`xdev_ext_stage_diag_read(owning_ring_fd, session_id, stage, out)` queries
STAGE_DIAG (operation 11, version 1). `xdev_ext_session_stage_diag` uses the
session's own ring. The ring must still own the session; stopped objects may
be queried until released. A missing session returns ENOENT, an invalid stage
returns EINVAL, a class without the hook or an unknown version returns
EOPNOTSUPP, and an incarnation mismatch returns ESTALE. The library checks the
returned identity, version, validity masks, reserved fields and timestamp order.
The version-1 library decoder currently supports XDOMAIN only and requires the
IDENTITY valid bit; other classes or a missing identity return EPROTO, as does
malformed output. Future classes need explicit client schema support. Every
failure leaves `out` zero.

The valid mask identifies IDENTITY (bit 0), NATIVE (1), RX_POSTED (2),
CONTROL (3), PROTOCOL (4), and RETENTION (5). Readiness identifies control UP
(bit 0), receive ready (1), closing (2), NHI gone (3), matching stage incarnation
(4), and the existing startup data challenge verified for this channel (5).
These observations do not establish GPU backing visibility or last use.
Native counts describe only the selected channel and direction's real native
in-flight list and software queue. RX_POSTED excludes frames still queued in
software. Missing retired native rings clear NATIVE and RX_POSTED validity;
zero counters alone do not establish safe release. Control free slots belong
to the shared link. Protocol counters report outstanding CTS, ACK, FAIL, final
chain waits, and completed local RX payload awaiting downstream release. The
RX reply preserves local completion facts from the native callback after CQE
fill releases its reusable network slot. Successful, proven quiescent RX
completion awaiting chain release contributes to both final_waiting_chain and
downstream_release_pending, even before the protocol marks the final reply
sendable. Actual chain release removes that wait and permits the existing
ACK/FAIL policy; diagnostics do not advance that policy or send replies.
Reply reallocation clears the saved facts for the next group. Errors and
UNKNOWN do not qualify as successful local quiescence. These counters do not
report CUDA kernel progress. Retention is the requester's existing aggregate
ledger, including other links and services.

The capture timestamps enclose separate lock-protected observations, rather
than one atomic snapshot across protocol, native rings and retention. Query
performs no allocation registration, mapping, provider admission, posting or
policy invocation. Normal ctl exposes `peer-diag --ring-fd FD --session ID
--stage N` through the same library API. Its wait helpers collect diagnostics
for XDOMAIN stages recorded from a CREATE plan before returning a timeout to
the original STOP and cleanup; diagnostic errors do not replace the timeout
or reset its deadline. This wait-helper boundary is connected, but the CLI
currently has no configurable XDOMAIN START/wait campaign. The `xdomain-probe`
command remains an admission probe followed by STOP.

The optional CUDA Driver library is built separately from the base C archive.
Set XDEV_EXT_CUDA_PTX to the matching real PTX artifact before opening a GPU
controller. Its control region is registered as mapped host metadata only;
payload remains device memory. A handle owns exactly one stream and requires
strict USER|POLL. System-scope acquire/release kernels consume fresh ready
key/ticket metadata at each replay. Native owner write ordering or supported
remote-write flush is required before device payload reads. During capture,
the flush is an actual batch-memop graph node linked to the stream's capture
dependencies. This is a capability-gated implementation, not hardware proof.

CUDA close requires the caller to have destroyed graph executables referencing
the handle, succeeds only after stream synchronization, unregisters metadata
and then detaches. Any CUDA or detach error retains the handle; a detach retry
does not unregister twice. d1 event_complete records and synchronizes a real
event after caller stream work before publishing done0; a CUDA failure posts
negative UNKNOWN status. d1 capture is unsupported. Physical correctness and
performance require separate device execution; link stubs are never runtime
execution libraries.

The ordinary PEER endpoint wrapper prepares a session and USER objects at open;
explicit `endpoint_create` binds them after optional GPU control attachment.
TX uses strict USER producer → XDOMAIN → strict USER terminal. RX uses
XDOMAIN → strict USER consumer. USER stages select POLL. Each endpoint owns
duplicates of both allocation and control fds; caller fds may be closed after
open. Duplex endpoints need distinct allocation authorities because the
kernel claims each registered allocation exclusively.

Endpoint next returns a dedicated message wrapper carrying the unchanged
legacy USER batch, its role and a non-reused endpoint origin cookie. Complete
checks origin, role, outstanding ticket/key/batch/arg and immutable frame
metadata, allowing only out_len to change. This cookie catches accidental
cross-endpoint misuse; it is not security authority for a malicious caller.
Accepted negative completion poisons the endpoint and preserves UNKNOWN.

CPU endpoint next waits on the producer and terminal USER eventfds, with
terminal priority and one monotonic deadline across interrupts and wake hints.
An attached external controller on either USER returns -EBUSY before CPU
consumption; the GPU owner continues to use its metadata protocol.

Endpoint close checks every external-control attachment before changing any
session or fd. If any USER is still attached it returns -EBUSY and preserves
the entire endpoint, even after payload STOP succeeded. The owner must call
endpoint_stop, successfully synchronize/unregister/detach its CUDA controller,
then endpoint_close. There is no automatic detach or assumption that native
payload completion proves the metadata controller has stopped.

CUDA operations bind each USER object's lifetime to its first qualified actual
CUDA context ID and stream ID. Queries use cuCtxGetId, cuStreamGetCtx and
cuStreamGetId, so a CU_STREAM_PER_THREAD numeric handle in another thread does
not bypass the single-stream contract. The private pair is installed and
checked under a tiny atomic flag; driver API calls happen outside that lock.
The CUDA controller and d1 event_complete share the same USER binding.
Current-context, actual stream context/ID and capture qualification errors
return before d1 event completion publishes any done entry. An actual event
record/synchronization error after qualification still reports negative
UNKNOWN. There is no new kernel UAPI or change to the public USER batch ABI.

Metadata atomicity uses NVIDIA's independent guarantee for naturally aligned
32/64-bit load/store on mapped host memory. The library still checks successful
mapped-host registration, alias/field alignment, complete region extents and
all CUDA query results. HOST_NATIVE_ATOMIC_SUPPORTED=0 alone does not reject
this load/store-only protocol. Adding atomic RMW would require separate
qualification. This qualification does not relax remote VRAM write visibility;
the same native-ordering or supported-flush requirement and physical GPU/NHI
acceptance remain necessary.
