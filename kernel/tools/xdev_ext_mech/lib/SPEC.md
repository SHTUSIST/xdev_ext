# libxdev_ext specification (version 1)

libxdev_ext is a thin user-space C library over the XDEV_EXT session
control plane (`IORING_REGISTER_XDEV_EXT_MECH`, see
`include/uapi/linux/xdev_ext_mech.h` and `docs/reference/session-api.md`).
It packages the steps of one run: io_uring setup, frame pool registration,
class program attach, CREATE, optional NOTIFY_ARM, START, waiting on the
session eventfd, STATS, STOP and resource release. It adds no kernel
interface and changes no UAPI. Every session decision (admission,
generation checks, DMA mapping, drain and quarantine) stays in the kernel.

Public header: `libxdev_ext.h`. Build: `make -C tools/xdev_ext_mech lib`
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
- `flags` fields: an unknown bit is `-EOPNOTSUPP`. Version 1 knows no bit.
- Library-reserved extension points (not implemented, reserved names only):
  appending batches to a running session, and NVMe completion polling. They
  will arrive as new `flags` bits or appended fields; a version 1 library
  rejects both with `-EOPNOTSUPP`, so a caller never silently runs without
  the requested behaviour. A second START on one session is `-EOPNOTSUPP`
  in version 1 for the same reason.

Error codes chosen by the library itself:

| code | meaning |
|---|---|
| `-EINVAL` | NULL pointer, out-of-range value, missing required field |
| `-EOPNOTSUPP` | unknown flag, nonzero unknown opts tail, reserved feature |
| `-ENOTCONN` | operation needs a created session (arm/start/wait/stats/stop before CREATE) |
| `-EALREADY` | the step already happened (second CREATE) |
| `-E2BIG` | the frame pool cannot hold what START would lend |
| `-ETIMEDOUT` | wait deadline passed without a notification |
| `-EBUSY` | STOP/close could not release: the kernel retains the session |
| `-EAGAIN` | STOP still refused after its bounded retry (own uring_cmds pending) |

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
- close on a live session issues stop first. On a retained handle, close
  queries STATS (which also finds sessions no longer listed on the ring):
  `-ENOENT` means the kernel released it, and close then frees everything
  and returns 0; any snapshot means it is still held, and close returns
  `-EBUSY` leaving every resource in place: no munmap, no fd close, no
  program detach. Resources whose accepted DMA outcome is unknown are never
  released early. The caller may call close again later; a retained handle
  that is never closed is a deliberate leak.
- close on a handle that never reached CREATE frees immediately.
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
(`tools/testing/selftests/xdev_ext_lib/guest/lib_kvm.sh`).

## 8. USER stage

The user side of a USER stage
(`Documentation/userspace-api/xdev_ext-user-stage.rst` in the kernel tree):
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
