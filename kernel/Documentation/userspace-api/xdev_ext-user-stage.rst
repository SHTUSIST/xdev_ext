XDEV_EXT mechanism USER stage
=============================

This page specifies the USER stage class: a stage of a mechanism session
whose work on each batch is done by a thread of the application, through two
rings in memory that the kernel and the application share. It exists for
functions that a BPF program of the CPU class cannot express (a function that
does not pass the verifier, or one that needs a library). Everything else in
the session stays as it is: the kernel keeps admission, frame ownership, the
lifecycle of every frame, generation pinning, teardown and quarantine; the
user thread only reads and writes the payload bytes of the frames the kernel
handed to it, and reports back once per batch.

A session without a USER stage behaves exactly as before. A USER stage is an
explicit choice of the application: the application does not submit
descriptors or re-arm anything, but the completion of each batch at that
stage depends on its user thread. Every batch therefore carries a required
deadline (section "Deadline and cancellation").

Nothing in this page claims that a USER stage is faster or slower than the
CPU class or a BPF compute program. The cost of the handoff between kernel and
user thread can only be measured on physical hardware.

Stage description
-----------------

``struct xdev_ext_mech_stage_uapi`` (``include/uapi/linux/xdev_ext_mech.h``):

``class_id``
  ``XDEV_EXT_MECH_CLASS_USER`` (10). ``XDEV_EXT_MECH_CLASS_MAX`` is 11.
``direction``
  ``XDEV_EXT_MECH_DIR_TO_DEVICE``. A USER stage works in place on the frames
  of the batch, like a fixed CPU transform; ``FROM_DEVICE`` is ``-EINVAL``.
``fd``
  A user stage fd created by ``XDEV_EXT_MECH_OP_USER_STAGE`` (below). A
  negative fd is ``-EBADF``. A fd that is not a user stage fd is ``-EINVAL``.
  One user stage fd serves exactly one stage of one session, once: a second
  CREATE with the same fd is ``-EBUSY``, also after the first session ended
  and also when the first CREATE failed after binding it.
``flags``
  0, or ``XDEV_EXT_USER_F_VARLEN``. Any other bit is ``-EINVAL``.
  ``XDEV_EXT_MECH_STAGE_F_POLL`` is ``-EOPNOTSUPP``: the class has no
  ``->poll`` (section "Polling"). ``XDEV_EXT_MECH_STAGE_F_FANOUT`` is
  ``-EINVAL``, as for every stage that is not a pure consumer.
``arg0``
  The deadline of every batch at this stage, in milliseconds, from 1 to
  ``XDEV_EXT_USER_DEADLINE_MAX_MS`` (600000). 0 or a larger value is
  ``-EINVAL``.
``arg1``
  The output length rule, per frame. Without ``XDEV_EXT_USER_F_VARLEN`` it
  is the exact length change ``D`` of every frame, as a two's complement
  64-bit value: the user thread must report ``data_len + D`` for every frame.
  ``|D|`` must not exceed ``layout.frame_size``, else ``-EINVAL``. With
  ``XDEV_EXT_USER_F_VARLEN`` it must be 0 (else ``-EINVAL``) and any output
  length from 1 to the frame's capacity is accepted.

CREATE also requires, with ``-EOPNOTSUPP`` otherwise:

* a pool with a CPU mapping (``IOU_UMEM`` or ``XSK``). A device-memory
  (``PEER``) pool is refused for every stage class whose peer capability is
  empty, USER included (``xdev_ext_mech_peer_dirs()``);
* when ``D != 0`` or ``XDEV_EXT_USER_F_VARLEN`` is set, no later NVMe or AF_XDP
  stage before a transform stage. Both write fixed groups; this is the same
  rule the CPU class applies to a length-changing transform. At run time the
  core still refuses (``-EOPNOTSUPP``) a batch whose byte count differs from
  the session's group when it reaches NVMe or AF_XDP;
* a struct_ops program of type ``xdev_ext_user_mech_ops`` attached, as for
  every class: a session never runs a class without its program ("no silent C
  path"). Its ``build`` may return ``XDEV_EXT_MECH_BUILD_DEFAULT``.

At bind, the ring size of the user stage fd must be at least the session
depth (``-EINVAL`` otherwise).

Creating a user stage fd
------------------------

``io_uring_register(ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1)`` with
``req.op = XDEV_EXT_MECH_OP_USER_STAGE`` (7) and ``req.arg`` pointing to
``struct xdev_ext_mech_user_stage``:

``size`` (in)
  ``sizeof(struct xdev_ext_mech_user_stage)`` (64).
``flags`` (in), ``rsvd`` (in)
  0.
``entries`` (in)
  Ring size, a power of two from 1 to ``XDEV_EXT_USER_RING_MAX`` (256). It
  must be at least the depth of the session that will use the fd.
``eventfd`` (in)
  An eventfd the kernel signals to wake a sleeping user thread, or -1 for a
  user thread that only polls the rings.
``fd`` (out)
  The new user stage fd, opened ``O_RDWR | O_CLOEXEC``.
``off`` (out)
  ``struct xdev_ext_user_ring_offsets``: ``mmap_size``, and the byte offsets
  ``hdr``, ``ready``, ``done`` and ``slots`` of the parts of the shared
  region inside the mapping.

Every output field must be 0 on input (``-EINVAL``). Other errors:
``-EBADF`` (eventfd), ``-ENOMEM``, ``-EFAULT``. The operation does not belong
to a session; the fd is not bound to anything until CREATE uses it.

The application maps the whole region once:
``mmap(NULL, off.mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)``.
A mapping at a nonzero offset or longer than ``mmap_size`` is ``-EINVAL``.

Shared region
-------------

All parts are written by one side only, except the frame ``out_len`` fields
noted below. The kernel never trusts a value it reads from this region: it
reads each value once into kernel memory and validates that copy.

``struct xdev_ext_user_ring_hdr`` at ``off.hdr``
  Four ring indices and two flag words, each in its own 64-byte line:
  ``ready_prod`` (kernel), ``ready_cons`` (user), ``done_prod`` (user),
  ``done_cons`` (kernel), ``user_flags`` (user) and ``kernel_flags``
  (kernel). Indices are free-running ``__u32`` counters; the entry of index
  ``i`` is at ``i & (entries - 1)``.

Ready ring at ``off.ready``: ``entries`` of ``struct xdev_ext_user_ready``
  Written by the kernel, one per batch handed to the user thread:
  ``slot`` (the batch slot, ``< depth``), ``nr_frames``, ``ticket`` (the
  batch's completion ticket), ``batch_id``, ``key`` (START sequence or RX hold
  key) and ``arg`` (from the program's build descriptor, below).

Completion ring at ``off.done``: ``entries`` of ``struct xdev_ext_user_done``
  Written by the user thread, one per batch it finished: ``slot``, ``ticket``
  (copied from the ready entry) and ``status`` (0, or a negative errno with
  which the batch fails).

Slot table at ``off.slots``: ``entries`` of ``struct xdev_ext_user_slot``
  Indexed by batch slot. Before the kernel produces a ready entry it writes
  the slot's ``ticket``, ``nr_frames`` and, for each frame, ``umem_addr`` (the
  frame's chunk base as an offset in the pool UMEM), ``data_off`` and
  ``data_len`` (the valid input bytes), ``capacity`` (``frame_size -
  data_off``) and ``out_len``, preset to ``data_len``. The user thread may
  overwrite ``out_len`` of the frames of a batch it holds; that is the only
  field user space writes in the slot table. The kernel sets the slot's
  ``ticket`` to 0 when the batch leaves the stage.

The payload of frame ``i`` of a held batch is at ``umem + umem_addr +
data_off``, where ``umem`` is the application's address of the pool UMEM.
The user thread may read the ``data_len`` input bytes and write any byte of
``[data_off, data_off + capacity)`` until it posts the batch's completion.

Ring protocol and memory order
------------------------------

Kernel, handing batch *b* to the user thread (in ``->submit``, on the
session worker):

1. If ``ready_prod - ready_cons`` (``ready_cons`` read once from user memory)
   is not smaller than ``entries``, the ring is full and the submit is
   refused with ``-ENOBUFS``; nothing was handed out and the batch aborts. A
   user thread that consumes ready entries never sees this: at most ``depth``
   batches are held at a time.
2. Write the slot table entry, then the ready entry, then
   ``smp_store_release(&ready_prod, ready_prod + 1)``.
3. ``smp_mb()``; if ``user_flags & XDEV_EXT_USER_F_SLEEPING`` and an eventfd
   was given, signal it.

User thread, taking work: ``smp_load_acquire(&ready_prod)``; read the ready
entry and the slot; ``smp_store_release(&ready_cons, ready_cons + 1)``. To
sleep: set ``XDEV_EXT_USER_F_SLEEPING``, ``smp_mb()``, read ``ready_prod`` and
``kernel_flags`` again, and wait on the eventfd only if there is still no
entry and ``XDEV_EXT_USER_K_STOPPED`` is clear; clear the flag after waking.

User thread, finishing batch *b*: write ``out_len`` of its frames; write the
completion entry; ``smp_store_release(&done_prod, done_prod + 1)``;
``smp_mb()``; if ``kernel_flags & XDEV_EXT_USER_K_NEED_KICK``, call
``ioctl(fd, XDEV_EXT_USER_IOC_KICK)``. Only one thread at a time may produce
completion entries of one stage; the ring has a single producer.

Kernel, reaping completions (``->progress``, on the session worker; the kick
ioctl, the deadline timer and STOP queue it): clear
``XDEV_EXT_USER_K_NEED_KICK``, ``smp_mb()``, then consume at most ``entries``
completion entries: ``smp_load_acquire(&done_prod)``, copy each entry, and
``smp_store_release(&done_cons, ...)`` after the pass. When the pass found no
more entries, set ``XDEV_EXT_USER_K_NEED_KICK``, ``smp_mb()`` and read
``done_prod`` once more; entries that arrived meanwhile are reaped in the
same call. With this order either the user thread sees the flag and kicks,
or the kernel sees the entry. A ``done_prod`` more than ``entries`` ahead of
``done_cons`` is a user bug: the kernel counts one reject and reads only
``entries`` entries, each still validated.

``XDEV_EXT_USER_IOC_KICK`` (``_IO('X', 0xe8)``, argument 0) returns 0, or
``-ENOTCONN`` when the fd is not bound to a live stage; a nonzero argument is
``-EINVAL``. A kick is never required for
correctness: without one, completions are reaped at the latest when the
oldest held batch reaches its deadline, and are then too late.

Validation of a completion entry
--------------------------------

For each completion entry the kernel, on its own copy:

1. Refuses the entry (counts ``rejects`` in STATS and otherwise ignores it)
   when ``slot`` is not smaller than the session depth, the slot holds no
   batch, or ``ticket`` is not the held batch's ticket. A late completion of
   a cancelled batch, a duplicate, and garbage are all refused here; none of
   them can affect a later batch in the same slot.
2. With a nonzero ``status``: the batch fails with ``status`` when it is a
   negative errno (``-4095 .. -1``), with ``-EPROTO`` otherwise (one
   ``protocol_err``).
3. With status 0: reads ``out_len`` of each frame of the batch once and checks
   ``1 <= out_len <= capacity`` and, without ``XDEV_EXT_USER_F_VARLEN``,
   ``out_len == data_len + D``. Every frame is checked before any length is
   applied. A violation fails the batch with ``-EPROTO`` (one
   ``protocol_err``).
4. Otherwise applies the lengths (``xdev_ext_mech_batch_cpu_length()``, the
   same bounded, claim-checked call the CPU class uses) and completes the
   batch with ``xdev_ext_mech_batch_complete()``.

A failed batch takes the normal abort path: its frames' lifecycle claims are
dropped (the frames become FREE), and the frames go back to the pool, or to
user space at the end of a ``USER_FRAMES`` run. A completion is never retried:
the user thread may already have modified the payload.

Lifecycle and frame ownership
-----------------------------

The USER stage adds no lifecycle state. Its role is ``INPLACE``, exactly like
a fixed CPU transform (``xdev_ext_mech_stage_role()``):

* the core acquires each frame of the batch from READY with an exclusive
  claim, so its lifecycle word becomes ``OUT_PENDING`` with the stage as sole
  owner, and moves its ownership word from HELD to INFLIGHT before
  ``->submit``;
* while the user thread holds the batch the frames stay OUT_PENDING/INFLIGHT.
  No device class can acquire them: the next stage acquires only from READY,
  and READY is published only after the completion below;
* on an accepted completion the native completion path republishes each
  frame READY with its new valid length and the reference count of the next
  stage group (``xdev_ext_mech_life_republish()``), as for the CPU class; the
  next stage then runs;
* on failure or cancellation the claim is dropped as a failed put and the
  frames become FREE.

The batches the user thread holds are recorded only in the class's own table
of held batches, one entry per batch slot with the batch, its ticket and its
deadline. This is the same shape as the SOCKET receive class's parked
batches. A lifecycle value does not identify them, and cancellation does not
need one.

Deadline and cancellation
-------------------------

At submit the class records ``deadline = jiffies + msecs_to_jiffies(arg0)``
for the batch. ``->progress`` returns the time to the earliest deadline of a
held batch, so the session worker runs it again then. A held batch is
cancelled (``xdev_ext_mech_batch_complete_cancelled()``) when:

* its deadline passed: error ``-ETIMEDOUT``, and STATS counts one
  ``timeouts``;
* the session no longer admits (STOP, an error stop, a retracted program
  generation, a sequestered batch): error ``-ESHUTDOWN``;
* the stage is dead: the user stage fd was released (below), error
  ``-EPIPE``.

A cancelled batch aborts. With no ordered stage after the USER stage the
session stays ACTIVE and later batches continue; ``last_err`` records the
first error (``-ETIMEDOUT`` for a deadline), and the final STOP returns it.
The exception is a ``RECYCLE`` START, which ends at its first failed batch
for every class (``xdev_ext_mech_end()``): it cannot lend that batch's frames
again.
If an ordered class (AF_XDP, SOCKET, NET) follows the USER stage, the abort
stops the whole session (``xdev_ext_mech_abort()``): those classes have no way
to skip a key on the wire. A USER batch stuck past its deadline before such a
stage therefore ends the session at the deadline.

After a cancellation the kernel has no way to stop a user thread that is
still running on the batch. A late user thread may still write the frames
after they returned to the pool and were reused by a later batch. This only
affects the application's own pool memory: the frames are the application's
UMEM pages, pinned by the pool, and no device and no kernel object depends on
their content. It can corrupt the payload of a later batch. A user thread must
therefore stop touching a batch once ``kernel_flags`` has
``XDEV_EXT_USER_K_STOPPED`` set or its slot's ``ticket`` no longer matches;
both are advisory, the kernel cannot enforce them.

The user stage fd and process exit
----------------------------------

The session does not hold a reference to the user stage file. The class
binds the fd's object (a reference to it, not to the file), so the file is
released when the application's last descriptor and last mapping of it are
gone, normally when the user thread's process exits. The release marks the
stage dead and stops the session with ``-EPIPE``
(``xdev_ext_mech_stage_dead()``, the path a class takes when its device goes
away): the worker cancels the held batches, the session drains and reaches
STOPPED with ``last_err`` ``-EPIPE``, and STOP then releases it and returns
``-EPIPE``. The region itself lives until both the file and the stage let go
of it.

When the process that owns the io_uring ring exits, ring exit stops and
destroys its sessions as for any session; the held USER batches are
cancelled by STOP.

The kernel sets ``XDEV_EXT_USER_K_STOPPED`` and signals the eventfd once
when the stage stops (cancelled for any reason above, or unbound), so a
sleeping user thread wakes and can exit.

Program
-------

The class's struct_ops type is ``xdev_ext_user_mech_ops`` with the members of
every mechanism type. Its ``build`` either returns
``XDEV_EXT_MECH_BUILD_DEFAULT`` (the class writes ``struct
xdev_ext_user_desc`` with ``version`` 1, ``flags`` 0 and ``arg`` 0) or
fills slot 0 itself through ``bpf_xdev_ext_desc()`` and returns
``XDEV_EXT_MECH_BUILD_SUBMIT``. ``version`` must be
``XDEV_EXT_USER_DESC_VERSION`` and ``flags`` 0 (``->validate`` refuses the
batch otherwise); ``arg`` is copied to the ready entry and has no meaning to
the kernel, so a program can pass a per-batch choice to the user thread.
``complete`` sees the batch's status after the user thread finished.

Polling
-------

The USER class has no ``->poll``, so ``XDEV_EXT_MECH_STAGE_F_POLL`` on a USER
stage fails CREATE with ``-EOPNOTSUPP`` (``xdev_ext-poll.rst``). The poll pass
re-queues itself with delay 0 for as long as any batch is in flight, which
would keep a CPU busy for the whole time the user thread computes. The kick
ioctl and the deadline timer cover completion reaping instead.

Limits and what is not provided
-------------------------------

* One user stage fd per USER stage; several USER stages in one session need
  several fds.
* Completion entries of one stage come from one producer at a time.
* At most ``entries`` completion entries are reaped per worker pass; more
  pending entries queue another pass.
* There is no per-frame or partial completion: a batch completes as a whole.
* Variable output into separate destination frames (the CPU class's
  deflate/inflate shape) is not supported; output stays in the batch's own
  frames within their capacity.

The user-space helpers of ``libxdev_ext`` (``tools/xdev_ext_mech/lib``,
``SPEC.md`` section 8) implement the user side of this protocol.
