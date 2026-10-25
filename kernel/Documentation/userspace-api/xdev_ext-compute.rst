XDEV_EXT mechanism BPF compute callback (CPU class)
===================================================

This page specifies how a CPU stage of a mechanism session runs a BPF program
over the payload of each batch, in place of one of the fixed kernel
transforms. The program is the ``compute`` member of the CPU class struct_ops
type. A session that does not select it behaves exactly as before, and a CPU
struct_ops object built without the member loads and runs unchanged.

Nothing in this page claims that a BPF transform is faster or slower than the
fixed kernel transform it replaces; that can only be measured on physical
hardware.

User parameters
---------------

A stage selects the callback with transform id ``XDEV_EXT_CPU_XFORM_BPF``
(10, ``include/uapi/linux/xdev_ext_mech.h``). The other stage fields keep the
CPU class rules: ``class_id = XDEV_EXT_MECH_CLASS_CPU``, ``direction =
XDEV_EXT_MECH_DIR_TO_DEVICE``, ``fd = -1``, ``flags = 0``.

``arg0``
  ``XDEV_EXT_CPU_XFORM_BPF``.

``arg1``
  The declared per-frame length change ``D``, a signed 64-bit value stored in
  two's complement, with ``-XDEV_EXT_CPU_BPF_DELTA_MAX <= D <=
  XDEV_EXT_CPU_BPF_DELTA_MAX`` (256). Every frame of every batch leaves the
  stage with exactly ``L + D`` valid bytes, where ``L`` is its valid length on
  entry. ``0`` keeps every length.

CREATE fails with ``-EINVAL`` for a ``D`` outside that range. Like a fixed
transform with a non-zero length change, a non-zero ``D`` followed by an NVMe
or AF_XDP stage without an intervening transform stage fails CREATE with
``-EOPNOTSUPP``, because both classes need the fixed group size.

CREATE fails with ``-EOPNOTSUPP`` when the CPU struct_ops generation the session
pins at CREATE has no ``compute`` program. There is no silent fallback to a
kernel transform.

A CPU program's ``build`` may still pick the transform of each batch through its
``struct xdev_ext_cpu_desc``: as before, it may pick only a transform with the
same length change as the one declared at CREATE. It may therefore pick
``XDEV_EXT_CPU_XFORM_BPF`` with ``param = D`` on a stage created with a fixed
transform of the same length change, and the other way round. Picking
``XDEV_EXT_CPU_XFORM_BPF`` while the pinned generation has no ``compute``
program rejects that batch with ``-EOPNOTSUPP`` before any frame is touched.

Program interface
-----------------

``__s32 (*compute)(const struct xdev_ext_mech_ctx *ctx)`` is a member of every
mechanism struct_ops type (it is part of ``XDEV_EXT_MECH_OPS_TYPE()``), but only
``struct xdev_ext_cpu_mech_ops`` accepts a program for it. Loading a program for
``compute`` of any other type fails in the verifier with ``attach to
unsupported member compute of struct ...``. The member is optional and never
sleeps: a sleepable program (``SEC("struct_ops.s/...")``) is rejected the same
way. libbpf matches struct_ops members by name, so an object whose type has no
``compute`` member leaves it NULL.

The core calls ``compute`` once per batch, from ``->submit`` of the CPU class on
the session's kernel worker. The context has ``member =
XDEV_EXT_MECH_MEMBER_COMPUTE`` (4), ``callsite = XDEV_EXT_MECH_SITE_WORKER`` and
``nr_frames`` set to the frames of the batch; the program walks them itself,
for example with ``bpf_loop()`` or ``bpf_for()``.

Return value: ``0`` accepts the batch. A value in ``[-4095, -1]`` completes the
batch with that error. Any other value completes it with ``-EPROTO`` and counts
a protocol error. A failed batch is never retried, because the program may have
changed part of the payload; it is handled like a failed fixed transform.

Kfuncs
------

Available only to ``compute``:

``__u32 bpf_xdev_ext_frame_len(ctx, __u32 pos)``
  The valid length ``L`` of frame ``pos`` on entry. An out-of-range ``pos``
  returns 0 and fails the batch with ``-EPROTO``.

``__u8 *bpf_xdev_ext_frame_rw(ctx, __u32 pos, __u32 off, const size_t rdwr_buf_size)``
  A writable view of bytes ``[off, off + rdwr_buf_size)`` of the frame's data
  area. ``off`` counts from the first valid byte of the frame. The size must be
  a verifier constant. The view may extend past ``L`` up to the frame's capacity,
  the bytes from the first valid byte to the end of the chunk, so that a program
  can append. The call returns NULL when the range does not lie inside that
  capacity, when ``rdwr_buf_size`` is 0, or when ``pos`` is out of range.

``int bpf_xdev_ext_frame_set_len(ctx, __u32 pos, __u32 len)``
  Records the output length of frame ``pos``. It accepts only ``len == L + D``.
  Any other value, or an out-of-range ``pos``, returns ``-EINVAL`` and fails the
  batch with ``-EPROTO``.

Also available to ``compute``, with the meaning they have in ``build`` and
``complete``: ``bpf_xdev_ext_frame()`` (read-only view; its ``off`` counts from
the start of the chunk, not from the first valid byte), ``bpf_xdev_ext_frame_crc32c()``
(also chunk offsets) and ``bpf_xdev_ext_crc32c()`` (over any memory the program
may read, for example a view returned by ``bpf_xdev_ext_frame_rw()``). No other
mechanism kfunc is available to ``compute``, and the three ``compute`` kfuncs are
not available to ``prepare``, ``build`` or ``complete``.

Every view is valid only during the call that returned it.

Length rule
-----------

Before it calls the program, the core checks every frame: if ``L + D`` is below
0 the batch fails with ``-EBADMSG``, and if it is above the frame's capacity it
fails with ``-EMSGSIZE``. In both cases the program does not run and no byte
changes.

After the program returns 0, the length recorded for every frame must be ``L +
D``. A frame for which the program did not call ``bpf_xdev_ext_frame_set_len()``
keeps ``L``, so with ``D != 0`` the program must set every frame. A mismatch
fails the batch with ``-EPROTO``. Only then does the core apply the new lengths
(``xdev_ext_mech_batch_cpu_length()``).

Variable output lengths are not supported by this callback. A transform whose
output length depends on the data stays a kernel transform with a reserved
destination (``XDEV_EXT_CPU_XFORM_DEFLATE`` and ``XDEV_EXT_CPU_XFORM_INFLATE``).

Ownership
---------

The callback runs at the same point as the fixed transforms, with the same
ownership: the frames are ``IN_FLIGHT``, and each frame's lifecycle word is
``OUT_PENDING`` with the stage's exclusive claim, so no device and no other
stage holds them. The previous stage's completion has already synchronised
them for the CPU. On success the batch completes synchronously and the frames
are published ``READY`` for the next stage with their new lengths, exactly as
after a fixed transform. No new lifecycle state exists for this callback.

Limits
------

* One program for all CPU sessions. The mechanism layer keeps one published
  struct_ops generation per class (a second attach fails with ``-EBUSY``), and a
  session pins the generation current at its CREATE. Every CPU session created
  while a generation is attached runs that generation's ``compute``. A session
  chooses per batch only between that program and the fixed transforms (see
  User parameters).
* The program runs to completion on the session's kernel worker and holds that
  worker meanwhile: no other batch, completion or STOP processing of the session
  runs until it returns. Its work per call is bounded only by the verifier
  limits: one million processed instructions per program, at most ``1 << 23``
  iterations per ``bpf_loop()`` call, and 512 bytes of stack.
* The pool must be CPU-mapped, as for every CPU stage; a device-memory pool is
  refused at CREATE.
* There is no per-session program selection and no sleepable ``compute``.

Tests
-----

Host rule and wiring tests: ``tools/testing/selftests/xdev_ext_mech/compute/``,
the CPU transform rules in
``tools/testing/selftests/xdev_ext_mech/xdev_ext_mech_cpu_xform_test.c`` and the
CREATE rules in ``xdev_ext_mech_fanout_step_test.c``. Verifier rejections:
``tools/testing/selftests/bpf/progs/xdev_ext_mech_fail_compute_*.c``, run in a
guest by ``tools/testing/selftests/xdev_ext_integration/verifier/run_compute.sh``.
KVM correctness run (NVMe read, CPU stage with ``compute``, NVMe write, compared
with an independent oracle): ``tools/testing/selftests/xdev_ext_mech/compute/compute_kvm.sh``.
