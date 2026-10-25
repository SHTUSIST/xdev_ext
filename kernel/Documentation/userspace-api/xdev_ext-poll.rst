XDEV_EXT mechanism stage polling
================================

This page specifies one optional, device-independent way for a mechanism
session to obtain the native completions of a stage by polling the device
from the session's own kernel worker, instead of waiting for the device
interrupt. Polling is off unless a stage asks for it. A session that does not
ask for it behaves exactly as before.

Polling trades CPU time for not depending on interrupt delivery. Nothing in
this page claims that a polled session is faster than an interrupt-driven
one; that can only be measured on physical devices, with the polling CPU
counted in the CPU budget of the comparison.

User parameter
--------------

``XDEV_EXT_MECH_STAGE_F_POLL`` (bit 29 of ``struct
xdev_ext_mech_stage_uapi.flags``, ``include/uapi/linux/xdev_ext_mech.h``) asks
for polling of that stage. The same bit has the same meaning on every class,
like ``XDEV_EXT_MECH_STAGE_F_FANOUT`` (bit 31). A caller that wants every
stage polled sets the bit on every stage; a caller that wants only the NVMe
stage polled sets it only there.

Why a stage bit and not a CREATE field: ``struct xdev_ext_mech_create`` has no
flags word, so a session-wide switch would change its layout. A stage bit keeps
every existing structure layout and also lets a session poll some stages but
not others (for example poll the NVMe read but leave a copy-engine stage on its
interrupt).

Strict meaning, no silent fallback
----------------------------------

CREATE fails with ``-EOPNOTSUPP`` when any stage carries the bit and either

* the stage's class has no poll implementation (``->poll`` is NULL in its
  ``struct xdev_ext_mech_class_ops``), or
* the class has one, but the bound device cannot be polled. The per-class
  conditions are listed below (for example an NVMe namespace without poll
  queues).

There is no case in which a stage requested polling, CREATE succeeded, and the
stage's completions are delivered by its interrupt instead, apart from one
condition the AF_XDP section names as outside the guarantee (an administrator
changing the NIC's NAPI settings after CREATE). Another poller of the same
native queue, or a driver timeout handler that polls, may also reap a
completion; that is still a polled completion. STATS is unchanged; a
successful CREATE is the report that every flagged stage is polled. The bit is stripped from ``flags`` before the generic per-class flag
rules run, and the class ``->bind`` receives the stage description without it.

NVMe has one more case after CREATE: if the namespace loses its poll queues
later (a controller reset with a different queue count), a submit whose block
request is not on a poll queue is refused before it reaches the device and the
batch fails with ``-EOPNOTSUPP``. It is never issued on an interrupt queue.

Kernel interface
----------------

``include/linux/xdev_ext_mech.h``:

``struct xdev_ext_mech_stage.poll``
  ``true`` when CREATE accepted ``XDEV_EXT_MECH_STAGE_F_POLL`` for this stage.
  Set by the core before ``->bind``; a class checks the device capability in
  its ``->bind`` and returns ``-EOPNOTSUPP`` when it cannot poll.

``int (*poll)(struct xdev_ext_mech_stage *st)`` in ``struct
xdev_ext_mech_class_ops``
  Optional. Called only for a stage whose ``st->poll`` is set, only from the
  session's kthread worker, never with a session lock held. One bounded pass:
  it reaps native completions of this stage that the device has already
  produced, and must not sleep, wait for the device, or submit new work.
  Completions it finds are delivered through the normal claim and publish
  calls (``xdev_ext_mech_batch_completion_claim()`` and the
  ``xdev_ext_mech_batch_complete*()`` family), possibly before ``->poll``
  returns, exactly as an interrupt-time completion would be. Returns the number
  of native completions the pass processed (``>= 0``; on a native queue shared
  with other users this may include their completions) or ``-errno`` when this
  pass could not poll. The return value is informational; the core does not
  stop polling because of it.

``int (*poll)(struct xdev_ext_dma_region *r)`` in ``struct
xdev_ext_dma_provider_ops`` and ``bool polled`` in ``struct xdev_ext_dma_region``
  The generic DMA provider route for new devices. The DMA class sets
  ``out->polled`` before calling the provider's ``->bind_region`` when the
  stage asked for polling. A provider without ``->poll`` makes such a CREATE
  fail with ``-EOPNOTSUPP``; a provider whose particular device cannot poll
  returns ``-EOPNOTSUPP`` from ``->bind_region``. For a polled region the
  provider delivers normal completions from ``->poll`` (or inline from
  ``->submit``) and must not depend on a device interrupt or a provider thread
  for them; completions caused by errors or teardown may still come from any
  context. Exactly-once completion per accepted submit and the ``hw_submitted``
  rules are unchanged. ``->poll`` runs in the session worker, must not sleep,
  and returns the number of transfers it completed or ``-errno``.

``int blk_mq_poll_hw_queue(struct request_queue *q, unsigned int queue_num,
struct io_comp_batch *iob)`` in ``include/linux/blk-mq.h``
  Runs one pass of ``q->mq_ops->poll`` on hardware queue ``queue_num`` if that
  queue is currently a poll queue, holding a queue usage reference as
  ``bio_poll()`` does, and returns the driver's count. It exists because the
  mechanism's NVMe requests are passthrough requests whose bio has no block
  device (so ``bio_poll()`` does not apply), and polling by request pointer
  (``blk_rq_poll()``) is unsafe here: another poller or the timeout handler can
  complete and free that request concurrently.

Who polls, when, and in which context
-------------------------------------

Each session has one ``kthread_delayed_work`` (``poll_work``) on its own
kthread worker, the same worker that already runs every build, submit and
completion step. User threads never poll; STATS does not poll; no new thread is
created. One pass calls ``->poll`` of every polled stage in stage order and then
decides whether to run again:

* again immediately (delay 0), while the session has live batches
  (``ss.inflight > 0``) and is ACTIVE, ERROR or STOPPING, or while it is ACTIVE
  and its stage 0 is a polled AF_XDP receive stage (a receive source has no
  submit to start polling and can receive at any time);
* again after one jiffy, while the session is ZOMBIE (the drain bound passed or
  something was sequestered) and still has live batches: late completions are
  still reaped, without keeping a CPU busy indefinitely;
* not again otherwise, and never after ``worker_gone`` is set.

The re-arm decision is taken under ``s->lock``, the same lock that sets
``worker_gone``. Polling starts on the first accepted submit to a polled stage
(``xdev_ext_mech_batch_run()`` queues ``poll_work`` with delay 0) and, for a
polled AF_XDP receive source, right after CREATE activates the session. A pass
is requeued at the tail of the worker's queue, so completion handling
(``drain_work``), START progress (``kick_work``), retries and STOP processing
run between passes; ``kthread_worker_fn()`` calls ``cond_resched()`` after each
work item.

Concurrency: only the session worker calls ``->poll``, so two passes of the
same stage never run at the same time. A native completion found by a pass
may race with the same completion arriving another way (another poller of a
shared queue, a timeout handler, device removal); the existing ticket claim
(``xdev_ext_mech_batch_completion_claim()``) admits exactly one of them.

STOP, drain, sequester and unknown DMA
--------------------------------------

STOP does not cancel ``poll_work``. While accepted native commands remain, the
worker keeps polling through STOPPING and the bounded drain, so their
completions arrive and the drain can finish within
``XDEV_EXT_MECH_DRAIN_TIMEOUT`` (5 s). Without this, an NVMe command on a poll
queue would complete only through ``nvme_timeout()``, which polls the queue
after ``io_timeout`` and logs ``timeout, completion polled`` long after the
drain bound.

The existing rules hold unchanged:

* Accepted commands are never resent; polling only collects completions of
  work the device already accepted.
* A stage the drain bound could not settle stays in ``release_deferred``; its
  worker keeps polling until the last batch ends and decides the release.
* AMBIGUOUS and unknown-DMA outcomes still sequester; a sequestered or ZOMBIE
  session still keeps every frame, mapping and module reference it held.
  Polling never makes an uncertain resource look quiescent.
* Teardown cancels ``poll_work`` with ``kthread_cancel_delayed_work_sync()``
  next to ``retry_work`` and ``progress_work``, after ``worker_gone`` is set and
  before ``kthread_destroy_worker()``; class ``->unbind`` runs after that, so no
  pass can use an unbound stage.

Per-class behaviour
-------------------

NVMe (``drivers/nvme/host/xdev_ext_mech_nvme.c``)
  ``->bind`` requires that the namespace queue can poll: ``BLK_FEAT_POLL`` and
  a nonzero ``HCTX_TYPE_POLL`` queue map (nvme-pci with ``nvme.poll_queues=N``
  at boot or before the controller reset, and at least two I/O queues). Each
  submit, host pages and device-memory pool alike, allocates its request with
  ``REQ_POLLED`` (the upstream polled passthrough pattern of
  ``nvme_alloc_user_request()``), refuses with ``-EOPNOTSUPP`` if
  ``blk_rq_is_poll()`` is false, and records the request's hardware queue
  number in its per-batch slot before ``blk_execute_rq_nowait()``. End_io clears
  that record. ``->poll`` calls ``blk_mq_poll_hw_queue()`` once for each
  distinct queue number recorded by a live slot. Completion still runs the same
  end_io, claim and publish code as an interrupt completion.

DMA provider class (``io_uring/xdev_ext_mech_dma.c``)
  ``->poll`` calls the provider's ``->poll`` for the stage's region; see the
  provider interface above. The CPU-memcpy selftest provider
  (``tools/testing/selftests/xdev_ext_mech/provider/xdev_ext_dma_provider_sim.c``)
  implements it for functional tests only; it is not a physical DMA result.

AF_XDP (``net/xdp/xsk_xdev_ext_mech.c``)
  Polling means NAPI preferred busy polling (``Documentation/networking/napi.rst``,
  section "Busy polling"): each pass calls ``napi_busy_loop()`` once, with
  ``prefer_busy_poll`` true and budget ``BUSY_POLL_BUDGET``, for the NAPI
  instance of the socket's receive queue and, for a zero-copy transmit stage
  whose transmit queue has its own NAPI instance, for that one too. The NAPI
  poll then runs in the session worker and processes received frames and
  transmit completions there. ``->bind`` requires, under RTNL: a valid NAPI id,
  and nonzero ``defer_hard_irqs`` and ``gro_flush_timeout`` on each polled NAPI
  instance (``/sys/class/net/<dev>/napi_defer_hard_irqs`` and
  ``gro_flush_timeout``, or the per-NAPI netlink settings). With these settings
  and preferred busy polling, NAPI keeps the device interrupt masked while the
  worker keeps polling, and returns to interrupts only after
  ``gro_flush_timeout`` passes without a poll; without them the interrupt path
  would still deliver completions, so CREATE refuses. The settings are checked
  at CREATE; changing them while a session runs is outside this guarantee.

  Roles:

  * The receive source (stage 0, FROM_DEVICE) polls the receive NAPI while the
    session is ACTIVE.
  * A zero-copy transmit stage completes in the NAPI instance the driver
    registered for its transmit queue (``netdev_queue.napi``). That instance
    must be known, and must either be the receive instance (one NAPI per queue
    pair) or be busy-pollable itself. A transmit-only instance added with
    ``netif_napi_add_tx()`` carries ``NAPI_STATE_NO_BUSY_POLL``, is never
    hashed and has no NAPI id, so no kernel interface can busy-poll it; CREATE
    refuses. virtio-net registers its transmit queues this way, so a zero-copy
    AF_XDP transmit stage on virtio-net cannot be polled.
  * A copy-mode transmit stage in reliable mode polls the receive NAPI, which
    delivers its acknowledgements.
  * A plain copy-mode transmit stage completes inside ``->submit``
    (``xsk_kernel_xmit()`` returns after the skb owns its bytes), so there is
    nothing to poll and CREATE refuses with ``-EOPNOTSUPP``.

Not pollable in this version (CREATE refuses the bit with ``-EOPNOTSUPP``)
  * CE (GPU copy engine): completions come from the backend driver. The NVIDIA
    backend (``gpu/kernel-open/nvidia/nv-xdev_ext-ce-backend.c``) retires
    requests from CeUtils semaphore events, or, when built with
    ``NV_XDEV_EXT_CE_POLL_COMPLETION``, from its own hrtimer that rechecks the
    semaphore watermark. Moving that retirement into the session worker needs
    a backend ``poll`` member and changes inside the GPU driver that cannot be
    validated without a GPU; the KVM copy-engine stand-in is CPU memcpy only.
    A new device should use the DMA provider route instead.
  * NET (native NIC over a device-memory pool): completions come from the peer
    NIC driver's completion queue processing. It would need an endpoint poll
    operation in ``xdev_ext_peer_net`` (for example NAPI busy polling of the
    mlx5 channel), which needs the physical NIC to test.
  * SOCKET and CPU: their completions are already synchronous in ``->submit``.
  * IAA: completions come from the crypto driver; polling there is a driver
    setting outside the mechanism.

CPU cost
--------

While a pass runs immediately after the previous one, the session worker keeps
one CPU busy: for the whole time any batch is live on a session with a polled
stage, and for the whole ACTIVE lifetime of a session whose receive source is
polled, even when no packet arrives. The worker is not bound to a CPU.
Requests submitted from different CPUs may use different NVMe poll queues; a
pass polls each queue that has a live request. Pollers on the same queue share
its completion lock. Any comparison with interrupt-driven sessions must report
this CPU as part of the measured system's CPU budget.

Tests
-----

Host tests (``tools/testing/selftests/xdev_ext_mech/poll/``) compile the
production functions with deterministic shims: CREATE flag admission, the
re-arm rule, the NVMe submit, end_io and ``->poll`` paths, the DMA class and
provider registry, and the AF_XDP capability checks. The KVM guest test
(``tools/testing/selftests/xdev_ext_mech/poll/poll_kvm.sh``) boots the product
kernel with ``nvme.poll_queues=2`` and checks real QEMU NVMe polled sessions,
STOP with polled commands in flight, the DMA selftest provider's poll mode
driven by the same bit, AF_XDP polling over two virtio-net devices, and every
refusal above. On virtio-net the KVM test polls the AF_XDP receive session
and shows the transmit refusal; a polled zero-copy transmit stage needs a
driver whose transmit queue completes in a busy-pollable NAPI. KVM results
are correctness evidence only.
