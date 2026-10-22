XDEV_EXT persistent peer memory
==============================

This interface is separate from the host ``struct page`` UMEM mechanism pool.
It registers device memory once and caches one DMA mapping for each PCI peer.
It does not manufacture CPU pages for GPU memory. The NVIDIA provider uses
``nvidia_p2p_get_pages_persistent`` and ``nvidia_p2p_dma_map_pages``. An NVIDIA
GPU file selects the expected GPU; the persistent pin resolves the GPU virtual
address in the registration caller's address space and verifies the resulting
allocation's GPU UUID against that file.

Registration and authority
--------------------------

With ``CONFIG_XDEV_EXT_MECH=y``, open ``/dev/xdev_ext_peer`` and issue
``XDEV_EXT_PEER_REGISTER`` from ``linux/xdev_ext_peer.h``. ``CAP_SYS_RAWIO`` is
required. Supply the open GPU fd, a 64-KiB-aligned GPU address and length, zero
flags and a zero generation. The ioctl returns an allocation fd with
``O_CLOEXEC`` and writes the allocation generation back. It retains the GPU
file and provider module. A consumer receives this allocation fd and bounded
offsets, not physical addresses. The fd may be transferred as an explicit
allocation authority.

Synchronize CUDA producers before a peer reads VRAM. Wait for a successful
native completion before launching CUDA consumers of peer-written VRAM. This
interface does not insert CUDA stream dependencies or claim cross-device
performance measurements.

NVMe
----

Issue ``XDEV_EXT_PEER_NVME_RW`` on a generic namespace fd (``/dev/ngXnY``),
or ``XDEV_EXT_PEER_NVME_BATCH`` for up to 64 ordered descriptors. A descriptor
contains the GPU allocation offset, namespace SLBA and byte count. Zero flags
reads NVMe into VRAM; ``XDEV_EXT_PEER_NVME_F_WRITE`` reads VRAM to NVMe. The
kernel snapshots the bounded descriptor array and retains the allocation file
through the whole batch. ``completed`` is the successful prefix; the first
failure stops the batch. There is no user continuation between descriptors.

The PCI transport constructs an inline data SGL directly from the admitted
peer DMA address and submits a native blk-mq passthrough request. It creates
no bio and maps no host pages. SGL-capable PCI NVMe, a ready NVM namespace,
ordinary metadata-free LBA format, valid namespace bounds and an aligned byte
count are required. Each command must fit within one GPU DMA-mapping page;
spans that cross a mapping page are rejected. Fabrics and unsupported formats
do not fall back to CE. Write commands require a writable namespace fd and a
writable disk; native passthrough permissions and ``CAP_SYS_RAWIO`` also apply.
Accepted native requests use fail-fast flags and are not resubmitted here.

NIC TX
------

Issue ``XDEV_EXT_PEER_NET_TX`` on ``/dev/xdev_ext_peer`` with an ifindex, TX
queue, allocation fd and up to 32 ordered descriptors. Each descriptor has an
inline CPU header (14--128 bytes), GPU payload offset and payload byte count.
Provide complete Ethernet/protocol headers and checksums. Frames must be at
least 60 bytes and fit the device MTU plus the Ethernet header. Both
``CAP_SYS_RAWIO`` and ``CAP_NET_RAW`` are required. ``completed`` counts
successful local TX CQEs, not remote packet delivery or acknowledgements.

The mlx5 Ethernet implementation queries the actual MKEY and admits only a
readable, full-address physical-address key matching the SQ. It inlines the
CPU header and writes the mapped GPU payload address into a native data WQE.
It checks ring room, queue state and supported inline/offload modes before
acceptance, then rings the native doorbell. Peer WQEs have no host DMA-unmap
entries. Their dedicated CQE path retires the lease; teardown or an unexpected
CQE reports unknown ownership. Accepted packets are not resent. The bounded
batch advances in the kernel after each successful native CQE.

Other NIC drivers without these explicit native operations return
``-EOPNOTSUPP``. RX/header splitting into a GPU payload is unsupported and
nonzero net flags are rejected. This TX contract does not imply NIC RX support.

Lifetime
--------

A generation mismatch, invalid allocation, incompatible direction or out-of-
range offset is rejected before native submission. A lease cannot span GPU
DMA pages. Active leases prevent unmap. Closing an allocation fd invalidates
new admissions and releases mappings only after native request references
are gone. Native unmap or persistent unpin failure retains the allocation.
An unquiesced callback cannot report successful completion, even when its
native status is zero. An uncertain native DMA result permanently quarantines
its mappings, PCI and GPU references and provider module. It is not made reusable by a late CQE.

NIC requests have a 30-second wait bound. On timeout, the common worker
quarantines the lease. Native callback context stays resident until a late CQE
or driver teardown; absence of either deliberately retains that context.

The allocation-fd interface also has a device-memory pool kind for mechanism
sessions. Host UMEM and device-memory frames remain distinct.

One START mechanism compositions
-------------------------------

``XDEV_EXT_MECH_POOL_PEER`` binds ``pool_fd`` to the existing allocation fd.
CREATE obtains a private kernel authority file, captures the allocation length
and generation, and excludes concurrent ordinary fd submissions or a second
mechanism claimant. The caller must still lend the allocation exclusively:
CUDA producers and alternative registrations must not race the session.
Unknown DMA retains this claim and its original file permanently.

The initial pool geometry uses 64-KiB frames, zero host-header room and one
GPU span per batch (``group_bytes <= seg_len <= frame_size``). There are no
CPU pages or CPU frame addresses. ``bpf_xdev_ext_frame`` and its CRC view
cannot return a GPU payload pointer. Class information contains only bounded
allocation offsets, lengths and generation; native addresses stay in C.

The first stage is an NVMe READ producer. Later stages may be NVMe READ/WRITE
or native NET TX. Host-only CE, DMA, IAA, socket and AF_XDP stages are rejected
for this pool; NET RX is rejected. This is a capability boundary rather than
a separate path for every device pair. NVMe keeps its existing 64-byte BPF
command descriptor and C namespace/window validation. NET has a separate
struct_ops type and at most 16 descriptors containing CPU headers and GPU
frame offsets. C requires ordered exact payload coverage without gaps,
duplicates or out-of-range spans before calling the shared native TX helper.

One START with zero user-frame flags advances all requested source batches
inside the existing session worker. BPF build and complete callbacks run at
each stage. Native acceptance is recorded separately from completion status:
refusal before every acceptance permits ordinary scheduling backpressure;
an accepted failure is never resubmitted. If a NET prefix completed and a
later descriptor was refused, the prefix remains completed and is not resent.
The current native helpers wait synchronously, so this interface does not
claim concurrent queue depth or optimal scheduling.

``tools/xdev_ext_mech/xdev_ext_peer_chain`` is a production caller. It loads
``nvme_s0.bpf.o`` (and ``net_peer.bpf.o`` for NET), borrows one GPU allocation,
creates one two-stage session, arms one final notification, issues one START,
checks final counters and STOPs with the full session identity. For example,
its CUDA mode takes::

  xdev_ext_peer_chain --cuda PCI_BDF GPU_NODE SOURCE_NG TARGET \
      GROUPS BYTES LBA_SHIFT SOURCE_SLBA TARGET_SLBA BPF_DIR

An allocation already registered by the calling application can instead be
passed with ``--allocation-fd FD``. TARGET is a writable NVMe generic namespace
or ``net/IFINDEX/QUEUE/LOCAL_MAC/PEER_MAC``. The reference NET BPF program sends
experimental Ethernet frames with a 16-byte CPU sequence/offset header and
1024-byte GPU payload segments. It supports groups up to 16 KiB and MTU at
least 1040; larger NET groups are rejected before device access. Its header
key is the zero-based stream group sequence. The existing ``nvme_s0`` policy
selects namespace group ``request_id % GROUPS`` with request IDs starting at
one. Thus header key ``k`` identifies source group ``(k + 1) % GROUPS``; NVMe
WRITE uses the same rotation on the target window. Receivers must implement
this mapping and the corresponding experimental Ethernet protocol. Local TX
completion does not provide remote acknowledgement or retransmission.
