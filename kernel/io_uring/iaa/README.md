# IAA kernel component

This directory contains the project-owned Intel IAA integration built by
`io_uring/Makefile`:

| File | Responsibility |
| --- | --- |
| `xdev_ext_iaa.c` | Asynchronous compression/decompression over registered UMEM page scatterlists, CryptoAPI submission, and terminal io_uring completion |
| `xdev_ext_iaa.h` | Internal interface used by the unified io_uring operations |
| `xdev_ext_iaa_core.h` | Admission, window, frame ownership, and request lifetime rules shared with host tests |
| `xdev_ext_mech_iaa.c` | Variable-length CryptoAPI transform adapter over independently leased mechanism pool pages |

`CONFIG_IO_URING_XDEV_EXT_IAA` builds the unified operation;
`CONFIG_XDEV_EXT_MECH_IAA` independently builds the mechanism adapter. Shared
UMEM, frame state, mechanism, and public UAPI definitions remain in their common
kernel locations. The component Makefile preserves the feature flags needed by
the unified operation.

The upstream providers retain their Linux layout: IDXD is under
`drivers/dma/idxd/` and the CryptoAPI IAA driver is under
`drivers/crypto/intel/iaa/`. Source preparation supplies unchanged upstream files;
this directory does not replace or duplicate those providers.

## Provider selection and attribution

The unified operation looks up the acomp driver named by
`/sys/module/xdev_ext_iaa/parameters/acomp_driver` (boot parameter
`xdev_ext_iaa.acomp_driver=`; default `deflate-iaa`). `deflate-generic` selects
the software CryptoAPI DEFLATE implementation for functional guest tests; it is
not a device stand-in and never measures IAA. Only algorithms whose CryptoAPI
name is `deflate` are accepted. One transform is shared by all requests; it is
looked up again after a provider-level failure (anything other than success,
`EINVAL`, `EOVERFLOW`, `ENOSPC`, `EBADMSG`, `E2BIG` or `EAGAIN`), after the
selection changes, and after five seconds without requests, so an idle cache
does not pin the provider module. A failed lookup is not cached.

`/sys/module/xdev_ext_iaa/parameters/acomp_served` prints one line per actual
serving driver, `<driver> requests=R errors=E bytes=B`, counting requests that
reached the provider. A `deflate-iaa` line still does not prove device
execution: the IAA driver may complete some decompressions in software, which
only its own statistics show.

## Hardware constraints

`deflate-iaa` maps each side with `dma_map_sg()` and fails with `EIO` unless
it gets one DMA segment. The mechanism adapter therefore merges physically
adjacent pieces and admits a hardware stage at CREATE (`EOPNOTSUPP` otherwise)
only when a batch group is one frame, every frame window
`[hdr_room, hdr_room + seg_len)` and each request slot's whole output window is
one physically contiguous range. A batch of another shape, for example a
multi-frame output of a preceding transform, is refused before CryptoAPI. IOMMU
merging is not relied upon. The unified operation submits one scatterlist entry
per page and makes no such check, so with `deflate-iaa` its buffers must map to
one DMA segment on the platform.

Set `/sys/bus/dsa/drivers/crypto/sync_mode` to `async_irq` before enabling the
IAA work queues. In `sync` and `async` modes the driver polls for completion
inside the submit call, so neither the unified operation nor the mechanism
session overlaps requests. The upstream iaa-crypto documentation notes that
`async_irq` is slower per operation than the polling mode; which mode serves a
given session better is a hardware measurement that has not been made. The IAA
driver copies `sync_mode` into each transform when it is created, so a cached
unified-operation transform or an existing mechanism session keeps the earlier
mode; rewrite `acomp_driver` (any value, including the current one) or create a
new session after changing it. A synchronous `EAGAIN` (a shared work queue that
did not accept the descriptor) is returned before acceptance; the mechanism
adapter reports it as backpressure and the session resubmits the batch.

The [standalone syscall gate](../../../tests/iaa/README.md) builds with
`make -C tests/iaa all check` from the repository root. Additional software
checks remain in `tools/testing/selftests/xdev_ext_iaa/` and
`tools/testing/selftests/xdev_ext_mech/iaa_transform/` under the kernel tree.
The latter exercises the actual adapter at a controlled CryptoAPI boundary;
its explicitly selected software backend does not establish physical IAA DMA
or performance. Hardware execution and attribution require the device/provider
prerequisites described by the syscall gate.
