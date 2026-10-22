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

The [standalone syscall gate](../../../tests/iaa/README.md) builds with
`make -C tests/iaa all check` from the repository root. Additional software
checks remain in `tools/testing/selftests/xdev_ext_iaa/` and
`tools/testing/selftests/xdev_ext_mech/iaa_transform/` under the kernel tree.
The latter exercises the actual adapter at a controlled CryptoAPI boundary;
its explicitly selected software backend does not establish physical IAA DMA
or performance. Hardware execution and attribution require the device/provider
prerequisites described by the syscall gate.
