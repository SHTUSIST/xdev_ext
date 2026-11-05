# Host-page requester mapping

This host test compiles the production requester unit
`src/core/io_uring/family/xdev_ext_requester.c` without changes and checks what
it does when an XDOMAIN stage binds its NHI to the ring's IOU_UMEM pool
(obligation 42-XDOMAIN-HOST).

```sh
python3 tests/core/requester_host/run.py --source-root "$SOURCE_ROOT" --output "$OUT"
python3 tests/core/requester_host/run.py --source-root "$SOURCE_ROOT" --output "$OUT-asan" --sanitize
python3 tests/core/requester_host/run.py --source-root "$SOURCE_ROOT" --output "$OUT-m" --mutation NAME
```

Exit 0 means every case passed with a positive assertion count, or that the
mutant was killed by a named `REQUESTER_HOST_ASSERT`. Exit 1 is a behaviour
failure or a surviving mutant, and exit 2 is a setup or compile error.

## What runs and what stands in

The requester unit is real. `shim.h` declares the kernel types it uses, and
`boundary.c` records each DMA API call (map, unmap, sync for the device, sync
for the CPU) and PCI reference. It gives every device its own address window
with pages at reversed positions, so a test never relies on two pages being
contiguous. `dma_need_sync()` answers as dma-direct does: true for a
non-coherent device or a forced bounce buffer. The PEER provider calls
(describe, premap) are stand-ins that report a BAR owner, so the unchanged
PEER path can run as a regression case.

## Cases

| Case | Requirement |
| --- | --- |
| `host_bind_maps_every_page` | the PEER bind (`xdev_ext_requester_bind()`) still refuses an IOU_UMEM pool; the host bind (`xdev_ext_requester_bind_host()`) binds the NHI and maps every pool page once in the stage direction, without CPU sync; the stage reports host RAM reached through a DMA-API mapping; `xdev_ext_requester_unbind_host()` returns every reference |
| `host_bind_rx_maps_from_device` | an RX stage maps for `DMA_FROM_DEVICE` |
| `host_bind_refuses_misaligned_pool` | a pool that does not start on a page boundary is refused with `-EINVAL` before any mapping (a 4 KiB NHI element would span two pages) |
| `host_bind_refuses_partial_page` | a pool whose last page is only partly inside it is refused with `-EINVAL` |
| `host_bind_map_error_unwinds` | a mapping error unmaps exactly the pages already mapped and keeps no reference |
| `host_lease_page_address` | an element gets its own page's address plus its offset; a full 4096-byte element is allowed, because the data ring carries payload only and headers travel on the control ring |
| `host_lease_refuses_spans` | `-ERANGE` for an element that crosses a page or frame boundary, leaves the pool or is empty; `-EACCES` against the mapping direction; the host bind refuses a PEER pool, and a host lease on a PEER requester is `-EINVAL` |
| `host_noncoherent_sync` | a non-coherent or bounced NHI gets one sync for the device per lease, covering exactly the element, and an RX buffer gets one sync for the CPU after a definite end; a TX end needs none |
| `host_coherent_no_sync` | a coherent, unbounced NHI gets no sync calls |
| `host_unknown_retains_mapping` | after an element ends with unknown device access, no CPU sync, no new lease (`-ESTALE`), the stage is not settled, and unbind never unmaps; the mapping keeps its NHI reference |
| `host_outstanding_lease_retains_mapping` | an unbind with an outstanding lease keeps the whole mapping |
| `host_quiesced_unbind_unmaps_once` | once every lease ended quiesced, unbind unmaps each page exactly once with the mapping's size and direction |
| `peer_bind_unchanged` | a PEER pool still describes and premaps, and the requester maps nothing itself |
| `host_create_report` | the CREATE report names the NHI and records the decision, without a provider description |

## Mutations

Each mutant edits one line group of a private copy of the requester unit so
that one requirement above becomes false, then runs the case that must catch
it. A mutant counts as killed only with exit 1 and a named assertion.

| Mutant | Change | Caught by |
| --- | --- | --- |
| `accept-misaligned-pool` | the page-alignment check of the pool is removed | `host_bind_refuses_misaligned_pool` |
| `accept-partial-page` | the whole-page check of the pool end is removed | `host_bind_refuses_partial_page` |
| `map-error-keeps-pages` | a mapping error no longer unmaps the pages already mapped | `host_bind_map_error_unwinds` |
| `lease-first-page` | every lease uses page 0's address | `host_lease_page_address` |
| `lease-crosses-page` | a lease may cross a page boundary | `host_lease_refuses_spans` |
| `lease-crosses-frame` | a lease may cross a frame boundary | `host_lease_refuses_spans` |
| `no-sync-for-device` | a lease no longer syncs for the device | `host_noncoherent_sync` |
| `no-sync-for-cpu` | a definite RX end no longer syncs for the CPU | `host_noncoherent_sync` |
| `sync-coherent-too` | a lease syncs even when the mapping needs no sync | `host_coherent_no_sync` |
| `lease-after-unknown` | a mapping with unknown device access still leases | `host_unknown_retains_mapping` |
| `unmap-after-unknown` | unbind unmaps after an unknown end | `host_unknown_retains_mapping` |
| `unmap-outstanding-lease` | unbind unmaps with a lease outstanding | `host_outstanding_lease_retains_mapping` |
| `peer-bind-takes-host-pool` | the PEER bind maps an IOU_UMEM pool itself, through the host bind | `host_bind_maps_every_page` |
| `host-bind-takes-peer-pool` | the host bind accepts a PEER pool | `host_lease_refuses_spans` |

## Limits

This is host software only. It does not exercise a real IOMMU, swiotlb or
cache maintenance, the NHI or the kernel.
