# System-heap DMA-BUF as an XDOMAIN frame source

This host test answers one question: can a system-heap DMA-BUF, registered
through `/dev/xdev_ext_peer` and bound as a PEER frame pool, serve as the frame
memory of an XDOMAIN stage whose requester is the Thunderbolt host controller
(NHI)? The XDOMAIN class accepts only PEER pools
(`src/network/io_uring/xdomain/xdev_ext_xdomain_class.c`, bind) and hands the
NHI function to `xdev_ext_requester_bind()` through the network family attach.
This test runs that requester bind and everything below it.

```sh
python3 tests/network/xdomain/dmabuf_requester/run.py \
  --source-root "$SOURCE_ROOT" --output "$PRIVATE_RESULTS" [--sanitize]
python3 tests/network/xdomain/dmabuf_requester/run.py \
  --source-root "$SOURCE_ROOT" --output "$PRIVATE_RESULTS" --mutation NAME
```

The runner returns 0 when every selected case passes, 1 for a behaviour
failure (or a surviving mutation), and 2 for setup or compile errors. A case
passes only with exit 0 and a positive assertion count.

## What is real and what is a stand-in

Compiled unchanged from the selected source root: the requester bind, unbind
and lease split (`src/core/io_uring/family/xdev_ext_requester.c`), the peer
region core (`xdev_ext_peer.c`), the DMA-BUF importer (`xdev_ext_peer_dmabuf.c`),
the whole peer fd unit including the REGISTER ioctl (`xdev_ext_peer_fd.c`), the
PEER pool bind (`xdev_ext_mech_peer_pool.c`) with the core ownership-word helper
it calls, and the system heap's describe hook and descriptor
(`src/core/drivers/dma-buf/heaps/system_heap.c`).

Stand-ins: kernel services and the DMA-BUF exporter come from
`tests/core/peer_dmabuf/kernel_shim.{h,c}`. The runner copies that header and
adds two declarations only (PCI bus number and devfn; ioctl members of
`file_operations`). The exporter's attach, pin and map are that shim's fake
attachment; its SG table is chosen per attachment by the test. A one-pool
session object stands in for the core session. The XDOMAIN class bind, its
link lookup and the NHI ring code are not compiled here; they run in the
XDOMAIN stack composition, where the requester bind is a recording stand-in
that rejects any device other than the endpoint's own NHI.

## Cases

| Case | Expected result |
| --- | --- |
| `nhi_admitted` | Bind succeeds for a trusted, coherent, unbounced NHI; backing host RAM with struct pages; no refusal; reachability "host DMA mapping established"; requester and CREATE report name the NHI; one exporter attachment, for the NHI; a lease resolves to the NHI attachment's address |
| `shared_pool` | NVMe (stage 0) and NHI (stage 1) bind the same pool; each lease uses its own device's attachment |
| `untrusted` | `-EXDEV`, no requester, no reference, no attachment left |
| `swiotlb` | Forced bounce buffering: `-EXDEV`, nothing left behind |
| `noncoherent` | `-EXDEV` with refusal bits "no P2P path" and "backing" |
| `need_sync` | A mapping that needs CPU synchronisation: `-EOPNOTSUPP` at premap |
| `unregistered_exporter` | REGISTER of an exporter without a describe hook: `-EOPNOTSUPP`, no fd |

Every case then closes the session's pool and the allocation fd and requires
the MEMLOCK and pinned-page charges, exporter attachments, pins, maps and
allocations to return to zero.

## Mutations

`--mutation` changes one production line in a private copy and runs the case
that must detect it: `admit-host-as-unknown` (requester ignores the described
backing), `skip-premap` (no mapping at bind), `accept-need-sync` (importer
accepts a mapping that needs CPU sync), `lease-first-mapping` (a lease uses
another device's attachment). KILLED requires exit 1 and a named
`DMABUF_REQ_ASSERT`.

## Limits

This is host software composition. It does not run a kernel, the NHI, DMA,
an IOMMU or a real exporter. Whether a given machine's NHI is trusted,
coherent and not bounced is a property of that machine; the cases show what
the code does in each of those situations.
