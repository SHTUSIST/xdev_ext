# Paths and requirements

The table describes interface routes and their requirements. Source availability and a successful build do not establish execution on a particular physical device. Check the selected test's [evidence scope](testing.md) separately.

| Path | Memory route | Requirements and limits |
|---|---|---|
| NVMe mechanism | Registered pool ↔ native NVMe I/O | Matching kernel, namespace access, admitted LBA window, alignment and descriptor limits; strict SGL mode requires controller data-SGL support |
| AF_XDP mechanism | Registered XSK pool ↔ network | Bound AF_XDP socket, matching queue/UMEM layout and program; copy and driver zero-copy modes have different requirements |
| GPU copy engine | Registered host pool ↔ GPU window | Matching NVIDIA provider and driver stack, authorized GPU window and supported DMA mappings |
| Registered DMA provider | Shared host pool ↔ provider window | A provider implementing bind, mapping, submit, synchronization and exact completion |
| IAA transform | Input lease → separate output lease | CryptoAPI asynchronous compression provider; actual produced length is propagated; software deflate is a functional-test option |
| Connected UDP sink | Registered pool → ordinary socket send | Connected IPv4/IPv6 UDP, one batch per datagram, bounded payload; local completion does not mean remote receipt |
| Peer allocation | Device allocation ↔ admitted native device request | Allocation fd, generation, mapping support, compatible device topology and provider; no fabricated host pages |

## Host staging and peer memory

A pipeline through shared host UMEM and GPU copy engines includes host↔VRAM DMA. It can avoid CPU payload copying at supported boundaries without becoming NIC-to-VRAM or NVMe-to-VRAM peer DMA. A peer allocation instead carries device-memory authority and must be mapped by the actual consuming device. A provider or direction that cannot satisfy this contract must reject it.

Native NIC peer transmit requires separate CPU-visible headers and a supported device-memory payload mapping. Receive requires its own supported header/payload and ownership contract; transmit support does not imply receive support. Physical GPU/NIC/NVMe combinations remain subject to PCIe reachability, driver capability and mapping constraints.

## Compatibility frontend

The opt-in preload frontend targets supported dynamically linked libc calls. Positional file I/O requires an explicitly allowed path, `O_DIRECT`, suitable reported alignment, and a request that fits the registered frame. Ordinary `read`/`write` retain their shared-file-position semantics through libc. This interface does not cover every binary or every database I/O API.

The mechanism socket frontend admits a limited connected UDP call shape. Unsupported call shapes or setup failures before publication can use libc fallback. An accepted request must reach its own terminal outcome without fallback replay. Native socket sending includes payload copies and provides local send completion rather than protocol ACK.

## Transforms and fixed-size stages

IAA produces an actual output length into an independent bounded destination. Capacity is not payload length. A stage whose format requires the original fixed group size rejects a transformed group of a different length; a compression/decompression pair can restore that size before such a stage.

For exact structures and flags, use the [session API reference](reference/session-api.md) and the linked source headers.
