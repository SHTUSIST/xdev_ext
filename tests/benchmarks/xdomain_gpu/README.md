# E4: VRAM to VRAM over one Thunderbolt/USB4 cable

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes,
comparison eligibility and performance claims.

These tools measure GPU memory to GPU memory transfers between two hosts
joined by one Thunderbolt/USB4 cable, for a GPU without GPUDirect RDMA (RTX
5090). Each tool has a ping-pong mode (half round-trip time per message size,
64 B to 4 MiB) and, except NCCL, a streaming mode (bandwidth of verified
unique bytes, timed on the receiver's clock). Nothing here has run on two
hosts. The host checks below exercise options, protocol and verification
only; their numbers are not results.

| Arm | Program | Path of one message |
| --- | --- | --- |
| `xdev-ext` | `xdomain_gpu` | copy engine VRAM to host frame, XDOMAIN session over the NHI, host frame to VRAM by the copy engine; no CPU payload copy |
| `tcp-cuda` | `tcp_cuda` | synchronous D2H copy into a `cudaHostAlloc`-type pinned buffer, `send()` over thunderbolt-net, `recv()`, synchronous H2D copy |
| `nccl` | `nccl_pingpong` | `ncclSend`/`ncclRecv` with NCCL defaults over NET/Socket |
| `nccl` bandwidth | `nccl_tests.py` | nccl-tests `sendrecv_perf -b 64 -e 4M -f 2 -g 1` |

The baselines use ordinary settings: kernel default sysctls, the
interface's default MTU, one TCP connection with `TCP_NODELAY` (recorded;
`--no-nodelay` turns it off), NCCL defaults with only `NCCL_SOCKET_IFNAME`
and `NCCL_DEBUG=INFO` set. `tcp_cuda` and `nccl_pingpong` open the CUDA
driver (`libcuda.so.1`) and NCCL (`libnccl.so.2`) at run time and call the
driver API equivalents of `cudaHostAlloc` and `cudaMemcpy`.

## Files

- `xdg_core.h`: size grid, split of a message into XDOMAIN groups (at most
  64 NHI frames of 4 KiB, so 256 KiB, per batch), slot payload, slot
  oracle and latency statistics; `test_xdg_core.c` checks it.
- `xdg_net.h`: control and data TCP connection, configuration check, barrier.
- `xdg_gpu.h`: device and pinned host memory through the CUDA driver API,
  or host memory with `--fake-gpu` (host checks only).
- `xdomain_gpu.c`, `tcp_cuda.c`, `nccl_pingpong.c`: the three programs.
- `nccl_tests.py`: runs `sendrecv_perf` and accepts the run only when every
  channel used NET/Socket and every row's two `#wrong` columns contain numeric
  zero. `N/A` means validation is missing and the run is rejected.
- `run.py`: rank-local runner; both hosts run the same arms in an order
  rotated per pair, optionally under `link_check.py`.

## xdev-ext sessions

Per message size each rank creates two sessions on the ring's XDEV_EXT UMEM:
TX `[CE D2H, XDOMAIN TX]` and RX `[XDOMAIN RX, CE H2D]`. Both CE stages run
in slot mode (`ce_plan_ops` from `examples/compute/ce_plan.bpf.c` attached as
the CE class program), each on its own CE file and CUDA VMM allocation
attached with `xdev_ext_nv_ce_attach_memory()`; the XDOMAIN class default
program (`examples/network/xdomain_peer.bpf.c`) must be attached. Ping-pong
uses depth and window equal to the groups of one message; streaming keeps
`--window` groups (32) in flight. After each size every RX slot must hold a
whole, distinct image of a sender slot and every image must appear; a
multi-group message lands in a permutation of the batch slots, which the
oracle accepts.

RX VRAM is poisoned again before each size, before any timed work or START.
The xdev-ext oracle validates the retained final window, not overwritten
message history: `verification_scope` is `final-window`, and streaming
`verified_bytes` is the checked window size (zero on failure).
`transferred_bytes` counts the logical payload covered by completed batches;
`gbps` uses that transfer count and the existing elapsed span. Neither field
certifies that every overwritten message was byte-checked. The TCP and NCCL
arms retain their existing validation and timing contracts.

`test_runtime.py` compiles the production xdev-ext orchestration and JSON
reporting with ASan/UBSan, replacing only CUDA memory operations, session
completion and the control peer. It checks stale data across successive
sizes, poison failures and final-window accounting. This host test supplies
no GPU, CE, Thunderbolt or throughput evidence.

Session close returning zero invalidates its handle. A failed close preserves
the handle for retry, even when the retained flag is false (`-EAGAIN`). Final
cleanup keeps that direction's borrowed CE fd and CUDA window while its
session remains live, and keeps the shared control fd until both directions
close. Cleanup errors still make the process fail. CUDA close errors preserve
the helper's remaining window state for retry. `test_session_cleanup.py` runs
the actual libxdev_ext allocation/close/free path with ASan/UBSan, substituting
only kernel registration and CUDA entry points; it establishes host ownership
behavior and supplies no device or DMA evidence.

The `[CE D2H, XDOMAIN TX]` CREATE has not been run (TODO.74); the CE class
admission rule applies only the file check to a CE stage without the target
range flag. A refused CREATE exits 4 with the kernel's CREATE report.

## Commands

```sh
make -C tests/eval/xdomain_gpu check                  # host checks, no device
make -C tests/eval/xdomain_gpu tools xdomain BUILD=$B # programs
# on both hosts, rank 1 first:
python3 tests/eval/xdomain_gpu/run.py --rank 1 --addr $RANK1_IP:24600 \
  --arms xdev-ext,tcp-cuda,nccl --pairs 5 --bin-dir $B --out $OUT \
  --link-check '--xdomain auto --netdev thunderbolt0 --pci $GPU_BDF=gpu' \
  --xdev-args '--gpu-bdf $GPU_BDF --ce-dev /dev/nvidia0 --service $SERVICE' \
  -- --sizes 64,256,4096,65536,1048576,4194304
python3 tests/eval/xdomain_gpu/nccl_tests.py --binary $NCCL_TESTS/sendrecv_perf \
  --ifname thunderbolt0 --launcher 'mpirun -np 2 -H host1,host2' --out nccl.json
```

The data connection of `tcp_cuda` and the control connection of the other
two programs use `--addr`; give the thunderbolt-net address of rank 1 so the
TCP baseline crosses the cable.
