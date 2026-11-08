# DPDK net_af_xdp baseline over thunderbolt-net (E4)

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

GPU memory to GPU memory messages between two hosts through DPDK. This
directory contains code only. It holds no measurement, and timings from a VM
are not performance data.

## Why net_af_xdp

thunderbolt-net has no DPDK poll-mode driver. The only DPDK port that works on
it is `net_af_xdp`, which opens an AF_XDP socket on the kernel interface.
thunderbolt-net has no `ndo_bpf`, so XDP can only run there in generic (skb)
mode, and the socket binds in copy mode. The interface also has a single
queue. Every record says what actually happened (`xdp_attach_mode`,
`xsk_zerocopy`) instead of assuming it.

The PMD's default XDP program cannot attach to such a device when DPDK is
built against libxdp. The PMD passes only `XDP_FLAGS_UPDATE_IF_NOEXIST`
(DPDK 24.11.8 `rte_eth_af_xdp.c`), and libxdp v1.6.2 turns "no mode flag"
into native mode (`lib/libxdp/xsk.c`, `xsk_convert_xdp_flags`). The kernel
then refuses with "Underlying driver does not support XDP in native mode".
This was observed in a guest on e1000, which also has no `ndo_bpf`. The
documented PMD option `xdp_prog=` takes the other path: the PMD attaches the
given object with libbpf's `bpf_xdp_attach` and the same single flag, and
the kernel picks generic mode by itself. `tb_xsk_redirect.bpf.c` is that
object. It behaves like libxdp's default program: a 64-entry XSKMAP named
`xsks_map`, each frame redirected to the socket of its RX queue or passed to
the kernel when none is bound. So on thunderbolt-net the vdev carries
`xdp_prog=`; on a NIC with native XDP it does not.

## What runs

| Piece | File |
| --- | --- |
| program (client and server) | `dpdk_tb.c` |
| GPU backend round-trip check | `test_gpu_backend.c` |
| XDP redirect program for devices without native XDP | `tb_xsk_redirect.bpf.c` |
| frame format, fragmentation, reassembly, window, arguments | `tb_wire.h` (checked by `test_wire.c`) |
| GPU copies: CUDA runtime | `tb_gpu_cuda.c` |
| GPU copies: host-memory stand-in, no GPU, correctness only | `tb_gpu_host.c` |
| DPDK fetch and build, program link | `build.py` |
| 2 MiB hugepages and hugetlbfs | `hugepages.sh` |
| functional check in one QEMU/KVM guest | `vm_check.sh` |

- **Send path.** `cudaMemcpyAsync` device to a `cudaHostRegister`-ed staging
  buffer, then `cudaStreamSynchronize`. The message is cut into frames that
  fit the port MTU, each frame's payload is copied into a DPDK mbuf, and the
  mbufs go out with `rte_eth_tx_burst`.
- **Receive path.** `rte_eth_rx_burst` returns mbufs. Their payloads are copied
  in order into a registered staging buffer, and once the message is complete
  one `cudaMemcpyAsync` host to device follows, then `cudaStreamSynchronize`.
- **Frame.** An Ethernet header with EtherType 0x88B5 (IEEE local
  experimental), a 32-byte header (type, flags, payload length, sequence,
  message id, message length, offset, aux, run id), then the payload. At the
  default MTU of 1500 a frame carries 1468 payload bytes, so a 4 MiB message
  is 2858 frames.
- **Flow control.** At most `--window-frames` (1024) frames may be
  unacknowledged. The receiver sends a cumulative ACK every `--ack-every`
  (256) frames, and also when a message's last frame asks for one; that ACK
  goes out after the message is in GPU memory. The window is smaller than
  the af_xdp PMD's 2048-entry RX ring, so a receiver that keeps polling never
  overflows it.
- **No retransmission.** A lost, repeated or inconsistent frame, or no
  progress for `--timeout-ms`, ends the run with exit status 1 and the frame
  counters. Every record therefore comes from a run without loss.
- **Defaults.** EAL `--vdev net_af_xdp0,iface=IF,start_queue=0,queue_count=1`,
  plus `xdp_prog=` only where the device has no native XDP (see above), and
  no other PMD option (no `force_copy` or `busy_budget`).
  `struct rte_eth_conf` is all zero, the RX and TX rings take the PMD default
  (0 descriptors requested), the mbuf pool uses `RTE_MBUF_DEFAULT_BUF_SIZE`,
  there is one lcore, and the burst size is 32. The program never sets the
  MTU; it uses the smaller of DPDK's and the interface's value. The CUDA
  runtime runs with its defaults on a single stream.
  `dpdk_max_mtu` records `rte_eth_dev_info.max_mtu` separately from the current
  `dpdk_mtu`, `netdev_mtu` and selected `mtu`. Zero is retained when the PMD
  does not advertise a limit; no larger usable MTU is inferred or selected.

## Measurements the program reports

- `--mode pingpong` (client): one-way latency is half the round trip. The
  round trip is timed from the start of the client's device-to-host copy to
  the end of the client's host-to-device copy of the echo, so it contains
  the copies on both GPUs. The client reports min, p50, p99 (nearest rank),
  mean and max over `--iters` messages per size, after `--warmup` messages
  that are verified byte for byte and not timed.
- `--mode stream` (client): bandwidth is bytes divided by the time from the
  first device-to-host copy until the server's ACK says the last message is
  in its GPU memory. Each size sends at least `--iters` messages and at least
  `--stream-min-bytes` (256 MiB) bytes.
- Sizes default to 64 B to 4 MiB, doubling. One JSON line per size on stdout;
  the server prints a summary line.
- `--verify all` checks every message, and the record then says
  `"timed_includes_verify": true`. Use it for correctness runs only.
  Streaming checks run on the receiver after the host-to-device copy, by
  reading device memory back and checking the message-id pattern before
  its completion ACK. The client's `verified_messages` counts those requested
  validations in the completed run. With the default `--verify warmup`, only
  warmup messages are validated, so the count does not certify timed payloads.

## Build

DPDK 24.11.8 (LTS) from https://fast.dpdk.org/rel/dpdk-24.11.8.tar.xz,
SHA-256 `f3dbfac841b2db8e53a97d68a5e14ebc943327a955f0afb97f8c14f544fbc4aa`.
net_af_xdp needs libxdp >= 1.2.2 and libbpf (the release's
`doc/guides/nics/af_xdp.rst`). The build also needs meson, ninja,
pyelftools, pkg-config, and clang with the libbpf headers for
`tb_xsk_redirect.o`, which lands next to the program in the build
directory.

```sh
python3 tests/eval/dpdk_tb/build.py --build-dir /abs/dir --gpu cuda --cuda-root /usr/local/cuda
python3 tests/eval/dpdk_tb/build.py --build-dir /abs/dir --gpu none      # VM stand-in
python3 tests/eval/dpdk_tb/build.py --build-dir /abs/dir --print-commands
```

## Run on the two-host Thunderbolt testbed

First check the CUDA side alone on each host (registered staging buffers,
copies of every size, byte comparison):

```sh
cc -std=gnu11 -O2 -Itests/eval/dpdk_tb tests/eval/dpdk_tb/test_gpu_backend.c \
   tests/eval/dpdk_tb/tb_gpu_cuda.c -I/usr/local/cuda/include \
   -L/usr/local/cuda/lib64 -lcudart -o /abs/dir/test_gpu_backend && /abs/dir/test_gpu_backend
```

Then, on both hosts, as root:

```sh
tests/eval/dpdk_tb/hugepages.sh            # 512 x 2 MiB at /dev/hugepages-tb
EAL="-l 2 --no-pci --huge-dir /dev/hugepages-tb --vdev net_af_xdp0,iface=thunderbolt0,start_queue=0,queue_count=1,xdp_prog=/abs/dir/tb_xsk_redirect.o"
host1$ /abs/dir/dpdk_tb $EAL -- --role server
host2$ /abs/dir/dpdk_tb $EAL -- --role client --mode pingpong > pingpong.jsonl
host1$ /abs/dir/dpdk_tb $EAL -- --role server
host2$ /abs/dir/dpdk_tb $EAL -- --role client --mode stream > stream.jsonl
```

The server serves one client session and exits after it. The client finds
the server with a broadcast HELLO; pass `--peer-mac` to skip that step. The
interface must be up, and thunderbolt0 has a single queue, so no ethtool
step is needed. Use the same EAL core list for every arm that is compared.

## Functional check without the testbed

`vm_check.sh --work DIR --bin B/dpdk_tb-host --xdp-prog B/tb_xsk_redirect.o`
boots one KVM guest and runs
client and server over a veth pair (XDP in native mode) and over two
emulated e1000 NICs joined by a QEMU hub (e1000 has no XDP support, so XDP
attaches in generic mode, as on thunderbolt-net, and the PMD gets
`xdp_prog=`). Each link
gets a pingpong run and a stream run, both with `--verify all`. It writes
`DIR/verdict.json`. It checks correctness only.

## Host checks

`make -C tests/eval dpdk-tb-check` (part of `reviewer-eval-check`) runs
`test_contract.py`. That covers framing, reassembly, the window, argument
handling, the build and hugepage plans, and the program's default settings.
It needs no DPDK, NIC or GPU.

The same target runs `test_program.py`, which compiles the actual
`client_stream`, `message_done`, port setup and record code with ASan/UBSan.
GPU copies, transport and DPDK port APIs are host boundaries; the real wire
reassembly and pattern checks still execute. Tests reject a damaged timed
message under `--verify all`, confirm warmup-only reporting and check that
the advertised maximum MTU is recorded without changing the selected MTU.
This is host correctness evidence, not an AF_XDP, GPU or PMD execution.
