# AF_XDP and GPU copy-engine samples

These userspace frontends use the canonical NVIDIA implementation in
`gpu/kernel-open` and the ioctl definitions in
`kernel/tools/include/xdev_ext_nv_p2p_ioctl.h`. This directory contains no
NVIDIA kernel driver overlay.

The CUDA sample shares packet data through registered host AF_XDP UMEM and
copies between that UMEM and a CUDA allocation using the GPU copy engine.
It avoids CPU payload copying on the CE path and includes host↔VRAM DMA.
It does not implement direct NIC-to-VRAM peer DMA.

Build from the repository's `kernel/` directory after source preparation:

```sh
make -f Makefile.pipeline gpu-nic-host
make -f Makefile.pipeline gpu-nic CUDA_HOME=/usr/local/cuda
```

The host target requires libxdp and libbpf development files. It produces
`gpu_xdp_p2p_nocuda`, which processes packets through CPU staging and never
opens or allocates a GPU. Its `-g` option is accepted only for compatibility.
The CUDA target also requires the CUDA toolkit and `nvcc`, and produces
`gpu_xdp_p2p`. CE operation requires the matching NVIDIA driver built with
`XDEV_EXT_ENABLE_GPU_CE_DMA=1` and loaded with `NVreg_EnableXdevExtCeDma=1`.
The selected CUDA GPU and opened GPU device must identify the same PCI GPU.

The CUDA executable selects one of these modes with `-m`:

| Mode | Data route |
|---|---|
| `roundtrip` | AF_XDP RX → host UMEM → GPU CE/CUDA processing → host UMEM → AF_XDP TX |
| `nic-to-gpu` | AF_XDP RX → host UMEM → GPU CE/CUDA processing; no packet TX |
| `gpu-to-nic` | CUDA-produced packets → GPU CE → host UMEM → AF_XDP TX |

`roundtrip` is the default. The host executable implements only the
CPU-staging roundtrip; it does not accept `-m`. Use `-i` for the network
interface, `-q` for its queue, and CUDA `-g` for the visible CUDA ordinal.
`-s` explicitly permits CUDA staging if CE registration is unavailable.
Check the transfer counters to distinguish CE and CUDA-staging execution.

`-A/-a/-P/-p` select source IPv4, destination IPv4, source UDP port and
destination UDP port respectively. Defaults are `192.0.2.1`, `192.0.2.2`,
`54321` and `12345`. Receive modes install a private exact-flow redirect for
untagged, unfragmented IPv4/UDP packets beginning with the four payload bytes
`55 42 52 47` (`UBRG`); other traffic remains in the host stack. They refuse
to replace an existing incompatible XDP program. Source mode uses these
options for its generated packet headers and does not attach an ingress redirect.

`-S/-D` set source and destination Ethernet addresses and are both required
by `gpu-to-nic`. For example:

```sh
./gpu_xdp_p2p -i eth0 -q 0 -g 0 -m gpu-to-nic \
  -A 192.0.2.1 -a 192.0.2.2 -P 54321 -p 12345 \
  -S 02:00:00:00:00:01 -D 02:00:00:00:00:02
```

The executable needs authority to configure AF_XDP and its private XDP
redirect and to access the selected GPU. Run `-h` for the current CLI.
On shutdown it drains outstanding TX and removes its own redirect before
releasing UMEM. If ownership cannot be proved safe, it retains backing
resources instead of recycling them. Local TX completion does not establish
remote delivery or acknowledgement.
