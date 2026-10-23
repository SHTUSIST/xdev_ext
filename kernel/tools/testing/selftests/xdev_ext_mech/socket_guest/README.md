# Independent socket mechanism verification

`make runtime check` compiles the guest runtime and independent CE BPF observer,
then executes verbatim production socket adapter functions in a host fixture.
The fixture uses actual IPv4 and IPv6 loopback UDP peers (257 datagrams each,
eight request slots), actual production span validation/completion decisions,
and explicit socket-state/worker/custody stubs. Four unsafe production mutations
must fail the behavioral assertions. These host results do not prove kernel
file ownership, BPF verifier acceptance, DMA, VM execution, or physical GPU I/O.

The CREATE admission test executes the current production validation path
and checks that the four-frame socket layout is accepted:

```sh
python3 independent_class7_admission.py
```

The guest fixture requires a private target-kernel VM with the existing
`nxp_nvme_ops` BPF attached using `nvme_mode=0` and its default `key_base=1`, and the main
harness's SHAKE-generated source image containing at least 257 distinct
8192-byte groups starting at `source_slba`. It opens both NVMe source handles
read-only, snapshots and compares the **entire** source block device, and never
writes any source span or disk. It rejects periodic/repeated source groups.

Place the following command after the provider/IAA guest campaigns have
unloaded their CE module and before the main harness loads CE. The main
harness resolves `source_ng` and `source_block` by the unique `UBRZCSRC01`
serial; pass the generic namespace before the block namespace:

```sh
sh /opt/xdev_ext/socket_guest/run-guest.sh \
  /opt/xdev_ext/socket_guest /opt/xdev_ext/xdev_ext_ce_sim.ko \
  /opt/xdev_ext/socket_sink.bpf.o "$source_slba" "$source_ng" "$source_block"
```

The guest starts keys 1 through 257, which the NVMe program maps to source
groups 0 through 256. The CE observer records those zero-based source indices.
`key_contract_test.py` executes the actual NVMe and CE BPF build functions
against the runtime's configured first key and checks all 257 source addresses,
four spans and eight slots before the VM run.

The guest runtime loads its own CE observer and the production socket BPF;
the shell loads/unloads a fresh CE CPU simulation module, preserving the main
campaign's zero-counter baseline. The runtime submits exactly one START for
NVMe READ → CE TO → CE FROM → SOCKET, 257 groups at depth eight. Its receiver
thread compares each complete datagram against the actual source snapshot.
It verifies all four native stage counters, 514 CE accepts/completions with no
pending operation, all eight CE slots and their final source contents, all
pool/window guards, 32 returned frame loans, STOP and CE reference release.
Closing the caller's socket fd immediately after CREATE also exercises the
core's retained file reference in the guest. STATS polling only observes
progress; it never submits or pumps another batch.

The actual guest output must be recorded before claiming the VM passes.
A local successful runtime/BPF compilation is not guest execution. CPU CE
simulation and socket native copying remain explicit; local UDP completion
never certifies remote delivery or a remote protocol ACK.

NIC fallback uses the existing NXP2 UDP wire format and configured peer tuple.
The plain SOCKET class remains available with zero flags and arguments. AUTO
and forced NIC substitution select `XDEV_EXT_SOCKET_F_NXP`, the existing
`--wire-session` value and interface MTU. Reliable NXP3 is refused. The finite
NXP2 path requires ordered groups/segments, discards foreign/duplicate/out-of-order
packets and never publishes a partial or CRC-invalid group. It provides no
retransmission or remote delivery guarantee.

`../socket_sink/nxp_interop_test.py` executes production socket adapter and BPF
functions with real UDP sockets against the AF_XDP reference wire encoder/parser.
It checks exact bytes, distinct groups, CRC, malformed and forged plans, a reader
race, truncation, STOP, accepted TX-prefix preservation, and bounded allocation.
`../socket_sink/ctl_socket_test.py` checks rejection of wrong source IP and port.
These are host boundary tests, not AF_XDP hook or kernel verifier execution.

The existing NIC fallback guest section now also checks both mixed directions.
It uses the guest's existing loopback interface at MTU 1500 to obtain a real AUTO
zero-copy refusal, while data traverses the existing eth0/eth1 pair. Only the
socket side is assigned its IP address, and socket TX uses a static peer neighbor,
so local routing cannot bypass the opposite AF_XDP endpoint. Each direction
requires the full destination byte comparison and its own AUTO_INTEROP marker.
The guest must be run before reporting those markers as observed results.
