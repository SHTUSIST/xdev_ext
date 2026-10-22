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
unloaded their CE module and before the main harness loads CE:

```sh
sh /opt/xdev_ext/socket_guest/run-guest.sh \
  /opt/xdev_ext/socket_guest /opt/xdev_ext/xdev_ext_ce_sim.ko \
  /opt/xdev_ext/socket_sink.bpf.o "$source_slba"
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
