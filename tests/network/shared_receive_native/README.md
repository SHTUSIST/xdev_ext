# Shared receive generated XDP native acceptance

This test uses the frozen shared AF_XDP dispatcher contract and its two public
headers. It compiles and links the actual canonical exported builder, creates
real kernel XSKMAP/HASH maps, calls `xdev_ext_xsk_shared_build_program`, loads the
exact generated instructions as XDP, then calls `bpf_prog_test_run_opts` on 37
literal PASS-path packet/flow cases. It does not interpret instructions or load
a replacement program. Candidate builder implementations and old test
expectations were not read to derive the packets or expected actions.

Build from this test checkout with explicit candidate and modern libbpf roots:

```sh
python3 tests/network/shared_receive_native/build.py \
  --candidate-root /absolute/candidate-checkout \
  --libbpf-build /absolute/modern-libbpf \
  --output /absolute/NEW_BUILD_DIR
```

`--libbpf-build` contains `include/bpf` and `libbpf.a`; use `--libbpf-archive`
when the archive is elsewhere. Optional `LDFLAGS='-static -lzstd'` supports a
static guest executable when those dependencies are available. GCC compiles
canonical `src/cli/xdev_ext_xsk_shared.c` with function/data sections and linker
GC, retaining the real exported builder without invoking the shared manager.
There is no copied source view and no clang dependency for generated insns.
The build entrypoint runs only `--selfcheck`, never native BPF. Its JSON/logs
record the exact command, header/test inputs and produced binary. Root records
candidate implementation and kernel source identities separately.

The pure output-oracle selfcheck requires literal XDP_PASS(2), unchanged complete
bytes and exact length; four wrong actions, two wrong lengths and three changed
byte positions must all be rejected. It proves this result checker only.

Root alone copies the binary into an independent correctness KVM guest and runs:

```sh
/opt/shared-xdp-native --private-guest --output /absolute/NEW_CAPTURE_DIR
```

The flag, root and fresh absolute output directory are mandatory. No interface
attachment, bpffs pin, ethtool call, socket creation/binding, network namespace
change or native host device operation is performed. The maps/program are
unattached local objects and only their owned FDs are closed. Root supplies an
outer guest timeout and exports the raw console, exact kernel/config/source,
command/exit status and complete capture directory. A prerequisite/map creation
failure is SETUP_ERROR/exit 2. Builder/load/test-run or assertion failure is
BEHAVIOR_RED/exit 1; neither is a successful negative case.

The XSKMAP is empty by construction: the test creates it fresh and performs
zero XSKMAP updates. Every flow-bearing case updates the actual HASH map and
reads the complete value back, checks exactly its key exists, then deletes it
and proves the HASH is empty. Complete input/output packets must match exactly
and every actual test-run retval must be XDP_PASS(2).

The frozen literal 60-byte golden frame and variants are in `packets.h`. It uses
IPv4 192.0.2.1:12345→198.51.100.2:31337, first UDP payload u32 0x12345678 encoded
as network bytes 12 34 56 78. Cases cover empty flow, missing XSK, three other-flow
keys, wrong queue, truncated/non-IP/tagged/options/fragment/non-UDP/invalid-length
packets, a coherent three-byte UDP payload, optional source IP/port/MAC/max-length
match/miss inputs, all optional fields, and literal zero key fields. RX queue is
0; wrong-queue case records flow queue 1, avoiding an invented nonzero device
queue. Native test-run frames start at 14 bytes because shorter packets may be
rejected by the kernel test-run entrypoint before reaching XDP.

Positive REDIRECT is `NOT_RUN_NO_BOUND_XSK`. Optional-filter and zero-literal
selectivity is `NOT_OBSERVABLE_WITHOUT_BOUND_XSK`: matching and rejected packets
both ultimately PASS when XSK is absent, so these cases do not prove filtering
selectivity. No AF_XDP delivery, shared manager lifecycle/pins/ntuple ownership,
DMA, zero-copy, physical hardware, or performance result is claimed.

Capture retains exact generated instructions, complete successful/failing
verifier text, actual map/program info and program map IDs; per-case raw key,
configured/readback flow, input/output packets, input/output XDP context and raw
returned libbpf test-run options; events and scoped result JSON. Kernel-returned
raw options may contain incidental duration; it is retained as raw evidence,
never aggregated or interpreted as a performance result. Root independently
checks the raw actions/bytes and registers the scoped result under
`/root/xdev_ext/test-results/`; a build or selfcheck is never native acceptance.
