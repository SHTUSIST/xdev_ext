# Upstream BPF token and PRIVATE session selection

`token_guest` tests the real running kernel, upstream BPF token delegation,
libbpf load/attach and `CREATE_PROGRAMS` with the CPU family and IOU_UMEM.
It creates no virtual device and issues no physical DMA or performance test.
Run it only in a prepared guest. The test parent needs guest administrator
privileges to delegate BPF; each loader runs in a new user namespace, with no
capabilities in the parent's initial user namespace. It does not change sysctls.

Build with matching product UAPI and libbpf 1.6 (token path support):

```sh
make -C tests/core/program_instances/token \
  KERNEL_SRC=/path/to/canonical-or-native-source \
  LIBBPF_INCLUDE=/path/to/libbpf/include \
  LIBBPF_A=/path/to/libbpf/libbpf.a \
  CLANG=clang-14 OUT=/path/to/output
```

An uninstalled libbpf build may also need
`LIBBPF_HELPER_INCLUDE=/path/to/libbpf` for its generated `bpf_helper_defs.h`.
Use `LIBBPF_EXTRA_LIBS=-lzstd` when the selected libbpf build enables zstd;
the default adds no extra libraries. Use `LDFLAGS=-static` when packaging a static guest executable; otherwise copy
its runtime libraries into the guest. `KERNEL_SRC` accepts canonical and native
source layouts. BPF Clang is used solely for the three BPF bytecode objects.

Copy the executable and three `.bpf.o` files into the guest, then run:

```sh
/opt/token/token_guest --guest /opt/token
```

Success requires all five cases. The positive case first proves that the same
loader cannot load struct_ops without a token. Administrator delegation allows
only MAP_CREATE/BTF_LOAD/PROG_LOAD, ARRAY/STRUCT_OPS maps, SOCKET_FILTER/STRUCT_OPS
programs, and attach values 0/2/3/4. libbpf 1.6 first loads a trivial
SOCKET_FILTER with expected_attach_type=0 before loading the object. The extra
SOCKET_FILTER/0 permission admits that prerequisite; callback member indices
2/3/4 are prepare/build/complete. TRACEPOINT and blanket `any` are not delegated.
In struct_ops the
`expected_attach_type` is the BTF member index, not a generic attach enum.
The child cannot set delegation itself. The parent only configures detached
bpffs mounts created by each child's namespace; it never mounts over a host path.

Two separately loaded PRIVATE link fds are explicitly selected by
`CREATE_PROGRAMS.program_fds[0]`. CPU `stage.fd=-1` requires no device fd.
Independent PREPARE maps must progress from `(0,0)` to `(1,0)` then `(1,2)`.
A BPF program invoking `probe_read_kernel` must fail with its exact whitelist
diagnostic. Only `bad_helper.bpf.o` receives special instruction handling: its
original `token_prepare` must contain one correctly encoded helper113 call in a
bounded instruction array. After libbpf prepare, the same call must still be
helper113 or its known legacy helper4 fallback; an independent instruction copy
restores only that immediate to113, preserving all prepared relocations. The
loader logs the verified call index and helper IDs. Preparation, missing or
malformed helper and restoration errors remain failures; they cannot satisfy
the exact verifier diagnostic. No TRACEPOINT permission is added. Four additional children independently omit the program-load
command, STRUCT_OPS map type, program type or callback attach mask; each must
create a real token and receive a permission failure while loading the same
previously qualified object. The no-prog and no-attach cases retain the
SOCKET_FILTER/0 prerequisite, so they must reach the object permission being
tested. The no-command case removes token authority for every program load;
the final STRUCT_OPS load still requires the missing delegated command.

Exit 0 is a native assertion pass, 1 is an assertion failure, and 2 is setup
failure. Missing matching BTF/type, namespace support, user mappings, mount
context/delegation, libbpf support, io_uring or UMEM admission are setup failures.
No arguments exits 2 before any namespace operation. A mismatched object or an
unexpected verifier/attach failure cannot satisfy a permission negative.

BPF token authority does not authorize any GPU address, allocation, namespace,
network queue or device operation. GPU REGISTER still requires CAP_SYS_RAWIO.
The 0600 control-device fd may be explicitly delegated, but possession of that
fd does not bypass REGISTER's management gate. A successful REGISTER issues an
anonymous allocation fd sealing its validated region; passing that fd delegates
exactly that region's exclusive claim, generation and lease bounds. NVMe PEER
bind independently requires the namespace fd's mode, native command-effects
permission, supported transport and admitted LBA window. NET's ifindex/queue
API has no delegated queue fd and retains its management gate.

The host-only `protocol_test.py` executes the actual delegation function with
only fsconfig/fsmount intercepted. It checks that the emitted masks admit the
libbpf prerequisite and isolate each intended permission denial without granting
other commands, maps, program types or attach values. This checks mask generation,
not kernel enforcement. It also opens the actual bad-helper ELF with libbpf,
without kernel loading, and checks the real helper validation/restoration
functions against original, sanitized, missing, duplicate, malformed and bounded
instruction inputs. Prepared bytes outside the helper immediate must survive.
Set `TOKEN_OBJECT_DIR` to an existing build directory containing
`bad_helper.bpf.o`, or provide `CLANG` and `LIBBPF_HELPER_INCLUDE` to compile it
in the temporary test directory. It also compiles the actual parent send/wait tail and
uses real socketpairs and children, without namespaces or BPF operations. It
requires failed SCM_RIGHTS sends to return SETUP (2), preserve their original
errno and reap the child; successful sends must also reap the child. Configure
`LIBBPF_INCLUDE` and `LIBBPF_A` as for the native build when running this probe.
