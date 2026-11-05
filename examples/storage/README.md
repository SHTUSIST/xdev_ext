# NVMe block table example

`nvme_blocktable.bpf.c` resolves a session's logical batch key through a BPF
HASH map. Changing map contents changes the selected blocks while the program,
registered bindings, and NVMe backend stay the same. This is a mechanism example;
it does not claim that selecting LBAs is novel or establish performance gains.
The existing reverse/gray examples remain in
`tests/benchmarks/mechanism_variants/` with their original scope.

The `blocks` map holds up to 1024 entries. `nvme_blocktable.h` defines its
native endian key and value ABI:

- Key: `session_id` from the callback's session, and `logical_key` from
  `base.src_offset` (the documented batch key). `request_id` does not select
  the entry.
- Value: `byte_offset` relative to the binding's admitted `window_slba`,
  `byte_length` equal to the batch payload and group bytes, and zero `reserved`.

An application loads the object, obtains the `blocks` map FD, and populates it
with `bpf_map_update_elem()` after CREATE supplies the session ID and before
START. For 512-byte LBAs, a window starting at LBA 2048 and a value of
`{byte_offset=12288, byte_length=4096, reserved=0}` selects LBA 2072 for that
logical key. Replacing only the value with `{16384,4096,0}` selects LBA 2080.
Stop and drain the session before changing mappings; atomic replacement of a
whole multi-field value during an active callback is outside this example's
contract. Delete obsolete entries after drain to reclaim map capacity.

This program issues READs. A missing key, nonzero reserved field, misalignment,
length mismatch, transfer limit violation, or window/capacity overflow aborts
before a descriptor is submitted. The map grants no additional authority:
existing C descriptor validation, binding extents, and the live namespace still
control admission and submission. Completion errors abort the chain.

Build BPF bytecode using a `vmlinux.h` dumped from the intended kernel's BTF and
real libbpf headers (Clang is used only for required BPF compilation):

```sh
python3 tools/run.py --cwd examples/storage make \
  CLANG=clang-14 VMLINUX_DIR=/path/to/target-btf-headers OUT=/path/to/output
python3 tools/run.py --cwd tests/storage/nvme/blocktable make check
```

The GCC host test executes the checked-in BPF callbacks and production SQE
admission helper, checks literal full descriptors and complete output bytes for
two map contents, then exercises failure boundaries. It provides host software
correctness evidence. BPF object compilation, target-kernel verifier loading,
and device execution are separate checks.

Generate a path responsibility report from an actual comparison:

```sh
python3 tools/analysis/responsibility.py --repo . --base BASE --head HEAD --format json
python3 tools/analysis/responsibility.py --repo . --base HEAD --working-tree
```

Reports group canonical Git paths into application, BPF, core, backend, support,
and other. Cross-category renames appear in both affected categories. Working
tree reports include staged, unstaged, and untracked paths. Reports include raw `git diff --numstat` added/deleted counts for tracked text
changes. Binary and untracked counts are explicitly unavailable. These are
descriptive Git facts, without treating line counts as evidence of contribution,
novelty, efficiency, or engineering cost.

## Ordinary block RW

`block_rw.bpf.c` uses `xdev_ext_block_mech_ops` and class
`XDEV_EXT_MECH_CLASS_BLOCK` (12). CREATE takes an already opened ordinary block
device FD with the required read or write mode and an exclusive claim held by
that same file. `arg0` and `arg1` authorize the partition-relative LBA window.
The session's existing file reference keeps the open and claim alive after the
application closes its FD. A regular file or another holder's claim is refused.

The build callback selects a whole group inside the authorized window using
`base.request_id`, writes READ (0) or WRITE (1) according to the stage direction,
and encodes SLBA and the actual NLB count in a zeroed 64-byte little-endian
descriptor. C independently admits the descriptor, rechecks the captured device
identity and submits host pages through the ordinary block BIO path. A partition
uses relative sectors; the block layer performs its native partition remap.
Completion errors abort the chain, including a terminal error after partial
I/O; the program never retries an accepted batch.

This member supports host pools and interrupt completion. PEER pools and POLL
are refused. It provides ordinary READ/WRITE, without flush/FUA or durability,
discard, zoned I/O, integrity payloads, compute or uring_cmd BUILD. Queue
admission can sleep in the existing session worker. Driver DMA mapping, native
splitting and merging remain block-layer responsibilities; this example makes
no zero-copy, physical DMA or performance claim.

The same `make` command above builds `block_rw.bpf.o` using target-kernel BTF
that includes the BLOCK types. Bytecode build, verifier loading, program
selection and actual device correctness require separate validation.
