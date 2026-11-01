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
