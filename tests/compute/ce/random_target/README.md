# CE random target admission: stage 1

This test compiles the actual mechanism CREATE, class-size and common window
copy headers through the existing canonical source-view reader. It exercises
the first admission and capacity requirements for an explicit two-stage
NVMe↔CE mode. It preserves 1 MiB payloads, 32 host frames, multiple batches,
legacy CE compositions and DMA's 32-entry limit.

```sh
python3 tests/compute/ce/random_target/run.py --suite controls \
  --keep-build build/ce-random-stage1/red-controls
python3 tests/compute/ce/random_target/run.py --suite all \
  --keep-build build/ce-random-stage1/red-all
```

The runner compiles the canonical `stage1.c` and current canonical production
header bytes; it does not clone a product revision. `--keep-build` accepts an
absolute path or a path relative to the current directory and requires a new
path. Reusing an existing path is refused. Without this option, the runner
creates a unique retained directory under the canonical root's
`build/ce-random-stage1/`. Keep selected paths in the project's owned storage.

The view, its reader receipt, binary, command arguments, command exit records
and logs remain in that directory after success or failure. `run.json` records
the reader and command status, including setup errors. Nothing is automatically
uploaded or deleted. The manifest stays unchanged and old controls run before
any new cohort. Compilation, source-view or process setup failures return 2.
Assertion failures return 1. A controls failure prevents assessment of the new
cohorts. Unexpected Python exceptions return SETUP (2), including failures after
a command has run; they are not behavioral RED. A nonzero exit alone is
insufficient evidence of the intended RED.

The proposed CE stage flag is an explicit test input, class-local bit 0. The
flags cohort calls CREATE with actual production declarations. The topology
cohort separately copies the actual CE declaration and adds only that bit to
its input `known_flags`; all production callbacks and other properties remain
unchanged. This qualified metadata input checks the composition rule after
flag recognition. It makes no claim that an unregistered flag already reaches
that path through the old runtime.

The capacity cohort calls the actual class-size rule and common copy validator
with valid aligned 1 MiB plans of 33, 48 and 64 pieces, isolating capacity from
the later target-range rules. Controls also call the actual compatibility CE
plan API with a legal 32-piece plan and an otherwise legal 33-piece plan
that must retain its capacity refusal. This guards the CE limit independently
of a literal limit supplied to the common helper. The runtime CE validator
instead calls `xdev_ext_comp_copy_stage_validate` with its selected limit;
neither the compatibility API nor a literal common-helper limit verifies that
runtime selection. The implementation stage must add that actual regression
before claiming flags-zero runtime preservation. Another control checks the
actual window rule with an explicit 48-piece 1 MiB plan starting at GPU byte offset 1.
No helper implementation is replaced with a successful stub.

This is a pure-rule check. It does not certify native owner admission, range
leases, concurrent DMA, BPF verification, kernel stack usage, GPU completion,
VRAM contents or performance. Whole-window and guard checks on a real GPU and
the complete 64-entry runtime dependency chain remain separate requirements.

The separate `runtime_validate.py` fixture selects the actual CE runtime
validator, common collect/validate functions, core batch accessors and frame
claim/native-owner functions. It includes the actual lifecycle rules. It has
no device backend or successful native-I/O stub. Metadata projections provide
the held session/batch fields; the actual functions read and validate them.

```sh
python3 tests/compute/ce/random_target/runtime_validate.py --suite all \
  --keep-build build/ce-random-stage1/runtime-red-all
```

Its controls call the actual CE runtime with flags zero and 32/33 entries.
The mode cohort requires flags-zero to stay at 32 and opt-in to admit 33/48/64.
The owners cohort validates all 64 transfers through actual frame claims and
the actual native-ticket/owner checker, including a stale last split and a
missing final frame claim. Retained evidence and SETUP/FAIL handling reuse the
stage1 runner. These checks still do not claim actual DMA or GPU contents.

## XDOMAIN RX producer

The `xdomain` cohort of `stage1.c` admits one more range composition: XDOMAIN
RX at stage 0 on the ring's IOU_UMEM host frames, then the CE range stage at
stage 1 (TO_DEVICE). An RX element ends successfully only with its full posted
length, so the whole group is in the host frames before CE validates its plan,
as after an NVMe READ. CE stays the only stage taking a range lease and the
last stage. PEER/XSK pools, XDOMAIN TX, CE first, CE FROM_DEVICE, three stages
and other producers stay refused; the NVMe pairs and flags-zero XDOMAIN->CE
are unchanged. `class_table_diff_test.c` repeats the matrix.

`xdomain_mutations.py` rewrites the new row in a private view (pool rule,
both directions, stage position, partner class, always-admit, row removed),
recompiles both tests and requires each mutant to fail an assertion:

```sh
python3 tests/compute/ce/random_target/xdomain_mutations.py \
  --output build/ce-random-xdomain-mutants/manual
```

These are pure admission rules. The separate
[XDOMAIN RX to CE runtime composition](../../../network/xdomain/chain/ce.md)
runs data movement through the actual worker, XDOMAIN and CE runtime with
IOU_UMEM frames and the CE simulator. It checks payload, destination offsets,
guards and failure lifetimes; it does not qualify physical Thunderbolt DMA
or real GPU memory. The admission tests above make no data-movement claim.
