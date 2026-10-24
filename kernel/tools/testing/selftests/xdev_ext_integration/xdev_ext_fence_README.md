# Matching-guest lifecycle/dma_fence checks

Performance comparisons follow the [evaluation policy](../../../../../tests/eval/PERFORMANCE_POLICY.md).

`xdev_ext_mech_zc_kvm.sh --fence-check` explicitly extends a normal correctness
plan. The default 13-case fault matrix does not select it. `--fault-campaign`,
non-normal providers and network fault cases are refused. It can accompany
`--lifecycle`, or normal CE/compatibility plans. The hook runs before networking
and CE loads, and does not change disk geometry or the existing disk oracle.

The harness enables and verifies `MODULES`, `MODULE_UNLOAD`, `DMA_SHARED_BUFFER`
and `DEBUG_FS`. It runs the full matching `bzImage vmlinux modules` build to
produce genuine `Module.symvers`, then builds the real external module with
`M=<checkout>/tests/eval/dmabuf_lifecycle`. The source retains its actual
production lifecycle header dependency. A failed full kernel or external module
link aborts before staging/guest execution; an object-only compile cannot be
staged as a module. No symbol versions are fabricated and MODPOST is mandatory.

The module, genuine symbol table, release, vmlinux, config, source SHA and relevant
source/helper dependencies are bound to the build artifact manifest. `--run-only`
requires that manifest, identical source SHA/profile, matching required config,
all required dependencies, module name, and vermagic matching the guest release.
The initramfs copy and fresh request are hashed in the run evidence too.

The Busybox guest script runs `mode=check iterations=8`, verifies read-only
sysfs mode/count/nonce, emits the complete original debugfs JSON, and unloads.
Four additional insmods use the actual `fail_alloc_at=1/2` and
`fail_callback_at=1/2` parameters. Each must fail and leave neither module nor
benchmark debugfs resources. Each case has a distinct 32-hex nonce derived from
a fresh host request. Existing producers are refused, and unverified ownership
never causes an unload. The check has no timing route or timing output.

The host validator reuses the actual experiment `run.validate_result`, adds
strict counter types, complete/unique case and JSON-key checks, request/source
identities, sysfs producer match, successful owned unload and absent resources,
guest kernel release/module-byte identity, clean dmesg, and both QEMU and outer
guest exits. `fence-result.txt` is a sub-verdict; the normal full-image and session
oracles must still succeed for the whole harness to pass. It never generates a
guest PASS from a host contract or fixture.

Host-only tests (no module loads or guest launches):

```
python3 kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_fence_validate_test.py -v
```

Synthetic reports in those rejection controls are unit-test input only. A host
test, dry-run or object compile does not establish matching-kernel runtime
acceptance or physical performance. Full genuine GCC/Clang module linkage and
matching debug/normal guest positive/negative runs remain separate acceptance.
