# Software-device fault campaigns

Performance comparisons follow the [evaluation policy](../../../../../tests/eval/PERFORMANCE_POLICY.md).

`xdev_ext_mech_zc_fault_matrix.sh` drives the 18 campaigns specified by the
existing `xdev_ext_mech_zc_fault_validate.py` oracle. Each campaign boots a
fresh private QEMU guest with file-backed NVMe namespaces, virtio-net on a
private hub, and the existing CPU-memcpy CE stand-in. This is correctness
testing, not GPU/DMA performance evidence.

The source must be a clean, prepared product checkout. Create a new mode-0700
scratch directory on the authorized test host, then use its absolute path:

```sh
bash xdev_ext_mech_zc_fault_matrix.sh --dry-run --groups 64 --depth 8 \
    /tmp/xdev-ext-e2e.Example /absolute/product/kernel
bash xdev_ext_mech_zc_fault_matrix.sh --groups 64 --depth 8 \
    /tmp/xdev-ext-e2e.Example /absolute/product/kernel
```

`--campaign NAME` selects one case; `--debug-locking` requests the diagnostic
kernel; `--run-only` reuses a build only after the underlying harness verifies
its exact source and artifact identities. A plan is not execution evidence.
The scripts do not bind host hardware, modify host links/routes, or use bare
host disks. Device removal and controller reset occur inside the guest only.

The guest prints actual process exit codes, observed session state and native
in-flight counts, CE module counters/references, pin-accounting snapshots, and
function trace counts. A session is FREED only after STATS returns ENOENT;
unknown DMA remains quarantined. Missing fault preconditions are INCONCLUSIVE,
never PASS. The host compares complete source/destination images with the
frozen oracle, preserving all undeclared regions. It records foreign QEMU
process identities without reading them into human-visible command logs.

Evidence is retained under `SCRATCH/fault-campaigns/NAME/`; existing campaign
directories are not overwritten. Exit 0 means every requested campaign passed,
1 means failure, 2 invalid configuration, and 5 an unexercised fault condition.
The lower-level KVM script reports only `FAULT_BOOT=COMPLETE`; the matrix's
full-image/session oracle must still accept the run.

The cross-session case needs a positive CE ABI attach before registering the
victim's CE mechanism, because each device class has one active program. The
malformed ABI attach is repeated while the victim runs. The different-UID
STATS helper drops all groups and real/effective/saved IDs before opening its
ring and issuing the real STATS operation. It does not infer permission
isolation from an inability to execute a root-only initramfs binary.

Host unit checks exercise command construction, status propagation, parsing,
and script syntax. Their fixtures and synthetic logs do not certify a guest
run. Actual guest validation is required for every new integrated source SHA.
