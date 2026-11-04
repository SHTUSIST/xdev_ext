# Actual-source copy runtime v2 cohort

This cohort tests the CE/DMA class paths against independently frozen behavior requirements. It compiles actual production class bodies, actual copy/lease/scope helpers and the actual core CE/DMA owner-phase admission functions. Kernel primitives, native operations and the remaining core lifecycle/frame/publication APIs are controlled boundaries.

```bash
python3 tests/compute/family/runtime/run.py --source-root "$PWD" --phase baseline
python3 tests/compute/family/runtime/run.py --source-root "$PWD" --phase mutations
python3 tests/compute/family/runtime/run.py --source-root "$PWD" --phase runtime
```

`--output PATH` selects an artifact root. The default is `build/compute-runtime-tests` under the checkout. Each build preserves its generated source, compiler command, source receipt, compiler log, executable and run log; repeated builds receive numeric suffixes.

`baseline` compiles and runs ordinary GCC and GCC with UBSan. `mutations` builds isolated semantic edits of the repaired actual production paths; every counted kill requires executable assertion exit70. Compiler failure is SETUP, other abnormal exits are EXECUTION_ERROR. The protected stale-read test traps any mutable-stage dereference in a child and asserts that the child exits normally.

`runtime` requires the new common source. It compiles the actual common and both class bodies together, checks the same literal assertions and compares all OBS/CQE/ABI/XFER lines with the frozen checked baseline. GCC function-entry instrumentation observes all ten common operations separately for CE and DMA (CE excludes poll), so one unused common implementation cannot satisfy the shared-use check. The v2-only repair vectors follow V2-ADDITIONAL-BEGIN; V1-V2-DELTA.json accounts for the only four inherited-observation changes. The fixed trace contains 330 OBS/CQE/ABI/XFER lines; a separate five-line supplement preserves NULL registry behavior. Runtime mutation anchors target the actual shared implementation, while baseline expectations stay frozen.

This is a 64-bit little-endian host projection. It does not test real kernel allocation/locking/module semantics, full core frame ownership/lifecycle/publication, device mapping/DMA, performance or physical quiescence. It does not replace root's real GCC kernel objects and integration/lifecycle checks. The v2 CE repaired configured-range/cleanup-hold behavior is required. V1 detach-before-unmap observations are historical and cannot satisfy v2 parity; root-owned kernel build and integration evidence remains separate from this host cohort. Test-only disposal after checking retained UNKNOWN state is explicitly marked and is not a claim that UNKNOWN may be reclaimed.
