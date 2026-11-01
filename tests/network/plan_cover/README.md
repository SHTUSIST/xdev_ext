# NET29-2 independent exact-cover cohort

Use this test checkout's scripts and point `--source-root` at the canonical candidate:

```sh
python3 tests/network/plan_cover/run.py --source-root /absolute/source --phase baseline --output /absolute/evidence/baseline
python3 tests/network/plan_cover/run.py --source-root /absolute/source --phase shared --output /absolute/evidence/shared
python3 tests/network/plan_cover/mutations.py --source-root /absolute/source --phase shared --output /absolute/evidence/mutants
```

Exit 0 means the selected control passes (or all requested mutants compiled and were detected). Exit 1 is a behavior/shared-consumer assertion failure or a surviving mutant. Exit 2 is SETUP: missing actual source/adapter, failed original-header include compatibility, compiler failure or nonmatching mutant target. SETUP never counts as semantic RED or detected mutation.

`baseline` runs both actual old NET wrapper and actual generic helper over literals, independent finite-domain predicates and deterministic random splits. It can legitimately pass before refactoring. `wiring` additionally requires the actual NET wrapper to call the existing family helper once; original duplicate-loop failure is a structural refusal, recorded independently of semantic compatibility. `shared` requires the frozen real context/span/entry adapters, their exact behavior, actual shared callback identities and max16 arguments.

No validator, entry policy or native operation is copied into a fake. `contract.c` wraps the real generic call with recording callbacks that immediately call the actual production adapters. Inputs and contexts use complete memcpy byte snapshots, including unused fields/header/padding. The small independent expected predicate uses hand-derived interval and header-size inequalities and never invokes production helpers.

`mutations.py` copies only compiler-discovered production dependencies and the three required headers into isolated evidence directories. Compiler/SETUP refusal does not count as a kill. Socket/XDomain/AF_XDP unchanged consumer tests, actual kernel objects, final source integration and test-results registration remain root gates. No native/device/performance claim follows from this host cohort.
