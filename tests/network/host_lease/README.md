# Socket HOST lease consumer tests

This suite freezes the old socket consumer observations before a HOST candidate
exists. It compiles the real socket methods and real network family runtime,
tracker and cover checker, with GCC and UBSan. The frame, stage, pool and call
argument declarations are extracted from production; batch-frame/slot/state
accessors and ticket claim/complete helpers are also the real bodies.

The host shim controls allocation, socket send/receive, credentials, admission,
counters and worker notification. Its session/batch structs project the fields
used by those actual accessors. Completion publication records the boundary
observation using the actual ticket publication primitive; it does not run the
core worker, lifecycle handoff, a network device or DMA. PEER boundaries are
counted forbidden calls here; this suite does not certify PEER behavior.

```sh
python3 tests/network/host_lease/run.py --out /absolute/evidence/baseline
python3 tests/network/host_lease/run.py --out /absolute/evidence/mutants --check-mutants
```

A later candidate is supplied independently, without changing the test inputs:

```sh
python3 tests/network/host_lease/run.py --source /absolute/candidate --out /absolute/evidence/candidate --compare-baseline /absolute/evidence/baseline/observations.log
python3 tests/network/host_lease/run.py --source /absolute/candidate --out /absolute/evidence/host --suite host
```

Exit 2 means SETUP (missing interface or compilation); it is never a semantic
RED. Exit 1 or a literal assertion is behavioral failure. Mutation checks require
a compiled executable to fail at a semantic assertion; missing source anchors,
compile errors and timeouts do not qualify as killed mutants.

`FROZEN-ASSERTIONS.md` in the private network-host-tests evidence directory records
the independent expectations, limits and ordering. Root owns the source version,
independent rerun, integration and registration in
`/root/xdev_ext/test-results/correctness/local/`.
