# Ordinary DATA POOL_DMA contract tests

This suite compiles actual kernel production function bodies into a host correctness harness. It preserves ordinary AF_XDP DATA submission and native count journal behavior while freezing typed pool lease refusal and cleanup requirements. It does not establish native DMA, hardware performance, reliable DATA/CONTROL/RX conversion or complete NET4/6/9 migration.

The baseline has no POOL_DMA API. Its valid behavior runs normally; the new API/provider/rollback/lifetime vectors and six candidate-only mutation recipes report SETUP until the production symbols exist. An invalid mapped-page count is safely observable against the old production body because the backing page array remains allocated: the old code accepts and synchronizes it. That is semantic RED for the new refusal contract, separately recorded from missing symbols.

## Invocation

From the repository root:

```sh
python3 tests/network/pool_dma/run.py --out-root /absolute/private/evidence --mutations
```

For a frozen candidate, retain these independent test files and provide only its production source root. Compare the old literal observable trace prefix:

```sh
python3 tests/network/pool_dma/run.py --source /absolute/candidate --out-root /absolute/private/evidence --mutations --compare-baseline /absolute/old/current/run.stdout
```

Every invocation creates a unique directory and preserves generated source, manifest, exact compiler argument list, stdout/stderr, invalid-mapping run and summary. GCC compile failure is SETUP. A mutation earns KILLED only after successful compilation and exit through its designated assertion; signal/crash/compiler failure does not count. Exit 42 is the explicit boundary assertion path, not a crash.

## Adapter boundary

`adapter.py` mechanically extracts production records and complete function bodies, removes header includes and renames only two instrumented symbols. The real raw DMA lookup still executes over a controlled mapped-page array; its wrapper records lock state. The future provider check wrapper records the successful check's lock epoch without changing arguments or return. DMA sync uses the actual production wrapper down to the OS call boundary. Native public completed/cancel-tail/set-tail/single-peek/batch-peek paths are compiled in full, including their controlled policy/upstream fallback branches.

The actual `xp_dma_unmap` and map-list lookup execute in the mixed-stop test. Only OS frees, trace emission, refcount decrement and physical shared-map destruction are boundary operations. The shared mapping has two users; this pool's unmap must invalidate its own map fields while leaving the shared map alive. Late completion uses the actual public completion hook.

Core frame copies, family existing HOST acquisition/release, packet checksum/validation header, portable journal, ordinary full submit, provider retire/cancel/stop/done and CQE fill are production bodies. Fixture declarations mirror the fields consumed by those bodies; they contain no replacement journal or lease algorithm. Reliable and policy full-path regressions remain separately required.

`ASSERTIONS.md` contains the independent literal contract frozen before source inspection. Candidate API absence is explicit; the suite does not fake the missing POOL implementation.
