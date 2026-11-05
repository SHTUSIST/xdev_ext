# COUNT_FIFO actual-body correctness gate

This suite selects an explicit fixture contract, executes complete production bodies
through instrumented OS/device boundaries, compares the whole stdout with that
contract's fixed golden, and checks shared COUNT_FIFO ownership and public wiring.
The unchanged sibling `tests/network/pool_dma` extractor and C fixture remain
required dependencies. Raw `test_count.c` is immutable in both profiles.

For current production, select the typed DATA contract explicitly:

```sh
python3 tests/network/count_fifo/run.py --source "$PWD" \
  --fixture-contract typed-data-v1 --mutations --out-root "$PWD/build/count-fifo"
```

`--source` names the canonical repository containing `source-layout.json` and `src/`.
No contract is inferred from production contents. The default
`--fixture-contract historical-raw-v0` retains the raw fixture and old golden; use
it only with its matching historical production root. It is not a current DATA
success contract. A missing typed helper is SETUP, never a raw fallback.

Each invocation creates a unique `count-*` directory containing complete generated
bodies, the byte-identical predecessor fixture, commands and compile/runtime output,
input hashes, structural findings and `summary.json`. Typed runs additionally save
`fixture-transform.json` for each baseline/mutant, also included in its summary
entry. This receipt records the raw and generated complete-file hashes, the exact
four forward and four inverse spans, named scopes, offsets, occurrence counts and
full inverse byte equality. Sources and sibling fixtures are never edited.

The baseline requires compile success, runtime exit zero, the selected whole-output
hash/length and ownership/wiring PASS. `--mutations` additionally requires all 24
original labels in original order, successful compilations and their original
designated checks. SETUP, SURVIVED, INVALID_MUTANT and missing runs fail acceptance.
`--only-mutation NAME` runs baseline plus one mutation for diagnosis. An unrelated
earlier assertion, unavailable anchor, signal or timeout is nonacceptance; recipes
and classifiers are not adjusted to obtain a kill.

The `disconnected_public_consumer` mutant compiles and exits zero. Its detached old
peek algorithm is killed only by the executable ownership/wiring check reporting
the original named direct-consumer failure (`kill_kind: ownership_wiring`). The
other 23 kills require their original runtime assertions. Original eleven mutants
retain predecessor execution mode; the thirteen new mutants stop at first failure.
Compiler/runtime flags, mutation identities, recipes and classifiers are shared
unchanged between profiles.

## Historical raw contract

The complete old stdout is 89,721 bytes with SHA256
`9fc5b51ce2e82c7b6411021549e3c4291e5cbe9797b210d0af3de71d514bdf81`.
These literals were frozen from the preproducer old-source capture. Its documented
production commit is `f77b908392c9058e9fcb574386c81c9302a71ee6`; matching source and
harness provenance is required for historical replay. Its original ownership RED
is a historical observation, not current acceptance. The accepted shared-COUNT
historical lane for all 24 original recipes has a separately pinned matching root.
The detached peek literal is used only by its deliberate mutation.

```sh
python3 tests/network/count_fifo/run.py --source /path/to/matching/historical/root \
  --fixture-contract historical-raw-v0 --mutations --out-root /path/to/output
```

Historical byte equality requires the original raw fixture and matching original
harness/production inputs. An old root lacking newer family mutations cannot supply
those kills. This maintained runner does not replace the preserved original
harness as historical provenance.

## Current typed DATA contract

`typed-data-v1` uses the independently constructed and frozen complete current
stdout: 90,093 bytes with SHA256
`66b024a622d5b206786011a26c81fd01747fdd724da1e65bf0bb2e28cf34f11e`.
Root froze this expectation from verified historical bytes and source-derived
literal deltas before the first current execution. Candidate output never supplies
or repairs the expectation. This is a new golden, separate from old byte equality.

Generation accepts only raw COUNT SHA256
`1efa6aa4cd946dd5bfeaa8d37ed794ce1e69933aff14157181502c92f9fdb8f2`.
Exactly four reversible changes apply to the generated copy:

- T1 supplies real DATA batch/frame authority and distinct matching descriptors for
  direct counts 1/32. DATA payload length stays 16, descriptor span stays 58, and
  packet bytes are untouched. CONTROL keeps address 22 and no DATA batch.
- T2 explicitly replaces `reliable_terminal_once`'s obsolete zero-DATA predicate:
  DATA requires exactly `count` operations and `16*count` bytes; CONTROL requires
  exactly 0/0. Callback-once and cursor conditions remain exact. The old predicate
  remains unchanged in raw historical C.
- T3/T4 attach the existing batch only to DATA owner `a` in physical wrap and U32
  origin cases. CONTROL owner `b`, descriptors and all queue predicates stay exact.

The adapter extracts the complete actual `xsk_rel_data_lease_locked` body before
its enqueue caller. No helper implementation, lease/rollback algorithm, zero-length
frame, admission bypass or counter suppression is supplied by the fixture. Raw
identity, scope/span count or inverse mismatch fails setup before compilation.
All other CHECK predicates, print formats, packet bytes, CONTROL cases and the
entire POOL fixture remain unchanged. The expected live typed lease and DATA
accounting observations are checked by the complete current stdout hash.

An optional external capture can add another exact byte comparison; it must match
the selected contract:

```sh
python3 tests/network/count_fifo/run.py --source "$PWD" --fixture-contract typed-data-v1 \
  --mutations --compare-baseline /path/to/frozen-typed.stdout \
  --out-root "$PWD/build/count-fifo-external"
```

Public execution needs no private capture or expected-output artifact. Root owns
exact candidate identity review, actual execution and final result registration.
Fixture-only unit tests can be run separately without importing production:

```sh
python3 -B -m unittest discover -s tests/network/count_fifo -p test_typed_fixture.py
```

## Scope

All original POOL assertions, packet literals, event assertions and TRACE prefix
remain in the unchanged sibling fixture. The extension retains the nineteen input
families in `ASSERTIONS.md`, including ordinary/reliable/control paths, mappings,
uncertainty, cancellation, fallback, callback ordering and shared-map release.
Public witnesses use real 64-chunk fixtures with a 32-chunk source partition; pure
capacities 1/2/4/8 support the state-machine checks.

The bounded search retains its declared legal event grammar, depth/state bounds
and fixed seed traces. BPF resend build, OS refs/frame moves, core terminal
publication and DMA are instrumented boundaries. Acceptance covers host actual-body
correctness and shared ownership for this slice. It supplies no native kernel,
physical DMA, performance, full family-member migration or whole-network closure
evidence. Source edits or unexecuted unit tests alone establish no acceptance.
