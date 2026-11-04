# CE residual exclusion regression

Execute the production CE bind, lease admission, typed validation, submit,
completion, cleanup, and core checked-unbind functions in a host harness.
Requirements are Python 3, GCC, and Linux userspace type headers. Every test input
comes from this folder or the explicit source tree; no private recipe generator,
prebuilt executable, Git metadata, or previously generated source is required.

From the checkout root:

```sh
python3 tests/compute/ce_residual/run.py --source-root . --phase repaired --output build/ce-residual/repaired
python3 tests/compute/ce_residual/run_supplement.py --base-evidence build/ce-residual/repaired --output build/ce-residual/multistage
python3 tests/compute/ce_residual/run_nonconflict.py --base-evidence build/ce-residual/repaired --output build/ce-residual/nonconflict
python3 tests/compute/ce_residual/run_mutants.py --base-evidence build/ce-residual/repaired --recipes tests/compute/ce_residual/mutation-recipes.json --output build/ce-residual/mutants
```

The combined mutation entry first verifies a fresh repaired base, then runs all
packaged recipes:

```sh
python3 tests/compute/ce_residual/run.py --source-root . --phase mutations --output build/ce-residual/mutation-phase
```

All commands also work from another directory with explicit source, evidence and
output paths. `run_mutants.py` defaults to the recipe file beside the script; an
explicit `--recipes` argument selects another file. Supplements consume the
actual-source extraction and compiler command recorded by the repaired run.
Keep the scripts, C files and recipe JSON together when copying the test folder.

`old-red` runs the same safety expectations against the previous source and
returns 1 when it demonstrates unsafe admission. Build/extraction failures return
2 and never count as behavioral failure evidence. `repaired` must return 0.
Mutations count as detected only after compilation succeeds and the chosen
unchanged scenario exits normally with its designated assertion failure. Signals,
timeouts, compilation errors and unrelated failures are not detections.

The extractor keeps every selected executable function body unchanged. Kernel
headers/passive class registration are omitted. The common runtime header/implementation and CE adapter are assembled from the
selected source when shared execution is present; the old repaired source remains
supported for private baseline replay. Only kernel includes are removed from
these runtime bodies. `CE_STATE` and `CE_COOKIE` in the harness project shared
fields and the opaque cookie representation without replacing execution. The
registry reset and observed registry lock follow the actual fixed registry.
Pure CE/lease/copy/cookie helpers
and native API structures come from the selected source tree. Native hooks,
module/allocation/list/mutex primitives, core accessors and completion-ticket
boundary services are host test facilities. Native hooks use the existing backend
registration API and can reenter the real B submit during A bind/unmap. No CE
policy is replaced and no new virtual device is registered. Missing source or
unmatched recipe targets fail; each applied edit is recorded; packaged snippets never replace absent source.

Assertions cover configured-range residual admission, cleanup refusal and retry,
same-generation later-stage admission, ordinary bind success, disjoint ranges,
different backend identities, malformed provider outputs, pin/count retention,
multistage holds, pre-native allocation failure, errno ordering, UNKNOWN/active
refusal, atomic detach, and exact successful CQE bytes. A mutex-unlock observer
checks the cleanup hold/removal boundary. The additional multistage control uses
successful native binds followed by direct class cleanup reentry; core checked
cleanup normally stops on its first refusal. The nonconflict control retains A's
cleanup region while B uses an adjacent range or independent registered backend.

The host harness proves class behavior. It does not execute physical mapping/GPU
DMA, Linux scheduler locking, complete core session teardown, VM or performance
experiments.

The packaged mutation anchors target the shared-runtime adapter. Their scenario
and expected assertion strings are unchanged from the accepted CE repair gate.
Host-unmap refusal/early detach target the corresponding CE callbacks, and early
module-put targets the typed wrapper; those paths execute through common checked
unmap. Keep the original recipes with an old repaired-source receipt when
replaying that private historical baseline.

### Common-lease identity mutation scope

For the common-lease source, `provider-field-identity` changes the actual CE
key-overlap policy to use provider-writable region ops/length. The policy is called
by both the foreign-group admission scan and the same-group serial predicate, so
this injection also affects that serial caller. It preserves the original targeted
fault and decisive cross-group assertion, rather than every possible side effect
of the old private-get edit: the designated identity control uses separate
single-region groups, and retains its original expected refusal/error string.
The published runtime `ce_configured_identity` mutation has the same two-caller
scope. Neither mutation counts a missing anchor or compile failure as detection.
