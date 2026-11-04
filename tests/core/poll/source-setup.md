# Stage-POLL source setup checks

`source_setup_test.py` exercises the existing runner's source-resolution and artifact-verification functions in isolated local fixtures. The 101 cases use real temporary Git repositories, the product's unchanged layout/preparation APIs and offline local upstream objects. Artifact contents and receipts are synthetic source fixtures. The suite supplies no guest, kernel, native DMA or performance evidence.

From a canonical checkout or its logical source view, run:

```sh
python3 tests/core/poll/source_setup_test.py --mutations
```

The script discovers the canonical product from its own location, the current directory or a logical view's `view.json` receipt. `--product DIR` or `PRODUCT=DIR` selects a canonical checkout or logical view explicitly. The default runner comes from the existing layout mapping for `tools/testing/selftests/xdev_ext_mech/poll/poll_kvm.sh`. `--runner PATH` can select a separate candidate without changing the tooling source.

Temporary fixture trees and `results.json` go under `PRODUCT/build/poll-source-setup`. Select a different output directory with `--artifacts DIR` or `ARTIFACTS=DIR`. Temporary trees are removed after execution; JSON results remain. No private staging files or API snapshots are required.

The default run checks all 101 acceptance/refusal cases. `--mutations` additionally verifies that the tests catch source-validation and artifact-validation bypasses in extracted source copies. Their two raw `FAIL` lines are expected sensitivity evidence; the final process succeeds only when all 101 real checks pass and both bypasses are caught. `--only TEXT` selects matching cases for diagnosis. `--fixture-check` constructs all fixtures without executing the candidate functions.

Only the two setup functions are extracted; the VM tail, guest program and validators are never sourced. A recording `modinfo` replacement is confined to each synthetic metadata boundary. Compiler, VM, module-loader, image and network commands listed by the fixture are rejected. The unchanged test boundary sets a 25-second subprocess timeout, 768 MiB address-space limit, CPU/file-size limits and bounded captured output.

Historical baseline evidence is optional and is not bundled. To replay a separately preserved, provenance-checked old prefix that ends before `/dev/kvm` access:

```sh
python3 tests/core/poll/source_setup_test.py --baseline --baseline-prefix /path/to/old-prefix.sh
```

This writes `baseline.json` under the selected artifact directory. Omitting `--baseline-prefix` is an argument error. The normal 101-case run never reads a historical prefix.

The public file preserves the independently frozen case tables, closures, assertions and source-copy mutations. `preservation.json` and `portable-changes.diff` document the packaging changes. Actual tool production, genuine module metadata, guest execution and test-result registration remain separate acceptance work.
