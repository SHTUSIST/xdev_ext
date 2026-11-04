# Source setup contract tests

Run from the canonical product root:

```sh
python3 -I tests/integration/session/source_setup/test_source_setup.py -v
```

The controls can run separately:

```sh
python3 -I tests/integration/session/source_setup/test_source_setup.py BaselineControls -v
```

`XDEV_SETUP_PRODUCT=/absolute/product/root` selects production inputs while leaving the test files fixed. `XDEV_SETUP_ARTIFACTS=/private/writable/path` controls the temporary fixture parent; the default is the private completion test-artifact directory. Fixtures use private local Git repositories and a tiny pinned upstream. The real layout and prepare helpers materialize independent source copies and an actual full-assembly receipt. The complete harness source-gate shell function is extracted without changing its embedded Python or its arguments. No existing test oracle supplies expected results.

Tests cover canonical/native/logical source identity, exact copy/header bytes, dirty/untracked/membership rejection, run-only refusal without repair, source-only runner queries, Kbuild identity and errors, actual E2 Makefile dependency resolution and source manifest coverage. Temporary source sentinels are ordinary source-admission inputs; they are never compiled as a kernel or represented as guest evidence. The runner's two pure oracle functions and lifecycle_core.h are checked against the frozen source boundary.

These tests do not run a guest, build a kernel, load a module, exercise devices, certify native runtime behavior, sign a gate, or measure performance. They do not invoke generic Clang. Project Git, manifests, CI and test-results registration remain with the root owner.
