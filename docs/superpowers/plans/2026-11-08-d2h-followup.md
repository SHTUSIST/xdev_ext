# D2H diagnostic follow-up implementation plan

> For agentic workers: execute serially in this already assigned isolated worktree; the parent agent supplies independent review. Do not spawn additional agents.

**Goal:** Make a supplemental software diagnostic distinguish a skipped D2H from a correct round trip, retaining the original aliasing negative control.

**Architecture:** Extend only the test CE simulator with default-off per-request Host payload inversion after the complete H2D copy and before completion. Compile the real simulator engine into a host correctness fixture, preserving all request prevalidation and checking entire buffers against independent expected data. This independently reconstructs the public recommendation; unavailable external attachment bytes are not certified.

**Tech Stack:** C, GCC UBSan/ASan, Python unittest, existing source-view mapping.

## Global constraints

- No production src/, BPF plan, paper, performance, remote build, QEMU or device execution.
- New fault modes report nominal complete bytes so assertions prove data observation.
- Diagnostic applies only to isolated, serial non-overlapping a/d payloads.
- Never infer physical DMA correctness from host tests.
- Only parent agent updates shared test STATUS/index.

## File map and interfaces

- `tests/support/ce_sim/xdev_ext_ce_sim.c`: add request snapshots `bool poison_after_h2d` and two skip modes; copy signature remains `int xdev_ext_ce_sim_copy(struct xdev_ext_ce_sim_req *)`.
- `tests/support/ce_sim/copy_contract.c`: user-space types and independent payload/guard expectations, include generated engine bodies.
- `tests/support/ce_sim/copy_contract.py`: extract `xdev_ext_ce_sim_in` and `xdev_ext_ce_sim_copy`, run sanitizer tests and isolated mutants without changing source.
- Existing `tests/integration/cli/xdev_ext_mech_ce_roundtrip_test.py`: invoke the companion runner through existing CI entry.
- `source-layout.json`: register the two new support files in existing simulate native path.
- `docs/human_read/d2h-followup-review.md`: decision first, current-code findings and evidence boundaries.

## Task: independent diagnostic reconstruction

- [x] Write a fixture that sets device to poison, Host to independent P, expects H2D to leave device=P and Host=~P when the request option is true, then D2H restores P. Original false option must retain aliasing behavior.
- [x] Compile the real current engine with the new boundary struct field; run the fixture before simulator changes. Expected RED: Host remains P and fails post-H2D poison assertion.
- [x] Add default-off module option, captured by submit; invert Host payload only after all copy reads complete, after full-request bounds prevalidation.
- [x] Add skip_h2d/skip_d2h modes captured by submit, updating nominal bytes without copying the specified direction.
- [x] Run sanitizer suite: correct copies; separate skip modes; both directions' full-buffer guards; adjacent segments; late invalid Host/GPU offset and overflow rejecting every write.
- [x] Mutate generated C to remove inversion, invert before H2D, and move prevalidation into per-item copy; each must fail explicit data assertions.
- [x] Run original CPU roundtrip suite through tools/run.py, source-view check and diff check; record results under independent local test ledger.
- [x] Report candidate scope before commit/push; parent independently reviews before main integration. Do not merge main.
