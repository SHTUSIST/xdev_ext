# Independent stage diagnostics checks

Requirements: the admission diagnostics plan, appendix A3 and Task 3, and
`docs/reference/library-contract.md`. This suite runs the normal session library
and normal ctl executable, replacing external syscall results only.

Plan before implementation review:

1. Check raw query envelope and owning ring/session/stage identity; corrupt each
   documented response schema field and require EPROTO with zero output.
2. Open/create/stop through normal public APIs; check that a retained, created
   session remains diagnosable, while a failed retained CREATE has no query ID.
3. Run normal `peer-diag` subprocesses with inherited ring descriptors; require
   failure on unsupported or corrupt diagnostics and reject missing arguments.
4. Only after these tests, inspect normal implementation and review timeout
   call paths against the specified XDOMAIN selection and error ordering.

This is postimplementation independent conformance, not a preimplementation
TDD result. Injected replies do not certify kernel queue facts, incarnation
locking, real hardware, or performance. The output-zero policy is explicitly
documented in the public library contract. DATA_VERIFIED readiness bit 5 is
accepted because the current public contract explicitly assigns it.
The first independent run exposed permissive handling of missing IDENTITY and
non-XDOMAIN class. Root explicitly tightened the version-1 client schema to
require IDENTITY and XDOMAIN; the original SDD did not explicitly define a
class upper bound. The generic kernel hook remains extensible.

Deadline checks execute the real `ctl_wait`, `ctl_wait_coarse`, and finalizer
at their function boundaries, with the normal library query. They prove stage
selection, deadline preservation and error priority at those boundaries.
Current normal CLI commands do not construct an XDOMAIN START/wait campaign:
`xdomain-probe` constructs XDOMAIN but immediately proceeds CREATE to STOP.
The deadline cases do not establish a reachable XDOMAIN campaign end to end.

Run `python3 tests/core/library/stage_diag/run.py --source-root ROOT --output OUT`.
It uses system libbpf headers and `-lbpf`; optional `--libbpf-build BUILD` uses
that build's `include/` and `libbpf.a`. Exit 2 means setup/build failure; exit 1 means behavior
failure; exit 0 means all executed checks passed. Evidence belongs outside
the public source tree.
