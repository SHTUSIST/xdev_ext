# Late RTS teardown regression plan

Requirement: an authenticated RTS arriving after the receiving worker has gone,
while its endpoint remains published, must retain a live reply owner or finish
with a refusal/terminal link outcome; successful refusal consumes its sequence
exactly once. Accepted native DMA and UNKNOWN custody must remain protected.

This test catches a silent RTS enqueue into a stage whose worker cannot run.
It reuses the complete stack X3/X4/X5/family/X6 units and extracts the production
core release and kick functions without changing their bodies. Kernel OS calls
are recording boundaries. The destroy-worker boundary delivers a real sender
RTS through native control storage and the real X4 decoder/dispatch. No virtual
device or replacement protocol implementation is added.

Files: `run.py` assembles a private ordinary-copy input closure and compiles;
`cases.c` supplies the independent assertions and worker-destruction interleave.
The shared stack fixture's session storage is extended only for fields used by
the actual core release function. Unused OS/resource branches trap if entered.

Steps:

- [x] Assemble only manifest-mapped runtime inputs and the pinned NHI header.
- [x] Compile actual release/kick, complete protocol units and test driver.
- [x] Run the after-detach positive control: FAIL reply, exact sequence debit.
- [x] Run the worker-gone/before-detach case: a named reply-responsibility RED.
- [x] Deliver the command and preserved logs; production changes belong to root.

No physical device, server, performance result or complete core engine is
claimed. Session admission, release ordering and worker-kick suppression execute
the selected real core functions; unrelated batch scheduling stays the existing
stack environment. The deterministic interleave is synchronous, so it proves
the reachable ordering, not a probabilistic race frequency.

Run from the repository root with an unused output directory:

```sh
python3 tests/network/xdomain/late_rts/run.py --out /absolute/private/b4-run
```

Exit 0 means both cases pass. Exit 1 means at least one executed behavior failed;
read its named assertion. Exit 2 marks compilation failure, which is never the
required RED. The input closure, compile command, full compile log, per-case logs
and structured result stay in the output directory. The current faulty source
passes `after_detach` and fails `worker_gone_before_detach` on reply responsibility.

The positive control requires one actual FAIL, four consumed native frames and
an up link. The interleaving case observes the primary outcome before sending a
second group. This later group exposes the sequence gap; its eventual link error
cannot retroactively satisfy the first group's missing reply responsibility.

A minimal repair can make class ingress return an explicit disposition to X4:
when a stopping class has no ARMED/native-control reply reservation, it must not
silently queue a fresh RTS; X4 already owns the link-level refusal and sequence
debit under `ep_mutex`. The production interface spans
`src/network/io_uring/xdomain/xdev_ext_xdomain.h`,
`xdev_ext_xdomain_class.c`, and `xdev_ext_xdomain_ring.c`. Preserve handling for
already accepted groups, duplicates, ARMED reply reservations and UNKNOWN native
custody; a blanket rejection of all stopping-session traffic is insufficient.
Core release ordering is the demonstrated caller, not a proposed ownership
shortcut. The implementer must verify any disposition transition against its
existing lock and lifetime rules before selecting the final repair.
