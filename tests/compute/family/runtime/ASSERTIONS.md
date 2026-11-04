# Independent copy-runtime v2 assertions

Authority: root-frozen compute-copy-runtime-v2, source078dcc407c4807646b99d98b2aa14ea105d96895, unchanged v1 CONTRACT.md/PLAN.md plus overriding REPAIR-DELTA.md. V1 source645ebb5c77b9a7b24425b252841eb5135500f810 and every original receipt/expected file remain immutable historical evidence.

All independently frozen v1 assertions apply unchanged except the four precise CE observations in REPAIR-DELTA D6. The exact old assertion text is preserved in the new artifact namespace as v1-ASSERTIONS.md. Completion/CQE status asymmetry, native ABI, registry capacity/allocation order, tickets, owner phases, transfer lifetime, PRIVATE/UNKNOWN retention, DMA behavior and poll behavior have no permitted delta.

The four CE repair expectations were frozen in the v2 artifact EXECUTION.md before executable adaptation:

- D6.1: Requested native ops/start/len record and its initial hold precede either native bind hook. Bind success clears only the transient hold; second allocation ENOMEM precedes all native hooks and checked rollback drops the selected pin exactly once.
- D6.2: Native region zero/rewrite/short output cannot change C-owned native ops or requested interval. Compatibility region.ops is restored after bind_region; actual submit/unmap/module owner remain selected native ops even if compatibility metadata is later poisoned.
- D6.3: Foreign overlapping cleanup/bind hold yields EAGAIN before native entry/cookie arm, including an active same-batch next stage. A lone own hold yields EBUSY. When both foreign and own holds exist, foreign EAGAIN wins in the repaired existing order. Disjoint requested ranges and distinct native ops remain independent; CE gains no DMA scope authority.
- D6.4: Native unmap begins only with configured record and cleanup hold present. Either refusal retains record/hold plus remaining handles/native pin. Successful host then refused region retains hostNULL; retry skips host. Both handles clear before one locked hold-drop/range-detach; only full success frees typed stage/provider pin.

Exact inherited-observation allowance: indices1 and3 of the 297-line v1 trace change only lease0→1/cleanup0→1 under D6.1; indices4 and244 change only those same two fields under D6.4. The other293 lines must be byte equal, including every DMA/ABI/CQE/XFER line. D6.2/D6.3 additional vectors are appended separately after V2-ADDITIONAL-BEGIN and mapped to their explicit delta sections.

For candidate-to-v2 comparison there is zero allowed delta. Missing new common runtime remains SETUP/NOT_IMPLEMENTED. Host repair/extraction evidence does not certify physical DMA/quiescence. The original ROOT-FREEZE-v2.json recorded actual repaired CE GCC as a pending root gate. Later kernel build and integration results remain separate root-owned evidence; these host assertions do not establish that gate.
