# Independent COUNT_FIFO acceptance assertions

Unchanged public behavior and shared rule ownership are separate requirements. The old runtime is expected to pass; the executable ownership/wiring checker must report named structural failures before producer GO. Setup, compiler errors, signals and timeout do not establish a semantic failure or a killed mutant.

## Frozen observations and limits

The original POOL test C file is copied byte for byte into each generated build and included with main renamed. Every original CHECK/REQUIRE invocation, packet literal, event assertion and TRACE prefix is retained; original fixture hashes are in each summary. Its tiny provider fixtures remain predecessor unit regressions. New public witnesses instead use real 64-chunk backing, mappings, descriptors and slots, invoke actual pool_admit/layout_frames, and retain a 32-chunk source partition. Batch 32 is exercised through actual ordinary submission; pure capacities 1/2/4/8 are never described as complete sessions.

The real old journal, ordinary submit, retire, cancel, stop, public/provider hooks, reliable enqueue, reliable initial submit, production resend, reliable native_done, pool lease and actual shared-map unmap bodies execute. The full portable reliable protocol header executes. The resend BPF build is a declared sealed-output boundary: it records chosen group/attempt and leaves prevalidated descriptor fixtures available; it supplies no count or journal algorithm. Device DMA, core terminal publication and OS refs/frame moves are instrumented boundaries. Frame/reference assertions distinguish definite return from UNKNOWN retention.

## Nineteen input families

1. Reserve 0/exact capacity/excess/full/fatal priority; refusal preserves start and prod, rollback changes prod only.
2. Native head selected independently from cons; PENDING and repeated DONE operations are no-ops.
3. Native tail cancellation produces a DONE hole that blocks capacity until earlier head reclamation.
4. Two batch owners cross physical ring wrap, reclaim holes and reuse; separate near-U32_MAX origin is explicitly an arithmetic translation.
5. set_only stores first entry result/fatal, keeps countdown/lease and never retires.
6. Raw native result 0/EAGAIN/EIO/ECANCELED/ENXIO/EPROTO/+1 remains separate from entry, frame, batch and fatal channels.
7. Preaccept full-ring EAGAIN is retryable; admitted native EAGAIN becomes terminal without resend.
8. Completion 0/exact/native+1/U32_MAX, repeat stop and late unmatched count do not over-retire or fall through.
9. Wakeup errors after zero/one/all three peeks cancel only pending suffix; public accepted return remains zero.
10. Shared journal stop with two batches, NATIVE prefix, DONE hole and PENDING suffix marks uncertainty before any retirement.
11. UNKNOWN POOL metadata and CONTROL native refs persist after empty cursors, repeat stop and late count.
12. stage_dead synchronously reenters stop only outside provider lock; callbacks preserve order and lock markers.
13. No-provider versus empty/stopped-provider calls reach policy/upstream only on EOPNOTSUPP; EPROTO never reaches fallback.
14. Single/batched public peek uses actual descriptors and clamps requested batch to tx_descs_capacity.
15. Ordinary all/partial/already-sent masks preserve original frame index, packet bytes, checksum, descriptor bind and sent-tag order.
16. POOL prefix failure clears only newly acquired prefix metadata and restores prod without checksum/sync/trace/tag effects.
17. Actual reliable initial submit and actual production resend reach the same enqueue and public completion, updating real protocol attempt/native-pending/deadline.
18. CONTROL tag and actual native_done preserve DATA accounting exclusion, definite HELD return/native put, stopped-map no-sync and UNKNOWN retention.
19. Metadata operations preserve descriptor/batch/index/tag payload; new view/union offsets and rollback-only-prod receive direct candidate assertions.

## Golden comparison and mutation requirements

Public snapshots contain ring cursors/FIFO/fatal/stopped, physical slot descriptor bytes/index/tag/state/result/links, each referenced batch countdown/status/uncertain/raw/cancel/err and typed POOL metadata, packet-buffer digest/tags, DMA spans/lock epochs, accounting, policy/upstream calls, callback event order, CONTROL refs/frame custody and real reliable protocol entries. Pointer addresses are normalized to owner/batch identity. Pure hashes serialize defined fields, never padding; state deduplication verifies full logical equality including batch status, uncertainty, raw error, cancellation and per-slot errors.

The bounded BFS enumerates the declared eighteen pure events to depth 8 for capacities 1/2 and depth 4 for 4/8, at most 100000 stored states and 128MiB address space. Eight fixed seeds (1,7,17,101,2026,0x12345678,0xc0ffee,0xdeadbeef) each produce 256 events per capacity. Failure diagnostics retain seed/step or BFS action replay. This finite event grammar is not universal concurrency coverage.

The eleven original semantic mutations and designated assertions are preserved in adapter. Five additional adapter mutations are runnable before extraction: set_only retires, stage_dead under lock, CONTROL UNKNOWN cleared, stop first pass removed, reliable CONTROL tag wrong. Seven shared-family mutations plus detached-public-consumer mutation are frozen for the new API: missing peek membership, unlink resets cons, tail selected from cons, fatal overwritten, accepted EAGAIN retry, wrong view stride, rollback overwrites issued, and public peek/batch rewired to an executable detached old algorithm. New API absence is SETUP. Each eventual mutant must compile and trigger its designated behavior/wiring assertion. The detached consumer additionally must preserve runtime behavior while failing direct consumer wiring; ordinary declarations do not satisfy the check.
