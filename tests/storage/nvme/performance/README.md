# NVMe peer lease retirement cost screening

This directory isolates a production lifecycle hotspot at explicit OS, reference
and provider boundaries. It does not issue NVMe commands or measure kernel lock
contention, I/O completion latency or storage throughput. See the
[performance policy](../../../../docs/reference/performance-policy.md).

- **NVMe peer lease retirement: traversal cost and lifetime balance** —
  `test_nvme_peer_lease_retirement_cost.py` extracts real core acquire/release,
  file acquire/release and storage-family retirement functions from a selected
  Git revision. It checks ordinary and authority paths, foreign live batches,
  get/put balance, final mapping state, stale refusal and duplicate-release
  idempotence.
- **NVMe lease lifecycle OS-boundary harness** —
  `nvme_peer_lease_retirement_harness.c` supplies only the explicit OS/reference
  seams. The control changes release call order; it is not a new unlink algorithm
  or a production patch. Reversing one batch does not eliminate other live
  batches' list prefixes.

```sh
python3 tests/storage/nvme/performance/test_nvme_peer_lease_retirement_cost.py \
  --revision HEAD --out build/nvme-peer-lease-retirement-cost
```

The output directory must be new; the requested revision must contain the source
paths and extraction anchors. Source changes requiring different instrumentation
fail setup rather than silently falling back to old code. A successful execution
certifies lifecycle assertions and reports actual traversal counts; it does not
mean release scales linearly. The characterized linked-list implementation can
require quadratic work while those lifecycle assertions pass.

Existing interface checks include `../peer_batch/` (runtime batch ownership),
`../window_handle/` (window reuse/tenant isolation), `../passthru/` (SGL/PRP and
native passthrough), and `../uring_lifecycle/` (actual completion/recovery).
Their PASS results cannot substitute for device performance or for this cost axis.
