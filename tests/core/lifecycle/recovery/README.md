# UMEM frame recovery host correctness

`run.py` executes the production recovery decision and list worker, requester
coverage comparison, lifecycle claims, UMEM registry and provider release with
OS/class services represented by `boundary.c`. Each of 18 cases runs under
GCC ASan and UBSan. This is host correctness evidence; it does not exercise
native DMA, actual NVMe reset, kernel workqueue scheduling, or performance.

```sh
python3 tests/core/lifecycle/recovery/run.py --source-root . --output build/recovery-host
python3 tests/core/lifecycle/recovery/mutations.py --source-root . --output build/recovery-mutants
```

The covered producer/consumer cases recover the original frame, claim a fresh
generation, reject the old token and repeat recovery without a second release.
Negative cases retain all lifecycle words, metadata, custody and UMEM bytes:
missing, same-epoch or another requester's proof; unsettled work or live refs;
failed unbind/release; stale producer/consumer claims; another frame or active
consumer; an active transform; and a batch whose second frame has a stale token.
A separate live borrower keeps its complete page, valid length and claim.

`reserved-output` calls the real frame-recovery helper before final destruction:
it requires the retired claim to become FREE while custody remains HELD for the
transform reservation. Final class unreserve is an explicit boundary and is not
certified by this case. Active transforms remain quarantined.

`mutations.py` changes generated C in its output directory only. Its four
intentional defects omit claim retirement, reuse a generation, clear the shared
lifecycle pool, and retire an early frame before full-set validation. A mutant
counts as detected only when a named recovery assertion exits with status 1;
compiler failures and sanitizer crashes do not count. Production files remain
unchanged. Source input hashes and the unchanged-input check fix the scope of a
run when the workspace contains an uncommitted production patch.
