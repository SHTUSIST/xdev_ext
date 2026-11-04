# Independent typed PEER A cohort

```sh
python3 tests/network/peer_lease/run.py --source-root /absolute/candidate --phase baseline --output /absolute/evidence/baseline
python3 tests/network/peer_lease/run.py --source-root /absolute/candidate --phase typed --output /absolute/evidence/typed
python3 tests/network/peer_lease/mutations.py --source-root /absolute/candidate --phase typed --output /absolute/evidence/mutants
```

The test script lives in the independent test checkout; `--source-root` selects production inputs. Exit0 is a passing control/all requested mutants detected;1 is an executed assertion failure or surviving mutant;2 is SETUP (missing actual symbol/type, compile failure or unmatched mutation). SETUP is never a semantic RED or a detected mutant.

The harness extracts actual family structures and complete runtime, peer/fd acquire/release bodies, actual NET completion-driven submit/fill/post builders/CQE result and selected XDomain ring post/callback bodies. The actual portable tracker header is compiled. Missing extraction fails hard. Native mapping/post/ring calls and OS/core-envelope boundaries are controlled; no lease, quarantine, duplicate, tracker or rollback algorithm is copied into the fixture.

The real peer implementation inserts/removes actual stable handle addresses in its intrusive mapping list. Tests distinguish active lease removal, backing quarantine and slot retention. Public body execution with controlled native answers proves software behavior only: no physical DMA, requester reachability or complete XDomain protocol/kernel build is inferred. `xd_member` is compiled for declaration fields only; selected native-ring adapters execute with a bounded native link envelope. The full XDomain class callbacks are not replaced with fake protocol logic.

Input snapshots use memcpy. Any failed setup/mutation target remains visible in evidence. `mutations.py` copies only compiler-discovered production dependencies plus explicitly selected actual source files. Root owns source integration, corresponding native/kernel acceptance and `/root/xdev_ext/test-results/` catalog registration.
