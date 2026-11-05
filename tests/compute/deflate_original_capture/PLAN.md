# Actual CPU / IAA software deflate original capture plan

Goal: retain exact compressed bytes from unchanged CPU variable DEFLATE and IAA SOFTWARE DEFLATE on one independent fixed input, then check each actual kernel INFLATE result against that input, source immutability and pool guards. No performance claim or throughput/cost measurement.

Architecture: two sequential depth-one, four-stage native sessions: actual compressor -> read-only USER observation -> actual decompressor -> read-only USER observation. USER is the existing application handoff ABI, not a compression implementation. CPU uses its admitted default build; IAA uses a bounded BPF descriptor. No DMA stand-in, new device or CryptoAPI replacement.

Scope: create only files in this directory (<120KB sources/docs), plus read-only upstream references saved under /root/xdev_ext/tmp/compute-comp1-deflate as root authorized. No production/test-oracle edits, Git, SSH, CI, compilation, VM/module/device access or children by this author. Root owns all execution and fresh independent reviews. The writing-plans default delegation/header workflow is superseded by that explicit no-children/test-author scope.

Files: CONTRACT.md fixes input/oracle/failure rules; capture.c runs native UAPI; plans.bpf.c supplies class programs; build.sh compiles into a root-selected external output and records identities; run-guest.sh executes and emits full captured bytes; README.md gives exact root commands and existing profile hook; FREEZE.json pins this source-only test and unchanged production inputs.

- [ ] Root first freezes sources and baseline identities before executing any original capture.
- [ ] Root GCC builds capture.c; mandatory Clang compiles BPF only. Unsupported config/absent tools or output is an error, never SKIP/PASS.
- [ ] Root executes this test on matching existing strict-debug KVM profile. The pre-existing source lacks an exact-byte mode; successful creation alone cannot satisfy this test. Keep baseline raw logs on any failure. This is test-only characterization; no production implementation is authored here and no RED/GREEN execution is claimed by this author.
- [ ] Actual two compressors each produce 1..8192 bytes; retain every byte before releasing USER custody. Each actual inflater must return exactly4096 bytes matching the independent fixed input. Full source frame stays unchanged. Compressed source frames stay unchanged through INFLATE. Full pool guards and unreserved frames stay unchanged.
- [ ] Root freezes successful baseline binary/hex observations with source, compiler, config, kernel image/release and provider identities before releasing COMP-4. Byte equality between CPU and IAA is recorded, not presumed. Candidate may only compare against this original; never generate its expected bytes.

Breaks caught: wrong compressor/decompressor selection; no/oversize/truncated output; wrong propagated lengths; payload corruption; source writes; writes beyond output capacity or into unrelated frames; absent native class or missing completion. Current compressor may write anywhere inside its destination capacity, so only capacity-exterior bytes are guards; no unspecified untouched-tail assertion is invented.

## Retry2 source repair

Root reported actual F1 build-entry RED and independent diagnostic-parser RED before author GO. The revised pre-edit plan is retry2/PLAN.md; all ten v1 preimages plus original freeze remain in retry2/v1/. The formal top-level entrypoints remain active. F1 removes only the nonexistent USER configuration gate. F2 emits actual observed bytes before assertions, retains bounded failure pool/snapshots and diagnostic extraction while preserving every success check. Root owns independent parser replay, fresh SPEC/QUALITY, source publication and actual GCC/BPF/native execution; none is claimed by this author.

## Retry3 bounded-reader repair

Only F2-R1 is repaired under retry3/PLAN.md after root's reported independent RED: two fixed CASE bits replace arbitrary identifiers, final/error counters saturate with explicit overflow/omission meaning, and all accepted unambiguous data still persists with permanent diagnostic failure. Ten retry2 source preimages plus their exact freeze are in retry3/v2/. All native C/BPF/build/guest/staging files remain unchanged. Root owns actual parser replay, fresh SPEC then QUALITY and later native gates.

## Retry4 CASE status repair

Only F2-R2 is addressed under the pre-edit retry4/PLAN.md: require the actual third CASE token to equal uppercase PASS, preserving recognized native records and fixed-category permanent errors without a new body grammar. The ten retry3 formal files and exact previous freeze are preserved in retry4/v3/ with a manifest. Native C/BPF/build/guest/staging and upstream-claims.jsonl remain byte-identical. Formal FREEZE.json records all ten current identities, unchanged fourteen baseline_inputs and provenance rooted in that exact previous freeze. The source author stops at SOURCE_READY without candidate execution/import or independent-test/runtime artifact inspection. Root owns fresh SPEC then QUALITY, independent six-plus-sixteen controls and memory test, followed by real native gates and catalog registration.
