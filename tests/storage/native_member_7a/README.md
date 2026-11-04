# Native member 7A characterization

These tests compile actual production storage-family and NVMe definitions with controlled external kernel APIs. The candidate runner executes the frozen original assertions together with direct family and actual registered native class hook-consumption assertions. The historical baseline runner replays the original pre-extraction NVMe layout.

Python 3 and GCC are required. From a clean checkout of the extracted implementation, the exact candidate command for CI is:

```sh
python3 tests/storage/native_member_7a/run_candidate.py --source-root "$PWD" --out "$PWD/build/native-member-7a-ci" --fixture-views --mutants
```

The output directory must not exist; each run creates it exclusively. Select a new owned output path for every execution. `SOURCE.json` records actual production/test input hashes and the selected source root. `RESULT.json` records exact compiler/run commands, exits and designated mutation assertions. Raw logs, generated C, exact include copies, field remaps and reverse-assertion evidence remain beside each case.

`candidate_adapter.h` contains only the five direct production identifier/field macros. It is local to this test directory. The runner requires no private source-freeze files or external adapter path.

`--fixture-views` is required for the frozen fixture that manually injects PEER resources after CREATE. Production borrows stable arrays at CREATE; the test's injected arrays therefore need their first/stride/count fields installed directly into the corresponding family views. This option changes only generated fixture setup. The original assertion file, literal expected values and production functions are unchanged. `assertions.reverse.c` and `REMAP.json` prove exact restoration of the frozen assertions after undoing field remaps and this fixture setup.

For historical baseline replay, use the pre-extraction source checkout explicitly:

```sh
python3 tests/storage/native_member_7a/run.py --source-root /path/to/pre-extraction-checkout --out /path/to/new-owned-baseline-results --mutants
```

The historical baseline recipe retains all 42 mutations and parses the selected old source only after baseline argument parsing. Importing baseline extraction helpers for candidate execution does not parse the historical native layout. Running baseline against the extracted candidate is outside the historical runner's source-layout scope.

A mutant counts as killed only after successful compilation and exit 1 at its designated literal assertion. Compile/setup errors, signals, sanitizer errors and wrong assertions never count as kills. GCC function-entry instrumentation retains the original authorization order observation, and the unchanged cohort also runs under UBSan.

These are host correctness characterizations. They do not establish kernel build/link success, native hardware execution, DMA reachability, performance, a second real storage member, or completion of later storage slices.
