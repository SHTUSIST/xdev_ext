# Independent typed COPY_WINDOW contract cohort

Run with GCC + UBSan against a canonical source checkout:

```sh
python3 tests/compute/copy_window/run.py --source-root /absolute/source/root --phase baseline --output /absolute/evidence/baseline
python3 tests/compute/copy_window/run.py --source-root /absolute/source/root --phase typed --output /absolute/evidence/typed
python3 tests/compute/copy_window/mutations.py --source-root /absolute/source/root --phase typed --output /absolute/evidence/mutants
```

Exit 0 is a passing control (or all requested mutants compiled and were detected). Exit 1 is semantic failure/surviving mutant. Exit 2 is SETUP, including absent typed API, missing actual extraction symbol, compiler failure or mutation target mismatch. Never count SETUP as semantic RED or mutant detection.

`run.py` extracts the actual bind/collect/validate/stage_xfers, stage/batch/region/xfer/native ops declarations and actual per-class claim bridges when typed API exists. Existing real pure headers and UAPI are compiled directly. Native/OS and opaque session/batch/core claim boundaries are supplied by `boundary*.h`; lease algorithms are deliberately outside this Slice1 cohort. `abi.expected.txt` is the independent actual-baseline host ABI freeze, not BTF output. `baseline.c` preserves old failure output/order behavior; `typed.c` derives expected intervals and split plans independently; `consumers.c` checks actual prepared/admitted object identity and uses admitted-state perturbation to reject disconnected redundant helpers.

Mutants run in isolated copies of only exact compiler-discovered production dependencies plus CE/DMA sources. No full source views or native device emulation are created. Baseline characterization is a positive control; the new API's absence on baseline is SETUP. This suite establishes bounded host software behavior only. Native kernel GCC object and physical DMA acceptance are separate root gates.
