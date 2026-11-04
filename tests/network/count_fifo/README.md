# COUNT_FIFO actual-body correctness gate

This suite requires unchanged public XSK behavior and shared COUNT_FIFO rule ownership. It executes production bodies through instrumented OS/device boundaries, compares the complete stdout with a frozen old-source golden, checks direct public consumer wiring, and can compile and execute all 24 designated mutations. The unchanged sibling `tests/network/pool_dma` suite supplies the original extractor and predecessor C fixture; both remain dependencies.

Run from a canonical checkout with Python 3 and GCC:

```sh
python3 tests/network/count_fifo/run.py --source "$PWD" --mutations --out-root "$PWD/build/count-fifo"
```

`--source` is required and names the canonical repository containing `source-layout.json` and `src/`. Output defaults to its `build/count-fifo` directory. Every invocation creates a unique `count-*` directory and keeps generated bodies, the byte-identical predecessor fixture, compiler commands/stdout/stderr, runtime stdout/stderr, input hashes, structural findings and `summary.json`. Nothing edits the source or sibling fixture.

The baseline always requires runtime exit zero, the fixed golden, and executable ownership/wiring PASS. `--mutations` additionally requires the exact 24 requested mutation labels, successful compilations and every original designated check. SETUP, SURVIVED, INVALID_MUTANT and missing mutation runs fail acceptance. `--only-mutation NAME` runs a baseline plus one designated mutation for diagnosis; CI uses the full `--mutations` command.

The `disconnected_public_consumer` mutant compiles and exits zero: its detached old algorithm preserves behavior. It is killed only by the executable ownership/wiring check reporting the original named direct-consumer failure. The receipt labels this `kill_kind: ownership_wiring`; it does not count as a runtime assertion failure. The other 23 kills require their original runtime assertions. Original eleven mutants retain the predecessor execution mode; new mutants stop on their first failed assertion.

## Fixed old golden

The expected complete stdout is 89,721 bytes with SHA256 `9fc5b51ce2e82c7b6411021549e3c4291e5cbe9797b210d0af3de71d514bdf81`. These literals were frozen from the root preproducer old-source capture, before the COUNT_FIFO implementation existed. The old production commit was `f77b908392c9058e9fcb574386c81c9302a71ee6`; the independent suite readiness receipt recorded the same byte count and the old executable ownership RED. The detached peek body is also an inline literal from that old capture, used exclusively for its deliberate mutation. Neither expectation is generated from the candidate.

A separate old stdout file can supply an additional external comparison:

```sh
python3 tests/network/count_fifo/run.py --source "$PWD" --mutations \
  --compare-baseline /path/to/frozen-old-run.stdout --out-root "$PWD/build/count-fifo-external"
```

Public CI needs no private captures, freeze files, result directories or worktrees. Current canonical production and original fixture hashes are recorded for provenance; root owns exact candidate identity checks and final result registration.

## Scope

All original POOL assertions, packet literals, event assertions and TRACE prefix remain in the unchanged sibling fixture. The independent extension retains nineteen input families described in `ASSERTIONS.md`, including actual ordinary/reliable/control paths, mappings, uncertainty, cancellation, fallback, callback ordering and shared-map release. New public witnesses use real 64-chunk fixtures with a 32-chunk source partition; pure capacities 1/2/4/8 are supporting state-machine checks.

The bounded search uses its declared legal event grammar, depth/state bounds and fixed seed traces. BPF resend build, OS refs/frame moves, core terminal publication and device DMA are declared instrumented boundaries. This establishes host actual-body correctness and shared ownership for this slice. It supplies no native kernel, physical DMA, performance, full family-member migration or whole-network closure evidence.
