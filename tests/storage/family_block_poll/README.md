# Storage block poll behavior tests

Run the independent old-behavior baseline with a product source checkout and an empty output directory:

```sh
python3 tests/storage/family_block_poll/run.py . /tmp/storage-poll-baseline
```

For a checkout containing the public STOR6B API, add `--new`. This compiles the actual block runtime and checks actual NVMe consumers through wrappers that invoke the real family functions. `mutate.py SOURCE OUTPUT --new` runs compiled source-copy semantic mutations. Build/link/interface errors return SETUP exit2 from run.py; they are never semantic mutation detection.

GCC, Python3 and ordinary Linux userspace development headers are sufficient. The tests require neither a full Linux source assembly nor network access. They execute controlled host native/accessor boundaries, not device DMA or kernel integration.

`upstream/` contains four small GPL-2.0 excerpts from the root-retained Linux target sources at `89be9a83ccf1f88522317ce02f854f30d6115c41`: the actual hctx enum, block feature type/flag, and out-of-line blk_rq_is_poll body. Each excerpt carries its upstream source path, commit and applicable source copyright. `upstream/provenance.json` records original snapshot hashes, exact source byte/line ranges, the exact payload bytes/hash, and the packaged file hash. Only a metadata comment precedes each unchanged source payload.

The runner checks the existing `third_party/sources.lock.json` Linux commit and excerpt integrity before compiling. Advancing the Linux lock requires an explicit excerpt provenance review. The existing overlay blk_types.h remains the source of blk_opf_t and request flags; native member layouts, poll endpoints, submit/end_io and stor_done are extracted from the supplied actual source checkout at runtime. No poll predicate or family algorithm is reimplemented in test boundaries.
