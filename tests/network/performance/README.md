# AF_XDP interface cost screening

This directory exercises production metadata rules, not NIC throughput. Locks,
interrupt delivery, DMA coherency and contention need separate device/kernel
runs. Read [the performance policy](../../../docs/reference/performance-policy.md).

- **AF_XDP completion FIFO: capacity and DONE-hole cost bounds** —
  `test_af_xdp_completion_cost.py` compiles the actual native-count header.
  One-descriptor lookup/retirement must stay within eight accessor calls at
  capacities 64, 1024 and 65536. The legal helper stress state with alternating
  DONE holes is not certified as reachable through a particular driver's
  completion order. Suffix reclamation has a separate amortized linear bound.
- **AF_XDP completion CPU cycle without lookup instrumentation** —
  `af_xdp_native_completion_cost.c` is the runner's C harness. It separately
  times the unchanged production header, with prefaulted storage and fixed
  work. Separate non-inlined caller wrappers preserve API-like boundaries;
  their CPU cost is included. It does not time kernel locks, driver calls or DMA.

Run the entire bounded experiment from the repository root:

```sh
python3 tests/network/performance/test_af_xdp_completion_cost.py \
  --out build/af-xdp-completion-cost
```

The output directory must be new. It retains exact inputs, compiler commands,
raw samples and a JSON receipt; rebuildable executables are removed. A deliberate
behavior-preserving scan regression must fail the designated operation bound.
CPU samples and access-count instrumentation use separate builds. A successful
receipt certifies only these rules and executions, not device performance.

Existing RX backlog behavior tests live in `../xsk/xsk_xdev_ext_mech_backlog_test.py`.
Their manual progress calls do not qualify real worker wakeup latency; that
scheduling boundary remains a separate check.
