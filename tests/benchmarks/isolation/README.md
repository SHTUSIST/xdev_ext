# E8: tenants beyond the core count

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes,
comparison eligibility and performance claims.

`tenants.py` runs the multi-tenant experiment of the evaluation plan (RQ4,
E8): N tenant processes read 4 KiB blocks at random from one NVMe namespace,
each inside its own disjoint window of one prepared region, while every
tenant is restricted to the same C CPUs. For each repetition and each N in
{1, C/2, C, C+1, 1.5C, 2C, 3C, 4C} (or `--tenants`), one row of
`results.jsonl` holds every tenant's numbers, the aggregate throughput (the
sum of each tenant's verified bytes over its measured interval) and the share
of requests that took 1 ms or more. The order of N alternates between
repetitions. `summarize` gives the median, min and max over repetitions per N.

Nothing in this directory has produced a performance number. A KVM run checks
that the runner and the tenants work; its timings are not results.

## CPU control

Tenants are restricted with `sched_setaffinity` to `--cpus` inside the running
kernel; the runner refuses CPUs outside its own affinity and never takes a CPU
offline. The plan's stricter control (only C CPUs online, in a kernel we
booted ourselves on a machine nobody else uses) is an operator step outside
this runner; record it with the run.

## Arms

| Arm | Tenant | Barrier | Per-request latency |
| --- | --- | --- | --- |
| `uring` | `uring_tenant`: O_DIRECT READ_FIXED into registered host buffers, no SQPOLL, no IOPOLL | TENANT_READY, then GO to all | yes, submission to reaped completion |
| `spdk` | one `spdk_nvme_perf` per tenant: `-w randread -LL`, shared `-i` group, one core each | started together | yes, from the `-LL` histogram |
| `xdev-ext` | one `session_nvme_ce` per tenant on its window (`--session-cmd`) | started together | no: share reported as not measured |
| `custom` | `--tenant-cmd`, a JSON argv template | TENANT_READY, then GO | as the tenant reports |

Limits that matter for E8, stated so the runs are not over-read:

- `uring_tenant` reads into host memory. It is the plan's host-destination
  control (ii) and the harness check; the GPU-destination io_uring arm of the
  plan is `../nvme_gpu/bench_uring_cuda.cc`, which does not speak the tenant
  contract yet.
- SPDK processes may not share cores (SPDK multi-process documentation), so
  the multi-process shape runs one core per tenant and refuses N > C. The
  plan's SPDK arm for N > C is one process with N threads, each with its own
  qpair; it is not written. `spdk_nvme_perf` has no LBA window option, so
  every SPDK tenant reads the whole namespace. A histogram bucket that spans
  1 ms is reported apart (`straddle_1ms`) and not counted as >= 1 ms.
- `session_nvme_ce` has a linear plan only (`--pattern seq`) and whole-pass
  timing, so the xdev_ext arm here reads sequentially and has no per-request
  latency. The plan's random-request timing mode and the BPF latency
  histogram belong to that program and are not part of this runner.

## Tenant contract

A contract tenant prints `TENANT_READY {json}` after setup, waits for `GO` on
stdin, runs `--warmup` seconds uncounted and `--seconds` counted, and prints
`TENANT_RESULT {json}` with at least `ops`, `bytes_ok` (verified bytes only),
`measured_ns`, `ge_1ms` (null when not measured) and `hist_log2_us`. A tenant
that fails, exits nonzero or reports no result makes its point fail; the
aggregate then carries no throughput.

## Running

Build in the source view (`python3 tools/layout.py view`), in
`tests/eval/isolation`: `make tenant`. Then, as root:

```sh
python3 tenants.py prepare --device /dev/nvme0n1 --region-bytes 68719476736 \
  --i-understand-this-overwrites
python3 tenants.py run --arm uring --device /dev/nvme0n1 --cpus 0-5 \
  --region-bytes 68719476736 --depth 32 --verify --output results/uring
python3 tenants.py summarize results/uring
```

`make check` runs the host tests: the runner against a fake tenant (barrier,
affinity, disjoint windows, aggregation, alternation), the SPDK output parser
on a recorded-format sample, and `uring_tenant` on a regular file
(set `E8_ODIRECT_DIR` to a directory whose file system accepts O_DIRECT).
