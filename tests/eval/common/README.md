# Shared evaluation accounting

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

Tools that any evaluation arm can run around its harness command. `make check`
runs their host tests against fixed perf, `/proc` and sysfs fixtures. These
tests open no counters and time nothing.

## CPU, DRAM and PCIe per payload byte: `cpu_account.py`

```sh
python3 tests/eval/common/cpu_account.py --arm nvme-nic-session \
  --payload-json-key verified_bytes --elapsed-json-key elapsed_s \
  --poller-cpus 7 --uncore --out receipt.json -- <harness command>
```

The harness runs in its own cgroup v2, `xdev_eval/<arm>-<pid>`, which the
workload joins before it execs. An inner `perf stat -a -A -G` counts `cycles`,
`cycles:u`, `cycles:k`, `instructions` and `task-clock` for each CPU, but only
while tasks of that cgroup are running. io_uring io-wq and SQPOLL threads
belong to the harness process and stay in the cgroup.

Kernel threads are never in that cgroup. The session worker is created with
`kthread_run_worker(0, "xdev_ext_mech/%llu", ...)` in
`io_uring/xdev_ext_mech.c` and lives in the root cgroup, and it runs the
drain, completion handling, BPF calls and class submits. Without the step
below the session arm would be charged too little. The tool therefore samples,
every `--kthread-interval` seconds (default 0.1), every task whose comm fully
matches a `--kthread-comm` regex (default `xdev_ext_mech/\d+`; repeat the
option for provider threads). For each such task it reads the runtime from
`/proc/<pid>/schedstat`, or from the `stat` utime+stime ticks when schedstat
is absent, and adds the runtime during the run to `cores_charged`. A thread
created during the run is charged from zero. A thread that exits between two
samples may have run up to one interval more; `kthreads.tail_bound_s` reports
that bound. perf cannot count cycles for these threads, because system-wide
`--per-thread` takes its thread list from `/proc` when perf starts
(`tools/perf/util/thread_map.c`), before the session creates its worker.
`kthread_cycles` is therefore `null`.

An outer system-wide `perf stat -a -A` (no `-G`) counts `cycles` and
`cycles:k` of the whole machine. `/proc/stat` gives the busy, hardirq (field
5) and softirq (field 6) time of all CPUs over the same interval. With
`--uncore` (or any `--pcie-event`), the outer perf stat also counts the memory
controller events and each `--pcie-event` (for example a free-running IIO
bandwidth event of the platform). Each event must exist under
`/sys/bus/event_source/devices`, or the tool refuses to run. The default DRAM
events are `uncore_imc/cas_count_read/` and `uncore_imc/cas_count_write/`.
`--imc-event READ --imc-event WRITE` replaces them; a unitless count of the
replacement is converted with `--imc-count-bytes` (default 64).

What the receipt attributes to the arm, and what it reports only for the
whole system (the receipt repeats this under `account.attribution`):

- attributed: the cgroup's cycles, user and kernel cycles, instructions and
  task-clock, and the runtime of the matched kthreads;
- system-wide only: work in shared workqueue kworkers (the copy-engine
  progress poll, peer NET work and session reap all run on
  `system_unbound_wq`), hardirq and softirq time, and other tenants. These
  appear in `system_cycles`, `system_busy_cores`, `hardirq_cores_system`,
  `softirq_cores_system` and `unattributed_busy_cores`. An interrupt that hit
  an arm task or a matched kthread may be counted both there and in the arm.
  Run comparisons on an otherwise idle host, and compare the system figures
  of the arms as well. `/proc/stat` interrupt time is exact only with
  `CONFIG_IRQ_TIME_ACCOUNTING`; otherwise it is tick-sampled.

The receipt reports the following:

- cycles, user cycles and kernel cycles per payload byte, and the IPC (cgroup
  only);
- `cores_measured`: the cgroup's task-clock divided by the wall time;
- `kthread_cores`: matched kthread runtime divided by the wall time;
- `cores_charged`: the measured cores on the other CPUs, plus one full core
  for each `--poller-cpus` CPU, plus `kthread_cores`. A pinned polling core
  cannot serve other work even while it spins idle, so it is charged whatever
  its measured busy time. A kthread whose affinity lies inside the poller CPUs
  is not charged a second time;
- `core_seconds_charged_per_GB`;
- `system_cycles`, `system_kernel_cycles`, `system_cycles_per_payload_byte`,
  `system_busy_cores` and `unattributed_busy_cores` (system busy cores minus
  the cgroup and kthread cores);
- `hardirq_cores_system` and `softirq_cores_system`;
- DRAM bytes per payload byte. A CAS count is one 64-byte line; a value perf
  prints in MiB is converted by that unit;
- each other uncore event, and its bytes per payload byte when perf prints a
  byte unit. A raw count is reported without a guessed conversion.

The payload size comes from `--payload-bytes N`, or from `--payload-json-key
KEY`: the dotted key in the last JSON object line that the harness printed.

### Wall time

Every counter covers perf's own counting window, from perf's start to the
harness's exit. perf in CSV mode does not print that window, so the tool uses
its own wall time around the perf command as the denominator of the core
figures. That time also contains perf and shell startup and teardown, so the
core figures of a short run come out slightly low. A run shorter than
`--min-wall-s` (default 10 s) therefore gets status `too_short` and exits 1.
The rate uses the harness's own timed span when `--elapsed-json-key KEY`
names it in the harness JSON (`rate.rate_wall_source` is then `harness`).

### Equal-throughput comparisons

`--target-rate BYTES_PER_S` gives the harness a byte rate. The rate is passed
either as `--rate-flag=FLAG` (appended to the harness argv as `FLAG VALUE`)
or as `--rate-env VAR`. The tool then compares the achieved payload rate with
the target. A run outside `--rate-tolerance` (default 5%) gets status
`rate_mismatch` and exits 1, so it cannot enter an equal-throughput figure by
accident. Each harness implements its own rate limiting; this tool only
passes the target and checks the result.

Exit status: 0 accounted, 1 harness failure, rate mismatch or too short, 2
usage, 4 refused. The tool refuses a hypervisor, a missing cgroup v2, perf or
the privilege to create a cgroup, and a missing PMU event. Counters inside
virtual machines are not used as performance evidence. `--dry-run` prints
the exact perf commands and needs none of these. The host tests include an
end-to-end run with a fake perf and a fake `/proc` in which a matched kthread
appears during the run; its runtime reaches `cores_charged`.

## IOMMU mode receipt: `iommu_receipt.py`

```sh
python3 tests/eval/common/iommu_receipt.py --device 0000:17:00.0 \
  --device 0000:65:00.0 --expect strict --out iommu.json
```

The receipt records the following:

- for each named PCI device, its IOMMU group, group type and driver;
- all groups and IOMMU units;
- the `iommu`, `iommu.strict`, `iommu.passthrough`, `intel_iommu` and
  `amd_iommu` boot parameters;
- the kernel's `CONFIG_IOMMU_DEFAULT_*` choice.

Group types map to modes as `drivers/iommu/iommu.c` prints them: `DMA` is
strict, `DMA-FQ` is lazy, and `identity` is passthrough. A device without an
`iommu_group` link is `off`. An IOMMU sensitivity campaign records one receipt
per boot configuration next to each result. `--expect` makes a run under the
wrong mode fail. The receipt does not count IOTLB invalidations.

## Evaluation data provenance: `check_eval_data_provenance.py`

```sh
python3 tests/eval/common/check_eval_data_provenance.py \
  --data-dir <paper>/eval_data --plot-script <paper>/plot_eval_suite.py
```

The tool only reads the CSV files. Each CSV must begin with comment lines that
name the product commit, the harness and the run directory, either on one line

```text
# provenance: source_sha=<7-40 hex> harness=tests/eval/<dir>/run.py run_dir=<path>
```

or as separate `# source_sha:`, `# harness:` and `# run_dir:` lines.
Independently, the tool flags a file whose name, comments or column names
call it an estimate, preview, model or projection. With `--plot-script`, the
report marks which files the plotting script names. Exit status: 0 every file
passes or `--report-only`, 1 some file fails, 2 no CSV found. A flagged word
is a signal for review, not a verdict: a comment saying that an older estimate
was replaced is also flagged.
