# Session path time breakdown

`run.py` generates a bpftrace program of fentry/fexit probes over the session
core and the class functions of one batch step. It runs a workload under that
program and reports the time per interval.

```sh
make -C tests/eval/breakdown check                      # host tests only
python3 tests/eval/breakdown/run.py --resolve-only      # which probes attach here
python3 tests/eval/breakdown/run.py --attach-check -- <workload>   # counts, guest ok
python3 tests/eval/breakdown/run.py --pair nvme-nic --size 4096 -- <workload>
python3 tests/eval/breakdown/run.py --emit              # print the program
```

| Interval | Function | Contains (direct catalog children) |
| --- | --- | --- |
| `drain` | `xdev_ext_mech_batch_drain` | `landed`, `build`, `core_submit` |
| `landed` (completion handling) | `xdev_ext_mech_batch_landed` | `sync_for_cpu`, `bpf_call`, `build`, `core_submit` of the next stage, READY publication |
| `build` (next-descriptor construction) | `xdev_ext_mech_build` | `sync_for_cpu`, `bpf_call`, validation |
| `sync_for_cpu` (DMA sync) | `xdev_ext_mech_sync_for_cpu` | |
| `bpf_prepare` / `bpf_build` / `bpf_complete` | `xdev_ext_mech_call`, split by member | |
| `core_submit` | `xdev_ext_mech_submit` | one class submit |
| `<class>_submit` | `nvme_xdev_ext_class_submit`, `xsk_xdev_ext_mech_submit`, `xdev_ext_ce_submit`, `xdev_ext_dma_submit`, `xdev_ext_net_submit`, `xdev_ext_socket_submit`, `xdev_ext_iaa_submit` | |
| native completion callbacks | `nvme_xdev_ext_class_end_io`, `xdev_ext_ce_complete`, `xdev_ext_dma_complete`, `xdev_ext_mech_batch_complete`, `xdev_ext_mech_batch_completion_publish` | |
| `submit_to_completion` | class submit entry to `xdev_ext_mech_batch_completion_publish` for the same batch | device time plus the class submit's own CPU time |
| `completion_to_landed` | that publish to `batch_landed` for the batch | queueing to the session worker |
| `submit_to_landed` | class submit entry to `batch_landed` for the batch | the two intervals above together |

The three cross-function intervals are keyed by the batch pointer. The
completion intervals end in `xdev_ext_mech_batch_completion_publish`, which
runs only for the winner of the completion claim. A callback that loses the
claim (a stale or duplicate ticket; the reliable AF_XDP path can call
`xdev_ext_mech_batch_complete` more than once per batch) publishes nothing
and ends no interval. A caller inside `xdev_ext_mech.c` may have the publish
inlined. Its completions then close only `submit_to_landed`, and the result
carries a `_warnings` entry when `submit_to_completion` counts fewer batches
than `submit_to_landed`. Exclusive
time subtracts only direct catalog children. A child counts as direct when no
intermediate catalog function is active on the same thread. An interrupt that
runs inside a measured function on the same thread counts in that function.

Only functions present in `/proc/kallsyms` under their exact name are attached.
`--resolve-only` reports the other catalog functions with one of two notes:

- *inlined or not built*: a static function absent from kallsyms;
- *only compiler clones*: a function that exists only as `.isra` or
  `.constprop` copies, which fentry cannot attach to.

A separate interval for these functions needs a tracepoint in the core. READY
publication (`xdev_ext_mech_life_publish`) is `static inline`. It therefore
always stays inside the `landed` exclusive time. A global function called
inside its own translation unit may also be inlined at those call sites. Its
count then covers only the out-of-line calls.

The probe syntax follows current bpftrace (`fentry:`, `args.b`). For older
releases, pass `--probe-prefix kfunc` and `--args-style arrow`. Timing refuses
a hypervisor (exit 4). `--attach-check` only counts entries and may run in a
guest. It shows that every resolved probe attaches and fires. Exit status: 0,
1 bpftrace or workload failure, 2 usage, 4 refused.

The host tests do the following without attaching anything:

- check every catalog symbol, its linkage and its batch argument against the
  kernel sources;
- generate programs from a fixture kallsyms;
- compute intervals from fixture bpftrace JSON and text output.
