# One-time setup costs

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

`setup_cost` times registration and release of the same host region through
the session path and through the baseline registration interfaces. It also
reports the BPF verifier cost of each mechanism plan.

```sh
make -C tests/eval/setup_cost check          # host tests; times nothing
python3 tests/eval/setup_cost/run.py --sizes 1M..96G --umem-cap 1G --devices nvme,nic,gpu \
  --nvme-ng /dev/ng0n1 --nvme-window 0:262144 --cuda-root /usr/local/cuda
python3 tests/eval/setup_cost/run.py --counts-only --plans all
python3 tests/eval/setup_cost/run.py --prog-stats --prog-prefix nxp -- <workload>
```

For every size, each repetition maps and populates a fresh anonymous region
and reports the populate time separately. It then times the registration and
the release:

| Measure | Registration | Release |
| --- | --- | --- |
| `umem` | `IORING_REGISTER_XDEV_EXT_UMEM` | `IORING_UNREGISTER_XDEV_EXT_UMEM` |
| `mech` | session CREATE of a one-stage NVMe READ session over that UMEM, including the device's DMA mapping | session STOP |
| `xdp` | AF_XDP `XDP_UMEM_REG` | closing the socket (the kernel may defer the unpin) |
| `iou` | `IORING_REGISTER_BUFFERS` in 1 GiB iovecs | `IORING_UNREGISTER_BUFFERS` |
| `cuda` | `cudaHostRegister` | `cudaHostUnregister` |
| `cufile` | `cuFileBufRegister` of a `cudaMalloc` buffer | `cuFileBufDeregister` |

`run.py` always runs `umem` and `iou`. `--devices nvme` adds `mech`, `nic`
adds `xdp`, and `gpu` adds `cuda` and `cufile`. `cuda` and `cufile` are built
only with `CUDA_ROOT` (`run.py --cuda-root`); without it they are reported as
`not_run_capability`. The `mech` measure also needs an NVMe plan attached
first, as the guest harnesses do:

```sh
xdev_ext_mech_ctl attach --obj nxp_mech.bpf.o --map nxp_nvme_ops --pin /sys/fs/bpf/nvme
```

A kernel or device refusal is a recorded result, with the step, the errno or
device error, and the number of repetitions completed. For example, UMEM
registration is capped at 1 GiB (`xdev_ext_umem.c`), so larger sizes report
`kernel_refused` and `EINVAL`. No refused size is retried with another value.
A release failure is a failure (exit 1).

Each repetition populates the whole region, and the host is shared. Before
any `mmap`, a size that would leave less than the margin of `MemAvailable`
is therefore recorded as `host_refused` with step `mem_available`, together
with the `MemAvailable` and margin values. The default margin is the larger of
4 GiB and one eighth of `MemAvailable`; `--mem-margin SIZE` replaces it. With
`--umem-cap SIZE` (the cap read from the kernel under test), the `umem` and
`mech` measures above it are recorded as `not_run_above_cap` and populate
nothing. This status is a skip, not a kernel result.

Each `--bpf-obj` (or each `--plans` object from the mechanism build directory)
is loaded with libbpf. For each program, `bpf_prog_info` gives
`verified_insns`, the translated instruction count and the JIT size. With
libbpf 1.0 or later, the `BPF_LOG_STATS` verifier log also gives the
verification time, and the whole object load is timed. `--counts-only` reports
only the instruction counts. These counts are deterministic, so that mode may
run in a guest. Every timed mode refuses a hypervisor with exit 4.

`--prog-stats` enables BPF run-time statistics with `BPF_ENABLE_STATS` while
the workload runs. It then reports, for each struct_ops program, the run count
and run time accumulated meanwhile. This BPF time per operation includes the
statistics overhead. Keep the plan attached across the whole workload: a
program unloaded during the run is not reported.

Output is one JSON document with summaries `{n, min, median, max}` in
nanoseconds. Exit status: 0 at least one result, 1 failure, 2 usage, 4 not
run. The host tests cover the following without loading or registering
anything:

- argument parsing, the summaries and the verifier-log parser;
- the refusals, including the `MemAvailable` check and the `--umem-cap` skip,
  both before any region is mapped;
- the CUDA section, compiled against declarations of the official API subset
  it uses.
