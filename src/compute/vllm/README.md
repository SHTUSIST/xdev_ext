# vLLM 0.10.2 plugin

The `vllm.general_plugins` entry point is `xdev_tp_vllm:install`. It accepts
exactly vLLM 0.10.2 and checks the fixed communicator signatures. It preserves
the existing `CudaCommunicator` class, `ca_comm`, and original NCCL resources.
Only names matching `tp:<integer>` select the strict backend. PP, DP, EP, DCP
and other group operations retain their original methods. Inherited `gather`
and `all_gather` are wrapped alongside all-reduce.

Build the real native library and framework extension, then install entry-point
metadata into the fixed worker environment:

```sh
python -m pip install --no-deps --no-build-isolation \
  src/compute/torch src/compute/vllm
```

Select the compiled packages with `PYTHONPATH=<framework-output>/python`, and
set `XDEV_TP_BACKEND=strict` and `XDEV_TP_CONFIG=/path/rank-{rank}.json`. The path
can also contain `{group}`. The shipped factory reads this rank-local JSON,
checks actual group rank/device and both ranks' namespace/geometry agreement
over the existing CPU ProcessGroup, then opens the production native owner.
Configuration contains admission inputs, never serialized native pointers.
The owner opens two separate allocations/authority fds, attaches the registered
USER and XDOMAIN BPF mechanisms, creates controls/endpoints, and starts them
after native TP creation. It borrows the actual PyTorch CUDA context.

Required JSON keys are `version` (1), `rank`, `world_size` (2), `device_index`,
`mode` (1 eager or 2 GPU), `nvidia_node`, `bpf_object`, `user_bpf_object`,
`ptx_path`, `link_token`, `allocation_bytes`, `group_bytes`, `depth`,
`nr_batches`, `first_sequence`, `timeout_ns`, `communicator_id`, `epoch` and
`max_payload_bytes`. `trace_capacity` is optional. d1 requires depth 1. d2 also
requires `control_ptx_path` to identify the same existing file as the process's
`XDEV_EXT_CUDA_PTX`. BPF and PTX paths name actual compiled inputs. Link tokens
are the corresponding local native link admission values; communicator/epoch
and operation geometry agree across ranks. Native validation remains final.

The default factory owns a persistent nondefault CUDA stream. Eager calls
scope execution to that stream with caller-to-communicator and return event
dependencies; the caller's current stream is restored. The fixed upstream
`GroupCoordinator.graph_capture` hook reuses this stream, preserving the shared
`GraphCaptureContext` object passed to TP and PP by the upstream module-level
capture entry. This respects one-controller/one-stream lifetime. Capture on an
unknown stream is rejected. No permanent global `set_stream` change is made.

`XDEV_TP_FACTORY=package.module:callable` is an optional advanced override. It
must return an actual `TorchCommunicator` with admitted resources and the same
TP rank/world. The default bootstrap does not require this override.

Call `assert_backend_selected(communicator)` after TP construction. At the end
of an actual run, before teardown, call `collect_backend_evidence` with the
explicit expected local ranks; the run coordinator checks both ranks for each
TP group. Acceptance requires actual native submitted/completed, TX terminal,
RX delivery and last-use release counters. Wrapper calls, fake/meta inference,
plugin loading and source checks do not establish GPU/model execution.

The fixed upstream GroupCoordinator destroy hook waits and checks native work
before the original code destroys either ProcessGroup. Unknown native/graph
users preserve the ProcessGroups and communicator resources. Reset/destroy
model graph objects before final communicator teardown. Original NCCL/CA
resources are released only after successful native close.
