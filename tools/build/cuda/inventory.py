"""CUDA and C++ sources with dedicated build or host-contract entrypoints.

This is a source-to-entrypoint inventory, not a build receipt. The shared
build_cuda_arms.py command neither executes these entries nor counts them as
built. Each entrypoint enforces its own dependencies; build entrypoints own their
receipts, and host-contract entrypoints own their test results. Optional kind
and needs fields distinguish SDK owner builds from host tests. The shared
sources.lock.json pins project kernel/NVIDIA inputs, not the CUDA SDK; SDK
identity is recorded by the real owner build receipt.
"""

DEDICATED_BUILDERS = (
    {
        "name": "peer_cuda_library_consumer",
        "sources": ("tp/cuda_library_link_test.cc",),
        "entrypoint": "tp/build.py",
        "required_args": ("--cuda-home", "--out"),
        "dependency_lock": "../../sources.lock.json",
        "kind": "cuda-owner",
        "needs": ("cuda-sdk", "libbpf"),
    },
    {
        "name": "tp_collectives",
        "sources": ("tp/xdev_tp.cc", "tp/xdev_tp.cu",
                    "tp/tests/public_api_link.cc", "tp/tp_library_link_test.cc"),
        "entrypoint": "tp/build_collectives.py",
        "required_args": ("--source-root", "--cuda-home", "--base-build", "--out"),
        "dependency_lock": "../../sources.lock.json",
        "kind": "cuda-owner",
        "needs": ("cuda-sdk", "built-peer-cuda-library", "libbpf"),
    },
    {
        "name": "tp_algorithm_contract",
        "sources": ("tp/tests/native_algorithm_probe.cc",),
        "entrypoint": "tp/tests/algorithm_resume_test.py",
        "required_args": ("--source-root", "--output"),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": (),
    },
    {
        "name": "bam_native",
        "sources": ("bam/bench_native.cu",),
        "entrypoint": "bam/build_native.py",
        "required_args": ("--upstream", "--cuda-root", "--output"),
        "dependency_lock": "bam/native.lock.json",
    },
    {
        "name": "xdomain_owner",
        "sources": ("xdomain/check_contract.c", "xdomain/epoch_control.c",
                    "xdomain/gpu_adapter.cc", "xdomain/agent_supervisor.cc",
                    "xdomain/xdomain_agent.cc", "xdomain/native_trace_owner.cc",
                    "xdomain/xdomain_gpu_pattern.cu"),
        "entrypoint": "xdomain/build.py",
        "required_args": ("--cuda-home", "--out"),
        "dependency_lock": "../../sources.lock.json",
        "kind": "cuda-owner",
        "needs": ("cuda-sdk", "libbpf"),
    },
    # These entries compile and run host contracts, never GPU benchmarks.
    # Their sources are the test-owned units; production dependencies above
    # are compiled by the same entrypoints without duplicate ownership here.
    {
        "name": "xdomain_gpu_contract",
        "sources": ("xdomain/gpu_contract_test.cc",),
        "entrypoint": "xdomain/test_gpu_contract.py",
        "required_args": (),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": ("cuda-headers",),
    },
    {
        "name": "xdomain_native_trace_owner_contract",
        "sources": ("xdomain/native_trace_owner_test.cc",),
        "entrypoint": "xdomain/test_native_trace_owner.py",
        "required_args": (),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": (),
    },
    {
        "name": "xdomain_durable_failure_contract",
        "sources": ("xdomain/durable_failure_test_owner.cc",),
        "entrypoint": "xdomain/test_durable_failure.py",
        "required_args": (),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": (),
    },
    {
        "name": "xdomain_create_refusal_contract",
        "sources": ("xdomain/create_refusal_test_owner.cc",),
        "entrypoint": "xdomain/test_create_refusal.py",
        "required_args": (),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": (),
    },
    {
        "name": "xdomain_retention_contract",
        "sources": ("xdomain/retention_test_owner.cc",),
        "entrypoint": "xdomain/test_retention.py",
        "required_args": (),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": (),
    },
    {
        "name": "xdomain_owner_close_contract",
        "sources": ("xdomain/owner_close_test.cc",),
        "entrypoint": "xdomain/test_owner_close.py",
        "required_args": (),
        "dependency_lock": "../../sources.lock.json",
        "kind": "host-contract",
        "needs": ("cuda-headers", "libbpf"),
    },
)
