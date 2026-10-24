"""CUDA sources with dependency-specific builders outside the eight shared arms.

This is a source-to-entrypoint inventory, not a build receipt. The shared
build_cuda_arms.py command neither executes these entries nor counts them as
built. Each entrypoint enforces its own dependencies and owns its own receipt.
"""

DEDICATED_BUILDERS = (
    {
        "name": "bam_native",
        "sources": ("bam/bench_native.cu",),
        "entrypoint": "bam/build_native.py",
        "required_args": ("--upstream", "--cuda-root", "--output"),
        "dependency_lock": "bam/native.lock.json",
    },
)
