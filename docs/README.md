# Documentation

Start with [getting started](guides/getting-started.md), check [supported paths](reference/supported-paths.md), then use the [build guide](guides/build.md) for a matching kernel and optional device providers.

| I want to… | Read |
|---|---|
| Run the first host checks | [Getting started](guides/getting-started.md) |
| Prepare and build the sources | [Build guide](guides/build.md) |
| Understand stage composition and ownership | [Architecture](architecture/overview.md) |
| Check devices, call shapes, and memory routes | [Supported paths](reference/supported-paths.md) |
| Run and interpret tests | [Testing](guides/testing.md) |
| Run comparison workloads and application call shapes | [Evaluation workloads](../tests/benchmarks/README.md) |
| Diagnose setup and runtime errors | [Troubleshooting](guides/troubleshooting.md) |
| Use the session interface | [Session API](reference/session-api.md) |
| Write a bounded eBPF plan | [BPF contract](reference/bpf-contract.md) |
| Add a device provider | [Provider API](reference/provider-api.md) |

See the [source layout and naming policy](project-layout.md) before adding or moving code.

The source headers define the exact ABI. The reference pages link to the corresponding declarations rather than duplicating their numeric layouts.
