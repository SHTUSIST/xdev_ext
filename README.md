# xdev_ext

Performance comparisons follow the [evaluation policy](docs/reference/performance-policy.md).

**Coordinate DMA devices over shared, pinned host pages with Linux kernel extensions, bounded eBPF programs, and device providers.**

**English** | [简体中文](README.zh-CN.md)

xdev_ext is a research system for coordinating storage, networking, and GPU DMA over the same shared, pinned host pages. Its common basis is registered host pages, native descriptors, DMA completion, and ownership handoff. NVMe, NIC, and GPU stages each use their own native descriptors to access these pages. The kernel manages the page pool, descriptor admission, generations, backpressure, and ownership; eBPF programs construct bounded transfer and protocol plans; device providers supply device-specific mappings, native submissions, synchronization, and completion callbacks.

[Get started](docs/guides/getting-started.md) · [Architecture](docs/architecture/overview.md) · [Supported paths](docs/reference/supported-paths.md) · [Documentation](docs/README.md)

## Why xdev_ext?

Storage, networking, and GPU stacks manage their buffers and completion semantics separately, making it difficult to reuse the same host pages across devices or compose their operations. xdev_ext coordinates registered host pages, native descriptors, DMA completion, and ownership handoff through common kernel and provider contracts, so a supported device capability can participate in multiple pipelines.

The main path uses shared host memory and does not require direct P2P DMA between device-local memories. Registering a logical page pool once establishes page registration and lifetime; it does not give every device a single shared DMA mapping or address. Each device/provider needs the mappings appropriate to its device and IOMMU domain, with its own DMA addresses, reachability, transfer direction, synchronization, and completion lifetime.

## Features

- **Shared host-page DMA coordination:** NVMe, NIC, and GPU stages use their own native descriptors over registered, pinned host pages, with explicit completion and ownership handoff.
- **Kernel-managed memory and ownership:** registered pools, bounded windows, generations, descriptor admission checks, and resource lifetimes.
- **Programmable I/O plans:** eBPF programs construct bounded requests, copy plans, and protocol decisions within kernel-enforced contracts.
- **Composable providers:** drivers supply per-device DMA mappings, native submission, synchronization, and completion for a capability through a common contract.
- **Pipelined execution:** userspace configures and starts a session; the kernel drives normal batches and reports final or exceptional outcomes.
- **Explicit failure handling:** accepted native commands are tracked through completion; uncertain completion or DMA quiescence retains the affected resources.

## Quick start

On Linux, install Python 3 and a C compiler with C11, pthread, and UndefinedBehaviorSanitizer support, then run:

```bash
git clone https://github.com/shtusist/xdev_ext.git
cd xdev_ext
python3 tools/ci/test_host.py
```

These host checks use the project sources without preparing or booting a complete kernel. They exercise software behavior and do not establish physical DMA execution or hardware performance.

To build the kernel or optional NVIDIA components, prepare their pinned public upstream sources:

```bash
make prepare-linux
make prepare-nvidia
```

The preparation step assembles the pinned upstream and canonical project sources into `build/assembled/linux` and `build/assembled/nvidia`. Edit the maintained sources under `src/`; assembled trees are generated build inputs. See the [build guide](docs/guides/build.md) for dependencies, configuration, BTF, and build commands.

## How it works

| Component | Responsibility |
|---|---|
| Userspace control | Register shared host pages and other resources, configure stages, start sessions, and observe results |
| eBPF programs | Construct bounded device and protocol plans and interpret permitted completion information |
| Kernel core | Manage the shared page pool, admit descriptors, enforce ownership and generations, apply backpressure, and drain or quarantine resources |
| Device providers | Map pages for each device and IOMMU domain, submit native descriptors, synchronize DMA, and report completion or invalidation |

Across stages, DMA completion and ownership handoff govern when the next device may use the same host pages. GPU copy-engine transfers still move data between host memory and VRAM; avoiding CPU payload copies depends on the supported path. An ordinary socket sink performs native socket copying. Optional peer-memory paths use a separate device-memory allocation and mapping contract.

The [architecture guide](docs/architecture/overview.md) explains stage composition. [Supported paths](docs/reference/supported-paths.md) describes memory routes, device prerequisites, and compatibility limits.

## Repository guide

```text
src/
  core/                 shared kernel contracts and lifecycle
  compute/              CPU, CE, IAA, CUDA and NVIDIA integration
  storage/              NVMe and block integration
  network/              NIC, socket, XDP and Thunderbolt/XDOMAIN
  lib/ cli/ frontend/ bpf/
examples/               runnable demonstrations
tests/                 component, integration and benchmark tests
docs/                  public guides, architecture and references
tools/                 build, CI, packaging and analysis entrypoints
third_party/           pinned dependencies and provenance
build/                 generated source views and build outputs
```

The [source layout and naming policy](docs/project-layout.md) defines permanent
ownership and directory names. GPU integration lives under `src/compute/nvidia`;
compute, storage and network remain sibling families. The canonical mapping is
`source-layout.json`; dependency pins are in `third_party/sources.lock.json`.
Linux/NVIDIA native paths are projected only into generated assembled trees or
`build/source-view`. The source view is an isolated copy workspace, not a Git
checkout; source provenance comes from the canonical repository and manifest.

## Documentation and contributing

Start with the [documentation index](docs/README.md). The [testing guide](docs/guides/testing.md) explains host, guest, and physical-device evidence. For configuration and runtime errors, see [troubleshooting](docs/guides/troubleshooting.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and issue-report expectations.

## License and provenance

Licenses apply by component and file. Linux-derived changes retain their applicable Linux licenses and SPDX identifiers; NVIDIA-derived changes retain the applicable upstream NVIDIA notices. See [LICENSE.md](LICENSE.md) for the component license map and attribution.
