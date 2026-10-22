# xdev_ext

**Compose cross-device I/O with Linux kernel extensions, bounded eBPF programs, and device providers.**

**English** | [简体中文](README.zh-CN.md)

xdev_ext is a research system for connecting storage, networking, and GPU I/O through a shared execution and ownership model. The kernel manages registered memory, descriptor admission, generations, backpressure, and completion. eBPF programs construct bounded transfer and protocol plans. Device providers supply mappings, native submissions, and completion callbacks.

[Get started](docs/getting-started.md) · [Architecture](docs/architecture.md) · [Supported paths](docs/supported-paths.md) · [Documentation](docs/README.md)

## Why xdev_ext?

A cross-device pipeline must coordinate buffer ownership, device mappings, queue acceptance, and completion across every stage. xdev_ext separates these responsibilities behind common kernel and provider contracts so that a supported device capability can participate in multiple pipelines.

## Features

- **Kernel-managed memory and ownership:** registered pools, bounded windows, generations, and descriptor admission checks.
- **Programmable I/O plans:** eBPF programs construct bounded requests, copy plans, and protocol decisions within kernel-enforced contracts.
- **Composable providers:** drivers supply device mapping, native submission, synchronization, and completion for a capability.
- **Pipelined execution:** userspace configures and starts a session; the kernel drives normal batches and reports final or exceptional outcomes.
- **Explicit failure handling:** accepted native commands are tracked through completion; uncertain completion or DMA quiescence retains the affected resources.

## Quick start

On Linux, install Python 3 and a C compiler with C11, pthread, and UndefinedBehaviorSanitizer support, then run:

```bash
git clone https://github.com/shtusist/xdev_ext.git
cd xdev_ext
python3 scripts/test_host.py
```

These host checks use the project sources without preparing or booting a complete kernel. They exercise software behavior and do not establish physical DMA execution or hardware performance.

To build the kernel or optional NVIDIA components, prepare their pinned public upstream sources:

```bash
python3 scripts/prepare_sources.py --component linux
python3 scripts/prepare_sources.py --component nvidia
```

The preparation step fills missing upstream files in `kernel/` and `gpu/`, retaining the checked-in project changes. See the [build guide](docs/build.md) for dependencies, configuration, BTF, and build commands.

## How it works

| Component | Responsibility |
|---|---|
| Userspace control | Register resources, configure stages, start sessions, and observe results |
| eBPF programs | Construct bounded device and protocol plans and interpret permitted completion information |
| Kernel core | Admit descriptors, enforce ownership and generations, apply backpressure, and drain or quarantine resources |
| Device providers | Map supported memory, submit native work, synchronize DMA, and report completion or invalidation |

The [architecture guide](docs/architecture.md) explains stage composition. [Supported paths](docs/supported-paths.md) describes memory routes, device prerequisites, and compatibility limits.

## Repository guide

| Path | Contents |
|---|---|
| `kernel/` | Linux changes, UAPI, BPF programs, userspace tools, and selftests |
| `gpu/` | NVIDIA open kernel module changes and host tests |
| `scripts/` | Host-test and pinned-source preparation entry points |
| `docs/` | Build instructions, architecture, supported paths, testing, and API references |
| `sources.lock.json` | Pinned public upstream sources used to assemble the complete trees |

The checked-in trees contain project source overlays. Source preparation supplies the unchanged upstream files needed for full builds.

## Documentation and contributing

Start with the [documentation index](docs/README.md). The [testing guide](docs/testing.md) explains host, guest, and physical-device evidence. For configuration and runtime errors, see [troubleshooting](docs/troubleshooting.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and issue-report expectations.

## License and provenance

Licenses apply by component and file. Linux-derived changes retain their applicable Linux licenses and SPDX identifiers; NVIDIA-derived changes retain the applicable upstream NVIDIA notices. See [LICENSE.md](LICENSE.md) for the component license map and attribution.
