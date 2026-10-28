# Getting started

Performance comparisons follow the [evaluation policy](../reference/performance-policy.md).

The first step is a host-only check. It needs Linux, Python 3, and a C compiler with C11 and pthread support. The default checks enable UndefinedBehaviorSanitizer; use `--no-sanitize` if your compiler/runtime does not provide it. It does not require a GPU, a custom kernel, or downloading the complete Linux sources.

From the repository root:

```bash
python3 tools/ci/test_host.py
```

Keep the complete output and exit status when reporting a failure. A successful host check establishes the behavior of the tests it ran; it does not establish device submission, DMA execution, or hardware performance. See [testing](testing.md) for the distinctions.

## Prepare a full source tree

For a kernel build:

```bash
make prepare-linux
```

For the NVIDIA driver changes as well:

```bash
make prepare-nvidia
```

Source preparation needs Git and network access. It obtains the pinned public upstream inputs described in `third_party/sources.lock.json`. Preparation combines the canonical project sources with upstream files under `build/assembled/linux` and `build/assembled/nvidia`. The maintained sources remain under `src/`. The complete upstream trees and Git-object cache consume substantially more disk space than the project overlay. See the [build guide](build.md) for cache selection, conflict handling and the limited offline `--check` operation.

Continue with [build instructions](build.md). Before running a device path, use [supported paths](../reference/supported-paths.md) to check its pool type, provider, mapping and device requirements. The custom interfaces require a matching patched kernel; a stock kernel can run host checks and eligible compatibility fallback tests.
