# Build

Run commands from the repository root unless a command explicitly changes directory. The source overlay targets Linux 6.16-rc7 and NVIDIA open kernel modules 590.48.01. Exact public upstream inputs are pinned in `third_party/sources.lock.json`.

## Host checks

Linux, Python 3, and a C11 compiler with pthread support are needed for the compact host entry point. The default checks also need UndefinedBehaviorSanitizer compiler/runtime support:

```bash
python3 tools/ci/test_host.py
```

Use `--no-sanitize` if that runtime is unavailable, and report that choice with the result. `CC` selects the host compiler. This path does not require a complete upstream kernel. See [testing](testing.md) for what the checks establish.

## Prepare upstream files

```bash
make prepare-linux
make prepare-nvidia
```

Preparation requires Git and network access to the pinned public upstreams. It assembles upstream files and the canonical project overlay in `build/assembled/linux` and `build/assembled/nvidia`. Edit maintained files under `src/`; generated assembly trees are build inputs. Downloaded inputs and generated build files are not project changes. The default Git-object cache is `build/upstream`; use `--cache` to choose another location. Allow space for that cache, the complete source trees and subsequent build outputs. The script streams Git archives without storing a separate tar or extracted upstream copy. After fetching, it checks conflicts and a conservative write-space budget before filling files. Concurrent disk use, quotas or later I/O errors can still interrupt a run; rerun preparation after resolving the error.

Existing matching base files are retained. A different untracked upstream file causes an error; `--replace-base` explicitly permits replacing such files and leaves tracked overlay files untouched. This option uses a conservative space estimate for replacement files as well.

For a quick local check:

```bash
python3 tools/build/prepare_sources.py --component linux --check
```

`--check` checks the assembly marker, manifest receipt, canonical overlay copies and required files against the lock. It does not verify every upstream file or the remote ref, and does not fetch. Ordinary preparation fetches the named ref every time, requires its peeled commit to match the pin, and stops on fetch failure or ref drift before filling files. `--help` describes all arguments.

## Linux kernel

A full build needs GNU make, a supported GCC toolchain, binutils, Python 3, flex, bison, OpenSSL development headers, libelf development headers, and `pahole` for BTF. Distribution package names vary. Use a configuration appropriate for the target architecture and devices.

For an x86-64 configuration:

```bash
kernel_build="$PWD/build/kernel"
make -C build/assembled/linux O="$kernel_build" x86_64_defconfig
make -C build/assembled/linux O="$kernel_build" menuconfig
```

Enable `CONFIG_IO_URING`, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_XDP_SOCKETS`, `CONFIG_IO_URING_XDEV_EXT_BPF_POLICY`, and `CONFIG_XDEV_EXT_MECH`, together with their dependencies. Select the required class options: `CONFIG_XDEV_EXT_MECH_CE`, `CONFIG_XDEV_EXT_MECH_DMA`, `CONFIG_XDEV_EXT_MECH_IAA`, or `CONFIG_XDEV_EXT_MECH_SOCKET`. The definitions and dependencies are in [io_uring/Kconfig](../../src/core/io_uring/Kconfig).

`CONFIG_XDEV_EXT_MECH_ZEROCOPY` selects the strict NVMe data-SGL path. `CONFIG_XDEV_EXT_MECH_KVM_BOUNCE` is a distinct test-only option available when strict mode is disabled; its payload-copy behavior changes the interpretation of results.

Then build:

```bash
make -C build/assembled/linux O="$kernel_build" olddefconfig
make -C build/assembled/linux O="$kernel_build" -j"$(nproc)" vmlinux bzImage modules
```

Check the resulting `.config`: Kconfig can disable an option whose dependencies are unmet. The resulting `vmlinux` supplies the BTF required by the matching BPF programs. Boot and module installation depend on the chosen target environment; these build commands do not install or load modules.

## Control tools and BPF objects

`make` prints the available root commands. `make source-view` materializes
isolated copies at native/logical paths for existing Makefiles. The view is not
a Git checkout; `source-layout.json` maps every maintained input back to the
canonical repository. Do not edit generated source-view files.


Install libbpf, libelf and zlib development files, Clang with the BPF target, and `bpftool`. Build against the BTF of the configured xdev_ext kernel:

```bash
kernel_build="$PWD/build/kernel"
make source-view
make -C build/source-view/kernel/tools/xdev_ext_mech \
  BUILD_DIR="$PWD/build/mech" VMLINUX_BTF="$kernel_build/vmlinux"
make -C build/source-view/kernel/tools -f Makefile.xdev_ext_policy \
  BUILD_DIR="$PWD/build/policy" VMLINUX_BTF="$kernel_build/vmlinux"
```

The first target builds mechanism tools and class BPF objects; the second builds the reference policy and loader. A stock host's BTF need not contain the project types and kfuncs. Use BTF from the intended target kernel rather than selecting the host BTF by convenience.

Build the compatibility library in the same generated source view:

```bash
make -C build/source-view/kernel/tools -f Makefile.unified_ops
```

The default library output is `build/source-view/kernel/tools/.unified-build/libio_uring_unified.so`.

## NVIDIA open kernel modules

Prepare the NVIDIA sources and first complete the target kernel build. Use the matching compiler toolchain, kernel configuration and symbol versions:

```bash
kernel_build="$PWD/build/kernel"
make -C build/assembled/nvidia modules -j"$(nproc)" \
  SYSSRC="$PWD/build/assembled/linux" SYSOUT="$kernel_build" \
  XDEV_EXT_ENABLE_GPU_CE_DMA=1
```

The provider feature switch is explicit. NVIDIA userspace components and GSP firmware must match release 590.48.01. A successful module build establishes compilation and linkage against the selected kernel, while runtime requires a compatible GPU and driver stack. See [supported paths](../reference/supported-paths.md) before choosing a device route.
