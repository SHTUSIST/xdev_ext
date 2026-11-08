# Bare-metal bring-up

`tools/build/baremetal.py` builds one kernel that carries every device route
at once and stages it with the NVIDIA open modules, the matching NVIDIA user
space and the GSP firmware. It never reboots, kexecs, loads modules or resets
devices.

## Kernel configuration

`tools/build/baremetal.config` is a Kconfig fragment for a distribution base
configuration. It enables the ice driver (its XDP and AF_XDP zero-copy support
is part of the driver), USB4/Thunderbolt with the XDOMAIN class, the CE, DMA,
socket and dma-buf peer classes, the strict NVMe SGL path, PCI P2PDMA with its
memory-hotplug dependencies, the Intel and AMD IOMMUs, built-in NVMe, BPF and
BTF. The NVMe bounce fallback used by KVM tests stays disabled.

Kconfig silently drops a symbol whose dependencies are unmet, so check the
final configuration after `olddefconfig`:

```bash
python3 tools/build/baremetal.py check-config "$kernel_build/.config"
```

The checker fails and names each symbol whose value is not one of the accepted
values in `REQUIRED` in the tool. ice, USB4 and XDOMAIN may be built in or
modules; the rest must be built in.

## Build and stage

Prepare the sources first (`make prepare-linux`, `make prepare-nvidia`) and
extract the official driver package of the same release as the open modules
(`sh NVIDIA-Linux-x86_64-590.48.01.run --extract-only`).

```bash
python3 tools/build/baremetal.py bringup --dry-run \
  --staging /path/to/staging --base-config /boot/config-$(uname -r) \
  --linux-src build/assembled/linux --nvidia-src build/assembled/nvidia \
  --nvidia-package /path/to/NVIDIA-Linux-x86_64-590.48.01
```

`--dry-run` prints every step, including the install steps, and writes
nothing. Without `--dry-run` the build and stage steps run and write only below
the staging directory, which must be absent or empty:

1. merge the fragment onto the base configuration, run `olddefconfig` and the
   checker; the build stops if a required symbol was dropped;
2. build `bzImage` and the modules, and `modules_install` into
   `staging/root` (stripped);
3. copy the open modules to `staging/nvidia-build`, build them against the new
   kernel with `XDEV_EXT_ENABLE_GPU_CE_DMA=1`, require a matching vermagic, and
   stage them under `lib/modules/<release>/extra/nvidia`;
4. stage the GSP firmware, `libcuda`, `libnvidia-ml`,
   `libnvidia-ptxjitcompiler` and `nvidia-smi` of the package, which must be
   the release named in the open modules' `version.mk`, plus a modprobe file
   that blacklists nouveau. The GPU CE DMA provider still needs
   `NVreg_EnableXdevExtCeDma=1` when `nvidia.ko` is loaded; the staged file
   leaves that option commented out.

The install steps are printed as skipped. `--lsmod FILE` trims the base
configuration to the modules in an `lsmod` listing before the fragment is
applied, which shortens a build on a test host. `--nvidia-src` and
`--nvidia-package` may be omitted for a kernel-only build.

## Install

On the target host, as root:

```bash
python3 tools/build/baremetal.py install --staging /path/to/staging \
  --apply --good-entry <current-permanent-default-entry-id>
```

Without `--apply` the command prints the steps and exits with status 2. With
it, the tool first refuses if any staged file would replace a different host
file or if its GRUB entry already exists; it then copies the staged tree, runs
`depmod`, `ldconfig` and `update-initramfs -c -k <release>`, appends a literal
menu entry with ID `xdev-ext-bm-<release>` to `/boot/grub/custom.cfg`, and runs
the read-only `kernel_switch.py plan` against the given good entry. The kexec
itself is left to the operator; see [kernel switching](kernel-switch.md).
`bringup --apply` runs the build, stage and install steps in one command.

## Day-1 facts

```bash
python3 tools/build/baremetal.py day1-check
```

Run as root. It prints JSON with, per NVMe controller, the SGL support field of
Identify Controller (`nvme id-ctrl -o json`, bits 1:0); per Thunderbolt/USB4
NHI, the MSI-X table size read from PCI configuration space and the number of
allocated vectors; the IOMMU units, vendor, IOMMU-related kernel parameters and
the IOMMU group type of each of these devices; and the current and maximum PCIe
link speed and width of each NVIDIA display device. The command only reads.
