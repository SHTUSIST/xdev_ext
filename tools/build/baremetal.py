#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bare-metal bring-up for the xdev_ext kernel and NVIDIA open modules.

check-config  verify a final .config against the deployment requirements.
bringup       build the kernel from a distribution base config plus
              baremetal.config, install its modules into a staging directory,
              build the NVIDIA open modules against it with the GPU CE DMA
              provider, and stage the matching NVIDIA user space and GSP
              firmware.  --dry-run prints every step and writes nothing.
              Without --apply, nothing is written outside the staging
              directory and the install steps are only printed.
install       copy an existing staging tree onto this host, generate the
              initramfs and a literal GRUB custom.cfg entry, and run the
              read-only kernel_switch.py plan.  Requires --apply and root.
day1-check    print read-only hardware facts: NVMe SGL support, Thunderbolt
              NHI MSI-X table size, IOMMU mode, NVIDIA GPU PCIe link.

Nothing here reboots, kexecs, loads modules or resets devices.
"""
import argparse
import filecmp
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
FRAGMENT = HERE / 'baremetal.config'
KERNEL_SWITCH = HERE.parent / 'boot' / 'kernel_switch.py'

Y, YM, N = frozenset('y'), frozenset('ym'), frozenset('n')
# Accepted values on the final .config.  Kconfig silently drops a symbol whose
# dependencies are unmet, so this is checked after olddefconfig.
REQUIRED = {
    'MODULES': Y, 'MODULE_UNLOAD': Y,
    'BPF': Y, 'BPF_SYSCALL': Y, 'BPF_JIT': Y, 'DEBUG_INFO_BTF': Y,
    'IO_URING_XDEV_EXT_BPF_POLICY': Y, 'XDP_SOCKETS': Y, 'XDP_SOCKETS_XDEV_EXT_POLICY': Y,
    'XDEV_EXT_MECH': Y, 'XDEV_EXT_MECH_CE': Y, 'XDEV_EXT_MECH_DMA': Y,
    'XDEV_EXT_MECH_ZEROCOPY': Y, 'XDEV_EXT_MECH_KVM_BOUNCE': N,
    'XDEV_EXT_MECH_SOCKET': Y, 'DMA_SHARED_BUFFER': Y, 'XDEV_EXT_PEER_DMABUF': Y,
    'MEMORY_HOTPLUG': Y, 'MEMORY_HOTREMOVE': Y, 'MIGRATION': Y,
    'SPARSEMEM_VMEMMAP': Y, 'ZONE_DEVICE': Y, 'PCI_P2PDMA': Y,
    'PCI': Y, 'PCI_MSI': Y,
    'IOMMU_SUPPORT': Y, 'INTEL_IOMMU': Y, 'AMD_IOMMU': Y,
    'BLK_DEV_NVME': Y,
    'NET_VENDOR_INTEL': Y, 'ICE': YM,
    'USB4': YM, 'XDEV_EXT_MECH_XDOMAIN': YM,
}
NV_MODULES = ('nvidia', 'nvidia-uvm', 'nvidia-modeset', 'nvidia-drm', 'nvidia-peermem')
GSP_FIRMWARE = ('gsp_ga10x.bin', 'gsp_tu10x.bin')
USER_LIBS = ('libcuda', 'libnvidia-ml', 'libnvidia-ptxjitcompiler')
LIBDIR = 'usr/lib/x86_64-linux-gnu'
MODPROBE_CONF = '''# Installed by tools/build/baremetal.py.
blacklist nouveau
# The GPU CE DMA provider is off unless nvidia.ko is loaded with it:
# options nvidia NVreg_EnableXdevExtCeDma=1
'''
# nvidia.ko does not create /dev/nvidia*; without a distribution NVIDIA package
# nothing else would.  udev runs nvidia-modprobe as root when the nvidia PCI
# driver registers: -c0 creates /dev/nvidiactl and /dev/nvidia0, -u loads
# nvidia-uvm and creates /dev/nvidia-uvm{,-tools}.
UDEV_RULE_PATH = 'etc/udev/rules.d/60-xdev-ext-nvidia.rules'
UDEV_RULE = '''# Installed by tools/build/baremetal.py.
# Creates /dev/nvidiactl, /dev/nvidia0 and /dev/nvidia-uvm* once nvidia.ko binds.
ACTION=="add", DEVPATH=="/bus/pci/drivers/nvidia", RUN+="/usr/bin/nvidia-modprobe -c0 -u"
'''
USB4_NHI_CLASS = '0x0c0340'
# Intel Thunderbolt 1-3 and Ice Lake NHIs report PCI_CLASS_SYSTEM_OTHER
# (0x088000) and are matched by device ID in drivers/thunderbolt/nhi.c.
LEGACY_NHI_CLASS = '0x088000'
LEGACY_INTEL_NHI_IDS = frozenset((
    '0x1513', '0x1547', '0x156a', '0x156c',                       # Thunderbolt 1/2
    '0x1575', '0x1577', '0x15bf', '0x15d2', '0x15d9', '0x15dc',   # Alpine Ridge
    '0x15dd', '0x15de', '0x15e8', '0x15eb',                       # Alpine/Titan Ridge
    '0x8a0d', '0x8a17'))                                          # Ice Lake
MSIX_UNREADABLE = 'unreadable: rerun as root'


class BringupError(Exception):
    pass


def parse_config(text):
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r'CONFIG_([A-Za-z0-9_]+)=(.*)', line)
        if match:
            values[match[1]] = match[2]
            continue
        match = re.fullmatch(r'# CONFIG_([A-Za-z0-9_]+) is not set', line)
        if match:
            values[match[1]] = 'n'
    return values


def check_config(text):
    values = parse_config(text)
    wrong = [f'{symbol}={values.get(symbol, "n")} (need {"|".join(sorted(allowed))})'
             for symbol, allowed in REQUIRED.items() if values.get(symbol, 'n') not in allowed]
    if wrong:
        raise ValueError('kernel config misses bare-metal requirements: ' + ', '.join(wrong))


def merge_fragment(base, fragment):
    """Fragment lines replace base lines of the same symbol (merge_config.sh -m)."""
    override = set(parse_config(fragment))
    kept = [line for line in base.splitlines(True)
            if not (set(parse_config(line)) & override)]
    if kept and not kept[-1].endswith('\n'):
        kept[-1] += '\n'
    return ''.join(kept) + fragment


def nvidia_release(nvidia_src):
    text = (nvidia_src / 'version.mk').read_text()
    match = re.search(r'^NVIDIA_VERSION = ([0-9]+\.[0-9]+(?:\.[0-9]+)?)$', text, re.M)
    if not match:
        raise BringupError(f'cannot read NVIDIA_VERSION from {nvidia_src}/version.mk')
    return match[1]


def package_files(package, release):
    files = [package / 'firmware' / name for name in GSP_FIRMWARE]
    files += [package / f'{lib}.so.{release}' for lib in USER_LIBS]
    files += [package / 'nvidia-smi', package / 'nvidia-modprobe']
    return files


def entry_id(release):
    return 'xdev-ext-bm-' + release


def grub_entry(release, facts):
    prefix = facts['boot_prefix']
    return (f"# Added by tools/build/baremetal.py for {release}\n"
            f"menuentry 'xdev_ext bare-metal {release}' --id {entry_id(release)} {{\n"
            f"\tinsmod gzio\n"
            f"\tsearch --no-floppy --fs-uuid --set=root {facts['boot_uuid']}\n"
            f"\tlinux {prefix}/vmlinuz-{release} root=UUID={facts['root_uuid']} {facts['cmdline']}\n"
            f"\tinitrd {prefix}/initrd.img-{release}\n"
            f"}}\n")


def _inside(path, root):
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    return path == root or root in path.parents


class Plan:
    """Ordered steps; build/stage steps may write only below the staging dir."""

    def __init__(self, staging, mode):
        self.staging = Path(os.path.abspath(staging))
        self.mode = mode          # 'dry-run', 'build' or 'apply'
        self.steps = []
        self.ctx = {}
        self.out = sys.stdout

    def add(self, phase, name, describe, action):
        self.steps.append((phase, name, describe, action))

    def guard(self, phase, path):
        if phase != 'install' and not _inside(path, self.staging):
            raise BringupError(f'refusing to write {path} outside staging {self.staging}')

    def execute(self, out=None):
        out = self.out = out or sys.stdout
        for index, (phase, name, describe, action) in enumerate(self.steps, 1):
            text = describe() if callable(describe) else describe
            label = f'{index:02d} [{phase}] {name}: {text}'
            if self.mode == 'dry-run':
                print('DRY-RUN ' + label, file=out)
            elif phase == 'install' and self.mode != 'apply':
                print('SKIP (needs --apply) ' + label, file=out)
            else:
                print('RUN ' + label, file=out, flush=True)
                action()


def run(argv, stdin_yes=False, log=None):
    stdout = open(log, 'a') if log else None
    try:
        if stdin_yes:
            yes = subprocess.Popen(['yes', ''], stdout=subprocess.PIPE)
            try:
                subprocess.run(argv, check=True, stdin=yes.stdout, stdout=stdout,
                               stderr=subprocess.STDOUT if stdout else None)
            finally:
                yes.kill()
                yes.wait()
        else:
            subprocess.run(argv, check=True, stdout=stdout,
                           stderr=subprocess.STDOUT if stdout else None)
    except subprocess.CalledProcessError as error:
        raise BringupError(f'command failed ({error.returncode}): {shlex.join(argv)}'
                           + (f'; see {log}' if log else '')) from error
    finally:
        if stdout:
            stdout.close()


def bringup_plan(options, mode):
    staging = Path(os.path.abspath(options.staging))
    linux = Path(os.path.abspath(options.linux_src))
    nvidia = Path(os.path.abspath(options.nvidia_src)) if options.nvidia_src else None
    package = Path(os.path.abspath(options.nvidia_package)) if options.nvidia_package else None
    base = Path(os.path.abspath(options.base_config))
    lsmod = Path(os.path.abspath(options.lsmod)) if options.lsmod else None
    for path, kind in ((linux / 'Makefile', 'Linux source'), (base, 'base config'),
                       (FRAGMENT, 'fragment')) + (((lsmod, 'lsmod listing'),) if lsmod else ()):
        if not path.is_file():
            raise BringupError(f'{kind} not found: {path}')
    if _inside(staging, linux) or (nvidia and _inside(staging, nvidia)):
        raise BringupError('staging must not be inside a source tree')
    if staging.exists() and (not staging.is_dir() or any(staging.iterdir())):
        raise BringupError(f'staging {staging} must be absent or empty')
    nv_release = None
    if nvidia:
        nv_release = nvidia_release(nvidia)
        if package:
            missing = [str(p) for p in package_files(package, nv_release) if not p.is_file()]
            if missing:
                raise BringupError(f'NVIDIA user space for release {nv_release} lacks: ' + ', '.join(missing))
    elif package:
        raise BringupError('--nvidia-package needs --nvidia-src to know the module release')
    if mode == 'apply' and not (nvidia and package):
        raise BringupError('--apply needs --nvidia-src and --nvidia-package')

    plan = Plan(staging, mode)
    ctx = plan.ctx
    kbuild, root, logs = staging / 'kbuild', staging / 'root', staging / 'logs'
    nvbuild = staging / 'nvidia-build'
    cc = options.cc
    kmake = ['make', '-C', str(linux), f'O={kbuild}', f'CC={cc}', f'HOSTCC={cc}']

    def release():
        return ctx.get('release', '<kernel-release>')

    def write(phase, path, data):
        plan.guard(phase, path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(data)

    def copy(phase, source, target):
        plan.guard(phase, target)
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    def symlink(phase, target, link):
        plan.guard(phase, link)
        Path(link).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, link)

    def prepare():
        for path in (staging, kbuild, root, logs):
            plan.guard('build', path)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
    plan.add('build', 'staging', f'mkdir -m 0700 {staging}/{{kbuild,root,logs}}', prepare)

    if lsmod:
        def trim():
            copy('build', base, kbuild / '.config')
            run(kmake + [f'LSMOD={lsmod}', 'localmodconfig'], stdin_yes=True, log=logs / 'localmodconfig.log')
        plan.add('build', 'localmodconfig',
                 f'cp {base} {kbuild}/.config; yes "" | {shlex.join(kmake + [f"LSMOD={lsmod}", "localmodconfig"])}',
                 trim)

    def merge():
        source = kbuild / '.config' if lsmod else base
        write('build', kbuild / '.config', merge_fragment(source.read_text(), FRAGMENT.read_text()))
        copy('build', base, logs / 'base.config')
    plan.add('build', 'merge-fragment',
             f'{"trimmed config" if lsmod else base} + {FRAGMENT} -> {kbuild}/.config', merge)
    plan.add('build', 'olddefconfig', shlex.join(kmake + ['olddefconfig']),
             lambda: run(kmake + ['olddefconfig'], log=logs / 'olddefconfig.log'))

    def check():
        try:
            check_config((kbuild / '.config').read_text())
        except ValueError as error:
            raise BringupError(str(error)) from error
    plan.add('build', 'check-config', f'{Path(__file__).name} check-config {kbuild}/.config', check)
    build = kmake + [f'-j{options.jobs}', 'bzImage', 'modules']

    def kernel():
        run(build, log=logs / 'kernel.log')
        ctx['release'] = (kbuild / 'include/config/kernel.release').read_text().strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+\-]*', ctx['release']):
            raise BringupError('unexpected kernel release ' + repr(ctx['release']))
    plan.add('build', 'kernel', shlex.join(build), kernel)

    install_mods = kmake + ['modules_install', f'INSTALL_MOD_PATH={root}', 'INSTALL_MOD_STRIP=1']
    plan.add('stage', 'modules_install', shlex.join(install_mods),
             lambda: run(install_mods, log=logs / 'modules_install.log'))

    def image():
        rel = release()
        copy('stage', kbuild / 'arch/x86/boot/bzImage', root / f'boot/vmlinuz-{rel}')
        copy('stage', kbuild / 'System.map', root / f'boot/System.map-{rel}')
        copy('stage', kbuild / '.config', root / f'boot/config-{rel}')
    plan.add('stage', 'kernel-image',
             lambda: f'cp bzImage System.map .config -> {root}/boot/{{vmlinuz,System.map,config}}-{release()}',
             image)

    if nvidia:
        nvmake = ['make', '-C', str(nvbuild), 'modules', f'-j{options.jobs}', f'SYSSRC={linux}',
                  f'SYSOUT={kbuild}', 'XDEV_EXT_ENABLE_GPU_CE_DMA=1', f'CC={cc}']

        def nv_modules():
            plan.guard('stage', nvbuild)
            shutil.copytree(nvidia, nvbuild, symlinks=True)
            run(nvmake, log=logs / 'nvidia.log')
            rel = release()
            for name in NV_MODULES:
                module = nvbuild / 'kernel-open' / f'{name}.ko'
                magic = subprocess.run(['modinfo', '-F', 'vermagic', str(module)], check=True,
                                       capture_output=True, text=True).stdout.split()
                if not magic or magic[0] != rel:
                    raise BringupError(f'{module} vermagic {magic[:1]} does not match {rel}')
                copy('stage', module, root / f'lib/modules/{rel}/extra/nvidia/{name}.ko')
        plan.add('stage', 'nvidia-modules',
                 lambda: f'cp -a {nvidia} {nvbuild}; {shlex.join(nvmake)}; '
                         f'cp {",".join(NV_MODULES)}.ko -> {root}/lib/modules/{release()}/extra/nvidia/',
                 nv_modules)
    depmod = lambda: ['depmod', '-b', str(root), release()]
    plan.add('stage', 'depmod', lambda: shlex.join(depmod()), lambda: run(depmod()))

    if nvidia and package:
        firmware = root / f'lib/firmware/nvidia/{nv_release}'

        def stage_firmware():
            for name in GSP_FIRMWARE:
                copy('stage', package / 'firmware' / name, firmware / name)
        plan.add('stage', 'nvidia-firmware',
                 f'cp {package}/firmware/{{{",".join(GSP_FIRMWARE)}}} -> {firmware}/', stage_firmware)

        def stage_userspace():
            for lib in USER_LIBS:
                copy('stage', package / f'{lib}.so.{nv_release}', root / LIBDIR / f'{lib}.so.{nv_release}')
                symlink('stage', f'{lib}.so.{nv_release}', root / LIBDIR / f'{lib}.so.1')
            symlink('stage', 'libcuda.so.1', root / LIBDIR / 'libcuda.so')
            copy('stage', package / 'nvidia-smi', root / 'usr/bin/nvidia-smi')
            helper = root / 'usr/bin/nvidia-modprobe'
            copy('stage', package / 'nvidia-modprobe', helper)
            helper.chmod(0o755)      # never setuid; the udev rule runs it as root
            write('stage', root / 'etc/modprobe.d/xdev-ext-nvidia.conf', MODPROBE_CONF)
            write('stage', root / UDEV_RULE_PATH, UDEV_RULE)
        plan.add('stage', 'nvidia-userspace',
                 f'cp {",".join(f"{lib}.so.{nv_release}" for lib in USER_LIBS)} (+ .so.1 links) -> '
                 f'{root}/{LIBDIR}/; nvidia-smi -> {root}/usr/bin/nvidia-smi; '
                 f'nvidia-modprobe (0755) -> {root}/usr/bin/nvidia-modprobe; '
                 f'blacklist nouveau -> {root}/etc/modprobe.d/xdev-ext-nvidia.conf; '
                 f'device-node rule -> {root}/{UDEV_RULE_PATH}', stage_userspace)

    def manifest():
        write('stage', staging / 'bringup.json', json.dumps({
            'kernel_release': release(), 'nvidia_release': nv_release,
            'base_config': str(base), 'fragment': str(FRAGMENT), 'lsmod': str(lsmod) if lsmod else None,
            'linux_src': str(linux), 'nvidia_src': str(nvidia) if nvidia else None,
            'nvidia_package': str(package) if package else None}, indent=1, sort_keys=True) + '\n')
    plan.add('stage', 'manifest', f'{staging}/bringup.json', manifest)

    add_install_steps(plan, staging, lambda: {'kernel_release': release(), 'nvidia_release': nv_release},
                      Path('/'), run_quiet, None, getattr(options, 'good_entry', None))
    return plan


def run_quiet(argv):
    run(list(argv))


def host_facts():
    def mount(target):
        out = subprocess.run(['findmnt', '-no', 'UUID,TARGET', '--target', target], check=True,
                             capture_output=True, text=True).stdout.split()
        if len(out) != 2:
            raise BringupError(f'cannot identify the filesystem of {target}')
        return out
    root_uuid, _ = mount('/')
    boot_uuid, boot_target = mount('/boot')
    tokens = [token for token in Path('/proc/cmdline').read_text().split()
              if not token.startswith(('BOOT_IMAGE=', 'initrd=', 'root='))]
    return {'root_uuid': root_uuid, 'boot_uuid': boot_uuid,
            'boot_prefix': '' if boot_target == '/boot' else '/boot', 'cmdline': ' '.join(tokens)}


def add_install_steps(plan, staging, manifest, target_root, runner, facts, good_entry):
    root = staging / 'root'
    target_root = Path(target_root)
    custom = target_root / 'boot/grub/custom.cfg'
    state = {}

    def release():
        return manifest()['kernel_release']

    def precheck():
        rel = release()
        state['facts'] = facts if facts is not None else host_facts()
        if custom.exists() and re.search(rf'--id\s+{re.escape(entry_id(rel))}(\s|$)', custom.read_text(), re.M):
            raise BringupError(f'GRUB entry {entry_id(rel)} already exists in {custom}')
        copies = []
        for dirpath, dirnames, filenames in os.walk(root):
            for name in sorted(dirnames + filenames):
                source = Path(dirpath, name)
                if source.is_dir() and not source.is_symlink():
                    continue
                target = target_root / source.relative_to(root)
                if target.is_symlink() or target.exists():
                    same = (os.readlink(target) == os.readlink(source)
                            if source.is_symlink() and target.is_symlink()
                            else not source.is_symlink() and not target.is_symlink()
                            and filecmp.cmp(source, target, shallow=False))
                    if not same:
                        raise BringupError(f'{target} exists with different content')
                    continue
                copies.append((source, target))
        state['copies'] = copies

    def install_files():
        for source, target in state['copies']:
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                os.symlink(os.readlink(source), target)
            else:
                shutil.copy2(source, target)

    def grub():
        custom.parent.mkdir(parents=True, exist_ok=True)
        old = custom.read_text() if custom.exists() else ''
        if old and not old.endswith('\n'):
            old += '\n'
        custom.write_text(old + grub_entry(release(), state['facts']))

    plan.add('install', 'precheck', f'refuse if any file under {target_root} differs or the GRUB entry exists',
             precheck)
    plan.add('install', 'install-files', f'copy {root}/* -> {target_root} (new files only)', install_files)
    plan.add('install', 'depmod', lambda: f'depmod {release()}', lambda: runner(['depmod', release()]))
    plan.add('install', 'ldconfig', 'ldconfig', lambda: runner(['ldconfig']))
    plan.add('install', 'initramfs', lambda: f'update-initramfs -c -k {release()}',
             lambda: runner(['update-initramfs', '-c', '-k', release()]))
    plan.add('install', 'grub-entry',
             lambda: f'append menuentry --id {entry_id(release())} to {custom}', grub)
    switch_plan = lambda: [sys.executable, str(KERNEL_SWITCH), 'plan', '--target-entry', entry_id(release()),
                           '--good-entry', good_entry or '<known-good-default-entry>']

    def kernel_switch():
        if good_entry:
            runner(switch_plan())
        print('NEXT (operator, not run here): ' + shlex.join(
            [sys.executable, str(KERNEL_SWITCH), 'switch', '--target-entry', entry_id(release()),
             '--good-entry', good_entry or '<known-good-default-entry>', '--execute',
             '--receipt', '<private-receipt-path>']), file=plan.out)
    plan.add('install', 'kernel-switch',
             lambda: f'{Path(KERNEL_SWITCH).name} plan --target-entry {entry_id(release())} '
                     f'--good-entry {good_entry or "<known-good-default-entry>"} (read-only)',
             kernel_switch)


def install(staging, *, apply, target_root=Path('/'), runner=run_quiet, euid=None,
            facts=None, good_entry=None, out=sys.stdout):
    staging = Path(os.path.abspath(staging))
    manifest = json.loads((staging / 'bringup.json').read_text())
    plan = Plan(staging, 'apply' if apply else 'build')
    add_install_steps(plan, staging, lambda: manifest, target_root, runner, facts, good_entry)
    if not apply:
        plan.execute(out)
        raise BringupError('refusing to install without an explicit --apply')
    if (os.geteuid() if euid is None else euid) != 0:
        raise BringupError('--apply requires root')
    plan.execute(out)


def decode_sgls(value):
    return ('unsupported', 'supported', 'supported-dword-aligned', 'reserved')[value & 3]


def msix_table_size(config):
    if len(config) < 0x40 or not struct.unpack_from('<H', config, 0x06)[0] & 0x10:
        return None
    pointer, seen = config[0x34] & ~3, 0
    while pointer and pointer + 4 <= len(config) and seen < 48:
        if config[pointer] == 0x11:
            return (struct.unpack_from('<H', config, pointer + 2)[0] & 0x7ff) + 1
        pointer, seen = config[pointer + 1] & ~3, seen + 1
    return None


def _read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def day_one_facts(root=Path('/'), runner=None):
    root = Path(root)
    if runner is None:
        def runner(argv):
            return subprocess.run(argv, check=True, capture_output=True, text=True).stdout
    facts = {'nvme': [], 'thunderbolt_nhi': [], 'nvidia_gpu': [], 'iommu': {}}
    interest = set()
    for controller in sorted((root / 'sys/class/nvme').glob('nvme*')):
        record = {'controller': controller.name}
        device = controller / 'device'
        if device.exists():
            record['pci'] = device.resolve().name
            interest.add(record['pci'])
        try:
            data = json.loads(runner(['nvme', 'id-ctrl', '/dev/' + controller.name, '-o', 'json']))
            record.update(sgls=decode_sgls(int(data['sgls'])), sgls_raw=hex(int(data['sgls'])),
                          model=str(data.get('mn', '')).strip())
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
            record['error'] = f'nvme id-ctrl failed: {error}'
        facts['nvme'].append(record)
    for device in sorted((root / 'sys/bus/pci/devices').glob('*')):
        vendor, klass = _read(device / 'vendor'), _read(device / 'class')
        driver = (device / 'driver').resolve().name if (device / 'driver').exists() else None
        if klass is None:
            continue
        device_id = _read(device / 'device')
        if (klass == USB4_NHI_CLASS or driver == 'thunderbolt'
                or (klass == LEGACY_NHI_CLASS and vendor == '0x8086' and device_id in LEGACY_INTEL_NHI_IDS)):
            record = {'pci': device.name, 'device': device_id, 'driver': driver}
            try:
                config = (device / 'config').read_bytes()
                record['msix_table_size'] = msix_table_size(config)
                # sysfs gives a non-root reader only the 64-byte header, which
                # holds no capability list.
                if record['msix_table_size'] is None and len(config) <= 0x40:
                    record['msix_table_size_unreadable'] = MSIX_UNREADABLE
            except OSError as error:
                record['msix_table_size'] = None
                record['msix_table_size_unreadable'] = MSIX_UNREADABLE
                record['error'] = str(error)
            irqs = device / 'msi_irqs'
            record['allocated_vectors'] = len(list(irqs.iterdir())) if irqs.is_dir() else 0
            facts['thunderbolt_nhi'].append(record)
            interest.add(device.name)
        elif vendor == '0x10de' and klass.startswith('0x03'):
            record = {'pci': device.name, 'device': _read(device / 'device'), 'driver': driver}
            for name in ('current_link_speed', 'current_link_width', 'max_link_speed', 'max_link_width'):
                record[name] = _read(device / name)
            facts['nvidia_gpu'].append(record)
            interest.add(device.name)
    units = sorted(path.name for path in (root / 'sys/class/iommu').glob('*'))
    vendors = {('intel' if unit.startswith('dmar') else 'amd' if unit.startswith('ivhd') else 'other')
               for unit in units}
    groups = {}
    for group in sorted((root / 'sys/kernel/iommu_groups').glob('*')):
        for member in (group / 'devices').glob('*'):
            if member.name in interest:
                groups[member.name] = _read(group / 'type')
    cmdline = (_read(root / 'proc/cmdline') or '').split()
    facts['iommu'] = {
        'units': units, 'vendor': ','.join(sorted(vendors)) if vendors else 'none', 'groups': groups,
        'cmdline': [token for token in cmdline if token.startswith(('iommu', 'intel_iommu', 'amd_iommu'))]}
    facts['lockdown'] = _read(root / 'sys/kernel/security/lockdown')
    return facts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    check = sub.add_parser('check-config')
    check.add_argument('config')
    bring = sub.add_parser('bringup')
    bring.add_argument('--staging', required=True)
    bring.add_argument('--base-config', required=True, help='distribution config, e.g. /boot/config-$(uname -r)')
    bring.add_argument('--linux-src', default='build/assembled/linux')
    bring.add_argument('--nvidia-src', help='assembled NVIDIA open modules, e.g. build/assembled/nvidia')
    bring.add_argument('--nvidia-package', help='extracted NVIDIA-Linux-x86_64-<release> directory')
    bring.add_argument('--lsmod', help='trim the base config to these loaded modules (localmodconfig)')
    bring.add_argument('--jobs', type=int, default=os.cpu_count() or 1)
    bring.add_argument('--cc', default='gcc')
    bring.add_argument('--good-entry', help='known-good GRUB default for the read-only kernel_switch plan')
    modes = bring.add_mutually_exclusive_group()
    modes.add_argument('--dry-run', action='store_true')
    modes.add_argument('--apply', action='store_true')
    inst = sub.add_parser('install')
    inst.add_argument('--staging', required=True)
    inst.add_argument('--apply', action='store_true')
    inst.add_argument('--good-entry')
    sub.add_parser('day1-check')
    options = parser.parse_args(argv)
    try:
        if options.action == 'check-config':
            check_config(Path(options.config).read_text())
            print('BAREMETAL CONFIG=PASS ' + options.config)
        elif options.action == 'bringup':
            mode = 'dry-run' if options.dry_run else 'apply' if options.apply else 'build'
            if mode == 'apply' and os.geteuid() != 0:
                raise BringupError('--apply requires root')
            bringup_plan(options, mode).execute()
        elif options.action == 'install':
            install(options.staging, apply=options.apply, good_entry=options.good_entry)
        else:
            print(json.dumps(day_one_facts(), indent=1, sort_keys=True))
        return 0
    except ValueError as error:
        print('FAIL ' + str(error), file=sys.stderr)
        return 1
    except BringupError as error:
        print('FAIL ' + str(error), file=sys.stderr)
        return 2 if 'without an explicit --apply' in str(error) else 1


if __name__ == '__main__':
    sys.exit(main())
