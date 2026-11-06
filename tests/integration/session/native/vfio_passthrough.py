#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Guard, bind and restore one PCI function for VFIO passthrough tests.

  check BDF                  exit 0 only if BDF is on vfio-pci and VFIO would
                             accept its whole IOMMU group
  users BDF                  list host users of BDF (exit 1 if any)
  bind BDF --state FILE [--target vfio-pci | --driverless]
           [--reset-method VALUE] [--dry-run]
  restore --state FILE [--dry-run]

The helper never stops services, unloads modules or resets devices. A bind
is refused while the device has a host user: a mounted, swapped or held
block device, an interface that is up or has an address, or a process that
holds one of the device's /dev nodes (for a GPU on the nvidia driver, any
/dev/nvidia* node). The state file is written before the first sysfs write,
so restore can return the original driver, driver_override and reset_method
even after a partial bind.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

VFIO = 'vfio-pci'
# driver_override naming no real driver keeps a function driverless.
NO_DRIVER = 'xdev-ext-no-driver'
VFIO_COMPATIBLE = (VFIO, 'pci-stub')
BRIDGE_DRIVERS = ('pcieport',)
BDF_RE = re.compile(r'^(?:([0-9a-fA-F]{4}):)?([0-9a-fA-F]{2}):([0-1][0-9a-fA-F])\.([0-7])$')


class GuardError(Exception):
    pass


def normalize_bdf(text):
    match = BDF_RE.match(text or '')
    if not match:
        raise GuardError(f'malformed PCI address: {text!r}')
    domain, bus, slot, function = match.groups()
    if int(slot, 16) > 31:
        raise GuardError(f'malformed PCI address: {text!r}')
    return f'{(domain or "0000").lower()}:{bus.lower()}:{slot.lower()}.{function}'


def ip_addresses(name):
    """Addresses of one interface from iproute2 JSON; [] if none."""
    run = subprocess.run(['ip', '-j', 'addr', 'show', 'dev', name],
                         capture_output=True, text=True)
    if run.returncode:
        raise GuardError(f'cannot list addresses of {name}: {run.stderr.strip()}')
    found = []
    for link in json.loads(run.stdout or '[]'):
        for info in link.get('addr_info', []):
            if info.get('local'):
                found.append(f"{info['local']}/{info.get('prefixlen', '')}")
    return found


class Host:
    def __init__(self, sys_root='/sys', proc_root='/proc', dev_root='/dev',
                 addresses=ip_addresses):
        self.sys = Path(sys_root)
        self.proc = Path(proc_root)
        self.dev = Path(dev_root)
        self.addresses = addresses

    def device_path(self, bdf):
        path = self.sys / 'bus/pci/devices' / bdf
        if not path.exists():
            raise GuardError(f'no PCI device {bdf}')
        return path

    def driver(self, bdf):
        link = self.device_path(bdf) / 'driver'
        return os.path.basename(os.readlink(link)) if link.is_symlink() else None

    def pci_class(self, bdf):
        return int((self.device_path(bdf) / 'class').read_text().strip(), 16)

    def is_bridge(self, bdf):
        return (self.pci_class(bdf) >> 8) == 0x0604

    def group_members(self, bdf):
        group = self.device_path(bdf) / 'iommu_group'
        if not group.exists():
            raise GuardError(f'{bdf} has no IOMMU group (IOMMU off?)')
        return sorted(os.listdir(group / 'devices'))

    def driver_dir(self, name):
        return self.sys / 'bus/pci/drivers' / name


def check_ready(host, bdf):
    """Raise GuardError unless BDF can be handed to QEMU's vfio-pci device."""
    bdf = normalize_bdf(bdf)
    if host.is_bridge(bdf):
        raise GuardError(f'{bdf} is a PCI bridge; pass its endpoints instead')
    driver = host.driver(bdf)
    if driver != VFIO:
        raise GuardError(f'{bdf} is bound to {driver or "no driver"}, not {VFIO}')
    for member in host.group_members(bdf):
        if member == bdf:
            continue
        other = host.driver(member)
        if other in VFIO_COMPATIBLE or other is None:
            continue
        if host.is_bridge(member) and other in BRIDGE_DRIVERS:
            continue
        raise GuardError(f'IOMMU group member {member} is bound to {other}; '
                         f'it must be on {VFIO}, driverless, or a bridge on pcieport')
    return bdf


def _block_devices(device):
    """(name, 'maj:min', holders) for every namespace and partition below a device."""
    found = []
    for dev_file in sorted(device.glob('nvme/*/*/dev')) + sorted(device.glob('nvme/*/*/*/dev')) + \
            sorted(device.glob('**/block/*/dev')) + sorted(device.glob('**/block/*/*/dev')):
        node = dev_file.parent
        holders = sorted(os.listdir(node / 'holders')) if (node / 'holders').is_dir() else []
        entry = (node.name, dev_file.read_text().strip(), holders)
        if entry not in found:
            found.append(entry)
    return found


def _device_nodes(host, bdf, device):
    """Device-node paths a process could hold that belong to this function."""
    nodes = set()
    driver = host.driver(bdf)
    for card in device.glob('drm/*'):
        nodes.add(str(host.dev / 'dri' / card.name))
        nodes.add('/dev/dri/' + card.name)
    for card in device.glob('sound/card*'):
        number = card.name[len('card'):]
        nodes.add(f'prefix:/dev/snd/controlC{number}')
        nodes.add(f'prefix:/dev/snd/pcmC{number}D')
        nodes.add(f'prefix:/dev/snd/hwC{number}D')
    for name, _, _ in _block_devices(device):
        nodes.add('/dev/' + name)
    for ctrl in device.glob('nvme/nvme*'):
        nodes.add('/dev/' + ctrl.name)
        for ns in ctrl.glob(ctrl.name + 'n*'):
            nodes.add('/dev/ng' + ns.name[len('nvme'):])
    if driver == 'nvidia':
        # Minor numbers are not in sysfs; any NVIDIA node blocks the unbind.
        nodes.add('prefix:/dev/nvidia')
    return nodes


def _holds(target, nodes):
    for node in nodes:
        if node.startswith('prefix:'):
            if target.startswith(node[len('prefix:'):]):
                return True
        elif target == node:
            return True
    return False


def active_users(host, bdf):
    bdf = normalize_bdf(bdf)
    device = host.device_path(bdf)
    users = []
    for net in sorted(device.glob('net/*')):
        name = net.name
        operstate = (net / 'operstate').read_text().strip() if (net / 'operstate').exists() else ''
        flags = int((net / 'flags').read_text().strip(), 16) if (net / 'flags').exists() else 0
        if operstate == 'up' or flags & 0x1:
            users.append(f'interface {name} is up')
        addresses = host.addresses(name)
        if addresses:
            users.append(f'interface {name} has addresses: {", ".join(addresses)}')
    numbers = {}
    for name, number, holders in _block_devices(device):
        numbers[number] = name
        for holder in holders:
            users.append(f'block device {name} is held by {holder}')
    mountinfo = host.proc / 'self/mountinfo'
    for line in mountinfo.read_text().splitlines() if mountinfo.exists() else ():
        fields = line.split()
        if len(fields) > 4 and fields[2] in numbers:
            users.append(f'block device {numbers[fields[2]]} ({fields[2]}) is mounted at {fields[4]}')
    swaps = host.proc / 'swaps'
    for line in swaps.read_text().splitlines()[1:] if swaps.exists() else ():
        source = line.split()[0] if line.split() else ''
        if os.path.basename(source) in numbers.values():
            users.append(f'block device {os.path.basename(source)} is used as swap')
    nodes = _device_nodes(host, bdf, device)
    if nodes:
        for proc in sorted(host.proc.glob('[0-9]*'), key=lambda p: int(p.name)):
            try:
                fds = list((proc / 'fd').iterdir())
            except OSError:
                continue
            for fd in fds:
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if _holds(target, nodes):
                    try:
                        comm = (proc / 'comm').read_text().strip()
                    except OSError:
                        comm = '?'
                    users.append(f'pid {proc.name} ({comm}) holds {target}')
    return users


def _write(path, value, dry_run, log):
    log.append((str(path), value))
    if dry_run:
        print(f'DRY-RUN write {value!r} > {path}')
        return
    with open(path, 'w') as out:
        out.write(value)


def _save_state(path, state):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    with os.fdopen(descriptor, 'w') as out:
        json.dump(state, out, indent=1, sort_keys=True)
        out.write('\n')
    os.replace(temporary, path)


def bind(host, bdf, target, state_path, reset_method=None, dry_run=False):
    """Move BDF to TARGET (or leave it driverless when TARGET is None)."""
    bdf = normalize_bdf(bdf)
    device = host.device_path(bdf)
    if target is not None and not host.driver_dir(target).is_dir():
        raise GuardError(f'{target} driver is not loaded')
    users = active_users(host, bdf)
    if users:
        raise GuardError(f'{bdf} has host users: ' + '; '.join(users))
    original = host.driver(bdf)
    reset_file = device / 'reset_method'
    state = dict(bdf=bdf, target=target, original_driver=original,
                 original_override=(device / 'driver_override').read_text().strip(),
                 original_reset_method=(reset_file.read_text().strip()
                                        if reset_file.exists() else None),
                 reset_method_written=reset_method is not None)
    actions = []
    if not dry_run:
        _save_state(state_path, state)
    if reset_method is not None:
        if not reset_file.exists():
            raise GuardError(f'{bdf} exposes no reset_method')
        # A zero-length write never reaches the sysfs store; an empty line
        # is the kernel's request to disable every reset method.
        _write(reset_file, reset_method or '\n', dry_run, actions)
    _write(device / 'driver_override', target or NO_DRIVER, dry_run, actions)
    if original and original != target:
        _write(host.driver_dir(original) / 'unbind', bdf, dry_run, actions)
    if target and original != target:
        _write(host.driver_dir(target) / 'bind', bdf, dry_run, actions)
    return actions


def restore(host, state_path, dry_run=False):
    """Undo bind(); return a word describing the original driver's state."""
    state = json.loads(Path(state_path).read_text())
    bdf = normalize_bdf(state['bdf'])
    device = host.device_path(bdf)
    actions = []
    current = host.driver(bdf)
    original = state['original_driver']
    if current and current != original:
        _write(host.driver_dir(current) / 'unbind', bdf, dry_run, actions)
    override = state['original_override']
    _write(device / 'driver_override', '\n' if override in ('', '(null)') else override,
           dry_run, actions)
    if state.get('reset_method_written') and state.get('original_reset_method') is not None:
        _write(device / 'reset_method', state['original_reset_method'] or '\n', dry_run, actions)
    if not original or current == original:
        return 'no-driver-to-restore' if not original else 'already-bound'
    if host.driver_dir(original).is_dir():
        _write(host.driver_dir(original) / 'bind', bdf, dry_run, actions)
        return 'bind-requested'
    _write(host.sys / 'bus/pci/drivers_probe', bdf, dry_run, actions)
    return 'original-driver-not-loaded'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--sys-root', default='/sys')
    parser.add_argument('--proc-root', default='/proc')
    parser.add_argument('--dev-root', default='/dev')
    parser.add_argument('--no-ip', action='store_true', help='do not query interface addresses')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check').add_argument('bdf')
    sub.add_parser('users').add_argument('bdf')
    bind_cmd = sub.add_parser('bind')
    bind_cmd.add_argument('bdf')
    choice = bind_cmd.add_mutually_exclusive_group(required=True)
    choice.add_argument('--target', choices=(VFIO,))
    choice.add_argument('--driverless', action='store_true')
    bind_cmd.add_argument('--reset-method')
    bind_cmd.add_argument('--state', required=True)
    bind_cmd.add_argument('--dry-run', action='store_true')
    restore_cmd = sub.add_parser('restore')
    restore_cmd.add_argument('--state', required=True)
    restore_cmd.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    host = Host(args.sys_root, args.proc_root, args.dev_root,
                (lambda name: []) if args.no_ip else ip_addresses)
    try:
        if args.command == 'check':
            print('VFIO_READY ' + check_ready(host, args.bdf))
        elif args.command == 'users':
            users = active_users(host, args.bdf)
            for user in users:
                print('USER ' + user)
            return 1 if users else 0
        elif args.command == 'bind':
            for path, value in bind(host, args.bdf, None if args.driverless else args.target,
                                    args.state, args.reset_method, args.dry_run):
                if not args.dry_run:
                    print(f'WROTE {value!r} > {path}')
        else:
            result = restore(host, args.state, args.dry_run)
            print('RESTORE ' + result)
            return 3 if result == 'original-driver-not-loaded' else 0
    except GuardError as error:
        print('REFUSED ' + str(error), file=sys.stderr)
        return 1
    except OSError as error:
        print('WRITE_FAILED ' + str(error), file=sys.stderr)
        return 4
    return 0


if __name__ == '__main__':
    sys.exit(main())
