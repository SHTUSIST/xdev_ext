#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Physical admission of the NVMe<->NIC eval: observe local evidence, never accept fixtures.

Checks adapted from tests/eval/hft/hardware_gate.py (physical(), kernel(),
source() at product HEAD 8e0238a).  Every refusal happens before any
workload, window write or peer data traffic.
"""
import gzip
import json
import os
from pathlib import Path
import re
import stat
import subprocess


class Refused(Exception):
    def __init__(self, status, message, completed=0):
        super().__init__(message)
        self.status, self.message, self.completed = status, message, completed


def refuse(message, status='not_run_hardware'):
    raise Refused(status, message)


def read(path):
    return Path(path).read_text().strip()


def physical(ifname, sysfs='/sys', proc='/proc'):
    """Positive DMI and PCI NIC evidence; any virtual hint refuses."""
    sysfs, proc = Path(sysfs), Path(proc)
    try:
        cpu = read(proc / 'cpuinfo').lower()
        if (sysfs / 'hypervisor/type').exists() or 'hypervisor' in cpu.split():
            refuse('virtual/hypervisor environment')
        dmi = ' '.join(read(sysfs / 'class/dmi/id' / name) for name in ('sys_vendor', 'product_name', 'board_vendor'))
    except OSError as error:
        refuse('DMI/CPU evidence unavailable: ' + str(error))
    if re.search('virtual|vmware|qemu|kvm|hvm|virtualbox|ec2|google compute|standard pc', dmi, re.I):
        refuse('virtual DMI evidence')
    if not re.search('dell|supermicro|hewlett|hpe|lenovo|asus|gigabyte|cisco|intel|tyan|fujitsu|huawei|inspur', dmi, re.I):
        refuse('unknown physical platform; positive DMI evidence required')
    device = sysfs / 'class/net' / ifname / 'device'
    if not device.exists() or '/pci' not in str(device.resolve()):
        refuse('physical PCI NIC required: ' + ifname)
    driver = (device / 'driver').resolve().name
    if re.search('virtio|vmxnet|hv_netvsc|veth|tun', driver):
        refuse('virtual NIC driver ' + driver)
    return dict(dmi=dmi, nic_pci=device.resolve().name, nic_driver=driver,
                mtu=int(read(sysfs / 'class/net' / ifname / 'mtu')),
                mac=read(sysfs / 'class/net' / ifname / 'address').lower())


def kernel_config(needs_session):
    release = os.uname().release
    for path in (Path('/proc/config.gz'), Path('/boot') / ('config-' + release)):
        if path.is_file():
            data = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
            strict = b'CONFIG_XDEV_EXT_MECH_ZEROCOPY=y' in data.splitlines()
            if needs_session and not strict:
                refuse('session arm needs a running kernel with CONFIG_XDEV_EXT_MECH_ZEROCOPY=y', 'not_run_capability')
            return dict(release=release, config=str(path), strict_zero_copy=strict)
    refuse('running kernel config not found', 'not_run_capability')


def nvme(block, ng, sysfs='/sys'):
    """Block and generic char devices of one physical PCI NVMe namespace."""
    try:
        if not stat.S_ISBLK(os.stat(block).st_mode):
            refuse('--source must be an NVMe block device')
        b = (Path(sysfs) / 'class/block' / Path(block).name / 'device').resolve()
        if '/pci' not in str(b):
            refuse('NVMe namespace is not on PCI')
        identity = dict(block=block, namespace=str(b))
        if ng:
            if not stat.S_ISCHR(os.stat(ng).st_mode):
                refuse('--ng must be the generic character device')
            n = (Path(sysfs) / 'class/nvme-generic' / Path(ng).name / 'device').resolve()
            if n != b:
                refuse('block and generic devices name different namespaces')
            identity['ng'] = ng
        return identity
    except OSError as error:
        refuse('NVMe identity unavailable: ' + str(error))


def addresses(ifname, local_ip, peer_ip, control_ip, local_mac, nic_mac):
    try:
        rows = json.loads(subprocess.run(['ip', '-j', 'address', 'show'], text=True,
                                         capture_output=True, timeout=30, check=True).stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        refuse('interface addresses unavailable: ' + str(error), 'not_run_capability')
    mine = [a['local'] for r in rows if r.get('ifname') == ifname for a in r.get('addr_info', []) if a.get('family') == 'inet']
    every = [a['local'] for r in rows for a in r.get('addr_info', []) if a.get('family') == 'inet']
    if local_ip not in mine:
        refuse('--local-ip is not an address of ' + ifname)
    for ip in (peer_ip, control_ip):
        if ip in every or ip.startswith('127.'):
            refuse('a real remote peer is required (peer address is local)')
    if local_mac and local_mac.lower() != nic_mac:
        refuse('--local-mac differs from the NIC address')


def admit(args, features):
    """Receipt of observed evidence for a measured run, or Refused."""
    for name in ('ifname', 'source', 'local_ip', 'peer_ip', 'peer_control', 'peer_port', 'nlb'):
        if not getattr(args, name):
            refuse('measured run needs --' + name.replace('_', '-'))
    session = 'session' in args.arms
    if 'uring' in args.arms and not features.get('uring'):
        refuse('producer built without liburing (make ENABLE_URING=1)', 'not_run_capability')
    if session:
        if not features.get('session'):
            refuse('producer built without the session backend (make ENABLE_SESSION=1)', 'not_run_capability')
        for name in ('ng', 'bpf_object', 'local_mac', 'peer_mac'):
            if not getattr(args, name):
                refuse('session arm needs --' + name.replace('_', '-'))
        if not Path(args.bpf_object).is_file():
            refuse('BPF object missing; make hardware-bpf', 'not_run_capability')
    receipt = dict(environment=physical(args.ifname), kernel=kernel_config(session),
                   nvme=nvme(args.source, args.ng if session else None))
    addresses(args.ifname, args.local_ip, args.peer_ip, args.peer_control[0], args.local_mac,
              receipt['environment']['mac'])
    return receipt
