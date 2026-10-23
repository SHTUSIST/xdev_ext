#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Admission of a timed chain run: observed physical devices only.

Every check reads the running system (sysfs, /proc, the kernel config); no
command-line flag can assert physical hardware.  The tests point SYSROOT at
a fabricated tree; run.py always uses the real root.  A refusal raises
Refusal and run.py exits 4 with no timing row.
"""
import gzip
import os
from pathlib import Path
import re
import stat

# PCI vendors of emulated or paravirtual devices.
VIRTUAL_VENDORS = {'0x1af4': 'virtio/Red Hat', '0x1b36': 'QEMU', '0x15ad': 'VMware',
                   '0x1414': 'Microsoft Hyper-V', '0x80ee': 'VirtualBox',
                   '0x1d0f': 'Amazon emulated'}
VIRTUAL_NIC_DRIVERS = re.compile(r'virtio|veth|^tun$|vmxnet|hv_netvsc|xen')
VIRTUAL_DMI = re.compile(r'qemu|kvm|virtual|vmware|virtualbox|bochs|hvm|xen|ec2|'
                         r'google compute|standard pc', re.I)
NVIDIA = '0x10de'


class Refusal(Exception):
    """The run is not admitted; str() says why."""


def _read(path):
    return Path(path).read_text().strip()


def _resolve(path):
    return Path(os.path.realpath(path))


def environment(root):
    """No hypervisor evidence anywhere the kernel or firmware reports it."""
    hyp = root / 'sys/hypervisor/type'
    if hyp.exists() and _read(hyp):
        raise Refusal('hypervisor reported by /sys/hypervisor/type: ' + _read(hyp))
    cpuinfo = root / 'proc/cpuinfo'
    if cpuinfo.exists() and re.search(r'^flags\s*:.*\bhypervisor\b', cpuinfo.read_text(), re.M):
        raise Refusal('CPU flags include hypervisor')
    dmi = ' '.join(_read(root / 'sys/class/dmi/id' / name)
                   for name in ('sys_vendor', 'product_name', 'board_vendor')
                   if (root / 'sys/class/dmi/id' / name).exists())
    if not dmi:
        raise Refusal('no DMI identity; physical platform not observable')
    if VIRTUAL_DMI.search(dmi):
        raise Refusal('virtual platform DMI: ' + dmi)
    return {'dmi': dmi}


def kernel_config(root, release=None):
    """CONFIG_XDEV_EXT_MECH_ZEROCOPY=y in the running kernel's own config."""
    release = release or os.uname().release
    for path in (root / 'proc/config.gz', root / 'boot' / ('config-' + release)):
        if path.exists():
            data = path.read_bytes()
            if path.suffix == '.gz':
                data = gzip.decompress(data)
            if b'CONFIG_XDEV_EXT_MECH_ZEROCOPY=y' in data.splitlines():
                return {'config': str(path), 'zerocopy': True}
            raise Refusal('running kernel lacks CONFIG_XDEV_EXT_MECH_ZEROCOPY=y (%s)' % path)
    raise Refusal('running kernel config not observable')


def _pci_function(root, dev_link):
    """The PCI function a sysfs device link ends at, with its vendor."""
    path = _resolve(dev_link)
    while path != path.parent and not (path / 'vendor').exists():
        path = path.parent
    if '/pci' not in str(path) or not (path / 'vendor').exists():
        raise Refusal('device %s is not on PCI' % dev_link)
    vendor = _read(path / 'vendor').lower()
    if vendor in VIRTUAL_VENDORS:
        raise Refusal('%s is a %s device (%s)' % (dev_link, VIRTUAL_VENDORS[vendor], vendor))
    return path, vendor


def nvme(root, block, ng=None):
    name = Path(block).name
    link = root / 'sys/class/block' / name / 'device'
    if not link.exists():
        raise Refusal('NVMe block device %s not in sysfs' % block)
    ctrl = _resolve(link)
    pci, vendor = _pci_function(root, link)
    if ng:
        nlink = root / 'sys/class/nvme-generic' / Path(ng).name / 'device'
        if not nlink.exists() or _resolve(nlink) != ctrl:
            raise Refusal('%s and %s are not the same NVMe namespace controller' % (ng, block))
    return {'block': block, 'pci': pci.name, 'vendor': vendor}


def nic(root, ifname):
    link = root / 'sys/class/net' / ifname / 'device'
    if not link.exists():
        raise Refusal('NIC %s has no device (virtual interface)' % ifname)
    pci, vendor = _pci_function(root, link)
    driver = _resolve(link / 'driver').name if (link / 'driver').exists() else ''
    if not driver or VIRTUAL_NIC_DRIVERS.search(driver):
        raise Refusal('NIC %s driver %r is virtual or unknown' % (ifname, driver))
    return {'ifname': ifname, 'pci': pci.name, 'vendor': vendor, 'driver': driver}


def _char_dev(path):
    """(major, minor) of the character device node @path."""
    st = os.stat(path)
    if not stat.S_ISCHR(st.st_mode):
        raise Refusal('%s is not a character device' % path)
    return os.major(st.st_rdev), os.minor(st.st_rdev)


def gpu_of_node(root, ce_dev):
    """The PCI function behind an NVIDIA device node, resolved as
    kernel/tools/xdev_ext_gpu_identity.c does: the node must be /dev/nvidiaN
    with minor N, then /sys/dev/char/MAJ:MIN/device, else the one
    /proc/driver/nvidia/gpus/<bdf>/information reporting that minor."""
    real = _resolve(root / ce_dev.lstrip('/'))
    m = re.fullmatch(r'nvidia([0-9]+)', real.name)
    if not m:
        raise Refusal('CE device %s is not an NVIDIA GPU node (/dev/nvidiaN)' % ce_dev)
    major, minor = _char_dev(real)
    if minor != int(m.group(1)):
        raise Refusal('CE device %s has minor %d, not %s' % (ce_dev, minor, m.group(1)))
    link = root / ('sys/dev/char/%d:%d/device' % (major, minor))
    if link.exists():
        return _resolve(link).name
    gpus = root / 'proc/driver/nvidia/gpus'
    found = sorted(info.parent.name for info in (gpus.glob('*/information') if gpus.is_dir() else [])
                   if re.search(r'^Device Minor:\s*%d\s*$' % minor, info.read_text(), re.M))
    if len(found) != 1:
        raise Refusal('CE device %s: %d NVIDIA GPUs report device minor %d'
                      % (ce_dev, len(found), minor))
    return found[0]


def gpu(root, bdf, ce_dev=None):
    if ce_dev and 'xdev_ext_ce_sim' in ce_dev:
        raise Refusal('CE device %s is the CPU memcpy simulator' % ce_dev)
    if not bdf:
        raise Refusal('a timed GPU stage needs the GPU PCI BDF')
    path = root / 'sys/bus/pci/devices' / bdf
    if not (path / 'vendor').exists() or _read(path / 'vendor').lower() != NVIDIA:
        raise Refusal('PCI %s is not an NVIDIA GPU' % bdf)
    if ce_dev:
        node = gpu_of_node(root, ce_dev)
        if node.lower() != bdf.lower():
            raise Refusal('CE device %s is GPU %s, not rig ce.bdf %s' % (ce_dev, node, bdf))
    return {'bdf': bdf, 'vendor': NVIDIA, 'ce_dev': ce_dev}


def iaa(root, software):
    if software:
        raise Refusal('IAA stage uses deflate-generic (CPU); timing needs deflate-iaa')
    crypto = root / 'proc/crypto'
    if not crypto.exists() or not re.search(r'^driver\s*:\s*deflate-iaa$', crypto.read_text(), re.M):
        raise Refusal('deflate-iaa is not registered in /proc/crypto')
    dsa = root / 'sys/bus/dsa/devices'
    if not dsa.is_dir() or not any(p.name.startswith('iax') for p in dsa.iterdir()):
        raise Refusal('no IAA (iax) device on the DSA bus')
    return {'driver': 'deflate-iaa'}


def admit(rig, chain_stages, arms, root=Path('/')):
    """Evidence for a timed campaign of @chain_stages under @arms, or Refusal.

    @chain_stages lists (class, direction, role) of every stage this host runs.
    """
    root = Path(root)
    evidence = {'environment': environment(root)}
    if 'session' in arms:
        evidence['kernel'] = kernel_config(root)
    devices = []
    for cls, _direction, role in chain_stages:
        if cls == 'nvme':
            side = rig['nvme_src' if role == 'src' else 'nvme_dst']
            devices.append(nvme(root, side['block'], side.get('ng')))
        elif cls == 'afxdp':
            devices.append(nic(root, rig['tx' if role == 'tx' else 'rx']['ifname']))
        elif cls == 'ce':
            ce = rig.get('ce', {})
            devices.append(gpu(root, ce.get('bdf'), ce.get('dev')))
        elif cls == 'iaa':
            devices.append(iaa(root, rig.get('iaa_software', True)))
    evidence['devices'] = devices
    return evidence
