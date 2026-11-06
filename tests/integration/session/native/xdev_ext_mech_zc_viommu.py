#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check from the guest kernel log that the emulated Intel VT-d translated DMA.

Requires: intel_iommu=on parsed, VT-d initialized, translated default domains
with strict invalidation, and every NVMe and virtio PCI function placed in an
IOMMU group. DMA remapping faults fail the check unless the caller expects
them (negative cases), in which case they are counted per requester.
This reads console text only; it is not a device or timing measurement.
"""
import json
from pathlib import Path
import re
import sys

ENDPOINT = re.compile(r'\] pci (0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]): \[([0-9a-f]{4}):([0-9a-f]{4})\] '
                      r'type 00 class 0x([0-9a-f]{6})')
GROUP = re.compile(r'\] pci (0000:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]): Adding to iommu group ([0-9]+)$')
FAULT = re.compile(r'DMAR: \[DMA (?:Read|Write)[^\]]*\] Request device \[([0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\]')
FAULT_STATUS = re.compile(r'DMAR: DRHD: handling fault status')


def validate_viommu_console(text, allow_faults=False):
    lines = text.replace('\r', '').splitlines()

    def has(fragment):
        return any(fragment in line for line in lines)

    if not has('DMAR: IOMMU enabled'):
        raise ValueError('guest did not report "DMAR: IOMMU enabled" (intel_iommu=on not in effect)')
    if not has('DMAR: Intel(R) Virtualization Technology for Directed I/O'):
        raise ValueError('guest did not initialize VT-d ("Directed I/O" line missing)')
    if not has('iommu: Default domain type: Translated') or has('iommu: Default domain type: Passthrough'):
        raise ValueError('default IOMMU domain is not Translated')
    if not has('iommu: DMA domain TLB invalidation policy: strict mode') or \
            has('iommu: DMA domain TLB invalidation policy: lazy mode'):
        raise ValueError('IOMMU invalidation policy is not strict')
    nvme, virtio, groups = set(), set(), {}
    for line in lines:
        match = ENDPOINT.search(line)
        if match:
            bdf, vendor, _, klass = match.groups()
            if klass.startswith('0108'):
                nvme.add(bdf)
            elif vendor == '1af4':
                virtio.add(bdf)
        match = GROUP.search(line)
        if match:
            bdf, group = match.group(1), int(match.group(2))
            if groups.setdefault(bdf, group) != group:
                raise ValueError('PCI function in two IOMMU groups: ' + bdf)
    if not nvme:
        raise ValueError('no NVMe PCI function enumerated in the guest log')
    for bdf in sorted(nvme | virtio):
        if bdf not in groups:
            raise ValueError('PCI function without IOMMU group: ' + bdf)
    fault_devices = []
    faults = 0
    for line in lines:
        match = FAULT.search(line)
        if match:
            faults += 1
            device = '0000:' + match.group(1)
            if device not in fault_devices:
                fault_devices.append(device)
    if not faults and any(FAULT_STATUS.search(line) for line in lines):
        faults = 1
    if faults and not allow_faults:
        raise ValueError('DMA remapping fault reported for %s' % (','.join(fault_devices) or 'unknown device'))
    return dict(dmar='enabled', domain='translated', policy='strict',
                nvme=sorted(nvme), virtio=sorted(virtio),
                groups={bdf: groups[bdf] for bdf in sorted(nvme | virtio)},
                faults=faults, fault_devices=fault_devices)


def main(argv):
    if len(argv) not in (3, 4) or (len(argv) == 4 and argv[3] != '--allow-faults'):
        print('usage: xdev_ext_mech_zc_viommu.py GUEST_LOG OUT_JSON [--allow-faults]', file=sys.stderr)
        return 2
    try:
        result = validate_viommu_console(Path(argv[1]).read_text(errors='replace'),
                                         allow_faults=len(argv) == 4)
    except ValueError as error:
        print('XDEV_EXT_ZC_VIOMMU=FAIL ' + str(error))
        return 1
    Path(argv[2]).write_text(json.dumps(result, sort_keys=True) + '\n')
    print('XDEV_EXT_ZC_VIOMMU=PASS dmar=enabled domain=translated policy=strict nvme=%d virtio=%d faults=%d'
          % (len(result['nvme']), len(result['virtio']), result['faults']))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
