#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Record the IOMMU translation mode a run actually used.

    iommu_receipt.py [--device BDF ...] [--kernel-config PATH]
                     [--expect strict|lazy|passthrough|off] [--out RECEIPT.json]

Reads /sys/kernel/iommu_groups/*/type and members, each named device's
iommu_group link and driver, /sys/class/iommu units, the iommu boot
parameters in /proc/cmdline and the CONFIG_IOMMU_DEFAULT_* choice of the
running kernel.  Group types map to modes as the kernel prints them
(drivers/iommu/iommu.c, iommu_group_show_type): DMA -> strict, DMA-FQ ->
lazy (flush queue), identity -> passthrough.  A device with no iommu_group
link is untranslated ("off"); a named device that does not exist is
"absent".  summary_mode is the one mode of the named devices (or of all
non-blocked groups), or "mixed".

The receipt states the mode; it does not count IOTLB invalidations.  An
IOMMU sensitivity campaign records one receipt per boot configuration
(iommu.strict=1, iommu.strict=0, iommu.passthrough=1) next to the harness
result and uses --expect so a run under the wrong mode fails (exit 1).
Exit status: 0 recorded, 1 expectation or read failure, 2 usage error.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import sys

SCHEMA = 'xdev-eval-iommu-receipt-v1'
MODES = {'DMA': 'strict', 'DMA-FQ': 'lazy', 'identity': 'passthrough',
         'blocked': 'blocked', 'unmanaged': 'unmanaged', 'unknown': 'unknown'}
PARAMS = ('iommu', 'iommu.strict', 'iommu.passthrough', 'intel_iommu', 'amd_iommu')
DEFAULTS = {'CONFIG_IOMMU_DEFAULT_DMA_STRICT': 'strict',
            'CONFIG_IOMMU_DEFAULT_DMA_LAZY': 'lazy',
            'CONFIG_IOMMU_DEFAULT_PASSTHROUGH': 'passthrough'}
BDF = re.compile(r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]')


class ReceiptError(Exception):
    pass


def mode_of(group_type):
    try:
        return MODES[group_type]
    except KeyError:
        raise ReceiptError('unknown iommu group type %r' % group_type) from None


def cmdline_params(text):
    out = {}
    for token in text.split():
        key, sep, value = token.partition('=')
        if sep and key in PARAMS:
            out[key] = value
    return out


def config_default(root, release, path=None):
    candidates = [Path(path)] if path else [root / 'boot' / ('config-' + release),
                                            root / 'proc/config.gz']
    for p in candidates:
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if p.name.endswith('.gz'):
            data = gzip.decompress(data)
        for line in data.decode(errors='replace').splitlines():
            key, _, value = line.partition('=')
            if value == 'y' and key in DEFAULTS:
                return DEFAULTS[key]
        return None
    return None


def read_groups(root):
    groups = {}
    base = root / 'sys/kernel/iommu_groups'
    if not base.is_dir():
        return groups
    for g in sorted(base.iterdir(), key=lambda p: int(p.name)):
        try:
            gtype = (g / 'type').read_text().strip()
        except OSError as e:
            raise ReceiptError('cannot read %s/type: %s' % (g, e)) from None
        devices = sorted(d.name for d in (g / 'devices').iterdir()) \
            if (g / 'devices').is_dir() else []
        groups[g.name] = dict(type=gtype, mode=mode_of(gtype), devices=devices)
    return groups


def device_entry(root, groups, bdf):
    d = root / 'sys/bus/pci/devices' / bdf
    if not d.exists():
        return dict(group=None, type=None, mode='absent', driver=None)
    driver = os.path.basename(os.readlink(d / 'driver')) if (d / 'driver').is_symlink() \
        else None
    link = d / 'iommu_group'
    if not link.is_symlink():
        return dict(group=None, type=None, mode='off', driver=driver)
    gid = os.path.basename(os.readlink(link))
    g = groups.get(gid)
    if g is None:
        raise ReceiptError('%s links to missing iommu group %s' % (bdf, gid))
    return dict(group=int(gid), type=g['type'], mode=g['mode'], driver=driver)


def summary(modes):
    modes = set(modes)
    if not modes:
        return 'off'
    return modes.pop() if len(modes) == 1 else 'mixed'


def collect(root, devices=None, kernel_config=None):
    root = Path(root)
    release = (root / 'proc/sys/kernel/osrelease').read_text().strip()
    groups = read_groups(root)
    units = sorted(p.name for p in (root / 'sys/class/iommu').iterdir()) \
        if (root / 'sys/class/iommu').is_dir() else []
    entries = {bdf: device_entry(root, groups, bdf) for bdf in devices or []}
    if entries:
        mode = summary(e['mode'] for e in entries.values())
    else:
        mode = summary(g['mode'] for g in groups.values() if g['mode'] != 'blocked')
    return dict(schema=SCHEMA, kernel_release=release,
                cmdline=cmdline_params((root / 'proc/cmdline').read_text()),
                config_default=config_default(root, release, kernel_config),
                iommu_units=units, groups=groups, devices=entries, summary_mode=mode)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--device', action='append', default=[], help='PCI BDF, repeatable')
    parser.add_argument('--kernel-config')
    parser.add_argument('--expect', choices=('strict', 'lazy', 'passthrough', 'off'))
    parser.add_argument('--out')
    parser.add_argument('--host-root', default='/', help='filesystem root (tests)')
    args = parser.parse_args(argv)
    for bdf in args.device:
        if not BDF.fullmatch(bdf):
            parser.error('--device must be a full PCI BDF such as 0000:17:00.0')
    try:
        receipt = collect(args.host_root, args.device, args.kernel_config)
    except (OSError, ReceiptError) as e:
        print('iommu_receipt: ' + str(e), file=sys.stderr)
        return 1
    text = json.dumps(receipt, indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + '\n')
    print(text)
    if args.expect and receipt['summary_mode'] != args.expect:
        print('iommu_receipt: expected %s, observed %s' %
              (args.expect, receipt['summary_mode']), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
