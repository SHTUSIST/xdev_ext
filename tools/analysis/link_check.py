#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Link speed and width check for E3/E4 runs (plan TODO.70).

    link_check.py --pci BDF=LABEL ... [--xdomain auto|DEV] [--netdev IF]
                  [--min-xdomain-lanes N] [--min-xdomain-gbps G]
                  [--interval-ms MS] [--warmup-ms MS] [--out FILE]
                  [--sysfs-root /sys] [--dry-run] [-- HARNESS ARGV...]

PCIe (the RTX 5090 and the NVMe): current_link_speed/current_link_width
against max_link_speed/max_link_width of /sys/bus/pci/devices/BDF.  The
kernel reads both from the device's Link Status and Link Capabilities
registers (drivers/pci/pci-sysfs.c), the same registers
ce_submit_diag --link-bdf samples.  A GPU drops its link speed when idle, so
an idle snapshot says little: with a harness after --, the links are sampled
every --interval-ms while it runs, and every sample after --warmup-ms must
be at the maximum speed and width; otherwise the run is rejected
(below_max).  Without a harness one snapshot is judged.

Thunderbolt/USB4 XDomain (E4): rx_speed, tx_speed, rx_lanes and tx_lanes of
/sys/bus/thunderbolt/devices/DEV (drivers/thunderbolt/xdomain.c).  Lanes
must reach --min-xdomain-lanes (2: the link is bonded) in both directions
and, when given, the speed --min-xdomain-gbps.  The reference line rate is
rx_speed * rx_lanes.  --netdev records the MTU and state of the
thunderbolt-net interface used by the TCP, NCCL and UCX baselines.

The check changes no setting.  Exit: 0 every link at its maximum, 1 a link
below its maximum, unreadable, or the harness failed, 2 usage, 4 a named
device does not exist.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

SCHEMA = 'xdev-eval-link-check-v1'
_GTS = re.compile(r'^\s*([0-9]+(?:\.[0-9]+)?)\s*GT/s')
_GBPS = re.compile(r'^\s*([0-9]+(?:\.[0-9]+)?)\s*Gb/s\s*$')


class Missing(RuntimeError):
    pass


def pcie_gts(text):
    m = _GTS.match(text)
    return float(m.group(1)) if m else None


def xdomain_gbps(text):
    m = _GBPS.match(text)
    return float(m.group(1)) if m else None


def _read(path):
    return path.read_text().strip()


def _int(text):
    return int(text) if text.isdigit() else None


class Pci:
    def __init__(self, root, bdf, label):
        self.dir = root / 'bus/pci/devices' / bdf
        if not self.dir.is_dir():
            raise Missing(f'PCI device {bdf} ({label}) not found under {root}')
        self.bdf, self.label = bdf, label
        self.max_gts = pcie_gts(_read(self.dir / 'max_link_speed'))
        self.max_width = _int(_read(self.dir / 'max_link_width'))
        self.samples = []	# (mono_ns, gts or None, width or None)

    def sample(self):
        self.samples.append((time.monotonic_ns(), pcie_gts(_read(self.dir / 'current_link_speed')),
                             _int(_read(self.dir / 'current_link_width'))))

    def summary(self, after_ns):
        judged = [s for s in self.samples if s[0] >= after_ns] or self.samples[-1:]
        speeds = [s[1] for s in judged]
        widths = [s[2] for s in judged]
        at_max = [s for s in judged if s[1] == self.max_gts and s[2] == self.max_width]
        if self.max_gts is None or self.max_width is None or None in speeds or None in widths:
            verdict = 'unreadable'
        elif len(at_max) == len(judged):
            verdict = 'ok'
        else:
            verdict = 'below_max'
        known = [v for v in speeds if v is not None]
        knownw = [v for v in widths if v is not None]
        return dict(bdf=self.bdf, max_gts=self.max_gts, max_width=self.max_width,
                    samples=len(judged), samples_total=len(self.samples),
                    min_gts=min(known) if known else None, max_seen_gts=max(known) if known else None,
                    min_width=min(knownw) if knownw else None,
                    fraction_at_max=len(at_max) / len(judged) if judged else None,
                    verdict=verdict)


def xdomain_device(root, name):
    base = root / 'bus/thunderbolt/devices'
    if name != 'auto':
        d = base / name
        if not (d / 'rx_speed').is_file():
            raise Missing(f'XDomain {name} not found under {base}')
        return d
    found = sorted(d for d in base.iterdir() if (d / 'rx_speed').is_file()) if base.is_dir() else []
    if len(found) != 1:
        raise Missing(f'--xdomain auto found {len(found)} XDomain devices under {base}')
    return found[0]


def xdomain_record(d, min_lanes, min_gbps):
    rx, tx = xdomain_gbps(_read(d / 'rx_speed')), xdomain_gbps(_read(d / 'tx_speed'))
    rxl, txl = _int(_read(d / 'rx_lanes')), _int(_read(d / 'tx_lanes'))
    if None in (rx, tx, rxl, txl):
        verdict = 'unreadable'
    elif min(rxl, txl) < min_lanes:
        verdict = 'lanes_below_min'
    elif min_gbps is not None and min(rx, tx) < min_gbps:
        verdict = 'speed_below_min'
    else:
        verdict = 'ok'
    return dict(device=d.name, rx_speed_gbps=rx, tx_speed_gbps=tx, rx_lanes=rxl, tx_lanes=txl,
                line_rate_gbps=rx * rxl if None not in (rx, rxl) else None,
                min_lanes=min_lanes, min_gbps=min_gbps, verdict=verdict)


def netdev_record(root, name):
    d = root / 'class/net' / name
    if not d.is_dir():
        raise Missing(f'network interface {name} not found under {root}')
    return dict(name=name, mtu=_int(_read(d / 'mtu')), operstate=_read(d / 'operstate'))


def check(args):
    root = Path(args.sysfs_root)
    devices = []
    for spec in args.pci:
        bdf, _, label = spec.partition('=')
        devices.append(Pci(root, bdf, label or bdf))
    xd = xdomain_device(root, args.xdomain) if args.xdomain else None
    net = netdev_record(root, args.netdev) if args.netdev else None
    harness = None
    for dev in devices:
        dev.sample()
    start = time.monotonic_ns()
    if args.harness:
        stop = threading.Event()

        def sampler():
            while not stop.wait(args.interval_ms / 1000):
                for dev in devices:
                    dev.sample()

        thread = threading.Thread(target=sampler, daemon=True)
        thread.start()
        result = subprocess.run(args.harness)
        stop.set()
        thread.join()
        harness = dict(argv=args.harness, exit=result.returncode)
        after = start + args.warmup_ms * 1_000_000
    else:
        after = 0
    pci = {dev.label: dev.summary(after) for dev in devices}
    xrec = xdomain_record(xd, args.min_xdomain_lanes, args.min_xdomain_gbps) if xd else None
    # A post-run XDomain reading catches a link that retrained during the run.
    if xd and args.harness:
        post = xdomain_record(xd, args.min_xdomain_lanes, args.min_xdomain_gbps)
        xrec = dict(xrec, after=post, verdict=xrec['verdict'] if xrec['verdict'] != 'ok'
                    else post['verdict'])
    verdicts = [p['verdict'] for p in pci.values()] + ([xrec['verdict']] if xrec else [])
    if harness and harness['exit']:
        verdict = 'harness_failed'
    elif 'unreadable' in verdicts:
        verdict = 'unreadable'
    elif any(v == 'below_max' for v in verdicts):
        verdict = 'below_max'
    elif any(v != 'ok' for v in verdicts):
        verdict = 'xdomain_' + xrec['verdict']
    else:
        verdict = 'ok'
    return dict(schema=SCHEMA, mode='under-load' if args.harness else 'snapshot',
                interval_ms=args.interval_ms, warmup_ms=args.warmup_ms, verdict=verdict,
                pci=pci, xdomain=xrec, netdev=net, harness=harness)


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--pci', action='append', default=[], metavar='BDF=LABEL')
    p.add_argument('--xdomain', metavar='auto|DEV')
    p.add_argument('--netdev')
    p.add_argument('--min-xdomain-lanes', type=int, default=2)
    p.add_argument('--min-xdomain-gbps', type=float)
    p.add_argument('--interval-ms', type=int, default=100)
    p.add_argument('--warmup-ms', type=int, default=500)
    p.add_argument('--sysfs-root', default='/sys')
    p.add_argument('--out')
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('harness', nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    if args.harness[:1] == ['--']:
        args.harness = args.harness[1:]
    if not (args.pci or args.xdomain or args.netdev):
        p.error('name at least one --pci, --xdomain or --netdev')
    if args.interval_ms <= 0 or args.warmup_ms < 0:
        p.error('--interval-ms must be positive and --warmup-ms not negative')
    return args


def main(argv=None):
    args = parse(argv)
    if args.dry_run:
        print(json.dumps(dict(dry_run=True, pci=args.pci, xdomain=args.xdomain,
                              netdev=args.netdev, harness=args.harness,
                              sysfs_root=args.sysfs_root)))
        return 0
    try:
        record = check(args)
    except (Missing, OSError) as error:
        print(f'link_check: {error}', file=sys.stderr)
        return 4
    text = json.dumps(record, indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + '\n')
    else:
        print(text)
    return 0 if record['verdict'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
