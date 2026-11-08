#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""K-KV metrics from raw run records (run.py output); nothing is invented.

  python3 analyze.py RESULT_DIR... [--bytes-per-count N] [--output report.json]

Per arm and prefix: restore latency median, IQR (inclusive quartiles) and
CV over successful runs; CPU core-seconds per GB (10^9 effective bytes) on
host 1 and host 2, raw and minus the arm's idle background rate measured
before its runs; host-2 memory traffic per effective byte when perf counts
and --bytes-per-count are given. Against Mooncake (same model and prefix):
ratio of median latencies with an independent bootstrap of each arm's runs,
verdict within_10pct / loss_slower_than_10pct / faster_by_more_than_10pct
(no verdict below 10 runs per arm), CPU reduction per host with a resource
claim only if both reach 2x, memory traffic pass at <= 0.1 B/B. Against
recompute: restore latency over the command's own prefill time. Host-2
criterion against the ordinary baseline (nvmeof, same model and prefix): the
CPU copies no payload byte on host 2 (host2_cpu_copy_bytes of every
successful run is 0; a run without the count gives not_measured) and host-2
CPU core-seconds per GB at most half of the baseline's (10 runs per arm).
Thresholds are those of the K-KV design; the report states no claim itself.

E5 ablation (run.py --step L1..L5): a result directory labelled with a level
goes only into report['ablation'], one entry per model and prefix with one
row per level: restore time median, min and max over the successful runs,
the median ratio to the previous present level and to L1 ("x faster"), and
per-restore CPU core-seconds on each host, raw and minus the idle rate times
the restore's wall time (raw values and idle rates are kept). A directory
whose rows carry another level, two configurations of one level, or a level
whose arm, destination or CE submission setting differs from its definition
is refused, so levels are never pooled.
"""
import argparse
import json
from pathlib import Path
import random
import statistics
import sys

GB = 1e9
MIN_RUNS = 10
LAT_BAND = 0.10
CPU_FACTOR = 2.0
MEM_LIMIT = 0.1
STEPS = ('L1', 'L2', 'L3', 'L4', 'L5')
STEP_DST = {'L2': 'user-copy', 'L3': 'user-direct', 'L4': 'ce-vmm', 'L5': 'ce-vmm'}
STEP_CE_ENTRIES = {'L4': (1,), 'L5': (0, None)}


def quantile(sorted_values, q):
    if not sorted_values:
        return None
    pos = (len(sorted_values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def describe(values):
    if not values:
        return None
    s = sorted(values)
    q = statistics.quantiles(s, n=4, method='inclusive') if len(s) > 1 else [s[0]] * 3
    mean = statistics.mean(s)
    return dict(n=len(s), median=statistics.median(s), q1=q[0], q3=q[2], iqr=q[2] - q[0],
                mean=mean, cv=statistics.stdev(s) / mean if len(s) > 1 and mean else 0.0,
                min=s[0], max=s[-1])


def summarize(records, idle=None, bytes_per_count=None):
    ok = [r for r in records if r.get('ok')]
    out = dict(n_total=len(records), n_ok=len(ok), n_failed=len(records) - len(ok),
               latency_s=describe([r['latency_ns'] / 1e9 for r in ok]))
    for host in ('host1', 'host2'):
        raw, net = [], []
        rate = None
        if idle and idle.get(host) and idle[host].get('wall_seconds'):
            rate = idle[host]['busy_core_seconds'] / idle[host]['wall_seconds']
        for r in ok:
            cpu = r.get(f'{host}_cpu') or {}
            if 'busy_core_seconds' not in cpu:
                continue
            gb = r['bytes'] / GB
            raw.append(cpu['busy_core_seconds'] / gb)
            if rate is not None:
                net.append((cpu['busy_core_seconds'] - rate * cpu['wall_seconds']) / gb)
        out[f'{host}_core_seconds_per_gb'] = dict(
            raw=statistics.median(raw) if raw else None,
            minus_idle=statistics.median(net) if net else None,
            idle_rate_core_seconds_per_second=rate)
    traffic = []
    if bytes_per_count:
        for r in ok:
            if r.get('perf'):
                traffic.append(sum(r['perf'].values()) * bytes_per_count / r['bytes'])
    out['host2_memory_bytes_per_byte'] = statistics.median(traffic) if traffic else None
    copies = [r.get('host2_cpu_copy_bytes') for r in ok]
    out['host2_cpu_copy_bytes'] = max(copies) if copies and None not in copies else None
    return out


def host2_criterion(name, s, base, dst=None):
    """Copy-free host 2 and halved host-2 CPU against the ordinary baseline."""
    copied = s['host2_cpu_copy_bytes']
    # The worker's count is a property of its code (no timed path copies
    # payload), not a measurement, so a zero reads 'by_construction', never
    # 'pass'; a measured quantity for this criterion is host-2 memory traffic.
    c = dict(arm=name, dst=dst, baseline='nvmeof', model=s['model'],
             prefix_tokens=s['prefix_tokens'], cpu_copy_bytes=copied,
             cpu_copy_bytes_basis='worker code, not measured',
             copy_verdict='not_measured' if copied is None else
             ('by_construction' if copied == 0 else 'fail'))
    mine, theirs = s['host2_core_seconds_per_gb']['raw'], base['host2_core_seconds_per_gb']['raw']
    c['core_seconds_ratio'] = theirs / mine if mine and theirs is not None else None
    if s['n_ok'] < MIN_RUNS or base['n_ok'] < MIN_RUNS:
        c['core_seconds_verdict'] = 'insufficient_runs'
    elif c['core_seconds_ratio'] is None:
        c['core_seconds_verdict'] = 'not_measured'
    else:
        c['core_seconds_verdict'] = 'pass' if c['core_seconds_ratio'] >= CPU_FACTOR else 'fail'
    return c


def bootstrap_ratio(a, b, resamples=10000, seed=1):
    """Median(a)/median(b) under independent resampling of each arm."""
    rng = random.Random(seed)
    ratios = []
    for _ in range(resamples):
        ra = statistics.median(rng.choices(a, k=len(a)))
        rb = statistics.median(rng.choices(b, k=len(b)))
        ratios.append(ra / rb)
    ratios.sort()
    return {f'p{p}': quantile(ratios, p / 100) for p in (2.5, 25, 50, 97.5)}


def load_dir(path):
    d = Path(path)
    meta = json.loads((d / 'run.json').read_text())
    records = [json.loads(l) for l in (d / 'results.jsonl').read_text().splitlines() if l.strip()]
    return meta, records


def latency_verdict(ratio):
    if ratio > 1 + LAT_BAND:
        return 'loss_slower_than_10pct'
    if ratio < 1 - LAT_BAND:
        return 'faster_by_more_than_10pct'
    return 'within_10pct'


def step_config(d, meta, records):
    """Check one labelled directory against its level's definition."""
    step = meta['step']
    if step not in STEPS:
        raise SystemExit(f'{d}: unknown level {step!r}')
    if step == 'L1':
        ok = meta.get('arm') in ('nvmeof', 'custom')
    else:
        ok = meta.get('arm') == 'xdev-ext' and meta.get('dst') == STEP_DST[step]
    if not ok or (step in STEP_CE_ENTRIES and
                  meta.get('ce_entries_per_submit') not in STEP_CE_ENTRIES[step]):
        raise SystemExit(f'{d}: arm {meta.get("arm")} dst {meta.get("dst")} ce_entries_per_submit '
                         f'{meta.get("ce_entries_per_submit")} is not level {step}')
    other = {r.get('step') for r in records} - {step}
    if other:
        raise SystemExit(f'{d}: rows of level(s) {sorted(map(str, other))} in a level {step} run')
    return (meta.get('arm'), meta.get('dst'), meta.get('ce_entries_per_submit'))


def idle_rate(idle, host):
    if idle and idle.get(host) and idle[host].get('wall_seconds'):
        return idle[host]['busy_core_seconds'] / idle[host]['wall_seconds']
    return None


def per_restore_cpu(records, host):
    """records: (row, idle of its directory); each run subtracts its own idle rate."""
    raw, net, rates = [], [], []
    for r, idle in records:
        rate = idle_rate(idle, host)
        if rate is not None and rate not in rates:
            rates.append(rate)
        cpu = r.get(f'{host}_cpu') or {}
        if 'busy_core_seconds' not in cpu:
            continue
        raw.append(cpu['busy_core_seconds'])
        if rate is not None:
            net.append(cpu['busy_core_seconds'] - rate * cpu['wall_seconds'])
    return dict(raw=statistics.median(raw) if raw else None,
                minus_idle=statistics.median(net) if net else None,
                idle_rate_core_seconds_per_second=rates)


def ablation(levels):
    """levels: step -> dict(config, records=[(row, idle of its directory)])."""
    points = {}
    for step, lv in levels.items():
        for r, idle in lv['records']:
            points.setdefault((r['model'], r['prefix_tokens']), {}).setdefault(step, []).append(
                (r, idle))
    out = []
    for (model, prefix), by_step in sorted(points.items()):
        rows_, prev, first = [], None, None
        for step in STEPS:
            recs = by_step.get(step)
            if recs is None:
                prev = None if step != 'L1' else prev
                continue
            ok = [(r, idle) for r, idle in recs if r.get('ok')]
            lat = sorted(r['latency_ns'] / 1e9 for r, _ in ok)
            arm, dst, ce = levels[step]['config']
            med = statistics.median(lat) if lat else None
            row = dict(step=step, arm=arm, dst=dst, ce_entries_per_submit=ce,
                       n_total=len(recs), n_ok=len(ok), insufficient_runs=len(ok) < MIN_RUNS,
                       latency_s=dict(median=med, min=lat[0], max=lat[-1]) if lat else None,
                       speedup_vs_previous=prev / med if prev and med else None,
                       speedup_vs_l1=first / med if first and med else None)
            for host in ('host1', 'host2'):
                row[f'{host}_core_seconds'] = per_restore_cpu(ok, host)
            if step == 'L1':
                first = med
            prev = med
            rows_.append(row)
        out.append(dict(model=model, prefix_tokens=prefix, levels=rows_))
    return out


def analyze(dirs, resamples=10000, seed=1, bytes_per_count=None):
    arms, recompute, levels = {}, [], {}
    inputs = []
    for d in dirs:
        meta, records = load_dir(d)
        inputs.append(dict(dir=str(d), arm=meta.get('arm', meta.get('kind')),
                           step=meta.get('step'), performance_claim=meta.get('performance_claim')))
        if meta.get('kind') == 'recompute':
            recompute.extend(records)
            continue
        if meta.get('step') is not None:
            config = step_config(d, meta, records)
            lv = levels.setdefault(meta['step'], dict(config=config, records=[]))
            if lv['config'] != config:
                raise SystemExit(f'level {meta["step"]} from two configurations: '
                                 f'{lv["config"]} and {config}')
            lv['records'].extend((r, meta.get('idle')) for r in records)
            continue
        arm = arms.setdefault(meta['arm'], dict(idle=meta.get('idle'), records=[],
                                                dst=meta.get('dst')))
        if arm['dst'] != meta.get('dst'):
            raise SystemExit(f"arm {meta['arm']} mixes dst {arm['dst']} and {meta.get('dst')}; "
                             'analyze each host-2 destination separately')
        arm['records'].extend(records)
    report = dict(schema=1, inputs=inputs, thresholds=dict(min_runs=MIN_RUNS, latency_band=LAT_BAND,
                                                          cpu_factor=CPU_FACTOR, memory_limit=MEM_LIMIT),
                  arms=[], comparisons=[], recompute=[], host2_criterion=[],
                  ablation=ablation(levels))
    points = {}
    for name, arm in sorted(arms.items()):
        groups = {}
        for r in arm['records']:
            groups.setdefault((r['model'], r['prefix_tokens']), []).append(r)
        entry = dict(arm=name, dst=arm['dst'], points=[])
        for (model, prefix), recs in sorted(groups.items()):
            s = dict(model=model, prefix_tokens=prefix, bytes=recs[0]['bytes'],
                     **summarize(recs, arm['idle'], bytes_per_count))
            entry['points'].append(s)
            points[(name, model, prefix)] = (s, [r['latency_ns'] / 1e9 for r in recs if r.get('ok')])
        report['arms'].append(entry)
    for (name, model, prefix), (s, _) in sorted(points.items()):
        ordinary = points.get(('nvmeof', model, prefix))
        if name == 'xdev-ext' and ordinary:
            report['host2_criterion'].append(host2_criterion(name, s, ordinary[0],
                                                             arms[name]['dst']))
    for (name, model, prefix), (s, lat) in sorted(points.items()):
        if name == 'mooncake':
            continue
        base = points.get(('mooncake', model, prefix))
        if not base or name != 'xdev-ext':
            continue
        bs, blat = base
        c = dict(arm=name, baseline='mooncake', model=model, prefix_tokens=prefix,
                 n=dict(arm=s['n_ok'], baseline=bs['n_ok']))
        if s['n_ok'] < MIN_RUNS or bs['n_ok'] < MIN_RUNS:
            c['latency_verdict'] = 'insufficient_runs'
        else:
            ratio = s['latency_s']['median'] / bs['latency_s']['median']
            ci = bootstrap_ratio(lat, blat, resamples, seed)
            verdict = latency_verdict(ratio)
            c.update(latency_ratio_median=ratio, latency_ratio_bootstrap=ci, latency_verdict=verdict,
                     ci_crosses_band=any(latency_verdict(ci[k]) != verdict for k in ('p2.5', 'p97.5')))
        red = {}
        for host in ('host1', 'host2'):
            mine, theirs = s[f'{host}_core_seconds_per_gb']['raw'], bs[f'{host}_core_seconds_per_gb']['raw']
            red[host] = theirs / mine if mine and theirs is not None else None
        c['cpu_reduction'] = red
        c['resource_claim_allowed'] = all(v is not None and v >= CPU_FACTOR for v in red.values())
        t = s['host2_memory_bytes_per_byte']
        c['host2_memory_bytes_per_byte'] = dict(
            value=t, verdict='not_measured' if t is None else ('pass' if t <= MEM_LIMIT else 'fail'))
        report['comparisons'].append(c)
    by_prefix = {}
    for r in recompute:
        if r.get('ok'):
            rep = r.get('reported') or {}
            value = rep.get('prefill_seconds') if isinstance(rep.get('prefill_seconds'), (int, float)) \
                else r['wall_ns'] / 1e9
            by_prefix.setdefault((r['model'], r['prefix_tokens']), []).append(value)
    slower_everywhere = bool(by_prefix)
    for (model, prefix), values in sorted(by_prefix.items()):
        mine = points.get(('xdev-ext', model, prefix))
        item = dict(model=model, prefix_tokens=prefix, recompute_s_median=statistics.median(values),
                    n=len(values))
        if mine and mine[0]['latency_s']:
            item['restore_over_recompute'] = mine[0]['latency_s']['median'] / item['recompute_s_median']
            slower_everywhere &= item['restore_over_recompute'] > 1
        else:
            slower_everywhere = False
        report['recompute'].append(item)
    report['slower_than_recompute_on_all_prefixes'] = slower_everywhere
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('dirs', nargs='+')
    p.add_argument('--bytes-per-count', type=float)
    p.add_argument('--resamples', type=int, default=10000)
    p.add_argument('--seed', type=int, default=1)
    p.add_argument('--output')
    args = p.parse_args(argv)
    report = analyze(args.dirs, args.resamples, args.seed, args.bytes_per_count)
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        Path(args.output).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
