#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Causal analysis of explicit record/frame/generation native-view events."""
from collections import defaultdict
import statistics
import copy

from contract import (PAIR_FIELDS, _cpu_scope_selection, canonical_recipe, cpu_interval,
                      inspect_collection, number, validate_run)


IDENTITY = ('session_id', 'record_id', 'generation')
OBSERVATIONS = frozenset(('user_observe', 'view_build_begin', 'view_build_end',
                          'cpu_stage_begin', 'cpu_stage_end', 'sync_begin', 'sync_end',
                          'admission_begin', 'admission_end', 'queue_wait_begin', 'queue_wait_end'))
DIAGNOSTICS = frozenset(('error', 'cancel', 'cancelled', 'stale', 'duplicate'))


def _key(row):
    return tuple(row.get(field) for field in IDENTITY)


def _valid(event):
    return event.get('accepted') is True and type(event.get('status')) is int and event['status'] == 0


def _difference(start, end, reasons):
    if start is None or end is None:
        return None
    if (not number(start.get('ts_ns')) or not number(end.get('ts_ns'))):
        reasons.append('invalid timestamp')
        return None
    if (not start.get('clock') or not start.get('clock_domain') or
            (start.get('clock'), start.get('clock_domain')) !=
            (end.get('clock'), end.get('clock_domain'))):
        reasons.append('clock or clock_domain mismatch')
        return None
    value = end['ts_ns'] - start['ts_ns']
    if value < 0:
        reasons.append('causal timestamp order violated')
        return None
    return value


def _stages(manifest, errors):
    stages = manifest.get('stages')
    if not isinstance(stages, list) or not stages:
        errors.append('stages: explicit dependencies required')
        return {}
    graph = {}
    for row in stages:
        if (not isinstance(row, dict) or not isinstance(row.get('id'), str) or
                not row['id'] or row['id'] in graph or not isinstance(row.get('after'), list)):
            errors.append('stages: invalid or duplicate stage')
            return {}
        graph[row['id']] = row['after']
    for stage, after in graph.items():
        if (any(not isinstance(dep, str) for dep in after) or
                len(set(after)) != len(after) or any(dep not in graph for dep in after)):
            errors.append('stages: unknown or duplicate dependency for ' + stage)
            return {}
    visited, active = set(), set()

    def visit(stage):
        if stage in active:
            return False
        if stage in visited:
            return True
        active.add(stage)
        for dep in graph[stage]:
            if not visit(dep):
                return False
        active.remove(stage)
        visited.add(stage)
        return True
    if not all(visit(stage) for stage in graph):
        errors.append('stages: dependency cycle')
        return {}
    return graph


def summarize_events(manifest, events, *, _admission=True):
    """Compute only matched intervals; missing/failed/foreign probes stay unknown.

    stages describe observed production topology. Supporting a fan-out trace here
    does not assert that a backend implements arbitrary dependency graphs.
    """
    errors, records, gaps, diagnostics = [], [], [], []
    graph = _stages(manifest, errors)
    if not graph:
        return dict(records=[], gaps=[], diagnostics=[], inter_completion_ns=[], errors=errors,
                    performance_eligible=False)
    required = {}
    for row in manifest.get('records', []):
        if (not isinstance(row, dict) or any(type(row.get(k)) is not int for k in IDENTITY) or
                not isinstance(row.get('frame_ids'), list) or not row['frame_ids'] or
                any(type(f) is not int or f < 0 for f in row['frame_ids'])):
            errors.append('records: invalid identity/frame_ids')
            continue
        key = _key(row)
        if key in required or len(set(row['frame_ids'])) != len(row['frame_ids']):
            errors.append('records: duplicate identity/frame_ids')
            continue
        required[key] = row
    indexed, event_errors = defaultdict(list), defaultdict(list)
    for e in events:
        if not isinstance(e, dict):
            errors.append('event: expected object')
            continue
        # Explicitly rejected stale/duplicate observations cannot complete work.
        if e.get('accepted') is False:
            diagnostics.append(e)
            continue
        if (e.get('run_id') != manifest.get('run_id') or _key(e) not in required):
            errors.append('event: foreign run/session/record/generation')
            continue
        row = required[_key(e)]
        key = _key(e)
        if e.get('accepted') is not True:
            event_errors[key].append('event: accepted must be boolean')
            continue
        if (e.get('frame_id') not in [-1, *row['frame_ids']] or
                any(type(e.get(k)) is not int for k in (*IDENTITY, 'frame_id'))):
            event_errors[key].append('event: foreign or invalid frame identity')
            continue
        name, stage, frame = e.get('event'), e.get('stage'), e.get('frame_id')
        if not isinstance(name, str) or not isinstance(stage, str):
            event_errors[key].append('event: invalid event/stage name')
            continue
        if isinstance(name, str) and name.lower() in DIAGNOSTICS:
            diagnostics.append(e)
            continue
        if name in ('native_submit', 'native_complete'):
            placement_ok = frame >= 0 and stage in graph
        elif name in ('record_admit', 'record_terminal'):
            placement_ok = frame == -1 and stage == 'record'
        elif name == 'recycle':
            placement_ok = frame >= 0 and stage == 'frame'
        elif name in OBSERVATIONS:
            placement_ok = ((frame == -1 and stage == 'record') or
                            (frame >= 0 and stage in graph))
        else:
            placement_ok = False
        if not placement_ok:
            event_errors[key].append('event: undeclared accepted work or invalid placement: %s stage=%s frame=%s' %
                                     (name, stage, frame))
            continue
        indexed[(key, frame, stage, name)].append(e)
    dropped = manifest.get('trace_dropped') != 0
    if dropped:
        errors.append('trace_dropped: missing/dropped events invalidate intervals')
    terminal_events = []
    lifetimes = defaultdict(list)
    for key, row in required.items():
        local_errors = list(event_errors[key])
        identity = dict(zip(IDENTITY, key))

        def unique(frame, stage, name):
            matches = indexed.get((key, frame, stage, name), [])
            if len(matches) != 1:
                problem = 'missing' if not matches else 'duplicate'
                local_errors.append('%s frame=%s stage=%s: %s %s' %
                                    (key, frame, stage, problem, name))
                return None
            e = matches[0]
            if not _valid(e):
                local_errors.append('%s frame=%s stage=%s: failed %s status=%r' %
                                    (key, frame, stage, name, e.get('status')))
                return None
            if (not number(e.get('ts_ns')) or
                    e.get('clock') != manifest.get('clock') or
                    e.get('clock_domain') != manifest.get('clock_domain')):
                local_errors.append('%s: %s clock/timestamp mismatch' % (key, name))
                return None
            return e

        admit = unique(-1, 'record', 'record_admit')
        terminal = unique(-1, 'record', 'record_terminal')
        for frame in row['frame_ids']:
            submits, completes = {}, {}
            for stage in graph:
                submits[stage] = unique(frame, stage, 'native_submit')
                completes[stage] = unique(frame, stage, 'native_complete')
                reasons = []
                if submits[stage] is not None and completes[stage] is not None:
                    # Logical generation identifies the record across stages.
                    # The raw stage-local frame generation may advance between
                    # stages, but must not change within one accepted operation.
                    for field in ('frame_generation', 'ticket', 'cookie', 'native_frame_id',
                                  'native_session_id', 'origin_tgid', 'process_start_ticks',
                                  'native_user_data', 'frame_offset', 'frame_length',
                                  'address', 'bytes', 'class_id'):
                        before, after = submits[stage], completes[stage]
                        if field in before or field in after:
                            if field not in before or field not in after or before[field] != after[field]:
                                reasons.append('accepted native request %s identity mismatch' % field)
                    if reasons:
                        completes[stage] = None
                _difference(admit, submits[stage], reasons)
                _difference(submits[stage], completes[stage], reasons)
                _difference(completes[stage], terminal, reasons)
                local_errors.extend('%s frame=%s stage=%s: %s' % (key, frame, stage, why)
                                    for why in reasons)
            for stage, dependencies in graph.items():
                for dep in dependencies:
                    reasons = []
                    before, after = completes[dep], submits[stage]
                    if before is None:
                        reasons.append('missing/invalid native_complete for ' + dep + ' (clock or identity may differ)')
                    if after is None:
                        reasons.append('missing/invalid accepted native_submit for ' + stage + ' (clock or identity may differ)')
                    value = _difference(before, after, reasons)
                    if dropped:
                        reasons.append('trace_dropped')
                    if reasons:
                        value = None
                        local_errors.extend('%s frame=%s %s->%s: %s' % (key, frame, dep, stage, why)
                                            for why in reasons)
                    gaps.append(dict(run_id=manifest.get('run_id'), **identity, frame_id=frame,
                                     from_stage=dep, to_stage=stage, duration_ns=value, reasons=reasons))
            recycles = indexed.get((key, frame, 'frame', 'recycle'), [])
            recycle = None
            if recycles:
                recycle = unique(frame, 'frame', 'recycle')
                if recycle is not None:
                    for stage, complete in completes.items():
                        reasons = []
                        if complete is None:
                            reasons.append('uncompleted consumer ' + stage)
                        _difference(complete, recycle, reasons)
                        local_errors.extend('%s frame=%s recycle: %s' % (key, frame, why) for why in reasons)
            frame_submits = [s for s in submits.values() if s is not None]
            if frame_submits:
                # A logical ordinal is reused in every expected record. Actual
                # resource reuse is scoped to the observed allocation/owner,
                # not that ordinal; old strict fixtures retain the logical key.
                source = frame_submits[0]
                allocation = ((source.get('native_session_id'), source.get('origin_tgid'),
                               source.get('process_start_ticks'), source['native_frame_id'])
                              if 'native_frame_id' in source else frame)
                lifetimes[(key[0], allocation)].append((key, min(s['ts_ns'] for s in frame_submits), recycle))
        reasons = []
        latency = _difference(admit, terminal, reasons)
        local_errors.extend('%s record latency: %s' % (key, why) for why in reasons)
        if dropped or local_errors:
            latency = None
        if latency is not None:
            terminal_events.append(terminal)
        errors.extend(local_errors)
        records.append(dict(run_id=manifest.get('run_id'), **identity, latency_ns=latency,
                            measured=row.get('measured', True), reasons=local_errors))
    # A reused frame in the same session cannot be admitted before last recycle.
    for frame, lives in lifetimes.items():
        lives.sort(key=lambda item: item[1])
        for previous, current in zip(lives, lives[1:]):
            if previous[2] is None or previous[2]['ts_ns'] > current[1]:
                errors.append('recycle: frame %s reused before previous last-consumer release' % (frame,))
                for rec in records:
                    if _key(rec) == current[0]:
                        rec['latency_ns'] = None
    completion_gaps = []
    # Inter-completion is a different statistic. Never subtract different clocks.
    valid_keys = {_key(r) for r in records if r['latency_ns'] is not None}
    terminal_events = [e for e in terminal_events if _key(e) in valid_keys]
    terminal_events.sort(key=lambda e: e['ts_ns'])
    for start, end in zip(terminal_events, terminal_events[1:]):
        reasons = []
        completion_gaps.append(_difference(start, end, reasons))
        errors.extend(reasons)
    return dict(records=records, gaps=gaps, diagnostics=diagnostics, inter_completion_ns=completion_gaps,
                errors=errors, performance_eligible=_admission and not errors and not validate_run(manifest, performance=True))


def compare_runs(left, right):
    """Pair equivalent runs; preserve right-minus-left negatives and unknowns."""
    if left is None or right is None:
        return dict(eligible=False, errors=['missing arm'], delta=None, performance_eligible=False)
    errors = [*['left.' + e for e in validate_run(left)],
              *['right.' + e for e in validate_run(right)]]
    for field in PAIR_FIELDS:
        if left.get(field) != right.get(field):
            errors.append(field + ': paired workload mismatch')
    if 'cpu_scope' in left or 'cpu_scope' in right:
        try:
            left_cpus = _cpu_scope_selection(left, left.get('cpu_scope'))
            right_cpus = _cpu_scope_selection(right, right.get('cpu_scope'))
            if left_cpus != right_cpus:
                errors.append('cpu_scope.selected_cpus: paired CPU set mismatch')
        except ValueError as error:
            errors.append('cpu_scope: ' + str(error))
    try:
        left_recipe, right_recipe = canonical_recipe(left), canonical_recipe(right)
        for field in left_recipe.keys() | right_recipe.keys():
            if (field not in left_recipe or field not in right_recipe or
                    left_recipe[field] != right_recipe[field]):
                errors.append('recipe.' + field + ': paired workload mismatch')
    except ValueError as error:
        errors.append(str(error))
    if errors:
        return dict(eligible=False, errors=errors, delta=None, performance_eligible=False)
    delta = {}
    for metric in left['metrics'].keys() | right['metrics'].keys():
        a, b = left['metrics'].get(metric), right['metrics'].get(metric)
        if metric == 'cpu_ns_per_record_bounds':
            delta[metric] = (dict(lower=b['lower'] - a['upper'], upper=b['upper'] - a['lower'])
                             if cpu_interval(a) and cpu_interval(b) else None)
        else:
            delta[metric] = b - a if number(a) and number(b) else None
    return dict(eligible=True, errors=[], delta=delta,
                performance_eligible=not validate_run(left, performance=True) and
                not validate_run(right, performance=True))


def compare_pairs(pairs):
    """Runs, never individual records, are independent statistical units."""
    kept, excluded = [], []
    seen = set()
    for index, (left, right) in enumerate(pairs):
        report = compare_runs(left, right)
        pair_id = left.get('pair_id') if isinstance(left, dict) else None
        if pair_id in seen:
            report.update(eligible=False, errors=['pair_id: duplicate statistical unit'])
        if report['eligible']:
            seen.add(pair_id)
            kept.append(dict(pair_id=pair_id, **report))
        else:
            excluded.append(dict(index=index, pair_id=pair_id, errors=report['errors']))
    metrics = set().union(*(r['delta'] for r in kept))
    means = {}
    for metric in metrics:
        values = [r['delta'].get(metric) for r in kept]
        if metric == 'cpu_ns_per_record_bounds':
            means[metric] = ({bound: statistics.fmean(v[bound] for v in values) for bound in ('lower', 'upper')}
                             if values and all(v is not None for v in values) else None)
        else:
            means[metric] = statistics.fmean(values) if values and all(v is not None for v in values) else None
    return dict(pairs=kept, excluded=excluded, mean_delta=means,
                performance_eligible=bool(kept) and not excluded and all(r['performance_eligible'] for r in kept))


def import_collection(manifest, receipt):
    """Import raw collector artifacts; derive metrics instead of using claimed ones."""
    observed = inspect_collection(manifest, receipt)
    plan = manifest.get('collection_manifest', manifest)
    imported = copy.deepcopy(plan)
    imported.update(collection_manifest=copy.deepcopy(plan), collection_receipt=copy.deepcopy(receipt))
    if observed.get('mapped_manifest') is not None:
        for field in ('runtime_mapping_version', 'runtime_bindings', 'runtime_frames'):
            imported[field] = copy.deepcopy(observed['mapped_manifest'][field])
    imported['total_cpu_ns'] = observed['total_cpu_ns']
    imported['total_cpu_ns_bounds'] = observed['total_cpu_ns_bounds']
    summary = summarize_events(imported, observed['events'], _admission=False)
    measured = [r for r in summary['records'] if r.get('measured', True)]
    latencies = [r['latency_ns'] for r in measured]
    imported['completed_records'] = sum(v is not None for v in latencies)
    imported['correctness_pass'] = not observed['errors'] and not summary['errors']
    imported['status'] = 'ok' if imported['correctness_pass'] else 'failed'
    valid = latencies and all(number(v, 1) for v in latencies)
    measured_keys = {_key(row) for row in measured}
    endpoints = [e for e in observed['events'] if _key(e) in measured_keys and e.get('accepted') is True and
                 e.get('status') == 0 and e.get('event') in ('record_admit', 'record_terminal')]
    admits = [e['ts_ns'] for e in endpoints if e['event'] == 'record_admit']
    terminals = [e['ts_ns'] for e in endpoints if e['event'] == 'record_terminal']
    elapsed = max(terminals) - min(admits) if valid and admits and terminals else None
    imported['metrics'] = dict(
        latency_ns=statistics.fmean(latencies) if valid else None,
        throughput_bytes_per_second=(len(latencies) * imported['record_bytes'] * 1e9 / elapsed
                                     if elapsed is not None and elapsed > 0 else None),
        cpu_ns_per_record=(observed['total_cpu_ns'] / len(latencies)
                           if valid and observed['total_cpu_ns'] is not None else None),
        cpu_ns_per_record_bounds=({bound: observed['total_cpu_ns_bounds'][bound] / len(latencies)
                                   for bound in ('lower', 'upper')}
                                  if valid and observed['total_cpu_ns_bounds'] is not None else None))
    errors = list(dict.fromkeys([*observed['errors'], *summary['errors'],
                                *validate_run(imported, performance=True)]))
    if not valid or elapsed is None or elapsed <= 0:
        errors.append('metrics: complete positive-duration matched record samples required')
    eligible = not errors
    summary['performance_eligible'] = eligible
    fatal_reasons = (*observed['errors'], *summary['errors'])
    failed = (
              (isinstance(receipt, dict) and (receipt.get('status') in ('failed', 'fail') or
               (type(receipt.get('returncode')) is int and receipt['returncode'] != 0))) or
              any(any(word in error for word in ('sha256 mismatch', 'identity/boundary mismatch', 'foreign', 'duplicate',
                                                              'invalid JSON', 'failed', 'regressed',
                                                              'causal timestamp', 'recycle:'))
                  for error in fatal_reasons))
    return dict(status='ok' if eligible else 'failed' if failed else 'unavailable',
                manifest=imported, summary=summary, errors=errors, performance_eligible=eligible)
