#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Admission for native-view evidence; schema validity is not physical proof."""
import hashlib
import math
from pathlib import Path
import re

COLLECTOR_ENTRY = Path(__file__).resolve().parent.parent / 'native_trace' / 'collector.py'
RUNTIME_FIELDS = frozenset(('runtime_mapping_version', 'runtime_bindings', 'runtime_frames'))
DERIVED_FIELDS = RUNTIME_FIELDS | frozenset(('collection_manifest', 'collection_receipt', 'metrics',
    'completed_records', 'correctness_pass', 'status', 'total_cpu_ns'))
# These must match in a paired comparison. Arm names and waiting strategy may differ.
PAIR_FIELDS = (
    'pair_id', 'exact_sha', 'config_hash', 'device_manifest', 'endpoint', 'load',
    'pool_bytes', 'record_bytes', 'frame_bytes', 'depth', 'batch', 'mtu',
    'protocol', 'crc', 'setup_in_timing', 'oracle_in_timing',
    'complete_boundary', 'submit_boundary', 'clock', 'clock_domain',
    'cpu_accounting', 'cpu_budget', 'completed_records', 'numa', 'iommu', 'group_bytes',
    'segments_per_group', 'inflight_bytes', 'native_batch', 'processing', 'stages',
    'records', 'workload',
)


def canonical_recipe(run):
    """Compare visible common work even when a claimed config hash is equal.

    Preserve unknown recipe fields conservatively: a new work parameter cannot
    silently evade pairing. Only the intentionally different arm/wait selection
    is excluded. Materialize the one actual workload default accepted by chains.
    """
    recipe = run.get('recipe')
    if recipe is None:
        return {}
    if not isinstance(recipe, dict):
        raise ValueError('recipe: expected object')
    common = {key: value for key, value in recipe.items()
              if key not in ('arm', 'arms', 'wait', 'wait_strategy')}
    common.setdefault('warmup_records', 4)
    return common


def number(value, minimum=0):
    return (type(value) in (int, float) and math.isfinite(value) and value >= minimum)


def _same_json(left, right):
    """Compare retained JSON values without treating False as integer zero."""
    import json
    try:
        return (json.dumps(left, sort_keys=True, allow_nan=False) ==
                json.dumps(right, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError):
        return False


def parse_quantity(text, kind='bytes'):
    """Parse case-sensitive SI/IEC units; a bit rate is converted to bytes/s."""
    if kind not in ('bytes', 'bytes_per_second') or not isinstance(text, str):
        raise ValueError('quantity needs bytes or bytes_per_second with explicit units')
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)(i?)([Bb])(/s)?', text)
    if not match:
        raise ValueError('invalid or missing quantity unit: %r' % text)
    value, prefix, binary, unit, rate = match.groups()
    if bool(rate) != (kind == 'bytes_per_second') or (binary and not prefix):
        raise ValueError('quantity unit does not match ' + kind)
    if kind == 'bytes' and unit != 'B':
        raise ValueError('bytes requires a byte unit')
    scale = (1024 if binary else 1000) ** ('KMGT'.index(prefix) + 1) if prefix else 1
    result = float(value) * scale / (8 if unit == 'b' else 1)
    if not math.isfinite(result):
        raise ValueError('nonfinite quantity')
    return int(result) if result.is_integer() else result


def validate_artifact(artifact, field):
    """Verify immutable raw-file linkage, rather than accepting a truth flag."""
    if not isinstance(artifact, dict) or not artifact.get('path'):
        return [field + ': missing raw artifact path/sha256']
    digest = artifact.get('sha256')
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        return [field + ': invalid sha256']
    try:
        hashed = hashlib.sha256()
        with Path(artifact['path']).open('rb') as stream:
            for chunk in iter(lambda: stream.read(1048576), b''):
                hashed.update(chunk)
        actual = hashed.hexdigest()
    except (OSError, TypeError, ValueError) as error:
        return [field + ': cannot read raw artifact: ' + str(error)]
    return [] if actual == digest else [field + ': raw artifact sha256 mismatch']


def validate_run(run, performance=False):
    """Return all diagnostics; fixtures can parse but cannot pass performance gates.

    Performance also needs raw evidence inspection by the collector. This function
    never elevates caller-supplied booleans into verified device observations.
    """
    if not isinstance(run, dict):
        return ['run: expected object']
    errors = []
    if run.get('schema_version') != 1:
        errors.append('schema_version: expected 1')
    for name in ('run_id', 'pair_id', 'arm', 'endpoint', 'load', 'protocol', 'crc',
                 'environment', 'evidence_kind', 'status', 'cpu_accounting',
                 'clock', 'clock_domain', 'complete_boundary', 'submit_boundary'):
        if not isinstance(run.get(name), str) or not run[name]:
            errors.append(name + ': missing nonempty string')
    for name, length in (('exact_sha', 40), ('bpf_object_hash', 64), ('config_hash', 64)):
        if not isinstance(run.get(name), str) or not re.fullmatch('[0-9a-f]{%d}' % length, run[name]):
            errors.append(name + ': missing or invalid hex identity')
    if not isinstance(run.get('device_manifest'), dict) or not run['device_manifest']:
        errors.append('device_manifest: missing device identities')
    for name in ('pool_bytes', 'record_bytes', 'frame_bytes', 'depth', 'batch', 'mtu',
                 'registration_calls'):
        if type(run.get(name)) is not int or run[name] < 1:
            errors.append(name + ': expected positive integer')
    for name in ('total_cpu_ns', 'payload_copy_bytes', 'completed_records', 'trace_dropped'):
        if type(run.get(name)) is not int or run[name] < 0:
            errors.append(name + ': expected nonnegative integer')
    for name in ('physical', 'correctness_pass', 'setup_in_timing', 'oracle_in_timing',
                 'registration_reused', 'shared_pages', 'afxdp_zero_copy', 'nvme_no_bounce'):
        if type(run.get(name)) is not bool:
            errors.append(name + ': expected boolean')
    for name in ('registration_reused', 'shared_pages', 'afxdp_zero_copy', 'nvme_no_bounce'):
        if run.get(name) is not True:
            errors.append(name + ': strong shared-page baseline requires true; unknown is insufficient')
    if run.get('registration_calls') != 1:
        errors.append('registration_calls: shared registration must be reused')
    if run.get('payload_copy_bytes') != 0:
        errors.append('payload_copy_bytes: baseline must eliminate CPU payload copying')
    if run.get('load') not in ('closed', 'sustained', 'open'):
        errors.append('load: unknown offered-load definition')
    stages = run.get('stages')
    if not isinstance(stages, list) or not stages:
        errors.append('stages: explicit dependency graph required')
    if not isinstance(run.get('records'), list) or not run['records']:
        errors.append('records: per-record frame identities required')
    if not isinstance(run.get('metrics'), dict):
        errors.append('metrics: expected object (unknown values use null)')
    else:
        for key, value in run['metrics'].items():
            if value is not None and not number(value):
                errors.append('metrics.' + key + ': expected finite nonnegative number or null')
    if isinstance(run.get('trace'), dict) and run['trace'].get('sessions'):
        errors.extend(validate_runtime_plan(run))
    if performance:
        for name in ('physical', 'correctness_pass'):
            if run.get(name) is not True:
                errors.append(name + ': required for physical performance')
        if run.get('environment') != 'physical':
            errors.append('environment: physical run required')
        if run.get('evidence_kind') != 'physical':
            errors.append('evidence_kind: physical raw evidence required')
        if run.get('status') != 'ok':
            errors.append('status: successful measured run required')
        if run.get('oracle_in_timing') is not False:
            errors.append('oracle_in_timing: independent post-run oracle must be outside timing')
        if run.get('setup_in_timing') is not False:
            errors.append('setup_in_timing: steady-state comparison excludes setup')
        if run.get('cpu_accounting') != 'system_total':
            errors.append('cpu_accounting: process-only accounting is insufficient')
        if not number(run.get('total_cpu_ns'), 1):
            errors.append('total_cpu_ns: positive whole-system CPU observation required')
        if not number(run.get('completed_records'), 1):
            errors.append('completed_records: positive success denominator required')
        if run.get('trace_dropped') != 0:
            errors.append('trace_dropped: loss invalidates causal evidence')
        if run.get('complete_boundary') != 'native_observed':
            errors.append('complete_boundary: native completion required, not user CQE observation')
        if run.get('submit_boundary') != 'native_accepted':
            errors.append('submit_boundary: accepted native request required')
        for name in ('cpu_budget', 'group_bytes', 'segments_per_group', 'inflight_bytes',
                     'native_batch', 'numa', 'iommu', 'processing'):
            if name not in run or run[name] is None:
                errors.append(name + ': missing matched measurement configuration')
        # Physical collection/import is a separate step. Raw files and verified
        # post-oracle/probe mappings must be produced by that collector, not here.
        observed = inspect_collection(run, run.get('collection_receipt'))
        errors.extend(observed['errors'])
        if observed['total_cpu_ns'] is not None and run.get('total_cpu_ns') != observed['total_cpu_ns']:
            errors.append('total_cpu_ns: does not match raw all-CPU counters')
        if observed['events']:
            from analyze import summarize_events
            checked = summarize_events(run, observed['events'], _admission=False)
            errors.extend(checked['errors'])
            count = sum(row['latency_ns'] is not None and row.get('measured', True)
                        for row in checked['records'])
            if count != run.get('completed_records'):
                errors.append('completed_records: differs from raw matched records')
    return errors


def inspect_collection(run, receipt):
    """Read and verify raw collection inputs, without trusting success booleans.

    Re-decoding raw trace uses this checkout's collector. The current U/K probe
    limitations remain unavailable until that implementation can prove mapping.
    """
    import importlib.util
    import json
    import sys

    errors, data = [], {}
    plan = run.get('collection_manifest', run)
    if not isinstance(plan, dict):
        errors.append('runtime_mapping: original collection manifest unavailable')
        plan = run
    for field in plan.keys() | run.keys():
        if field not in DERIVED_FIELDS and (field not in plan or field not in run or plan[field] != run[field]):
            errors.append('runtime_mapping: original expectation changed: ' + field)
    runtime = bool(plan.get('trace', {}).get('sessions'))
    if runtime:
        errors.extend(validate_runtime_plan(plan))
    if not isinstance(receipt, dict):
        receipt = {}
    if (receipt.get('status') in ('failed', 'fail') or
            (type(receipt.get('returncode')) is int and receipt['returncode'] != 0)):
        errors.append('collection: actual workload failed')
    elif receipt.get('status') not in ('ok', 'pass') or receipt.get('returncode') != 0:
        errors.append('collection: actual subprocess status/returncode unavailable')
    artifacts = receipt.get('artifacts', {})
    if not isinstance(artifacts, dict):
        artifacts = {}
    kinds = ['raw_trace', 'events', 'trace_metadata', 'system_cpu_before',
             'system_cpu_after', 'workload_stdout', 'workload_stderr', 'oracle', 'zero_copy']
    if run.get('arm') in ('U-poll', 'U-event') or runtime:
        kinds.append('journal')
    if runtime:
        kinds += ['mapped_manifest', 'oracle_expected', 'oracle_readback', 'oracle_spec']
    for kind in kinds:
        problems = validate_artifact(artifacts.get(kind), kind)
        errors.extend(problems)
        if not problems:
            try:
                data[kind] = (Path(artifacts[kind]['path']) if kind in ('oracle_expected', 'oracle_readback')
                              else Path(artifacts[kind]['path']).read_text())
            except (OSError, UnicodeError) as error:
                errors.append(kind + ': raw text unreadable: ' + str(error))
    for kind in ('trace_metadata', 'oracle', 'zero_copy', 'mapped_manifest', 'oracle_spec'):
        if kind in data:
            try:
                data[kind] = json.loads(data[kind])
                if not isinstance(data[kind], dict):
                    raise ValueError('expected object')
            except ValueError as error:
                errors.append(kind + ': invalid JSON: ' + str(error))
                data.pop(kind)
    if 'events' in data:
        try:
            data['events'] = [json.loads(line) for line in data['events'].splitlines() if line.strip()]
            if not data['events'] or any(not isinstance(e, dict) for e in data['events']):
                raise ValueError('empty events or non-object event')
        except ValueError as error:
            errors.append('events: invalid JSONL: ' + str(error))
            data.pop('events')
    metadata = data.get('trace_metadata', {})
    if metadata:
        if run.get('arm') in ('U-poll', 'U-event') or runtime:
            if metadata.get('journal_artifact') != artifacts.get('journal') or 'journal' not in data:
                errors.append('journal: immutable U cookie mapping raw artifact unavailable/mismatch')
        if metadata.get('schema_version') != 1:
            errors.append('trace_metadata.schema_version: expected 1')
        for field in ('run_id', 'exact_sha', 'config_hash', 'arm', 'clock', 'clock_domain',
                      'endpoint', 'physical', 'environment', 'evidence_kind',
                      'complete_boundary', 'submit_boundary'):
            if field not in metadata or metadata[field] != run.get(field):
                errors.append('trace_metadata.' + field + ': run identity/boundary mismatch')
        if metadata.get('cpu_interval_scope') != 'steady_state':
            errors.append('system_cpu: steady-state interval unavailable; whole-command includes setup/oracle')
        for field in ('cpu_budget', 'numa', 'iommu', 'group_bytes', 'segments_per_group',
                      'inflight_bytes', 'native_batch', 'processing'):
            if field not in metadata or metadata[field] != run.get(field):
                errors.append('trace_metadata.' + field + ': observed configuration mismatch/unknown')
        if metadata.get('trace_dropped') != 0:
            errors.append('trace_metadata.trace_dropped: lost or unknown trace')
        probes = metadata.get('probes', {})
        for event in ('native_submit', 'native_complete'):
            probe = probes.get(event, {}) if isinstance(probes, dict) else {}
            if (not isinstance(probe, dict) or probe.get('layer') != 'native_provider' or
                    not isinstance(probe.get('source'), str) or not probe['source'] or
                    'cqe_observe' in probe['source'].lower()):
                errors.append('trace_metadata.probes.' + event + ': same-layer native probe unavailable')
    mapped_manifest = None
    if 'events' in data and 'raw_trace' in data and metadata:
        collector = COLLECTOR_ENTRY
        try:
            if not collector.is_file():
                raise ValueError('native_trace_probe_unavailable: collector/decoder missing')
            spec = importlib.util.spec_from_file_location('native_views_evidence_decoder', collector)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            decoder = getattr(module, 'decode_trace', None)
            if not callable(decoder):
                raise ValueError('native_trace_probe_unavailable: raw native decoder missing')
            decoded = decoder(plan, data['raw_trace'], metadata)
            if not _same_json(decoded, data['events']):
                errors.append('events: raw trace re-decoding does not match events.jsonl')
            if runtime:
                mapper = getattr(module, 'derive_mapped_manifest', None)
                if not callable(mapper):
                    raise ValueError('runtime_mapping: raw runtime mapper unavailable')
                mapped = mapper(plan, data['raw_trace'], metadata)
                if not _same_json({key: value for key, value in mapped.items() if key not in RUNTIME_FIELDS}, plan):
                    errors.append('runtime_mapping: mapper changed frozen expectations')
                elif not _same_json(mapped, data.get('mapped_manifest')):
                    errors.append('runtime_mapping: mapped manifest differs from raw/sideband reconstruction')
                else:
                    problems = validate_runtime_mapping(plan, mapped, decoded)
                    errors.extend(problems)
                    critical = ('raw_trace', 'events', 'trace_metadata', 'journal', 'mapped_manifest')
                    if (not problems and all(kind in data for kind in critical) and
                            _same_json(decoded, data['events']) and
                            metadata.get('journal_artifact') == artifacts.get('journal')):
                        mapped_manifest = mapped
        except (ImportError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            errors.append('raw_trace: cannot verify native identity mapping: ' + str(error))
    if 'oracle' in data:
        errors.extend(_check_campaign(run, data['oracle']))
    if 'zero_copy' in data:
        errors.extend(_check_backing(run, data['zero_copy']))
    if runtime and all(kind in data for kind in ('oracle_expected', 'oracle_readback', 'oracle_spec')):
        errors.extend(_check_postoracle(plan, artifacts, data['oracle_spec']))
    cpu_ns = None
    if 'system_cpu_before' in data and 'system_cpu_after' in data:
        try:
            cpu_ns = _system_cpu_ns(data['system_cpu_before'], data['system_cpu_after'],
                                    metadata.get('cpu_tick_hz'))
        except ValueError as error:
            errors.append('system_cpu: ' + str(error))
    return dict(errors=errors, events=data.get('events', []), metadata=metadata,
                mapped_manifest=mapped_manifest,
                total_cpu_ns=cpu_ns)


def _system_cpu_ns(before, after, tick_hz):
    """Whole-host busy CPU, excluding idle, iowait, steal and guest double count."""
    if type(tick_hz) is not int or tick_hz <= 0:
        raise ValueError('cpu_tick_hz missing/invalid')

    def parse(text):
        cpus = {}
        for line in text.splitlines():
            parts = line.split()
            if parts and re.fullmatch(r'cpu(?:[0-9]+)?', parts[0]):
                if parts[0] in cpus or len(parts) < 9:
                    raise ValueError('duplicate/truncated CPU counter row')
                try:
                    counters = [int(v) for v in parts[1:]]
                except ValueError:
                    raise ValueError('noninteger CPU counter') from None
                if any(v < 0 for v in counters):
                    raise ValueError('negative CPU counter')
                cpus[parts[0]] = counters
        if 'cpu' not in cpus or len(cpus) < 2:
            raise ValueError('aggregate and all cpuN counters required')
        return cpus
    a, b = parse(before), parse(after)
    if set(a) != set(b):
        raise ValueError('CPU set changed/incomplete all-CPU capture')
    for cpu in a:
        if len(a[cpu]) != len(b[cpu]) or any(y < x for x, y in zip(a[cpu], b[cpu])):
            raise ValueError('CPU counter regressed/reset')
    # /proc/stat aggregate includes every CPU; per-CPU rows prove the captured
    # set, while summing both would double count. Tick resolution is preserved.
    busy_ticks = sum(b['cpu'][i] - a['cpu'][i] for i in (0, 1, 2, 5, 6))
    return busy_ticks * 1_000_000_000 // tick_hz


def _check_campaign(run, campaign):
    errors = []
    recipe = run.get('recipe', {})
    if campaign.get('schema') != 'xdev-chain-campaign-v1' or campaign.get('correctness_only') is not False:
        errors.append('oracle: measured chains campaign required')
    rows = campaign.get('rows')
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        return [*errors, 'oracle: one actual arm/run campaign row required']
    row = rows[0]
    arm = 'userspace-shared' if str(run.get('arm', '')).startswith('U-') else 'session'
    for field, expected in (('chain', recipe.get('chain')), ('size', run.get('record_bytes')),
                            ('arm', arm), ('load', run.get('load')), ('seed', recipe.get('seed'))):
        if row.get(field) != expected:
            errors.append('oracle.' + field + ': campaign workload mismatch')
    if str(run.get('arm', '')).startswith('U-'):
        expected = 'poll' if run['arm'] == 'U-poll' else 'eventfd'
        if row.get('wait') != expected:
            errors.append('oracle.wait: campaign wait strategy mismatch')
    result = row.get('result', {})
    if not isinstance(result, dict) or result.get('status') != 'pass':
        return [*errors, 'oracle: actual workload failed/not-run']
    for name in ('sender', 'receiver'):
        child = result.get(name, {})
        if not isinstance(child, dict) or child.get('status') != 'pass' or child.get('exit') != 0:
            errors.append('oracle.' + name + ': actual subprocess failed/not-run')
    receiver = result.get('receiver', {})
    oracle = receiver.get('oracle', {}) if isinstance(receiver, dict) else {}
    expected_bytes = (recipe.get('records', 0) + recipe.get('warmup_records', 4)) * run.get('record_bytes', 0)
    if (not isinstance(oracle, dict) or oracle.get('kind') != 'file' or
            oracle.get('verdict') != 'pass' or oracle.get('bytes') != expected_bytes or expected_bytes <= 0):
        errors.append('oracle: full byte-for-byte post-run file oracle missing/failed/wrong denominator')
    all_evidence = campaign.get('evidence', {})
    evidence = all_evidence.get(recipe.get('chain'), {}) if isinstance(all_evidence, dict) else {}
    if (not isinstance(evidence, dict) or not isinstance(evidence.get('environment'), dict) or
            not evidence['environment'].get('dmi') or not isinstance(evidence.get('devices'), list) or
            not evidence['devices']):
        errors.append('oracle: actual chains physical hardware gate evidence missing')
    return errors


def _check_backing(run, proof):
    errors = []
    for field in ('run_id', 'exact_sha'):
        if proof.get(field) != run.get(field):
            errors.append('zero_copy.' + field + ': raw mapping identity mismatch')
    if proof.get('schema_version') != 1 or proof.get('source') != 'native_provider':
        errors.append('zero_copy: native provider mapping observations required')
    for field, value in (('afxdp_mode', 'zc'), ('nvme_bounces', 0), ('payload_copy_bytes', 0)):
        if field not in proof or proof[field] != value:
            errors.append('zero_copy.' + field + ': missing or nonzero/copy-mode observation')
    frames = proof.get('frames', [])
    if not isinstance(frames, list):
        return [*errors, 'zero_copy.frames: per-frame backing observations required']
    record_bytes = run.get('record_bytes')
    if type(record_bytes) is not int or record_bytes <= 0:
        return [*errors, 'zero_copy.record_bytes: positive measured payload length required']
    for record in run.get('records', []):
        record_ranges = []
        for frame in record['frame_ids']:
            matches = [f for f in frames if isinstance(f, dict) and
                       all(f.get(k) == record.get(k) for k in ('session_id', 'record_id', 'generation')) and f.get('frame_id') == frame]
            if len(matches) != 1:
                errors.append('zero_copy.frames: missing/duplicate frame mapping')
                continue
            observed = matches[0]
            views = observed.get('native_views', [])
            if not observed.get('backing_id') or not isinstance(views, list):
                errors.append('zero_copy.frames: missing backing/native views')
                continue
            # A one-frame record has an unambiguous default payload span. For
            # multiple frames the provider must observe the actual record/frame
            # offsets; frame size is capacity, not an inferred payload length.
            single_frame = len(record['frame_ids']) == 1
            record_offset = observed.get('record_offset_bytes', 0 if single_frame else None)
            payload_offset = observed.get('payload_offset_bytes', 0 if single_frame else None)
            payload_bytes = observed.get('payload_bytes', record_bytes if single_frame else None)
            valid_bytes = observed.get('valid_bytes')
            if (any(type(value) is not int for value in
                    (record_offset, payload_offset, payload_bytes, valid_bytes)) or
                    min(record_offset, payload_offset) < 0 or payload_bytes <= 0 or
                    valid_bytes <= 0 or record_offset + payload_bytes > record_bytes or
                    payload_offset + payload_bytes > valid_bytes):
                errors.append('zero_copy.frames: explicit legal record/payload span required')
                continue
            record_ranges.append((record_offset, record_offset + payload_bytes))
            declared_layout = run.get('trace', {}).get('layout')
            if declared_layout is not None:
                declared = [span for span in declared_layout if span.get('frame_id') == frame]
                if (len(declared) != 1 or
                        (record_offset, payload_bytes) != (declared[0]['offset_bytes'], declared[0]['length_bytes'])):
                    errors.append('zero_copy.frames: payload span changed predeclared logical frame layout')
            ranges = {'nvme': [], 'afxdp': []}
            for view in views:
                if not isinstance(view, dict):
                    errors.append('zero_copy.native_views: invalid view')
                    continue
                kind = view.get('kind')
                offset, length = view.get('offset_bytes'), view.get('length_bytes')
                if (view.get('backing_id') != observed['backing_id'] or
                        type(offset) is not int or type(length) is not int or
                        offset < 0 or length <= 0 or offset + length > valid_bytes):
                    errors.append('zero_copy.native_views: foreign backing or illegal byte range')
                    continue
                if kind in ranges:
                    ranges[kind].append((offset, offset + length))
            required_span = [(payload_offset, payload_offset + payload_bytes)]
            for kind, spans in ranges.items():
                ordered_spans = sorted(spans)
                if any(left[1] > right[0] for left, right in zip(ordered_spans, ordered_spans[1:])):
                    errors.append('zero_copy.native_views.%s: overlapping/duplicate bytes in ungrouped native view' % kind)
                if _merge_ranges(spans) != required_span:
                    errors.append('zero_copy.native_views.%s: full measured payload span must match backing/ranges' % kind)
        # Every measured record byte must occur in exactly one frame payload.
        # Different native descriptor segmentation within each frame is legal.
        ordered = sorted(record_ranges)
        if (_merge_ranges(ordered) != [(0, record_bytes)] or
                any(left[1] > right[0] for left, right in zip(ordered, ordered[1:]))):
            errors.append('zero_copy.frames: record payload coverage missing or overlapping')
    return errors


def _merge_ranges(ranges):
    """Canonical byte coverage, independent of legal IOV/SG segmentation."""
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def validate_runtime_plan(plan):
    """Freeze the complete logical workload before binding any native IDs."""
    errors = []
    trace, recipe = plan.get('trace', {}), plan.get('recipe', {})
    sessions = trace.get('sessions', [])
    if (not isinstance(sessions, list) or len(sessions) != 2 or
            any(not isinstance(s, dict) for s in sessions)):
        return ['runtime_mapping: predeclare sender and receiver roles']
    roles = {s.get('role'): s for s in sessions}
    ids = [s.get('logical_id') for s in sessions]
    if (set(roles) != {'sender', 'receiver'} or any(type(i) is not int or i < 0 for i in ids) or
            len(set(ids)) != len(ids) or roles.get('sender', {}).get('measured') is not True or
            roles.get('receiver', {}).get('measured') is not False):
        return ['runtime_mapping: ambiguous logical roles/measurement scope']
    count, warm = recipe.get('records'), recipe.get('warmup_records', 4)
    if (type(count) is not int or not 1 <= count <= 65536 or
            type(warm) is not int or not 0 <= warm <= 4096 or
            type(recipe.get('seed')) is not int or not 0 <= recipe['seed'] < 1 << 64 or
            recipe.get('chain') != 'nvme-nic' or
            type(plan.get('record_bytes')) is not int or plan['record_bytes'] <= 0 or
            type(trace.get('burst')) is not int or trace['burst'] != 1 or
            type(trace.get('batch_key_origin')) is not int):
        return ['runtime_mapping: predeclared count/warmup/seed/shape required (burst=1)']
    if plan.get('arm', '').startswith('K'):
        if trace.get('generation_mapping') != 'batch_key_relative' or trace.get('batch_key_origin') != 1:
            errors.append('runtime_mapping: K origin=1 and relative generation must be fixed before capture')
    elif trace.get('batch_key_origin') != 0:
        errors.append('runtime_mapping: U origin=0 must be fixed before capture')
    layout, offset = trace.get('layout'), 0
    if not isinstance(layout, list) or not layout:
        return [*errors, 'runtime_mapping: predeclared logical payload layout required']
    for ordinal, span in enumerate(layout):
        if (not isinstance(span, dict) or type(span.get('frame_id')) is not int or span['frame_id'] != ordinal or
                span.get('offset_bytes') != offset or type(span.get('length_bytes')) is not int or
                span['length_bytes'] <= 0):
            return [*errors, 'runtime_mapping: logical frame layout has hole/overlap/ambiguous ordinal']
        offset += span['length_bytes']
    if offset != plan['record_bytes']:
        errors.append('runtime_mapping: frame layout does not cover expected record bytes')
    records = plan.get('records', [])
    expected = [(roles['sender']['logical_id'], i, i, i >= warm) for i in range(count + warm)]
    actual = [(r.get('session_id'), r.get('record_id'), r.get('generation'), r.get('measured'))
              for r in records if isinstance(r, dict)]
    if (not _same_json(actual, expected) or
            any(r.get('frame_ids') != list(range(len(layout))) for r in records)):
        errors.append('runtime_mapping: expected record keys/counts/measurement flags differ from frozen recipe')
    return errors


def validate_runtime_mapping(plan, mapped, events):
    """Check that runtime fields only bind proven IDs to the frozen logical plan."""
    errors = []
    if mapped.get('runtime_mapping_version') != 1:
        errors.append('runtime_mapping: unsupported mapping version')
    plans = {s['logical_id']: s for s in plan.get('trace', {}).get('sessions', [])}
    bindings = mapped.get('runtime_bindings', [])
    if not isinstance(bindings, list) or len(bindings) != len(plans):
        return [*errors, 'runtime_mapping: not every predeclared role was bound']
    owners, seen = {}, set()
    for row in bindings:
        if not isinstance(row, dict):
            return [*errors, 'runtime_mapping: malformed runtime role binding']
        logical = row.get('logical_session_id')
        expected = plans.get(logical)
        if (expected is None or logical in seen or row.get('role') != expected['role'] or
                row.get('measured') is not expected['measured'] or
                any(type(row.get(k)) is not int or row[k] <= 0 for k in
                    ('native_session_id', 'origin_tgid', 'process_start_ticks'))):
            return [*errors, 'runtime_mapping: duplicate/foreign/unproven role binding']
        seen.add(logical)
        owners[logical] = row
    fields = ('session_id', 'record_id', 'generation', 'frame_id', 'native_session_id',
              'native_frame_id', 'frame_generation', 'frame_offset', 'frame_length',
              'stage', 'origin_tgid', 'process_start_ticks')
    observed = []
    layout = {span['frame_id']: span for span in plan['trace']['layout']}
    for event in events:
        if event.get('event') != 'native_submit' or event.get('accepted') is not True:
            continue
        if any(field not in event for field in fields):
            errors.append('runtime_mapping: accepted work missing raw identity/span')
            continue
        owner = owners.get(event['session_id'])
        span = layout.get(event['frame_id'])
        if (owner is None or span is None or not owner['measured'] or
                any(event[k] != owner[k] for k in ('native_session_id', 'origin_tgid', 'process_start_ticks')) or
                type(event['native_frame_id']) is not int or event['native_frame_id'] < 0 or
                (event['frame_offset'], event['frame_length']) != (span['offset_bytes'], span['length_bytes'])):
            errors.append('runtime_mapping: native frame owner/range differs from logical binding')
        row = {field: event[field] for field in fields}
        if row not in observed:
            observed.append(row)
    expected_frames = sorted(observed, key=lambda r: (r['session_id'], r['record_id'], r['frame_id'], r['stage']))
    if mapped.get('runtime_frames') != expected_frames:
        errors.append('runtime_mapping: native frame bindings differ from accepted raw operations')
    return errors


def _check_postoracle(plan, artifacts, spec):
    """Compare every retained expected/readback byte with bounded memory."""
    recipe, errors = plan['recipe'], []
    count = recipe['records'] + recipe.get('warmup_records', 4)
    expected_size = count * plan['record_bytes']
    if (spec.get('chain') != 'nic-nvme' or spec.get('mode') != 'timing' or
            spec.get('group_bytes') != plan['record_bytes'] or spec.get('burst') != 1 or
            spec.get('batches') != recipe['records'] or
            spec.get('warmup') != recipe.get('warmup_records', 4) or
            not isinstance(spec.get('oracle'), dict) or spec['oracle'].get('kind') != 'file'):
        errors.append('postoracle: actual receiver spec differs from frozen shape/byte count')
    expected, actual = (Path(artifacts[kind]['path']) for kind in ('oracle_expected', 'oracle_readback'))
    try:
        if expected.stat().st_size != expected_size or actual.stat().st_size != expected_size:
            errors.append('postoracle: incomplete expected/readback byte denominator')
        left_hash, right_hash = hashlib.sha256(), hashlib.sha256()
        differ = False
        with expected.open('rb') as left, actual.open('rb') as right:
            while True:
                a, b = left.read(1048576), right.read(1048576)
                left_hash.update(a)
                right_hash.update(b)
                differ |= a != b
                if not a and not b:
                    break
        if differ:
            errors.append('postoracle: actual retained readback bytes differ from expected bytes')
        if (left_hash.hexdigest() != artifacts['oracle_expected']['sha256'] or
                right_hash.hexdigest() != artifacts['oracle_readback']['sha256']):
            errors.append('postoracle: retained file sha256 changed during comparison')
    except OSError as error:
        errors.append('postoracle: raw byte comparison unavailable: ' + str(error))
    return errors
