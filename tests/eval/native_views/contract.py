#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Admission for native-view evidence; schema validity is not physical proof."""
import hashlib
import math
from pathlib import Path
import re

# These must match in a paired comparison. Arm names and waiting strategy may differ.
PAIR_FIELDS = (
    'pair_id', 'exact_sha', 'config_hash', 'device_manifest', 'endpoint', 'load',
    'pool_bytes', 'record_bytes', 'frame_bytes', 'depth', 'batch', 'mtu',
    'protocol', 'crc', 'setup_in_timing', 'oracle_in_timing',
    'complete_boundary', 'submit_boundary', 'clock', 'clock_domain',
    'cpu_accounting', 'cpu_budget', 'completed_records', 'numa', 'iommu', 'group_bytes',
    'segments_per_group', 'inflight_bytes', 'native_batch', 'processing',
)


def number(value, minimum=0):
    return (type(value) in (int, float) and math.isfinite(value) and value >= minimum)


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
        actual = hashlib.sha256(Path(artifact['path']).read_bytes()).hexdigest()
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
            if len(checked['records']) != run.get('completed_records'):
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
    if run.get('arm') in ('U-poll', 'U-event'):
        kinds.append('journal')
    for kind in kinds:
        problems = validate_artifact(artifacts.get(kind), kind)
        errors.extend(problems)
        if not problems:
            try:
                data[kind] = Path(artifacts[kind]['path']).read_text()
            except (OSError, UnicodeError) as error:
                errors.append(kind + ': raw text unreadable: ' + str(error))
    for kind in ('trace_metadata', 'oracle', 'zero_copy'):
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
        if run.get('arm') in ('U-poll', 'U-event'):
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
    if 'events' in data and 'raw_trace' in data and metadata:
        collector = Path(__file__).resolve().parent.parent / 'native_trace' / 'collector.py'
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
            decoded = decoder(run, data['raw_trace'], metadata)
            if decoded != data['events']:
                errors.append('events: raw trace re-decoding does not match events.jsonl')
        except (ImportError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            errors.append('raw_trace: cannot verify native identity mapping: ' + str(error))
    if 'oracle' in data:
        errors.extend(_check_campaign(run, data['oracle']))
    if 'zero_copy' in data:
        errors.extend(_check_backing(run, data['zero_copy']))
    cpu_ns = None
    if 'system_cpu_before' in data and 'system_cpu_after' in data:
        try:
            cpu_ns = _system_cpu_ns(data['system_cpu_before'], data['system_cpu_after'],
                                    metadata.get('cpu_tick_hz'))
        except ValueError as error:
            errors.append('system_cpu: ' + str(error))
    return dict(errors=errors, events=data.get('events', []), metadata=metadata,
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
    for record in run.get('records', []):
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
            kinds = set()
            for view in views:
                if not isinstance(view, dict):
                    errors.append('zero_copy.native_views: invalid view')
                    continue
                kinds.add(view.get('kind'))
                if (view.get('backing_id') != observed['backing_id'] or
                        not number(view.get('offset_bytes')) or not number(view.get('length_bytes'), 1) or
                        not number(observed.get('valid_bytes'), 1) or
                        view['offset_bytes'] + view['length_bytes'] > observed['valid_bytes']):
                    errors.append('zero_copy.native_views: foreign backing or illegal byte range')
            if not {'nvme', 'afxdp'} <= kinds:
                errors.append('zero_copy.native_views: both NVMe and AF_XDP mappings required')
    return errors
