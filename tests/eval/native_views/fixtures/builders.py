# SPDX-License-Identifier: GPL-2.0
"""Hand-authored schema fixtures. These are never hardware observations."""
import copy
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent.parent


def target(name):
    path = HERE / (name + '.py')
    assert path.is_file(), 'missing native_views implementation: ' + path.name
    spec = importlib.util.spec_from_file_location('native_views_target_' + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.path.insert(0, str(HERE))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(HERE))
    return module


def run_fixture(arm='U-poll', pair='pair-1'):
    return dict(
        schema_version=1, run_id='fixture-' + arm + '-' + pair, pair_id=pair,
        arm=arm, exact_sha='a' * 40, bpf_object_hash='b' * 64,
        config_hash='c' * 64, device_manifest={'nvme': 'fixture', 'nic': 'fixture'},
        physical=False, environment='fixture', evidence_kind='fixture',
        correctness_pass=True, status='ok', load='closed', endpoint='remote_receive',
        pool_bytes=16 << 20, record_bytes=4096, frame_bytes=4096, depth=8,
        batch=1, mtu=1500, protocol='nxp-v1', crc='crc32c',
        payload_copy_bytes=0, setup_in_timing=False, oracle_in_timing=False,
        total_cpu_ns=1200, cpu_accounting='system_total', completed_records=1,
        registration_calls=1, registration_reused=True, shared_pages=True,
        afxdp_zero_copy=True, nvme_no_bounce=True, wait_strategy=arm,
        metrics={'latency_ns': 400, 'throughput_bytes_per_second': 1000},
        trace_dropped=0, clock='CLOCK_MONOTONIC', clock_domain='host-fixture',
        complete_boundary='native_observed', submit_boundary='native_accepted',
        stages=[{'id': 'read', 'after': []}, {'id': 'send', 'after': ['read']}],
        records=[{'session_id': 7, 'record_id': 0, 'generation': 1, 'frame_ids': [0]}],
        commands=[])


def event(manifest, name, timestamp, stage='record', record=0, frame=-1,
          generation=1, session=7, **extra):
    value = dict(run_id=manifest['run_id'], session_id=session, record_id=record,
                 frame_id=frame, generation=generation, stage=stage, event=name,
                 ts_ns=timestamp, clock='CLOCK_MONOTONIC', clock_domain='host-fixture',
                 accepted=True, status=0)
    value.update(extra)
    return value


def record_events(manifest, record=0, generation=1, start=100, complete=200,
                  submit=300, terminal=500, frame=0, session=7):
    def e(name, timestamp, stage='record', actual_frame=-1):
        return event(manifest, name, timestamp, stage, record, actual_frame,
                     generation, session)
    return [e('record_admit', start), e('native_submit', start + 1, 'read', frame),
            e('native_complete', complete, 'read', frame),
            e('native_submit', submit, 'send', frame),
            e('native_complete', terminal - 1, 'send', frame),
            e('record_terminal', terminal), e('recycle', terminal + 1, 'frame', frame)]


def clone(value):
    return copy.deepcopy(value)
