# SPDX-License-Identifier: GPL-2.0
"""Serialization adapters for actual production policy/accounting helpers.

No vector or expected result is read. Synthetic timestamp observations are
accounting correctness inputs, never physical performance evidence.
"""
import importlib.util
from pathlib import Path
import sys


def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod)
    return mod


def observe(data,root):
    root=Path(root);r=data['request'];action=r['action']
    if data['family']=='bridge' or r.get('contiguous') is False:
        policy=root/'src/compute/torch/xdev_tp_torch/policy.py'
        detail={}
        if policy.exists():
            impl=module('tp_observed_policy',policy)
            shape=r.get('shape',[r.get('numel',4)])
            try:
                q=impl.qualify(shape,dtype={'f16':'float16','bf16':'bfloat16','f32':'float32'}.get(r.get('dtype','f32'),r.get('dtype')),
                   device_type='meta' if action=='fake_meta_gather' else 'cuda',contiguous=r.get('contiguous',True),
                   world_size=r.get('world_size',2),rank=r.get('rank',0),operation='all_reduce' if r.get('op')=='sum' else 'gather',
                   dim=r.get('dim',-1),dst=r.get('dst_rank',0),max_payload_bytes=1<<30)
                detail={'policy_output_shape':list(q.output_shape) if q.output_shape is not None else None,
                        'policy_rows':q.rows,'policy_width':q.width}
            except (ValueError,OverflowError) as error:detail={'policy_rejected':True,'policy_exception':str(error)}
        return {'blocked':'Actual ATen Tensor/runtime/storage observations require the built extension and real torch; policy alone does not certify this vector',**detail},2
    path=root/'tests/benchmarks/tp/accounting.py'
    if data['family']!='accounting' or not path.exists():return {'blocked':'Actual production accounting helper is not available for this request'},2
    impl=module('tp_observed_accounting',path)
    clocks={'host_monotonic':1,'gpu_globaltimer':2}
    if action=='e6':
        start,end=r['start'],r['end']
        interval={'start':start['value'],'end':end['value'],'rank':start['rank'],'end_rank':end['rank'],
                  'clock':clocks[start['clock']],'end_clock':clocks[end['clock']],
                  'kind':'allreduce','completed':True,'custody_released':True}
        try:result=impl.local_durations([interval])
        except ValueError:return {'valid':False},0
        return {'valid':True,'elapsed_ns':result[0]['duration_ns'],'metric':'rank_local_end_to_end'},0
    if action=='e7_unique':
        records=[{'communicator':v['comm'],'epoch':v['epoch'],'sequence':v['seq'],'rank':v['rank'],
                  'direction':v['direction'],'payload_bytes':v['bytes'],'valid':v['validated'],'delivered':True} for v in r['records']]
        totals=impl.validated_payload_totals(records)
        return {'unique_validated_payload_bytes':sum(totals.values()),'tx_bytes':totals.get('tx',0),'rx_bytes':totals.get('rx',0)},0
    if action=='e7' and r.get('trace_dropped',0):
        metadata={'communicator':r.get('communicator_id',7),'epoch':r.get('epoch',9),'rank':0,
                  'clock':clocks[r['clock']],'trace_dropped':r['trace_dropped'],'requested_depth':r['configured_depth']}
        try:impl.analyze([],[],metadata)
        except ValueError:return {'valid':False,'depth_evidence_valid':False},0
        return {'valid':True,'depth_evidence_valid':True},0
    if action=='e7':
        if not hasattr(impl,'observe_lifetimes'):return {'blocked':'Production partial-lifetime observer is required; strict throughput admission cannot substitute depth accounting'},2
        observation=impl.observe_lifetimes(r['events'])
        return {'valid':True,'observed_high_water':observation['logical_inflight_high_water'],
                'final_inflight':observation['logical_inflight'],'unique_validated_payload_bytes':observation['unique_validated_payload_bytes'],
                'failed_payload_bytes':observation['failed_payload_bytes'],
                'depth_series':[[e['timestamp'],e['inflight']] for e in observation['timeline']],
                'completed_lifetimes':observation['completed_lifetimes']},0
    return {'blocked':'No actual production helper for request'},2
