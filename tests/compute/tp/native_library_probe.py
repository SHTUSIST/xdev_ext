#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Thin JSON/CLI adapter around the complete production TP library.

Host Driver declarations are explicit test boundaries, not official SDK/GPU
qualification. The probe never reads collective_vectors.json or expectations.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def build(root,out):
    root=root.resolve();out=out.resolve();out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('tp_library_layout',root/'tools/layout.py')
    layoutmod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=layoutmod;spec.loader.exec_module(layoutmod)
    layout=layoutmod.load_layout(root);view=layoutmod.materialize_view(root,out/'source-view')
    production=view.root/layout.logical('src/compute/collectives/xdev_tp.cc')
    kernels=view.root/layout.logical('src/compute/collectives/xdev_tp.cu')
    library=(view.root/layout.logical('src/lib/xdev_ext_user.c')).read_text()
    extract_spec=importlib.util.spec_from_file_location('tp_span_extract',root/'tests/core/admission_report/run.py')
    extract=importlib.util.module_from_spec(extract_spec);extract_spec.loader.exec_module(extract)
    span=out/'actual-peer-span.inc';span.write_text(extract.function(library,'xdev_ext_user_batch_peer_span'))
    facade=out/'driver-boundary';facade.mkdir(exist_ok=True)
    shutil.copyfile(HERE/'driver_boundary.h',facade/'cuda.h')
    exe=out/'native-library-probe'
    cmd=[os.environ.get('CXX','g++'),'-std=c++17','-O0','-g','-Wall','-Wextra',
         '-Wno-misleading-indentation','-pthread','-fsanitize=undefined','-fno-sanitize-recover=undefined',
         '-I'+str(facade),'-DTP_LIBRARY_SOURCE="'+str(production)+'"',
         '-DTP_KERNEL_SOURCE="'+str(kernels)+'"','-DTP_PEER_SPAN_SOURCE="'+str(span)+'"',
         str(HERE/'native_library_boundary.cc'),'-o',str(exe)]
    for name in ('src/lib/libxdev_ext.h','src/compute/cuda/libxdev_ext_cuda.h'):
        cmd.insert(1,'-I'+str((view.root/layout.logical(name)).parent))
    if 'void xdev_tp_pack_payload(' in kernels.read_text():cmd.insert(1,'-DTP_PHASED_KERNELS')
    if 'xdev_tp_submit_batch(' in production.with_name('xdev_tp.h').read_text():cmd.insert(1,'-DTP_HAS_BATCH')
    run=subprocess.run(cmd,text=True,capture_output=True,timeout=90)
    (out/'compile.log').write_text(run.stdout+run.stderr)
    receipt={'scope':'host complete production TP library with controlled Driver/endpoint boundaries',
             'source_root':str(root),'production_source':str(production),'command':cmd,
             'compile_exit':run.returncode,'official_sdk_build':'not-run','gpu_execution':'not-run'}
    (out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n')
    if run.returncode:raise RuntimeError('host boundary compile failed; not behavior RED; see '+str(out/'compile.log'))
    return exe


def observe(data,exe):
    r=data['request'];action=r['action']
    if action not in ('create','submit','d2_cross_stream','fault_after_ready','submit_and_complete','script','batch_capability','capture_and_replay','captured_storage_lifetime','batch','trace_capability'):
        return {'blocked':'This adapter currently executes actual library pre-submit qualification only'},2
    if r.get('contiguous') is False:
        return {'blocked':'Raw-pointer C ABI has no tensor stride/contiguity; requires real ATen bridge'},2
    creating=action=='create';depth=r.get('logical_depth',1);slot=r.get('slot_capacity',4096)
    batch=action=='batch';replay=action=='capture_and_replay';storage=action=='captured_storage_lifetime';captured=action=='script' or replay or storage or batch
    if batch:depth=1 if r.get('scenario')=='d1' else 2;slot=8192
    args=['create' if creating else 'replay' if replay else 'storage' if storage else action if action in ('script','batch_capability','batch','trace_capability') else 'complete' if action=='submit_and_complete' else 'submit',r.get('communicator_id',7),r.get('epoch',9),r.get('first_sequence',23),
          r.get('rank',0),r.get('world_size',2),r.get('tx_va',0x100000),r.get('rx_va',0x200000),
          r.get('tx_bytes',slot),r.get('rx_bytes',slot),r.get('flags',0),r.get('op','sum'),
          {'f16':1,'bf16':2,'f32':3}.get(r.get('dtype','f32'),0),len(r['inputs_per_replay'][0]) if replay else r.get('numel',4),r.get('rows',1),r.get('local_width',4),
          r.get('input',4096),r.get('output',8192),r.get('input_bytes',16),r.get('output_bytes',16),
          r.get('context',1),r.get('stream_context',1),r.get('memory_context',r.get('context',1)),
          int(r.get('managed',False)),int(r.get('memory_type')=='host'),slot,int(r.get('capturing',False) or captured),depth,
          r.get('sequence',23),r.get('dst_rank',0),1 if batch and r.get('scenario')=='d1' else 2 if action in ('d2_cross_stream','trace_capability') or captured else 1,r.get('caller_stream',1)]
    if action=='fault_after_ready':args.append({'wrong_role':1,'wrong_key':2,'before_take':3}[r['fault']])
    if action=='script':args.extend([0,','.join(r['events'])])
    if storage:args.extend([0,','.join(r['events'])])
    if batch:args.extend([0,r.get('scenario','valid')])
    if replay:
        size=4 if r.get('dtype','f32')=='f32' else 2
        def payload(bits):return b''.join(int(b,16).to_bytes(size,'little') for b in bits).hex()
        args.extend([0,';'.join(str(key)+':'+payload(local)+':'+payload(peer) for key,local,peer in zip(r['ready_keys'],r['inputs_per_replay'],r['peer_per_replay']))])
        if 'trace_capacity' in r:args.append(r['trace_capacity'])
    run=subprocess.run([str(exe),*map(str,args)],text=True,capture_output=True,timeout=15)
    if run.returncode:return {'setup_error':'native boundary exited '+str(run.returncode),'stdout':run.stdout,'stderr':run.stderr},2
    return json.loads(run.stdout),0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',action='store_true');p.add_argument('--source-root',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--tp-observe-json',action='store_true');a=p.parse_args()
    if a.build:
        if not a.source_root or not a.output:p.error('--build requires --source-root and --output')
        try:print(build(a.source_root,a.output));return 0
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:print(str(error),file=sys.stderr);return 2
    path=os.environ.get('XDEV_TP_LIBRARY_PROBE')
    if not path:print(json.dumps({'blocked':'Set XDEV_TP_LIBRARY_PROBE to the compiled actual-library boundary executable'}));return 2
    try:result,code=observe(json.load(sys.stdin),Path(path));print(json.dumps(result));return code
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:print(json.dumps({'setup_error':str(error)}));return 2


if __name__=='__main__':raise SystemExit(main())
