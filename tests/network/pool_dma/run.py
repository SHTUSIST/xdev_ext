#!/usr/bin/env python3
"""Build real production bodies and preserve every command/output in a fresh directory."""
import argparse,json,os,shutil,subprocess,tempfile,sys
sys.dont_write_bytecode=True
from pathlib import Path
from adapter import generate,SetupError
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[3]);p.add_argument('--out-root',type=Path,required=True);p.add_argument('--mutations',action='store_true');p.add_argument('--compare-baseline',type=Path);a=p.parse_args()
base=Path(__file__).resolve().parent;a.out_root.mkdir(parents=True,exist_ok=True)
out=Path(tempfile.mkdtemp(prefix='pool-dma-',dir=a.out_root));summary={'source':str(a.source.resolve()),'runs':[]}
mutants={'cpu_derived_dma':'sync_span','data_only_sync':'sync_span','callback_under_lock':'callback_outside_lock','accepted_eagain_retry':'accepted_eagain_terminal','fifo_head_is_cons':'fifo_head_not_cons','accessor_outside_lock':'mapping_lock','compacted_frame_index':'BOUNDARY_ASSERT partial_sent: checksum_before_sync','checksum_before_prepare':'prefix_no_checksum','rollback_prod_missing':'prefix_prod_restore','unknown_lease_clear':'unknown_full_bytes','set_only_early_release':'set_only_lease'}
def execute(label,mutation=None):
    d=out/label;d.mkdir();entry={'label':label};summary['runs'].append(entry)
    for n in ['os_boundary.h','test_pool_dma.c']:shutil.copy2(base/n,d/n)
    try:have,manifest=generate(a.source,d,mutation)
    except SetupError as e:entry.update(verdict='SETUP',reason=str(e));return
    (d/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    cmd=['gcc','-std=gnu11','-O0','-g','-funsigned-char','-fno-strict-aliasing','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare',f'-DHAVE_POOL={int(have)}','test_pool_dma.c','-o','test_pool_dma']
    (d/'command.json').write_text(json.dumps(cmd)+'\n')
    r=subprocess.run(cmd,cwd=d,capture_output=True,text=True);(d/'compile.stdout').write_text(r.stdout);(d/'compile.stderr').write_text(r.stderr);entry['compile_exit']=r.returncode
    if r.returncode:entry.update(verdict='SETUP',reason='compiler error is not semantic RED');return
    r=subprocess.run([str(d/'test_pool_dma')],capture_output=True,text=True,timeout=30);(d/'run.stdout').write_text(r.stdout);(d/'run.stderr').write_text(r.stderr);entry['exit']=r.returncode
    if mutation:
        designated=mutants[mutation];entry['designated_assertion']=designated
        entry['verdict']='KILLED' if r.returncode in (1,42) and designated in r.stderr else 'SURVIVED' if r.returncode==0 else 'INVALID_MUTANT'
    else:
        entry['verdict']='PASS' if r.returncode==0 else 'FAIL'
        if a.compare_baseline:
            old=[line for line in a.compare_baseline.read_text().splitlines() if line.startswith('TRACE ')]
            new=[line for line in r.stdout.splitlines() if line.startswith('TRACE ')][:len(old)]
            entry['old_trace_comparison']='PASS' if old==new else 'FAIL'
            if old!=new: entry['verdict']='FAIL'
        entry['candidate_setup']='available' if have else 'POOL_DMA API absent'
        red=subprocess.run([str(d/'test_pool_dma'),'invalid'],capture_output=True,text=True,timeout=30);(d/'invalid.stdout').write_text(red.stdout);(d/'invalid.stderr').write_text(red.stderr)
        entry['invalid_mapping_exit']=red.returncode;entry['invalid_mapping_verdict']='PASS' if red.returncode==0 else 'SEMANTIC_RED' if red.returncode==1 and 'ASSERT invalid_mapping_refusal: invalid_mapping_refusal' in red.stderr else 'SETUP'
execute('current')
if a.mutations:
    for m in mutants:execute(m,m)
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(out);print(json.dumps(summary,indent=2))
raise SystemExit(0 if summary['runs'][0].get('verdict')=='PASS' else 2)
