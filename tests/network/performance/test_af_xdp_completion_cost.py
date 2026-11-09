#!/usr/bin/env python3
"""Native AF_XDP completion cost: exact production FIFO, bounded lookup checks.

The normal single-descriptor path must not scan DONE holes or journal capacity.
STOP/error suffix reclamation is separately permitted amortized linear work.
Timing uses an unmodified production header and measures only host helper CPU.
"""
from pathlib import Path
import argparse,datetime,hashlib,json,os,platform,statistics,subprocess
ROOT=Path(os.environ.get('XDEV_EXT_CANONICAL_ROOT',Path(__file__).resolve().parents[3])).resolve()
HERE=Path(__file__).resolve().parent
HEADER=ROOT/'src/network/include/linux/xdev_ext_netfam_count.h'
def observed_header(text,regress=False):
    anchor='{\n\treturn (struct xdev_ext_net_count_entry *)'
    if text.count(anchor)!=1:raise ValueError('production accessor changed')
    modified=text.replace(anchor,'{\n\tmetadata_lookups++; /* COST_OBSERVER */\n\treturn (struct xdev_ext_net_count_entry *)')
    if ''.join(l for l in modified.splitlines(keepends=True) if '/* COST_OBSERVER */' not in l)!=text:raise ValueError('observer strip mismatch')
    if regress:
        anchor='return r->native_count;'
        if modified.count(anchor)!=1:raise ValueError('native count accessor changed')
        modified=modified.replace(anchor,'for (__u32 i=r->cons; i!=r->issued; i++) metadata_lookups++;\n\t'+anchor)
    return modified
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    original=HEADER.read_text()
    def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
    result={'started_utc':now(),'scope':'Original production FIFO helpers; host CPU only, no NIC/locks/DMA',
      'source_header':str(HEADER.relative_to(ROOT)),
      'source_sha256':hashlib.sha256(original.encode()).hexdigest(),
      'environment':{'uname':platform.uname()._asdict(),'cpu_count':os.cpu_count(),
       'affinity':sorted(os.sched_getaffinity(0)),'clock':'CLOCK_MONOTONIC and CLOCK_PROCESS_CPUTIME_ID',
       'frequency_affinity_control':'NONE; no device measurement'},'runs':[]}
    for name,header,sanitize,contract in [
      ('lookup_contract',observed_header(original),True,True),
      ('scan_regression',observed_header(original,True),True,True),
      ('uninstrumented_cpu',original,False,False)]:
        work=a.out/name;work.mkdir();(work/'native_count.h').write_text(header)
        binary=work/'cost'
        command=['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(work),str(HERE/'af_xdp_native_completion_cost.c'),'-o',str(binary)]
        if sanitize:command+=['-fsanitize=undefined','-fno-sanitize-recover=undefined']
        if contract:command+=['-DCOST_INSTRUMENTED=1']
        c=subprocess.run(command,capture_output=True,text=True,timeout=30)
        (work/'compile.log').write_text(c.stdout+c.stderr)
        if c.returncode:raise RuntimeError(f'{name} compiler exit {c.returncode}')
        argv=[str(binary),'contract' if contract else 'timing']
        run=subprocess.run(argv,capture_output=True,text=True,timeout=30)
        (work/'stdout.log').write_text(run.stdout);(work/'stderr.log').write_text(run.stderr)
        entry={'name':name,'compiler':command,'argv':argv,'exit':run.returncode,
          'header_sha256':hashlib.sha256(header.encode()).hexdigest()}
        if name=='scan_regression':
            if run.returncode!=1 or 'condition=count<=8' not in run.stderr:
                raise RuntimeError('behavior-preserving scan regression not rejected by designated cost bound')
            entry['verdict']='EXPECTED_COST_REGRESSION_REJECTED'
        else:
            if run.returncode:raise RuntimeError(f'{name} runtime exit {run.returncode}')
            entry['verdict']='PASS'
        result['runs'].append(entry)
        binary.unlink()  # reproducible host executable, source/commands/logs retained
    rows=[]
    for line in (a.out/'uninstrumented_cpu/stdout.log').read_text().splitlines():
        if not line.startswith('NIC_FIFO_CPU '):continue
        row=dict(token.split('=',1) for token in line.split()[1:]);rows.append(row)
    if len(rows)!=21:raise RuntimeError('missing CPU samples')
    summaries=[]
    for cap in [64,1024,65536]:
        subset=[r for r in rows if int(r['capacity'])==cap]
        if sorted(int(r['rep']) for r in subset)!=list(range(7)):raise RuntimeError('bad sample identities')
        values=[int(r['process_ns'])/int(r['cycles']) for r in subset]
        summaries.append({'capacity':cap,'samples':7,'process_ns_per_cycle_min_median_max':[min(values),statistics.median(values),max(values)]})
    result.update(status='PASS',finished_utc=now(),cpu_summaries=summaries,
      interpretation='Cost contract passed; timings characterize only original-header helper cycle and host cache/CPU. No hardware throughput conclusion.')
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'PASS','cpu_summaries':summaries,'scope':result['scope']}))
