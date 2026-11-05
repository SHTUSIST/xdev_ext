#!/usr/bin/env python3
import argparse,json,subprocess,sys,tempfile,resource,hashlib,os
from pathlib import Path
sys.dont_write_bytecode=True
from adapter import generate,structure,freeze_inputs,FIXTURE,OLD_MUTANTS,NEW_MUTANTS,SetupError
from typed_fixture import migrate,FixtureContractError,CONTRACT,GOLDEN_BYTES as TYPED_GOLDEN_BYTES,GOLDEN_SHA256 as TYPED_GOLDEN_SHA256
# SHA256 and length of the complete frozen preproducer old-source stdout.
GOLDEN_SHA256="9fc5b51ce2e82c7b6411021549e3c4291e5cbe9797b210d0af3de71d514bdf81"
GOLDEN_BYTES=89721
p=argparse.ArgumentParser(description='COUNT_FIFO actual-body correctness, explicit fixture contract and ownership/wiring gate');p.add_argument('--source',type=Path,required=True,help='canonical repository containing source-layout.json and src/');p.add_argument('--out-root',type=Path);p.add_argument('--fixture-contract',choices=['historical-raw-v0',CONTRACT],default='historical-raw-v0',help='explicit fixture/golden profile; historical raw is the default and requires its matching production root');g=p.add_mutually_exclusive_group();g.add_argument('--mutations',action='store_true');p.add_argument('--compare-baseline',type=Path,help='optional additional exact comparison with an external capture matching the selected fixture contract');g.add_argument('--only-mutation',choices=list(OLD_MUTANTS)+list(NEW_MUTANTS));a=p.parse_args()
golden_bytes,golden_sha256=(TYPED_GOLDEN_BYTES,TYPED_GOLDEN_SHA256) if a.fixture_contract==CONTRACT else (GOLDEN_BYTES,GOLDEN_SHA256)
a.source=a.source.resolve()
if not (a.source/'source-layout.json').is_file() or not (a.source/'src/network').is_dir():p.error('--source must name the canonical repository, not a generated view')
base=Path(__file__).resolve().parent;outroot=a.out_root or a.source/'build/count-fifo';outroot.mkdir(parents=True,exist_ok=True);out=Path(tempfile.mkdtemp(prefix='count-',dir=outroot));summary={'source':str(a.source),'fixture_contract':a.fixture_contract,'golden':{'bytes':golden_bytes,'sha256':golden_sha256},'inputs':freeze_inputs(a.source),'structural':structure(a.source),'runs':[]}
def limits():resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
def execute(label,mutation=None):
 d=out/label;d.mkdir();entry={'label':label};summary['runs'].append(entry)
 for n in ['os_boundary.h','test_count.c']:(d/n).write_bytes((base/n).read_bytes())
 (d/'frozen_pool_test.c').write_bytes((FIXTURE/'test_pool_dma.c').read_bytes())
 try:
  if a.fixture_contract==CONTRACT:
   generated,receipt=migrate((d/'test_count.c').read_bytes())
   (d/'fixture-transform.json').write_text(json.dumps(receipt,indent=2)+'\n')
   entry['fixture_transform']=receipt
   (d/'test_count.c').write_bytes(generated)
  have,manifest=generate(a.source,d,mutation,fixture_contract=a.fixture_contract)
 except (SetupError,FixtureContractError) as e:entry.update(verdict='SETUP',reason=str(e));return
 (d/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 cmd=['gcc','-std=gnu11','-O0','-funsigned-char','-fno-strict-aliasing','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-sign-compare',f'-DHAVE_POOL={int(have)}',f'-DHAVE_COUNT={int((a.source/"src/network/include/linux/xdev_ext_netfam_count.h").exists())}','test_count.c','-o','test_count'];(d/'command.json').write_text(json.dumps(cmd)+'\n')
 r=subprocess.run(cmd,cwd=d,capture_output=True,text=True);(d/'compile.stdout').write_text(r.stdout);(d/'compile.stderr').write_text(r.stderr);entry['compile_exit']=r.returncode
 if r.returncode:entry.update(verdict='SETUP',reason='compiler failure is never semantic RED');return
 try:r=subprocess.run([str(d/'test_count')],capture_output=True,text=True,timeout=45,preexec_fn=limits,env={**os.environ,**({'COUNT_MUTATION':mutation,**({'COUNT_FAIL_FAST':'1'} if mutation in NEW_MUTANTS else {})} if mutation else {})})
 except subprocess.TimeoutExpired:entry.update(verdict='SETUP',reason='runtime bound exceeded');return
 (d/'run.stdout').write_text(r.stdout);(d/'run.stderr').write_text(r.stderr);entry['exit']=r.returncode
 if mutation:
  designated=OLD_MUTANTS.get(mutation) or NEW_MUTANTS[mutation][3];entry['designated_assertion']=designated
  if mutation=='disconnected_public_consumer':
   finding=json.loads((d/'mutation_structural.json').read_text());entry['structural_mutation']=finding
   entry['kill_kind']='ownership_wiring'
   entry['verdict']='KILLED' if r.returncode==0 and finding['verdict']=='OWNERSHIP_WIRING_RED' and designated in finding['assertions'] else 'INVALID_MUTANT'
  else:
   entry['kill_kind']='runtime_assertion'
   entry['verdict']='KILLED' if r.returncode in (1,42) and designated in r.stderr else 'SURVIVED' if not r.returncode else 'INVALID_MUTANT'
 else:
  entry['verdict']='PASS' if not r.returncode else 'FAIL'
  observed=r.stdout.encode('utf-8');entry['stdout_bytes']=len(observed);entry['stdout_sha256']=hashlib.sha256(observed).hexdigest()
  entry['frozen_golden']='PASS' if len(observed)==golden_bytes and entry['stdout_sha256']==golden_sha256 else 'FAIL'
  if entry['frozen_golden']=='FAIL':entry['verdict']='FAIL'
  if a.compare_baseline:
   entry['golden_compare']='PASS' if a.compare_baseline.read_bytes()==observed else 'FAIL'
   if entry['golden_compare']=='FAIL':entry['verdict']='FAIL'
execute('baseline')
if a.only_mutation:execute(a.only_mutation,a.only_mutation)
if a.mutations:
 for m in OLD_MUTANTS:execute(m,m)
 for m in NEW_MUTANTS:execute(m,m)
expected=list(OLD_MUTANTS)+list(NEW_MUTANTS) if a.mutations else [a.only_mutation] if a.only_mutation else []
baseline=summary['runs'][0]
accepted=(baseline.get('compile_exit')==0 and baseline.get('exit')==0 and baseline.get('verdict')=='PASS' and baseline.get('frozen_golden')=='PASS' and summary['structural']['verdict']=='PASS')
accepted=accepted and [entry['label'] for entry in summary['runs'][1:]]==expected
for entry in summary['runs'][1:]:
 if entry.get('compile_exit')!=0 or entry.get('verdict')!='KILLED':accepted=False
summary['expected_mutations']=expected;summary['accepted']=accepted
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');(out/'structural.json').write_text(json.dumps(summary['structural'],indent=2)+'\n')
print(out);print(json.dumps(summary,indent=2));raise SystemExit(0 if accepted else 2)
