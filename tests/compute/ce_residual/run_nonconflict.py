#!/usr/bin/env python3
"""Run additive held-range nonconflict control against a prior extracted input."""
import argparse, json, pathlib, subprocess, sys
p = argparse.ArgumentParser()
p.add_argument('--base-evidence', type=pathlib.Path, required=True)
p.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args()
a.base_evidence = a.base_evidence.resolve()
a.output = a.output.resolve()
a.output.mkdir(parents=True, exist_ok=True)
receipt = json.loads((a.base_evidence / 'receipt.json').read_text())
cmd = receipt['compile_command'][:]
here = pathlib.Path(__file__).resolve().parent
cmd[cmd.index(str(here / 'harness.c'))] = str(here / 'nonconflict_hold.c')
cmd[cmd.index('-o') + 1] = str(a.output / 'nonconflict-hold')
build = subprocess.run(cmd, text=True, capture_output=True)
(a.output / 'build.log').write_text(build.stdout + build.stderr)
if build.returncode:
    print('SETUP: supplemental control compilation failed')
    print(build.stderr)
    sys.exit(2)
run = subprocess.run([str(a.output / 'nonconflict-hold')], text=True, capture_output=True)
(a.output / 'run.log').write_text(run.stdout + run.stderr)
(a.output / 'receipt.json').write_text(json.dumps({'base_evidence': str(a.base_evidence), 'compile_command': cmd, 'compile_exit': build.returncode, 'execution_exit': run.returncode, 'limit': 'actual checked cleanup refusal leaves A configured identity; adjacent same-ops and equal numeric range different-ops B remain admissible'}, indent=2) + '\n')
print(run.stdout, end='')
sys.exit(run.returncode)
