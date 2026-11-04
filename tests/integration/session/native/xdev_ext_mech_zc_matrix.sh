#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Run only on the authorized build host, using a clean exact GitHub checkout.
set -euo pipefail
umask 077
scratch=${1:?usage: xdev_ext_mech_zc_matrix.sh SCRATCH SOURCE}
source_tree=${2:?usage: xdev_ext_mech_zc_matrix.sh SCRATCH SOURCE}
[[ $# == 2 ]]
harness=$source_tree/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh
[[ -r "$harness" ]]
# The explicit assembly receipt and current layout identify the helper; neither
# an enclosing Git repository nor a directory name is source authority.
archive_paths=$(python3 -B - "$source_tree" <<'PY_ARCHIVE'
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

def real(path):
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise ValueError('source paths must be absolute real paths')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('source paths must not contain symlinks')
    return path

def regular(path):
    real(path)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('source input must be regular: ' + str(path))
    return path

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

native = real(Path(sys.argv[1]))
marker = regular(native / '.xdev-ext-source.json')
receipt = json.loads(marker.read_text())
repo = real(Path(receipt['canonical_root']))
if (receipt.get('kind') != 'full-assembly' or receipt.get('component') != 'linux'
        or receipt.get('output') != str(native)):
    raise ValueError('source must be its recorded full Linux assembly')
if git(repo, 'rev-parse', '--show-toplevel') != str(repo):
    raise ValueError('canonical source must be its own Git root')
if git(repo, 'status', '--porcelain', '--untracked-files=all'):
    raise ValueError('canonical source contains dirty or untracked files')
git(repo, 'ls-files', '--error-unmatch', '--', 'tools/layout.py', 'source-layout.json')
layout_path = regular(repo / 'tools/layout.py')
spec = importlib.util.spec_from_file_location('_matrix_layout', layout_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
layout = module.load_layout(repo)
name = 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_archive.py'
source = layout.by_native[('linux', name)]
git(repo, 'ls-files', '--error-unmatch', '--', source)
helper = regular(repo / source)
actual = regular(native / name)
if receipt.get('source_origins', {}).get(name) != source or actual.read_bytes() != helper.read_bytes():
    raise ValueError('native archive helper differs from its mapped canonical source')
print(repo)
print(helper)
PY_ARCHIVE
)
mapfile -t archive_paths <<<"$archive_paths"
source_root=${archive_paths[0]}
archive_helper=${archive_paths[1]}
mkdir -p "$scratch/campaigns"
run_campaign()
{
    local name=$1
    shift
    local status=0 command_status
    local -a campaign_args=(--groups 257 --depth 8 --ce-slots 8 --ce-sim
        --ce-delay-us 10000 --rx-ce)
    if [[ "$name" == provider-* ]]; then
        campaign_args=(--provider-case "${name#provider-}")
    elif [[ "$name" != legacy-* ]]; then
        campaign_args+=(--reliable)
    fi
    [[ ! -e "$scratch/campaigns/$name" ]] || {
        echo "FAIL campaign evidence already exists: $name" >&2; return 1;
    }
    local case_dir=$scratch/acceptance/cases/$name
    [[ ! -e "$case_dir" && ! -L "$case_dir" ]] || {
        echo "FAIL campaign archive already exists: $name" >&2; return 1;
    }
    python3 -B "$archive_helper" run --scratch "$scratch" --case-dir "$case_dir" \
        --source-root "$source_root" --native-root "$source_tree" -- \
        bash "$harness" --scratch "$scratch" --source "$source_tree" \
        "${campaign_args[@]}" "$@" || status=$?
    # Archive errors must not replace a recorded child failure.
    if [[ "$status" != 0 && -f "$case_dir/command.exit" && ! -L "$case_dir/command.exit" ]]; then
        if command_status=$(cat -- "$case_dir/command.exit") &&
                [[ "$command_status" =~ ^-?[1-9][0-9]{0,2}$ ]] &&
                (( command_status >= -127 && command_status <= 255 )); then
            status=$(( command_status < 0 ? 128 - command_status : command_status ))
        fi
    fi
    if [[ -d "$case_dir/evidence" ]]; then
        cp -a "$case_dir/evidence" "$scratch/campaigns/$name"
        if [[ -f "$case_dir/command.exit" ]]; then
            cp "$case_dir/command.exit" "$scratch/campaigns/$name/matrix.exit"
            chmod a-w "$scratch/campaigns/$name/matrix.exit"
        fi
    elif [[ "$status" == 0 ]]; then
        echo "FAIL frozen campaign evidence missing: $name" >&2
        status=1
    fi
    return "$status"
}
run_campaign normal --fault none
for fault in reliable-drop-data reliable-drop-ack reliable-duplicate-ack \
             reliable-replay-group reliable-reorder-group reliable-budget-unknown; do
    run_campaign "$fault" --run-only --fault "$fault"
done
run_campaign credit-window-one --run-only --fault none --remote-window 1
run_campaign legacy-normal --run-only --fault none
run_campaign legacy-drop-middle --run-only --fault drop-middle
run_campaign legacy-duplicate-middle --run-only --fault duplicate-middle
run_campaign provider-short --run-only
run_campaign provider-ambiguous --run-only
echo 'XDEV_EXT_ZC_MATRIX=PASS campaigns=13 legacy_campaigns=3 stream_groups=257 depth=8 ce_slots=8 dedicated_quarantine_guests=2 scope=KVM-software-devices'
