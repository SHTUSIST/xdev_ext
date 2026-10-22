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
mkdir -p "$scratch/campaigns"
run_campaign()
{
    local name=$1
    shift
    local status=0
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
    bash "$harness" --scratch "$scratch" --source "$source_tree" \
        "${campaign_args[@]}" "$@" || status=$?
    cp -a "$scratch/evidence" "$scratch/campaigns/$name"
    printf '%s\n' "$status" >"$scratch/campaigns/$name/matrix.exit"
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
