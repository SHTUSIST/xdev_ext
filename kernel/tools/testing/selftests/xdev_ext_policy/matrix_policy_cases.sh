#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Append to the existing 13-case correctness campaign on the authorized guest host.
# A successful invocation needs an already built exact-SHA harness scratch directory.
set -euo pipefail
umask 077
scratch=${1:?usage: matrix_policy_cases.sh SCRATCH KERNEL_SOURCE}
source_tree=${2:?usage: matrix_policy_cases.sh SCRATCH KERNEL_SOURCE}
[[ $# == 2 ]]
harness=$source_tree/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh
mkdir -p "$scratch/policy-campaigns"
for policy in window1 window8 every-n delayed exponential oldest round-robin; do
    destination=$scratch/policy-campaigns/$policy
    [[ ! -e "$destination" ]] || { echo "evidence already exists: $destination" >&2; exit 1; }
    fault=none
    case "$policy" in exponential|oldest|round-robin) fault=reliable-drop-data ;; esac
    status=0
    bash "$harness" --scratch "$scratch" --source "$source_tree" --run-only \
        --groups 257 --depth 8 --ce-slots 8 --ce-sim --ce-delay-us 10000 --rx-ce \
        --reliable --rel-policy "$policy" --fault "$fault" || status=$?
    cp -a "$scratch/evidence" "$destination"
    printf '%s\n' "$status" >"$destination/policy.exit"
    [[ "$status" == 0 ]] || exit "$status"
done
echo 'XDEV_EXT_REL_POLICY_MATRIX=PASS cases=7 scope=KVM-software-correctness'
