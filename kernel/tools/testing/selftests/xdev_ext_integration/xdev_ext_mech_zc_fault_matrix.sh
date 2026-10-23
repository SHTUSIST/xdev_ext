#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail
exec python3 -B "$(dirname "$0")/xdev_ext_mech_zc_fault_matrix.py" "$@"
