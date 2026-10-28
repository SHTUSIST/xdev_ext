#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Selftest entry for the lifecycle model check (see life_explore.c): explore
# the live headers, then require every seeded defect to be found.  Fails if
# either header changes while it runs, so a pass names what it checked.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel_dir=${KERNEL_DIR:-$(CDPATH= cd -- "$test_dir/../../../../.." && pwd)}
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/xdev-life-model.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
headers="io_uring/xdev_ext_mech_lifecycle.h io_uring/xdev_ext_mech_core.h"
before=$(cd "$kernel_dir" && sha256sum $headers)
echo "$before" | sed 's/^/# /'
${CC:-cc} -std=gnu11 -O2 -g -Wall -Wextra -Werror \
    -fsanitize=undefined -fno-sanitize-recover=all \
    -I "$test_dir/shim" -I "$kernel_dir" "$test_dir/life_explore.c" \
    -o "$build_dir/life_explore"
"$build_dir/life_explore"
python3 "$test_dir/mutants.py" "$kernel_dir" "$build_dir"
after=$(cd "$kernel_dir" && sha256sum $headers)
if [ "$before" != "$after" ]; then
    echo "not ok - a header changed during the model check; rerun" >&2
    exit 1
fi
