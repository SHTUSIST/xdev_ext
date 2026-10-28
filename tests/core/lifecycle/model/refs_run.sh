#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Selftest entry for the reference-counted lifecycle model (refs_explore.c):
# explore the live lifecycle header, then require every seeded defect of
# refs_mutants.py to be found.  Fails if the header changes while it runs.
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel_dir=${KERNEL_DIR:-$(CDPATH= cd -- "$test_dir/../../../../.." && pwd)}
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/xdev-refs-model.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
header=io_uring/xdev_ext_mech_lifecycle.h
before=$(cd "$kernel_dir" && sha256sum $header)
echo "$before" | sed 's/^/# /'
if ! ${CC:-cc} -std=gnu11 -O2 -g -Wall -Wextra -Werror \
    -fsanitize=undefined -fno-sanitize-recover=all \
    -I "$test_dir/shim" -I "$kernel_dir" "$test_dir/refs_explore.c" \
    -o "$build_dir/refs_explore" 2>"$build_dir/build.log"; then
    sed 's/^/# /' "$build_dir/build.log"
    echo "not ok - refs_explore does not build against $header"
    exit 1
fi
"$build_dir/refs_explore"
python3 "$test_dir/refs_mutants.py" "$kernel_dir" "$build_dir/mutants"
after=$(cd "$kernel_dir" && sha256sum $header)
if [ "$before" != "$after" ]; then
    echo "not ok - the header changed during the model check; rerun" >&2
    exit 1
fi
