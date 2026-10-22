#!/bin/sh
set -eu
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
kernel_dir=${KERNEL_DIR:-$(CDPATH= cd -- "$test_dir/../../../../.." && pwd)}
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/xdev-reliability.XXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
if [ -n "${RELIABLE_HEADER:-}" ]; then
    set -- "-DRELIABLE_HEADER=\"$RELIABLE_HEADER\""
else
    set --
fi
${CC:-cc} -std=gnu11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize=undefined -fno-sanitize-recover=all \
    -I "$kernel_dir" "$@" "$test_dir/reliable_behavior_test.c" \
    -o "$build_dir/reliable_behavior_test"
"$build_dir/reliable_behavior_test"
