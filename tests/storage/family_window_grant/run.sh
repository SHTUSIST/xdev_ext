#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -eu
# run.sh SOURCE_ROOT OUTPUT_DIR
# Storage LBA window grant rules, gcc and UBSan.
source_root=$(realpath "${1:?source root}")
output_dir=${2:?output dir}
mkdir -p "$output_dir"
test_dir=$(cd "$(dirname "$0")" && pwd)
printf 'source_root=%s\n' "$source_root" > "$output_dir/context.txt"
${CC:-gcc} --version > "$output_dir/compiler.txt"
rc=0
for profile in gcc ubsan; do
 flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror)
 if [ "$profile" = ubsan ]; then flags+=(-fsanitize=undefined -fno-sanitize-recover=all); fi
 command=("${CC:-gcc}" "${flags[@]}" -I"$source_root/src/storage/include/linux" "$test_dir/test_window_grant.c" -o "$output_dir/$profile")
 printf '%q ' "${command[@]}" > "$output_dir/$profile.command"
 printf '\n' >> "$output_dir/$profile.command"
 if "${command[@]}" > "$output_dir/$profile.compile.log" 2>&1; then
  if "$output_dir/$profile" > "$output_dir/$profile.run.log" 2>&1; then printf '0\n' > "$output_dir/$profile.exit";
  else result=$?;printf '%s\n' "$result" > "$output_dir/$profile.exit";rc=1;fi
  cat "$output_dir/$profile.run.log"
 else
  result=$?;printf 'SETUP compile:%s\n' "$result" > "$output_dir/$profile.exit"
  cat "$output_dir/$profile.compile.log";rc=2
 fi
done
exit "$rc"
