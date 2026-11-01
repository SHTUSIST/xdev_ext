#!/usr/bin/env bash
set -eu
# run.sh SOURCE_ROOT OUTPUT_DIR [legacy|new]
source_root=$(realpath "${1:?source root}")
output_dir=${2:?output dir}
mode=${3:-legacy}
mkdir -p "$output_dir"
test_dir=$(cd "$(dirname "$0")" && pwd)
extra=()
case "$mode" in legacy) ;; new) extra+=(-DSW_SCHEMA_NEW=1);; *) exit 2;; esac
printf 'source_root=%s\nmode=%s\n' "$source_root" "$mode" > "$output_dir/context.txt"
gcc --version > "$output_dir/compiler.txt"
rc=0
for profile in gcc ubsan; do
 flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror)
 if [ "$profile" = ubsan ]; then flags+=(-fsanitize=undefined -fno-sanitize-recover=all); fi
 command=(gcc "${flags[@]}" "${extra[@]}" -I"$source_root/src/storage/include/linux" -I"$source_root/src/core/include/linux" "$test_dir/test_window_schema.c" -o "$output_dir/$profile")
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
