#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Bounded serial transport of actual private-guest files, no verdict synthesis.
set -eu
[ "$#" = 1 ] && [ "${E2_PRIVATE_GUEST:-}" = yes ] || exit 2
dir=$1
[ -d "$dir" ] && [ ! -e "$dir/export.manifest" ] || exit 2
count=0 total=0
: > "$dir/export.manifest"
for file in "$dir"/*; do
    name=${file##*/}
    [ "$name" != export.manifest ] || continue
    [ -f "$file" ] && [ ! -L "$file" ]
    case "$name" in ''|*[!A-Za-z0-9_.-]*|.*) exit 2;; esac
    [ "${#name}" -le 128 ]
    bytes=$(wc -c < "$file")
    [ "$bytes" -le 8388608 ]
    hash=$(sha256sum "$file"); hash=${hash%% *}
    printf '%s %s %s\n' "$name" "$bytes" "$hash" >> "$dir/export.manifest"
    count=$((count+1)); total=$((total+bytes))
    [ "$count" -lt 96 ] && [ "$total" -le 33554432 ]
done
for file in "$dir"/*; do
    name=${file##*/}
    bytes=$(wc -c < "$file")
    hash=$(sha256sum "$file"); hash=${hash%% *}
    printf 'E2_ARTIFACT_BEGIN name=%s bytes=%s sha256=%s\n' "$name" "$bytes" "$hash"
    base64 "$file" | sed 's/^/E2_ARTIFACT_DATA /'
    printf 'E2_ARTIFACT_END name=%s\n' "$name"
done
manifest_bytes=$(wc -c < "$dir/export.manifest")
manifest_hash=$(sha256sum "$dir/export.manifest"); manifest_hash=${manifest_hash%% *}
printf 'E2_ARTIFACT_SET_END files=%s bytes=%s manifest_sha256=%s\n' \
    "$((count+1))" "$((total+manifest_bytes))" "$manifest_hash"
