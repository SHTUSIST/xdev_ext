#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Print every commit of a BaM clone whose three patched files are exactly the
# pre-patch blobs of upstream.lock, newest first, then check that the patch
# applies on the first one.  Reads the clone only; it never checks out,
# fetches or writes.
#
#   find_upstream_commit.sh BAM_CLONE [LOCK] [PATCH]
set -eu

clone=$1
here=$(cd "$(dirname "$0")" && pwd)
lock=${2:-$here/upstream.lock}
patch=${3:-$here/bam-linux6-gcc13-compat.patch}
git -C "$clone" rev-parse --git-dir >/dev/null

wanted=$(awk '$1 == "blob" { print $2 " " $3 }' "$lock")
test -n "$wanted"
paths=$(printf '%s\n' "$wanted" | awk '{ print $1 }')
found=
for commit in $(git -C "$clone" rev-list --all); do
	match=1
	for path in $paths; do
		want=$(printf '%s\n' "$wanted" | awk -v p="$path" '$1 == p { print $2 }')
		have=$(git -C "$clone" rev-parse -q --verify "$commit:$path" 2>/dev/null || true)
		if [ "$have" != "$want" ]; then
			match=0
			break
		fi
	done
	if [ "$match" = 1 ]; then
		echo "match $commit $(git -C "$clone" log -1 --format='%cI %s' "$commit")"
		[ -n "$found" ] || found=$commit
	fi
done
if [ -z "$found" ]; then
	echo "no commit carries the pre-patch blobs" >&2
	exit 1
fi
# Apply-check against that commit's tree in a throwaway index.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
GIT_INDEX_FILE=$tmp/index git -C "$clone" read-tree "$found"
GIT_INDEX_FILE=$tmp/index git -C "$clone" apply --cached --check "$patch"
echo "pin $found (patch applies)"
