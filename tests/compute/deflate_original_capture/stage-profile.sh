#!/bin/bash
# Root-only: specialize an EXISTING prepared strict-debug profile's generated
# initroot. No production source or original test runner is modified.
set -euo pipefail
[[ $# == 2 ]] || { echo 'usage: stage-profile.sh EXISTING_PROFILE_INITROOT BUILD_OUTPUT' >&2; exit 2; }
root=$(realpath "$1")
output=$(realpath "$2")
[[ -f "$root/init" && -x "$root/bin/busybox" && ! -e "$root/opt/deflate-original" ]]
mkdir -p "$root/opt/deflate-original"
cp -a "$output/." "$root/opt/deflate-original/"
for app in sh mount mkdir cat grep uname sha256sum dmesg sync poweroff; do
 ln -sf busybox "$root/bin/$app"
done
ldd "$output/capture" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}' > "$output/guest-libraries.txt"
[[ -s "$output/guest-libraries.txt" ]]
while IFS= read -r lib; do
 [[ -r "$lib" && "$lib" == /* ]]
 mkdir -p "$root$(dirname "$lib")"
 cp -L "$lib" "$root$lib"
done < "$output/guest-libraries.txt"
cp -p "$root/init" "$root/init.before-deflate-original"
cat > "$root/init" <<'GUEST'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc || exit 1
mount -t sysfs sysfs /sys || exit 1
mount -t devtmpfs devtmpfs /dev || exit 1
mount -t tmpfs tmpfs /tmp || exit 1
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf || exit 1
sh /opt/deflate-original/run-guest.sh /opt/deflate-original
code=$?
echo "XDEV_EXT_DEFLATE_GUEST_EXIT=$code"
dmesg
sync
poweroff -f
GUEST
chmod 755 "$root/init"
