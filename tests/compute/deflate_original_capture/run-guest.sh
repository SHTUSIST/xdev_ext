#!/bin/sh
# Run inside the root-owned matching correctness guest, before other ops attach.
set -eu
here=${1:-/opt/deflate-original}
[ "$(id -u)" = 0 ] || { echo 'FAIL requires guest root'; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo 'FAIL BTF unavailable'; exit 1; }
[ "$(uname -r)" = "$(cat "$here/identity/kernel.release")" ] || { echo 'FAIL kernel release mismatch'; exit 1; }
for name in xdev_ext_cpu_mech_ops xdev_ext_iaa_mech_ops xdev_ext_user_mech_ops; do
 grep -aqF "$name" /sys/kernel/btf/vmlinux || { echo "FAIL native class BTF absent: $name"; exit 1; }
done
(cd "$here" && sha256sum -c artifacts.sha256)
echo XDEV_EXT_DEFLATE_IDENTITY_BEGIN
cat "$here/identity/source.json" "$here/identity/gcc.txt" "$here/identity/bpf-clang.txt"
cat "$here/identity/test-freeze.json"
echo XDEV_EXT_DEFLATE_IDENTITY_END
# The complete registry is preserved; unique driver selection is source-pinned.
echo XDEV_EXT_DEFLATE_CRYPTO_BEGIN
cat /proc/crypto
echo XDEV_EXT_DEFLATE_CRYPTO_END
grep -Eq '^driver[[:space:]]*:[[:space:]]*deflate-generic$' /proc/crypto || { echo 'FAIL deflate-generic is absent'; exit 1; }
[ ! -e /tmp/deflate-original-output ] || { echo 'FAIL output already exists'; exit 1; }
mkdir -m 700 /tmp/deflate-original-output
set +e
XDEV_EXT_DEFLATE_ORIGINAL_GUEST=1 "$here/capture" "$here/plans.bpf.o" /tmp/deflate-original-output
capture_status=$?
set -e
echo "XDEV_EXT_DEFLATE_CAPTURE_EXIT=$capture_status"
exit "$capture_status"
