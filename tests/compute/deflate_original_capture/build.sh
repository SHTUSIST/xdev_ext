#!/bin/bash
# Root-only GCC userspace build; Clang is used solely for mandatory BPF.
set -euo pipefail
umask 077
[[ $# == 4 ]] || { echo 'usage: build.sh PRODUCT_SOURCE KERNEL_BUILD SOURCE_ID NEW_OUTPUT' >&2; exit 2; }
source_root=$(realpath "$1")
kernel_build=$(realpath "$2")
source_id=$3
out=$4
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[[ -n "$source_id" && ! -e "$out" ]] || { echo 'FAIL source-id empty or output exists' >&2; exit 1; }
python3 - "$here/FREEZE.json" "$source_root" "$here" <<'FREEZE'
import hashlib,json,pathlib,sys
m=json.loads(pathlib.Path(sys.argv[1]).read_text())
for group,root in [('baseline_inputs',pathlib.Path(sys.argv[2])),('test_files',pathlib.Path(sys.argv[3]))]:
 for name,want in m[group].items():
  if hashlib.sha256((root/name).read_bytes()).hexdigest()!=want:
   raise SystemExit('FAIL frozen input changed: '+str(root/name))
print('FROZEN_INPUTS_MATCH=1')
FREEZE
mkdir -m 700 "$out"
out=$(realpath "$out")
mkdir "$out/identity"
CC=${CC:-gcc-14}
CLANG=${CLANG:-/usr/bin/clang-21}
for symbol in XDEV_EXT_MECH XDEV_EXT_MECH_CPU XDEV_EXT_MECH_IAA CRYPTO_ACOMP2 CRYPTO_DEFLATE IO_URING BPF_SYSCALL DEBUG_INFO_BTF; do
 grep -Fxq "CONFIG_$symbol=y" "$kernel_build/.config" || { echo "FAIL CONFIG_$symbol=y required" >&2; exit 1; }
done
[[ -s "$kernel_build/arch/x86/boot/bzImage" && -s "$kernel_build/include/config/kernel.release" ]]
cp "$kernel_build/.config" "$out/identity/kernel.config"
cp "$kernel_build/include/config/kernel.release" "$out/identity/kernel.release"
python3 - "$source_root" "$kernel_build" "$source_id" "$out/identity/source.json" <<'PY'
import hashlib, json, pathlib, sys
src, build, ident, output = sys.argv[1:]
relative = [
 'src/core/include/uapi/linux/io_uring.h', 'src/core/include/uapi/linux/xdev_ext_mech.h',
 'src/core/include/uapi/linux/xdev_ext_binding.h', 'src/core/include/linux/xdev_ext_mech.h',
 'src/compute/include/linux/xdev_ext_compfam.h', 'src/core/include/linux/xdev_ext_family_core.h',
 'src/core/io_uring/xdev_ext_mech.c', 'src/core/io_uring/xdev_ext_mech_ops.c',
 'src/core/io_uring/xdev_ext_mech_user.c', 'src/compute/io_uring/xdev_ext_mech_cpu.c',
 'src/compute/io_uring/xdev_ext_mech_cpu_core.h', 'src/compute/io_uring/iaa/xdev_ext_mech_iaa.c',
 'third_party/sources.lock.json']
def digest(p):
 h = hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
 return h.hexdigest()
d = {'source_root':src,'source_id_root_supplied':ident,'kernel_build':build,
     'claim':'KVM correctness original bytes, no timing; root must certify kernel-source parity',
     'files':{r:digest(pathlib.Path(src,r)) for r in relative},
     'kernel_artifacts':{r:digest(pathlib.Path(build,r)) for r in
                         ['.config','include/config/kernel.release','arch/x86/boot/bzImage']}}
p = pathlib.Path(build,'xdev-ext-source.commit')
if p.is_file(): d['build_source_marker'] = p.read_text().strip()
pathlib.Path(output).write_text(json.dumps(d,indent=2)+'\n')
PY
"$CC" --version > "$out/identity/gcc.txt"
"$CLANG" --version > "$out/identity/bpf-clang.txt"
"$CC" -std=gnu11 -O2 -g -Wall -Wextra -Werror -iquote "$source_root/src/core/include/uapi" \
 "$here/capture.c" -o "$out/capture" -lbpf -lelf -lz
multiarch=$("$CC" -print-multiarch)
"$CLANG" -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86 \
 -iquote "$source_root/src/core/include/uapi" -idirafter "/usr/include/$multiarch" \
 -c "$here/plans.bpf.c" -o "$out/plans.bpf.o"
python3 - "$out/identity/source.json" <<'PY'
import hashlib,json,pathlib,sys
m=json.loads(pathlib.Path(sys.argv[1]).read_text())
for name,want in m['files'].items():
 got=hashlib.sha256(pathlib.Path(m['source_root'],name).read_bytes()).hexdigest()
 if got!=want: raise SystemExit('FAIL source changed during build: '+name)
print('BUILD_SOURCE_UNCHANGED=1')
PY
cp "$here/run-guest.sh" "$out/run-guest.sh"
cp "$here/FREEZE.json" "$out/identity/test-freeze.json"
(cd "$out" && sha256sum capture plans.bpf.o run-guest.sh identity/* > artifacts.sha256)
printf 'ROOT_BUILD_OUTPUT=%s\n' "$out"
