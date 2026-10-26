#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Sourced only by the explicit E2-only mode of the existing private KVM harness.
e2_paths() {
    E2_OUT=$TOOLS/e2
    E2_LIBBPF=$E2_OUT/libbpf
    [[ -r "$SRC/include/trace/events/xdev_ext.h" ]] || { echo 'FAIL E2 needs actual native-event hooks' >&2; return 1; }
    grep -q 'xdev-native-v1-nvme-xsk-batch' "$SRC/include/trace/events/xdev_ext.h"
}
e2_record_sources() {
    (set -o pipefail
        cd "$SOURCE_GIT_ROOT" || exit 1
        git ls-files -z -- tests/eval/mechanism_variants kernel/include/trace/events/xdev_ext.h \
            kernel/io_uring kernel/drivers/nvme/host/xdev_ext_mech_nvme.c kernel/net/xdp/xsk.c \
            kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh \
            kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py \
            | while IFS= read -r -d '' path; do sha256sum "$SOURCE_GIT_ROOT/$path" || exit 1; done
    ) > "$BUILD/xdev-ext-e2-sources.sha256" || return 1
    [[ -s "$BUILD/xdev-ext-e2-sources.sha256" ]]
}
# Publish a new receipt only after the non-overwriting exporter succeeds.
e2_export_old_ticket() {
    local parent capture receipt
    mkdir -p "$E2_OUT" || return 1
    parent=$(mktemp -d "$E2_OUT/software-old-ticket.XXXXXXXX") || return 1
    parent=$(realpath -e -- "$parent") || return 1
    capture=$parent/capture
    python3 "$E2_SOURCE/export_old_ticket.py" "$SRC" "$capture" --cc gcc-14 > "$EV/e2-old-ticket-host.log" 2>&1 || return 1
    receipt=$(mktemp "$BUILD/xdev-ext-e2-old-ticket.path.XXXXXXXX") || return 1
    printf '%s\n' "$capture" > "$receipt" || return 1
    mv -f -- "$receipt" "$BUILD/xdev-ext-e2-old-ticket.path"
}
# Resolve the one selected capture, rejecting aliases and incomplete exports.
e2_old_ticket_path() {
    python3 - "$E2_OUT" "$BUILD/xdev-ext-e2-old-ticket.path" <<'PY_PATH'
import pathlib,sys
try:
    root=pathlib.Path(sys.argv[1]).resolve(strict=True)
    receipt=pathlib.Path(sys.argv[2])
    if receipt.is_symlink(): raise ValueError('symlink path receipt')
    value=receipt.read_text()
    if not value.endswith('\n') or len(value.splitlines())!=1:
        raise ValueError('expected one capture path')
    name=value[:-1]
    capture=pathlib.Path(name)
    actual=capture.resolve(strict=True)
    if not capture.is_absolute() or str(actual)!=name or root not in actual.parents or not actual.is_dir():
        raise ValueError('capture must be canonical and inside E2_OUT')
    required={'old-ticket-fixture.c','old-ticket-fixture','build.log','command.json',
              'old-ticket.log','old_ticket.json','source.json'}
    files=list(actual.iterdir())
    if required!={p.name for p in files}: raise ValueError('unexpected or incomplete capture')
    if any(p.is_symlink() or not p.is_file() or '\n' in p.name or '\r' in p.name for p in files):
        raise ValueError('capture must contain regular files')
    print(actual)
except (OSError,ValueError) as exc:
    sys.exit('FAIL E2 old-ticket capture: '+str(exc))
PY_PATH
}
e2_build() {
    e2_paths || return 1
    mkdir -p "$E2_OUT" "$E2_LIBBPF" "$E2_OUT/bpftool-build" || return 1
    lowprio make -C "$SRC/tools/lib/bpf" OUTPUT="$E2_LIBBPF/" CC=gcc-14 HOSTCC=gcc-14 \
        prefix="$E2_LIBBPF" "$E2_LIBBPF/libbpf.a" install_headers > "$EV/e2-libbpf-build.log" 2>&1 || return 1
    lowprio make -C "$SRC/tools/bpf/bpftool" OUTPUT="$E2_OUT/bpftool-build/" \
        CC=gcc-14 HOSTCC=gcc-14 CLANG=/usr/bin/clang-21 > "$EV/e2-bpftool-build.log" 2>&1 || return 1
    cp "$E2_OUT/bpftool-build/bpftool" "$E2_OUT/bpftool" || return 1
    lowprio make -C "$E2_SOURCE" BUILD="$E2_OUT" CC=gcc-14 \
        CPPFLAGS="-I$E2_LIBBPF/include" LIBBPF_LIBS="$E2_LIBBPF/libbpf.a" \
        sink ctl > "$EV/e2-frontends-build.log" 2>&1 || return 1
    lowprio make -C "$E2_SOURCE/tests" BUILD_DIR="$E2_OUT" \
        CLANG=/usr/bin/clang-21 BPFTOOL="$E2_OUT/bpftool" VMLINUX_BTF="$BUILD/vmlinux" \
        bpf > "$EV/e2-bpf-build.log" 2>&1 || return 1
    cp "$E2_SOURCE/"{guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} "$E2_OUT/" || return 1
    e2_export_old_ticket || return 1
    e2_record_sources || return 1
    printf 'mechanism_variants=1\nsource_commit=%s\n' "$SOURCE_COMMIT" > "$BUILD/xdev-ext-e2-mode.txt"
}
e2_record_artifacts() {
    local capture
    e2_paths || return 1
    capture=$(e2_old_ticket_path) || return 1
    sha256sum "$E2_OUT/"{mv_ctl,mv_sink,bpftool,nvme_reverse.bpf.o,nvme_gray.bpf.o,guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} \
        "$BUILD/xdev-ext-e2-mode.txt" "$BUILD/xdev-ext-e2-sources.sha256" \
        "$BUILD/xdev-ext-e2-old-ticket.path" "$capture/"* >> "$BUILD/xdev-ext-artifacts.sha256"
}
e2_verify_identity() {
    local artifact symbol capture identity
    e2_paths || return 1
    capture=$(e2_old_ticket_path) || return 1
    grep -Fxq mechanism_variants=1 "$BUILD/xdev-ext-e2-mode.txt" || return 1
    grep -Fxq "source_commit=$SOURCE_COMMIT" "$BUILD/xdev-ext-e2-mode.txt" || return 1
    for symbol in TRACING FTRACE BPF_EVENTS XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY VIRTIO_CONSOLE; do
        grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || return 1
    done
    sha256sum -c "$BUILD/xdev-ext-e2-sources.sha256" > "$EV/e2-reused-source-check.log" || return 1
    for artifact in "$E2_OUT/"{mv_ctl,mv_sink,bpftool,nvme_reverse.bpf.o,nvme_gray.bpf.o,guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} \
        "$BUILD/xdev-ext-e2-mode.txt" "$BUILD/xdev-ext-e2-sources.sha256" "$BUILD/xdev-ext-e2-old-ticket.path"; do
        [[ -s "$artifact" ]] || return 1
        identity=$(sha256sum -- "$artifact") || return 1
        grep -Fxq -- "$identity" "$BUILD/xdev-ext-artifacts.sha256" || return 1
    done
    for artifact in "$capture/"*; do
        identity=$(sha256sum -- "$artifact") || return 1
        grep -Fxq -- "$identity" "$BUILD/xdev-ext-artifacts.sha256" || return 1
    done
}
e2_stage() {
    local capture
    e2_verify_identity || return 1
    capture=$(e2_old_ticket_path) || return 1
    mkdir -p "$ROOT/opt/xdev_ext/e2" || return 1
    cp "$E2_OUT/"{mv_ctl,mv_sink,nvme_reverse.bpf.o,nvme_gray.bpf.o,guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} "$ROOT/opt/xdev_ext/e2/" || return 1
    cp "$TOOLS/nxp_mech.bpf.o" "$TOOLS/nvme_s0.bpf.o" "$ROOT/opt/xdev_ext/e2/" || return 1
    cp "$E2_OUT/bpftool" "$ROOT/usr/bin/bpftool" || return 1
    mkdir -p "$EV/e2-software" || return 1
    cp "$capture/"* "$EV/e2-software/" || return 1
    for app in cp rm seq dd sha256sum base64 gzip awk sort stat; do ln -sf /bin/busybox "$ROOT/bin/$app" || return 1; done
}
e2_images() {
    python3 - "$SCRATCH" "$E2_SOURCE" "$IMAGE_BYTES" <<'PY'
import hashlib,pathlib,sys
scratch,source=map(pathlib.Path,sys.argv[1:3]);sys.path.insert(0,str(source))
from image import lba_bytes
size=int(sys.argv[3]);window=b''.join(lba_bytes(lba) for lba in range(2048,2112))
if len(window)!=32768 or size<2048*512+len(window):raise ValueError('invalid private E2 image geometry')
image=bytearray(size);image[1048576:1048576+len(window)]=window
for name in ('source.raw','source-before.raw'):(scratch/name).write_bytes(image)
for name in ('destination.raw','destination-before.raw','expected.raw'):(scratch/name).write_bytes(bytes(size))
(scratch/'evidence/e2-source-window.bin').write_bytes(window)
(scratch/'evidence/source-before.sha256').write_text(hashlib.sha256(image).hexdigest()+'\n')
PY
}
