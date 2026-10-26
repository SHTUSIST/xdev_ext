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
    (cd "$SOURCE_GIT_ROOT"
        git ls-files -z -- tests/eval/mechanism_variants kernel/include/trace/events/xdev_ext.h \
            kernel/io_uring kernel/drivers/nvme/host/xdev_ext_mech_nvme.c kernel/net/xdp/xsk.c \
            kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh \
            kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py \
            | while IFS= read -r -d '' path; do sha256sum "$SOURCE_GIT_ROOT/$path"; done
    ) > "$BUILD/xdev-ext-e2-sources.sha256"
    [[ -s "$BUILD/xdev-ext-e2-sources.sha256" ]]
}
e2_build() {
    e2_paths
    mkdir -p "$E2_OUT" "$E2_LIBBPF" "$E2_OUT/bpftool-build"
    lowprio make -C "$SRC/tools/lib/bpf" OUTPUT="$E2_LIBBPF/" CC=gcc-14 HOSTCC=gcc-14 \
        prefix="$E2_LIBBPF" "$E2_LIBBPF/libbpf.a" install_headers > "$EV/e2-libbpf-build.log" 2>&1
    lowprio make -C "$SRC/tools/bpf/bpftool" OUTPUT="$E2_OUT/bpftool-build/" \
        CC=gcc-14 HOSTCC=gcc-14 CLANG=/usr/bin/clang-21 > "$EV/e2-bpftool-build.log" 2>&1
    cp "$E2_OUT/bpftool-build/bpftool" "$E2_OUT/bpftool"
    lowprio make -C "$E2_SOURCE" BUILD="$E2_OUT" CC=gcc-14 \
        CPPFLAGS="-I$E2_LIBBPF/include" LIBBPF_LIBS="$E2_LIBBPF/libbpf.a" \
        sink ctl > "$EV/e2-frontends-build.log" 2>&1
    lowprio make -C "$E2_SOURCE/tests" BUILD_DIR="$E2_OUT" \
        CLANG=/usr/bin/clang-21 BPFTOOL="$E2_OUT/bpftool" VMLINUX_BTF="$BUILD/vmlinux" \
        bpf > "$EV/e2-bpf-build.log" 2>&1
    cp "$E2_SOURCE/"{guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} "$E2_OUT/"
    python3 "$E2_SOURCE/export_old_ticket.py" "$SRC" "$E2_OUT/software-old-ticket" --cc gcc-14 > "$EV/e2-old-ticket-host.log" 2>&1
    e2_record_sources
    printf 'mechanism_variants=1\nsource_commit=%s\n' "$SOURCE_COMMIT" > "$BUILD/xdev-ext-e2-mode.txt"
}
e2_record_artifacts() {
    e2_paths
    sha256sum "$E2_OUT/"{mv_ctl,mv_sink,bpftool,nvme_reverse.bpf.o,nvme_gray.bpf.o,guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} \
        "$BUILD/xdev-ext-e2-mode.txt" "$BUILD/xdev-ext-e2-sources.sha256" \
        "$E2_OUT/software-old-ticket/"* >> "$BUILD/xdev-ext-artifacts.sha256"
}
e2_verify_identity() {
    local artifact symbol
    e2_paths
    grep -Fxq mechanism_variants=1 "$BUILD/xdev-ext-e2-mode.txt"
    grep -Fxq "source_commit=$SOURCE_COMMIT" "$BUILD/xdev-ext-e2-mode.txt"
    for symbol in TRACING FTRACE BPF_EVENTS XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY VIRTIO_CONSOLE; do
        grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config"
    done
    sha256sum -c "$BUILD/xdev-ext-e2-sources.sha256" > "$EV/e2-reused-source-check.log"
    for artifact in "$E2_OUT/"{mv_ctl,mv_sink,bpftool,nvme_reverse.bpf.o,nvme_gray.bpf.o,guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} \
        "$BUILD/xdev-ext-e2-mode.txt" "$BUILD/xdev-ext-e2-sources.sha256"; do
        [[ -s "$artifact" ]] && grep -Fxq -- "$(sha256sum -- "$artifact")" "$BUILD/xdev-ext-artifacts.sha256"
    done
}
e2_stage() {
    e2_verify_identity
    mkdir -p "$ROOT/opt/xdev_ext/e2"
    cp "$E2_OUT/"{mv_ctl,mv_sink,nvme_reverse.bpf.o,nvme_gray.bpf.o,guest_run.sh,trace_ctl.sh,kvm_guest.sh,export_artifacts.sh} "$ROOT/opt/xdev_ext/e2/"
    cp "$TOOLS/nxp_mech.bpf.o" "$TOOLS/nvme_s0.bpf.o" "$ROOT/opt/xdev_ext/e2/"
    cp "$E2_OUT/bpftool" "$ROOT/usr/bin/bpftool"
    mkdir -p "$EV/e2-software"
    cp "$E2_OUT/software-old-ticket/"* "$EV/e2-software/"
    for app in cp rm seq dd sha256sum base64 gzip awk sort stat; do ln -sf /bin/busybox "$ROOT/bin/$app"; done
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
