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
    python3 -B - "$SOURCE_GIT_ROOT" "$SRC" "$SOURCE_SUPPORT_VIEW" "$SOURCE_COMMIT" <<'PY_E2_SOURCES' > "$BUILD/xdev-ext-e2-sources.sha256" || return 1
import hashlib,json,pathlib,sys
repo,native,view=map(pathlib.Path,sys.argv[1:4]);revision=sys.argv[4]
sys.path.insert(0,str(repo/'tools'))
from layout import load_layout,provenance,safe_file,isolated_file,read_source
identity=provenance(repo)
if identity['dirty'] or identity['revision']!=revision:raise ValueError('E2 canonical identity changed')
layout=load_layout(repo)
receipt=json.loads(isolated_file(view,'view.json',True).read_text())
if (receipt.get('schema')!=1 or receipt.get('kind')!='host-source-view' or receipt.get('canonical_root')!=str(repo) or
    receipt.get('revision')!=revision or receipt.get('source_origins')!=layout.by_logical or
    receipt.get('manifest')!=layout.manifest):raise ValueError('E2 support view identity differs')
logical_inputs={name for name in layout.by_logical if name.startswith('tests/eval/mechanism_variants/')}
if 'tests/eval/mechanism_variants/Makefile' not in logical_inputs:raise ValueError('missing E2 support sources')
natives={'include/trace/events/xdev_ext.h','drivers/nvme/host/xdev_ext_mech_nvme.c','net/xdp/xsk.c',
         'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh',
         'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py'}
core={name for component,name in layout.by_native if component=='linux' and name.startswith('io_uring/')}
if 'io_uring/xdev_ext_mech.c' not in core:raise ValueError('missing E2 core sources')
natives.update(core)
natives.update(name for component,name in layout.by_native if component=='linux' and
    name.startswith(('tools/xdev_ext_mech/','tools/include/','tools/xdev_ext_')))
natives.update(('include/linux/xdev_ext_mech.h','include/uapi/linux/xdev_ext_mech.h','include/uapi/linux/io_uring.h'))
logical_inputs.update('kernel/'+name for name in natives)
# The unchanged actual-core exporter also consumes these support fixture files.
logical_inputs.update(name for name in layout.by_logical if name.startswith((
    'kernel/tools/testing/selftests/xdev_ext_mech/fanout_scheduler/',
    'kernel/tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/')))
paths=set()
for logical in sorted(logical_inputs):
    source=layout.by_logical[logical]
    original=safe_file(repo,source);copy=isolated_file(view,logical,True)
    if original.read_bytes()!=copy.read_bytes():raise ValueError('E2 logical copy differs: '+logical)
    paths.update((original,copy))
    if logical.startswith('kernel/'):
        name=logical[len('kernel/'):]
        actual=safe_file(native,name)
        expected=read_source(repo,'linux',name,revision)
        if actual.read_bytes()!=expected or original.read_bytes()!=expected:raise ValueError('E2 native input differs: '+name)
        paths.add(actual)
for name in ('source-layout.json','tools/layout.py',layout.manifest.get('dependency_lock','third_party/sources.lock.json')):
    paths.add(safe_file(repo,name))
paths.update((isolated_file(view,'view.json',True),safe_file(native,'.xdev-ext-source.json')))
for path in sorted(paths):print(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path.absolute()))
PY_E2_SOURCES
    [[ -s "$BUILD/xdev-ext-e2-sources.sha256" ]]
}
# Publish a new receipt only after the non-overwriting exporter succeeds.
e2_export_old_ticket() {
    local parent capture receipt
    mkdir -p "$E2_OUT" || return 1
    parent=$(mktemp -d "$E2_OUT/software-old-ticket.XXXXXXXX") || return 1
    parent=$(realpath -e -- "$parent") || return 1
    capture=$parent/capture
    python3 "$E2_SOURCE/export_old_ticket.py" "$SOURCE_SUPPORT_VIEW/kernel" "$capture" --cc gcc-14 > "$EV/e2-old-ticket-host.log" 2>&1 || return 1
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
