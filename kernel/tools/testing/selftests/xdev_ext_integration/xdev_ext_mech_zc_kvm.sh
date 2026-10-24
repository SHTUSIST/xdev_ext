#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Focused correctness proof, never a virtual-device performance benchmark.
# Run on an authorized build host against a private exact source snapshot:
#   bash xdev_ext_mech_zc_kvm.sh --scratch /tmp/xdev-ext-e2e.RUN --source /tmp/xdev-ext-e2e.SOURCE
# Add --ce-sim for chains a/b/d through a guest-only CPU-memcpy stand-in;
# this exercises the CE class, not a GPU or GPU performance.
# Source is a clean GitHub checkout (--source, or scratch/src); all disk writes and networking are
# confined to private image files and a QEMU hub/private UNIX stream cable.
set -euo pipefail
umask 077
SCRATCH=''
SOURCE_OVERRIDE=''
RUN_ONLY=0
PREPARE_ONLY=0
DEBUG_LOCKING=0
COMPAT=0
LIFECYCLE=0
PEER=0
GROUP_COUNT=4
DEPTH=''
CE_SLOTS=''
CE_SIM=0
CE_DELAY_US=0
FAULT=none
RX_CE=0
RELIABLE=0
REMOTE_WINDOW=''
REL_POLICY=default
PROVIDER_CASE=normal
FAULT_CAMPAIGN=''
while (($#)); do
	case "$1" in
	--scratch) SCRATCH=$2; shift 2 ;;
	--source) SOURCE_OVERRIDE=$2; shift 2 ;;
	--run-only) RUN_ONLY=1; shift ;;
	--prepare-only) PREPARE_ONLY=1; shift ;;
	--debug-locking) DEBUG_LOCKING=1; shift ;;
	--lifecycle) LIFECYCLE=1; shift ;;
	--compat) COMPAT=1; CE_SIM=1; shift ;;
	--peer) PEER=1; CE_SIM=1; shift ;;
	--groups) GROUP_COUNT=$2; shift 2 ;;
	--depth) DEPTH=$2; shift 2 ;;
	--ce-slots) CE_SLOTS=$2; shift 2 ;;
	--ce-sim) CE_SIM=1; shift ;;
	--ce-delay-us) CE_DELAY_US=$2; shift 2 ;;
	--fault) FAULT=$2; shift 2 ;;
	--rx-ce) RX_CE=1; shift ;;
 --reliable) RELIABLE=1; shift ;;
 --remote-window) REMOTE_WINDOW=$2; shift 2 ;;
 --rel-policy) REL_POLICY=$2; shift 2 ;;
 --provider-case) PROVIDER_CASE=$2; CE_SIM=1; shift 2 ;;
 --fault-campaign) FAULT_CAMPAIGN=$2; CE_SIM=1; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
# Debug kernels are correctness runs; allow instrumentation overhead without
# changing the default campaign budgets or matrix selection.
TIMEOUT_FACTOR=$((DEBUG_LOCKING ? 4 : 1))
CLI_TIMEOUT_MS=$((60000 * TIMEOUT_FACTOR))
RX_TIMEOUT_MS=$((15000 * TIMEOUT_FACTOR))
QEMU_TIMEOUT_SECONDS=$((150 * TIMEOUT_FACTOR))
# Campaign length is independent of the bounded in-flight pool/window.
[[ "$GROUP_COUNT" =~ ^[1-9][0-9]{0,3}$ && "$GROUP_COUNT" -le 1024 ]]
[[ -n "$DEPTH" ]] || DEPTH=$((RELIABLE ? 8 : (GROUP_COUNT < 64 ? GROUP_COUNT : 64)))
[[ -n "$CE_SLOTS" ]] || CE_SLOTS=$DEPTH
[[ "$DEPTH" =~ ^[1-9][0-9]?$ && "$DEPTH" -le 64 ]]
(( ! RELIABLE || DEPTH <= 32 ))
[[ -n "$REMOTE_WINDOW" ]] || REMOTE_WINDOW=$DEPTH
[[ "$REMOTE_WINDOW" =~ ^[1-9][0-9]?$ && "$REMOTE_WINDOW" -le 32 || "$RELIABLE" == 0 ]]
[[ "$CE_SLOTS" =~ ^[1-9][0-9]{0,3}$ && "$CE_SLOTS" -ge "$DEPTH" && "$CE_SLOTS" -le 1024 ]]
[[ "$CE_DELAY_US" =~ ^[0-9]+$ && "$CE_DELAY_US" -le 10000000 ]]
case "$REL_POLICY" in
 default) ;;
 window1|window8|every-n|delayed|exponential|oldest|round-robin) (( RELIABLE )) ;;
 *) echo 'invalid reliable policy case' >&2; exit 2 ;;
esac
case "$FAULT" in
none|drop-middle|duplicate-middle) [[ "$RELIABLE" == 0 || "$FAULT" == none ]] ;;
reliable-drop-data|reliable-drop-ack|reliable-duplicate-ack|reliable-replay-group|reliable-reorder-group|reliable-budget-unknown) (( RELIABLE )) ;;
*) exit 2 ;;
esac
case "$PROVIDER_CASE" in
normal) ;;
short|ambiguous) [[ "$FAULT" == none && "$RELIABLE" == 0 && "$RX_CE" == 0 ]] ;;
*) exit 2 ;;
esac
# Compatibility is an additional normal correctness campaign, with its own
# private ext4 disk and CE module lifetime. Fault matrices stay independent.
if (( COMPAT )); then [[ "$PROVIDER_CASE" == normal && "$FAULT" == none ]]; fi
if (( PEER )); then [[ "$PROVIDER_CASE" == normal && "$FAULT" == none && "$GROUP_COUNT" -ge 257 ]]; fi
if [[ -n "$FAULT_CAMPAIGN" ]]; then
    [[ "$FAULT" == none && "$PROVIDER_CASE" == normal && "$RELIABLE" == 0 && "$RX_CE" == 0 && "$COMPAT" == 0 && "$PEER" == 0 ]]
    (( GROUP_COUNT >= 2 && GROUP_COUNT <= 256 && DEPTH <= 8 && DEPTH <= GROUP_COUNT ))
fi
if (( LIFECYCLE )); then
    [[ -z "$FAULT_CAMPAIGN" ]]
    [[ "$FAULT" == none && "$PROVIDER_CASE" == normal && "$CE_SIM" == 0 && "$RELIABLE" == 0 ]]
fi
(( ! RX_CE || CE_SIM ))
(( ! CE_DELAY_US || CE_SIM ))
[[ "$FAULT" == none || "$GROUP_COUNT" -ge 2 ]]
[[ "$SCRATCH" =~ ^/tmp/xdev-ext-e2e\.[A-Za-z0-9]+$ ]]
[[ $(stat -c %a "$SCRATCH") == 700 && ! -L "$SCRATCH" ]]
SRC=${SOURCE_OVERRIDE:-$SCRATCH/src}
verify_source_checkout() {
    local anchor prefix=''
    [[ -d "$SRC" && ! -L "$SRC" ]] || {
        echo 'FAIL source must be a real checkout directory' >&2; return 1;
    }
    SRC=$(cd "$SRC" && pwd -P)
    SOURCE_GIT_ROOT=$(git -C "$SRC" rev-parse --show-toplevel) || {
        echo 'FAIL source is not a Git checkout' >&2; return 1;
    }
    SOURCE_GIT_ROOT=$(cd "$SOURCE_GIT_ROOT" && pwd -P)
    if [[ "$SOURCE_GIT_ROOT" == "$SRC" ]]; then
        SOURCE_LAYOUT=kernelgit
    elif [[ "$SOURCE_GIT_ROOT/kernel" == "$SRC" ]]; then
        SOURCE_LAYOUT=overlay
        prefix=kernel/
        git -C "$SOURCE_GIT_ROOT" ls-files --error-unmatch -- \
            sources.lock.json scripts/prepare_sources.py >/dev/null || {
            echo 'FAIL overlay source lacks tracked preparation metadata' >&2; return 1;
        }
    else
        echo 'FAIL source must be the Git root or its prepared kernel directory' >&2; return 1;
    fi
    for anchor in net/xdp/xsk_xdev_ext_mech_zc_core.h \
        tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh \
        tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py \
        tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_validate.py; do
        git -C "$SOURCE_GIT_ROOT" ls-files --error-unmatch -- "$prefix$anchor" >/dev/null || {
            echo "FAIL source lacks tracked kernel anchor: $anchor" >&2; return 1;
        }
    done
    git -C "$SOURCE_GIT_ROOT" diff --quiet
    git -C "$SOURCE_GIT_ROOT" diff --cached --quiet
    [[ -z $(git -C "$SOURCE_GIT_ROOT" ls-files --others --exclude-standard) ]] || {
        echo 'FAIL source Git root contains untracked files' >&2; return 1;
    }
    if [[ "$SOURCE_LAYOUT" == overlay ]]; then
        python3 - "$SOURCE_GIT_ROOT/sources.lock.json" <<'PYSOURCEPATH'
import json, sys
with open(sys.argv[1]) as source:
    lock = json.load(source)
if lock.get('components', {}).get('linux', {}).get('path') != 'kernel':
    raise SystemExit('FAIL overlay preparation must describe kernel/')
PYSOURCEPATH
        python3 "$SOURCE_GIT_ROOT/scripts/prepare_sources.py" --component linux --check
    fi
    SOURCE_COMMIT=$(git -C "$SOURCE_GIT_ROOT" rev-parse --verify 'HEAD^{commit}')
}
verify_source_checkout
# Use the same campaign geometry for native commands, image creation and
# the strict full-image validator. The two destination spans never alias.
read -r SOURCE_SLBA RX_SLBA CE_SLBA IMAGE_BYTES <<<"$(python3 - "$SRC" "$GROUP_COUNT" "${FAULT_CAMPAIGN:-}" <<'PYLAYOUT'
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1])/'tools/testing/selftests/xdev_ext_integration'))
from xdev_ext_mech_zc_validate import image_layout
if sys.argv[3]:
    from xdev_ext_mech_zc_fault_validate import CAMPAIGNS, fault_layout
    if sys.argv[3] not in CAMPAIGNS:
        raise SystemExit('unknown fault campaign')
    layout = fault_layout(int(sys.argv[2]))
else:
    layout = image_layout(int(sys.argv[2]))
print(*(layout[key] for key in ('source_slba', 'rx_slba', 'ce_slba', 'image_bytes')))
PYLAYOUT
)"
BUILD=$SCRATCH/build
EV=$SCRATCH/evidence
ROOT=$SCRATCH/initroot
TOOLS=$SCRATCH/tools
CE_SIM_OUT=$TOOLS/ce-sim
DMA_SIM_OUT=$TOOLS/dma-provider
IAA_OUT=$TOOLS/iaa-transform
SOCKET_OUT=$TOOLS/socket-guest
PRELOAD_OUT=$TOOLS/preload
PEER_OUT=$TOOLS/peer-guest
QEMU=/usr/local/bin/qemu-system-x86_64
mkdir -p "$BUILD" "$EV" "$TOOLS"
# Only current-run derived verdicts are invalidated. Historical campaign
# directories and raw logs remain available even when this run fails early.
clear_derived_results() {
    rm -f -- "$EV/result.txt" "$EV/data-result.txt" "$EV/validation.json" \
        "$EV/data.sha256" "$EV/source-after.sha256" "$EV/debug-locking.json" "$EV/debug-locking-result.txt"
}
clear_derived_results
exec > >(tee -a "$EV/harness.log") 2>&1
DEBUG_HELPER=$SRC/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py
# Reusing an older CE-only build cannot certify the new transform campaign.
verify_iaa_identity() {
    local symbol artifact
    for symbol in XDEV_EXT_MECH_IAA CRYPTO_ACOMP2 CRYPTO_DEFLATE; do
        grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || {
            echo "FAIL software IAA requires CONFIG_$symbol=y" >&2; return 1;
        }
    done
    for artifact in "$IAA_OUT/iaa_runtime" "$IAA_OUT/iaa_pair.bpf.o"; do
        [[ -s "$artifact" ]] && awk -v target="$artifact" '$2 == target { found=1 } END { exit !found }' "$BUILD/xdev-ext-artifacts.sha256" || {
            echo 'FAIL software IAA artifact identity absent; rebuild exact source' >&2; return 1;
        }
    done
}
verify_compat_identity() {
    local symbol artifact
    for symbol in XDEV_EXT_MECH_SOCKET IO_URING_XDEV_EXT_IAA EXT4_FS VIRTIO_BLK; do
        grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || {
            echo "FAIL compatibility requires CONFIG_$symbol=y" >&2; return 1;
        }
    done
    for artifact in "$SOCKET_OUT/socket_runtime" "$SOCKET_OUT/ce_observe.bpf.o" \
        "$TOOLS/socket_sink.bpf.o" "$PRELOAD_OUT/libio_uring_unified.so" \
        "$PRELOAD_OUT/xdev_ext_preload_mech_workload" \
        "$PRELOAD_OUT/xdev_ext_preload_socket_smoke" "$PRELOAD_OUT/xdev_ext_preload_db_workload" \
        "$PRELOAD_OUT/xdev_ext_preload_ordinary_fork_guest"; do
        [[ -s "$artifact" ]] && awk -v target="$artifact" '$2 == target { found=1 } END { exit !found }' "$BUILD/xdev-ext-artifacts.sha256" || {
            echo 'FAIL compatibility artifact identity absent; rebuild exact source' >&2; return 1;
        }
    done
}
verify_peer_identity() {
    local symbol artifact
    for symbol in XDEV_EXT_MECH MLX5_CORE MLX5_CORE_EN; do
        grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config" || {
            echo "FAIL peer guest requires CONFIG_$symbol=y" >&2; return 1;
        }
    done
    for artifact in "$PEER_OUT/xdev_ext_peer_sw.ko" "$PEER_OUT/peer_nvme_e2e"; do
        [[ -s "$artifact" ]] && awk -v target="$artifact" '$2 == target { found=1 } END { exit !found }' "$BUILD/xdev-ext-artifacts.sha256" || {
            echo 'FAIL peer guest artifact identity absent; rebuild exact source' >&2; return 1;
        }
    done
}
if (( RUN_ONLY )); then
    [[ -r "$BUILD/xdev-ext-source.commit" ]] || {
        echo 'FAIL run-only build identity missing; rebuild exact source' >&2; exit 1;
    }
    [[ $(cat "$BUILD/xdev-ext-source.commit") == "$SOURCE_COMMIT" ]] || {
        echo 'FAIL run-only source SHA mismatch; rebuild exact source' >&2; exit 1;
    }
    [[ -r "$BUILD/xdev-ext-artifacts.sha256" ]] || {
        echo 'FAIL run-only artifact identity missing; rebuild exact source' >&2; exit 1;
    }
    sha256sum -c "$BUILD/xdev-ext-artifacts.sha256" >"$EV/reused-artifact-check.log" 2>&1 || {
        echo 'FAIL run-only artifact hash mismatch' >&2; exit 1;
    }
    python3 "$DEBUG_HELPER" reuse "$BUILD/.config" "$BUILD/xdev-ext-debug-profile.json" "$DEBUG_LOCKING"
    cp "$BUILD/.config" "$EV/kernel.config"
fi
lowprio() { nice -n 10 ionice -c 3 "$@"; }
kmake() { lowprio make -C "$SRC" O="$BUILD" -j8 CC=gcc-14 HOSTCC=gcc-14 "$@"; }
printf 'date_utc=%s\nhost=%s\nscratch=%s\nclaim=KVM correctness only; software NIC and NVMe backends\n' \
	"$(date -u +%FT%TZ)" "$(hostname)" "$SCRATCH" >"$EV/provenance.txt"
printf 'ce_sim=%s\nce_delay_us=%s\nfault=%s\nrx_ce=%s\nreliable=%s\ndepth=%s\nce_backend=CPU-memcpy stand-in; no GPU claim\n' "$CE_SIM" "$CE_DELAY_US" "$FAULT" "$RX_CE" "$RELIABLE" "$DEPTH" >>"$EV/provenance.txt"
printf 'groups=%s\ndepth=%s\nce_slots=%s\n' "$GROUP_COUNT" "$DEPTH" "$CE_SLOTS" >>"$EV/provenance.txt"
printf 'remote_window=%s\nrel_policy=%s\n' "$REMOTE_WINDOW" "$REL_POLICY" >>"$EV/provenance.txt"
printf 'provider_case=%s\n' "$PROVIDER_CASE" >>"$EV/provenance.txt"
printf 'compat=%s\n' "$COMPAT" >>"$EV/provenance.txt"
printf 'lifecycle=%s\n' "$LIFECYCLE" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'peer=%s\n' "$PEER" >>"$EV/provenance.txt"
printf 'debug_locking=%s\ntimeout_factor=%s\ncli_timeout_ms=%s\nrx_timeout_ms=%s\nqemu_timeout_seconds=%s\n' \
    "$DEBUG_LOCKING" "$TIMEOUT_FACTOR" "$CLI_TIMEOUT_MS" "$RX_TIMEOUT_MS" "$QEMU_TIMEOUT_SECONDS" >>"$EV/provenance.txt"
printf 'source_slba=%s\nrx_slba=%s\nce_slba=%s\nimage_bytes=%s\n' \
    "$SOURCE_SLBA" "$RX_SLBA" "$CE_SLBA" "$IMAGE_BYTES" >>"$EV/provenance.txt"
printf 'source_git_root=%s\nsource_directory=%s\nsource_layout=%s\nsource_commit=%s\n' \
    "$SOURCE_GIT_ROOT" "$SRC" "$SOURCE_LAYOUT" "$SOURCE_COMMIT" >>"$EV/provenance.txt"
printf '%s\n' "$SOURCE_COMMIT" >>"$EV/provenance.txt"
(cd "$SRC"
	git diff --binary
	# A patch-applied checkout has new headers as untracked files. Include
	# their contents too; git diff by itself is not a complete snapshot.
	while IFS= read -r -d '' path; do
		git diff --no-index --binary -- /dev/null "$path" || [[ $? == 1 ]]
	done < <(git ls-files --others --exclude-standard -z)
) >"$EV/source.patch"
git -C "$SOURCE_GIT_ROOT" status --porcelain=v1 >"$EV/source-status.txt"
(cd "$SRC"; { git diff --name-only --diff-filter=ACMRTUXB -z;
	git ls-files --others --exclude-standard -z; } | sort -zu | xargs -0 -r sha256sum;
	sha256sum net/xdp/xsk_xdev_ext_mech_zc_core.h \
	tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh \
	tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py \
	tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_validate.py) >"$EV/source-files.sha256"
if (( CE_SIM )); then
	(cd "$SRC"; sha256sum tools/testing/selftests/xdev_ext_mech/simulate/{Makefile,xdev_ext_ce_sim.c} \
		tools/xdev_ext_mech/ce_plan.bpf.c) >>"$EV/source-files.sha256"
fi
if (( ! RUN_ONLY )); then
	kmake defconfig >"$EV/defconfig.log" 2>&1
	cfg() { "$SRC/scripts/config" --file "$BUILD/.config" "$@"; }
	for symbol in MODULES WERROR DEBUG_INFO_NONE DEBUG_INFO_REDUCED \
		DEBUG_INFO_DWARF4 DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
		XDEV_EXT_MECH_KVM_BOUNCE LOCALVERSION_AUTO PROVE_LOCKING DEBUG_ATOMIC_SLEEP \
        KASAN KASAN_GENERIC KASAN_KUNIT_TEST; do cfg -d "$symbol"; done
	for symbol in BLK_DEV_INITRD RD_GZIP DEVTMPFS DEVTMPFS_MOUNT TMPFS \
		PROC_FS SYSFS DEBUG_FS NET UNIX PACKET INET NETDEVICES \
		PCI PCI_MSI ACPI SERIAL_8250 SERIAL_8250_CONSOLE BLOCK BLK_DEV_NVME \
		NVME_CORE IO_URING BPF BPF_SYSCALL BPF_JIT BPF_EVENTS KPROBES \
		KPROBE_EVENTS UPROBES UPROBE_EVENTS FTRACE FUNCTION_TRACER \
		DEBUG_INFO DEBUG_INFO_DWARF5 DEBUG_INFO_BTF XDP_SOCKETS \
		XDP_SOCKETS_DIAG CRYPTO IO_URING_XDEV_EXT_BPF_POLICY \
		XDP_SOCKETS_XDEV_EXT_POLICY XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY \
		VIRTIO VIRTIO_PCI VIRTIO_NET BPF_JIT_ALWAYS_ON; do cfg -e "$symbol"; done
	if (( CE_SIM )); then cfg -e MODULES -e MODULE_UNLOAD -e XDEV_EXT_MECH_CE -e XDEV_EXT_MECH_DMA; fi
    if (( CE_SIM )) && [[ "$PROVIDER_CASE" == normal ]]; then
        cfg -e XDEV_EXT_MECH_IAA -e CRYPTO_DEFLATE
    fi
    if (( LIFECYCLE )); then cfg -e XDEV_EXT_MECH_CPU -e CRYPTO_DEFLATE; fi
    if (( COMPAT )); then cfg -e XDEV_EXT_MECH_SOCKET -e IO_URING_XDEV_EXT_IAA -e EXT4_FS -e VIRTIO_BLK; fi
    if (( PEER )); then cfg -e NET_VENDOR_MELLANOX -e MLX5_CORE -e MLX5_CORE_EN; fi
    if (( DEBUG_LOCKING )); then
        for symbol in DEBUG_KERNEL PROVE_LOCKING DEBUG_ATOMIC_SLEEP KASAN KASAN_GENERIC DETECT_HUNG_TASK; do cfg -e "$symbol"; done
        cfg -d KASAN_KUNIT_TEST
    fi
	cfg --set-str LOCALVERSION '-xdev_ext-mech-zc'
	cfg --set-str SYSTEM_TRUSTED_KEYS ''
	cfg --set-str SYSTEM_REVOCATION_KEYS ''
	kmake olddefconfig >"$EV/olddefconfig.log" 2>&1
	for symbol in IO_URING_XDEV_EXT_BPF_POLICY XDP_SOCKETS_XDEV_EXT_POLICY XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY; do cfg -e "$symbol"; done
	kmake olddefconfig >>"$EV/olddefconfig.log" 2>&1
	cp "$BUILD/.config" "$EV/kernel.config"
    python3 "$DEBUG_HELPER" config "$BUILD/.config" /dev/null "$DEBUG_LOCKING"
	for symbol in DEBUG_INFO_BTF VIRTIO_NET BLK_DEV_NVME XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY; do
		grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config"
	done
	if (( CE_SIM )); then
		for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH_CE XDEV_EXT_MECH_DMA; do grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config"; done
	fi
    if (( CE_SIM )) && [[ "$PROVIDER_CASE" == normal ]]; then
        for symbol in XDEV_EXT_MECH_IAA CRYPTO_ACOMP2 CRYPTO_DEFLATE; do grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config"; done
    fi
	if (( PREPARE_ONLY )); then echo XDEV_EXT_ZC_CONFIG=PASS; exit 0; fi
	if (( CE_SIM )); then
		kmake bzImage vmlinux modules_prepare >"$EV/kernel-build.log" 2>&1
		# All guest drivers are built in; only this external stand-in is loaded.
		cp "$BUILD/vmlinux.symvers" "$BUILD/Module.symvers"
		mkdir -p "$CE_SIM_OUT"
		cp "$SRC/tools/testing/selftests/xdev_ext_mech/simulate/Makefile" \
			"$SRC/tools/testing/selftests/xdev_ext_mech/simulate/xdev_ext_ce_sim.c" "$CE_SIM_OUT/"
		kmake M="$CE_SIM_OUT" MODULE_PAHOLE_FLAGS= modules >"$EV/ce-sim-build.log" 2>&1
        mkdir -p "$DMA_SIM_OUT"
        cp "$SRC/tools/testing/selftests/xdev_ext_mech/provider/"{Makefile,*.c,*.h,run-guest.sh} "$DMA_SIM_OUT/"
        lowprio make -C "$DMA_SIM_OUT" runtime KERNEL_SRC="$SRC" CC=gcc-14 CLANG=/usr/bin/clang-21 >"$EV/dma-tools-build.log" 2>&1
        kmake M="$DMA_SIM_OUT" MODULE_PAHOLE_FLAGS= modules >"$EV/dma-provider-build.log" 2>&1
        if [[ "$PROVIDER_CASE" == normal ]]; then
            mkdir -p "$IAA_OUT"
            cp "$SRC/tools/testing/selftests/xdev_ext_mech/iaa_transform/"{Makefile,iaa_runtime.c,iaa_pair.bpf.c,campaign.h,observations.h,run-guest.sh} "$IAA_OUT/"
            lowprio make -C "$IAA_OUT" runtime KERNEL_SRC="$SRC" PROVIDER_HEADERS="$DMA_SIM_OUT" CC=gcc-14 CLANG=/usr/bin/clang-21 >"$EV/iaa-tools-build.log" 2>&1
        fi
	else
		kmake bzImage >"$EV/kernel-build.log" 2>&1
	fi
	lowprio make -C "$SRC/tools/xdev_ext_mech" -j8 BUILD_DIR="$TOOLS" \
		VMLINUX_BTF="$BUILD/vmlinux" CC=gcc-14 CLANG=/usr/bin/clang-21 \
		all >"$EV/tools-build.log" 2>&1
    if (( COMPAT )); then
        mkdir -p "$SOCKET_OUT" "$PRELOAD_OUT"
        cp "$SRC/tools/testing/selftests/xdev_ext_mech/socket_guest/"{Makefile,socket_runtime.c,observations.h,ce_observe.bpf.c} "$SOCKET_OUT/"
        lowprio make -C "$SOCKET_OUT" CC=gcc-14 CLANG=/usr/bin/clang-21 KERNEL_SRC="$SRC" \
            runtime >"$EV/socket-tools-build.log" 2>&1
        lowprio make -C "$SRC/tools/testing/selftests/xdev_ext_preload" OUTPUT="$PRELOAD_OUT" \
            CC=gcc-14 all >"$EV/preload-tools-build.log" 2>&1
    fi
    if (( PEER )); then
        mkdir -p "$PEER_OUT"
        cp "$SRC/tools/testing/selftests/xdev_ext_peer/guest/"{Makefile,xdev_ext_peer_sw.c,peer_nvme_e2e.c,sw_provider_uapi.h} "$PEER_OUT/"
        lowprio make -C "$PEER_OUT" KERNEL_SRC="$SRC" CC=gcc-14 LDFLAGS=-static \
            peer_nvme_e2e >"$EV/peer-tools-build.log" 2>&1
        kmake M="$PEER_OUT" MODULE_PAHOLE_FLAGS= modules >"$EV/peer-module-build.log" 2>&1
    fi
fi
lowprio make -C "$SRC/tools/testing/selftests/xdev_ext_integration/verifier" -j2 \
	BUILD_DIR="$TOOLS/verifier" CLANG=/usr/bin/clang-21 HOSTCC=gcc-14 \
	all >"$EV/verifier-build.log" 2>&1
if (( ! RUN_ONLY )); then
    python3 "$DEBUG_HELPER" record "$BUILD/.config" "$BUILD/xdev-ext-debug-profile.json" "$DEBUG_LOCKING"
    sha256sum "$BUILD/.config" "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" \
        "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/"*.bpf.o "$TOOLS/verifier/"*.bpf.o \
        >"$BUILD/xdev-ext-artifacts.sha256"
    sha256sum "$BUILD/xdev-ext-debug-profile.json" >>"$BUILD/xdev-ext-artifacts.sha256"
    if (( CE_SIM )); then
        sha256sum "$CE_SIM_OUT/xdev_ext_ce_sim.ko" \
            "$DMA_SIM_OUT/xdev_ext_dma_provider_sim.ko" \
            "$DMA_SIM_OUT/dma_provider_runtime" "$DMA_SIM_OUT/dma_provider_pair.bpf.o" \
            >>"$BUILD/xdev-ext-artifacts.sha256"
        if [[ "$PROVIDER_CASE" == normal ]]; then
            sha256sum "$IAA_OUT/iaa_runtime" "$IAA_OUT/iaa_pair.bpf.o" >>"$BUILD/xdev-ext-artifacts.sha256"
        fi
    fi
    if (( COMPAT )); then
        sha256sum "$SOCKET_OUT/socket_runtime" "$SOCKET_OUT/ce_observe.bpf.o" \
            "$PRELOAD_OUT/libio_uring_unified.so" "$PRELOAD_OUT/xdev_ext_preload_mech_workload" \
            "$PRELOAD_OUT/xdev_ext_preload_socket_smoke" "$PRELOAD_OUT/xdev_ext_preload_db_workload" \
        "$PRELOAD_OUT/xdev_ext_preload_ordinary_fork_guest" \
            >>"$BUILD/xdev-ext-artifacts.sha256"
    fi
    if (( PEER )); then
        sha256sum "$PEER_OUT/xdev_ext_peer_sw.ko" "$PEER_OUT/peer_nvme_e2e" >>"$BUILD/xdev-ext-artifacts.sha256"
    fi
    printf '%s\n' "$SOURCE_COMMIT" >"$BUILD/xdev-ext-source.commit"
fi
sha256sum "$BUILD/.config" "$BUILD/xdev-ext-debug-profile.json" >>"$EV/provenance.txt"
if (( CE_SIM )); then
	for symbol in MODULES MODULE_UNLOAD XDEV_EXT_MECH_CE XDEV_EXT_MECH_DMA; do grep -Fxq "CONFIG_$symbol=y" "$BUILD/.config"; done
	[[ -s "$CE_SIM_OUT/xdev_ext_ce_sim.ko" && -s "$TOOLS/ce_plan.bpf.o" ]]
fi
if (( CE_SIM )) && [[ "$PROVIDER_CASE" == normal ]]; then verify_iaa_identity; fi
if (( COMPAT )); then verify_compat_identity; fi
if (( PEER )); then verify_peer_identity; fi
[[ -c /dev/kvm && -w /dev/kvm && -x "$QEMU" && -x "$TOOLS/xdev_ext_mech_ctl" ]]
mkdir -p "$ROOT"/{bin,sbin,dev,proc,sys,tmp,run,etc,usr/bin,opt/xdev_ext}
[[ -e "$ROOT/dev/console" ]] || mknod -m 600 "$ROOT/dev/console" c 5 1
[[ -e "$ROOT/dev/null" ]] || mknod -m 666 "$ROOT/dev/null" c 1 3
cp /bin/busybox "$ROOT/bin/busybox"
for app in sh mount umount mkdir cat echo sleep poweroff ip grep dmesg sync readlink timeout date tail head sed rmdir mktemp env wc cmp id basename cut mknod; do
	ln -sf /bin/busybox "$ROOT/bin/$app"
done
if (( CE_SIM )); then
	for app in insmod rmmod; do ln -sf /bin/busybox "$ROOT/bin/$app"; done
	cp "$CE_SIM_OUT/xdev_ext_ce_sim.ko" "$TOOLS/ce_plan.bpf.o" "$ROOT/opt/xdev_ext/"
    mkdir -p "$ROOT/opt/xdev_ext/provider"
    cp "$DMA_SIM_OUT/"{xdev_ext_dma_provider_sim.ko,dma_provider_runtime,dma_provider_pair.bpf.o,run-guest.sh} "$ROOT/opt/xdev_ext/provider/"
    if [[ "$PROVIDER_CASE" == normal ]]; then
        mkdir -p "$ROOT/opt/xdev_ext/iaa"
        cp "$IAA_OUT/"{iaa_runtime,iaa_pair.bpf.o,run-guest.sh} "$ROOT/opt/xdev_ext/iaa/"
    fi
fi
cp "$TOOLS/xdev_ext_mech_ctl" "$TOOLS/nxp_mech.bpf.o" "$TOOLS/nxp_reliable.bpf.o" "$ROOT/opt/xdev_ext/"
DESTINATION_READONLY=0
if [[ -n "$FAULT_CAMPAIGN" ]]; then
    cp "$SRC/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_fault_guest.sh" "$ROOT/opt/xdev_ext/"
    gcc-14 -O2 -Wall -Wextra -Werror \
        "$SRC/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_fault_uid.c" \
        -o "$TOOLS/fault_uid"
    cp "$TOOLS/fault_uid" "$ROOT/opt/xdev_ext/"
    python3 - "$SRC" "$ROOT/opt/xdev_ext/fault.env" "$FAULT_CAMPAIGN" "$GROUP_COUNT" <<'PYFAULTENV'
import pathlib, shlex, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1])/'tools/testing/selftests/xdev_ext_integration'))
from xdev_ext_mech_zc_fault_validate import CAMPAIGNS, expectation_line, fault_layout
name = sys.argv[3]
case = CAMPAIGNS[name]
values = fault_layout(int(sys.argv[4]))
values.update(fault_campaign=name, fault_expectation=expectation_line(name),
              fault_after=int(case['after']), ce_fail_mode=case['fail_mode'],
              ce_fault_delay_us=case['delay_us'], nvme_mode=case['nvme_mode'])
pathlib.Path(sys.argv[2]).write_text(''.join(k+'='+shlex.quote(str(v))+'\n' for k, v in values.items()))
PYFAULTENV
    [[ "$FAULT_CAMPAIGN" != nvme-readonly-dest ]] || DESTINATION_READONLY=1
fi
if (( LIFECYCLE )); then
    grep -Fxq CONFIG_XDEV_EXT_MECH_CPU=y "$BUILD/.config"
    awk -v target="$TOOLS/cpu_plan.bpf.o" '$2 == target { found=1 } END { exit !found }' "$BUILD/xdev-ext-artifacts.sha256"
    lifecycle_guest=$SRC/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_lifecycle_guest.sh
    for command in fanout cpu-chain verify-xform; do
        grep -Fq "\"\$ctl\" $command " "$lifecycle_guest"
    done
    cp "$TOOLS/cpu_plan.bpf.o" "$lifecycle_guest" "$ROOT/opt/xdev_ext/"
fi
if (( COMPAT )); then
    mkdir -p "$ROOT/opt/xdev_ext/socket_guest" "$ROOT/opt/xdev_ext/preload"
    cp "$SOCKET_OUT/"{socket_runtime,ce_observe.bpf.o} \
        "$SRC/tools/testing/selftests/xdev_ext_mech/socket_guest/run-guest.sh" "$ROOT/opt/xdev_ext/socket_guest/"
    cp "$TOOLS/socket_sink.bpf.o" "$ROOT/opt/xdev_ext/"
    cp "$PRELOAD_OUT/"{libio_uring_unified.so,xdev_ext_preload_mech_workload,xdev_ext_preload_socket_smoke,xdev_ext_preload_db_workload,xdev_ext_preload_ordinary_fork_guest} \
        "$SRC/tools/testing/selftests/xdev_ext_preload/xdev_ext_preload_mech_guest.sh" "$ROOT/opt/xdev_ext/preload/"
    truncate -s 64M "$SCRATCH/compat.raw"
    /usr/sbin/mkfs.ext4 -q -F "$SCRATCH/compat.raw"
fi
if (( PEER )); then
    mkdir -p "$ROOT/opt/xdev_ext/peer_guest"
    cp "$PEER_OUT/"{xdev_ext_peer_sw.ko,peer_nvme_e2e} \
        "$SRC/tools/testing/selftests/xdev_ext_peer/guest/run-guest.sh" "$ROOT/opt/xdev_ext/peer_guest/"
    truncate -s 16M "$SCRATCH/peer.raw"
fi
mkdir -p "$ROOT/opt/xdev_ext/verifier"
cp "$TOOLS/verifier/"*.bpf.o \
	"$SRC/tools/testing/selftests/xdev_ext_integration/verifier/run.sh" \
	"$SRC/tools/testing/selftests/xdev_ext_integration/verifier/run_state.sh" \
	"$SRC/tools/testing/selftests/xdev_ext_integration/verifier/run_abi.sh" \
	"$SRC/tools/testing/selftests/xdev_ext_integration/verifier/run_reliable.sh" \
	"$ROOT/opt/xdev_ext/verifier/"
printf 'groups=%s\nwindow_nlb=%s\nce_sim=%s\nce_len=%s\nce_delay_us=%s\nfault=%s\nrx_ce=%s\nreliable=%s\ndepth=%s\nce_slots=%s\nremote_window=%s\n' \
	"$GROUP_COUNT" "$((GROUP_COUNT * 16))" "$CE_SIM" "$((CE_SLOTS * 8192))" \
	"$CE_DELAY_US" "$FAULT" "$RX_CE" "$RELIABLE" "$DEPTH" "$CE_SLOTS" "$REMOTE_WINDOW" \
	>"$ROOT/opt/xdev_ext/zc.env"
printf 'rel_policy=%s\n' "$REL_POLICY" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'provider_case=%s\n' "$PROVIDER_CASE" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'fault_campaign=%s\n' "$FAULT_CAMPAIGN" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'compat=%s\n' "$COMPAT" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'peer=%s\n' "$PEER" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'debug_locking=%s\ntimeout_factor=%s\ncli_timeout_ms=%s\nrx_timeout_ms=%s\n' \
    "$DEBUG_LOCKING" "$TIMEOUT_FACTOR" "$CLI_TIMEOUT_MS" "$RX_TIMEOUT_MS" >>"$ROOT/opt/xdev_ext/zc.env"
printf 'source_slba=%s\nrx_slba=%s\nce_slba=%s\n' \
    "$SOURCE_SLBA" "$RX_SLBA" "$CE_SLBA" >>"$ROOT/opt/xdev_ext/zc.env"
# --- Track S (appended): NIC-boundary fallback section switch and its tools.
NIC_FALLBACK=${XDEV_EXT_ZC_NIC_FALLBACK:-1}
[[ "$NIC_FALLBACK" == 0 || "$NIC_FALLBACK" == 1 ]]
if [[ "$FAULT" != none || "$RELIABLE" != 0 || "$RX_CE" != 0 || "$PROVIDER_CASE" != normal ]]; then NIC_FALLBACK=0; fi
printf 'nic_fallback=%s\n' "$NIC_FALLBACK" >"$ROOT/opt/xdev_ext/nic_fallback.env"
if (( NIC_FALLBACK )); then
    [[ -s "$TOOLS/socket_sink.bpf.o" ]]
    cp "$TOOLS/socket_sink.bpf.o" "$ROOT/opt/xdev_ext/"
    ln -sf /bin/busybox "$ROOT/bin/dd"
fi
# --- end track S section
GUEST_PROGRAMS=("$TOOLS/xdev_ext_mech_ctl")
if [[ -n "${FAULT_CAMPAIGN:-}" ]]; then GUEST_PROGRAMS+=("$TOOLS/fault_uid"); fi
if (( CE_SIM )) && [[ "$PROVIDER_CASE" == normal ]]; then GUEST_PROGRAMS+=("$IAA_OUT/iaa_runtime"); fi
if (( ${COMPAT:-0} )); then
    GUEST_PROGRAMS+=("$SOCKET_OUT/socket_runtime" "$PRELOAD_OUT/libio_uring_unified.so" \
        "$PRELOAD_OUT/xdev_ext_preload_mech_workload" "$PRELOAD_OUT/xdev_ext_preload_socket_smoke" \
        "$PRELOAD_OUT/xdev_ext_preload_db_workload" "$PRELOAD_OUT/xdev_ext_preload_ordinary_fork_guest")
    # glibc dlopens this runtime for pthread_cancel; ldd of the applications
    # does not list it. Resolve it with the compiler used for these tools.
    GUEST_CANCEL_RUNTIME=$(gcc-14 -print-file-name=libgcc_s.so.1)
    [[ "$GUEST_CANCEL_RUNTIME" = /* && -f "$GUEST_CANCEL_RUNTIME" ]] || {
        echo 'FAIL compatibility cancellation runtime libgcc_s.so.1 is unresolved' >&2
        exit 1
    }
    GUEST_CANCEL_RUNTIME=$(readlink -f "$GUEST_CANCEL_RUNTIME")
    GUEST_PROGRAMS+=("$GUEST_CANCEL_RUNTIME")
fi
# One ldd invocation per executable avoids multi-file "executable:" headers.
# Keep each report and propagate ldd failures before copying the merged paths.
GUEST_LIBRARIES=$EV/guest-library-paths.txt
: >"$GUEST_LIBRARIES"
if (( ${COMPAT:-0} )); then printf '%s\n' "$GUEST_CANCEL_RUNTIME" >>"$GUEST_LIBRARIES"; fi
for program in "${GUEST_PROGRAMS[@]}"; do
    dependency_report=$EV/ldd.$(basename "$program").txt
    ldd "$program" >"$dependency_report"
    awk '/=> \/|^[[:space:]]*\// { for (i=1;i<=NF;i++) if ($i ~ /^\//) print $i }' \
        "$dependency_report" >>"$GUEST_LIBRARIES"
done
sort -u "$GUEST_LIBRARIES" -o "$GUEST_LIBRARIES"
while IFS= read -r lib; do
	[[ -f "$lib" ]]
	mkdir -p "$ROOT$(dirname "$lib")"
	cp -L "$lib" "$ROOT$lib"
done <"$GUEST_LIBRARIES"
cat >"$ROOT/init" <<'GUEST'
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t bpf bpf /sys/fs/bpf
mount -t tracefs tracefs /sys/kernel/tracing
finish() {
	code=$?
	set +e
	cat /tmp/rx.log /tmp/tx.log 2>/dev/null
	cat /tmp/ce-a.log /tmp/ce-d.log 2>/dev/null
	echo "XDEV_EXT_ZC_GUEST_EXIT=$code"
	dmesg
	sync
	poweroff -f
}
trap finish EXIT
set -eu
. /opt/xdev_ext/zc.env
echo "XDEV_EXT_ZC_CE_DELAY_US=$ce_delay_us"
if [ "$provider_case" != normal ]; then
    # These cases retain unknown native owners and end this guest immediately.
    # No network setup or later module cleanup may run after quarantine.
    sh /opt/xdev_ext/provider/run-guest.sh /opt/xdev_ext/provider \
        /opt/xdev_ext/xdev_ext_ce_sim.ko "$provider_case"
    echo "XDEV_EXT_ZC_PROVIDER_CASE=PASS case=$provider_case backend=CPU-memcpy-standin"
    exit 0
fi
ip link set lo up
ip link set eth0 up
ip link set eth1 up
ip link show
# NVMe controllers may probe asynchronously. Device numbers are not roles.
resolve_nvme_roles() {
    nvme_role_sysfs=$1
    nvme_role_dev=$2
    nvme_role_peer=$3
    nvme_source= nvme_destination= nvme_peer=
    source_block= source_ng= destination_block= destination_ng= peer_block= peer_ng=
    case "$nvme_role_peer" in 0|1) ;; *) echo 'FAIL NVMe role invalid peer flag' >&2; return 1 ;; esac
    for nvme_serial_file in "$nvme_role_sysfs"/nvme*/serial; do
        [ -f "$nvme_serial_file" ] || continue
        nvme_controller=${nvme_serial_file%/serial}
        nvme_controller=${nvme_controller##*/}
        case "${nvme_controller#nvme}" in
            ''|*[!0-9]*) echo 'FAIL NVMe role invalid controller name' >&2; return 1 ;;
        esac
        nvme_serial=$(sed 's/[[:space:]]*$//' "$nvme_serial_file") || return 1
        case "$nvme_serial" in
            UBRZCSRC01)
                [ -z "$nvme_source" ] || { echo 'FAIL NVMe role duplicate source serial' >&2; return 1; }
                nvme_source=$nvme_controller ;;
            UBRZCDST01)
                [ -z "$nvme_destination" ] || { echo 'FAIL NVMe role duplicate destination serial' >&2; return 1; }
                nvme_destination=$nvme_controller ;;
            XDEVPEER01)
                [ "$nvme_role_peer" = 1 ] || { echo 'FAIL NVMe role unexpected peer serial' >&2; return 1; }
                [ -z "$nvme_peer" ] || { echo 'FAIL NVMe role duplicate peer serial' >&2; return 1; }
                nvme_peer=$nvme_controller ;;
            *) echo 'FAIL NVMe role unknown serial' >&2; return 1 ;;
        esac
    done
    [ -n "$nvme_source" ] && [ -n "$nvme_destination" ] || {
        echo 'FAIL NVMe role missing source or destination serial' >&2; return 1;
    }
    if [ "$nvme_role_peer" = 1 ] && [ -z "$nvme_peer" ]; then
        echo 'FAIL NVMe role missing peer serial' >&2; return 1
    fi
    source_block=$nvme_role_dev/${nvme_source}n1
    source_ng=$nvme_role_dev/ng${nvme_source#nvme}n1
    destination_block=$nvme_role_dev/${nvme_destination}n1
    destination_ng=$nvme_role_dev/ng${nvme_destination#nvme}n1
    [ -b "$source_block" ] && [ -c "$source_ng" ] &&
    [ -b "$destination_block" ] && [ -c "$destination_ng" ] || {
        echo 'FAIL NVMe role missing or wrong namespace node type' >&2; return 1;
    }
    if [ "$nvme_role_peer" = 1 ]; then
        peer_block=$nvme_role_dev/${nvme_peer}n1
        peer_ng=$nvme_role_dev/ng${nvme_peer#nvme}n1
        [ -b "$peer_block" ] && [ -c "$peer_ng" ] || {
            echo 'FAIL NVMe role missing or wrong peer namespace node type' >&2; return 1;
        }
    fi
    printf 'XDEV_EXT_ZC_NVME_ROLES=PASS source=%s source_ng=%s destination=%s destination_ng=%s peer=%s peer_ng=%s\n' \
        "$source_block" "$source_ng" "$destination_block" "$destination_ng" "$peer_block" "$peer_ng"
}
resolve_nvme_roles /sys/class/nvme /dev "$peer"
if [ -n "$fault_campaign" ]; then
    export source_block source_ng destination_block destination_ng nvme_source nvme_destination
    sh /opt/xdev_ext/xdev_ext_mech_zc_fault_guest.sh
    exit 0
fi
trace=/sys/kernel/tracing
echo 0 >"$trace/tracing_on"
echo >"$trace/set_ftrace_filter"
echo XDEV_EXT_ZC_TRACE_AVAILABLE_BEGIN
for fn in xsk_kernel_xmit __xsk_rcv xsk_xdev_ext_mech_tx_complete xsk_xdev_ext_mech_rx; do
	if grep -Eq "^$fn([[:space:]]|$)" "$trace/available_filter_functions"; then
		grep -E "^$fn([[:space:]]|$)" "$trace/available_filter_functions"
		echo "$fn" >>"$trace/set_ftrace_filter"
	fi
done
echo XDEV_EXT_ZC_TRACE_AVAILABLE_END
grep -q '^xsk_kernel_xmit$' "$trace/set_ftrace_filter"
echo function >"$trace/current_tracer"
echo >"$trace/trace"
echo 1 >"$trace/tracing_on"
ctl=/opt/xdev_ext/xdev_ext_mech_ctl
if [ "$reliable" = 1 ]; then
 $ctl attach --obj /opt/xdev_ext/nxp_reliable.bpf.o --map nxp_afxdp_ops --pin /sys/fs/bpf/zc-afxdp
else
 $ctl attach --obj /opt/xdev_ext/nxp_mech.bpf.o --map nxp_afxdp_ops \
  --pin /sys/fs/bpf/zc-afxdp --set nxp_session=270019
fi
$ctl attach --obj /opt/xdev_ext/nxp_mech.bpf.o --map nxp_nvme_ops \
	--pin /sys/fs/bpf/zc-nvme --set nvme_mode=0
if [ "$lifecycle" = 1 ]; then
    sh /opt/xdev_ext/xdev_ext_mech_lifecycle_guest.sh "$ctl" \
        "$source_ng" "$source_block" "$destination_ng" "$destination_block" \
        "$source_slba" "$rx_slba" "$groups" "$depth" /opt/xdev_ext/cpu_plan.bpf.o
    exit 0
fi
if [ "$peer" = 1 ]; then
    XDEV_EXT_PEER_GUEST=1 sh /opt/xdev_ext/peer_guest/run-guest.sh \
        "$source_block" "$source_ng" "$peer_block" "$peer_ng" "$source_slba"
    echo 'XDEV_EXT_PEER_SOFTWARE_GUEST=PASS native=NVMe-SGL memory=host-RAM-standin gpu=none'
fi
if [ "$ce_sim" = 1 ]; then
	ce_check() {
		grep -Fxq "XDEV_EXT_MECH_CE_SIM=PASS chain=$2" "$1"
		grep -Fxq 'XDEV_EXT_MECH_NOTIFY mode=terminal eventfd_reads=1 stats_reads=1' "$1"
		grep -Eq "^XDEV_EXT_MECH_STATS .* last_err=0 batches_done=$groups batches_abort=0 rejects=0 .* sequestered=0 timeouts=0 inflight=0 native_publish=0 protocol_err=0 " "$1"
	}
	# fail_mode=none is enum 0; the stand-in copies on the CPU workqueue.
    sh /opt/xdev_ext/provider/run-guest.sh /opt/xdev_ext/provider /opt/xdev_ext/xdev_ext_ce_sim.ko
    echo XDEV_EXT_DMA_DYNAMIC_PROVIDER=PASS
    sh /opt/xdev_ext/iaa/run-guest.sh /opt/xdev_ext/iaa /opt/xdev_ext/provider/xdev_ext_dma_provider_sim.ko
    echo 'XDEV_EXT_IAA_SOFTWARE=PASS cases=5 groups=257 depth=8 backend=deflate-generic dma_backend=CPU-memcpy-standin'
    if [ "$compat" = 1 ]; then
        sh /opt/xdev_ext/socket_guest/run-guest.sh /opt/xdev_ext/socket_guest \
            /opt/xdev_ext/xdev_ext_ce_sim.ko /opt/xdev_ext/socket_sink.bpf.o "$source_slba" "$source_ng" "$source_block"
        insmod /opt/xdev_ext/xdev_ext_ce_sim.ko fail_mode=none delay_us="$ce_delay_us"
        $ctl attach --obj /opt/xdev_ext/socket_sink.bpf.o --map socket_sink_ops --pin /sys/fs/bpf/compat-socket
        $ctl attach --obj /opt/xdev_ext/ce_plan.bpf.o --map ce_plan_ops --pin /sys/fs/bpf/compat-ce
        mkdir -p /tmp/compatfs
        mount -t ext4 /dev/vda /tmp/compatfs
        XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE=/dev/xdev_ext_ce_sim \
        XDEV_EXT_PRELOAD_SOCKET_CE_ADDR=0 XDEV_EXT_PRELOAD_SOCKET_CE_LEN=65536 \
            sh /opt/xdev_ext/preload/xdev_ext_preload_mech_guest.sh \
            /opt/xdev_ext/preload /tmp/preload-logs /tmp/compatfs/workload
        umount /tmp/compatfs
        $ctl detach --pin /sys/fs/bpf/compat-ce
        $ctl detach --pin /sys/fs/bpf/compat-socket
        for i in $(/bin/busybox seq 1 200); do
            [ "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0 ] && break
            sleep 0.05
        done
        test "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0
        rmmod xdev_ext_ce_sim
        echo 'XDEV_EXT_COMPAT_GUEST=PASS ce_module_unloaded=1'
    fi
	insmod /opt/xdev_ext/xdev_ext_ce_sim.ko fail_mode=none delay_us="$ce_delay_us"
	test -c /dev/xdev_ext_ce_sim
	test "$(cat /sys/module/xdev_ext_ce_sim/parameters/fail_mode)" = none
	test "$(cat /sys/module/xdev_ext_ce_sim/parameters/delay_us)" = "$ce_delay_us"
	echo 'XDEV_EXT_ZC_CE_BACKEND=CPU-memcpy-standin gpu=none performance_claim=none'
	$ctl attach --obj /opt/xdev_ext/ce_plan.bpf.o --map ce_plan_ops --pin /sys/fs/bpf/zc-ce
	$ctl ce-chain --chain a --ce-dev /dev/xdev_ext_ce_sim --ce-len "$ce_len" \
		--src-ng "$source_ng" --slba "$source_slba" --nlb "$window_nlb" \
		--dst-ng "$destination_ng" --dst-slba "$ce_slba" --dst-nlb "$window_nlb" \
		--groups "$groups" --depth "$depth" --group-bytes 8192 \
		--timeout-ms "$cli_timeout_ms" >/tmp/ce-a.log 2>&1
	ce_check /tmp/ce-a.log a
	$ctl ce-chain --chain d --ce-dev /dev/xdev_ext_ce_sim --ce-len "$ce_len" \
		--groups "$groups" --depth "$depth" --group-bytes 8192 \
		--timeout-ms "$cli_timeout_ms" >/tmp/ce-d.log 2>&1
	ce_check /tmp/ce-d.log d
fi
# The reverse chain owns a distinct simulated device window.
if [ "$rx_ce" = 1 ]; then
	set -- --ce-dev /dev/xdev_ext_ce_sim --ce-va 2097152 --ce-len "$ce_len"
else
	set --
fi
if [ "$reliable" = 1 ]; then set -- "$@" --reliable --remote-window "$remote_window"; fi
# Each policy class uses the same CREATE path on both peers.
case "$rel_policy" in
 default) ;;
 window1) set -- "$@" --rel-window 1 --rel-initial-credit 1 ;;
 window8) set -- "$@" --rel-window 8 --rel-initial-credit 8 ;;
 every-n) set -- "$@" --rel-ack-rule every-n --rel-ack-every 4 --rel-ack-delay-us 1000 ;;
 delayed) set -- "$@" --rel-ack-rule delayed --rel-ack-delay-us 1000 ;;
 exponential) set -- "$@" --rel-rto-us 10000 --rel-rto-max-us 80000 --rel-backoff exponential ;;
 oldest|round-robin) set -- "$@" --rel-resend-order "$rel_policy" ;;
esac
rx_timeout=$rx_timeout_ms
rx_started=$(date +%s)
$ctl nic-nvme "$@" --ifname eth1 --dst-ng "$destination_ng" --slba "$rx_slba" --nlb "$window_nlb" \
	--peer-mac 02:00:00:00:00:01 --local-ip 192.0.2.2 --peer-ip 192.0.2.1 \
	--local-port 12345 --peer-port 54321 --groups "$groups" --depth "$depth" --group-bytes 8192 \
	--timeout-ms "$rx_timeout" >/tmp/rx.log 2>&1 &
rx=$!
ready=0
for i in $(/bin/busybox seq 1 "$((200 * timeout_factor))"); do
	if grep -q 'XDEV_EXT_MECH_READY mode=nic-nvme .* xsk=zc' /tmp/rx.log; then ready=1; break; fi
	sleep 0.05
done
test "$ready" = 1
# Chain b has the same native AF_XDP TX stage as the default sender.
if [ "$ce_sim" = 1 ]; then
	set -- ce-chain --chain b --ce-dev /dev/xdev_ext_ce_sim --ce-len "$ce_len"
else
	set -- nvme-nic
fi
if [ "$reliable" = 1 ]; then set -- "$@" --reliable --remote-window "$remote_window"; fi
# Each policy class uses the same CREATE path on both peers.
case "$rel_policy" in
 default) ;;
 window1) set -- "$@" --rel-window 1 --rel-initial-credit 1 ;;
 window8) set -- "$@" --rel-window 8 --rel-initial-credit 8 ;;
 every-n) set -- "$@" --rel-ack-rule every-n --rel-ack-every 4 --rel-ack-delay-us 1000 ;;
 delayed) set -- "$@" --rel-ack-rule delayed --rel-ack-delay-us 1000 ;;
 exponential) set -- "$@" --rel-rto-us 10000 --rel-rto-max-us 80000 --rel-backoff exponential ;;
 oldest|round-robin) set -- "$@" --rel-resend-order "$rel_policy" ;;
esac
tx_started=$(date +%s)
set +e
$ctl "$@" --ifname eth0 --src-ng "$source_ng" --slba "$source_slba" --nlb "$window_nlb" \
	--peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 \
	--local-port 54321 --peer-port 12345 --groups "$groups" --depth "$depth" --group-bytes 8192 \
	--timeout-ms "$cli_timeout_ms" >/tmp/tx.log 2>&1
tx_exit=$?
wait "$rx"
rx_exit=$?
set -e
rx_elapsed=$(( ($(date +%s) - rx_started) * 1000 ))
role_evidence() {
 role=$1
 file=$2
 # Locate the last snapshot, then emit in original file order. Keep every
 # other final marker so duplicates or bad ordering remain validator errors.
 # The complete, unchanged raw CLI logs are printed by the guest exit trap.
 /bin/busybox awk -v role="$role" '
  NR == FNR { if (/^XDEV_EXT_MECH_STATS /) last = FNR; next }
  /^XDEV_EXT_MECH_STATS / { if (FNR != last) next }
  /^XDEV_EXT_MECH_(STATS|TRANSPORT|FINALIZE|REMOTE_OUTCOME) / {
   sub(/^XDEV_EXT_MECH_/, "XDEV_EXT_ZC_" role "_"); print
  }
 ' "$file" "$file"
}
role_evidence RX /tmp/rx.log
role_evidence TX /tmp/tx.log
tx_elapsed=$(( ($(date +%s) - tx_started) * 1000 ))
if [ "$fault" = reliable-budget-unknown ]; then
 test "$tx_exit" != 0
 grep -Eq '^XDEV_EXT_MECH_REMOTE_OUTCOME outcome=UNKNOWN cause=remote-ack-unconfirmed .*durable=unclaimed$' /tmp/tx.log
 test "$rx_exit" != 0
 tx_outcome=unknown
 rx_outcome=incomplete-remote-unknown
else
 test "$tx_exit" = 0
 tx_outcome=success
fi
if [ "$fault" = drop-middle ]; then
	test "$rx_exit" != 0
	rx_outcome=fail-stop
elif [ "$fault" != reliable-budget-unknown ]; then
	test "$rx_exit" = 0
	rx_outcome=success
fi
echo "XDEV_EXT_ZC_TX_RESULT outcome=$tx_outcome exit=$tx_exit elapsed_ms=$tx_elapsed timeout_ms=$cli_timeout_ms"
rx_result_timeout=$rx_timeout
[ "$fault" != reliable-budget-unknown ] || rx_result_timeout=$((rx_timeout + 10000 * timeout_factor))
echo "XDEV_EXT_ZC_RX_RESULT outcome=$rx_outcome exit=$rx_exit elapsed_ms=$rx_elapsed timeout_ms=$rx_result_timeout"
if [ "$ce_sim" = 1 ]; then
	if [ "$fault" != reliable-budget-unknown ]; then ce_check /tmp/tx.log b; fi
	if [ "$fault" != drop-middle ] && [ "$fault" != reliable-budget-unknown ]; then
		if [ "$rx_ce" = 1 ]; then
			grep -Eq '^XDEV_EXT_MECH_NIC_CE_NVME_E2E=PASS ' /tmp/rx.log
		else
			grep -Eq '^XDEV_EXT_MECH_NIC_NVME_E2E=PASS .* errors=0 sequestered=0 inflight=0$' /tmp/rx.log
		fi
	fi
	ce_stats='XDEV_EXT_ZC_CE_SIM_STATS'
	for name in accepted completed pending peak_pending submit_before_first_complete; do
		ce_stats="$ce_stats $name=$(cat /sys/module/xdev_ext_ce_sim/parameters/$name)"
	done
	echo "$ce_stats delay_us=$ce_delay_us"
	$ctl detach --pin /sys/fs/bpf/zc-ce
	# Session teardown may finish asynchronously after ctl closes its ring.
    if [ "$fault" = reliable-budget-unknown ]; then
        # An unconfirmed remote outcome may quarantine protocol-owned pages.
        # Do not force module removal or require unknown resources to be freed.
        echo "XDEV_EXT_ZC_UNKNOWN_OWNERS ce_refs=$(cat /sys/module/xdev_ext_ce_sim/refcnt) action=retain-until-guest-exit"
    else
	for i in $(/bin/busybox seq 1 "$((200 * timeout_factor))"); do
		[ "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0 ] && break
		sleep 0.05
	done
	test "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0
	rmmod xdev_ext_ce_sim
	echo 'XDEV_EXT_ZC_CE_CHAINS=PASS chains=a,b,d backend=CPU-memcpy-standin'
    fi
fi
echo 0 >"$trace/tracing_on"
echo XDEV_EXT_ZC_TRACE_BEGIN
cat "$trace/set_ftrace_filter" "$trace/trace"
echo XDEV_EXT_ZC_TRACE_END
copy_calls=$(grep -cE ' (xsk_kernel_xmit|__xsk_rcv) <-' "$trace/trace" || true)
zc_calls=$(grep -cE ' (xsk_xdev_ext_mech_tx_complete|xsk_xdev_ext_mech_rx) <-' "$trace/trace" || true)
test "$copy_calls" = 0
test "$zc_calls" -gt 0
echo "XDEV_EXT_ZC_TRACE_CONTROL=PASS calls=$zc_calls"
echo "XDEV_EXT_ZC_COPY_FALLBACK=PASS calls=$copy_calls"
# --- Track S (appended): NIC-boundary copy fallback and copy-mode accounting.
# Correctness/teardown validation only; no timing is recorded or compared.
# Runs after the zero-copy trace check so its copy-mode calls cannot touch it.
nic_fallback=0
[ ! -f /opt/xdev_ext/nic_fallback.env ] || . /opt/xdev_ext/nic_fallback.env
if [ "$nic_fallback" = 1 ] && [ "$fault" = none ] && [ "$reliable" = 0 ] && [ "$rx_ce" = 0 ]; then
    nicfb_log() { /bin/busybox sed "s/^/XDEV_EXT_ZC_NICFB_LOG $1 /" "$2"; }
    nicfb_frames=$(/bin/busybox sed -n 's/^XDEV_EXT_MECH_READY mode=nic-nvme .* frames=\([0-9]*\) .*/\1/p' /tmp/rx.log)
    [ -n "$nicfb_frames" ]
    nicfb_bytes=$((groups * 8192))
    # Main AF_XDP zero-copy run: zero-copy counters only.
    grep -Eq "^XDEV_EXT_MECH_NIC_ACCOUNTING session=[0-9]+ path=zc nic_copy_ops=0 nic_copy_bytes=0 nic_zc_ops=$((groups * nicfb_frames)) nic_zc_bytes=$nicfb_bytes\$" /tmp/rx.log
    grep -Eq "^XDEV_EXT_MECH_NIC_ACCOUNTING session=[0-9]+ path=zc nic_copy_ops=0 nic_copy_bytes=0 nic_zc_ops=$((groups * nicfb_frames)) nic_zc_bytes=$nicfb_bytes\$" /tmp/tx.log
    nicfb_clear() {
        dd if=/dev/zero of="$destination_block" bs=512 seek="$rx_slba" count="$window_nlb" conv=fsync 2>/dev/null
        sync; echo 3 >/proc/sys/vm/drop_caches
        dd if="$destination_block" bs=512 skip="$rx_slba" count="$window_nlb" of=/tmp/nicfb-dst.bin 2>/dev/null
        ! cmp -s /tmp/nicfb-src.bin /tmp/nicfb-dst.bin
    }
    nicfb_compare() {
        sync; echo 3 >/proc/sys/vm/drop_caches
        dd if="$destination_block" bs=512 skip="$rx_slba" count="$window_nlb" of=/tmp/nicfb-dst.bin 2>/dev/null
        cmp /tmp/nicfb-src.bin /tmp/nicfb-dst.bin
    }
    nicfb_ready() {
        for i in $(/bin/busybox seq 1 "$((200 * timeout_factor))"); do
            if grep -Eq "^XDEV_EXT_MECH_READY mode=nic-nvme .* xsk=$2( |\$)" "$1"; then return 0; fi
            sleep 0.05
        done
        return 1
    }
    dd if="$source_block" bs=512 skip="$source_slba" count="$window_nlb" of=/tmp/nicfb-src.bin 2>/dev/null
    echo 67108864 >/proc/sys/net/core/rmem_max
    echo 67108864 >/proc/sys/net/core/wmem_max
    $ctl attach --obj /opt/xdev_ext/socket_sink.bpf.o --map socket_sink_ops --pin /sys/fs/bpf/nicfb-socket
    # 1. Forced socket adapter both ways: NVMe READ -> UDP send ... UDP receive -> NVMe WRITE.
    nicfb_clear
    $ctl nic-nvme --nic-fallback force --ifname eth1 --dst-ng "$destination_ng" --slba "$rx_slba" --nlb "$window_nlb" \
        --peer-mac 02:00:00:00:00:01 --local-ip 127.0.0.1 --peer-ip 127.0.0.1 \
        --local-port 23456 --peer-port 23457 --groups "$groups" --depth "$depth" --group-bytes 8192 \
        --timeout-ms "$rx_timeout_ms" >/tmp/nicfb-socket-rx.log 2>&1 &
    nicfb_rx=$!
    nicfb_ready /tmp/nicfb-socket-rx.log socket
    set +e
    $ctl nvme-nic --nic-fallback force --ifname eth0 --src-ng "$source_ng" --slba "$source_slba" --nlb "$window_nlb" \
        --peer-mac 02:00:00:00:00:02 --local-ip 127.0.0.1 --peer-ip 127.0.0.1 \
        --local-port 23457 --peer-port 23456 --groups "$groups" --depth "$depth" --group-bytes 8192 \
        --timeout-ms "$cli_timeout_ms" >/tmp/nicfb-socket-tx.log 2>&1
    nicfb_tx_exit=$?
    wait "$nicfb_rx"
    nicfb_rx_exit=$?
    set -e
    nicfb_log socket-rx /tmp/nicfb-socket-rx.log
    nicfb_log socket-tx /tmp/nicfb-socket-tx.log
    test "$nicfb_tx_exit" = 0
    test "$nicfb_rx_exit" = 0
    grep -Eq '^XDEV_EXT_MECH_READY mode=source .* xsk=socket( |$)' /tmp/nicfb-socket-tx.log
    grep -Eq '^XDEV_EXT_MECH_NIC_NVME_E2E=PASS .* errors=0 sequestered=0 inflight=0$' /tmp/nicfb-socket-rx.log
    for log in /tmp/nicfb-socket-rx.log /tmp/nicfb-socket-tx.log; do
        grep -Eq "^XDEV_EXT_MECH_NIC_ACCOUNTING session=[0-9]+ path=socket nic_copy_ops=$((groups * nicfb_frames)) nic_copy_bytes=$nicfb_bytes nic_zc_ops=0 nic_zc_bytes=0\$" "$log"
    done
    nicfb_compare
    # 2. AF_XDP sockets opened without zero-copy: copy-mode counters only.
    nicfb_clear
    $ctl nic-nvme --copy --ifname eth1 --dst-ng "$destination_ng" --slba "$rx_slba" --nlb "$window_nlb" \
        --peer-mac 02:00:00:00:00:01 --local-ip 192.0.2.2 --peer-ip 192.0.2.1 \
        --local-port 12345 --peer-port 54321 --groups "$groups" --depth "$depth" --group-bytes 8192 \
        --timeout-ms "$rx_timeout_ms" >/tmp/nicfb-copy-rx.log 2>&1 &
    nicfb_rx=$!
    nicfb_ready /tmp/nicfb-copy-rx.log copy
    set +e
    $ctl nvme-nic --copy --ifname eth0 --src-ng "$source_ng" --slba "$source_slba" --nlb "$window_nlb" \
        --peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 \
        --local-port 54321 --peer-port 12345 --groups "$groups" --depth "$depth" --group-bytes 8192 \
        --timeout-ms "$cli_timeout_ms" >/tmp/nicfb-copy-tx.log 2>&1
    nicfb_tx_exit=$?
    wait "$nicfb_rx"
    nicfb_rx_exit=$?
    set -e
    nicfb_log copy-rx /tmp/nicfb-copy-rx.log
    nicfb_log copy-tx /tmp/nicfb-copy-tx.log
    test "$nicfb_tx_exit" = 0
    test "$nicfb_rx_exit" = 0
    grep -Eq '^XDEV_EXT_MECH_READY mode=source .* xsk=copy( |$)' /tmp/nicfb-copy-tx.log
    grep -Eq '^XDEV_EXT_MECH_NIC_NVME_E2E=PASS .* errors=0 sequestered=0 inflight=0$' /tmp/nicfb-copy-rx.log
    for log in /tmp/nicfb-copy-rx.log /tmp/nicfb-copy-tx.log; do
        grep -Eq "^XDEV_EXT_MECH_NIC_ACCOUNTING session=[0-9]+ path=copy nic_copy_ops=$((groups * nicfb_frames)) nic_copy_bytes=$nicfb_bytes nic_zc_ops=0 nic_zc_bytes=0\$" "$log"
    done
    nicfb_compare
    # 3/4. Actual AUTO ZC refusal on existing loopback, with a single socket
    # boundary and the unchanged AF_XDP peer on the existing QEMU NIC pair.
    # Only the socket side owns an IP address, so socket TX traverses eth0
    # instead of taking the local route and bypassing the AF_XDP RX hook.
    nicfb_lo_mtu=$(cat /sys/class/net/lo/mtu)
    ip link set lo mtu 1500
    for nicfb_mixed in rx tx; do
        nicfb_clear
        if [ "$nicfb_mixed" = rx ]; then
            ip addr add 192.0.2.2/24 dev eth1
            nicfb_rx_if=lo; nicfb_rx_policy=auto; nicfb_rx_path=socket
            nicfb_tx_if=eth0; nicfb_tx_policy=off; nicfb_tx_path=zc
        else
            ip addr add 192.0.2.1/24 dev eth0
            ip neigh replace 192.0.2.2 lladdr 02:00:00:00:00:02 nud permanent dev eth0
            nicfb_rx_if=eth1; nicfb_rx_policy=off; nicfb_rx_path=zc
            nicfb_tx_if=lo; nicfb_tx_policy=auto; nicfb_tx_path=socket
        fi
        $ctl nic-nvme --nic-fallback "$nicfb_rx_policy" --ifname "$nicfb_rx_if" \
            --dst-ng "$destination_ng" --slba "$rx_slba" --nlb "$window_nlb" \
            --peer-mac 02:00:00:00:00:01 --local-ip 192.0.2.2 --peer-ip 192.0.2.1 \
            --local-port 12345 --peer-port 54321 --groups "$groups" --depth "$depth" \
            --group-bytes 8192 --timeout-ms "$rx_timeout_ms" >/tmp/nicfb-mixed-rx.log 2>&1 &
        nicfb_rx=$!
        nicfb_ready /tmp/nicfb-mixed-rx.log "$nicfb_rx_path"
        set +e
        $ctl nvme-nic --nic-fallback "$nicfb_tx_policy" --ifname "$nicfb_tx_if" \
            --src-ng "$source_ng" --slba "$source_slba" --nlb "$window_nlb" \
            --peer-mac 02:00:00:00:00:02 --local-ip 192.0.2.1 --peer-ip 192.0.2.2 \
            --local-port 54321 --peer-port 12345 --groups "$groups" --depth "$depth" \
            --group-bytes 8192 --timeout-ms "$cli_timeout_ms" >/tmp/nicfb-mixed-tx.log 2>&1
        nicfb_tx_exit=$?
        wait "$nicfb_rx"
        nicfb_rx_exit=$?
        set -e
        nicfb_log "auto-$nicfb_mixed-rx" /tmp/nicfb-mixed-rx.log
        nicfb_log "auto-$nicfb_mixed-tx" /tmp/nicfb-mixed-tx.log
        test "$nicfb_tx_exit" = 0
        test "$nicfb_rx_exit" = 0
        grep -Eq "^XDEV_EXT_MECH_READY mode=source .* xsk=$nicfb_tx_path( |\$)" /tmp/nicfb-mixed-tx.log
        grep -Eq '^XDEV_EXT_MECH_NIC_NVME_E2E=PASS .* errors=0 sequestered=0 inflight=0$' /tmp/nicfb-mixed-rx.log
        grep -Eq "^XDEV_EXT_MECH_NIC_ACCOUNTING session=[0-9]+ path=socket nic_copy_ops=$((groups * nicfb_frames)) nic_copy_bytes=$nicfb_bytes nic_zc_ops=0 nic_zc_bytes=0\$" "/tmp/nicfb-mixed-$nicfb_mixed.log"
        nicfb_compare
        if [ "$nicfb_mixed" = rx ]; then
            ip addr del 192.0.2.2/24 dev eth1
        else
            ip neigh del 192.0.2.2 dev eth0
            ip addr del 192.0.2.1/24 dev eth0
        fi
        echo "XDEV_EXT_ZC_NIC_AUTO_INTEROP=PASS socket_side=$nicfb_mixed groups=$groups"
    done
    ip link set lo mtu "$nicfb_lo_mtu"
    $ctl detach --pin /sys/fs/bpf/nicfb-socket
    echo "XDEV_EXT_ZC_NIC_FALLBACK=PASS socket_groups=$groups copy_groups=$groups zc_copy_ops=0"
fi
# --- end track S section
$ctl detach --pin /sys/fs/bpf/zc-afxdp
$ctl detach --pin /sys/fs/bpf/zc-nvme
verifier_status=0
LOG_DIR=/tmp/verifier-evidence sh /opt/xdev_ext/verifier/run.sh || verifier_status=$?
LOG_DIR=/tmp/verifier-state-evidence sh /opt/xdev_ext/verifier/run_state.sh || verifier_status=$?
LOG_DIR=/tmp/verifier-abi-evidence sh /opt/xdev_ext/verifier/run_abi.sh || verifier_status=$?
LOG_DIR=/tmp/verifier-reliable-evidence sh /opt/xdev_ext/verifier/run_reliable.sh || verifier_status=$?
echo XDEV_EXT_ZC_VERIFIER_LOG_BEGIN
cat /tmp/verifier-evidence/*.log /tmp/verifier-state-evidence/*.log /tmp/verifier-abi-evidence/*.log /tmp/verifier-reliable-evidence/*.log
echo XDEV_EXT_ZC_VERIFIER_LOG_END
test "$verifier_status" = 0
if [ "$fault" = reliable-budget-unknown ]; then
    echo XDEV_EXT_ZC_UNKNOWN=PASS
elif [ "$fault" = drop-middle ]; then
	echo XDEV_EXT_ZC_FAIL_STOP=PASS
else
	echo XDEV_EXT_ZC_CHAIN=PASS
fi
GUEST
chmod 0700 "$ROOT/init"
(cd "$ROOT" && find . -print0 | cpio --null -o -H newc 2>"$EV/cpio.log" | gzip -1) >"$SCRATCH/initramfs.cpio.gz"
python3 - "$SCRATCH" "$GROUP_COUNT" "$CE_SIM" "$FAULT" "$SRC" "${FAULT_CAMPAIGN:-}" "${LIFECYCLE:-0}" <<'PY'
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(pathlib.Path(sys.argv[5])/'tools/testing/selftests/xdev_ext_integration'))
from xdev_ext_mech_zc_validate import image_layout
if sys.argv[6]:
    from xdev_ext_mech_zc_fault_validate import make_images
    make_images(p, int(sys.argv[2]))
    (p/'evidence/source-before.sha256').write_text(hashlib.sha256((p/'source-before.raw').read_bytes()).hexdigest()+'\n')
    raise SystemExit(0)
layout = image_layout(int(sys.argv[2]))
source_offset, rx_offset, ce_offset = (layout[key] * 512 for key in
                                       ('source_slba', 'rx_slba', 'ce_slba'))
lifecycle = sys.argv[7] == '1'
image_bytes = max(layout['image_bytes'], rx_offset + (4 * int(sys.argv[2]) + 1) * 8192) if lifecycle else layout['image_bytes']
src = bytearray(image_bytes)
data = hashlib.shake_256(b'XDEV_EXT strict SGL and AF_XDP ZC 20261019').digest(int(sys.argv[2]) * 8192)
src[source_offset:source_offset+len(data)] = data
(p/'source.raw').write_bytes(src)
(p/'source-before.raw').write_bytes(src)
(p/'destination.raw').write_bytes(bytes(len(src)))
(p/'destination-before.raw').write_bytes(bytes(len(src)))
expected = bytearray(len(src))
rx_bytes = 8192 if sys.argv[4] == 'drop-middle' else len(data)
expected[rx_offset:rx_offset+rx_bytes] = data[:rx_bytes]
if sys.argv[3] == '1':
    expected[ce_offset:ce_offset+len(data)] = data
if lifecycle:
    # Independent bit-at-a-time Castagnoli oracle; each frame seals its own tail.
    def seal(block):
        result = bytearray(block)
        for group in range(0, len(block), 8192):
            for off in range(group, group + 8192, 1432):
                end = min(off + 1432, group + 8192)
                crc = 0xffffffff
                for byte in block[off:end-4]:
                    crc ^= byte
                    for _ in range(8):
                        crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
                result[end-4:end] = (crc ^ 0xffffffff).to_bytes(4, 'little')
        return result
    expected = bytearray(len(src))
    for index, payload in enumerate((data, data, seal(data), seal(data))):
        off = rx_offset + index * len(data)
        expected[off:off+len(data)] = payload
(p/'expected.raw').write_bytes(expected)
(p/'evidence/source-before.sha256').write_text(hashlib.sha256(src).hexdigest()+'\n')
PY
# Reliable campaigns bound outstanding groups by depth; v2 retains its
# finite fail-stop experiment. Extra virtual RX capacity is test plumbing.
# This QEMU requires default TX=256.
wire_args=(-netdev hubport,id=wire0,hubid=0 -netdev hubport,id=wire1,hubid=0)
proxy_pid=''
cleanup_proxy() {
	if [[ -n "$proxy_pid" ]]; then
		kill -TERM "$proxy_pid" 2>/dev/null || true
		wait "$proxy_pid" || true
		proxy_pid=''
	fi
}
trap cleanup_proxy EXIT
if [[ "$FAULT" != none ]]; then
	"$QEMU" --version >"$EV/qemu-version.txt"
	# QEMU help is retained as evidence of the target binary's stream backend.
	"$QEMU" -netdev help >"$EV/qemu-netdev-help.txt" 2>&1
	grep -Eq '(^|[[:space:]])stream([[:space:]]|$)' "$EV/qemu-netdev-help.txt"
	python3 "$SRC/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py" \
		--left "$SCRATCH/wire0.sock" --right "$SCRATCH/wire1.sock" \
		--fault "$FAULT" --stats "$EV/wire-stats.json" >"$EV/wire.log" 2>&1 &
	proxy_pid=$!
	for ((i=0; i<100; i++)); do
		[[ -S "$SCRATCH/wire0.sock" && -S "$SCRATCH/wire1.sock" ]] && break
		kill -0 "$proxy_pid"
		sleep 0.05
	done
	[[ -S "$SCRATCH/wire0.sock" && -S "$SCRATCH/wire1.sock" ]]
	wire_args=(-netdev "stream,id=wire0,server=off,addr.type=unix,addr.path=$SCRATCH/wire0.sock"
		-netdev "stream,id=wire1,server=off,addr.type=unix,addr.path=$SCRATCH/wire1.sock")
fi
destination_drive="file=$SCRATCH/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"
if (( DESTINATION_READONLY )); then destination_drive+=,readonly=on; fi
args=(-machine q35,accel=kvm -cpu host -smp 4 -m 4096 -nographic -no-reboot
	-kernel "$BUILD/arch/x86/boot/bzImage" -initrd "$SCRATCH/initramfs.cpio.gz"
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1'
	-nic none "${wire_args[@]}"
	-device virtio-net-pci,netdev=wire0,mac=02:00:00:00:00:01,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-device virtio-net-pci,netdev=wire1,mac=02:00:00:00:00:02,iommu_platform=on,disable-legacy=on,rx_queue_size=1024
	-drive "file=$SCRATCH/source.raw,if=none,id=src,format=raw,cache=none,aio=threads"
	-device nvme,drive=src,serial=UBRZCSRC01
	-drive "$destination_drive"
	-device nvme,drive=dst,serial=UBRZCDST01)
if (( COMPAT )); then
    args+=(-drive "file=$SCRATCH/compat.raw,if=none,id=compat,format=raw,cache=none,aio=threads"
        -device virtio-blk-pci,drive=compat)
fi
if (( PEER )); then
    args+=(-drive "file=$SCRATCH/peer.raw,if=none,id=peer,format=raw,cache=none,aio=threads"
        -device nvme,drive=peer,serial=XDEVPEER01)
fi
printf '%q ' "$QEMU" "${args[@]}" >"$EV/qemu.command"
printf '\n' >>"$EV/qemu.command"
sha256sum "$BUILD/arch/x86/boot/bzImage" "$BUILD/vmlinux" "$TOOLS/xdev_ext_mech_ctl" \
	"$TOOLS/nxp_mech.bpf.o" "$SCRATCH/initramfs.cpio.gz" >"$EV/artifacts.sha256"
if [[ -n "$FAULT_CAMPAIGN" ]]; then
    sha256sum "$TOOLS/fault_uid" "$ROOT/opt/xdev_ext/xdev_ext_mech_zc_fault_guest.sh" >>"$EV/artifacts.sha256"
fi
if (( CE_SIM )); then
	sha256sum "$CE_SIM_OUT/xdev_ext_ce_sim.ko" "$TOOLS/ce_plan.bpf.o" >>"$EV/artifacts.sha256"
    if [[ "$PROVIDER_CASE" == normal ]]; then
        sha256sum "$IAA_OUT/iaa_runtime" "$IAA_OUT/iaa_pair.bpf.o" >>"$EV/artifacts.sha256"
    fi
fi
if (( COMPAT )); then
    sha256sum "$SOCKET_OUT/socket_runtime" "$SOCKET_OUT/ce_observe.bpf.o" \
        "$PRELOAD_OUT/libio_uring_unified.so" "$PRELOAD_OUT/xdev_ext_preload_mech_workload" \
        "$PRELOAD_OUT/xdev_ext_preload_socket_smoke" "$PRELOAD_OUT/xdev_ext_preload_db_workload" \
        "$PRELOAD_OUT/xdev_ext_preload_ordinary_fork_guest" \
        >>"$EV/artifacts.sha256"
fi
if (( PEER )); then
    sha256sum "$PEER_OUT/xdev_ext_peer_sw.ko" "$PEER_OUT/peer_nvme_e2e" >>"$EV/artifacts.sha256"
fi
cat /proc/modules >"$EV/host-modules-before.txt"
ip -details link show >"$EV/host-links-before.txt"
set +e
timeout --signal=TERM --kill-after=10 "$QEMU_TIMEOUT_SECONDS" "$QEMU" "${args[@]}" >"$EV/guest.raw.log" 2>&1
rc=$?
set -e
cleanup_proxy
tr -d '\r' <"$EV/guest.raw.log" >"$EV/guest.log"
if [[ "$FAULT" != none ]]; then
	cat "$EV/wire.log" >>"$EV/guest.log"
	python3 - "$EV/wire-stats.json" <<'PYWIRE'
import json, pathlib, sys
stats = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert not stats['errors'], stats
PYWIRE
elif [[ -z "$FAULT_CAMPAIGN" ]]; then
	echo 'XDEV_EXT_ZC_FAULT_COUNTS mode=none matched=0 dropped=0 duplicated=0 session=270019 generation=2 index=2 count=6' >>"$EV/guest.log"
fi
printf '%s\n' "$rc" >"$EV/qemu.exit"
cat /proc/modules >"$EV/host-modules-after.txt"
ip -details link show >"$EV/host-links-after.txt"
python3 "$DEBUG_HELPER" console "$EV/guest.log" "$EV/debug-locking.json" "$DEBUG_LOCKING" \
    | tee "$EV/debug-locking-result.txt"
[[ $rc == 0 ]]
if [[ -n "$FAULT_CAMPAIGN" ]]; then
    # The matrix owns the full-image/pin/session oracle and foreign-QEMU
    # snapshots. A clean boot alone is never reported as a campaign PASS.
    grep -Fxq XDEV_EXT_ZC_FAULT_GUEST_EXIT=0 "$EV/guest.log"
    echo "XDEV_EXT_ZC_FAULT_BOOT=COMPLETE campaign=$FAULT_CAMPAIGN validation=matrix-required" | tee "$EV/result.txt"
    exit 0
fi
if (( LIFECYCLE )); then
    grep -Fxq XDEV_EXT_ZC_GUEST_EXIT=0 "$EV/guest.log"
    grep -Fxq XDEV_EXT_MECH_LIFECYCLE_GUEST=PASS "$EV/guest.log"
    cmp "$SCRATCH/source-before.raw" "$SCRATCH/source.raw"
    cmp "$SCRATCH/expected.raw" "$SCRATCH/destination.raw"
    sha256sum "$SCRATCH/source.raw" "$SCRATCH/destination.raw" >"$EV/data.sha256"
    echo 'XDEV_EXT_LIFECYCLE_KVM=PASS source=unchanged destination=whole-image' | tee "$EV/result.txt"
    exit 0
fi
if (( COMPAT )); then
    python3 "$SRC/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_compat_validate.py" \
        "$SRC" "$EV/guest.log" "$EV/preload-logs"
fi
if (( PEER )); then
    python3 - "$SRC" "$EV/guest.log" <<'PYPEER'
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1])/'tools/testing/selftests/xdev_ext_integration'))
from xdev_ext_mech_zc_compat_validate import validate_peer
validate_peer(pathlib.Path(sys.argv[2]).read_text())
PYPEER
fi
if [[ "$PROVIDER_CASE" != normal ]]; then
    python3 - "$SRC" "$SCRATCH" "$PROVIDER_CASE" <<'PYPROVIDER'
import pathlib, sys
source, scratch = map(pathlib.Path, sys.argv[1:3])
sys.path.insert(0, str(source/'tools/testing/selftests/xdev_ext_integration'))
from xdev_ext_mech_zc_validate import validate_provider_console
validate_provider_console((scratch/'evidence/guest.log').read_text(), case=sys.argv[3])
for before, after in (('source-before.raw', 'source.raw'),
                      ('destination-before.raw', 'destination.raw')):
    if (scratch/before).read_bytes() != (scratch/after).read_bytes():
        raise ValueError('dedicated provider guest changed unused disk image: ' + after)
PYPROVIDER
    echo "XDEV_EXT_ZC_PROVIDER_KVM=PASS case=$PROVIDER_CASE source_disk=unchanged destination_disk=unchanged" \
        | tee "$EV/result.txt"
    exit 0
fi
if [[ "$FAULT" == reliable-budget-unknown ]]; then
    grep -Fxq XDEV_EXT_ZC_UNKNOWN=PASS "$EV/guest.log"
elif [[ "$FAULT" == drop-middle ]]; then
	grep -Fxq XDEV_EXT_ZC_FAIL_STOP=PASS "$EV/guest.log"
else
	grep -Fxq XDEV_EXT_ZC_CHAIN=PASS "$EV/guest.log"
fi
grep -Fxq XDEV_EXT_ZC_GUEST_EXIT=0 "$EV/guest.log"
grep -Eq '^XDEV_EXT_MECH_READY mode=source .* xsk=zc$' "$EV/guest.log"
grep -Fxq 'XDEV_EXT_ZC_COPY_FALLBACK=PASS calls=0' "$EV/guest.log"
# --- Track S (appended): the NIC-boundary fallback section must have passed.
if (( NIC_FALLBACK )); then
    grep -Fxq "XDEV_EXT_ZC_NIC_FALLBACK=PASS socket_groups=$GROUP_COUNT copy_groups=$GROUP_COUNT zc_copy_ops=0" "$EV/guest.log"
    grep -Fxq "XDEV_EXT_ZC_NIC_AUTO_INTEROP=PASS socket_side=rx groups=$GROUP_COUNT" "$EV/guest.log"
    grep -Fxq "XDEV_EXT_ZC_NIC_AUTO_INTEROP=PASS socket_side=tx groups=$GROUP_COUNT" "$EV/guest.log"
fi
# --- end track S section
if (( CE_SIM )); then
    ce_chains='a b d'
    [[ "$FAULT" != reliable-budget-unknown ]] || ce_chains='a d'
	for chain in $ce_chains; do grep -Fxq "XDEV_EXT_MECH_CE_SIM=PASS chain=$chain" "$EV/guest.log"; done
	if [[ "$FAULT" != reliable-budget-unknown ]]; then
	grep -Fxq 'XDEV_EXT_ZC_CE_CHAINS=PASS chains=a,b,d backend=CPU-memcpy-standin' "$EV/guest.log"
    fi
	grep -Fxq 'XDEV_EXT_DMA_DYNAMIC_PROVIDER=PASS' "$EV/guest.log"
fi
! grep -Eq 'BUG:|WARNING:|Kernel panic|Oops:' "$EV/guest.log"
python3 - "$SRC" "$SCRATCH" "$GROUP_COUNT" "$CE_SIM" "$CE_DELAY_US" "$FAULT" "$RX_CE" "$RELIABLE" "$DEPTH" "$CE_SLOTS" <<'PYVALIDATE'
import json, pathlib, sys
src, scratch = map(pathlib.Path, sys.argv[1:3])
sys.path.insert(0, str(src/'tools/testing/selftests/xdev_ext_integration'))
from xdev_ext_mech_zc_validate import image_layout, validate_console, validate_images
options = dict(groups=int(sys.argv[3]), ce_sim=sys.argv[4] == '1', fault=sys.argv[6], rx_ce=sys.argv[7] == '1', reliable=sys.argv[8] == '1', depth=int(sys.argv[9]), ce_slots=int(sys.argv[10]))
result = validate_console((scratch/'evidence/guest.log').read_text(), ce_delay_us=int(sys.argv[5]), **options)
validate_images(*( (scratch/name).read_bytes() for name in
                  ('source-before.raw', 'source.raw', 'destination-before.raw', 'destination.raw')),
                **options, **result)
if options['fault'] == 'reliable-budget-unknown':
    # Commit the expected image for the observed complete prefix only after
    # the independent full-image validator has checked that exact prefix.
    expected = bytearray((scratch/'destination-before.raw').read_bytes())
    source = (scratch/'source-before.raw').read_bytes()
    layout = image_layout(options['groups'])
    source_offset, rx_offset, ce_offset = (layout[key] * 512 for key in
                                           ('source_slba', 'rx_slba', 'ce_slba'))
    copied = result['receiver_batches_done'] * 8192
    expected[rx_offset:rx_offset+copied] = source[source_offset:source_offset+copied]
    if options['ce_sim']:
        size = options['groups'] * 8192
        expected[ce_offset:ce_offset+size] = source[source_offset:source_offset+size]
    (scratch/'expected.raw').write_bytes(expected)
(scratch/'evidence/validation.json').write_text(json.dumps(result) + '\n')
PYVALIDATE
sha256sum "$SCRATCH/source.raw" | awk '{ print $1 }' >"$EV/source-after.sha256"
cmp "$EV/source-before.sha256" "$EV/source-after.sha256"
sha256sum "$SCRATCH/source.raw" "$SCRATCH/destination.raw" \
	"$SCRATCH/expected.raw" >"$EV/data.sha256"
echo "XDEV_EXT_ZC_DATA=PASS destination=whole-image source=unchanged groups=$GROUP_COUNT group_bytes=8192" \
	| tee "$EV/data-result.txt"
echo XDEV_EXT_ZC_KVM=PASS | tee "$EV/result.txt"
