#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Correctness of the eval session arms of tests/eval (chains, nvme_gpu,
# gpu_nic) inside an xdev_ext KVM guest, with the CPU-memcpy copy-engine
# stand-in.  Correctness only: no timing is printed or recorded, and
# performance_claim=none.  The guest builds nothing; the KVM image carries
# the binaries of `make -C tests/eval/session_guest guest GUEST_OUT=DIR`.
#
#   xdev_ext_eval_session_guest.sh EVAL_DIR XDEV_DIR SRC_BLOCK SRC_NG DST_BLOCK DST_NG TIMEOUT_MS
#
# EVAL_DIR   chain_bench, chain_plan.bpf.o, session_nvme_ce, session_gpu_nic,
#            eval_session_oracle
# XDEV_DIR   xdev_ext_mech_ctl, nxp_mech.bpf.o, ce_plan.bpf.o, xdev_ext_ce_sim.ko
# SRC_*/DST_* the guest's source and destination NVMe namespaces (block and
#            generic character devices); eth0 and eth1 are linked AF_XDP NICs
#            with MACs 02:00:00:00:00:01 and 02:00:00:00:00:02.
#
# Preconditions: the CE stand-in is not loaded and no nxp_nvme_ops,
# nxp_afxdp_ops or ce_plan_ops plan is attached.  This script attaches its
# own, loads the stand-in, runs every case, then detaches and unloads them.
#
# Disks: every case uses one 1 MiB scratch span at byte 12 MiB of each
# namespace.  The span is saved first (eval_session_oracle snapshot) and
# written back and compared at the end, so the images keep the bytes the
# harness validates.  Each case writes fresh data (seeded) before it runs.
#
# Every case prints
#   XDEV_EXT_EVAL_SESSION=<arm>:<case> PASS|FAIL bytes=<n> sha256=<hex>
# where the hash covers the bytes eval_session_oracle read back after the
# arm exited and checked against its own expected bytes (the canonical
# order is described in xdev_ext_eval_session_validate.py); then
#   XDEV_EXT_EVAL_SESSION_DONE=<n_pass>/<n_total>
# The host validates the console with xdev_ext_eval_session_validate.py.
# Exit 0 only when every case passed and both spans were restored.
set -eu
[ "$#" = 7 ] || { echo "seven guest arguments required" >&2; exit 2; }

eval_dir=$1
opt=$2
src_block=$3
src_ng=$4
dst_block=$5
dst_ng=$6
timeout_ms=$7

oracle=$eval_dir/eval_session_oracle
bench=$eval_dir/chain_bench
ctl=$opt/xdev_ext_mech_ctl
ce=/dev/xdev_ext_ce_sim
wire_session=270019
scratch_offset=$((12 << 20))
scratch_len=$((1 << 20))
guard_offset=$((scratch_offset - 4096))
guard_len=$((scratch_len + 8192))
records=4
warmup=1
depth=4
zero_hash=0000000000000000000000000000000000000000000000000000000000000000
n_pass=0
n_total=0
attached=''
restored=0
ready_rounds=$((timeout_ms / 50))

log() {
	echo "XDEV_EXT_EVAL_SESSION_LOG $*"
}

lba_of() {
	cat "/sys/block/$(basename "$1")/queue/logical_block_size"
}

sectors_of() {
	cat "/sys/block/$(basename "$1")/size"
}

for f in "$oracle" "$bench" "$eval_dir/session_nvme_ce" "$eval_dir/session_gpu_nic" "$ctl"; do
	test -x "$f"
done
for f in "$eval_dir/chain_plan.bpf.o" "$opt/nxp_mech.bpf.o" "$opt/ce_plan.bpf.o" "$opt/xdev_ext_ce_sim.ko"; do
	test -r "$f"
done
test -b "$src_block" && test -c "$src_ng" && test -b "$dst_block" && test -c "$dst_ng"
test ! -e /sys/module/xdev_ext_ce_sim
lba=$(lba_of "$dst_block")
test "$(lba_of "$src_block")" = "$lba"
for dev in "$src_block" "$dst_block"; do
	test "$(( $(sectors_of "$dev") * 512 ))" -ge "$((scratch_offset + scratch_len))"
done
slba=$((scratch_offset / lba))
work=$(mktemp -d /tmp/eval-session.XXXXXX)

"$oracle" snapshot --dev "$src_block" --offset "$scratch_offset" --length "$scratch_len" \
	--out "$work/src.snap"
"$oracle" snapshot --dev "$dst_block" --offset "$scratch_offset" --length "$scratch_len" \
	--out "$work/dst.snap"

teardown() {
	for pin in $attached; do
		"$ctl" detach --pin "/sys/fs/bpf/eval-session-$pin" || return 1
	done
	attached=''
	if [ -e /sys/module/xdev_ext_ce_sim ]; then
		i=0
		while [ "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" != 0 ] && [ "$i" -lt "$ready_rounds" ]; do
			sleep 0.05
			i=$((i + 1))
		done
		test "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0 || return 1
		rmmod xdev_ext_ce_sim || return 1
	fi
}

restore() {
	src=$("$oracle" restore --dev "$src_block" --offset "$scratch_offset" --snapshot "$work/src.snap") || return 1
	dst=$("$oracle" restore --dev "$dst_block" --offset "$scratch_offset" --snapshot "$work/dst.snap") || return 1
	restored=1
	echo "XDEV_EXT_EVAL_SESSION_SCRATCH=restored source_sha256=${src##*sha256=} destination_sha256=${dst##*sha256=}"
}

# Failure preserves scratch bytes and logs. Never restore a possibly active DMA target.
abnormal() {
	code=$?
	set +e
	if [ "$restored" = 0 ]; then
		teardown
		log "failure: retained scratch and logs at $work (no restore)" >&2
	fi
	exit "$code"
}
trap abnormal EXIT

insmod "$opt/xdev_ext_ce_sim.ko" fail_mode=none
test -c "$ce"
test "$(cat /sys/module/xdev_ext_ce_sim/parameters/fail_mode)" = none
echo 'XDEV_EXT_EVAL_SESSION_BACKEND=CPU-memcpy-standin gpu=none performance_claim=none'
"$ctl" attach --obj "$opt/nxp_mech.bpf.o" --map nxp_nvme_ops --pin /sys/fs/bpf/eval-session-nvme \
	--set nvme_mode=0
attached="nvme"
"$ctl" attach --obj "$opt/nxp_mech.bpf.o" --map nxp_afxdp_ops --pin /sys/fs/bpf/eval-session-afxdp \
	--set nxp_session=$wire_session
attached="afxdp $attached"
"$ctl" attach --obj "$opt/ce_plan.bpf.o" --map ce_plan_ops --pin /sys/fs/bpf/eval-session-ce
attached="ce $attached"

# One marker per case; a body prints only the oracle's result line.
mark() {
	n_total=$((n_total + 1))
	if [ "$2" = PASS ]; then
		n_pass=$((n_pass + 1))
		echo "XDEV_EXT_EVAL_SESSION=$1 PASS $3"
	else
		echo "XDEV_EXT_EVAL_SESSION=$1 FAIL bytes=0 sha256=$zero_hash"
	fi
}

# Snapshot the complete scratch extent plus boundary guards, and both halves
# of the existing 4 MiB CE window. Only declared write regions may differ.
guard_prepare() {
	src_used=0 dst_used=0 ce0_used=0 ce1_used=0
	case $1 in
	nvme_gpu_body) dst_used=$(($3 * $4)); ce0_used=$dst_used ;;
	gpu_nic_body) ce0_used=$(($2 * $3)); ce1_used=$ce0_used ;;
	chain_pair_body)
		src_used=$(((records + warmup) * $5)); dst_used=$src_used
		if [ "$2" = nvme-gpu-nic ]; then ce0_used=1048576; ce1_used=1048576; fi ;;
	chain_iaa_body) src_used=$3; ce0_used=1048576 ;;
	*) return 1 ;;
	esac
	rm_ "$work/src.guard" "$work/dst.guard" "$work/ce0.guard" "$work/ce1.guard"
	"$oracle" snapshot --dev "$src_block" --offset "$guard_offset" --length "$guard_len" --out "$work/src.guard" &&
	"$oracle" snapshot --dev "$dst_block" --offset "$guard_offset" --length "$guard_len" --out "$work/dst.guard" &&
	"$oracle" snapshot --dev "$ce" --offset 0 --length 2097152 --out "$work/ce0.guard" &&
	"$oracle" snapshot --dev "$ce" --offset 2097152 --length 2097152 --out "$work/ce1.guard"
}

guard_check() {
	# A process exit alone does not prove asynchronous session release.
	i=0
	while [ "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" != 0 ] && [ "$i" -lt "$ready_rounds" ]; do
		sleep 0.05
		i=$((i + 1))
	done
	test "$(cat /sys/module/xdev_ext_ce_sim/refcnt)" = 0 &&
	"$oracle" compare --dev "$src_block" --offset "$guard_offset" --snapshot "$work/src.guard" --skip-offset 4096 --skip-length "$src_used" &&
	"$oracle" compare --dev "$dst_block" --offset "$guard_offset" --snapshot "$work/dst.guard" --skip-offset 4096 --skip-length "$dst_used" &&
	"$oracle" compare --dev "$ce" --offset 0 --snapshot "$work/ce0.guard" --skip-offset 0 --skip-length "$ce0_used" &&
	"$oracle" compare --dev "$ce" --offset 2097152 --snapshot "$work/ce1.guard" --skip-offset 0 --skip-length "$ce1_used"
}

# Raw counts and cleanup observations from the child, never invented success.
# Host validation checks every count and requires exactly the expected stops.
audit_arm() {
	role=$1 errfile=$2 stops=$3
	test "$(grep -c '^EVAL_STOP=PASS result=0$' "$errfile")" = "$stops" &&
	test "$(grep -c '^EVAL_FD_CHECK=PASS ' "$errfile")" = 1 || return 1
	if grep -Eq '^EVAL_(STOP|FD_CHECK)=FAIL' "$errfile"; then return 1; fi
	grep -E '^(XDEV_EXT_MECH_STATS |EVAL_STOP=|EVAL_FD_CHECK=)' "$errfile" |
		sed "s|^|XDEV_EXT_EVAL_ARM=$id/$role |" >&2
}

run_case() {
	id=$1
	shift
	guard_prepare "$@" || return 1
	if result=$("$@") && echo "$result" | grep -Eqx 'bytes=[0-9]+ sha256=[0-9a-f]{64}' && guard_check; then
		echo "XDEV_EXT_EVAL_SESSION_CHECKS=$id guards=pass ce_refs=0"
		mark "$id" PASS "$result"
	else
		mark "$id" FAIL
		return 1
	fi
}

# A failed arm's record and stderr, timing fields removed.
show() {
	for f in "$@"; do
		[ -s "$f" ] || continue
		sed -E 's/"[a-z_]*(_ns|_us)":[0-9]+,?//g; s/^/XDEV_EXT_EVAL_SESSION_LOG /' "$f" | tail -n 20
	done
}

# record: status pass, the stand-in backend, no performance claim.
standin_pass() {
	grep -q '"status":"pass"' "$1" &&
	grep -q '"execution":"kvm-ce-sim","performance_claim":"none"' "$1"
}

wait_ready() {
	i=0
	while [ "$i" -lt "$ready_rounds" ]; do
		grep -q "$2" "$1" 2>/dev/null && return 0
		kill -0 "$3" 2>/dev/null || return 1
		sleep 0.05
		i=$((i + 1))
	done
	return 1
}

# --- nvme_gpu: [NVMe READ, CE H2D] load and [CE D2H, NVMe WRITE] save -------

nvme_gpu_body() {
	direction=$1 size=$2 qd=$3 seed=$4
	rec=$work/nvme-gpu.json err=$work/nvme-gpu.err
	"$eval_dir/session_nvme_ce" --direction "$direction" --ng "$dst_ng" --slba "$slba" \
		--lba-size "$lba" --file "$dst_block" --file-offset "$scratch_offset" --ce-dev "$ce" \
		--ce-va 0 --size "$size" --qd "$qd" --window-bytes "$((size * qd))" --passes 2 \
		--seed "$seed" --timeout-ms "$timeout_ms" >"$rec" 2>"$err" &&
	standin_pass "$rec" || { show "$rec" "$err" >&2; return 1; }
	audit_arm main "$err" 2 || return 1
	if [ "$direction" = load ]; then
		"$oracle" xg-slots --ce "$ce" --va 0 --size "$size" --slots "$qd" --seed "$seed"
	else
		"$oracle" xg-file --dev "$dst_block" --offset "$scratch_offset" --size "$size" \
			--groups "$qd" --slots "$qd" --seed "$seed"
	fi
}

nvme_gpu_case() {
	run_case "nvme_gpu:$1-s$2-q$3-seed$4" nvme_gpu_body "$@"
}

# --- gpu_nic: egress [CE D2H, AF_XDP TX] on eth0 feeds ingest [AF_XDP RX, CE H2D] on eth1

gpu_nic_body() {
	size=$1 depth_=$2 seed=$3
	common="--ce-dev $ce --size $size --messages $depth_ --depth $depth_ --wire-session $wire_session --seed $seed --timeout-ms $timeout_ms"
	# shellcheck disable=SC2086
	"$eval_dir/session_gpu_nic" --direction ingest --ifname eth1 --ce-va 2097152 $common \
		--local-ip 192.0.2.2 --peer-ip 192.0.2.1 --local-port 12345 --peer-port 54321 \
		--peer-mac 02:00:00:00:00:01 >"$work/ingest.json" 2>"$work/ingest.err" &
	rx=$!
	if ! wait_ready "$work/ingest.err" 'XDEV_EVAL_READY direction=ingest .* xsk=zc' "$rx"; then
		kill "$rx" 2>/dev/null
		wait "$rx"
		show "$work/ingest.err" >&2
		return 1
	fi
	# shellcheck disable=SC2086
	"$eval_dir/session_gpu_nic" --direction egress --ifname eth0 --ce-va 0 $common \
		--local-ip 192.0.2.1 --peer-ip 192.0.2.2 --local-port 54321 --peer-port 12345 \
		--peer-mac 02:00:00:00:00:02 >"$work/egress.json" 2>"$work/egress.err"
	tx=$?
	wait "$rx"
	rx=$?
	if [ "$tx" != 0 ] || [ "$rx" != 0 ] || ! standin_pass "$work/egress.json" ||
	   ! standin_pass "$work/ingest.json" || ! grep -q '"xsk":"zc"' "$work/egress.json" ||
	   ! grep -q '"xsk":"zc"' "$work/ingest.json"; then
		show "$work/egress.json" "$work/egress.err" "$work/ingest.json" "$work/ingest.err" >&2
		return 1
	fi
	audit_arm tx "$work/egress.err" 1 && audit_arm rx "$work/ingest.err" 1 || return 1
	"$oracle" xg-slots --ce "$ce" --va 2097152 --size "$size" --slots "$depth_" --seed "$seed"
}

gpu_nic_case() {
	run_case "gpu_nic:egress-ingest-s$1-d$2-seed$3" gpu_nic_body "$@"
}

# --- chains: chain_bench session arm specs -----------------------------------

# group_bytes of a NIC chain record: a power of two of at most 32 NXP segments.
nic_group() {
	g=1
	m=$1
	[ "$m" -le 45824 ] || m=45824
	while [ $((g * 2)) -le "$m" ]; do
		g=$((g * 2))
	done
	echo "$g"
}

spec_head() {
	# chain group batches warmup burst load seed
	printf '{"schema":"xdev-chain-spec-v1","chain":"%s","arm":"session","mode":"correctness",' "$1"
	printf '"group_bytes":%s,"batches":%s,"warmup":%s,"burst":%s,"depth":%s,' "$2" "$3" "$4" "$5" "$depth"
	printf '"start_per":"batch","plan":"bpf","afxdp_mode":"zc","timeout_ms":%s,"seed":%s,"load":"%s",' \
		"$timeout_ms" "$7" "$6"
}

peer_tx='"peer":{"local_mac":"02:00:00:00:00:01","peer_mac":"02:00:00:00:00:02","local_ip":"192.0.2.1","peer_ip":"192.0.2.2","local_port":54321,"peer_port":12345,"session":270019}'
peer_rx='"peer":{"local_mac":"02:00:00:00:00:02","peer_mac":"02:00:00:00:00:01","local_ip":"192.0.2.2","peer_ip":"192.0.2.1","local_port":12345,"peer_port":54321,"session":270019}'

chain_pair_body() {
	sender=$1 receiver=$2 load=$3 record=$4 seed=$5
	g=$(nic_group "$record")
	burst=$((record / g))
	total=$(((records + warmup) * burst))
	bytes=$((total * g))
	nlb=$((bytes / lba))
	ref=$work/ref-$seed.bin
	src_stage=$(printf '{"class":"nvme","dir":"from","dev":"%s","block":"%s","slba":%s,"nlb":%s}' \
		"$src_ng" "$src_block" "$slba" "$nlb")
	dst_stage=$(printf '{"class":"nvme","dir":"to","dev":"%s","block":"%s","slba":%s,"nlb":%s}' \
		"$dst_ng" "$dst_block" "$slba" "$nlb")
	"$oracle" chain-source --dev "$src_block" --offset "$scratch_offset" --group "$g" \
		--groups "$total" --seed "$seed" >&2 &&
	"$oracle" fill --dev "$dst_block" --offset "$scratch_offset" --length "$bytes" --byte 90 >&2 &&
	"$oracle" chain-ref --out "$ref" --group "$g" --groups "$total" --seed "$seed" >&2 || return 1
	case $sender in
	nvme-nic)
		tx_stages="$src_stage,{\"class\":\"afxdp\",\"dir\":\"to\",\"ifname\":\"eth0\",\"queue\":0}"
		rx_stages="{\"class\":\"afxdp\",\"dir\":\"from\",\"ifname\":\"eth1\",\"queue\":0},$dst_stage"
		tx_ce='' rx_ce='' ;;
	nvme-gpu-nic)
		tx_stages="$src_stage,{\"class\":\"ce\",\"dir\":\"to\"},{\"class\":\"ce\",\"dir\":\"from\"},{\"class\":\"afxdp\",\"dir\":\"to\",\"ifname\":\"eth0\",\"queue\":0}"
		rx_stages="{\"class\":\"afxdp\",\"dir\":\"from\",\"ifname\":\"eth1\",\"queue\":0},{\"class\":\"ce\",\"dir\":\"to\"},{\"class\":\"ce\",\"dir\":\"from\"},$dst_stage"
		tx_ce="\"ce\":{\"dev\":\"$ce\",\"va\":0,\"len\":1048576,\"alloc\":\"given\"},"
		rx_ce="\"ce\":{\"dev\":\"$ce\",\"va\":2097152,\"len\":1048576,\"alloc\":\"given\"},"
		;;
	*) return 1 ;;
	esac
	{ spec_head "$sender" "$g" "$((records * burst))" "$((warmup * burst))" "$burst" "$load" "$seed"
	  printf '%s%s,"stages":[%s]}\n' "$tx_ce" "$peer_tx" "$tx_stages"; } >"$work/tx.spec.json"
	{ spec_head "$receiver" "$g" "$((records * burst))" "$((warmup * burst))" "$burst" "$load" "$seed"
	  printf '%s%s,"oracle":{"kind":"file","path":"%s","offset":%s,"reference":"%s"},"stages":[%s]}\n' \
		"$rx_ce" "$peer_rx" "$dst_block" "$scratch_offset" "$ref" "$rx_stages"; } >"$work/rx.spec.json"
	"$bench" --spec "$work/rx.spec.json" >"$work/rx.out" 2>"$work/rx.err" &
	rx=$!
	if ! wait_ready "$work/rx.err" '^CHAIN_READY .* xsk=zc' "$rx"; then
		kill "$rx" 2>/dev/null
		wait "$rx"
		show "$work/rx.out" "$work/rx.err" >&2
		return 1
	fi
	"$bench" --spec "$work/tx.spec.json" >"$work/tx.out" 2>"$work/tx.err"
	tx=$?
	wait "$rx"
	rx=$?
	if [ "$tx" != 0 ] || [ "$rx" != 0 ] || ! grep -q '"status":"pass"' "$work/tx.out" ||
	   ! grep -q '"status":"pass"' "$work/rx.out" ||
	   ! grep -q '"oracle":{"kind":"file","verdict":"pass"' "$work/rx.out"; then
		show "$work/tx.out" "$work/tx.err" "$work/rx.out" "$work/rx.err" >&2
		return 1
	fi
	audit_arm tx "$work/tx.err" 1 && audit_arm rx "$work/rx.err" 1 || return 1
	rm_ "$ref"
	"$oracle" chain-file --dev "$dst_block" --offset "$scratch_offset" --group "$g" \
		--groups "$total" --seed "$seed"
}

chain_pair_case() {
	run_case "chains:$1+$2-$3-r$4-seed$5" chain_pair_body "$@"
}

# nvme-iaa-gpu: [NVMe READ, IAA decompress (deflate-generic), CE H2D]
chain_iaa_body() {
	# One produced record remains entirely observable after completion;
	# a slot ring cannot prove bytes of overwritten intermediate records.
	records=1 warmup=0
	load=$1 record=$2 seed=$3
	g=$record
	[ "$g" -le 131072 ] || g=131072
	burst=$((record / g))
	total=$(((records + warmup) * burst))
	nlb=$((total * g / lba))
	ref=$work/ref-$seed.bin
	every=false
	[ "$load" = closed ] && [ "$burst" = 1 ] && every=true
	"$oracle" chain-source --dev "$src_block" --offset "$scratch_offset" --group "$g" \
		--groups "$total" --seed "$seed" --compress >&2 &&
	"$oracle" chain-ref --out "$ref" --group "$g" --groups "$total" --seed "$seed" --text >&2 || return 1
	{ spec_head nvme-iaa-gpu "$g" "$((records * burst))" "$((warmup * burst))" "$burst" "$load" "$seed"
	  printf '"ce":{"dev":"%s","va":0,"len":1048576,"alloc":"given"},"pool":{"frame_size":%s},' "$ce" "$g"
	  printf '"oracle":{"kind":"ce-window","reference":"%s","every_window":%s},' "$ref" "$every"
	  printf '"plans":[{"obj":"%s","map":"chain_iaa_ops","set":{"expect_out":%s}}],' \
		"$eval_dir/chain_plan.bpf.o" "$g"
	  printf '"stages":[{"class":"nvme","dir":"from","dev":"%s","block":"%s","slba":%s,"nlb":%s},' \
		"$src_ng" "$src_block" "$slba" "$nlb"
	  printf '{"class":"iaa","dir":"from","software":true,"capacity":%s,"expect":%s},{"class":"ce","dir":"to"}]}\n' \
		"$g" "$g"; } >"$work/iaa.spec.json"
	if ! "$bench" --spec "$work/iaa.spec.json" >"$work/iaa.out" 2>"$work/iaa.err" ||
	   ! grep -q '"status":"pass"' "$work/iaa.out" ||
	   ! grep -q '"oracle":{"kind":"ce-window","verdict":"pass"' "$work/iaa.out"; then
		show "$work/iaa.out" "$work/iaa.err" >&2
		return 1
	fi
	audit_arm main "$work/iaa.err" 1 || return 1
	rm_ "$ref"
	"$oracle" chain-ce --ce "$ce" --va 0 --group "$g" --slots "$depth" --groups "$total" --seed "$seed"
}

chain_iaa_case() {
	run_case "chains:nvme-iaa-gpu-$1-r$2-seed$3" chain_iaa_body "$@"
}

rm_() {
	/bin/busybox rm -f "$@"
}

nvme_gpu_case load 8192 4 11
nvme_gpu_case load 65536 4 12
nvme_gpu_case save 8192 4 13
nvme_gpu_case save 65536 4 14
gpu_nic_case 4096 4 21
gpu_nic_case 16384 4 22
chain_pair_case nvme-nic nic-nvme closed 4096 31
chain_pair_case nvme-nic nic-nvme sustained 4096 32
chain_pair_case nvme-gpu-nic nic-gpu-nvme closed 4096 33
chain_pair_case nvme-gpu-nic nic-gpu-nvme sustained 4096 34
chain_pair_case nvme-gpu-nic nic-gpu-nvme closed 65536 35
chain_pair_case nvme-gpu-nic nic-gpu-nvme sustained 65536 36
chain_iaa_case closed 4096 41
chain_iaa_case sustained 4096 42
chain_iaa_case closed 65536 43
chain_iaa_case sustained 65536 44

teardown
restore
trap - EXIT
/bin/busybox rm -rf "$work"
echo "XDEV_EXT_EVAL_SESSION_DONE=$n_pass/$n_total"
test "$n_pass" = "$n_total"
