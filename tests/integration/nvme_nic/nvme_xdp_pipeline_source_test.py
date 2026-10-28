#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Production-path contract checks for the bidirectional vector executor."""

from pathlib import Path
import re
import sys


SOURCE = Path(__file__).resolve().parents[4] / "nvme_xdp_pipeline.c"
CORE = Path(__file__).resolve().parents[4] / "nvme_xdp_pipeline_core.h"
text = SOURCE.read_text(encoding="utf-8")
core_text = CORE.read_text(encoding="utf-8")
checks = 0
failures = 0


def require(condition: bool, message: str) -> None:
    global checks, failures
    checks += 1
    if not condition:
        failures += 1
        print(f"not ok {checks} - {message}")
    else:
        print(f"ok {checks} - {message}")


def function_body(name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", text, re.S)
    if not match:
        return ""
    start = match.end() - 1
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start : pos + 1]
    return ""


tx = function_body("run_vector_tx_pipeline")
staging_tx = function_body("run_pipeline_batched")
prepare_staging = function_body("pipeline_prepare_staging_frames")
copy_staging = function_body("pipeline_copy_staging_group")
process_data = function_body("process_data")
rx = function_body("run_rx_write_pipeline")
entry = function_body("run_pipeline")
main = function_body("main")
refill = function_body("pipeline_refill_rx_frames")
prepare_write = function_body("pipeline_prepare_rx_write")
prepare_tx = function_body("pipeline_prepare_tx_group")
publish_tx = function_body("pipeline_submit_tx_group")
publish_ready_tx = function_body("pipeline_publish_ready_tx_groups")
init_xsk = function_body("init_xsk")
decode_rx = function_body("pipeline_decode_rx_descriptor")
validate_rx = function_body("pipeline_validate_rx_packet")
validate_vector = function_body("pipeline_validate_umem_vector")
detach_redirect = function_body("pipeline_detach_xsk_redirect")
hold_backing = function_body("pipeline_hold_unquiesced_backing")
drop_external = function_body("pipeline_rx_drop_external")
expire_group = function_body("pipeline_rx_expire_group")
validate_transform = function_body("pipeline_validate_transform")

require(bool(tx), "vector TX executor exists")
require("pipeline_prepare_tx_group" in tx, "TX prepares one logical vector command")
require("submit_prepared_batch" in tx, "TX uses accepted-prefix submit journal")
require("pipeline_publish_ready_tx_groups" in tx and
        "pipeline_submit_tx_group" in publish_ready_tx,
        "TX publishes the segmented wire group")
require("pipeline_find_next_tx_group" in publish_ready_tx and
        "next_publish" in tx,
        "out-of-order NVMe CQEs are reordered before strict wire publication")
require("pipeline_publish_ready_tx_groups" in staging_tx and
        "next_publish" in staging_tx,
        "staging diagnostic also preserves strict wire generation order")
require(bool(re.search(
            r"pipeline_publish_ready_tx_groups\([^;]+;\s*"
            r"tx_pending_kick\s*\+=\s*published\s*;\s*if\s*\(ret\)",
            staging_tx, re.S)),
        "staging kicks a committed TX prefix even when a later group fails")
require("nxp_wire_mtu_layout_plan" in prepare_staging and
        "for (uint16_t i = 0; i < slot->wire_layout.segment_count; i++)" in
        prepare_staging and "xsk_alloc_umem_frame" in prepare_staging,
        "staging reserves the complete ordinary-datagram group for one logical read")
require("memcpy(" in copy_staging and
        "slot->vector[i].iov_len" in copy_staging and
        "copied == g_block_size" in copy_staging,
        "staging scatters one completed NVMe buffer across every planned frame")
require("pipeline_prepare_staging_frames" in staging_tx and
        "pipeline_copy_staging_group" in staging_tx and
        "segment_count != 1" not in staging_tx,
        "8KiB staging follows the multi-frame path instead of a single-frame gate")
require("g_transform == PIPELINE_TRANSFORM_NONE" in process_data and
        "PIPELINE_TRANSFORM_XOR" in text,
        "payload transfer is byte-preserving unless XOR is explicitly selected")
require("NXP_IO_READ" in prepare_tx and "NXP_IO_WRITE" in publish_tx,
        "source NVMe READ is encoded as destination WRITE on wire")
require("NVME_URING_CMD_IO_VEC" in function_body("fill_nvme_vector_sqe"),
        "vector SQE uses NVME_URING_CMD_IO_VEC")
require("run_vector_tx_pipeline" in entry, "main pipeline reaches vector TX")

require(bool(rx), "RX-to-NVMe WRITE executor exists")
require("pipeline_refill_rx_frames" in rx and
        "xsk_ring_prod__reserve(&ctx->xsk.fq" in refill,
        "RX executor populates/refills AF_XDP FQ")
require("pipeline_decode_rx_descriptor" in rx and
        ".frame_headroom = PKT_START_OFF" in init_xsk and
        "NXP_VECTOR_ALIGNMENT" in decode_rx,
        "RX descriptor/headroom layout aligns direct IO_VEC payloads")
require("parse_wire_packet" in rx, "RX executor strictly parses production packets")
require("pipeline_validate_rx_packet" in rx and
        "NXP_IO_READ" in validate_rx and "-EACCES" in validate_rx,
        "RX rejects wire READ so network input can request only local WRITE")
require("nxp_wire_group_accept" in rx, "RX executor enforces ordered wire groups")
rx_hold = rx.index("nxp_rx_frame_hold_for_io(")
rx_count = rx.index("slot->segment_count++;", rx_hold)
rx_chain = rx.index("pipeline_chain_begin_rx_frame(", rx_hold)
require(rx_hold < rx_count < rx_chain,
        "RX cleanup accounts for the current IO-owned frame before chain begin")
require("pipeline_prepare_rx_write" in rx and "NXP_IO_WRITE" in prepare_write and
        "fill_nvme_vector_sqe" in prepare_write,
        "RX executor submits one local fixed-vector NVMe WRITE")
require("pipeline_validate_umem_vector" in prepare_tx and
        "pipeline_validate_umem_vector" in prepare_write,
        "both directions validate their production IO_VEC before SQ publication")
require("fixed_buffer_registered" in validate_vector and
        "ctx->xsk.umem_area" in validate_vector and
        "NXP_VECTOR_ALIGNMENT" in validate_vector and
        "FRAME_SIZE" in validate_vector,
        "IO_VEC entries must be aligned, single-frame ranges in registered UMEM")
require("run_rx_write_pipeline" in entry, "main pipeline reaches RX-write mode")
require("case 'm'" in main and "rx-write" in main,
        "CLI exposes explicit RX-write direction")
require("O_RDWR" in main and "PIPELINE_NIC_TO_NVME" in main,
        "only write mode requests a writable NVMe descriptor")
require(bool(re.search(r"g_block_size\s*=\s*8192\s*;", text)) and
        "nxp_group_capacity_validate" in main and
        "nxp_group_capacity_validate" in tx and
        "nxp_group_capacity_validate" in rx,
        "default 8KiB path rejects depth beyond frame/XSK ring capacity")
require("descriptor->options = 0" in publish_tx and
        "XDP_PKT_CONTD" not in core_text and
        "nxp_wire_layout_plan" not in core_text,
        "wire segments are independent ordinary datagrams, never implicit XDP multi-buffer packets")
require("tools/include/xdev_ext_xsk_redirect.h" in text and
        "struct xdev_ext_xsk_redirect" in text,
        "pipeline owns the project XSK redirect loader state")
require("XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD" in init_xsk and
        "xdev_ext_xsk_redirect_attach" in init_xsk,
        "pipeline explicitly loads and attaches its self-contained redirect program")
require("struct xdev_ext_xsk_flow_filter" in main and
        "XDEV_EXT_XSK_FILTER_F_ALL" in main and
        ".payload_magic = NXP_WIRE_MAGIC" in main,
        "pipeline redirect is restricted to the exact configured flow and NXP2 magic")
require("XDP_FLAGS_DRV_MODE" in init_xsk and
        "XDP_FLAGS_SKB_MODE" in init_xsk,
        "redirect attach mode follows the successful zero-copy or copy bind")
require("XDEV_EXT_XSK_REDIRECT_MAX_QUEUES" in main,
        "CLI rejects queue IDs outside the private XSKMAP")
require("pipeline_detach_xsk_redirect" in main and
        "xdev_ext_xsk_redirect_detach" in detach_redirect and
        "xdev_ext_xsk_redirect_is_active" in detach_redirect,
        "teardown proves redirect quiescence before destroying XSK backing")
guard = main.find("if (!pipeline_can_destroy_xsk(&ctx))")
guard_end = main.find("if (xsk_ready)", guard)
require(guard >= 0 and guard_end > guard and
        "pipeline_hold_unquiesced_backing(" in main[guard:guard_end] and
        "return" not in main[guard:guard_end],
        "unproven DMA/CQ ownership cannot return into process teardown")
require(bool(hold_backing) and "for (;;)" in hold_backing and
        all(sig in hold_backing for sig in
            ("SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM")),
        "unquiesced backing hold ignores ordinary termination signals")
require("case 'e'" in main and "!ctx.session_id" in main and
        "session=%llu" in entry,
        "CLI requires and reports a nonzero wire session identity")
require("case 't'" in main and 'strcmp(optarg, "none")' in main and
        'strcmp(optarg, "xor")' in main,
        "CLI exposes explicit none/xor transformation selection")
require("PIPELINE_NIC_TO_NVME" in validate_transform and
        "PIPELINE_TRANSFORM_NONE" in validate_transform and
        "pipeline_validate_transform" in main,
        "RX-write rejects the sender-only XOR transformation")
require("packet->segment.session_id != ctx->session_id" in validate_rx and
        "nxp_wire_mtu_layout_plan(ctx->session_id" in validate_rx,
        "RX rejects a different session before accepting its wire layout")
require("nxp_rx_frame_drop" in drop_external and
        "NXP_STAT_DROP" in drop_external and
        "nxp_latch_error" not in drop_external,
        "untrusted malformed or stale-session packets are dropped without ending the run")
require("NXP_RX_GROUP_TIMEOUT_NS" in expire_group and
        "pipeline_chain_recycle_rx_group" in expire_group and
        "*active_slot = -1" in expire_group,
        "a missing UDP segment expires and recycles its incomplete group")
require("nxp_rx_idle_poll_result" in core_text and
        "nxp_rx_idle_poll_result" in rx and "pfd.revents" in rx and
        "rx_idle_deadline_ns" in rx,
        "RX poll errors terminate and empty wakeups share an absolute deadline")
require("last_wire_generation = packet.segment.generation" in rx and
        rx.index("last_wire_generation = packet.segment.generation") >
        rx.index("nxp_wire_group_finish"),
        "RX commits generation only after a complete group so the same group can retry")
require("NXP_WIRE_MAGIC" in core_text and
        "session_id" in core_text and "NXP_WIRE_HEADER_LEN UINT8_C(40)" in
        core_text,
        "wire v2 binds CRC-protected groups to a 64-bit session")

# PIPELINE_RX_SUMMARY: one line per rx-write run whose receive loop started.
print_summary = function_body("pipeline_print_rx_summary")
require(bool(print_summary) and
        "nxp_rx_summary_report" in print_summary and
        "nxp_rx_summary_format" in print_summary and
        'printf("%s\\n", line)' in print_summary,
        "the rx summary line is derived and formatted by the core helpers")
require('#define NXP_RX_SUMMARY_TAG "PIPELINE_RX_SUMMARY"' in core_text and
        '"PIPELINE_RX_SUMMARY' not in text,
        "the summary tag has one definition, in the core header")
require(text.count("pipeline_print_rx_summary(") == 2 and
        "pipeline_print_rx_summary(" in rx and
        all("pipeline_print_rx_summary" not in body and
            "nxp_rx_summary" not in body
            for body in (tx, staging_tx, entry, main)),
        "only the rx-write executor prints the summary; TX mode never does")
rx_cpu_start = rx.find("getrusage(RUSAGE_SELF, &usage_start)")
rx_loop = rx.find("while (finished < num_groups)")
rx_cpu_end = rx.find("getrusage(RUSAGE_SELF, &usage_end)")
rx_print = rx.find("pipeline_print_rx_summary(")
rx_out = rx.find("\nout:")
require(0 <= rx_cpu_start < rx_loop < rx_cpu_end < rx_print < rx_out and
        "goto out" not in rx[rx_loop:rx_print] and
        not re.search(r"\breturn\b", rx[rx_loop:rx_print]),
        "every exit of the started receive loop reaches the summary print")
rx_census = rx.find("nxp_rx_frame_census_take(frame_states, NUM_FRAMES,")
require(0 <= rx_cpu_end < rx_census < rx_print and
        "nxp_rx_summary_note_census(" in rx[rx_census:rx_print] and
        "-EPROTO" in rx[rx_census:rx_print],
        "every frame is counted by state after the loop, before the summary print, and an outstanding one fails closed")
exit_map = main.find("nxp_stop_exit_status(ctx.first_error, teardown_error,")
require(exit_map > main.find("ret = pipeline_close_ring(&ctx);") >= 0 and
        "nxp_latch_error(&teardown_error, ret)" in main and
        "pipeline_rx_stop_signal()" in main[exit_map:],
        "a stopped rx-write run exits 128 + signal only when no other step, teardown included, failed")
ring_init = function_body("production_ring_init")
open_eventfd = function_body("pipeline_open_cq_eventfd")
ring_close = function_body("production_ring_close")
wait_cqe_or_rx = function_body("production_wait_cqe_or_rx")
rx_wait = function_body("pipeline_rx_wait_bounded")
require("pipeline_open_cq_eventfd(&ctx->uring)" in ring_init and
        "g_direction != PIPELINE_NIC_TO_NVME || g_iopoll" in ring_init and
        "io_uring_register_eventfd(&uring->ring, fd)" in open_eventfd and
        "EFD_NONBLOCK" in open_eventfd and
        0 <= ring_close.find("io_uring_queue_exit(") <
        ring_close.find("close(ctx->uring.cq_eventfd)"),
        "only rx-write without IOPOLL registers a CQ eventfd on its ring, closed after the ring")
require("ctx->uring.cq_eventfd" in wait_cqe_or_rx and
        "ctx->xsk.xsk_fd" in wait_cqe_or_rx and
        "poll(fds, 2," in wait_cqe_or_rx and
        "read(fds[0].fd" in wait_cqe_or_rx,
        "rx-write waits on WRITE completions and the RX ring in one poll(), as the traditional receiver does")
rx_in_flight = rx.find("pipeline_rx_wait_bounded(ctx, &cqe_deadline_ns, watch_rx,")
require(rx_in_flight >= 0 and
        rx.find("pipeline_handle_wait_failure(", rx_in_flight) > rx_in_flight and
        "pipeline_wait_bounded(" not in rx and
        # The reset after a reaped CQE, not the declaration's initialiser.
        re.search(r"if \(reaped\)\s*cqe_deadline_ns = 0;", rx) and
        "NXP_WAIT_TIMEOUT_NS" in rx_wait and
        "xsk_cons_nb_avail(&ctx->xsk.rx, 1)" in rx_wait,
        "rx-write notices RX while WRITEs are in flight; the completion deadline and wait-failure handling are kept")
rx_accept = rx.find("nxp_wire_group_accept(")
require(0 <= rx_accept <
        rx.find("nxp_rx_summary_note_packet(&g_rx_summary, true)") and
        rx.find("nxp_rx_summary_note_packet(&g_rx_summary, false)",
                rx.find("rx_external_drop:")) >= 0 and
        rx.find("nxp_rx_summary_note_packet(&g_rx_summary, false)",
                rx.find("rx_protocol_error:")) >= 0,
        "packets are counted with the loop's own accept and drop decisions")
require(rx.find("nxp_rx_summary_note_submitted(&g_rx_summary, accepted)") >
        rx.find("submit_prepared_batch(") >= 0 and
        rx.find("nxp_rx_summary_note_completion(") >
        rx.find("pipeline_handle_cqe(") >= 0,
        "NVMe WRITEs are counted when the kernel accepts them and when their CQE is reaped")

print(f"1..{checks}")
if failures:
    print(f"# FAIL: {failures}/{checks} source checks", file=sys.stderr)
    raise SystemExit(1)
print(f"# PASS: {checks} source checks")
