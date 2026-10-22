#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract for GPU/AF_XDP frame ownership."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SAMPLES = ROOT / "drivers/gpu/nvidia-p2p/samples"
RUNTIME = (SAMPLES / "gpu_xdp_frame_runtime.h").read_text()
IDENTITY = (ROOT / "tools/xdev_ext_gpu_identity.c").read_text()


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : pos + 1]
    raise AssertionError(f"unterminated function: {signature}")


identity_resolve = function_body(IDENTITY, "xdev_ext_gpu_identity_from_opened_with(")
bounded_bdf = identity_resolve.index("strnlen(candidates[i].bdf,")
assert "XDEV_EXT_GPU_PCI_BDF_SIZE" in identity_resolve[bounded_bdf:bounded_bdf + 120]
parse_bdf = identity_resolve.index(
    "xdev_ext_gpu_identity_is_pci_bdf(candidates[i].bdf)"
)
assert bounded_bdf < parse_bdf


reap = function_body(RUNTIME, "gpu_xdp_reap_completions(")
assert "expected_tx_addrs[frame_index] != completion_addr" in reap
complete = reap.index("xdev_ext_xsk_frame_complete_tx(")
recycle = reap.index("xdev_ext_xsk_recycle_push(")
release = reap.index("xsk_ring_cons__release(")
assert "xsk_ring_cons__comp_addr(" in reap
assert complete < recycle < release

refill = function_body(RUNTIME, "gpu_xdp_refill(")
assert "XDEV_EXT_XSK_FRAME_FREE" in refill
assert refill.index("xdev_ext_xsk_frame_to_fill(") < refill.index(
    "xsk_ring_prod__fill_addr("
)

# Autonomous GPU->NIC traffic owns a dedicated pool in APP state.  It never
# invents an RX transition, and exact TX completion is the only path back to
# the source pool.
acquire_app = function_body(RUNTIME, "gpu_xdp_frame_acquire_app(")
assert "XDEV_EXT_XSK_FRAME_FREE" in acquire_app
assert "GPU_XDP_FRAME_APP" in acquire_app
assert acquire_app.index("xdev_ext_xsk_recycle_peek(") < acquire_app.index(
    "xdev_ext_xsk_recycle_consume("
)
submit_app = function_body(RUNTIME, "gpu_xdp_frame_submit_app_tx(")
assert "GPU_XDP_FRAME_APP" in submit_app
assert "XDEV_EXT_XSK_FRAME_TX" in submit_app
assert "XDEV_EXT_XSK_FRAME_RX" not in submit_app
cancel_prod = function_body(RUNTIME, "gpu_xdp_ring_prod_cancel(")
assert "cached_prod -= reserved" in cancel_prod
sequester_unpublished = function_body(
    RUNTIME, "gpu_xdp_frame_sequester_unpublished_tx("
)
assert "XDEV_EXT_XSK_FRAME_TX" in sequester_unpublished
assert "XDEV_EXT_XSK_FRAME_SEQUESTERED" in sequester_unpublished

for name in ("gpu_xdp_p2p.c", "gpu_xdp_p2p_nocuda.c"):
    source = (SAMPLES / name).read_text()
    create_xsk = function_body(source, "static int create_xsk(")
    # These samples own their ingress setup.  The project loader avoids a
    # runtime dependency on libxdp's separately installed
    # xsk_def_xdp_prog.o, attaches a bounded redirect program, and populates
    # its XSKMAP explicitly.
    assert "XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD" in create_xsk
    assert "xdev_ext_xsk_redirect_attach(" in create_xsk
    assert "const struct xdev_ext_xsk_flow_filter *flow_filter" in source[
        source.index("static int create_xsk(") : source.index(
            "{", source.index("static int create_xsk(")
        )
    ]
    assert "flow_filter" in create_xsk[create_xsk.index(
        "xdev_ext_xsk_redirect_attach(") :]
    assert "xdev_ext_xsk_redirect_detach(" in source
    attach_failure = create_xsk.index('if (ret) {', create_xsk.index(
        "xdev_ext_xsk_redirect_attach("))
    attach_failure_end = create_xsk.index("return ret;", attach_failure)
    assert "xdev_ext_xsk_redirect_is_active(" in create_xsk[
        attach_failure:attach_failure_end
    ]

    detach_redirect = function_body(source, "static int detach_xsk_redirect(")
    assert "XSK_REDIRECT_DETACH_ATTEMPTS" in detach_redirect
    assert "xdev_ext_xsk_redirect_detach(" in detach_redirect
    assert "xdev_ext_xsk_redirect_is_active(" in detach_redirect
    assert "for (" in detach_redirect

    hold_redirect = function_body(source, "static void hold_redirect_backing(")
    for signame in ("SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"):
        assert f"signal({signame}, SIG_IGN)" in hold_redirect
    assert "for (;;)" in hold_redirect
    assert "pause()" in hold_redirect
    init = function_body(source, "static int gpu_p2p_init(")
    assert "int xsk_fd" in source[source.index("static int gpu_p2p_init(") : source.index("{", source.index("static int gpu_p2p_init("))]
    if name == "gpu_xdp_p2p.c":
        assert "pin_params.xsk_fd = xsk_fd" in init
        assert "int allow_cuda_staging" in source[
            source.index("static int gpu_p2p_init(") : source.index(
                "{", source.index("static int gpu_p2p_init(")
            )
        ]
        assert "if (!allow_cuda_staging)" in init
        assert "CUDA staging mode was explicitly requested" in init
    else:
        assert "xdev_ext_nv_p2p_pin_umem(" not in init
        assert "return -saved_errno;" in init
        prologue = source[:source.index("*/")]
        assert "long-term pin/unpin" not in prologue
        assert "NVIDIA driver with P2P UMEM support" not in prologue
    process = function_body(source, "static int process_packets(")
    assert "gpu_xdp_frame_accept_rx(" in process
    assert "gpu_xdp_frame_submit_tx(" in process
    assert "gpu_xdp_reap_completions(" in process
    assert "gpu_xdp_refill(" in process
    assert "xsk_ring_prod__fill_addr(" not in process
    submit = process.index("xsk_ring_prod__submit(&ctx->tx")
    ownership = process.index("gpu_xdp_frame_submit_tx(")
    fail_closed = process.index("return -EPROTO", ownership)
    assert ownership < fail_closed < submit
    tx_setup = process[ownership:submit]
    assert "desc_addrs[i]" in tx_setup
    assert "tx_desc->options = 0" in tx_setup
    assert submit < process.index("gpu_xdp_reap_completions(", submit)

    # Runtime/protocol failures must reach main, and an unretired TX frame is
    # ambiguous DMA ownership.  Closing the XSK is not proof of quiescence.
    run_loop = function_body(source, "static int run_loop(")
    assert "return loop_status;" in run_loop
    drain_tx = function_body(source, "static int drain_tx_completions(")
    assert "return -ETIMEDOUT;" in drain_tx
    assert "return 0;" in drain_tx

    main = function_body(source, "int main(")
    assert "atoi(" not in main
    assert "parse_gpu_id(optarg, &gpu_id)" in main
    assert "XDEV_EXT_XSK_FILTER_F_ALL" in main
    for option in ("case 'A':", "case 'a':", "case 'P':", "case 'p':"):
        assert option in main
    redirect_detach = main.index("detach_xsk_redirect(")
    still_active = main.index("xdev_ext_xsk_redirect_is_active(", redirect_detach)
    hold_active = main.index("hold_redirect_backing();", still_active)
    run = main.index("run_loop(&xsk_ctx")
    drain = main.index("if (drain_tx_completions(")
    assert "exit_status = 1;" in main[run:drain]
    assert "exit_status = 1;" in main[drain:drain + 420]
    unpin = main.index("gpu_p2p_cleanup(", drain)
    delete = main.index("xsk_socket__delete(", drain)
    assert redirect_detach < still_active < hold_active < drain < unpin < delete
    if name == "gpu_xdp_p2p.c":
        assert "gpu_ctx.dma_sequestered = 1;" in main[run:drain]
        assert "gpu_ctx.dma_sequestered = 1;" in main[drain:unpin]
        assert "hold_sequestered_backing();" in main[drain:]
    else:
        assert "backing_sequestered = true;" in main[run:drain]
        hold_unquiesced = function_body(
            source, "static void hold_unquiesced_backing("
        )
        assert "for (;;)" in hold_unquiesced
        assert "hold_unquiesced_backing();" in main[drain:unpin]

cuda = (SAMPLES / "gpu_xdp_p2p.c").read_text()
makefile = (ROOT / "Makefile.pipeline").read_text()
redirect_header = (ROOT / "tools/include/xdev_ext_xsk_redirect.h").read_text()
identity_header = (ROOT / "tools/include/xdev_ext_gpu_identity.h").read_text()

# The CUDA ordinal and the opened RM character device must identify exactly
# one PCI function.  Never silently substitute the global control node.
assert '"/dev/nvidiactl"' not in cuda
cuda_init = function_body(cuda, "static int gpu_p2p_init(")
assert '"/dev/nvidia%d"' in cuda_init
assert "open(dev_path, O_RDWR | O_CLOEXEC)" in cuda_init
assert '#include "../../../../tools/include/xdev_ext_gpu_identity.h"' in cuda
assert "static int gpu_p2p_opened_device_bdf(" not in cuda
assert "static int gpu_p2p_driver_sysfs_bdf(" not in cuda
match = function_body(cuda, "static int gpu_p2p_match_cuda_device(")
assert "cudaDeviceGetPCIBusId(" in match
assert "for (" in match
assert "matches != 1" in match
assert "matched_ordinal != gpu_id" in match
opened = cuda_init.index("open(dev_path, O_RDWR | O_CLOEXEC)")
verified = cuda_init.index("xdev_ext_gpu_identity_from_opened(", opened)
matched = cuda_init.index("gpu_p2p_match_cuda_device(", verified)
pinned = cuda_init.index("xdev_ext_nv_p2p_pin_umem(", matched)
assert "(unsigned int)gpu_id" in cuda_init[verified:matched]
assert opened < verified < matched < pinned
assert "#ifdef __cplusplus" in identity_header
assert 'extern "C" {' in identity_header

# The supported build surface always offers a CPU-only AF_XDP executable;
# systems with nvcc can additionally build the real CUDA/CE executable.
for target in ("gpu-nic:", "gpu-nic-host:"):
    assert target in makefile
assert "gpu_xdp_p2p_nocuda.c" in makefile
assert "gpu_xdp_p2p.c" in makefile
assert "$(NVCC)" in makefile
assert "tools/xdev_ext_xsk_redirect.c" in makefile
assert "NVCC_HOST_COMPILER ?= $(CXX)" in makefile
assert "#ifdef __cplusplus" in redirect_header
assert 'extern "C" {' in redirect_header
cuda_object_rule = makefile.split("$(GPU_NIC_CUDA_OBJ):", 1)[1].split(
    "$(GPU_NIC_REDIRECT_OBJ):", 1
)[0]
for dependency in ("xdev_ext_nv_p2p_ioctl.h", "xdev_ext_xsk_frame_owner.h",
                   "xdev_ext_gpu_identity.h"):
    assert dependency in cuda_object_rule
cuda_link_rule = makefile.split("gpu_xdp_p2p:", 1)[1].split("\n\n", 1)[0]
assert "$(CUDA_LDLIBS)" in cuda_link_rule
assert "$(GPU_IDENTITY_OBJ)" in cuda_link_rule
host_rule = makefile.split("gpu_xdp_p2p_nocuda:", 1)[1].split("\n\n", 1)[0]
assert host_rule.count("tools/xdev_ext_gpu_identity.c") >= 2

for signature in ("static int gpu_transfer_to_gpu(",
                  "static int gpu_transfer_from_gpu("):
    transfer = function_body(cuda, signature)
    p2p = transfer.index("xdev_ext_nv_p2p_dma_xfer(")
    fallback = transfer.index("cudaMemcpyAsync(")
    assert "return -1;" in transfer[p2p:fallback]
    assert "if (!ctx->allow_cuda_staging)" in transfer[p2p:fallback]

cuda_cleanup = function_body(cuda, "static int gpu_p2p_cleanup(")
unpin = cuda_cleanup.index("xdev_ext_nv_p2p_unpin_umem(")
unpin_failure = cuda_cleanup.index("return -1;", unpin)
close = cuda_cleanup.index("close(ctx->gpu_fd)")
free_gpu = cuda_cleanup.index("cudaFree(ctx->gpu_buffer)")
assert unpin < unpin_failure < close < free_gpu

cuda_main = function_body(cuda, "int main(")
assert 'case \'s\':' in cuda_main
assert "allow_cuda_staging = 1" in cuda_main
assert "atoi(" not in cuda_main
assert "parse_gpu_id(optarg, &gpu_id)" in cuda_main
gpu_parser = function_body(cuda, "static int parse_gpu_id(")
for token in ("strtol(", "errno", "value < 0", "value > INT_MAX"):
    assert token in gpu_parser
assert "gpu_p2p_cleanup(&gpu_ctx) == 0" in cuda_main
cleanup_ok = cuda_main.index("gpu_p2p_cleanup(&gpu_ctx) == 0")
delete_xsk = cuda_main.index("xsk_socket__delete(", cleanup_ok)
assert cleanup_ok < delete_xsk
assert "not P2P or zero-copy" in cuda

for signature in ("static int gpu_transfer_batch_to_gpu(",
                  "static int gpu_transfer_batch_from_gpu("):
    batch_transfer = function_body(cuda, signature)
    assert "struct xdev_ext_nv_p2p_dma_batch" in batch_transfer
    assert "XDEV_EXT_NV_P2P_MAX_BATCH" in batch_transfer
    assert "xdev_ext_nv_p2p_dma_batch(" in batch_transfer
    assert "stats.ce_transfers += batch.completed" in batch_transfer

cuda_process = function_body(cuda, "static int process_packets(")
to_batch = cuda_process.index("gpu_transfer_batch_to_gpu(")
kernel = cuda_process.index("gpu_process_batch(", to_batch)
kernel_completion = cuda_process.index("cudaStreamSynchronize(", kernel)
from_batch = cuda_process.index("gpu_transfer_batch_from_gpu(", kernel)
return_completion = cuda_process.index("cudaStreamSynchronize(", from_batch)
tx_submit = cuda_process.index("xsk_ring_prod__submit(&ctx->tx", from_batch)
assert to_batch < kernel < kernel_completion < from_batch
assert from_batch < return_completion < tx_submit
return_barrier = cuda_process[from_batch:return_completion]
assert "allow_cuda_staging" in return_barrier
assert "!ctx->gpu_ctx->p2p_handle" in return_barrier
assert cuda_process[to_batch:tx_submit].count("sequester_active_frames(") >= 4

# Keep the coupled round trip while exposing each direction independently.
for mode in ("GPU_XDP_MODE_ROUNDTRIP", "GPU_XDP_MODE_NIC_TO_GPU",
             "GPU_XDP_MODE_GPU_TO_NIC"):
    assert mode in cuda
mode_parser = function_body(cuda, "static int parse_mode(")
for spelling in ("roundtrip", "nic-to-gpu", "gpu-to-nic"):
    assert f'"{spelling}"' in mode_parser

sink = function_body(cuda, "static int process_nic_to_gpu(")
sink_to = sink.index("gpu_transfer_batch_to_gpu(")
sink_sync = sink.index("cudaStreamSynchronize(", sink_to)
sink_drop = sink.index("gpu_xdp_frame_drop_rx(", sink_sync)
assert sink_to < sink_sync < sink_drop
assert "gpu_transfer_batch_from_gpu(" not in sink
assert "gpu_xdp_frame_submit_tx(" not in sink
assert "sequester_active_frames(" in sink

source = function_body(cuda, "static int process_gpu_to_nic(")
source_reap = source.index("gpu_xdp_reap_completions(")
source_reserve = source.index("xsk_ring_prod__reserve(")
source_acquire = source.index("gpu_xdp_frame_acquire_app(", source_reserve)
source_dma = source.index("gpu_transfer_batch_from_gpu(", source_acquire)
source_submit_owner = source.index("gpu_xdp_frame_submit_app_tx(", source_dma)
source_submit_ring = source.index("xsk_ring_prod__submit(", source_submit_owner)
assert source_reap < source_reserve < source_acquire < source_dma
assert source_dma < source_submit_owner < source_submit_ring
assert "gpu_transfer_batch_to_gpu(" not in source
assert "gpu_xdp_frame_accept_rx(" not in source
assert "sequester_source_frames(" in source
assert "gpu_xdp_reap_completions(" in source
source_staging_sync = source.index("cudaStreamSynchronize(", source_dma)
assert source_dma < source_staging_sync < source_submit_owner
assert "uint32_t reserved" in source
# Every exit after a successful producer reservation and before publication
# rolls back the exact reservation.  The defensive partial APP->TX failure
# sequesters those unpublished frames instead of recycling them.
assert source.count("gpu_xdp_ring_prod_cancel(&ctx->tx, reserved)") >= 5
partial_submit_failure = source.index("if (ret) {", source_submit_owner)
partial_submit_return = source.index("return ret;", partial_submit_failure)
partial_submit_block = source[partial_submit_failure:partial_submit_return]
assert "gpu_xdp_ring_prod_cancel(&ctx->tx, reserved)" in partial_submit_block
assert "sequester_unpublished_source_frames(" in partial_submit_block

source_template = function_body(cuda, "static int build_source_packet(")
for field in ("h_source", "h_dest", "saddr", "daddr", "source", "dest"):
    assert field in source_template
assert "GPU_XDP_FLOW_MAGIC" in source_template
assert "ipv4_checksum(" in source_template
prepare_template = function_body(cuda, "static int gpu_prepare_source_templates(")
template_copy = prepare_template.index("cudaMemcpyAsync(")
template_sync = prepare_template.index("cudaStreamSynchronize(", template_copy)
assert template_copy < template_sync

cuda_create_xsk = function_body(cuda, "static int create_xsk(")
assert cuda_create_xsk.count("mode != GPU_XDP_MODE_GPU_TO_NIC") >= 2
assert "gpu_xdp_refill(" in cuda_create_xsk
assert "xdev_ext_xsk_redirect_attach(" in cuda_create_xsk

cuda_run_loop = function_body(cuda, "static int run_loop(")
assert "process_packets(ctx)" in cuda_run_loop
assert "process_nic_to_gpu(ctx)" in cuda_run_loop
assert "process_gpu_to_nic(" in cuda_run_loop
fatal_events = cuda_run_loop.index("POLLERR | POLLHUP | POLLNVAL")
first_datapath = min(cuda_run_loop.index("process_packets(ctx)"),
                     cuda_run_loop.index("process_nic_to_gpu(ctx)"),
                     cuda_run_loop.index("process_gpu_to_nic("))
assert fatal_events < first_datapath
assert "fds[0].revents & POLLIN" in cuda_run_loop
assert "fds[0].revents & POLLOUT" in cuda_run_loop
assert "ret == 0" in cuda_run_loop

# Roundtrip TX completions must keep moving even after ingress goes quiet.
# POLLOUT is armed for one maintenance opportunity after RX work, then
# disarmed so an always-writable XSK cannot turn the loop into a busy spin;
# the timeout remains an independent CQ/FQ progress path.  The sink has no
# TX work and therefore waits only for ingress.
#
# Substring presence cannot tell "POLLIN" from "POLLIN | POLLOUT", or a
# timeout condition from one that also requires the armed flag.  So this
# contract strips comments, tokenizes, splits the bodies into C statements,
# and evaluates the loop's poll-mask and trigger conditions over every
# reachable (mode, armed, ret, revents) state.  It then checks that those
# states are what the conditions see and that a roundtrip timeout reaches
# the maintenance block: poll() keeps its timeout, ret and revents are not
# rewritten, the poll array has one spelling, and only four known exits may
# leave an iteration.  Layout, comments and operand order are free; a change
# in what the loop waits for, or in whether a timeout maintains, fails here.
C_TOKEN = re.compile(r"""
    \s+
  | (?P<tok>
        "(?:\\.|[^"\\])*" | '(?:\\.|[^'\\])*'
      | [A-Za-z_]\w* | \d\w*
      | -> | \+\+ | -- | <<= | >>= | << | >> | <= | >= | == | != | && | \|\|
      | [-+*/%&|^]= | [{}()\[\];,.<>=!&|^~?:+*/%-]
    )""", re.X)
C_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
            "++", "--"}


def strip_comments(text: str) -> str:
    out, pos = [], 0
    while pos < len(text):
        if text.startswith("/*", pos):
            pos = text.index("*/", pos + 2) + 2
            out.append(" ")
        elif text.startswith("//", pos):
            end = text.find("\n", pos)
            pos = len(text) if end < 0 else end
        elif text[pos] in "\"'":
            end = pos + 1
            while text[end] != text[pos]:
                end += 2 if text[end] == "\\" else 1
            out.append(text[pos:end + 1])
            pos = end + 1
        else:
            out.append(text[pos])
            pos += 1
    return "".join(out)


def c_tokens(text: str) -> list:
    tokens, pos = [], 0
    while pos < len(text):
        match = C_TOKEN.match(text, pos)
        assert match, f"untokenizable C near {text[pos:pos + 40]!r}"
        if match.group("tok"):
            tokens.append(match.group("tok"))
        pos = match.end()
    return tokens


class CStmt:
    def __init__(self, kind, tokens, cond=None, body=None, orelse=None,
                 block=None):
        self.kind, self.tokens, self.cond = kind, tokens, cond
        self.body, self.orelse, self.block = body, orelse, block


def close_paren(tokens, pos):
    assert tokens[pos] == "(", tokens[pos:pos + 5]
    depth = 0
    for end in range(pos, len(tokens)):
        depth += {"(": 1, ")": -1}.get(tokens[end], 0)
        if depth == 0:
            return end + 1
    raise AssertionError("unbalanced parenthesis")


def parse_c_stmt(tokens, pos):
    head = tokens[pos]
    if head == "{":
        block, end = parse_c_block(tokens, pos)
        return CStmt("block", tokens[pos:end], block=block), end
    if head in ("if", "while", "for", "switch"):
        cond_end = close_paren(tokens, pos + 1)
        body, end = parse_c_stmt(tokens, cond_end)
        orelse = None
        if head == "if" and end < len(tokens) and tokens[end] == "else":
            orelse, end = parse_c_stmt(tokens, end + 1)
        return CStmt(head, tokens[pos:end], cond=tokens[pos + 2:cond_end - 1],
                     body=body, orelse=orelse), end
    depth, end = 0, pos
    while depth or tokens[end] != ";":
        depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(
            tokens[end], 0)
        end += 1
    return CStmt("simple", tokens[pos:end + 1]), end + 1


def parse_c_block(tokens, pos=0):
    assert tokens[pos] == "{", tokens[pos:pos + 5]
    stmts, pos = [], pos + 1
    while tokens[pos] != "}":
        stmt, pos = parse_c_stmt(tokens, pos)
        stmts.append(stmt)
    return stmts, pos + 1


def c_function(source: str, signature: str) -> list:
    text = strip_comments(source)
    assert signature in text, f"missing function {signature}...)"
    tokens = c_tokens(function_body(text, signature))
    stmts, end = parse_c_block(tokens)
    assert end == len(tokens)
    return stmts


C_BINARY = (("||",), ("&&",), ("|",), ("&",), ("==", "!="),
            ("<", ">", "<=", ">="))
C_APPLY = {"||": lambda a, b: int(bool(a or b)),
           "&&": lambda a, b: int(bool(a and b)),
           "|": lambda a, b: a | b, "&": lambda a, b: a & b,
           "==": lambda a, b: int(a == b), "!=": lambda a, b: int(a != b),
           "<": lambda a, b: int(a < b), ">": lambda a, b: int(a > b),
           "<=": lambda a, b: int(a <= b), ">=": lambda a, b: int(a >= b)}


def c_eval(tokens, env):
    """Evaluate a side-effect-free C condition with C precedence.  Any
    operand or operator outside this small subset fails the contract."""
    pos = 0

    def take():
        nonlocal pos
        assert pos < len(tokens), f"truncated C: {' '.join(tokens)}"
        pos += 1
        return tokens[pos - 1]

    def operand():
        tok = take()
        if tok == "!":
            return int(not operand())
        if tok == "(":
            value = binary(0)
            assert take() == ")", tokens
            return value
        if tok.isdigit():
            return int(tok)
        assert re.fullmatch(r"[A-Za-z_]\w*", tok), (tok, tokens)
        name = tok
        while pos < len(tokens) and tokens[pos] in ("[", "."):
            if take() == "[":
                name += "[" + take() + take()
            else:
                name += "." + take()
        assert name in env, f"unexpected operand {name} in {' '.join(tokens)}"
        return env[name]

    def binary(level):
        if level == len(C_BINARY):
            return operand()
        value = binary(level + 1)
        while pos < len(tokens) and tokens[pos] in C_BINARY[level]:
            op = take()
            value = C_APPLY[op](value, binary(level + 1))
        return value

    value = binary(0)
    assert pos == len(tokens), f"unparsed C: {' '.join(tokens[pos:])}"
    return value


def assignments(tokens, target):
    """Number of writes to target (=, compound assignment, ++/--, prefix
    ++/--)."""
    lhs = c_tokens(target)
    return sum(1 for i in range(len(tokens) - len(lhs))
               if tokens[i:i + len(lhs)] == lhs
               and (tokens[i + len(lhs)] in C_ASSIGN
                    or i > 0 and tokens[i - 1] in ("++", "--")))


def run_chain(stmt, target, env, initial):
    """Value written to target by an if/else-if/else chain whose every arm
    is exactly '<target> = <expr>;' (bare or as the only braced statement)."""
    lhs = c_tokens(target)
    while stmt is not None:
        if stmt.kind == "if":
            cond, arm, stmt = stmt.cond, stmt.body, stmt.orelse
        else:
            cond, arm, stmt = None, stmt, None
        if arm.kind == "block" and len(arm.block) == 1:
            arm = arm.block[0]
        assert (arm.kind == "simple" and arm.tokens[:len(lhs) + 1] == lhs +
                ["="]), f"arm is not '{target} = ...;': {' '.join(arm.tokens)}"
        if cond is None or c_eval(cond, env):
            return c_eval(arm.tokens[len(lhs) + 1:-1], env)
    return initial


def only_stmt(stmts, predicate, what):
    found = [i for i, stmt in enumerate(stmts) if predicate(stmt)]
    assert len(found) == 1, f"expected exactly one {what}, found {len(found)}"
    return found[0]


def is_tokens(text):
    expected = c_tokens(text)
    return lambda stmt: stmt.tokens == expected


def writes(target):
    return lambda stmt: assignments(stmt.tokens, target) > 0


POLLIN, POLLOUT = 0x1, 0x4
RT = "GPU_XDP_MODE_ROUNDTRIP"
SINK = "GPU_XDP_MODE_NIC_TO_GPU"
SRC = "GPU_XDP_MODE_GPU_TO_NIC"
LOOP_ENV = {"POLLIN": POLLIN, "POLLOUT": POLLOUT, RT: 0, SINK: 1, SRC: 2}


def selection(target, initial=0):
    """The one statement choosing a trigger: an if/else chain or a plain
    assignment, but not the per-iteration '= @initial' declaration."""
    reset = is_tokens(f"int {target} = {initial};")
    return lambda stmt: writes(target)(stmt) and not reset(stmt)


def substituted(stmt, names):
    """@stmt with each C expression in @names (C text -> operand name)
    replaced by that operand name in its condition and in its arms, so that
    c_eval() can evaluate a condition that calls a function."""
    if stmt is None:
        return None
    seqs = [(c_tokens(text), name) for text, name in names.items()]

    def sub(tokens):
        if tokens is None:
            return None
        out, pos = [], 0
        while pos < len(tokens):
            for seq, name in seqs:
                if tokens[pos:pos + len(seq)] == seq:
                    out.append(name)
                    pos += len(seq)
                    break
            else:
                out.append(tokens[pos])
                pos += 1
        return out

    return CStmt(stmt.kind, sub(stmt.tokens), cond=sub(stmt.cond),
                 body=substituted(stmt.body, names),
                 orelse=substituted(stmt.orelse, names),
                 block=None if stmt.block is None else
                 [substituted(inner, names) for inner in stmt.block])


def macro_value(source, name):
    match = re.search(rf"^#define\s+{name}\s+(\d+)\b", source, re.M)
    assert match, f"missing '#define {name} <number>'"
    return int(match.group(1))


TX_NAMES = {"tx_ring_pending(ctx)": "tx_pending",
            "ctx->tx_copy_mode": "tx_copy_mode",
            "xsk_ring_prod__needs_wakeup(&ctx->tx)": "tx_needs_wakeup"}


def check_tx_retry(source, maintenance, maintenance_refill):
    """Copy mode (the XDP_FLAGS_SKB_MODE fallback) transmits only when
    sendto() or poll() runs the kernel's transmit pass, at most 32
    descriptors per pass, and a pass that hits -EAGAIN leaves descriptors on
    the TX ring for userspace to retry.  So the sample knows when TX waits
    (the kernel's consumer index is behind what was published), records copy
    mode where the fallback bind succeeds, kicks with a non-blocking sendto()
    in copy mode or when the TX ring asks for a wakeup, sends both of its TX
    kicks through that rule, and kicks again from maintenance while TX
    waits.  The run-loop side (short re-poll) is checked with the poll."""
    pending = c_function(source, "static int tx_ring_pending(")
    assert [stmt.tokens for stmt in pending] == [c_tokens(
        "return xsk_prod_nb_free(&ctx->tx, ctx->tx.size) < ctx->tx.size;")], \
        "tx_ring_pending() must compare the TX consumer with the producer"

    kick = c_function(source, "static void kick_tx(")
    assert len(kick) == 1 and kick[0].kind == "if" and \
        kick[0].orelse is None, "kick_tx() must be one if statement"
    send = kick[0].body
    if send.kind == "block" and len(send.block) == 1:
        send = send.block[0]
    assert send.tokens == c_tokens("(void)sendto(xsk_socket__fd(ctx->xsk), "
                                   "NULL, 0, MSG_DONTWAIT, NULL, 0);"), \
        "kick_tx() must kick with a non-blocking sendto()"
    cond = substituted(kick[0], TX_NAMES).cond
    for copy in (0, 1):
        for wakeup in (0, 1):
            got = c_eval(cond, {"tx_copy_mode": copy,
                                "tx_needs_wakeup": wakeup})
            want = int(bool(copy or wakeup))
            assert bool(got) == bool(want), (
                f"kick_tx(), copy mode={copy} needs wakeup={wakeup}: "
                f"kicks={int(bool(got))}, expected {want}")

    # The copy-mode bind is the only place that records copy mode, after its
    # own failure exit; nothing else writes the flag.
    all_tokens = c_tokens(re.sub(r"(?m)^[ \t]*#(?:.*\\\n)*.*$", " ",
                                 strip_comments(source)))
    copy_writes = [i for i, tok in enumerate(all_tokens)
                   if tok == "tx_copy_mode" and
                   (all_tokens[i + 1] in C_ASSIGN or
                    all_tokens[i - 1] in ("++", "--"))]
    assert len(copy_writes) == 1, "exactly one write to tx_copy_mode"
    create = c_function(source, "static int create_xsk(")
    fallback = only_stmt(
        create, lambda s: s.kind == "if" and s.body.kind == "block" and any(
            is_tokens("cfg.xdp_flags = XDP_FLAGS_SKB_MODE;")(inner)
            for inner in s.body.block), "copy-mode fallback")
    fallback = create[fallback].body.block
    rebind = only_stmt(fallback, lambda s: "xsk_socket__create" in s.tokens,
                       "copy-mode bind")
    rebind_fail = fallback[rebind + 1]
    assert rebind_fail.kind == "if" and rebind_fail.cond == ["ret"] and \
        rebind_fail.body.block[-1].tokens == c_tokens("return ret;"), \
        "the copy-mode bind must be followed by its failure exit"
    record = only_stmt(fallback, is_tokens("ctx->tx_copy_mode = 1;"),
                       "copy-mode record")
    assert rebind + 1 < record, \
        "copy mode is recorded only after the copy-mode bind succeeded"

    # process_packets() kicks the TX it just published through kick_tx().
    process = c_function(source, "static int process_packets(")
    assert "sendto" not in [tok for stmt in process for tok in stmt.tokens], \
        "process_packets() must kick TX through kick_tx()"
    submit = only_stmt(
        process, is_tokens("if (ret) xsk_ring_prod__submit(&ctx->tx, ret);"),
        "TX submit")
    process_kick = only_stmt(process, lambda s: "kick_tx" in s.tokens,
                             "RX-batch TX kick")
    assert submit < process_kick and is_tokens("if (ret) kick_tx(ctx);")(
        process[process_kick]), "process_packets() must kick after submit"

    # Maintenance kicks waiting TX after its fail-closed reap and refill.
    maintenance_kick = only_stmt(maintenance,
                                 lambda s: "kick_tx" in s.tokens,
                                 "maintenance TX kick")
    assert is_tokens("if (tx_ring_pending(ctx)) kick_tx(ctx);")(
        maintenance[maintenance_kick]), \
        "maintenance must kick TX exactly while TX descriptors wait"
    assert maintenance_refill + 1 < maintenance_kick < len(maintenance) - 1, \
        "the maintenance TX kick follows the refill failure exit"


def check_roundtrip_poll_loop(source, modes, tx_retry=False):
    """The run-loop contract for a sample whose datapaths are @modes;
    @tx_retry: TX may wait on the ring for a retry (copy mode)."""
    # maintain_roundtrip(): reap the CQ first and stop fail-closed on a reap
    # failure, so only an exact TX completion returns a frame to FREE; then
    # refill the FQ from those FREE frames and stop fail-closed on a refill
    # failure; the FQ wakeup follows the refill, so the kernel sees the new
    # FILL entries.
    maintenance = c_function(source, "static int maintain_roundtrip(")
    maintenance_tokens = [tok for stmt in maintenance for tok in stmt.tokens]
    for call in ("gpu_xdp_reap_completions", "gpu_xdp_refill",
                 "xsk_ring_prod__needs_wakeup"):
        assert maintenance_tokens.count(call) == 1, call
    reap_prefix = c_tokens(
        "reaped = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq,")
    refill_prefix = c_tokens("ret = gpu_xdp_refill(&ctx->frames, &ctx->fq,")
    wakeup_cond = c_tokens("xsk_ring_prod__needs_wakeup(&ctx->fq)")
    maintenance_reap = only_stmt(
        maintenance, lambda s: s.tokens[:len(reap_prefix)] == reap_prefix,
        "top-level CQ reap")
    maintenance_refill = only_stmt(
        maintenance, lambda s: s.tokens[:len(refill_prefix)] == refill_prefix,
        "top-level FQ refill")
    maintenance_wakeup = only_stmt(
        maintenance, lambda s: s.kind == "if" and s.cond == wakeup_cond,
        "top-level FQ wakeup")
    assert maintenance_reap < maintenance_refill < maintenance_wakeup, \
        "maintain_roundtrip must reap, then refill, then wake the FQ"
    assert is_tokens("if (reaped < 0) { running = 0; return reaped; }")(
        maintenance[maintenance_reap + 1]), "reap failure must stop first"
    assert is_tokens("if (ret < 0) { running = 0; return ret; }")(
        maintenance[maintenance_refill + 1]), "refill failure must stop first"
    if tx_retry:
        check_tx_retry(source, maintenance, maintenance_refill)
    else:
        assert "kick_tx" not in maintenance_tokens

    run_loop_stmts = c_function(source, "static int run_loop(")
    run_loop_tokens = [tok for stmt in run_loop_stmts for tok in stmt.tokens]
    loop_index = only_stmt(
        run_loop_stmts, lambda s: s.kind == "while" and s.cond == ["running"],
        "while (running) loop")
    assert run_loop_stmts[loop_index].body.kind == "block"
    loop = run_loop_stmts[loop_index].body.block
    armed_decl = only_stmt(run_loop_stmts,
                           is_tokens("int roundtrip_pollout_armed = 0;"),
                           "disarmed roundtrip_pollout_armed declaration")
    assert armed_decl < loop_index

    # Per-iteration order: fresh trigger flags, the mask chosen from the armed
    # state, poll(), fatal revents before any datapath work, then the triggers,
    # RX work, and maintenance.
    loop_process_decl = only_stmt(loop, is_tokens("int should_process = 0;"),
                                  "per-iteration should_process reset")
    loop_maintain_decl = only_stmt(loop, is_tokens("int should_maintain = 0;"),
                                   "per-iteration should_maintain reset")
    loop_mask = only_stmt(loop, writes("fds[0].events"), "poll-mask selection")
    loop_revents = only_stmt(loop, is_tokens("fds[0].revents = 0;"),
                             "revents reset")
    loop_poll = only_stmt(loop, lambda s: "poll" in s.tokens, "poll() call")
    loop_fatal = only_stmt(
        loop, lambda s: s.kind == "if" and "POLLERR" in s.cond,
        "fatal revents")
    loop_process_chain = only_stmt(loop, selection("should_process"),
                                  "should_process selection")
    loop_maintain_chain = only_stmt(loop, selection("should_maintain"),
                                    "should_maintain selection")
    loop_process = only_stmt(
        loop, lambda s: s.kind == "if" and s.cond == ["should_process"],
        "RX work block")
    loop_maintain = only_stmt(
        loop, lambda s: s.kind == "if" and s.cond == ["should_maintain"],
        "maintenance block")
    assert max(loop_process_decl, loop_maintain_decl) < loop_mask
    assert loop_mask < loop_revents < loop_poll < loop_fatal
    assert loop_fatal < loop_process_chain < loop_maintain_chain
    assert loop_maintain_chain < loop_process < loop_maintain
    mask_chain = loop[loop_mask]
    process_chain = loop[loop_process_chain]
    maintain_chain = loop[loop_maintain_chain]
    assert mask_chain.kind == "if"

    # Nothing else writes the mask or the triggers (no pre-loop mask, no
    # "events |= POLLOUT" after the selection, no extra trigger elsewhere).
    for target, chain, declared in (("fds[0].events", mask_chain, 0),
                                    ("should_process", process_chain, 1),
                                    ("should_maintain", maintain_chain, 1)):
        assert assignments(run_loop_tokens, target) == declared + assignments(
            chain.tokens, target), target

    # The poll mask, over every mode and armed state.
    expected_mask = {(SRC, 0): POLLOUT, (SRC, 1): POLLOUT,
                     (RT, 0): POLLIN, (RT, 1): POLLIN | POLLOUT,
                     (SINK, 0): POLLIN, (SINK, 1): POLLIN}
    expected_mask = {key: mask for key, mask in expected_mask.items()
                     if key[0] in modes}
    for (mode, armed), mask in expected_mask.items():
        env = dict(LOOP_ENV, mode=LOOP_ENV[mode],
                   roundtrip_pollout_armed=armed)
        got = run_chain(mask_chain, "fds[0].events", env, None)
        assert got == mask, (f"{mode} armed={armed} polls for "
                             f"{got if got is None else hex(got)}, "
                             f"expected {mask:#x}")

    # The single POLLOUT opportunity is armed by successful roundtrip RX work
    # only: after the RX failure exit, as the last RX-block statement.
    rx_block = loop[loop_process].body
    assert rx_block.kind == "block"
    rx_arm = only_stmt(rx_block.block, writes("roundtrip_pollout_armed"),
                       "RX arming statement")
    rx_fail = only_stmt(rx_block.block,
                        lambda s: s.kind == "if" and s.cond ==
                        c_tokens("process_ret < 0"), "RX failure exit")
    assert rx_fail < rx_arm == len(rx_block.block) - 1
    for mode in modes:
        for process_ret in (0, 1, 64):
            for armed in (0, 1):
                env = dict(LOOP_ENV, mode=LOOP_ENV[mode],
                           process_ret=process_ret,
                           roundtrip_pollout_armed=armed)
                got = run_chain(rx_block.block[rx_arm],
                                "roundtrip_pollout_armed", env, armed)
                want = int(process_ret > 0) if mode == RT else armed
                assert bool(got) == bool(want), (mode, process_ret, armed, got)

    # Maintenance: one call, immediately followed by an unconditional disarm,
    # and a failed reap/refill is an ownership failure that reaches main
    # through loop_status.  Exactly three writes to the armed flag exist: the
    # disarmed declaration, RX arming, and this disarm.
    maintain_block = loop[loop_maintain].body
    assert maintain_block.kind == "block"
    assert run_loop_tokens.count("maintain_roundtrip") == 1, \
        "maintain_roundtrip must be called only from the maintenance block"
    assert is_tokens("int maintain_ret = maintain_roundtrip(ctx);")(
        maintain_block.block[0])
    assert is_tokens("roundtrip_pollout_armed = 0;")(
        maintain_block.block[1]), \
        "maintenance must disarm POLLOUT unconditionally, right after the call"
    assert assignments(run_loop_tokens, "roundtrip_pollout_armed") == 3, \
        "only the declaration, RX arming and maintenance disarm may write it"
    maintain_fail = maintain_block.block[2]
    assert maintain_fail.kind == "if"
    assert maintain_fail.cond == c_tokens("maintain_ret < 0")
    assert [stmt.tokens for stmt in maintain_fail.body.block][-2:] == [
        c_tokens("loop_status = maintain_ret;"), c_tokens("break;")], \
        "a maintenance failure must reach main through loop_status"

    # The RX and maintenance triggers over every reachable poll() outcome.  A
    # timeout (ret == 0) leaves revents 0; otherwise poll() reports a non-empty
    # subset of the requested mask (fatal revents already left the loop).
    for (mode, armed), mask in expected_mask.items():
        if armed and mode != RT:
            continue  # unreachable: only roundtrip RX work arms (table above)
        outcomes = [(0, 0)] + [(1, revents) for revents in
                               (POLLIN, POLLOUT, POLLIN | POLLOUT)
                               if revents & ~mask == 0]
        for ret, revents in outcomes:
            env = dict(LOOP_ENV, mode=LOOP_ENV[mode], ret=ret,
                       roundtrip_pollout_armed=armed)
            env["fds[0].revents"] = revents
            process = run_chain(process_chain, "should_process", env, 0)
            if mode == SRC:
                want_process = ret == 0 or revents & POLLOUT
            else:
                want_process = ret > 0 and revents & POLLIN
            assert bool(process) == bool(want_process), (mode, armed, ret,
                                                         revents)
            env["should_process"] = process
            maintain = run_chain(maintain_chain, "should_maintain", env, 0)
            # Every roundtrip timeout maintains, armed or not (no quiet-period
            # stall); an armed POLLOUT with no RX work is consumed by exactly
            # this maintenance (no busy spin); the sink and source never do.
            want_maintain = mode == RT and (
                ret == 0 or (armed and not process and revents & POLLOUT))
            assert bool(maintain) == bool(want_maintain), (
                f"{mode} armed={armed} ret={ret} revents={revents:#x}: "
                f"should_maintain={maintain}, "
                f"expected {int(bool(want_maintain))}")

    # Reachability.  The tables above hold only if the conditions see what
    # poll() returned and every roundtrip timeout gets to the maintenance
    # block.  poll() keeps a finite, non-zero timeout (none: the quiet-period
    # stall returns; zero: every iteration is a timeout, a busy spin).  Its
    # error exit directly follows it and leaves only on ret < 0.  ret and
    # revents have one write each, and the poll array is used only as
    # fds[0].<field>, so no other spelling rewrites the mask or the outcome.
    # Only the poll() error exit, the fatal check (never taken on a timeout,
    # its only jump the final break), the RX failure exit and the maintenance
    # failure exit may leave an iteration.
    POLLERR, POLLHUP, POLLNVAL = 0x8, 0x10, 0x20
    JUMPS = {"continue", "break", "return", "goto"}
    if not tx_retry:
        assert is_tokens("int ret = poll(fds, 1, 1000);")(loop[loop_poll]), \
            "poll() must keep its finite, non-zero timeout"
    else:
        # The kernel's write-space wakeup is POLLOUT-keyed and does not wake
        # a POLLIN-only wait, so TX left after -EAGAIN would wait the whole
        # timeout.  While TX waits, poll() gets the short retry timeout,
        # whose expiry runs the maintenance kick; an empty TX ring keeps the
        # full 1000 ms (no idle spin).  The timeout is chosen per iteration
        # before poll() and written nowhere else.
        retry_ms = macro_value(source, "TX_RETRY_POLL_MS")
        assert 0 < retry_ms < 1000, \
            f"TX_RETRY_POLL_MS={retry_ms} must be a short, non-zero timeout"
        assert is_tokens("int ret = poll(fds, 1, poll_timeout_ms);")(
            loop[loop_poll]), "poll() must use the per-iteration timeout"
        timeout_decl = only_stmt(loop,
                                 is_tokens("int poll_timeout_ms = 1000;"),
                                 "per-iteration full poll timeout")
        timeout_pick = only_stmt(loop, selection("poll_timeout_ms", 1000),
                                 "poll timeout selection")
        assert timeout_decl < timeout_pick < loop_poll
        assert assignments(run_loop_tokens, "poll_timeout_ms") == 1 + \
            assignments(loop[timeout_pick].tokens, "poll_timeout_ms"), \
            "only the declaration and the selection may set the timeout"
        pick = substituted(loop[timeout_pick], TX_NAMES)
        for tx_pending in (0, 1):
            env = {"tx_pending": tx_pending, "TX_RETRY_POLL_MS": retry_ms}
            got = run_chain(pick, "poll_timeout_ms", env, 1000)
            want = retry_ms if tx_pending else 1000
            assert got == want, (f"TX pending={tx_pending}: poll timeout "
                                 f"{got}, expected {want}")
    loop_poll_err = only_stmt(
        loop, lambda s: s.kind == "if" and s.cond == c_tokens("ret < 0"),
        "poll() error exit")
    assert loop_poll + 1 == loop_poll_err < loop_fatal, \
        "the poll() error exit must directly follow poll()"
    assert is_tokens('if (ret < 0) { if (errno == EINTR) continue; '
                     'perror("poll"); loop_status = -errno; break; }')(
        loop[loop_poll_err]), "poll() error exit must not absorb timeouts"
    for target in ("ret", "fds[0].revents"):
        assert assignments(run_loop_tokens, target) == 1, \
            f"{target} must have exactly one write"
    for i, tok in enumerate(run_loop_tokens):
        if tok == "fds":
            assert (run_loop_tokens[i + 1:i + 5] == ["[", "0", "]", "."]
                    or run_loop_tokens[i - 2:i] == ["poll", "("]
                    or run_loop_tokens[i - 2:i + 5] ==
                    c_tokens("struct pollfd fds[1];")), \
                ("poll array used outside fds[0].field: "
                 f"{run_loop_tokens[i:i + 4]}")

    fatal = loop[loop_fatal]
    fatal_outcomes = [(0, 0)] + [
        (1, ready | bad) for ready in (0, POLLIN, POLLOUT, POLLIN | POLLOUT)
        for bad in (0, POLLERR, POLLHUP, POLLNVAL) if ready | bad]
    for mode in modes:
        for ret, revents in fatal_outcomes:
            env = dict(LOOP_ENV, POLLERR=POLLERR, POLLHUP=POLLHUP,
                       POLLNVAL=POLLNVAL, mode=LOOP_ENV[mode], ret=ret)
            env["fds[0].revents"] = revents
            want_fatal = (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0
            assert bool(c_eval(fatal.cond, env)) == want_fatal, (
                f"fatal check, {mode} ret={ret} revents={revents:#x}: "
                f"expected {int(want_fatal)}")
    assert fatal.orelse is None and fatal.body.kind == "block"
    assert fatal.body.block[-1].tokens == ["break", ";"], \
        "the fatal check must end with break"
    for stmt in fatal.body.block[:-1]:
        assert not JUMPS & set(stmt.tokens), \
            f"unexpected fatal-check exit: {' '.join(stmt.tokens)}"

    exits = {loop_poll_err, loop_fatal, loop_process, loop_maintain}
    for i, stmt in enumerate(loop):
        if i not in exits:
            assert not JUMPS & set(stmt.tokens), \
                f"unexpected loop exit: {' '.join(stmt.tokens)}"
    for i, stmt in enumerate(rx_block.block):
        allowed = (JUMPS if i == rx_fail else
                   {"break"} if stmt.kind == "switch" else set())
        assert not (JUMPS - allowed) & set(stmt.tokens), \
            f"unexpected RX-block exit: {' '.join(stmt.tokens)}"
    for stmt in maintain_block.block:
        if stmt is not maintain_fail:
            assert not JUMPS & set(stmt.tokens), \
                f"unexpected maintenance exit: {' '.join(stmt.tokens)}"


# The CUDA sample has all three datapaths.  The no-CUDA sample has only the
# roundtrip datapath and follows the same rules: no busy spin on an always
# writable socket, fatal revents before any datapath work, and CQ/FQ
# maintenance on the timeout and on the one POLLOUT armed after RX work.
# The no-CUDA sample falls back to a copy-mode socket, where TX waits on the
# ring for userspace retries; the CUDA sample binds zero-copy only, and a
# zero-copy driver's NAPI drains the TX ring itself.
for sample, sample_modes, tx_retry in (
        ("gpu_xdp_p2p.c", (RT, SINK, SRC), False),
        ("gpu_xdp_p2p_nocuda.c", (RT,), True)):
    try:
        check_roundtrip_poll_loop((SAMPLES / sample).read_text(),
                                  sample_modes, tx_retry)
    except (AssertionError, ValueError) as err:
        raise AssertionError(f"{sample} run loop: {err}") from err

assert "parse_mac(" in cuda
assert "source_mac_set" in cuda_main
assert "destination_mac_set" in cuda_main
assert "Source mode requires both -S and -D MAC addresses" in cuda_main
gpu_kernel = function_body(cuda, "__global__ void gpu_process_packets(")
for field in ("h_source", "h_dest", "saddr", "daddr", "source", "dest"):
    assert field in gpu_kernel
assert "sizeof(structethhdr)+sizeof(structiphdr)+sizeof(structudphdr)" in "".join(
    gpu_kernel.split()
)
nocuda = (SAMPLES / "gpu_xdp_p2p_nocuda.c").read_text()
cpu_kernel = function_body(nocuda, "static void cpu_process_packet(")
for field in ("h_source", "h_dest", "saddr", "daddr", "source", "dest"):
    assert field in cpu_kernel

# Packets sit at frame-aligned offsets, so in the packet rewrite the IPv4
# header (offset 14) is at an address that is 2 mod 4.  Reading saddr/daddr
# through a struct iphdr pointer there is undefined behaviour in C and a
# misaligned-address fault in CUDA device code; the UDP header (offset 34)
# is 2-byte aligned only because the IPv4 header is exactly 20 bytes.  So
# the rewrite copies the IPv4 and UDP headers into local structs through
# byte pointers and copies them back, and this contract rejects the other
# ways to reach a header field: a pointer to struct iphdr or struct udphdr,
# a cast to or a declaration of a pointer to anything but bytes, void or the
# packed struct ethhdr (alignment 1), '->' through anything but such an
# ethhdr pointer, and a call to anything but memcpy or offsetof (a helper
# would take the access out of this check).  It runs on the comment-stripped
# token stream.
REWRITE_POINTEES = {("uint8_t",), ("__u8",), ("char",), ("unsigned", "char"),
                    ("signed", "char"), ("void",), ("struct", "ethhdr")}
C_QUALIFIERS = {"const", "volatile", "restrict", "__restrict",
                "__restrict__"}
C_KEYWORDS = {"return", "goto", "case", "sizeof", "if", "else", "while",
              "for", "switch", "do", "break", "continue", "default"}
C_IDENT = re.compile(r"[A-Za-z_]\w*")


def check_rewrite_header_access(source, signature):
    tokens = c_tokens(function_body(strip_comments(source), signature))

    def ident(pos):
        return pos < len(tokens) and bool(C_IDENT.fullmatch(tokens[pos]))

    def run_end(pos):
        while ident(pos):
            pos += 1
        return pos

    def stars_end(pos):
        """End of a '*'/qualifier sequence at pos, and its '*' count."""
        stars = 0
        while pos < len(tokens) and (tokens[pos] == "*" or
                                     tokens[pos] in C_QUALIFIERS):
            stars += tokens[pos] == "*"
            pos += 1
        return pos, stars

    def pointee(run, what):
        target = tuple(tok for tok in run if tok not in C_QUALIFIERS)
        assert target in REWRITE_POINTEES, (
            f"{what} to '{' '.join(target)}': only byte, void and "
            "struct ethhdr pointers may address the packet")
        return target

    def statement_start(pos):
        return (tokens[pos - 1] in (";", "{", "}") or
                tokens[pos - 2:pos] == ["for", "("])

    ethhdr_pointers = set()
    for i, tok in enumerate(tokens):
        if tok in ("iphdr", "udphdr"):
            context = " ".join(tokens[max(i - 3, 0):i + 3])
            assert tokens[i - 1] == "struct", f"'{tok}' in '{context}'"
            operand = (tokens[i - 3:i - 1] == ["sizeof", "("] and
                       tokens[i + 1] == ")" or
                       tokens[i - 3:i - 1] == ["offsetof", "("] and
                       tokens[i + 1] == ",")
            local = (statement_start(i - 1) and ident(i + 1) and
                     tokens[i + 2] == ";")
            assert operand or local, (
                f"struct {tok} in '{context}': only sizeof(struct {tok}), "
                f"offsetof(struct {tok}, ...) and a local "
                f"'struct {tok} name;' are allowed")
        if tok == "(" and ident(i + 1) and tokens[i + 1] not in C_KEYWORDS:
            end, stars = stars_end(run_end(i + 1))
            if stars and end < len(tokens) and tokens[end] == ")":
                pointee(tokens[i + 1:run_end(i + 1)], "cast")
        if tok == "(" and ident(i - 1) and tokens[i - 1] not in C_KEYWORDS:
            assert tokens[i - 1] in ("memcpy", "offsetof"), (
                f"call to {tokens[i - 1]}(): only memcpy() and offsetof() "
                "are allowed")
        if not (ident(i) and tok not in C_KEYWORDS and statement_start(i)):
            continue
        # A declaration: '<type> *...name' or '<type> name', then more
        # declarators after top-level commas.  An expression statement
        # starts with one identifier and is skipped.
        type_end = run_end(i)
        end, stars = stars_end(type_end)
        if stars:
            base, declarators = tokens[i:type_end], [(end, stars)]
        elif type_end - i >= 2:
            base, declarators = tokens[i:type_end - 1], []
        else:
            continue
        depth, pos = 0, type_end
        while tokens[pos] != ";" or depth:
            depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1,
                      "}": -1}.get(tokens[pos], 0)
            if tokens[pos] == "," and not depth:
                declarators.append(stars_end(pos + 1))
            pos += 1
        for name_pos, name_stars in declarators:
            if name_stars:
                target = pointee(base, "pointer declaration")
                if target == ("struct", "ethhdr") and ident(name_pos):
                    ethhdr_pointers.add(tokens[name_pos])
    for i, tok in enumerate(tokens):
        if tok == "->":
            assert tokens[i - 1] in ethhdr_pointers, \
                f"'{tokens[i - 1]}->{tokens[i + 1]}' is not an ethhdr access"


for sample, signature in (
        ("gpu_xdp_p2p.c", "__global__ void gpu_process_packets("),
        ("gpu_xdp_p2p_nocuda.c", "static void cpu_process_packet(")):
    try:
        check_rewrite_header_access((SAMPLES / sample).read_text(),
                                    signature)
    except (AssertionError, ValueError) as err:
        raise AssertionError(f"{sample} packet rewrite: {err}") from err

# The source-mode template frame is frame-aligned too, so build_source_packet()
# builds its IPv4 and UDP headers in local structs and copies them in as
# bytes instead of writing through header pointers into the frame.
source_template_code = strip_comments(source_template)
assert not re.search(r"struct\s+(iphdr|udphdr)\s*\*", source_template_code), \
    "build_source_packet: header pointer into the frame"
assert re.search(r"struct\s+iphdr\s+\w+\s*;", source_template_code)
assert re.search(r"struct\s+udphdr\s+\w+\s*;", source_template_code)

readme =(ROOT / "drivers/gpu/nvidia-p2p/README.md").read_text()
for mode in ("roundtrip", "nic-to-gpu", "gpu-to-nic"):
    assert f"`{mode}`" in readme
for option in ("`-A/-a/-P/-p`", "`-S/-D`"):
    assert option in readme
assert "does not attach an ingress redirect" in readme
sequester = function_body(cuda, "static void sequester_active_frames(")
assert "gpu_xdp_frame_sequester_rx(" in sequester
assert "ctx->gpu_ctx->dma_sequestered = 1" in sequester
assert "running = 0" in sequester

cuda_cleanup = function_body(cuda, "static int gpu_p2p_cleanup(")
sequester_guard = cuda_cleanup.index("if (ctx->dma_sequestered)")
unpin = cuda_cleanup.index("xdev_ext_nv_p2p_unpin_umem(")
assert sequester_guard < unpin
stream_sync = cuda_cleanup.index("cudaStreamSynchronize(")
stream_sync_failure = cuda_cleanup.index("ctx->dma_sequestered = 1", stream_sync)
unpin_failure = cuda_cleanup.index("ctx->dma_sequestered = 1", unpin)
assert stream_sync < stream_sync_failure < unpin < unpin_failure

hold = function_body(cuda, "static void hold_sequestered_backing(")
for signame in ("SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"):
    assert f"signal({signame}, SIG_IGN)" in hold
assert "for (;;)" in hold
assert "pause()" in hold
cleanup_failure = cuda_main.index("Backing release skipped")
assert "hold_sequestered_backing();" in cuda_main[cleanup_failure:]

assert "host XSK UMEM" in cuda[:cuda.index("*/")]
assert "not NIC-to-VRAM GPUDirect" in cuda[:cuda.index("*/")]
assert "Direct GPU DMA to/from network packets" not in cuda[:cuda.index("*/")]

print("PASS: GPU/AF_XDP frame ownership source contract")
