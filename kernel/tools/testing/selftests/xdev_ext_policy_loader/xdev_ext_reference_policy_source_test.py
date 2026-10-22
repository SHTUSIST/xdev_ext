#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract for the explicit five-backend reference policy loader."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[4]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def function_body(source: str, signature: str) -> str:
    require(signature in source, f"missing function: {signature}")
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for position in range(brace, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : position + 1]
    raise AssertionError(f"unterminated function: {signature}")


def check_stage_attribution(bpf: str, dispatch: str, complete: str) -> None:
    """Every callback updates its backend row and its ctx->current_stage row."""
    stage_rows = function_body(
        bpf, "xdev_ext_reference_stage_stats(const struct xdev_ext_binding_ctx_v2 *binding_ctx)")
    require("binding_ctx->current_stage >= XDEV_EXT_BINDING_STAGE_MAX" in stage_rows,
            "stage row index is not bounded by the UAPI stage count")
    require("xdev_ext_reference_stats.stage[binding_ctx->current_stage]" in stage_rows,
            "stage row is not keyed by the context's stage field")
    require(stage_rows.index("XDEV_EXT_BINDING_STAGE_MAX") <
            stage_rows.index("xdev_ext_reference_stats.stage[binding_ctx->current_stage]"),
            "stage row is not keyed by the context's stage field after the bound check")

    helpers = {
        "dispatch_enter": ("dispatch_callbacks",),
        "dispatch_exit": ("dispatch_kfunc_ok", "dispatch_kfunc_errors"),
        "complete_enter": ("complete_callbacks", "result_ok", "result_errors",
                           "bytes_done", "last_result"),
        "complete_exit": ("complete_kfunc_ok", "complete_kfunc_errors"),
    }
    for helper, counters in helpers.items():
        body = function_body(bpf, f"xdev_ext_reference_{helper}(struct xdev_ext_reference_policy_backend_stats *stats")
        for counter in counters:
            require(f"stats->{counter}" in body,
                    f"xdev_ext_reference_{helper} does not update {counter}")
        require("bpf_xdev_ext_" not in body,
                f"xdev_ext_reference_{helper} calls a phase kfunc")

    for body, phase, kfunc, enter_args, exit_args in (
            (dispatch, "dispatch", "bpf_xdev_ext_dispatch_action(", "", ""),
            (complete, "complete", "bpf_xdev_ext_complete_action(", ", binding_ctx", "")):
        require("backend = xdev_ext_reference_backend_stats(binding_ctx);" in body and
                "stage = xdev_ext_reference_stage_stats(binding_ctx);" in body,
                f"{phase} does not select both its backend row and its stage row")
        call = body.index(kfunc)
        for row in ("backend", "stage"):
            enter = f"xdev_ext_reference_{phase}_enter({row}{enter_args});"
            leave = f"xdev_ext_reference_{phase}_exit({row}, ret{exit_args});"
            require(body.count(enter) == 1 and body.index(enter) < call,
                    f"{phase} does not count the {row} row once before its kfunc")
            require(body.count(leave) == 1 and body.index(leave) > call,
                    f"{phase} does not record the {row} row's kfunc result once")


def strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    return re.sub(r"//[^\n]*", " ", source)


def statement_at_top_level(body: str, position: int) -> bool:
    """True when position starts a statement directly inside the body braces."""
    depth = body[:position].count("{") - body[:position].count("}")
    previous = body[:position].rstrip()
    return depth == 1 and previous[-1:] in (";", "{", "}")


def closing_paren(code: str, opening: int) -> int:
    """Index of the parenthesis that closes the one at opening."""
    depth = 0
    for position in range(opening, len(code)):
        if code[position] == "(":
            depth += 1
        elif code[position] == ")":
            depth -= 1
            if depth == 0:
                return position
    raise AssertionError("unterminated call")


def check_returns_kfunc_result(bpf: str, body: str, phase: str) -> None:
    """The callback hands the phase kfunc's verdict back to C verbatim."""
    kfunc = f"bpf_xdev_ext_{phase}_action("
    other = "bpf_xdev_ext_complete_action(" if phase == "dispatch" else "bpf_xdev_ext_dispatch_action("
    code = strip_comments(body)
    source = strip_comments(bpf)
    require(other not in code, f"{phase} callback calls the other phase's kfunc")
    # The verdict crosses only signed 32-bit types between the kfunc and C,
    # so no declaration can narrow or reinterpret it on the way back.
    extern = re.findall(r"^extern\s+int\s+" + re.escape(kfunc), source, re.M)
    require(len(extern) == 1, f"{kfunc}) is not declared exactly once as returning int")
    require(source.count(kfunc) - len(extern) == 1,
            f"{kfunc} is called outside the {phase} callback")
    require(re.search(r'SEC\("struct_ops/' + phase + r'"\)\s*__s32\s+BPF_PROG\(xdev_ext_reference_' +
                      phase + ",", source),
            f"{phase} callback does not return __s32")

    returns = re.findall(r"\breturn\b[^;]*;", code)
    require(returns == ["return ret;"],
            f"{phase} callback must return the kfunc result unchanged, found {returns}")
    require(statement_at_top_level(code, code.index("return ret;")),
            f"{phase} callback returns the kfunc result only conditionally")

    writes = re.findall(r"\bret\s*(?:<<|>>|[-+*/%&|^])?=(?!=)", code)
    require(len(writes) == 1, f"{phase} callback writes ret more than once")
    assignment = re.search(r"\bret\s*=\s*" + re.escape(kfunc), code)
    require(assignment is not None and statement_at_top_level(code, assignment.start()),
            f"{phase} callback does not take ret unconditionally from {kfunc}")
    call_end = closing_paren(code, assignment.end() - 1)
    require(code[call_end + 1 :].lstrip().startswith(";"),
            f"{phase} callback changes the {kfunc}) result before storing it in ret")
    require(not re.search(r"&\s*ret\b|\+\+\s*ret\b|\bret\s*\+\+|--\s*ret\b|\bret\s*--", code),
            f"{phase} callback modifies ret after the kfunc call")

    typed = [use for use in re.finditer(r"\bret\b", code)
             if re.search(r"\b(?!return\b)\w+\s*$", code[: use.start()])]
    declaration = re.search(r"\b(?:int|__s32)\s+ret\s*;", code)
    require(len(typed) == 1 and declaration is not None and
            declaration.start() < typed[0].start() < declaration.end() and
            statement_at_top_level(code, declaration.start()),
            f"{phase} callback must declare ret exactly once, as int ret; or __s32 ret;")


def check_stage_table_matches_kernel(core: str) -> None:
    """The printed stage rows are exactly the stages each backend accepts."""
    validity = function_body(
        (ROOT / "include/linux/xdev_ext_binding.h").read_text(),
        "xdev_ext_binding_backend_stage_direction_valid(")
    kernel_pairs = set()
    for backend, chunk in re.findall(
            r"case XDEV_EXT_BINDING_BACKEND_(\w+):(.*?)(?=case XDEV_EXT_BINDING_BACKEND_|default:)",
            validity, re.S):
        for stage in re.findall(r"XDEV_EXT_BINDING_STAGE_(\w+)", chunk):
            kernel_pairs.add((backend, stage))
    require(len({backend for backend, _ in kernel_pairs}) == 5,
            "kernel stage/direction rule no longer lists five backends")

    table = re.search(
        r"xdev_ext_reference_policy_stage_descriptors\[XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT\]\s*=\s*\{(.*?)\n\};",
        core, re.S)
    require(table is not None, "loader lacks the stage descriptor table")
    rows = re.findall(
        r"\{\s*XDEV_EXT_BINDING_BACKEND_(\w+)\s*,\s*\"(\w+)\"\s*,\s*XDEV_EXT_BINDING_STAGE_(\w+)\s*\}",
        table.group(1))
    require({(backend, stage) for backend, _, stage in rows} == kernel_pairs and
            len(rows) == len(kernel_pairs),
            "stage rows differ from the kernel's backend stage/direction rule")
    for _, name, stage in rows:
        require(name == stage.lower(), f"stage label {name} does not name {stage}")
    count = re.search(r"#define XDEV_EXT_REFERENCE_POLICY_STAGE_COUNT (\d+)U", core)
    require(count is not None and int(count.group(1)) == len(rows),
            "stage count differs from the stage table")


def main() -> None:
    bpf_path = ROOT / "tools/xdev_ext_reference_policy.bpf.c"
    loader_path = ROOT / "tools/xdev_ext_reference_policy.c"
    makefile_path = ROOT / "tools/Makefile.xdev_ext_policy"
    abi_path = ROOT / "tools/xdev_ext_reference_policy_abi.h"
    core_path = ROOT / "tools/xdev_ext_reference_policy_core.h"
    selftests_makefile_path = ROOT / "tools/testing/selftests/Makefile"

    for path in (bpf_path, loader_path, makefile_path, abi_path, core_path):
        require(path.is_file(), f"missing production artifact: {path}")

    bpf = bpf_path.read_text()
    require(bpf.index('#include "xdev_ext_reference_policy_abi.h"') <
            bpf.index("#include <bpf/bpf_helpers.h>"),
            "kernel integer types must precede bpf_helpers declarations")
    dispatch = function_body(bpf, "BPF_PROG(xdev_ext_reference_dispatch,")
    complete = function_body(bpf, "BPF_PROG(xdev_ext_reference_complete,")
    require(dispatch.count("bpf_xdev_ext_dispatch_action(") == 1,
            "dispatch must call its phase kfunc exactly once")
    require("XDEV_EXT_BINDING_ACTION_FALLBACK" in dispatch,
            "dispatch default is not native fallback")
    require(complete.count("bpf_xdev_ext_complete_action(") == 1,
            "complete must call its phase kfunc exactly once")
    require("XDEV_EXT_BINDING_ACTION_FALLBACK" in complete,
            "completion default is not native fallback")
    for body, phase in ((dispatch, "dispatch"), (complete, "complete")):
        require(re.search(r"XDEV_EXT_BINDING_ACTION_FALLBACK\s*,\s*0\s*,\s*0\s*,\s*0", body),
                f"{phase} changes recipe, next stage, or profile")

    check_returns_kfunc_result(bpf, dispatch, "dispatch")
    check_returns_kfunc_result(bpf, complete, "complete")
    check_stage_attribution(bpf, dispatch, complete)

    policies = re.findall(
        r"struct xdev_ext_binding_ops\s+(\w+)\s+SEC\(\"\.struct_ops\.link\"\)\s*=\s*\{(.*?)\n\};",
        bpf,
        re.S,
    )
    require(len(policies) == 5, "reference object must define exactly five struct_ops maps")
    expected = {
        "socket_policy": ("XDEV_EXT_BINDING_BACKEND_SOCKET", None),
        "afxdp_policy": ("XDEV_EXT_BINDING_BACKEND_AFXDP", "XDEV_EXT_BINDING_OPS_F_AFXDP_RX"),
        "nvme_policy": ("XDEV_EXT_BINDING_BACKEND_NVME", None),
        "iaa_policy": ("XDEV_EXT_BINDING_BACKEND_IAA", None),
        "gpu_policy": ("XDEV_EXT_BINDING_BACKEND_GPU", None),
    }
    require({name for name, _ in policies} == set(expected),
            "five policy map names do not match the loader contract")
    for name, initializer in policies:
        backend, required_flag = expected[name]
        require(f".backend = {backend}" in initializer,
                f"{name} selects the wrong backend")
        require(".dispatch = (void *)xdev_ext_reference_dispatch" in initializer,
                f"{name} lacks the dispatch callback")
        require(".complete = (void *)xdev_ext_reference_complete" in initializer,
                f"{name} lacks the completion callback")
        if required_flag:
            require(f".flags = {required_flag}" in initializer,
                    "AF_XDP policy does not opt in to RX callbacks")

    loader = loader_path.read_text()
    core = core_path.read_text()
    main_body = function_body(loader, "int main(")
    require("bpf_object__load(" in loader,
            "loader never loads the reference BPF object")
    require("bpf_map__attach_struct_ops(" in loader,
            "loader never attaches struct_ops maps")
    require("xdev_ext_reference_policy_start(" in main_body,
            "CLI bypasses the tested attach/rollback state machine")
    require("sigwait(" in main_body,
            "CLI does not hold links until an explicit shutdown signal")
    require("xdev_ext_reference_policy_stop(" in main_body,
            "CLI does not release links and object on shutdown")
    require(main_body.index("xdev_ext_reference_policy_start(") <
            main_body.index("sigwait(") <
            main_body.rindex("xdev_ext_reference_policy_stop("),
            "CLI lifetime is not attach, wait, reverse cleanup")
    require("XDEV_EXT_REFERENCE_POLICY_READY" in loader,
            "loader lacks an unbuffered post-attach READY record")
    require("XDEV_EXT_REFERENCE_POLICY_FINAL" in core,
            "loader lacks final per-backend evidence")
    require("XDEV_EXT_REFERENCE_POLICY_STAGE_FINAL" in core,
            "loader lacks final per-stage evidence")
    check_stage_table_matches_kernel(core)
    print_stats = function_body(loader, "static int xdev_ext_reference_policy_print_stats(")
    require("xdev_ext_reference_policy_emit_snapshot(" in print_stats and
            "xdev_ext_reference_policy_format_backend(" not in print_stats,
            "CLI prints statistics outside the tested snapshot order")
    require("XDEV_EXT_REFERENCE_POLICY_ATTACH_FAILED" in loader and
            "last_map" in loader,
            "attach conflict lacks the failed map diagnostic")
    require("bpf_map_lookup_elem(" in loader,
            "loader does not read the kernel-updated statistics map")
    require("bpf_map__value_size(" in loader and
            "xdev_ext_reference_policy_stats_value_size_valid(" in loader,
            "loader does not reject a mismatched .bss value size before lookup")
    read_stats = function_body(loader, "xdev_ext_reference_policy_read_stats(")
    require(read_stats.index("bpf_map__value_size(") <
            read_stats.index("bpf_map_lookup_elem("),
            "statistics size validation occurs after the potentially unsafe lookup")
    require(main_body.index("pthread_sigmask(") <
            main_body.index("xdev_ext_reference_policy_start("),
            "termination signals are not blocked before attachment")
    ready = main_body.index("XDEV_EXT_REFERENCE_POLICY_READY")
    require(ready < main_body.index("fflush(stdout)", ready) <
            main_body.index("sigwait("),
            "READY is not flushed before the loader begins waiting")
    require(main_body.index("xdev_ext_reference_policy_print_stats(") <
            main_body.rindex("xdev_ext_reference_policy_stop("),
            "statistics must be read before object ownership is released")

    makefile = makefile_path.read_text()
    require("xdev_ext_reference_policy.bpf.o" in makefile and
            "xdev_ext_reference_policy" in makefile,
            "production Makefile does not build both loader artifacts")
    require("VMLINUX_BTF" in makefile and "BPFTOOL" in makefile and
            "CLANG" in makefile,
            "production BPF build does not name its target-BTF toolchain")
    require("BPF_CFLAGS" in makefile and "-Werror" in makefile,
            "production BPF build does not fail on compiler warnings")
    require('temporary="$@.tmp"' in makefile and
            'mv -f "$$temporary" "$@"' in makefile,
            "a failed target-BTF check can leave a falsely successful make target")

    selftests_makefile = selftests_makefile_path.read_text()
    require("TARGETS += xdev_ext_policy_loader" in selftests_makefile,
            "policy-loader tests are absent from the kselftest target list")

    print("ok 1 - explicit five-backend reference policy source contract")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError) as error:
        print(f"not ok 1 - {error}")
        raise SystemExit(1)
