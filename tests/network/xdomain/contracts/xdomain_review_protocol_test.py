#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent review-P contract tests executing real XDOMAIN class and BPF.

The existing host/device boundaries and original case/oracle bytes are reused
unchanged. No original case is executed or edited. No physical DMA claim.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from contextlib import nullcontext
import xdomain_class_test as fixture
import xdomain_ring_test as ring_fixture

CASES = ("reject_credit", "reject_ring_full", "reject_33", "wait_three", "timer_local", "preaccept_rx", "old_cancel", "accepted_cancel", "core_self_kick", "unbound_ring_full", "unbound_duplicate", "reject_duplicate", "reverse_shared", "timer_posted", "preaccept_lease")


def source(kernel, here):
    read = lambda relative: (kernel / relative).read_text()
    mech = read("include/linux/xdev_ext_mech.h")
    declarations = "\n".join(fixture.struct(mech, name) for name in (
        "xdev_ext_mech_frame", "xdev_ext_family_hooks_hdr", "xdev_ext_mech_stage",
        "xdev_ext_mech_class_ops", "xdev_ext_xdomain_proto_result", "xdev_ext_mech_call_args"))
    for name in ("include/linux/xdev_ext_requester.h", "include/linux/xdev_ext_netfam.h", "io_uring/xdomain/xdev_ext_xdomain.h"):
        declarations += fixture.no_includes(read(name)) + "\n"
    core_text = read("io_uring/xdev_ext_mech.c")
    enum = re.search(r"enum xdev_ext_mech_end\s*\{[^}]+\};", core_text)
    if not enum:
        raise ValueError("actual end enum absent")
    core = enum.group() + "\n" + "\n".join(fixture.function(core_text, name) for name in (
        "xdev_ext_mech_settled", "xdev_ext_mech_settle_locked", "xdev_ext_mech_progress_work",
        "xdev_ext_mech_session_stop", "xdev_ext_mech_session_stop_started_ns",
        "xdev_ext_mech_stage_native_get", "xdev_ext_mech_stage_native_put", "xdev_ext_mech_stage_kick", "xdev_ext_mech_end") +
        (("xdev_ext_mech_stage_stop",) if "\nvoid xdev_ext_mech_stage_stop(" in core_text else ()))
    family = fixture.region(read("io_uring/family/xdev_ext_netfam.c"),
        "/* xdev_ext_netfam runtime begin */", "/* xdev_ext_netfam runtime end */")
    # The original case source is included verbatim with a renamed entry point;
    # its helpers are setup only and none of its assertions are rewritten.
    cases = "#define main review_unused_original_main\n" + (here / "xdomain_cases.c").read_text() + "\n#undef main\n"
    cases += "\n#define main review_protocol_case_main\n" + (here / "xdomain_review_protocol_cases.c").read_text() + "\n#undef main\n"
    cases += (here / "xdomain_review_protocol_terminal_cases.c").read_text()
    result = (here / "xdomain_host.h").read_text()
    # Replace only test scheduler stubs: execute the actual core kick/worker and
    # model the kthread queue-vs-mod API, including an already queued self-kick.
    result = result.replace("struct work_struct { unsigned queued; };", "struct work_struct { unsigned queued; u64 due; };")
    result = result.replace("static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { st->s->queued=1; /* records only; never calls progress */ }", "void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st);")
    old_queue = "static int kthread_queue_delayed_work(void *queue,struct kthread_delayed_work *w,unsigned long delay) { (void)delay;return queue_work(queue,&w->work); }"
    new_queue = """
static int kthread_mod_delayed_work(void *queue,struct kthread_delayed_work *w,unsigned long delay) {
 (void)queue;bool pending=w->work.queued;w->work.queued=1;w->work.due=host_ns+delay*NSEC_PER_MSEC;
 container_of(w,struct xdev_ext_mech_session,progress_work)->queued=1;return pending;
}
static int kthread_queue_delayed_work(void *queue,struct kthread_delayed_work *w,unsigned long delay) {
 (void)queue;if(w->work.queued)return 0;w->work.queued=1;w->work.due=host_ns+delay*NSEC_PER_MSEC;
 container_of(w,struct xdev_ext_mech_session,progress_work)->queued=1;return 1;
}
"""
    if old_queue not in result:
        raise ValueError("test scheduler stub changed; audit required")
    result = result.replace(old_queue, new_queue)
    for token, value in {
        "@KERNEL@": str(kernel), "@UAPI@": str(kernel / "include/uapi/linux/xdev_ext_mech.h"),
        "@PROG@": str(kernel / "tools/xdev_ext_mech/xdev_ext_mech_prog.h"),
        "@DECLARATIONS@": declarations, "@CORE@": core, "@FAMILY@": family,
        "@BPF@": fixture.no_includes(read("tools/xdev_ext_mech/xdomain_peer.bpf.c")),
        "@CLASS@": fixture.no_includes(read("io_uring/xdomain/xdev_ext_xdomain_class.c")),
        "@BOUNDARIES@": (here / "xdomain_boundaries.c").read_text(), "@CASES@": cases,
    }.items():
        result = result.replace(token, value)
    result = result.replace("@PRESSURE@", (here / "xdomain_pressure_adapter.c").read_text())
    if re.search(r"@[A-Z_]+@", result):
        raise ValueError("unexpanded fixture token")
    return result



def ring_source(kernel, here):
    read = lambda relative: (kernel / relative).read_text()
    support = ""
    if (kernel / "include/linux/xdev_ext_requester_retention.h").is_file():
        from xdomain_retention_fixture import retention_unit, descriptor_unit
        support = retention_unit(kernel) + descriptor_unit(kernel)
    declaration = ring_fixture.declaration
    lease = "\n".join(declaration(read("include/linux/xdev_ext_peer.h"), "struct " + name)
                       for name in ("xdev_ext_peer_lease", "xdev_ext_peer_fd_lease"))
    net = read("include/linux/xdev_ext_netfam.h")
    family = (declaration(net, "enum xdev_ext_net_hdr_policy") +
              "\n".join(line for line in net.splitlines() if line.startswith("#define XDEV_EXT_NET_DEV_AREA") or
                        line.startswith("#define XDEV_EXT_NETFAM_MAX_ELEMS")) + "\n" +
              declaration(net, "struct xdev_ext_net_elem") + declaration(net, "struct xdev_ext_net_dev_ops"))
    return ((here / "xdomain_ring_compat.h").read_text() +
            '\n#include "include/uapi/linux/xdev_ext_mech.h"\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n\n#include "include/linux/xdev_ext_mech_reliable_core.h"\n' +
            lease + family + fixture.no_includes(read("io_uring/xdomain/xdev_ext_xdomain.h")) +
            (here / "xdomain_ring_boundaries.c").read_text() + support +
            fixture.no_includes(read("io_uring/xdomain/xdev_ext_xdomain_ring.c")) +
            "\n#define main review_unused_ring_original_main\n" + (here / "xdomain_ring_cases.c").read_text() +
            "\n#undef main\n" + (here / "xdomain_review_protocol_ring_cases.c").read_text())



def down_source(kernel, here):
    # Complete main.c and unchanged login boundary/case bytes. The appended
    # independent case runs actual link_fail/down_work, not their recorder.
    support = ""
    clock = ""
    if (kernel / "include/linux/xdev_ext_requester_retention.h").is_file():
        from xdomain_retention_fixture import retention_unit
        support = retention_unit(kernel)
        clock = "\nstatic unsigned long jiffies;\n#define time_before(a,b) ((long)((a)-(b))<0)\n#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n"
    return ((here / "xdomain_login_compat.h").read_text() + clock +
            '\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n' +
            fixture.no_includes((kernel / "io_uring/xdomain/xdev_ext_xdomain.h").read_text()) +
            (here / "xdomain_login_boundaries.c").read_text() + support +
            fixture.no_includes((kernel / "io_uring/xdomain/xdev_ext_xdomain_main.c").read_text()) +
            "\n#define main review_unused_login_original_main\n" + (here / "xdomain_login_cases.c").read_text() +
            "\n#undef main\n" + (here / "xdomain_review_protocol_down_cases.c").read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, default=Path(__file__).resolve().parents[5])
    parser.add_argument("--artifact-directory", type=Path)
    parser.add_argument("--case", choices=CASES, action="append")
    args = parser.parse_args()
    here, kernel = Path(__file__).resolve().parent, args.kernel.resolve()
    context = nullcontext(str(args.artifact_directory.resolve())) if args.artifact_directory else tempfile.TemporaryDirectory(prefix="xdomain-review-P-")
    if args.artifact_directory:
        args.artifact_directory.mkdir(parents=True, exist_ok=True)
    with context as directory:
        src, binary = Path(directory) / "protocol.c", Path(directory) / "protocol"
        src.write_text(source(kernel, here))
        command = ["gcc", "-std=gnu11", "-O1", "-g", "-pthread", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                   "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I" + str(kernel), str(src), "-o", str(binary)]
        print("COMMAND:", " ".join(command), flush=True)
        subprocess.run(command, check=True)
        ring_binary = Path(directory) / "protocol-ring"
        chosen = args.case or CASES
        if any(name.startswith("unbound_") for name in chosen):
            ring_src = Path(directory) / "protocol-ring.c"
            ring_src.write_text(ring_source(kernel, here))
            ring_command = ["gcc", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Wno-unused-parameter",
                            "-Wno-unused-function", "-Wno-unused-variable", "-Werror=implicit-function-declaration",
                            "-pthread", "-I", str(kernel), str(ring_src), "-o", str(ring_binary)]
            print("COMMAND:", " ".join(ring_command), flush=True)
            subprocess.run(ring_command, check=True)
        down_binary = Path(directory) / "protocol-down"
        if "unbound_ring_full" in chosen:
            down_src = Path(directory) / "protocol-down.c"
            down_src.write_text(down_source(kernel, here))
            down_command = ["gcc", "-std=gnu11", "-O0", "-g", "-Wall", "-Wextra", "-Wno-unused-parameter",
                            "-Wno-unused-function", "-Wno-unused-variable", "-Werror=implicit-function-declaration",
                            "-I", str(kernel), str(down_src), "-o", str(down_binary)]
            print("COMMAND:", " ".join(down_command), flush=True)
            subprocess.run(down_command, check=True)
        failed = 0
        for name in chosen:
            run = subprocess.run([str(ring_binary if name.startswith("unbound_") else binary), name], timeout=15, env={**os.environ, "X5_CASE": ""})
            if name == "unbound_ring_full" and not run.returncode:
                # Joint proof: ring failure transfers exact EAGAIN, real X3
                # preserves/executes it, and actual sender reaches error even
                # when no immediate peer notification can arrive.
                for terminal_command in ([str(down_binary)], [str(binary), "sender_terminal"]):
                    terminal = subprocess.run(terminal_command, timeout=15)
                    print("TERMINAL COMMAND:", " ".join(terminal_command), "exit=", terminal.returncode, flush=True)
                    if terminal.returncode:
                        run = terminal
                        break
            print(f"{'not ok' if run.returncode else 'ok'} - {name}; exit={run.returncode}", flush=True)
            failed += bool(run.returncode)
        return bool(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print("PROTOCOL REVIEW SETUP FAILURE:", error, file=sys.stderr)
        sys.exit(2)
