#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the required XDOMAIN software closure checks, with durable command logs.

This checks host contracts and actual source composition, including the real
NHI ring joined to XDOMAIN. MMIO/IRQ/link simulation remains a host boundary.
Official CUDA headers qualify declarations only; no device or SDK-build claim.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess

import sys

for _parent in Path(__file__).resolve().parents:
    if (_parent / 'tools/layout.py').is_file():
        sys.path.insert(0, str(_parent / 'tools'))
        break
from layout import canonical_root, materialize_view, load_layout, isolated_file, _atomic_copy

CANONICAL_ROOT = canonical_root(Path(__file__))
ROOT = materialize_view(CANONICAL_ROOT).root
_LAYOUT = load_layout(CANONICAL_ROOT)
_LOCK = json.loads((CANONICAL_ROOT / _LAYOUT.manifest['dependency_lock']).read_text())
NHI_REGS_INPUT = CANONICAL_ROOT / ('tests/support/fixtures/upstream/linux-' +
    _LOCK['components']['linux']['commit'] + '/nhi_regs.h')
# Host NHI composition requires one pinned upstream-only declaration file.
# Admit that exact fixture; a prepared full kernel header tree is unnecessary.
_atomic_copy(NHI_REGS_INPUT, isolated_file(ROOT, 'kernel/drivers/thunderbolt/nhi_regs.h'))
PEER = "kernel/tools/testing/selftests/xdev_ext_mech/peer_graph/"
CONTROLLER = "tests/eval/xdomain/"
STACK = "kernel/tools/testing/selftests/xdev_ext_mech/xdomain/"

# Keep this list explicit: a missing new composition test must fail, rather than
# disappearing from a glob while its implementation is still being integrated.
ENTRYPOINTS = (
    *(PEER + name for name in (
        "xdomain_class_test.py", "xdomain_review_geometry_test.py", "xdomain_review_protocol_test.py", "xdomain_login_test.py", "xdomain_ring_test.py",
        "xdomain_kfunc_test.py", "xdomain_identity_test.py", "xdomain_program_test.py",
        "xdomain_guest_verdict_test.py", "xdomain_nhi_test.py",
        "netfam_rel_kfunc_test.py", "class_table_source_test.py", "class_bind_test.py",
        "tb_protocol_handler_lifetime_test.py", "tbnet_handler_teardown_test.py",
        "session_stop_clock_test.py",
        "xdomain_review_lifecycle_test.py",
        "xdomain_review_retry_test.py",
        "xdomain_review_readiness_test.py",
        "xdomain_review_stats_ring_test.py",
        "requester_retention_test.py",
        "xdomain_review_retention_ring_test.py",
        "xdomain_login_reply_test.py", "xdomain_review_tbnet_test.py",
        "xdomain_review_stop_epoch_test.py",
    )),
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/stop_report_test.py",
    "gpu/tests/nv_xdev_ext_peer_raw_bus_source_test.py",
    *(CONTROLLER + name for name in (
        "test_action_provider.py", "test_build.py", "test_c2_terminals.py",
        "test_case_dispatch.py", "test_cases.py", "test_contract.py",
        "test_control_guard.py", "test_create_refusal.py", "test_durable_failure.py",
        "test_epoch_control.py", "test_gpu_contract.py", "test_native_barrier.py",
        "test_native_trace_owner.py", "test_observer.py", "test_oracle.py",
        "test_owner_close.py", "test_platform_facts.py", "test_retention.py",
        "test_runtime_package.py", "test_stop_report.py", "test_uapi_search.py",
    )),
    STACK + "test_prepared_inputs.py",
    STACK + "stack_test.py",
    STACK + "test_mutations.py",
    STACK + "nhi_stack_test.py",
    STACK + "test_nhi_stack_mutations.py",
    STACK + "stack_environment_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/ordered_frames_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/ordered_frames_worker_test.py",
    "kernel/tools/testing/selftests/xdev_ext_mech/user_stage/run.py",
)

# Canonical entrypoints consume an explicit source root and their own isolated
# outputs. Keep every regression visible; none is discovered through a glob.
CANONICAL_ENTRYPOINTS = {
    "tests/core/library/peer_wait/run.py": ("--out",),
    "tests/network/xdomain/probe/probe_gate_test.py": ("--keep-build",),
    "tests/network/xdomain/probe/probe_wire_test.py": ("--keep-build",),
    "tests/network/xdomain/probe/probe_transport_test.py": ("--keep-build",),
    "tests/core/admission_report/run.py": ("--output",),
    "tests/core/library/create_report/run.py": ("--out",),
    "tests/network/xdomain/diagnostics/run.py": ("--output",),
    "tests/core/library/stage_diag/run.py": ("--output",),
}

REJECT_OUTPUT = re.compile(
    r"^\s*(?:not ok(?:\s|$)|(?:FAIL|FAILED|ERROR|UNAVAILABLE|SKIP)(?:[:(\s]|$))"
    r"|#\s*SKIP\b|\.\.\.\s+skipped\b|^OK\s*\(skipped=",
    re.IGNORECASE | re.MULTILINE,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", required=True, type=Path)
    args = parser.parse_args()
    log_dir = args.log_dir.resolve()
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = []
    layout = load_layout(CANONICAL_ROOT)
    for index, entry in enumerate((*ENTRYPOINTS, *CANONICAL_ENTRYPOINTS)):
        canonical = entry in CANONICAL_ENTRYPOINTS
        source = entry if canonical else layout.by_logical[entry]
        cwd = CANONICAL_ROOT if canonical else ROOT
        argv = ["python3", entry]
        if canonical:
            output = log_dir / (f"{index:02d}-" + Path(entry).parent.name)
            argv += ["--source-root", str(CANONICAL_ROOT),
                     CANONICAL_ENTRYPOINTS[entry][0], str(output)]
            if entry.endswith("diagnostics/run.py"):
                argv += ["--nhi-regs", str(NHI_REGS_INPUT)]
        header = f"SOURCE {source}\nCWD {cwd}\nCOMMAND {shlex.join(argv)}\n"
        print(header, end="", flush=True)
        if not (cwd / entry).is_file():
            output = f"MISSING FAIL: {source}\n"
            returncode, reason = 127, "missing required entrypoint"
        else:
            try:
                result = subprocess.run(argv, cwd=cwd, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        timeout=600)
                output, returncode = result.stdout, result.returncode
                reason = "failed or skipped output" if REJECT_OUTPUT.search(output) else ""
            except subprocess.TimeoutExpired as error:
                raw = error.stdout or b""
                output = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
                output += "\nFAIL: host check exceeded 600 seconds\n"
                returncode, reason = 124, "timeout"
            except OSError as error:
                output = f"FAIL: cannot execute command: {error}\n"
                returncode, reason = 126, "command unavailable"
        failed = returncode != 0 or bool(reason)
        footer = f"EXIT {returncode} STATUS {'FAIL' if failed else 'PASS'}"
        if reason:
            footer += " REASON " + reason
        footer += "\n"
        path = log_dir / f"{index:02d}-{Path(source).stem}.log"
        path.write_text(header + output + footer)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        print(footer, end="", flush=True)
        records.append(dict(source=source, argv=argv, cwd=str(cwd),
                            returncode=returncode, status="fail" if failed else "pass",
                            reason=reason, log=path.name))
    failed = any(row["status"] == "fail" for row in records)
    (log_dir / "manifest.json").write_text(json.dumps(dict(
        scope="host-software-closure", hardware="none", sdk_build=False,
        status="fail" if failed else "pass", commands=records), indent=2) + "\n")
    print(f"XDOMAIN HOST CHECKS={'FAIL' if failed else 'PASS'} commands={len(records)}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
