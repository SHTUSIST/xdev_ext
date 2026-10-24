#!/usr/bin/env python3
"""Execute the real session scheduler and native completion handoff.

Only OS work queues, descriptor construction and device submission are host
boundaries. No scheduler, lifecycle or completion decision is restated here.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("KERNEL_SRC", next(p for p in HERE.parents
            if (p / "io_uring/xdev_ext_mech.c").is_file())))


def definition(text, name, structure=False):
    pattern = (r"^struct " + name + r" \{\n.*?^\};" if structure else
               r"^\w[^;{}]*\b" + name + r"\([^;{}]*\)\n\{\n.*?^\}")
    match = re.search(pattern, text, re.M | re.S)
    if not match:
        raise RuntimeError("missing production definition: " + name)
    return match[0]


def generate():
    core = (ROOT / "io_uring/xdev_ext_mech.c").read_text()
    abi = (ROOT / "include/linux/xdev_ext_mech.h").read_text()
    names = ["xdev_ext_mech_frame", "xdev_ext_mech_stage", "xdev_ext_mech_class_ops",
             "xdev_ext_mech_pool_ops", "xdev_ext_mech_pool", "xdev_ext_mech_call_args"]
    structs = "\n".join(definition(abi, n, True) for n in names)
    structs += "\n" + "\n".join(definition(core, n, True) for n in
                                ("xdev_ext_mech_batch", "xdev_ext_mech_session"))
    names = ["xdev_ext_mech_frames_move", "xdev_ext_mech_batch_priv", "xdev_ext_mech_batch_cookie",
             "xdev_ext_mech_batch_ticket", "xdev_ext_mech_batch_queue",
             "xdev_ext_mech_sync_for_cpu", "xdev_ext_mech_life_undo",
             "xdev_ext_mech_batch_acquire", "xdev_ext_mech_batch_completion_claim",
             "xdev_ext_mech_batch_handoff", "xdev_ext_mech_batch_completion_publish",
             "xdev_ext_mech_batch_complete", "xdev_ext_mech_batch_complete_produced", "xdev_ext_mech_batch_sequester",
             "xdev_ext_mech_submit", "xdev_ext_mech_batch_run",
             "xdev_ext_mech_batch_landed", "xdev_ext_mech_batch_drain",
             "xdev_ext_mech_retry_work", "xdev_ext_mech_trim_produced",
             "xdev_ext_mech_recycle_produced_tail"]
    # New scheduler helpers are compiled verbatim once implemented; the RED
    # baseline still executes the existing batch_run/landed path.
    names += list(dict.fromkeys(re.findall(r"^\w[^;{}]*\b(xdev_ext_mech_fanout_\w+)\([^;{}]*\)\n\{", core, re.M)))
    functions = [definition(core, n) for n in names]
    prototypes = "\n".join(f[:f.index("\n{")] + ";" for f in functions)
    code = (HERE / "fixture.c").read_text()
    code = code.replace("/* STRUCTURES */", structs)
    code = code.replace("/* PROTOTYPES */", prototypes)
    code = code.replace("/* PRODUCTION */", "\n".join(functions))
    # Allocation topology is fixture setup, never a scheduler decision.
    if "fan_batches" in definition(core, "xdev_ext_mech_session", True):
        code = code.replace("/* FAN_ALLOC */", "s->fan_batches = child;\n" +
                            "for (u32 i=0;i<4;i++) { child[i].s=s; child[i].priv=priv[i+1]; child[i].cookie=cookies[i+1]; INIT_LIST_HEAD(&child[i].node); }")
    return code


def main():
    with tempfile.TemporaryDirectory(prefix="fanout-core-") as tmp:
        tmp = Path(tmp)
        source = tmp / "probe.c"
        source.write_text(generate())
        binary = tmp / "probe"
        command = shlex.split(os.environ.get("CC", "cc")) + ["-std=gnu11", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-variable",
            "-Wno-unused-parameter", "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
            "-pthread", "-I" + str(ROOT), "-I" + str(HERE), str(source), "-o", str(binary)]
        subprocess.run(command, check=True)
        failed = 0
        cases = ("parallel", "reverse", "inline", "duplicate", "late", "eagain",
                 "fail", "stop", "quarantine", "same-class", "dependent")
        print("TAP version 13", flush=True)
        print("1.." + str(len(cases)), flush=True)
        for i, case in enumerate(cases, 1):
            run = subprocess.run([str(binary), case], text=True, capture_output=True, timeout=10)
            print(("not ok" if run.returncode else "ok") + f" {i} - {case}", flush=True)
            print(run.stdout + run.stderr, end="", flush=True)
            failed += bool(run.returncode)
        return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
