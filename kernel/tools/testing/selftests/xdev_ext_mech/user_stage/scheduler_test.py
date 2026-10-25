#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real session core with the real USER stage class on the host.

The worker steps (acquire, submit, native completion handoff, landing,
drain) come verbatim from io_uring/xdev_ext_mech.c, and the USER class's
build default, validate, submit, completion reaping, deadline/stop
cancellation and dead marking come verbatim from io_uring/xdev_ext_mech_user.c.
Only work queues, device submission and the program call are host stand-ins
(scheduler_fixture.c).  Each case runs in its own process.  Prints TAP.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("KERNEL_SRC", next(p for p in HERE.parents
            if (p / "io_uring/xdev_ext_mech.c").is_file())))
CASES = ("complete", "sleep", "varlen", "deadline", "stop", "dead", "stale",
         "badlen", "status", "full", "multi", "kick-race")


def definition(text, name, structure=False):
    pattern = (r"^struct " + name + r" \{\n.*?^\};" if structure else
               r"^\w[^;{}]*\b" + name + r"\([^;{}]*\)\n\{\n.*?^\}")
    match = re.search(pattern, text, re.M | re.S)
    if not match:
        raise RuntimeError("missing production definition: " + name)
    return match[0]


def generate():
    core = (ROOT / "io_uring/xdev_ext_mech.c").read_text()
    user = (ROOT / "io_uring/xdev_ext_mech_user.c").read_text()
    abi = (ROOT / "include/linux/xdev_ext_mech.h").read_text()
    names = ["xdev_ext_mech_frame", "xdev_ext_mech_stage", "xdev_ext_mech_class_ops",
             "xdev_ext_mech_pool_ops", "xdev_ext_mech_pool", "xdev_ext_mech_call_args"]
    structs = "\n".join(definition(abi, n, True) for n in names)
    structs += "\n" + "\n".join(definition(core, n, True) for n in
                                ("xdev_ext_mech_batch", "xdev_ext_mech_session"))
    structs += "\n" + "\n".join(definition(user, n, True) for n in
                                ("xdev_ext_user_held", "xdev_ext_user_stage"))
    core_names = ["xdev_ext_mech_frames_move", "xdev_ext_mech_batch_priv", "xdev_ext_mech_batch_cookie",
                  "xdev_ext_mech_batch_ticket", "xdev_ext_mech_batch_queue", "xdev_ext_mech_batch_id",
                  "xdev_ext_mech_batch_key", "xdev_ext_mech_batch_slot", "xdev_ext_mech_batch_nr_frames",
                  "xdev_ext_mech_batch_frame", "xdev_ext_mech_batch_cpu_length",
                  "xdev_ext_mech_session_pool", "xdev_ext_mech_session_depth", "xdev_ext_mech_stage_kick",
                  "xdev_ext_mech_progress_work",
                  "xdev_ext_mech_sync_for_cpu", "xdev_ext_mech_life_undo",
                  "xdev_ext_mech_batch_acquire", "xdev_ext_mech_batch_completion_claim",
                  "xdev_ext_mech_batch_handoff", "xdev_ext_mech_batch_completion_publish",
                  "xdev_ext_mech_batch_complete", "xdev_ext_mech_batch_complete_produced",
                  "xdev_ext_mech_batch_complete_cancelled", "xdev_ext_mech_batch_sequester",
                  "xdev_ext_mech_submit", "xdev_ext_mech_poll_kick", "xdev_ext_mech_batch_run",
                  "xdev_ext_mech_batch_landed", "xdev_ext_mech_batch_drain",
                  "xdev_ext_mech_retry_work", "xdev_ext_mech_trim_produced",
                  "xdev_ext_mech_recycle_produced_tail"]
    core_names += list(dict.fromkeys(re.findall(
        r"^\w[^;{}]*\b(xdev_ext_mech_fanout_\w+)\([^;{}]*\)\n\{", core, re.M)))
    user_names = ["xdev_ext_user_default_build", "xdev_ext_user_validate", "xdev_ext_user_stopped",
                  "xdev_ext_user_end", "xdev_ext_user_submit", "xdev_ext_user_reap_one",
                  "xdev_ext_user_reap", "xdev_ext_user_progress", "xdev_ext_user_mark_dead"]
    functions = [definition(core, n) for n in core_names]
    functions += [definition(user, n) for n in user_names]
    prototypes = "\n".join(f[:f.index("\n{")] + ";" for f in functions)
    code = (HERE / "scheduler_fixture.c").read_text()
    code = code.replace("/* STRUCTURES */", structs)
    code = code.replace("/* PROTOTYPES */", prototypes)
    code = code.replace("/* PRODUCTION */", "\n".join(functions))
    return code


def main():
    print("TAP version 13", flush=True)
    with tempfile.TemporaryDirectory(prefix="user-stage-scheduler-") as tmp:
        tmp = Path(tmp)
        try:
            code = generate()
        except (OSError, RuntimeError) as error:
            print(f"1..1\nnot ok 1 - extract the production code ({error})", flush=True)
            return 1
        source = tmp / "probe.c"
        source.write_text(code)
        binary = tmp / "probe"
        command = shlex.split(os.environ.get("CC", "cc")) + ["-std=gnu11", "-O1", "-g",
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-variable",
            "-Wno-unused-parameter", "-fsanitize=address,undefined", "-fno-sanitize-recover=undefined",
            "-pthread", "-I" + str(ROOT), "-I" + str(HERE.parent), "-I" + str(HERE),
            str(source), "-o", str(binary)]
        build = subprocess.run(command, text=True, capture_output=True)
        if build.returncode:
            print(f"1..1\nnot ok 1 - compile the production code with the fixture", flush=True)
            print(build.stdout + build.stderr, end="", flush=True)
            return 1
        failed = 0
        print("1.." + str(len(CASES)), flush=True)
        for i, case in enumerate(CASES, 1):
            run = subprocess.run([str(binary), case], text=True, capture_output=True, timeout=30)
            print(("not ok" if run.returncode else "ok") + f" {i} - {case}", flush=True)
            print(run.stdout + run.stderr, end="", flush=True)
            failed += bool(run.returncode)
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
