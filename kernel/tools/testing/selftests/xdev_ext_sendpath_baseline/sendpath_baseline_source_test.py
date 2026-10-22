#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Call-site checks for xdev_ext_sendpath_baseline.c.

The core test exercises the decisions in tools/xdev_ext_sendpath_baseline_core.h,
and the runtime test runs the program, but neither can see a few lines of
the program itself on a host without a block device or a timing-independent
view of the opcodes and depth: the receive guard in the run loop, the
partition check of a block target, the sysfs root it uses, and where the
write operations are counted.  These checks pin those lines.
"""

from pathlib import Path
import re
import sys


SOURCE = Path(__file__).resolve().parents[3] / "xdev_ext_sendpath_baseline.c"
text = SOURCE.read_text(encoding="utf-8")
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
    """The braces-delimited body of the static function definition name."""
    match = re.search(rf"^static\b[^;{{]*\b{name}\s*\([^;{{]*\)\s*\{{",
                      text, re.M)
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


def ordered(body: str, *needles: str) -> bool:
    """Every needle occurs in body, each after the previous one."""
    pos = 0
    for needle in needles:
        pos = body.find(needle, pos)
        if pos < 0:
            return False
        pos += len(needle)
    return True


open_target = function_body("spb_open_target")
submit = function_body("spb_submit_write")
run = function_body("spb_run")
summary = function_body("spb_print_summary")

# The sysfs root the program hands to the partition check.
require(len(re.findall(r'^#define SPB_SYSFS_ROOT "/sys"$', text, re.M)) == 1 and
        len(re.findall(r"^#define SPB_SYSFS_ROOT\b", text, re.M)) == 1,
        'SPB_SYSFS_ROOT is defined once, as "/sys"')

# A block target is classified (whole device or partition) before use.
classify = "ret = spb_target_classify(&st, SPB_SYSFS_ROOT, &rt->target_kind);"
require(bool(open_target) and text.count("spb_target_classify(") == 1 and
        open_target.count(classify) == 1,
        "spb_open_target classifies the target once, against SPB_SYSFS_ROOT")
require(ordered(open_target, "fstat(rt->target_fd, &st)", classify,
                "if (ret) {", "return ret;", "if (S_ISBLK(st.st_mode))"),
        "the classification follows fstat(), and its refusal returns before "
        "the block-device branch")
require(not re.search(r"\brt->target_kind\s*=[^=]", text),
        "only spb_target_classify sets the target kind")

# The run loop's only receive decision is the core guard.
guard = "receive = spb_loop_may_receive(&rt->rx, rt->stop);"
require(bool(run) and run.count(guard) == 1 and
        len(re.findall(r"^\s*receive = spb_loop_may_receive\(&rt->rx, "
                       r"rt->stop\);$", run, re.M)) == 1,
        "spb_run decides to receive with exactly spb_loop_may_receive()")
require(len(re.findall(r"\breceive\s*(?:[&|^]?=)(?!=)", run)) == 1,
        "spb_run assigns receive nowhere else")

# The write operations are counted at the submission site: pwrite() through
# the one spb_receiver_issue() call, io_uring by the opcode of the SQE that
# was given to the kernel.
issue_calls = re.findall(r"\bspb_receiver_issue\s*\(", text)
require(len(issue_calls) == 1 and
        ordered(submit, "if (rt->options.io == SPB_IO_PWRITE) {",
                "ret = spb_receiver_issue(&rt->rx, group, SPB_WRITE_OP_PWRITE);",
                "pwrite(rt->target_fd"),
        "the single spb_receiver_issue() call counts pwrite() before the call")
require(len(re.findall(r"\bspb_receiver_issue_sqe\s*\(", text)) == 1 and
        ordered(submit, "spb_prep_uring_write(&rt->rx, group, rt->target_fd,",
                "io_uring_get_sqe(&rt->ring)", "*sqe = prepared;",
                "io_uring_submit(&rt->ring)",
                "ret = spb_receiver_issue_sqe(&rt->rx, group, sqe);"),
        "io_uring writes are counted once, from the ring SQE after submit")
require(bool(re.search(r"spb_prep_uring_write\(&rt->rx, group, rt->target_fd,"
                       r"\s*rt->options\.fixed_buffer, &prepared,"
                       r"\s*&prepared_op\);", submit)),
        "the SQE is prepared for the tier that --fixed-buffer selects")
require(not re.search(r"\bSPB_WRITE_OP_WRITE(?:_FIXED)?\b",
                      text.replace(summary, "")),
        "the program never names an io_uring write operation outside the "
        "summary, so it cannot count one by option")
counter = r"writes(?:\.|->)(?:ops\s*\[[^\]]*\]|max_inflight|inflight)"
require(not re.search(counter + r"\s*(?:[-+*/|&^]?=(?!=)|\+\+|--)", text) and
        not re.search(r"(?:\+\+|--)\s*[\w.>-]*" + counter, text),
        "the program never changes the write counters itself")
require(bool(summary) and
        "const struct spb_write_stats *writes = &rt->rx.writes;" in summary and
        ordered(summary, "writes->ops[SPB_WRITE_OP_WRITE]",
                "writes->ops[SPB_WRITE_OP_WRITE_FIXED]",
                "writes->ops[SPB_WRITE_OP_PWRITE]",
                "writes->max_inflight,"),
        "the SUMMARY prints the core's counters and depth reached")

# The arrival fields follow the depth reached and come from the core's
# spb_arrival_report().  A group's arrival is read before its write's
# completion clears the slot, which would otherwise time the sample from 0.
finish = function_body("spb_finish_write")
require(ordered(finish,
                "const uint64_t arrival = rt->groups[group].last_arrival_ns;",
                "ret = spb_receiver_retire(&rt->rx, group);",
                "rt->post_arrival_ns[rt->written] =") and
        ordered(summary,
                "spb_arrival_report(rt->first_datagram_ns, "
                "rt->rx.last_arrival_ns,",
                "rt->end_ns, rt->post_arrival_ns, samples, &arrival);",
                "writes->max_inflight,", "arrival.rx_span_us",
                "arrival.tail_us", "arrival.post_arrival_us_p50",
                "arrival.post_arrival_us_p99);"),
        "the SUMMARY's arrival fields come from spb_arrival_report(), each "
        "group's arrival read before its slot is cleared")

print(f"1..{checks}")
if failures:
    print(f"# FAIL: {failures}/{checks} source checks", file=sys.stderr)
    raise SystemExit(1)
print(f"# PASS: {checks} source checks")
