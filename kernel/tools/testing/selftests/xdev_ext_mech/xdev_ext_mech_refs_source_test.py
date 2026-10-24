#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Integration source contracts; these are not native-callback runtime tests."""
from pathlib import Path
import re
import unittest

KERNEL = Path(__file__).resolve().parents[4]


def active(text):
    """Keep non-legacy branches, including the else branch of a legacy guard."""
    stack = []
    lines = []
    for line in text.splitlines():
        directive = re.match(r"\s*#\s*(if|ifdef|ifndef|else|elif|endif)\b(.*)", line)
        if directive:
            op, expr = directive.groups()
            if op in ("if", "ifdef", "ifndef"):
                legacy = bool(re.search(r"\bXDEV_EXT_[A-Z0-9_]*LEGACY[A-Z0-9_]*\b", expr))
                disabled = legacy and op != "ifndef" and not re.search(r"!\s*defined", expr)
                stack.append([legacy, disabled])
            elif op in ("else", "elif") and stack and stack[-1][0]:
                stack[-1][1] = not stack[-1][1]
            elif op == "endif" and stack:
                stack.pop()
        if not any(disabled for _, disabled in stack):
            lines.append(line)
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", "\n".join(lines), flags=re.S)


def source(name):
    path = KERNEL / name
    if not path.is_file():
        raise AssertionError(f"missing production file: {name}")
    return active(path.read_text())


def body(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", text)
    if not match:
        raise AssertionError(f"missing function definition: {name}")
    start = match.end()
    depth = 1
    for pos in range(start, len(text)):
        depth += (text[pos] == "{") - (text[pos] == "}")
        if not depth:
            return text[start:pos]
    raise AssertionError(f"unbalanced function definition: {name}")


class IntegrationContracts(unittest.TestCase):
    # Source failures report the absent/present contract, not a whole source dump.
    def assertIn(self, member, container, msg=None):
        self.assertTrue(member in container, msg or f"missing source token: {member}")

    def assertNotIn(self, member, container, msg=None):
        self.assertFalse(member in container, msg or f"retired source token: {member}")

    def assertRegex(self, text, pattern, msg=None):
        self.assertIsNotNone(re.search(pattern, text), msg or f"missing pattern: {pattern}")

    def assertNotRegex(self, text, pattern, msg=None):
        self.assertIsNone(re.search(pattern, text), msg or f"retired pattern: {pattern}")

    def test_L1_only_four_production_states(self):
        header = source("io_uring/xdev_ext_mech_lifecycle.h")
        self.assertNotRegex(header, r"\bXDEV_EXT_MECH_L_(?:IO_FROM_READY|PUBLISHING)\b")

    def test_L6_handoff_inside_completion_ticket(self):
        callback = body(source("io_uring/xdev_ext_mech.c"),
                        "xdev_ext_mech_batch_completion_publish")
        for token in ("xdev_ext_mech_completion_publish_begin(",
                      "xdev_ext_mech_batch_handoff(", "xdev_ext_mech_completion_publish_end("):
            self.assertIn(token, callback)
        begin = callback.index("xdev_ext_mech_completion_publish_begin(")
        handoff = callback.index("xdev_ext_mech_batch_handoff(")
        end = callback.index("xdev_ext_mech_completion_publish_end(")
        self.assertLess(begin, handoff)
        self.assertLess(handoff, end)

    def test_L6_worker_does_not_publish_or_release(self):
        worker = body(source("io_uring/xdev_ext_mech.c"), "xdev_ext_mech_batch_landed")
        self.assertNotRegex(worker, r"xdev_ext_mech_life_(?:publish|republish|put|fail_put|"
                            r"fail_produce|complete_consume)\s*\(")

    def test_L6_handoff_has_no_new_sleep_lock_or_allocation(self):
        handoff = body(source("io_uring/xdev_ext_mech.c"), "xdev_ext_mech_batch_handoff")
        self.assertNotRegex(handoff, r"\b(?:mutex_lock|spin_lock\w*|kmalloc\w*|kzalloc\w*|"
                            r"kv?calloc|schedule\w*|msleep\w*|wait_for_completion\w*|"
                            r"dma_fence_add_callback)\s*\(")
        self.assertIn("sequester", handoff)

    def test_L8_iaa_uses_current_lifecycle(self):
        paths = sorted((KERNEL / "io_uring/iaa").glob("*.[ch]"))
        self.assertTrue(paths)
        for path in paths:
            text = active(path.read_text())
            self.assertNotIn("xdev_ext_frame_sm.h", text, str(path))
            self.assertNotRegex(text, r"\b(?:XDEV_EXT_FRAME_\w*|xdev_ext_frame_\w*|"
                                r"xdev_ext_sm_\w*)\b", str(path))
        combined = "\n".join(active(p.read_text()) for p in paths)
        self.assertIn("xdev_ext_mech_life", combined)

    def test_L7_cpu_binding_is_registered_and_completes(self):
        cpu = source("io_uring/xdev_ext_mech_cpu.c")
        for token in ("XDEV_EXT_MECH_CLASS_CPU", "xdev_ext_mech_cpu_apply(",
                      "xdev_ext_mech_cpu_desc_check(", "xdev_ext_mech_cpu_var_result(",
                      "xdev_ext_mech_batch_complete(", "crypto_alloc_acomp("):
            self.assertIn(token, cpu)
        self.assertIn("CONFIG_XDEV_EXT_MECH_CPU", source("io_uring/Makefile"))
        self.assertIn("config XDEV_EXT_MECH_CPU", source("io_uring/Kconfig"))

    def test_L2_L9_core_uses_plan_and_frame_record(self):
        core = source("io_uring/xdev_ext_mech.c")
        for name in ("xdev_ext_mech_chain_refs", "xdev_ext_mech_stage_group_end",
                     "xdev_ext_mech_frame_rec_fill"):
            self.assertRegex(core, r"\b" + name + r"\s*\(")
        self.assertIn("XDEV_EXT_MECH_L_ACQ_FANOUT", core)
        self.assertIn("XDEV_EXT_MECH_L_ACQ_EXCLUSIVE", core)

    def test_L3_L7_ctl_commands_and_guest_invocations(self):
        ctl = source("tools/xdev_ext_mech/xdev_ext_mech_ctl.c")
        guest = (KERNEL / "tools/testing/selftests/xdev_ext_integration/"
                 "xdev_ext_mech_zc_kvm.sh").read_text()
        guest = "\n".join(line for line in guest.splitlines()
                          if not line.lstrip().startswith("#"))
        for command in ("fanout", "cpu-chain", "verify-xform"):
            self.assertIn('"' + command + '"', ctl)
            self.assertRegex(guest, r"\b" + command + r"\b")

    def test_L10_existing_model_also_migrated(self):
        model = source("tools/testing/selftests/xdev_ext_mech/model/life_explore.c")
        self.assertNotRegex(model, r"\bxdev_ext_mech_life_begin_(?:produce|consume)\s*\(")
        self.assertRegex(model, r"\bxdev_ext_mech_life_(?:acquire|put)\s*\(")


if __name__ == "__main__":
    unittest.main(verbosity=2)
