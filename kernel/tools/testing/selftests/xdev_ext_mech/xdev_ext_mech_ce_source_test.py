#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of the copy-engine class: orderings the unit test cannot see."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
CE = ROOT / "io_uring/xdev_ext_mech_ce.c"
CE_CORE = ROOT / "io_uring/xdev_ext_mech_ce_core.h"
NVME_CLASS = ROOT / "drivers/nvme/host/xdev_ext_mech_nvme.c"
SIM = Path(__file__).resolve().parent / "simulate"


def body(text: str, name: str) -> str:
    """Body of the function @name defined at column 0."""
    match = re.search(rf"^[a-z].*\b{name}\((?:[^;{{]|\n)*?\)\n{{\n(.*?)^}}\n",
                      text, re.M | re.S)
    if not match:
        raise AssertionError(f"no definition of {name}()")
    return match.group(1)


def identifiers(text: str) -> set:
    """C identifiers outside comments and string or character literals."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    text = re.sub(r'"(?:\\.|[^"\\\n])*"', " ", text)
    text = re.sub(r"'(?:\\.|[^'\\\n])*'", " ", text)
    return set(re.findall(r"[A-Za-z_]\w*", text))


def words(ident: str) -> list:
    return [w.lower() for w in ident.split("_") if w]


def nvme_symbols(ids: set) -> list:
    return sorted(i for i in ids if any("nvme" in w for w in words(i)))


def afxdp_symbols(ids: set) -> list:
    return sorted(i for i in ids
                  if any("xsk" in w or "xdp" in w for w in words(i)))


def ce_symbols(ids: set) -> list:
    return sorted(i for i in ids if "ce" in words(i))


def ordered(test, text: str, *needles: str):
    """Each needle occurs, the first occurrences in this order."""
    at = []
    for needle in needles:
        test.assertIn(needle, text)
        at.append(text.index(needle))
    test.assertEqual(at, sorted(at), " < ".join(needles))


class CeClassSourceTest(unittest.TestCase):
    def setUp(self):
        self.text = CE.read_text(encoding="utf-8")

    def test_built_with_its_config(self):
        makefile = (ROOT / "io_uring/Makefile").read_text(encoding="utf-8")
        self.assertRegex(makefile,
                         r"(?m)^obj-\$\(CONFIG_XDEV_EXT_MECH_CE\)\s*\+= xdev_ext_mech_ce\.o$")

    def test_module_entry_points_are_gpl_exports(self):
        for name in ("xdev_ext_ce_backend_register", "xdev_ext_ce_backend_unregister",
                     "xdev_ext_ce_complete"):
            self.assertIn(f"EXPORT_SYMBOL_GPL({name});", self.text)
        self.assertNotRegex(self.text, r"EXPORT_SYMBOL\(")

    def test_class_has_no_silent_c_plan(self):
        table = re.search(r"struct xdev_ext_mech_class_ops xdev_ext_ce_class = {(.*?)};",
                          self.text, re.S)
        self.assertIsNotNone(table)
        table = table.group(1)
        self.assertIn(".class_id\t= XDEV_EXT_MECH_CLASS_CE,", table)
        self.assertIn("sizeof(struct xdev_ext_ce_copy_desc)", table)
        self.assertIn(".desc_cap\t= XDEV_EXT_CE_MAX_ENTRIES,", table)
        self.assertNotIn("default_build", table)
        self.assertIn("xdev_ext_mech_class_register(&xdev_ext_ce_class)", self.text)

    def test_backend_found_by_f_op_and_pinned_under_the_lock(self):
        get = body(self.text, "xdev_ext_ce_backend_get")
        ordered(self, get, "mutex_lock(&xdev_ext_ce_backend_lock)",
                "->fops == file->f_op", "try_module_get(",
                "mutex_unlock(&xdev_ext_ce_backend_lock)")

    def test_bind_order_and_unwind(self):
        bind = body(self.text, "xdev_ext_ce_bind")
        # The window is resolved in the CREATE caller's context, before the
        # pool pages are handed to the backend.
        ordered(self, bind, "xdev_ext_ce_backend_get(", "->bind_region(",
                "xdev_ext_ce_geom_init(", "->bind_host(", "st->priv = cs;")
        unwind = bind[bind.index("st->priv = cs;"):]
        ordered(self, unwind, "->unbind_region(", "module_put(", "kfree(cs)")

    def test_unbind_never_after_ambiguous(self):
        unbind = body(self.text, "xdev_ext_ce_unbind")
        ordered(self, unbind, "atomic_read(&cs->ambiguous)", "return;",
                "->unbind_host(", "->unbind_region(", "module_put(")

    def test_validate_stages_only_an_accepted_plan(self):
        validate = body(self.text, "xdev_ext_ce_validate")
        ordered(self, validate, "cs->staged = NULL;", "xdev_ext_ce_plan_check(",
                "if (err)", "cs->staged = b;")

    def test_submit_arms_before_the_backend_and_takes_back_a_refusal(self):
        submit = body(self.text, "xdev_ext_ce_submit")
        self.assertIn("struct xdev_ext_ce_cookie *ck = xdev_ext_mech_batch_cookie(b);", submit)
        ordered(self, submit, "xdev_ext_ce_cookie_arm(", "ck->b = b;",
                "xdev_ext_ce_stage_xfers(", "->submit(", "xdev_ext_ce_cookie_disarm(")
        self.assertIn("xdev_ext_mech_batch_ticket(b)", submit)
        stage = body(self.text, "xdev_ext_ce_stage_xfers")
        ordered(self, stage, "cs->staged = NULL;", "return -ENODEV;",
                "staged != b", "cb->x[i]")

    def test_completion_classified_once_and_ambiguous_sequestered(self):
        complete = body(self.text, "xdev_ext_ce_complete")
        self.assertIn("xdev_ext_ce_classify(status, hw_submitted)", complete)
        self.assertRegex(complete, r"if \(xdev_ext_mech_batch_completion_claim\("
                         r"ck->b, ticket\)\)\s+return;")
        ordered(self, complete,
                "xdev_ext_mech_batch_completion_claim(ck->b, ticket)",
                "xdev_ext_ce_cookie_finish(", "ck->outcome = ",
                "xdev_ext_ce_disposition(")
        ambiguous = complete[complete.index("if (xdev_ext_ce_disposition("):]
        ordered(self, ambiguous, "atomic_inc(&ck->cs->ambiguous)",
                "xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, true);\n\t\treturn;",
                "xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, false);")
        # Both an invalid cookie and an ambiguous native result quarantine;
        # neither is allowed to publish a reusable normal completion.
        invalid = complete[complete.index("if (WARN_ONCE(!xdev_ext_ce_cookie_finish("):
                           complete.index("ck->outcome = ")]
        ordered(self, invalid, "atomic_inc(&ck->cs->ambiguous)",
                "xdev_ext_mech_batch_completion_publish(ck->b, ticket, -EPROTO, true);",
                "return;")
        self.assertEqual(complete.count("xdev_ext_mech_batch_completion_publish("), 3)
        claim = complete.index("xdev_ext_mech_batch_completion_claim(ck->b, ticket)")
        for metadata in ("xdev_ext_ce_cookie_finish(", "ck->outcome = ",
                         "ck->status = ", "ck->bytes_done = "):
            self.assertLess(claim, complete.index(metadata))

    def test_callback_cookie_survives_stage_private_area_reset(self):
        batch = re.search(r"struct xdev_ext_ce_batch {\n(.*?)\n};", self.text,
                          re.S).group(1)
        self.assertNotIn("xdev_ext_ce_cookie", batch)
        self.assertIn(".batch_cookie_size = sizeof(struct xdev_ext_ce_cookie)", self.text)
        submit = body(self.text, "xdev_ext_ce_submit")
        self.assertIn("if (!ck->b)\n\t\tck->b = b;", submit)
        fill = body(self.text, "xdev_ext_ce_fill_cqe")
        self.assertIn("const struct xdev_ext_ce_cookie *ck = xdev_ext_mech_batch_cookie(b);", fill)
        core = (ROOT / "io_uring/xdev_ext_mech.c").read_text(encoding="utf-8")
        buffers = body(core, "xdev_ext_mech_session_buffers")
        self.assertIn("s->cookies = kvcalloc(s->depth, cookie, GFP_KERNEL);", buffers)
        self.assertIn("b->cookie = cookie ? s->cookies + (size_t)i * cookie : NULL;",
                      buffers)
        self.assertIn("memset(b->priv, 0, s->priv_size);", body(core, "xdev_ext_mech_build"))
        self.assertNotRegex(core, r"memset\(\s*(?:b->cookie|s->cookies)")


class ClassIsolationTest(unittest.TestCase):
    """A chain is three class files plus one BPF object, not paired C."""

    def test_detector_sees_cross_class_symbols(self):
        ids = identifiers("struct xdp_desc d; /* nvme_x */ f(\"xsk_y\");\n"
                          "nvme_submit(XDEV_EXT_CE_OK, xdev_ext_ce_complete, device);")
        self.assertEqual(nvme_symbols(ids), ["nvme_submit"])
        self.assertEqual(afxdp_symbols(ids), ["xdp_desc"])
        self.assertEqual(ce_symbols(ids), ["XDEV_EXT_CE_OK", "xdev_ext_ce_complete"])

    def test_ce_class_has_no_nvme_or_afxdp_symbols(self):
        for path in (CE, CE_CORE):
            ids = identifiers(path.read_text(encoding="utf-8"))
            self.assertEqual(nvme_symbols(ids), [], path.name)
            self.assertEqual(afxdp_symbols(ids), [], path.name)

    def test_nvme_class_has_no_afxdp_or_ce_symbols(self):
        if not NVME_CLASS.is_file():
            self.skipTest(f"{NVME_CLASS.relative_to(ROOT)} not in this tree")
        ids = identifiers(NVME_CLASS.read_text(encoding="utf-8"))
        self.assertEqual(afxdp_symbols(ids), [])
        self.assertEqual(ce_symbols(ids), [])


class CeSimulateTest(unittest.TestCase):
    """The CPU stand-in backend, kept apart from the real implementation."""

    def setUp(self):
        self.sim = (SIM / "xdev_ext_ce_sim.c").read_text(encoding="utf-8")

    def test_stand_in_is_documented_and_out_of_tree(self):
        readme = (SIM / "README").read_text(encoding="utf-8")
        self.assertIn("memcpy", readme)
        self.assertIn("stand-in", readme)
        makefile = (SIM / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(makefile, r"(?m)^obj-m\s*:=\s*xdev_ext_ce_sim\.o$")

    def test_real_implementation_never_names_the_stand_in(self):
        paths = sorted((ROOT / "io_uring").glob("*"))
        paths += [ROOT / "include/linux/xdev_ext_mech.h",
                  ROOT / "include/uapi/linux/xdev_ext_mech.h"]
        for path in paths:
            if path.is_file():
                self.assertNotIn("xdev_ext_ce_sim", path.read_text(
                    encoding="utf-8", errors="replace"), path.name)

    def test_registers_like_a_real_backend(self):
        table = re.search(
            r"struct xdev_ext_ce_backend_ops xdev_ext_ce_sim_backend = {(.*?)};",
            self.sim, re.S)
        self.assertIsNotNone(table)
        # The owner pin is what keeps a sequestered session's module busy.
        self.assertIn(".owner\t\t= THIS_MODULE,", table.group(1))
        self.assertIn(".fops\t\t= &xdev_ext_ce_sim_fops,", table.group(1))
        ordered(self, body(self.sim, "xdev_ext_ce_sim_init"), "vzalloc(",
                "alloc_workqueue(", "misc_register(",
                "xdev_ext_ce_backend_register(&xdev_ext_ce_sim_backend)")
        ordered(self, body(self.sim, "xdev_ext_ce_sim_exit"),
                "xdev_ext_ce_backend_unregister(&xdev_ext_ce_sim_backend)",
                "misc_deregister(", "destroy_workqueue(", "synchronize_rcu(",
                "vfree(")

    def test_failure_modes_report_the_submission_boundary(self):
        self.assertRegex(self.sim, r'"none",\s*\[SIM_FAIL_PRE_SUBMIT\]\s*=\s*'
                         r'"pre_submit",\s*\[SIM_FAIL_AMBIGUOUS\]\s*=\s*'
                         r'"ambiguous"')
        work = body(self.sim, "xdev_ext_ce_sim_work")
        pre = work[work.index("case SIM_FAIL_PRE_SUBMIT:"):
                   work.index("case SIM_FAIL_AMBIGUOUS:")]
        amb = work[work.index("case SIM_FAIL_AMBIGUOUS:"):
                   work.index("default:")]
        self.assertIn("req->hw_submitted = false;", pre)
        self.assertNotIn("xdev_ext_ce_sim_copy(", pre)
        self.assertIn("req->hw_submitted = true;", amb)
        ordered(self, work, "switch (req->mode)", "hrtimer_start(",
                "xdev_ext_ce_sim_finish(req)")

    def test_completion_from_the_workqueue_or_an_hrtimer(self):
        ordered(self, body(self.sim, "xdev_ext_ce_sim_timer"),
                "xdev_ext_ce_sim_finish(", "return HRTIMER_NORESTART;")
        ordered(self, body(self.sim, "xdev_ext_ce_sim_finish"),
                "xdev_ext_ce_complete(req->ck, req->ticket,", "kfree(req)")
        ordered(self, body(self.sim, "xdev_ext_ce_sim_submit"), "kzalloc(",
                "memcpy(req->x, x,", "req->ticket = ticket;",
                "queue_work(xdev_ext_ce_sim_wq")

    def test_device_refuses_out_of_range_before_copying(self):
        copy = body(self.sim, "xdev_ext_ce_sim_copy")
        ordered(self, copy, "return -EFAULT;", "memcpy(")


if __name__ == "__main__":
    unittest.main()
