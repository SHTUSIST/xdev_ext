#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source contract of the copy-engine class: orderings the unit test cannot see."""

import re
import unittest
from pathlib import Path
import json

def source_owner():
    """Find the canonical owner of this test or its ordinary registered copy."""
    for parent in Path(__file__).resolve().parents:
        marker = parent / 'view.json'
        if marker.is_file():
            receipt = json.loads(marker.read_text())
            if receipt.get('kind') == 'host-source-view':
                return Path(receipt['canonical_root']).resolve()
        if (parent / 'source-layout.json').is_file():
            return parent
    raise RuntimeError('SETUP: no canonical owner or registered source view')


ROOT = source_owner()
CE = ROOT / "src/compute/io_uring/xdev_ext_mech_ce.c"
CE_CORE = ROOT / "src/compute/io_uring/xdev_ext_mech_ce_core.h"
NVME_CLASS = ROOT / "src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c"
SIM = ROOT / "tests/support/ce_sim"


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
        self.common = (ROOT / "src/compute/io_uring/xdev_ext_compfam_copy.c").read_text(encoding="utf-8")
        lease = ROOT / "src/compute/io_uring/xdev_ext_compfam_copy_lease.c"
        self.lease = lease.read_text(encoding="utf-8") if lease.is_file() else None

    def test_built_with_its_config(self):
        makefile = (ROOT / "src/core/io_uring/Makefile").read_text(encoding="utf-8")
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
        self.assertIn(".desc_cap\t= XDEV_EXT_CE_RANGE_MAX_ENTRIES,", table)
        self.assertNotIn("default_build", table)
        self.assertIn("xdev_ext_mech_class_register(&xdev_ext_ce_class)", self.text)

    def test_backend_found_by_f_op_and_pinned_under_the_lock(self):
        get = body(self.text, "xdev_ext_ce_backend_get")
        self.assertIn("xdev_ext_comp_copy_registry_get(&xdev_ext_ce_registry, file, &member)", get)
        ordered(self, get, "xdev_ext_comp_copy_registry_get(", "return member.identity;")
        ordered(self, body(self.common, "xdev_ext_comp_copy_registry_get"),
                "mutex_lock(&registry->lock)", "p->member.fops == file->f_op",
                "try_module_get(", "*out = p->member;", "mutex_unlock(&registry->lock)")

    def test_bind_order_and_unwind(self):
        bind = body(self.text, "xdev_ext_ce_bind")
        # L11: preserve partially created mappings in st->priv before bind;
        # checked core rollback, not a local unconditional free, owns unwind.
        ordered(self, bind, "xdev_ext_ce_backend_get(", "cs->ops = ops;", "st->priv = cs;",
                "xdev_ext_ce_lease_bind(st, cs, u->arg0, u->arg1)",
                "->bind_region(", "cs->region.ops = cs->ops;",
                "xdev_ext_ce_geom_init(", "->bind_host(",
                ("xdev_ext_comp_copy_lease_hold(&cs->lease, false)" if self.lease is not None
                 else "xdev_ext_ce_lease_bind_ready(cs)"))
        if self.lease is not None:
            # Actual-boundary companions: residual allocation/residual/positive/
            # errors and runtime ce_v2_bind_and_identity; initial/late/ready mutants.
            configured = body(self.text, "xdev_ext_ce_lease_bind")
            ordered(self, configured, "cs->window_start = start;", "cs->window_len = len;",
                    "return xdev_ext_comp_copy_lease_bind(&xdev_ext_ce_lease_domain, &cs->lease,",
                    "st->s, xdev_ext_mech_session_depth(st->s), cs, true)")
            held = body(self.lease, "xdev_ext_comp_copy_lease_bind")
            ordered(self, held, "mutex_lock(&domain->lock)", "region->cleanup_held = hold_at_bind;",
                    "if (hold_at_bind)", "found->cleanup_holds++;",
                    "list_add_tail(&region->node, &found->regions)")
            host = bind[bind.index("err = cs->ops->bind_host("):]
            ordered(self, host, "if (err)", "return err;",
                    "xdev_ext_comp_copy_lease_hold(&cs->lease, false)", "return 0;")
        self.assertNotIn("->unbind_region(", bind)
        self.assertNotIn("module_put(", bind)
        core = (ROOT / "src/core/io_uring/xdev_ext_mech.c").read_text(encoding="utf-8")
        bind_stages = body(core, "xdev_ext_mech_session_bind")
        self.assertRegex(bind_stages,
                         r"if \(st->cls->unbind_checked && st->priv\)\s+s->nr_bound\+\+;")

    def test_unbind_never_after_ambiguous(self):
        # Follow checked common cleanup and the actual CE policy callbacks.
        unbind = body(self.text, "xdev_ext_ce_unbind")
        ordered(self, unbind, "xdev_ext_comp_copy_unbind(&cs->copy)",
                "if (err)", "return err;", "st->priv = NULL;", "kfree(cs)", "module_put(")
        checked = body(self.common, "xdev_ext_comp_copy_unbind")
        ordered(self, checked, "atomic_read(&cs->ambiguous)", "return -EBUSY;",
                "cs->ops->unbind_begin(cs)", "cs->ops->unbind_host(cs)",
                "cs->host = NULL;", "cs->ops->unbind_region(cs)", "cs->ops->unbind_end(cs)")
        for name in ("unbind_begin", "unbind_host", "unbind_region"):
            part = checked[checked.index("err = cs->ops->"+name):]
            ordered(self, part, "if (err)", "return err;")
        begin = body(self.text, "xdev_ext_ce_copy_unbind_begin")
        if self.lease is None:
            self.assertIn("xdev_ext_ce_lease_cleanup_begin(cs)", begin)
        else:
            # Teardown refusing-host/region/retry and residual multistage/refusals/
            # atomic_cleanup exercise these real begin/end boundaries and locks.
            self.assertIn("return xdev_ext_comp_copy_lease_cleanup_begin(&cs->lease);", begin)
            cleanup = body(self.lease, "xdev_ext_comp_copy_lease_cleanup_begin")
            ordered(self, cleanup, "if (!group)", "return 0;", "mutex_lock(&domain->lock)",
                    "group->state.active_batches || group->state.quarantined",
                    "mutex_unlock(&domain->lock)", "return -EBUSY;",
                    "if (!region->cleanup_held)", "region->cleanup_held = true;",
                    "group->cleanup_holds++;")
            self.assertEqual(cleanup.count("mutex_lock(&domain->lock)"), 1)
            hold = cleanup[cleanup.index("if (!region->cleanup_held)"):]
            ordered(self, hold, "group->cleanup_holds++;", "mutex_unlock(&domain->lock)", "return 0;")
        self.assertIn("cs->ops->unbind_host(copy->host)", body(self.text, "xdev_ext_ce_copy_unbind_host"))
        region = body(self.text, "xdev_ext_ce_copy_unbind_region")
        ordered(self, region, "cs->ops->unbind_region(&cs->region)", "if (err)",
                "return err;", "cs->region.priv = NULL;")
        end = body(self.text, "xdev_ext_ce_copy_unbind_end")
        if self.lease is None:
            self.assertIn("xdev_ext_ce_lease_unbind(cs)", end)
        else:
            ordered(self, end, "if (cs->lease.group &&",
                    "WARN_ON_ONCE(!xdev_ext_comp_copy_lease_unbind(&cs->lease, true))",
                    "return -EBUSY;", "return 0;")
            detach = body(self.lease, "xdev_ext_comp_copy_lease_unbind")
            ordered(self, detach, "mutex_lock(&domain->lock)",
                    "group->state.active_batches || group->state.quarantined",
                    "mutex_unlock(&domain->lock)", "return false;",
                    "if (release_hold && region->cleanup_held)", "group->cleanup_holds--;",
                    "region->cleanup_held = false;", "list_del(&region->node)",
                    "region->group = NULL;")
            critical = detach[detach.index("if (release_hold && region->cleanup_held)"):
                              detach.index("region->group = NULL;")]
            self.assertNotIn("mutex_unlock(", critical)
            self.assertEqual(detach.count("mutex_lock(&domain->lock)"), 1)
            ordered(self, detach[detach.index("region->group = NULL;"):],
                    "list_del(&group->node)", "mutex_unlock(&domain->lock)", "kvfree(group)")
        for name in ("unbind_begin", "unbind_host", "unbind_region", "unbind_end"):
            self.assertIn("."+name+" = xdev_ext_ce_copy_"+name+",", self.text)
        self.assertRegex(self.text, r"\.unbind_checked\s*=\s*xdev_ext_ce_unbind")

    def test_validate_stages_only_an_accepted_plan(self):
        self.assertIn("xdev_ext_comp_copy_stage_validate(&cs->copy, b, scratch, n,",
                      body(self.text, "xdev_ext_ce_validate"))
        validate = body(self.common, "xdev_ext_comp_copy_stage_validate")
        ordered(self, validate, "cs->staged = NULL;", "xdev_ext_comp_copy_validate(",
                "if (err)", "cs->staged = b;")

    def test_submit_arms_before_the_backend_and_takes_back_a_refusal(self):
        self.assertIn("xdev_ext_comp_copy_stage_submit(&cs->copy, st, b)",
                      body(self.text, "xdev_ext_ce_submit"))
        submit = body(self.common, "xdev_ext_comp_copy_stage_submit")
        self.assertIn("struct xdev_ext_comp_copy_cookie *ck = xdev_ext_mech_batch_cookie(b);", submit)
        ordered(self, submit, "cs->ops->lease_get(cs, b)", "xdev_ext_window_copy_cookie_arm(",
                "ck->b = b;", "cs->staged = NULL;", "READ_ONCE(cs->dead)",
                "staged != b", "xdev_ext_comp_copy_transfer(", "cs->ops->submit(",
                "xdev_ext_window_copy_cookie_disarm(")
        self.assertIn("err = -ENODEV;", submit)
        self.assertIn("xdev_ext_mech_batch_ticket(b)", submit)
        get = body(self.text, "xdev_ext_ce_copy_lease_get")
        if self.lease is None:
            self.assertIn("return xdev_ext_ce_lease_get(cs, b);", get)
        else:
            # Runtime lease_refusal, provider overlap/depth/shifted/unmap controls
            # and the actual-get bypass mutation exercise this admission edge.
            self.assertIn("return xdev_ext_comp_copy_lease_get(&cs->lease,\n"
                          "\t\txdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));", get)
            self.assertNotIn("xdev_ext_mech_batch_ticket", get)
        refusal = submit[submit.index("err = cs->ops->lease_get(cs, b)"):
                         submit.index("xdev_ext_window_copy_cookie_arm(")]
        ordered(self, refusal, "if (err)", "return err;")
        self.assertNotIn("cs->staged = NULL;", refusal)
        adapted = body(self.text, "xdev_ext_ce_copy_submit")
        ordered(self, adapted, "cb->x[i]", "cs->ops->submit(")
        for name in ("lease_get", "submit"):
            self.assertIn("."+name+" = xdev_ext_ce_copy_"+name+",", self.text)

    def test_completion_classified_once_and_ambiguous_sequestered(self):
        wrapper = body(self.text, "xdev_ext_ce_complete")
        self.assertIn("xdev_ext_comp_copy_complete(", wrapper)
        self.assertIn("status, hw_submitted, bytes_done, &xdev_ext_ce_copy_ops)", wrapper)
        classify = body(self.text, "xdev_ext_ce_copy_classify")
        self.assertIn("xdev_ext_ce_classify(*status, *hw_submitted)", classify)
        self.assertIn(".classify = xdev_ext_ce_copy_classify,", self.text)
        complete = body(self.common, "xdev_ext_comp_copy_complete")
        self.assertRegex(complete, r"if \(xdev_ext_mech_batch_completion_claim\(ck->b, ticket\)\)\s+return;")
        ordered(self, complete, "xdev_ext_mech_batch_completion_claim(ck->b, ticket)",
                "xdev_ext_window_copy_cookie_finish(", "ops->classify(",
                "ck->outcome = ", "xdev_ext_window_copy_disposition(")
        ambiguous = complete[complete.index("sequester = xdev_ext_window_copy_disposition("):]
        ordered(self, ambiguous, "if (sequester)", "atomic_inc(&ck->cs->ambiguous)",
                "xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, sequester);")
        invalid = complete[complete.index("if (!xdev_ext_window_copy_cookie_finish("):
                           complete.index("outcome = ops->classify(")]
        ordered(self, invalid, "atomic_inc(&ck->cs->ambiguous)",
                "xdev_ext_mech_batch_completion_publish(ck->b, ticket, -EPROTO, true);", "return;")
        # Normal and ambiguous publish share the exact disposition boolean now;
        # invalid-cookie publication remains its own unconditional quarantine.
        self.assertEqual(complete.count("xdev_ext_mech_batch_completion_publish("), 2)
        claim = complete.index("xdev_ext_mech_batch_completion_claim(ck->b, ticket)")
        for metadata in ("xdev_ext_window_copy_cookie_finish(", "ck->outcome = ",
                         "ck->status = ", "ck->bytes_done = "):
            self.assertLess(claim, complete.index(metadata))

    def test_callback_cookie_survives_stage_private_area_reset(self):
        batch = re.search(r"struct xdev_ext_ce_batch {\n(.*?)\n};", self.text,
                          re.S).group(1)
        self.assertNotIn("xdev_ext_ce_cookie", batch)
        self.assertIn(".batch_cookie_size = sizeof(struct xdev_ext_comp_copy_cookie)", self.text)
        submit = body(self.common, "xdev_ext_comp_copy_stage_submit")
        self.assertIn("if (!ck->b)\n\t\tck->b = b;", submit)
        fill = body(self.text, "xdev_ext_ce_fill_cqe")
        self.assertIn("const struct xdev_ext_comp_copy_cookie *ck = xdev_ext_mech_batch_cookie(b);", fill)
        core = (ROOT / "src/core/io_uring/xdev_ext_mech.c").read_text(encoding="utf-8")
        buffers = body(core, "xdev_ext_mech_session_buffers")
        # L11: preallocated fan-out branches each retain their own stable cookie.
        self.assertIn("s->cookies = kvcalloc(s->depth * (XDEV_EXT_MECH_MAX_STAGES + 1), cookie, GFP_KERNEL);", buffers)
        self.assertIn("offset = s->depth + i * XDEV_EXT_MECH_MAX_STAGES + j;", buffers)
        self.assertIn("child->cookie = cookie ? s->cookies + (size_t)offset * cookie : NULL;", buffers)
        self.assertIn("xdev_ext_mech_completion_init(&child->completion)", buffers)
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
        paths = sorted(path for area in ("core", "compute", "storage", "network")
                       for path in (ROOT / "src" / area / "io_uring").rglob("*"))
        paths += [ROOT / "src/core/include/linux/xdev_ext_mech.h",
                  ROOT / "src/core/include/uapi/linux/xdev_ext_mech.h"]
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
