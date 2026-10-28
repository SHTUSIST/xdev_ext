#!/usr/bin/env python3
"""Hardware registry and admission evidence tests; performs no hardware action."""
import copy
import dataclasses
import importlib
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

CASES = ("bringup", "strict-swiotlb", "strict-no-path", "explicit-unverified-override",
         "external-owner-refusal", "functional-epochs", "bulk-static", "stop-inflight",
         "cable-loss", "remove-on-resume", "peer-reboot", "idle-suspend-resume",
         "idle-module-unload")


def diagnostic(seq=101, when=1100, **changes):
    fields = dict(session=99, stage=0, requester="0000:07:00.0", errno=-18,
                  reachability=2, distance=-1, backing=1, refused=1, mapped=0)
    fields.update(changes)
    text = ("XDEV_EXT_XDOMAIN_ADMIT session={session} stage={stage} requester={requester} "
            "errno={errno} reachability={reachability} distance={distance} "
            "backing=0x{backing:x} refused=0x{refused:x} mapped={mapped}").format(**fields)
    return dict(seq=seq, monotonic_ns=when, message=text)


def window(**changes):
    result = dict(cursor_seq=100, begin_ns=1000, end_ns=1200,
                  exclusive_creator=True, lock_held=True, complete=True,
                  kmsg_lost=False, readable=True)
    result.update(changes)
    return result


class AdmissionAssociation(unittest.TestCase):
    def setUp(self):
        self.admission = importlib.import_module("admission")
        self.expected = dict(requester="0000:07:00.0", stage=0, errno=-18)

    def match(self, records, bounds=None):
        return self.admission.match_admission(records, window() if bounds is None else bounds,
                                              self.expected)

    def incomplete(self, records, bounds=None):
        answer = self.match(records, bounds)
        self.assertEqual(answer["status"], "incomplete")
        self.assertIsNone(answer["matched"])
        self.assertTrue(answer["reason"])

    def test_exactly_one_complete_record_retains_every_scalar(self):
        answer = self.match([diagnostic()])
        self.assertEqual(answer, dict(status="matched", reason="", matched=dict(
            session=99, stage=0, requester="0000:07:00.0", errno=-18,
            reachability=2, distance=-1, backing=1, refused=1, mapped=0)))

    def test_stale_identical_record_before_cursor_cannot_match(self):
        self.incomplete([diagnostic(seq=100), diagnostic(seq=99)])
        self.assertEqual(self.match([diagnostic(seq=99), diagnostic()])["status"], "matched")

    def test_two_matches_are_ambiguous(self):
        self.incomplete([diagnostic(), diagnostic(seq=102, when=1101)])

    def test_unrelated_concurrent_admission_is_not_ignored(self):
        for change in ({"requester": "0000:08:00.0"}, {"stage": 1}, {"errno": -16}):
            with self.subTest(change=change):
                self.incomplete([diagnostic(), diagnostic(seq=102, when=1101, **change)])

    def test_outside_invocation_interval_and_missing_diagnostic_incomplete(self):
        for records in ([], [diagnostic(when=999)], [diagnostic(when=1201)],
                        [dict(seq=101, monotonic_ns=1100, message="unrelated kernel line")]):
            with self.subTest(records=records):
                self.incomplete(records)

    def test_exclusive_lock_readability_boundary_and_loss_are_required(self):
        for change in ({"exclusive_creator": False}, {"lock_held": False},
                       {"complete": False}, {"kmsg_lost": True}, {"readable": False},
                       {"end_ns": None}, {"begin_ns": 1300}):
            with self.subTest(change=change):
                self.incomplete([diagnostic()], window(**change))

    def test_malformed_duplicate_missing_or_overflow_scalar_not_match(self):
        for transform in (lambda x: x.replace(" mapped=0", ""),
                          lambda x: x + " refused=0x1",
                          lambda x: x.replace("session=99", "session=18446744073709551616"),
                          lambda x: x.replace("distance=-1", "distance=nan")):
            row = diagnostic()
            row["message"] = transform(row["message"])
            with self.subTest(text=row["message"]):
                self.incomplete([row])


def evidence():
    ident = dict(sha="a" * 40, gpu_bdf="0000:01:00.0", nhi_bdf="0000:07:00.0",
                 local_inc=17, remote_inc=29, boot_id="boot-A")
    return dict(physical_execution=True,
                prerequisites=dict(service_listing=["xdev_ext_xdomain"],
                    software_connection_manager=True, credits=[14],
                    kernel_sha="a" * 40, driver_sha="a" * 40, config="CONFIG_XDEV_EXT=y",
                    nhi="0000:07:00.0", gpu="0000:01:00.0", node="/dev/nvidia0",
                    bdf="0000:01:00.0", acs="recorded", iommu="translated",
                    link_token=901, local_inc=17, remote_inc=29, admission="raw-admission"),
                expected_identity=ident, observed_identity=copy.deepcopy(ident),
                create=dict(attempted=True, error=0, refused=0, reachability="PASSED",
                            stage_caps_queried=True),
                admission=dict(status="matched", matched=dict(refused=0)),
                active_run=dict(session_id=101, batch_id=11, group=71, acceptance_seq=57,
                                local_inc=17, remote_inc=29,
                                identity=dict(version=1, run_id="independent-c", sha="a" * 40,
                                              role="tx", case="functional-epochs",
                                              direction="a-to-b", epoch=3)),
                barrier=dict(native_accepted=True, acceptance_seq=57, inflight=1,
                             start_accepted=True, submitted=1, session_id=101,
                             batch_id=11, group=71, local_inc=17, remote_inc=29,
                             identity=dict(version=1, run_id="independent-c", sha="a" * 40,
                                           role="tx", case="functional-epochs",
                                           direction="a-to-b", epoch=3)),
                action=dict(kind="stop", ack_count=1, boot_id_before="boot-A",
                            boot_id_after="boot-B", new_incarnation=30,
                            logout=True, link_down=True, nhi_removed=True, going_away=True,
                            upstream_still_running_warning=True),
                terminal=dict(stop_proved=True, quiesced=True, sequestered=0,
                              freed=False, verify_ok=True))


class HardwareCases(unittest.TestCase):
    def setUp(self):
        self.registry = importlib.import_module("case_registry")

    def evaluate(self, case_id, facts):
        for key in ("active_run", "barrier"):
            if key in facts and "identity" in facts[key]:
                facts[key]["identity"]["case"] = case_id
        result = self.registry.evaluate_case(case_id, facts)
        self.assertIn(result["status"], ("pass", "failed", "incomplete",
                                        "awaiting-physical-execution", "UNVERIFIED_FORCED"))
        if result["status"] != "pass":
            self.assertTrue(result["reason"])
        return result

    def reject(self, case_id, facts):
        self.assertIn(self.evaluate(case_id, facts)["status"], ("failed", "incomplete"))

    def test_registry_complete_immutable_and_no_hardware_gets_pass(self):
        self.assertEqual(set(self.registry.CASES), set(CASES))
        for case_id in CASES:
            spec = self.registry.CASES[case_id]
            self.assertEqual([f.name for f in dataclasses.fields(spec)],
                             ["case_id", "prerequisites", "action_barrier", "expected_terminal", "required_evidence"])
            self.assertEqual(spec.case_id, case_id)
            self.assertTrue(spec.prerequisites)
            self.assertTrue(spec.required_evidence)
            with self.assertRaises(dataclasses.FrozenInstanceError):
                spec.case_id = "renamed"
            result = self.evaluate(case_id, {"physical_execution": False})
            self.assertEqual(result["status"], "awaiting-physical-execution")

    def test_frozen_six_positive_three_capacity_negative_without_hidden_clamp(self):
        self.assertEqual(tuple(self.registry.GEOMETRY_REQUESTS), (
            (4096, 1, True), (4096, 4, True), (4096, 16, True),
            (65536, 1, True), (65536, 4, True), (262144, 1, True),
            (65536, 16, False), (262144, 4, False), (262144, 16, False)))

    def test_wrong_sha_bdf_or_incarnation_cannot_get_pass(self):
        for field, bad in (("sha", "b" * 40), ("gpu_bdf", "0000:02:00.0"),
                           ("nhi_bdf", "0000:08:00.0"), ("local_inc", 16),
                           ("remote_inc", 28)):
            facts = evidence()
            facts["observed_identity"][field] = bad
            with self.subTest(field=field):
                self.reject("functional-epochs", facts)

    def test_missing_h0_fact_cannot_get_pass(self):
        for field in evidence()["prerequisites"]:
            facts = evidence()
            del facts["prerequisites"][field]
            with self.subTest(field=field):
                self.reject("bringup", facts)

    def test_strict_refusal_requires_actual_failed_create_diagnostic_not_stage_caps(self):
        for case_id, bit in (("strict-swiotlb", 2), ("strict-no-path", 1),
                             ("external-owner-refusal", 32)):
            facts = evidence()
            facts["create"].update(error=-18, refused=bit, reachability="FAILED",
                                    stage_caps_queried=False)
            facts["admission"]["matched"]["refused"] = bit
            self.assertEqual(self.evaluate(case_id, facts)["status"], "pass")
            for change in ({"error": 0}, {"refused": 0}, {"stage_caps_queried": True}):
                bad = copy.deepcopy(facts)
                bad["create"].update(change)
                with self.subTest(case_id=case_id, change=change):
                    self.reject(case_id, bad)
            facts["admission"]["status"] = "incomplete"
            self.reject(case_id, facts)

    def test_override_only_no_path_and_forced_outcome_never_topology_pass(self):
        facts = evidence()
        facts["create"].update(refused=1, reachability="UNVERIFIED_FORCED")
        facts["admission"]["matched"]["refused"] = 1
        forced = self.evaluate("explicit-unverified-override", facts)
        self.assertEqual(forced["status"], "UNVERIFIED_FORCED")
        self.assertEqual(forced["outcome"], "UNVERIFIED_FORCED")
        for refused in (1 | 2, 1 | 32, 1 | 2 | 32):
            bad = copy.deepcopy(facts)
            bad["create"]["refused"] = refused
            bad["admission"]["matched"]["refused"] = refused
            with self.subTest(refused=refused):
                self.reject("explicit-unverified-override", bad)

    def test_start_accepted_or_submitted_is_not_native_inflight_barrier(self):
        for change in ({"native_accepted": False}, {"acceptance_seq": 0},
                       {"inflight": 0}, {"local_inc": 16}, {"remote_inc": 28}):
            facts = evidence()
            facts["barrier"].update(change)
            with self.subTest(change=change):
                self.reject("stop-inflight", facts)

    def test_matching_native_inflight_and_successful_stop_is_positive_contract(self):
        self.assertEqual(self.evaluate("stop-inflight", evidence())["status"], "pass")

    def test_complete_bringup_and_verified_functional_contracts_are_positive(self):
        for case_id in ("bringup", "functional-epochs", "bulk-static"):
            with self.subTest(case_id=case_id):
                self.assertEqual(self.evaluate(case_id, evidence())["status"], "pass")

    def test_native_acceptance_must_match_independent_active_run(self):
        for field, bad in (("session_id", 102), ("batch_id", 12), ("group", 72),
                           ("acceptance_seq", 58), ("local_inc", 18), ("remote_inc", 30)):
            facts = evidence()
            facts["barrier"][field] = bad
            with self.subTest(field=field):
                self.reject("stop-inflight", facts)
        for field, bad in (("run_id", "other"), ("sha", "b" * 40), ("epoch", 2),
                           ("role", "rx"), ("direction", "b-to-a")):
            facts = evidence()
            facts["barrier"]["identity"][field] = bad
            with self.subTest(identity_field=field):
                self.reject("stop-inflight", facts)

    def test_duplicate_action_ack_is_not_an_action_barrier(self):
        facts = evidence()
        facts["action"]["ack_count"] = 2
        self.reject("stop-inflight", facts)

    def test_disconnect_is_not_peer_reboot_without_new_boot_and_incarnation(self):
        facts = evidence()
        facts["action"]["kind"] = "reboot"
        self.assertEqual(self.evaluate("peer-reboot", facts)["status"], "pass")
        for change in ({"boot_id_after": "boot-A"}, {"new_incarnation": 29},
                       {"kind": "ssh-eof"}):
            bad = copy.deepcopy(facts)
            bad["action"].update(change)
            with self.subTest(change=change):
                self.reject("peer-reboot", bad)

    def test_cable_loss_requires_operator_event_not_ssh_eof(self):
        facts = evidence()
        facts["action"]["kind"] = "ssh-eof"
        self.reject("cable-loss", facts)

    def test_remove_resume_missing_native_removal_or_hidden_warning_incomplete(self):
        for field in ("nhi_removed", "going_away", "upstream_still_running_warning"):
            facts = evidence()
            facts["action"]["kind"] = "remove-on-resume"
            facts["action"][field] = False
            with self.subTest(field=field):
                self.reject("remove-on-resume", facts)

    def test_idle_unload_requires_logout_and_link_down(self):
        for change in ({"logout": False}, {"link_down": False}):
            facts = evidence()
            facts["action"].update(kind="unload", **change)
            with self.subTest(change=change):
                self.reject("idle-module-unload", facts)

    def test_sequestered_free_and_unknown_callback_never_quiesced(self):
        facts = evidence()
        facts["terminal"].update(sequestered=1, freed=True, quiesced=False)
        for case_id in ("stop-inflight", "cable-loss", "remove-on-resume"):
            with self.subTest(case_id=case_id):
                self.reject(case_id, facts)


if __name__ == "__main__":
    unittest.main()
