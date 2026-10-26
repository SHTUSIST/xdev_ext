# SPDX-License-Identifier: GPL-2.0
"""Hardware cases remain visible even when physical execution is unavailable."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    prerequisites: tuple
    action_barrier: str
    expected_terminal: str
    required_evidence: tuple


_NAMES = (
    "bringup",
    "strict-swiotlb",
    "strict-no-path",
    "explicit-unverified-override",
    "external-owner-refusal",
    "functional-epochs",
    "bulk-static",
    "stop-inflight",
    "cable-loss",
    "remove-on-resume",
    "peer-reboot",
    "idle-suspend-resume",
    "idle-module-unload",
)
CASES = {
    name: CaseSpec(
        name,
        ("exclusive-physical-hosts", "identity", "preflight"),
        (
            "accepted-native-inflight"
            if name
            in ("stop-inflight", "cable-loss", "remove-on-resume", "peer-reboot")
            else "idle-or-terminal"
        ),
        (
            "UNVERIFIED_FORCED"
            if name == "explicit-unverified-override"
            else (
                "strict-refusal"
                if name.startswith("strict-") or name == "external-owner-refusal"
                else "safe-or-retained"
            )
        ),
        ("identity", "create", "terminal"),
    )
    for name in _NAMES
}
GEOMETRY_REQUESTS = (
    (4096, 1, True),
    (4096, 4, True),
    (4096, 16, True),
    (65536, 1, True),
    (65536, 4, True),
    (262144, 1, True),
    (65536, 16, False),
    (262144, 4, False),
    (262144, 16, False),
)


def evaluate_case(case_id, evidence):
    if case_id not in CASES:
        raise ValueError("unknown hardware case")

    def result(status, reason, outcome=None):
        d = {
            "case_id": case_id,
            "status": status,
            "reason": reason,
            "evidence_scope": "contract-evaluation",
            "physical_dma_proved": False,
        }
        if outcome is not None:
            d["outcome"] = outcome
        return d

    e = evidence
    if e.get("physical_execution") is not True:
        return result(
            "awaiting-physical-execution", "physical execution has not occurred"
        )
    try:
        p = e["prerequisites"]
        expected = e["expected_identity"]
        observed = e["observed_identity"]
        if expected != observed:
            return result("failed", "physical identity mismatch")
        required = (
            "service_listing",
            "software_connection_manager",
            "credits",
            "kernel_sha",
            "driver_sha",
            "config",
            "nhi",
            "gpu",
            "node",
            "bdf",
            "acs",
            "iommu",
            "link_token",
            "local_inc",
            "remote_inc",
            "admission",
        )
        if any(
            k not in p or p[k] is None or p[k] is False or p[k] == "" or p[k] == []
            for k in required
        ):
            return result("incomplete", "missing preflight prerequisite")
        if (
            p["kernel_sha"] != expected["sha"]
            or p["driver_sha"] != expected["sha"]
            or p["bdf"] != expected["gpu_bdf"]
            or p["nhi"] != expected["nhi_bdf"]
            or p["local_inc"] != expected["local_inc"]
            or p["remote_inc"] != expected["remote_inc"]
        ):
            return result("failed", "preflight identity mismatch")
        c = e["create"]
        t = e["terminal"]
        if t.get("sequestered", 0) and t.get("freed"):
            return result("failed", "sequestered resources were freed")
        if t.get("unknown_callback") or t.get("callback_unknown"):
            return result("incomplete", "unknown callback cannot prove quiescence")
        refusals = {
            "strict-swiotlb": 2,
            "strict-no-path": 1,
            "external-owner-refusal": 32,
        }
        if case_id in refusals:
            a = e["admission"]
            if not c.get("attempted") or c.get("error", 0) >= 0:
                return result("failed", "strict request unexpectedly succeeded")
            if c.get("stage_caps_queried"):
                return result("failed", "STAGE_CAPS queried after failed CREATE")
            if a.get("status") != "matched" or not a.get("matched"):
                return result(
                    "incomplete", "strict refusal lacks associated diagnostic"
                )
            if not (a["matched"].get("refused", 0) & refusals[case_id]) or not (
                c.get("refused", 0) & refusals[case_id]
            ):
                return result("failed", "wrong refusal bit")
            return result("pass", "associated strict refusal observed", "REFUSED")
        if case_id == "explicit-unverified-override":
            if (
                c.get("error")
                or c.get("refused", 0) & ~1
                or c.get("reachability") not in ("UNVERIFIED_FORCED", 3)
            ):
                return result(
                    "failed", "override exceeded NO_P2P_PATH or lacks forced outcome"
                )
            return result(
                "UNVERIFIED_FORCED",
                "explicit unverified override recorded",
                "UNVERIFIED_FORCED",
            )
        if c.get("error") or not c.get("attempted") or not c.get("stage_caps_queried"):
            return result("incomplete", "successful CREATE and STAGE_CAPS required")
        native = case_id in (
            "stop-inflight",
            "cable-loss",
            "remove-on-resume",
            "peer-reboot",
        )
        if native:
            b = e["barrier"]
            active = e["active_run"]
            if (
                b.get("native_accepted") is not True
                or type(b.get("inflight")) is not int
                or b["inflight"] <= 0
            ):
                return result(
                    "incomplete", "no actual accepted native work still inflight"
                )
            for k in (
                "session_id",
                "batch_id",
                "group",
                "acceptance_seq",
                "local_inc",
                "remote_inc",
                "identity",
            ):
                if k not in b or b[k] != active[k]:
                    return result("failed", "native acceptance identity mismatch")
            if not b["acceptance_seq"]:
                return result("incomplete", "no native acceptance sequence")
        if case_id in (
            "stop-inflight",
            "cable-loss",
            "remove-on-resume",
            "peer-reboot",
            "idle-suspend-resume",
            "idle-module-unload",
        ):
            a = e["action"]
            if a.get("ack_count") != 1:
                return result("incomplete", "action requires one acknowledgement")
            expected_action = {
                "stop-inflight": "stop",
                "cable-loss": "cable-loss",
                "remove-on-resume": "remove-on-resume",
                "peer-reboot": "reboot",
                "idle-suspend-resume": "suspend-resume",
                "idle-module-unload": "unload",
            }[case_id]
            if a.get("kind") != expected_action:
                return result("incomplete", "missing physical action event")
            if case_id == "cable-loss" and not (
                a.get("operator_event") or a.get("cable_event")
            ):
                return result("incomplete", "SSH disconnect is not cable evidence")
            if case_id == "peer-reboot":
                if (
                    not a.get("boot_id_after")
                    or a["boot_id_after"] == a.get("boot_id_before")
                    or not a.get("new_incarnation")
                    or a["new_incarnation"]
                    in (expected["local_inc"], expected["remote_inc"])
                ):
                    return result(
                        "incomplete", "reboot needs new boot identity and incarnation"
                    )
            if case_id == "remove-on-resume" and not all(
                a.get(k) is True
                for k in ("nhi_removed", "going_away", "upstream_still_running_warning")
            ):
                return result(
                    "incomplete", "missing native removal or upstream warning evidence"
                )
            if case_id == "idle-module-unload" and not (
                a.get("logout") is True and a.get("link_down") is True
            ):
                return result("incomplete", "unload needs LOGOUT and link-down")
        if t.get("sequestered", 0):
            if t.get("freed"):
                return result("failed", "sequestered resource freed")
            return result("incomplete", "resources retained; quiescence unproved")
        if not t.get("stop_proved") or not t.get("quiesced"):
            return result("incomplete", "native release unproved")
        if case_id in ("functional-epochs", "bulk-static") and not t.get("verify_ok"):
            return result("failed", "payload verification absent or failed")
        return result("pass", "all required contract evidence present", "PASSED")
    except (KeyError, TypeError, ValueError):
        return result("incomplete", "missing or malformed physical evidence")
