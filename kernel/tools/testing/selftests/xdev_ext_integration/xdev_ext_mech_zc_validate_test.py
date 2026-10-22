#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-only evidence-validation tests; no KVM, network or device access.

The fixtures are synthetic, never evidence that a guest was actually run.
Run directly with python3 xdev_ext_mech_zc_validate_test.py -v.
"""

import hashlib
import importlib.util
import sys
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
HELPER = HERE / "xdev_ext_mech_zc_validate.py"
GROUP_BYTES = 8192
GROUPS = 8
SOURCE_OFF = 2048 * 512
RX_OFF = 4096 * 512
CE_OFF = 8192 * 512


def iaa_console_fixture():
    """Synthetic IAA evidence; never an executed guest result."""
    lines = []
    for mode in ('normal', 'delay', 'stale', 'duplicate'):
        lines.append(f"PASS IAA case={mode} groups=257 depth=8 software=deflate-generic "
                     "compressed_min=25 compressed_max=4101 actual_lengths=257 restored_bytes=1052672 "
                     "full_source=1 all_window_guards=1 all_pool_guards=1 mutation_rejects=4 "
                     "stage_counts=257,257,257,257 native_accepted=514 native_completed=514 "
                     "pending=0 owners_released=1 dma_cpu_simulation=1")
    lines.append("PASS IAA case=stop groups=257 depth=8 pending_drained=1 owners_released=1 "
                 "full_source_and_guards=1 software=deflate-generic dma_cpu_simulation=1 "
                 "stopped_stage=DMA native_accepted=8 native_completed=8 pending=0 region_unbinds=2 host_unbinds=2")
    lines.extend(["PASS IAA software campaign unloaded provider after complete ownership return",
                  "XDEV_EXT_IAA_SOFTWARE=PASS cases=5 groups=257 depth=8 "
                  "backend=deflate-generic dma_backend=CPU-memcpy-standin"])
    return "\n".join(lines) + "\n"


def console_fixture(*, fault="none", ce_sim=True, delay_us=100000, rx_ce=False):
    """Public line protocol, including the receiver's own labelled stats."""
    drop = fault == "drop-middle"
    done = 1 if drop else GROUPS
    lines = [
        "[    0.1] Linux version synthetic-fixture",
        f"XDEV_EXT_ZC_CE_DELAY_US={delay_us}",
        "XDEV_EXT_MECH_READY mode=source session=18 xsk=zc",
        "XDEV_EXT_ZC_RX_STATS session=17 state={} last_err={} batches_done={} "
        "batches_abort={} rejects=0 recycled={recycled} held=48 sequestered=0 "
        "timeouts={} inflight=0 native_publish=0 protocol_err=0 published=0 "
        "submitted=0,{done},0,0 completed={done},{done},0,0".format(
            "STOPPED" if drop else "ACTIVE",
            "-ETIMEDOUT" if drop else "0", done, int(drop), int(drop),
            done=done, recycled=48 + int(fault == "duplicate-middle")),
        "XDEV_EXT_ZC_RX_RESULT outcome={} exit={} elapsed_ms=1500 timeout_ms=60000".format(
            "fail-stop" if drop else "success", int(drop)),
        "XDEV_EXT_ZC_FAULT_COUNTS mode={} matched={} dropped={} duplicated={} "
        "session=270019 generation=2 index=2 count=6".format(
            fault, int(fault != "none"), int(drop),
            int(fault == "duplicate-middle")),
        "XDEV_EXT_ZC_TRACE_CONTROL=PASS calls=48",
        "XDEV_EXT_ZC_COPY_FALLBACK=PASS calls=0",
    ]
    if drop:
        lines.append("XDEV_EXT_ZC_FAIL_STOP=PASS")
    else:
        lines.extend([
            "XDEV_EXT_MECH_NIC_NVME_E2E=PASS groups=8 held=48 nvme_submitted=8 "
            "nvme_completed=8 recycled=48 published=0 errors=0 sequestered=0 inflight=0",
            "XDEV_EXT_ZC_CHAIN=PASS",
        ])
    if rx_ce:
        lines = [line.replace(f"submitted=0,{done},0,0", f"submitted=0,{done},{done},{done}")
                 .replace(f"completed={done},{done},0,0", f"completed={done},{done},{done},{done}")
                 for line in lines]
    if ce_sim:
        accepted = 6 * GROUPS + (2 * done if rx_ce else 0)
        lines.extend([
            "XDEV_EXT_MECH_CE_SIM=PASS chain=a",
            "XDEV_EXT_MECH_CE_SIM=PASS chain=d",
            "XDEV_EXT_MECH_CE_SIM=PASS chain=b",
            "XDEV_EXT_ZC_CE_CHAINS=PASS chains=a,b,d backend=CPU-memcpy-standin",
            "XDEV_EXT_ZC_CE_SIM_STATS accepted={} completed={} pending=0 "
            "peak_pending=8 submit_before_first_complete=8 delay_us={}".format(
                accepted, accepted, delay_us),
        ])
    if ce_sim:
        lines.extend(iaa_console_fixture().splitlines())
    lines.append("XDEV_EXT_ZC_GUEST_EXIT=0")
    return "\n".join(lines) + "\n"


def image_fixture(*, fault="none", ce_sim=True, completed=None, groups=GROUPS):
    """Nonzero sentinels expose accidental writes outside either window."""
    ce_off = max(CE_OFF, RX_OFF + (groups + 1) * GROUP_BYTES)
    size = max(16 * 1024 * 1024, ce_off + (groups + 1) * GROUP_BYTES)
    source = bytearray(b"\x7b" * size)
    payload = hashlib.shake_256(b"independent image fixture").digest(groups * GROUP_BYTES)
    source[SOURCE_OFF:SOURCE_OFF + len(payload)] = payload
    before = bytes(b"\xa5" * size)
    after = bytearray(before)
    done = (1 if fault == "drop-middle" else groups) if completed is None else completed
    after[RX_OFF:RX_OFF + done * GROUP_BYTES] = payload[:done * GROUP_BYTES]
    if ce_sim:
        after[ce_off:ce_off + len(payload)] = payload
    return bytes(source), bytes(source), before, bytes(after)


class HelperContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(),
                        "missing host console/image validator required by async/loss harness")
        spec = importlib.util.spec_from_file_location("xdev_ext_mech_zc_validate", HELPER)
        self.helper = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.helper
        spec.loader.exec_module(self.helper)
        for name in ("validate_console", "validate_images"):
            self.assertTrue(callable(getattr(self.helper, name, None)),
                            f"validator must export {name}")

    def console(self, text=None, *, fault="none", ce_sim=True, delay_us=100000, rx_ce=False):
        return self.helper.validate_console(
            console_fixture(fault=fault, ce_sim=ce_sim, delay_us=delay_us, rx_ce=rx_ce)
            if text is None else text,
            groups=GROUPS, ce_sim=ce_sim, ce_delay_us=delay_us, fault=fault,
            rx_ce=rx_ce)

    def images(self, images=None, *, fault="none", ce_sim=True, completed=None):
        if completed is None:
            completed = 1 if fault == "drop-middle" else GROUPS
        return self.helper.validate_images(
            *(image_fixture(fault=fault, ce_sim=ce_sim, completed=completed)
              if images is None else images),
            groups=GROUPS, receiver_batches_done=completed,
            ce_sim=ce_sim, fault=fault)


class ConsoleEvidenceTest(HelperContract):
    def test_normal_delayed_eight_groups_proves_overlap(self):
        self.assertEqual(self.console()["receiver_batches_done"], 8)

    def test_old_undelayed_non_ce_control_remains_supported(self):
        self.assertEqual(self.console(ce_sim=False, delay_us=0)["receiver_batches_done"], 8)

    def test_receive_ce_adds_two_real_submissions_per_completed_group(self):
        self.assertEqual(self.console(rx_ce=True)["receiver_batches_done"], 8)

    def test_receive_ce_cannot_be_claimed_with_only_sender_ce_counts(self):
        with self.assertRaises(ValueError):
            self.console(console_fixture(rx_ce=False), rx_ce=True)

    def test_receive_ce_requires_ce_backend(self):
        with self.assertRaises(ValueError):
            self.console(ce_sim=False, delay_us=0, rx_ce=True)

    def test_terminal_console_crlf_is_accepted(self):
        self.assertEqual(self.console(console_fixture().replace("\n", "\r\n"))[
            "receiver_batches_done"], 8)

    def test_serial_completion_fails_even_with_pass_markers(self):
        with self.assertRaises(ValueError):
            self.console(console_fixture().replace("peak_pending=8", "peak_pending=1"))

    def test_submit_before_first_complete_is_required_independently(self):
        with self.assertRaises(ValueError):
            self.console(console_fixture().replace("submit_before_first_complete=8",
                                                   "submit_before_first_complete=1"))

    def test_all_five_sim_counters_are_mandatory(self):
        for field in ("accepted=48", "completed=48", "pending=0", "peak_pending=8",
                      "submit_before_first_complete=8"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.console(console_fixture().replace(field + " ", "", 1))

    def test_counter_balance_and_expected_submit_count(self):
        for old, new in (("completed=48", "completed=47"),
                         ("pending=0 ", "pending=1 "),
                         ("accepted=48", "accepted=47"),
                         ("peak_pending=8", "peak_pending=49"),
                         ("submit_before_first_complete=8", "submit_before_first_complete=49")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture().replace(old, new, 1))

    def test_delay_must_match_requested_value(self):
        with self.assertRaises(ValueError):
            self.console(console_fixture().replace("delay_us=100000", "delay_us=0"))

    def test_receiver_leaks_errors_or_missing_completion_reject_success(self):
        for old, new in (("batches_done=8", "batches_done=7"),
                         ("batches_abort=0", "batches_abort=1"),
                         ("last_err=0", "last_err=-EIO"),
                         ("sequestered=0", "sequestered=1"),
                         ("inflight=0", "inflight=1"),
                         ("native_publish=0", "native_publish=1")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture().replace(old, new, 1))

    def test_duplicate_native_write_cannot_hide_behind_correct_done_count(self):
        for old, new in (("submitted=0,8,0,0", "submitted=0,9,0,0"),
                         ("completed=8,8,0,0", "completed=8,9,0,0")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(fault="duplicate-middle").replace(old, new),
                             fault="duplicate-middle")

    def test_receive_ce_stats_must_cover_both_ce_stages_and_final_nvme(self):
        for new in ("submitted=0,8,0,8", "submitted=0,8,8,0", "submitted=0,9,8,8"):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(rx_ce=True).replace("submitted=0,8,8,8", new),
                             rx_ce=True)

    def test_receiver_requires_rx_completions_without_rx_submissions(self):
        # RX batches complete when all segments have arrived, without a
        # native RX submit.  That completion is independently counted.
        for rx_ce, good, bad in ((False, "completed=8,8,0,0", "completed=0,8,0,0"),
                                 (True, "completed=8,8,8,8", "completed=0,8,8,8")):
            with self.subTest(rx_ce=rx_ce), self.assertRaises(ValueError):
                self.console(console_fixture(rx_ce=rx_ce).replace(good, bad), rx_ce=rx_ce)

    def test_unlabelled_sender_stats_cannot_replace_receiver_stats(self):
        text = console_fixture().replace("XDEV_EXT_ZC_RX_STATS", "XDEV_EXT_MECH_STATS")
        with self.assertRaises(ValueError):
            self.console(text)

    def test_missing_guest_exit_or_nonzero_exit_rejects(self):
        for new in ("", "XDEV_EXT_ZC_GUEST_EXIT=1\n"):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture().replace("XDEV_EXT_ZC_GUEST_EXIT=0\n", new))

    def test_duplicate_contradictory_final_stats_rejected(self):
        text = console_fixture() + "XDEV_EXT_ZC_CE_SIM_STATS accepted=48 completed=47 pending=1 " \
            "peak_pending=8 submit_before_first_complete=8 delay_us=100000\n"
        with self.assertRaises(ValueError):
            self.console(text)

    def test_negative_and_duplicate_counter_fields_rejected(self):
        for old, new in (("pending=0 ", "pending=-1 "),
                         ("accepted=48", "accepted=48 accepted=47")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture().replace(old, new, 1))

    def test_kernel_diagnostic_always_rejects_even_after_pass(self):
        for line in ("BUG: injected", "WARNING: injected", "Kernel panic: injected", "Oops: injected"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.console(console_fixture() + line + "\n")

    def test_false_or_missing_trace_control_rejected(self):
        for old, new in (("XDEV_EXT_ZC_TRACE_CONTROL=PASS calls=48", "XDEV_EXT_ZC_TRACE_CONTROL=PASS calls=0"),
                         ("XDEV_EXT_ZC_COPY_FALLBACK=PASS calls=0", "XDEV_EXT_ZC_COPY_FALLBACK=PASS calls=1")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture().replace(old, new))


class FaultEvidenceTest(HelperContract):
    def test_single_middle_loss_reports_fail_stop_and_incomplete_count(self):
        self.assertEqual(self.console(fault="drop-middle")["receiver_batches_done"], 1)

    def test_duplicate_middle_still_completes_every_group(self):
        self.assertEqual(self.console(fault="duplicate-middle")["receiver_batches_done"], 8)

    def test_receive_ce_loss_counts_only_the_complete_prefix(self):
        self.assertEqual(self.console(fault="drop-middle", rx_ce=True)[
            "receiver_batches_done"], 1)

    def test_receive_ce_loss_cannot_claim_all_requested_receive_submissions(self):
        text = console_fixture(fault="drop-middle", rx_ce=True).replace(
            "accepted=50 completed=50", "accepted=64 completed=64")
        with self.assertRaises(ValueError):
            self.console(text, fault="drop-middle", rx_ce=True)

    def test_receive_ce_duplicate_still_completes_all_receive_ce_stages(self):
        self.assertEqual(self.console(fault="duplicate-middle", rx_ce=True)[
            "receiver_batches_done"], 8)

    def test_drop_requires_one_actual_drop(self):
        for old, new in (("dropped=1", "dropped=0"), ("dropped=1", "dropped=2"),
                         ("matched=1", "matched=0"), ("duplicated=0", "duplicated=1")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(fault="drop-middle").replace(old, new),
                             fault="drop-middle")

    def test_duplicate_requires_one_actual_injection(self):
        for old, new in (("duplicated=1", "duplicated=0"), ("duplicated=1", "duplicated=2"),
                         ("dropped=0", "dropped=1")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(fault="duplicate-middle").replace(old, new),
                             fault="duplicate-middle")

    def test_default_none_has_no_injected_fault(self):
        with self.assertRaises(ValueError):
            self.console(console_fixture().replace("dropped=0", "dropped=1"))

    def test_wrong_wire_target_or_non_middle_segment_rejects(self):
        for old, new in (("session=270019", "session=270020"),
                         ("generation=2", "generation=3"),
                         ("index=2", "index=0"), ("index=2", "index=5"),
                         ("count=6", "count=1")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(fault="drop-middle").replace(old, new),
                             fault="drop-middle")

    def test_loss_cannot_claim_receiver_success_or_full_count(self):
        for old, new in (("outcome=fail-stop", "outcome=success"), ("exit=1", "exit=0"),
                         ("batches_done=1", "batches_done=8")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(fault="drop-middle").replace(old, new),
                             fault="drop-middle")

    def test_loss_cannot_publish_any_later_group_after_generation_two(self):
        with self.assertRaises(ValueError):
            self.console(console_fixture(fault="drop-middle").replace("batches_done=1", "batches_done=2"),
                         fault="drop-middle")

    def test_loss_has_bounded_receiver_termination(self):
        for old, new in (("elapsed_ms=1500", "elapsed_ms=60001"),
                         ("timeout_ms=60000", "timeout_ms=0"),
                         ("elapsed_ms=1500", "elapsed_ms=-1")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.console(console_fixture(fault="drop-middle").replace(old, new),
                             fault="drop-middle")

    def test_fail_stop_label_requires_receiver_error_or_timeout_evidence(self):
        text = console_fixture(fault="drop-middle").replace("state=STOPPED", "state=ACTIVE") \
            .replace("last_err=-ETIMEDOUT", "last_err=0").replace("timeouts=1", "timeouts=0")
        with self.assertRaises(ValueError):
            self.console(text, fault="drop-middle")

    def test_loss_rejects_false_normal_pass_or_a_recovery_claim(self):
        for line in ("XDEV_EXT_ZC_CHAIN=PASS", "XDEV_EXT_MECH_NIC_NVME_E2E=PASS groups=8",
                     "XDEV_EXT_ZC_RECOVERY=PASS"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.console(console_fixture(fault="drop-middle") + line + "\n", fault="drop-middle")


class ImageEvidenceTest(HelperContract):
    def test_long_campaign_has_disjoint_windows_and_complete_guard_checks(self):
        for groups in (257, 1024):
            with self.subTest(groups=groups):
                images = image_fixture(groups=groups)
                self.assertIsNone(self.helper.validate_images(*images, groups=groups,
                    receiver_batches_done=groups, ce_sim=True, depth=8, ce_slots=8))
                rx_end = RX_OFF + groups * GROUP_BYTES
                ce_off = max(CE_OFF, rx_end + GROUP_BYTES)
                for index in (rx_end, ce_off - 1, ce_off + groups * GROUP_BYTES):
                    changed = list(images)
                    after = bytearray(changed[3])
                    after[index] ^= 1
                    changed[3] = bytes(after)
                    with self.subTest(guard=index), self.assertRaises(ValueError):
                        self.helper.validate_images(*changed, groups=groups,
                            receiver_batches_done=groups, ce_sim=True, depth=8, ce_slots=8)

    def test_old_257_group_alias_cannot_be_accepted_as_a_valid_campaign(self):
        groups = 257
        images = list(image_fixture(groups=groups))
        payload = images[0][SOURCE_OFF:SOURCE_OFF + groups * GROUP_BYTES]
        after = bytearray(images[2])
        # Actual old guest order: CE first, then RX overwrote CE group zero.
        after[CE_OFF:CE_OFF + len(payload)] = payload
        after[RX_OFF:RX_OFF + len(payload)] = payload
        self.assertNotEqual(payload[:GROUP_BYTES], payload[-GROUP_BYTES:])
        images[3] = bytes(after)
        with self.assertRaises(ValueError):
            self.helper.validate_images(*images, groups=groups,
                receiver_batches_done=groups, ce_sim=True, depth=8, ce_slots=8)

    def test_layout_supports_maximum_campaign_with_a_full_guard_between_windows(self):
        for groups in (1, 8, 255, 256, 257, 1024):
            with self.subTest(groups=groups):
                layout = self.helper.image_layout(groups)
                self.assertEqual(layout['source_slba'], SOURCE_OFF // 512)
                self.assertEqual(layout['rx_slba'], RX_OFF // 512)
                self.assertEqual(layout['ce_slba'] * 512,
                                 max(CE_OFF, RX_OFF + (groups + 1) * GROUP_BYTES))
                self.assertGreaterEqual(layout['image_bytes'],
                    layout['ce_slba'] * 512 + (groups + 1) * GROUP_BYTES)
        for groups in (0, -1, 1025):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                self.helper.image_layout(groups)

    def test_normal_and_duplicate_compare_complete_images(self):
        for fault in ("none", "duplicate-middle"):
            with self.subTest(fault=fault):
                self.assertIsNone(self.images(fault=fault))

    def test_loss_allows_only_complete_prefix_and_independent_ce_window(self):
        self.assertIsNone(self.images(fault="drop-middle"))

    def test_loss_can_finish_before_any_group_is_written(self):
        self.assertIsNone(self.images(fault="drop-middle", completed=0))

    def test_loss_rejects_one_byte_of_partial_generation(self):
        images = list(image_fixture(fault="drop-middle"))
        after = bytearray(images[3])
        after[RX_OFF + GROUP_BYTES] ^= 1
        images[3] = bytes(after)
        with self.assertRaises(ValueError):
            self.images(images, fault="drop-middle")

    def test_loss_rejects_complete_later_group_after_gap(self):
        images = list(image_fixture(fault="drop-middle"))
        after = bytearray(images[3])
        off = 2 * GROUP_BYTES
        after[RX_OFF + off:RX_OFF + off + GROUP_BYTES] = images[0][
            SOURCE_OFF + off:SOURCE_OFF + off + GROUP_BYTES]
        images[3] = bytes(after)
        with self.assertRaises(ValueError):
            self.images(images, fault="drop-middle")

    def test_source_mutation_is_detected_outside_the_payload_too(self):
        images = list(image_fixture())
        after = bytearray(images[1])
        after[0] ^= 1
        images[1] = bytes(after)
        with self.assertRaises(ValueError):
            self.images(images)

    def test_wrong_payload_and_every_write_boundary_are_detected(self):
        for index in (0, RX_OFF - 1, RX_OFF, RX_OFF + GROUPS * GROUP_BYTES - 1,
                      RX_OFF + GROUPS * GROUP_BYTES, CE_OFF - 1, CE_OFF,
                      CE_OFF + GROUPS * GROUP_BYTES - 1,
                      CE_OFF + GROUPS * GROUP_BYTES):
            with self.subTest(index=index):
                images = list(image_fixture())
                after = bytearray(images[3])
                after[index] ^= 1
                images[3] = bytes(after)
                with self.assertRaises(ValueError):
                    self.images(images)

    def test_non_ce_control_cannot_write_ce_window(self):
        with self.assertRaises(ValueError):
            self.images(image_fixture(ce_sim=True), ce_sim=False)

    def test_truncated_or_grown_images_are_not_equal(self):
        for which in range(4):
            for suffix in (b"", b"\x00\x00"):
                with self.subTest(which=which, suffix=suffix):
                    images = list(image_fixture())
                    images[which] = images[which][:-1] + suffix
                    with self.assertRaises(ValueError):
                        self.images(images)

    def test_too_small_equal_images_cannot_pass_vacuously(self):
        with self.assertRaises(ValueError):
            self.images((b"",) * 4)

    def test_invalid_completion_counts_reject_before_image_acceptance(self):
        for done in (-1, 8, 9):
            with self.subTest(done=done), self.assertRaises(ValueError):
                self.images(image_fixture(fault="drop-middle"), fault="drop-middle", completed=done)


if __name__ == "__main__":
    unittest.main()
