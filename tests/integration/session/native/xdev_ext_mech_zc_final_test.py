#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Synthetic evidence tests against the real final campaign validator.

These tests certify rejection of misleading logs, never a guest execution.
"""
import importlib.util
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = load("final_validator", HERE / "xdev_ext_mech_zc_validate.py")
fixtures = load("final_fixtures", HERE / "xdev_ext_mech_zc_validate_test.py")
wire = load("final_wire", HERE / "xdev_ext_mech_zc_wire.py")
packets = load("reliable_packets", HERE.parent /
               "xdev_ext_mech/reliable/wire_fault_test.py")


def reliable_console():
    text = fixtures.console_fixture()
    rx = next(line for line in text.splitlines()
              if line.startswith("XDEV_EXT_ZC_RX_STATS "))
    tx = rx.replace("_RX_STATS ", "_TX_STATS ").replace("session=17", "session=18")
    tx = tx.replace("submitted=0,8,0,0", "submitted=8,8,8,8")
    tx = tx.replace("completed=8,8,0,0", "completed=8,8,8,8")
    final = []
    for role, session in (("RX", 17), ("TX", 18)):
        final.extend([
            f"XDEV_EXT_ZC_{role}_TRANSPORT session={session} "
            "native_controls=0 pending_acks=0 uncertain_controls=0",
            f"XDEV_EXT_ZC_{role}_FINALIZE session={session} stop_ret=0",
        ])
    rx_final = "\n".join(final[:2]) + "\n"
    text = text.replace("XDEV_EXT_ZC_RX_RESULT", rx_final + "XDEV_EXT_ZC_RX_RESULT")
    tx_final = tx + "\n" + "\n".join(final[2:]) + "\n" + \
        "XDEV_EXT_ZC_TX_RESULT outcome=success exit=0 elapsed_ms=1500 timeout_ms=60000\n"
    return text.replace("XDEV_EXT_ZC_GUEST_EXIT=0", tx_final + "XDEV_EXT_ZC_GUEST_EXIT=0")


def unknown_console():
    text = reliable_console().replace(
        "XDEV_EXT_ZC_RX_RESULT outcome=success exit=0",
        "XDEV_EXT_ZC_RX_RESULT outcome=incomplete-remote-unknown exit=1")
    text = text.replace("XDEV_EXT_ZC_TX_RESULT outcome=success exit=0",
                        "XDEV_EXT_ZC_TX_RESULT outcome=unknown exit=1")
    text = text.replace("TX_FINALIZE session=18 stop_ret=0", "TX_FINALIZE session=18 stop_ret=-121")
    tx = next(line for line in text.splitlines() if line.startswith("XDEV_EXT_ZC_TX_STATS "))
    text = text.replace(tx, tx.replace("last_err=0", "last_err=-EREMOTEIO")
                        .replace("batches_done=8", "batches_done=7")
                        .replace("batches_abort=0", "batches_abort=1"))
    text = text.replace("mode=none matched=0 dropped=0", "mode=reliable-budget-unknown matched=8 dropped=8")
    text = text.replace("XDEV_EXT_ZC_CHAIN=PASS", "XDEV_EXT_ZC_UNKNOWN=PASS")
    text = text.replace("accepted=48 completed=48", "accepted=80 completed=80")
    text = text.replace("XDEV_EXT_MECH_CE_SIM=PASS chain=b\n", "")
    text = "\n".join(line for line in text.splitlines()
                     if not line.startswith("XDEV_EXT_MECH_NIC_NVME_E2E=PASS")) + "\n"
    text += "XDEV_EXT_ZC_TX_REMOTE_OUTCOME outcome=UNKNOWN cause=remote-ack-unconfirmed " \
            "batches_abort=1 durable=unclaimed\n"
    return text


class RoleExtraction(unittest.TestCase):
    """Run the actual guest shell function; raw CLI files stay byte-for-byte intact."""
    def extract(self, role, raw):
        script = (HERE / 'xdev_ext_mech_zc_kvm.sh').read_text()
        function = re.search(r'(?ms)^role_evidence\(\) \{\n.*?^\}', script)
        self.assertIsNotNone(function)
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'role.log'
            log.write_text(raw)
            before = log.read_bytes()
            run = subprocess.run(['sh', '-euc', function[0] +
                '\nrole_evidence "$1" "$2"', 'role-test', role, str(log)],
                capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(log.read_bytes(), before, 'extractor modified raw CLI evidence')
            return run.stdout

    def raw_records(self, text, role):
        prefix = f'XDEV_EXT_ZC_{role}_'
        return [line.replace(prefix, 'XDEV_EXT_MECH_', 1)
                for line in text.splitlines()
                if any(line.startswith(prefix + kind + ' ')
                       for kind in ('STATS', 'TRANSPORT', 'FINALIZE'))]

    def replace_role(self, text, role, raw):
        canonical = [line for line in text.splitlines()
                     if any(line.startswith(f'XDEV_EXT_ZC_{role}_{kind} ')
                            for kind in ('STATS', 'TRANSPORT', 'FINALIZE'))]
        block = '\n'.join(canonical)
        self.assertIn(block, text, 'fixture role records must be contiguous')
        return text.replace(block, self.extract(role, raw).rstrip('\n'))

    def validate(self, text):
        return validator.validate_console(text, groups=8, ce_sim=True,
                                          ce_delay_us=100000, reliable=True)

    def test_two_snapshots_select_last_for_each_role(self):
        for role in ('RX', 'TX'):
            with self.subTest(role=role):
                text = reliable_console()
                stats, transport, finalize = self.raw_records(text, role)
                earlier = stats.replace('batches_done=8', 'batches_done=7')
                raw = '\n'.join((earlier, stats, transport, finalize)) + '\n'
                result = self.replace_role(text, role, raw)
                self.assertEqual(sum(line.startswith(f'XDEV_EXT_ZC_{role}_STATS ')
                                     for line in result.splitlines()), 1)
                self.assertEqual(self.validate(result)['receiver_batches_done'], 8)

    def test_last_error_snapshot_cannot_be_replaced_with_earlier_success(self):
        text = reliable_console()
        stats, transport, finalize = self.raw_records(text, 'RX')
        raw = '\n'.join((stats, stats.replace('last_err=0', 'last_err=-EIO'),
                           transport, finalize)) + '\n'
        with self.assertRaises(ValueError):
            self.validate(self.replace_role(text, 'RX', raw))

    def test_last_stats_after_finalize_remains_after_finalize_and_rejects(self):
        text = reliable_console()
        stats, transport, finalize = self.raw_records(text, 'RX')
        raw = '\n'.join((stats, transport, finalize, stats)) + '\n'
        selected = self.extract('RX', raw).splitlines()
        self.assertEqual(selected, [line.replace('XDEV_EXT_MECH_', 'XDEV_EXT_ZC_RX_', 1)
                                    for line in (transport, finalize, stats)])
        with self.assertRaises(ValueError):
            self.validate(self.replace_role(text, 'RX', raw))

    def test_bad_transport_finalize_order_is_preserved_and_rejected(self):
        text = reliable_console()
        stats, transport, finalize = self.raw_records(text, 'RX')
        raw = '\n'.join((stats, finalize, transport)) + '\n'
        with self.assertRaises(ValueError):
            self.validate(self.replace_role(text, 'RX', raw))

    def test_duplicate_final_records_are_preserved_and_rejected(self):
        for kind in ('TRANSPORT', 'FINALIZE'):
            with self.subTest(kind=kind):
                text = reliable_console()
                records = self.raw_records(text, 'RX')
                duplicate = next(line for line in records
                                 if line.startswith('XDEV_EXT_MECH_' + kind + ' '))
                raw = '\n'.join((*records, duplicate)) + '\n'
                selected = self.extract('RX', raw)
                self.assertEqual(sum(line.startswith(f'XDEV_EXT_ZC_RX_{kind} ')
                                     for line in selected.splitlines()), 2)
                with self.assertRaises(ValueError):
                    self.validate(self.replace_role(text, 'RX', raw))

    def test_missing_stats_is_not_synthesized_and_rejects(self):
        text = reliable_console()
        _, transport, finalize = self.raw_records(text, 'RX')
        raw = '\n'.join((transport, finalize)) + '\n'
        self.assertNotIn('_STATS ', self.extract('RX', raw))
        with self.assertRaises(ValueError):
            self.validate(self.replace_role(text, 'RX', raw))

    def test_legacy_loss_uses_last_snapshot_and_keeps_fail_stop_contract(self):
        text = fixtures.console_fixture(fault='drop-middle')
        stats = next(line for line in text.splitlines()
                     if line.startswith('XDEV_EXT_ZC_RX_STATS '))
        raw_stats = stats.replace('XDEV_EXT_ZC_RX_', 'XDEV_EXT_MECH_', 1)
        raw = raw_stats.replace('batches_done=1', 'batches_done=0') + '\n' + raw_stats + '\n'
        selected = text.replace(stats, self.extract('RX', raw).rstrip('\n'))
        result = validator.validate_console(selected, groups=8, ce_sim=True,
                                           ce_delay_us=100000, fault='drop-middle')
        self.assertEqual(result['receiver_batches_done'], 1)


class FinalEvidence(unittest.TestCase):
    def check(self, text):
        return validator.validate_console(text, groups=8, ce_sim=True,
                                          ce_delay_us=100000, reliable=True)

    def test_complete_role_snapshots_are_accepted(self):
        self.assertEqual(self.check(reliable_console())["receiver_batches_done"], 8)

    def test_each_success_role_rejects_stopped_snapshot(self):
        for role in ("RX", "TX"):
            text = reliable_console()
            line = next(line for line in text.splitlines()
                        if line.startswith(f"XDEV_EXT_ZC_{role}_STATS "))
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.check(text.replace(line, line.replace("state=ACTIVE", "state=STOPPED")))

    def test_both_success_roles_reject_stopped_snapshots(self):
        with self.assertRaises(ValueError):
            self.check(reliable_console().replace("state=ACTIVE", "state=STOPPED"))

    def test_legacy_campaign_preserves_existing_contract(self):
        self.assertEqual(validator.validate_console(fixtures.console_fixture(), groups=8,
            ce_sim=True, ce_delay_us=100000)["receiver_batches_done"], 8)

    def test_each_role_requires_transport_and_actual_stop(self):
        for role in ("RX", "TX"):
            for kind in ("TRANSPORT", "FINALIZE", "STATS", "RESULT"):
                with self.subTest(role=role, kind=kind), self.assertRaises(ValueError):
                    text = "\n".join(line for line in reliable_console().splitlines()
                                     if not line.startswith(f"XDEV_EXT_ZC_{role}_{kind} "))
                    self.check(text)

    def test_each_unsettled_ack_owner_rejects_success(self):
        for role in ("RX", "TX"):
            for field in ("native_controls", "pending_acks", "uncertain_controls"):
                with self.subTest(role=role, field=field), self.assertRaises(ValueError):
                    text = reliable_console()
                    line = next(line for line in text.splitlines()
                                if line.startswith(f"XDEV_EXT_ZC_{role}_TRANSPORT "))
                    self.check(text.replace(line, line.replace(field + "=0", field + "=1")))

    def test_stop_fatal_and_busy_reject_success(self):
        for error in (-5, -16, -121):
            with self.subTest(error=error), self.assertRaises(ValueError):
                self.check(reliable_console().replace("stop_ret=0", f"stop_ret={error}", 1))

    def test_role_session_cannot_be_substituted(self):
        for marker in ("RX_TRANSPORT", "RX_FINALIZE", "TX_TRANSPORT", "TX_FINALIZE"):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                text = reliable_console()
                line = next(line for line in text.splitlines()
                            if line.startswith(f"XDEV_EXT_ZC_{marker} "))
                self.check(text.replace(line, line.replace("session=17", "session=19")
                                       .replace("session=18", "session=19")))

    def test_snapshot_and_stop_order_is_required(self):
        text = reliable_console()
        transport = next(line for line in text.splitlines()
                         if line.startswith("XDEV_EXT_ZC_RX_TRANSPORT "))
        stop = next(line for line in text.splitlines()
                    if line.startswith("XDEV_EXT_ZC_RX_FINALIZE "))
        with self.assertRaises(ValueError):
            self.check(text.replace(transport + "\n" + stop, stop + "\n" + transport))

    def test_duplicate_field_cannot_erase_native_error(self):
        with self.assertRaises(ValueError):
            self.check(reliable_console().replace("last_err=0", "last_err=-5 last_err=0", 1))

    def test_stopping_receiver_cannot_pass(self):
        with self.assertRaises(ValueError):
            self.check(reliable_console().replace("state=ACTIVE", "state=STOPPING", 1))

    def test_source_native_reexecution_cannot_hide_in_receive_success(self):
        with self.assertRaises(ValueError):
            self.check(reliable_console().replace("submitted=8,8,8,8", "submitted=9,8,8,8"))


class LongStreamWire(unittest.TestCase):
    def injector(self, mode):
        try:
            return wire.FaultInjector(mode)
        except ValueError as error:
            self.fail(f"production wire lacks {mode}: {error}")

    def test_reorder_group_buffers_then_delivers_exact_reverse_order(self):
        injector = self.injector("reliable-reorder-group")
        group = [packets.packet(index=i) for i in range(6)]
        for frame in group[:-1]:
            self.assertEqual(injector.process_frame(frame), [])
        self.assertEqual(injector.process_frame(group[-1]), list(reversed(group)))
        self.assertEqual(injector.process_frame(group[0]), [group[0]])
        self.assertEqual(injector.stats["reordered"], 6)
        self.assertEqual(injector.stats["dropped"], 0)

    def test_unknown_budget_drops_every_target_ack_attempt(self):
        injector = self.injector("reliable-budget-unknown")
        data = packets.packet()
        self.assertEqual(injector.process_frame(data), [data])
        for attempt in range(1, 9):
            self.assertEqual(injector.process_frame(packets.packet(2, attempt=attempt)), [])
        other = packets.packet(2, group=3)
        self.assertEqual(injector.process_frame(other), [other])
        self.assertEqual(injector.stats["dropped"], 8)

    def test_reorder_cannot_mix_attempts_or_foreign_identity(self):
        injector = self.injector("reliable-reorder-group")
        self.assertEqual(injector.process_frame(packets.packet(index=0)), [])
        retry = packets.packet(index=1, attempt=2)
        self.assertEqual(injector.process_frame(retry), [retry])
        foreign = packets.packet(index=1, session=270020)
        self.assertEqual(injector.process_frame(foreign), [foreign])


class UnknownEvidence(unittest.TestCase):
    def check(self, text):
        return validator.validate_console(text, groups=16, depth=8, ce_slots=8,
            ce_sim=True, ce_delay_us=100000, reliable=True, fault="reliable-budget-unknown")

    def test_unknown_preserves_confirmed_receiver_prefix(self):
        self.assertEqual(self.check(unknown_console())["receiver_batches_done"], 8)

    def test_one_shot_loss_is_not_a_budget_unknown_test(self):
        with self.assertRaises(ValueError):
            self.check(unknown_console().replace("matched=8 dropped=8", "matched=1 dropped=1"))

    def test_unknown_requires_explicit_remote_cause(self):
        with self.assertRaises(ValueError):
            self.check(unknown_console().replace("outcome=UNKNOWN", "outcome=SUCCESS"))

    def test_unknown_cannot_claim_network_success(self):
        with self.assertRaises(ValueError):
            self.check(unknown_console()+"XDEV_EXT_MECH_NIC_CE_NVME_E2E=PASS groups=16\n")

    def test_unknown_native_stages_are_not_resubmitted(self):
        with self.assertRaises(ValueError):
            self.check(unknown_console().replace("submitted=8,8,8,8", "submitted=8,9,8,8"))

    def test_unknown_also_requires_both_final_role_snapshots(self):
        for role in ("RX", "TX"):
            for kind in ("TRANSPORT", "FINALIZE"):
                with self.subTest(role=role, kind=kind), self.assertRaises(ValueError):
                    self.check("\n".join(line for line in unknown_console().splitlines()
                        if not line.startswith(f"XDEV_EXT_ZC_{role}_{kind} ")))

    def test_unknown_stop_cannot_erase_remote_error(self):
        with self.assertRaises(ValueError):
            self.check(unknown_console().replace("stop_ret=-121", "stop_ret=0"))

    def test_failed_transport_query_is_not_retained_owner_evidence(self):
        with self.assertRaises(ValueError):
            self.check(unknown_console().replace("native_controls=0", "native_controls=4294967295")
                       .replace("stop_ret=-121", "stop_ret=-16").replace("stop_ret=0", "stop_ret=-16"))


class RunOnlyIdentity(unittest.TestCase):
    def run_only(self, stamp=None):
        # The actual harness accepts only an alphanumeric private suffix.
        root = Path("/tmp/xdev-ext-e2e." + secrets.token_hex(8))
        root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, root)
        source = root / "src"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        for relative in ("net/xdp/xsk_xdev_ext_mech_zc_core.h",
                "tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh",
                "tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py",
                "tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_validate.py"):
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("isolated source identity fixture\n")
            subprocess.run(["git", "-C", str(source), "add", relative], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Selftest",
                "-c", "user.email=selftest@invalid", "commit", "-q", "--allow-empty",
                "-m", "isolated selftest fixture"], check=True)
        if stamp is not None:
            (root / "build").mkdir()
            (root / "build/xdev-ext-source.commit").write_text(stamp + "\n")
        return subprocess.run(["bash", str(HERE / "xdev_ext_mech_zc_kvm.sh"),
                "--scratch", str(root), "--source", str(source), "--run-only"],
                capture_output=True, text=True, timeout=20)

    def test_old_unstamped_artifacts_are_not_relabelled_with_current_source(self):
        run = self.run_only()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("run-only build identity missing", run.stdout + run.stderr)

    def test_different_source_sha_cannot_reuse_build(self):
        run = self.run_only("0" * 40)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("run-only source SHA mismatch", run.stdout + run.stderr)


class ProviderQuarantineEvidence(unittest.TestCase):
    def fixture(self, case="short"):
        return (f"PASS provider case={case} groups=1 depth=1 success=0 accepted=1 completed=1 "
            "sequestered=2 source_and_guards=unchanged owner_refs_retained=1 stop_ret=-16 "
            "region_unbinds=0 host_unbinds=0 ce_refs_retained=1\n"
            f"PASS quarantine case={case} retained=1 forced_unload=0 dedicated_guest_shutdown_required=1\n"
            f"XDEV_EXT_ZC_PROVIDER_CASE=PASS case={case} backend=CPU-memcpy-standin\n"
            "XDEV_EXT_ZC_GUEST_EXIT=0\n")

    def check(self, text, case="short"):
        self.assertTrue(callable(getattr(validator, "validate_provider_console", None)),
                        "dedicated provider guest lacks quarantine evidence validation")
        return validator.validate_provider_console(text, case=case)

    def test_both_dedicated_faults_require_full_retained_ownership(self):
        for case in ("short", "ambiguous"):
            with self.subTest(case=case):
                self.check(self.fixture(case), case)

    def test_early_unbind_or_forced_unload_is_rejected(self):
        for field in ("region_unbinds", "host_unbinds", "forced_unload"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(self.fixture().replace(field + "=0", field + "=1"))

    def test_stop_success_or_missing_module_pin_is_rejected(self):
        for before, after in (("stop_ret=-16", "stop_ret=0"),
                              ("ce_refs_retained=1", "ce_refs_retained=0"),
                              ("owner_refs_retained=1", "owner_refs_retained=0")):
            with self.subTest(field=before), self.assertRaises(ValueError):
                self.check(self.fixture().replace(before, after))

    def test_wrong_case_or_guest_failure_is_rejected(self):
        for text in (self.fixture("ambiguous"), self.fixture().replace("GUEST_EXIT=0", "GUEST_EXIT=1")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.check(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
