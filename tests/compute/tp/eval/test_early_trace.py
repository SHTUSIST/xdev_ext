# SPDX-License-Identifier: GPL-2.0
"""Independent, literal timelines: metadata and partial traces never prove EARLY."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[3] / "benchmarks/tp/early_trace.py"
STATS = "cpu0:\nentries: 20\noverrun: 0\ncommit overrun: 0\ndropped events: 0\n"

def event(phase, ts, **kw):
    e = dict(phase=phase, ts_ns=ts, session_id=41, stage=1, direction=1,
             early=1, local_inc=17, remote_inc=23, tx_bind=7, rx_bind=9,
             group=1, key=37, ticket=11, pool_generation=3,
             status=0, quiesced=0)
    e.update(kw)
    return e

def tx_trace(attempt=30, received=10, accepted=20):
    return [event("stage_bound", 1, group=0, key=0, ticket=0, rx_bind=0),
            event("cts_received", received, ticket=0),
            event("grant_accepted", accepted, ticket=0),
            event("tx_attempt", attempt, group=0),
            event("native_accepted", 40),
            event("native_complete", 50, quiesced=1)]

def rx_trace(key=37, group=1, base=0):
    kw = dict(session_id=42, stage=0, direction=2, key=key, group=group)
    return [event("rx_reserved", base+10, **kw),
            event("native_accepted", base+20, **kw),
            event("cts_sent", base+30, **kw),
            event("native_complete", base+40, quiesced=1, **kw),
            event("consumer_release", base+80, quiesced=1, **kw),
            event("ack_sent", base+90, quiesced=1, **kw)]

def rx_bound():
    return event("stage_bound", 1, session_id=42, stage=0, direction=2,
                 group=0, key=0, ticket=0, tx_bind=0)

def frame(key, group, frame_id, start, generation=3):
    return dict(phase="native_submit", ts_ns=start, session_id=42, stage=0,
                class_id=11, batch_id=key, batch_key=key, frame_id=frame_id,
                generation=generation, ticket=11, cookie=group,
                frame_ordinal=0, frame_offset=0, frame_length=4096,
                bytes=4096, address=0, status=0)

class EarlyTraceTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(MODULE.is_file(), "EARLY timeline analyzer is missing")
        spec = importlib.util.spec_from_file_location("tp_early_trace", MODULE)
        self.a = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.a)

    def test_grant_before_first_attempt_is_observed_independently_of_request(self):
        r = self.a.analyze(tx_trace(), STATS)
        self.assertEqual(r["tx_groups"], 1)
        self.assertEqual(r["grants_before_first_tx_attempt"], 1)
        self.assertEqual(r["received_before_first_tx_attempt"], 1)
        self.assertEqual(r["grant_lead_ns"], [10])
        self.assertFalse(r["physical_dma_proven"])

    def test_earlier_eagain_attempt_prevents_false_pregrant(self):
        es = tx_trace()
        es.append(event("tx_attempt", 5, group=0, rx_bind=0, ticket=10))
        r = self.a.analyze(es, STATS)
        self.assertEqual(r["grants_before_first_tx_attempt"], 0)
        self.assertEqual(r["grant_lead_ns"], [-15])

    def test_cts_receipt_is_not_grant_acceptance(self):
        r = self.a.analyze(tx_trace(attempt=20, received=10, accepted=30), STATS)
        self.assertEqual(r["received_before_first_tx_attempt"], 1)
        self.assertEqual(r["grants_before_first_tx_attempt"], 0)

    def test_request_only_and_trace_loss_are_refused(self):
        for es, stats in [([], STATS),
                          (tx_trace(), STATS.replace("overrun: 0", "overrun: 1", 1)),
                          (tx_trace(), "cpu0:\noverrun: 0\n"),
                          (tx_trace(), "")]:
            with self.subTest(stats=stats, count=len(es)):
                with self.assertRaises(ValueError):
                    self.a.analyze(es, stats)

    def test_missing_completion_is_incomplete_not_a_success(self):
        r = self.a.analyze(tx_trace()[:-1], STATS)
        self.assertFalse(r["complete"])
        self.assertEqual(r["counts"]["native_accepted"], 1)
        self.assertEqual(r["counts"].get("native_complete", 0), 0)

    def test_duplicate_native_acceptance_is_refused(self):
        es = tx_trace()+[event("native_accepted", 41)]
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS)

    def test_wrong_bind_or_generation_does_not_join(self):
        for field in ("rx_bind", "tx_bind", "local_inc", "pool_generation"):
            es = tx_trace()
            es[2] = dict(es[2], **{field: 999})
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.a.analyze(es, STATS)

    def test_receive_requires_preposted_descriptors_and_release_before_ack(self):
        good = [rx_bound()]+rx_trace()
        self.assertTrue(self.a.analyze(good, STATS)["protocol_complete"])
        # Full execution also needs native frame identities and core terminal.
        self.assertFalse(self.a.analyze(good, STATS)["complete"])
        for phase, when in [("cts_sent", 15), ("ack_sent", 70)]:
            es = [dict(e, ts_ns=when) if e["phase"] == phase else e for e in good]
            with self.subTest(phase=phase):
                with self.assertRaises(ValueError):
                    self.a.analyze(es, STATS)

    def test_unknown_native_custody_cannot_qualify_release(self):
        es = [rx_bound()]+rx_trace()
        es = [dict(e, quiesced=0) if e["phase"] == "native_complete" else e for e in es]
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS)

    def test_disjoint_custody_overlap_has_exact_local_interval(self):
        es = [rx_bound()]+rx_trace()+rx_trace(key=901, group=2, base=35)
        frames = [frame(37, 1, 2, 20), frame(901, 2, 8, 55)]
        r = self.a.analyze(es, STATS, frames)
        # New native accepted..complete [55,75], old consumer custody [40,80].
        self.assertEqual(r["rx_native_consumer_overlap_ns"], 20)
        self.assertEqual(r["rx_overlapping_group_pairs"], 1)
        self.assertTrue(r["frame_identity_checked"])
        self.assertFalse(r["gpu_compute_overlap_proven"])

    def test_same_frame_before_old_consumer_release_is_refused(self):
        es = [rx_bound()]+rx_trace()+rx_trace(key=901, group=2, base=35)
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS, [frame(37,1,2,20),frame(901,2,2,55,4)])

    def test_reuse_is_checked_at_rx_reservation_even_if_post_returns_late(self):
        es = [rx_bound()]+rx_trace()
        late = rx_trace(key=901, group=2, base=60)
        # The old consumer releases at 80. A new native post returns at 90,
        # but reserved the same frame at 70, before that ownership release.
        late = [dict(e, ts_ns=90) if e["phase"] == "native_accepted" else e for e in late]
        with self.assertRaises(ValueError):
            self.a.analyze(es+late, STATS, [frame(37,1,2,20),frame(901,2,2,90,4)])

    def test_custody_overlap_without_frame_evidence_stays_unqualified(self):
        es = [rx_bound()]+rx_trace()+rx_trace(key=901, group=2, base=35)
        r = self.a.analyze(es, STATS)
        self.assertIsNone(r["rx_native_consumer_overlap_ns"])
        self.assertFalse(r["frame_identity_checked"])

    def test_error_release_is_not_success(self):
        es = [rx_bound()]+rx_trace()
        es = [dict(e, status=-5) if e["phase"] == "consumer_release" else
              dict(e, phase="fail_sent", status=-5) if e["phase"] == "ack_sent" else e
              for e in es]
        r = self.a.analyze(es, STATS)
        self.assertFalse(r["complete"])
        self.assertEqual(r["error_events"], 2)

    def test_key_zero_is_a_valid_transaction(self):
        es = [dict(e, key=0) for e in tx_trace()]
        self.assertEqual(self.a.analyze(es, STATS)["grants_before_first_tx_attempt"], 1)

    def test_callback_can_complete_before_post_returns(self):
        es = [dict(e, ts_ns=39) if e["phase"] == "native_complete" else e for e in tx_trace()]
        r = self.a.analyze(es, STATS)
        self.assertTrue(r["protocol_complete"])
        self.assertEqual(r["completion_before_post_return_groups"], 1)

    def test_full_completion_requires_every_matching_frame_terminal(self):
        es = [rx_bound()]+rx_trace()
        f = frame(37, 1, 2, 20)
        terminal = dict(f, phase="record_terminal", ts_ns=79, stage=1, class_id=10)
        self.assertTrue(self.a.analyze(es, STATS, [f, terminal])["complete"])
        self.assertFalse(self.a.analyze(es, STATS, [f])["complete"])
        self.assertFalse(self.a.analyze(es, STATS, [f, dict(terminal, batch_id=999)])["complete"])

    def test_frame_key_mismatch_is_not_ownership_evidence(self):
        es = [rx_bound()]+rx_trace()
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS, [dict(frame(37, 1, 2, 20), batch_key=901)])

    def test_wrong_native_ticket_cannot_complete_another_request(self):
        es = [dict(e, ticket=999) if e["phase"] == "native_complete" else e for e in tx_trace()]
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS)

    def test_session_filter_excludes_other_jobs_and_requires_both_ids(self):
        es = tx_trace()+[rx_bound()]+rx_trace()
        es.append(event("stage_bound", 1, session_id=999, group=0, key=0))
        selected, _ = self.a.select_sessions(es, [], [41, 42])
        self.assertEqual({e["session_id"] for e in selected}, {41, 42})
        with self.assertRaises(ValueError):
            self.a.select_sessions(es, [], [41, 123])

    def test_whole_group_must_match_admitted_incarnation_and_pool(self):
        for field in ("local_inc", "remote_inc", "pool_generation"):
            es = [tx_trace()[0]] + [dict(e, **{field: 999}) for e in tx_trace()[1:]]
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.a.analyze(es, STATS)

    def test_unmatched_attempt_or_idle_selected_stage_is_incomplete(self):
        es = [rx_bound()]+rx_trace()
        f = frame(37, 1, 2, 20)
        terminal = dict(f, phase="record_terminal", ts_ns=79, stage=1, class_id=10)
        bound = event("stage_bound", 1, group=0, key=0, ticket=0, rx_bind=0)
        for extra in ([bound], [bound, event("tx_attempt", 60, group=0, key=901)]):
            with self.subTest(extra=len(extra)):
                r = self.a.analyze(es+extra, STATS, [f, terminal])
                self.assertFalse(r["protocol_complete"])
                self.assertFalse(r["complete"])
        # A completed TX group must not hide a later unsuccessful first attempt.
        r = self.a.analyze(tx_trace()+[event("tx_attempt", 70, group=0, key=901)], STATS)
        self.assertFalse(r["protocol_complete"])

    def test_terminal_before_native_completion_is_refused(self):
        es = [rx_bound()]+rx_trace()
        f = frame(37, 1, 2, 20)
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS, [f, dict(f, phase="record_terminal", ts_ns=39)])

    def test_partial_or_noncontiguous_native_frames_are_refused(self):
        es = [rx_bound()]+rx_trace()
        f = frame(37, 1, 2, 20)
        for broken in (dict(f, bytes=8192), dict(f, frame_ordinal=1),
                       dict(f, frame_offset=1)):
            with self.subTest(frame=broken):
                with self.assertRaises(ValueError):
                    self.a.analyze(es, STATS, [broken])

    def test_unknown_release_does_not_qualify_overlap(self):
        es = [rx_bound()]+rx_trace()+rx_trace(key=901, group=2, base=35)
        es = [dict(e, quiesced=0) if e["key"] == 37 and
              e["phase"] in ("native_complete", "consumer_release") else e
              for e in es if not (e["key"] == 37 and e["phase"] == "ack_sent")]
        r = self.a.analyze(es, STATS, [frame(37,1,2,20),frame(901,2,8,55)])
        self.assertFalse(r["protocol_complete"])
        self.assertIsNone(r["rx_native_consumer_overlap_ns"])

    def test_tp_workload_count_cannot_be_proved_by_one_complete_prefix(self):
        es = tx_trace()+[rx_bound()]+rx_trace()
        f = frame(37, 1, 2, 20)
        tx = dict(f, session_id=41, stage=1, ts_ns=40)
        native = [f, tx, dict(f, phase="record_terminal", ts_ns=79),
                  dict(tx, phase="record_terminal", ts_ns=60)]
        metadata = dict(early_cts_requested=True, tx_session_id=41, rx_session_id=42,
                        iterations=1, requested_depth=1, completed=1, first_sequence=37,
                        group_bytes=4096, frame_size=4096, frame_count=1,
                        completion_boundary="kernel-end-prefix")
        r = self.a.analyze(es, STATS, native)
        self.assertTrue(r["complete"])
        self.a.qualify_tp(r, es, native, metadata)
        self.assertTrue(r["complete"])
        self.assertTrue(r["tp_workload_covered"])
        for changed in (dict(iterations=2, completed=2), dict(first_sequence=36)):
            r = self.a.analyze(es, STATS, native)
            self.a.qualify_tp(r, es, native, dict(metadata, **changed))
            self.assertFalse(r["complete"])
            self.assertFalse(r["tp_workload_covered"])
        for changed in (dict(group_bytes=8192, frame_count=2),
                        dict(early_cts_requested=False), dict(completed=2)):
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    self.a.qualify_tp(self.a.analyze(es, STATS, native), es, native,
                                      dict(metadata, **changed))

    def test_same_frame_twice_in_one_group_is_not_full_coverage(self):
        es = [rx_bound()]+rx_trace()
        f = dict(frame(37, 1, 2, 20), bytes=8192)
        second = dict(f, frame_ordinal=1, frame_offset=4096, generation=4)
        with self.assertRaises(ValueError):
            self.a.analyze(es, STATS, [f, second])

    def test_text_parser_ignores_other_events_but_checks_required_fields(self):
        line = "worker-1 [000] ... 0.1: xdomain_event: abi=xdev-xdomain-v1 "
        raw = "# tracer: nop\n"+line+" ".join(f"{k}={v}" for k,v in tx_trace()[0].items())+"\n"
        es, frames = self.a.parse_trace(raw.splitlines())
        self.assertEqual(len(es), 1)
        self.assertEqual(es[0]["session_id"], 41)
        self.assertEqual(frames, [])
        with self.assertRaises(ValueError):
            self.a.parse_trace([(line+"phase=stage_bound session_id=41")])

if __name__ == "__main__":
    unittest.main()
