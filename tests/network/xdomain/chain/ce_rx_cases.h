/* SPDX-License-Identifier: GPL-2.0 */
/* RX-native faults run through NHI descriptor completion, the XDOMAIN class,
 * and the real worker. The tests never fabricate a successful core CQE. */

static void rx_partial_wait(void)
{
	unsigned steps = 0;

	ce_up(NULL, 0);
	ce_start(1);
	while (chain_rx_callbacks() < 1) {
		CHECK(chain_pump(1, 0) == -ELOOP, "first RX element reaches its real callback");
		CHECK(++steps < BUDGET, "first RX callback is reached within the event budget");
	}
	CHECK(chain_rx_callbacks() == 1, "exactly one of two RX elements has completed");
	chain_hold_tx_completions(1, true);
	ce_settle(5);
	CHECK(chain_stage_completed(rx, 0) == 0, "partial group is not a completed RX batch");
	CHECK(chain_stage_submitted(rx, 1) == 0 && chain_ce_stats().accepted == 0,
	      "a partial RX cannot submit CE");
	CHECK(chain_control_tx_count(1, ACK) == 0, "partial RX cannot acknowledge a restore");
	CHECK(chain_session_done(rx) == 0, "partial RX cannot report batch success");
	ce_pristine();
	for (unsigned f = 0; f < CE_GROUP / CE_FRAME; f++)
		CHECK(chain_frame_custody(rx, f) != chain_frame_state_user() &&
		      chain_frame_custody(rx, f) != chain_frame_state_free(),
		      "partially completed RX keeps every group frame out of the free pool");
	chain_hold_tx_completions(1, false);
	ce_settle(50);
	CHECK(chain_stage_completed(rx, 0) == 1 && chain_ce_stats().completed == 1,
	      "the last RX callback permits exactly one CE completion");
	CHECK(chain_session_done(rx) == 1 && chain_session_done(tx) == 1,
	      "both endpoints finish after full RX and CE");
	ce_verify(1);
}

static void rx_failed(bool short_frame)
{
	ce_up(NULL, 0);
	chain_rx_fault(short_frame ? (int)CE_FRAME - 1 : -1, short_frame ? 0 : 1);
	ce_start(1);
	ce_settle(50);
	CHECK(chain_rx_callbacks() == CE_GROUP / CE_FRAME,
	      "all native RX callbacks drained, including the failed element");
	CHECK(chain_stage_completed(rx, 0) == 1, "failed native RX reaches the worker");
	CHECK(chain_stage_submitted(rx, 1) == 0 && chain_ce_stats().accepted == 0,
	      "short or failed RX never submits CE");
	CHECK(chain_session_done(rx) == 0 && chain_session_aborted(rx) == 1,
	      "failed RX aborts the restore instead of reporting success");
	CHECK(chain_control_tx_count(1, ACK) == 0 && chain_control_tx_count(1, FAIL) >= 1,
	      "failed RX sends failure, never a success ACK");
	CHECK(chain_session_last_err(rx) != 0, "native RX error is visible to the session");
	ce_pristine();
	for (unsigned f = 0; f < CE_GROUP / CE_FRAME; f++) {
		CHECK(!chain_live_leases(1, CHAIN_DEV_NHI, f * CE_FRAME, CE_FRAME),
		      "known-quiesced RX error leaves no live NHI lease");
		CHECK(chain_frame_custody(rx, f) == chain_frame_state_user(),
		      "fully drained RX error returns its lent Host frames");
	}
	CHECK(chain_violations() == 0, "RX error did not violate a device mapping or lease");
}

static void rx_unknown_late(void)
{
	unsigned mask = 0, leased = 0;

	ce_up(NULL, 0);
	chain_hold_tx_completions(1, true);
	ce_start(1);
	ce_settle(10);
	CHECK(chain_rx_callbacks() == 0, "native RX callbacks are withheld");
	CHECK(chain_stage_submitted(rx, 0) == 1 && chain_stage_submitted(rx, 1) == 0,
	      "RX is accepted and CE has not started");
	for (unsigned f = 0; f < chain_pool_frames(rx); f++)
		if (chain_live_leases(1, CHAIN_DEV_NHI, f * CE_FRAME, CE_FRAME)) {
			mask |= 1u << f;
			leased++;
		}
	CHECK(leased == CE_GROUP / CE_FRAME, "the pending RX owns exactly one group's NHI leases");
	CHECK(chain_session_stop(rx, -ECANCELED) == 0, "STOP receive session while native RX is unresolved");
	for (unsigned i = 0; i < 40; i++)
		ce_pump(100000000ULL);
	CHECK(chain_stage_submitted(rx, 1) == 0 && chain_ce_stats().accepted == 0,
	      "UNKNOWN RX cannot trigger CE");
	CHECK(chain_session_done(rx) == 0 && chain_control_tx_count(1, ACK) == 0,
	      "UNKNOWN RX cannot report success or acknowledge restoration");
	CHECK(chain_stage_unbind_checked(rx, 0) == -EIO,
	      "unsettled native RX refuses checked unbind");
	for (unsigned f = 0; f < chain_pool_frames(rx); f++)
		if (mask & (1u << f)) {
			CHECK(chain_frame_custody(rx, f) == chain_frame_state_sequestered(),
			      "UNKNOWN RX sequesters its Host frames");
			CHECK(chain_retained_leases(1, CHAIN_DEV_NHI, f * CE_FRAME, CE_FRAME) >= 1,
			      "UNKNOWN RX retains NHI DMA ownership");
		}
	ce_pristine();
	chain_hold_tx_completions(1, false);
	ce_settle(50);
	CHECK(chain_rx_callbacks() == CE_GROUP / CE_FRAME, "the withheld native RX callbacks really run late");
	CHECK(chain_stage_submitted(rx, 1) == 0 && chain_session_done(rx) == 0,
	      "late RX completion neither starts CE nor converts the failed batch to success");
	for (unsigned f = 0; f < chain_pool_frames(rx); f++)
		if (mask & (1u << f))
			CHECK(chain_frame_custody(rx, f) == chain_frame_state_sequestered(),
			      "late completion cannot recycle quarantined Host frames");
	CHECK(count(CHAIN_EV_DMA_UNMAP, 1) == 0, "pending and late RX never unmaps retained NHI pages");
	CHECK(chain_violations() == 0, "no later device accesses retained frames under a new lease");
	ce_pristine();
}

static bool ce_rx_case(const char *name)
{
	if (!strcmp(name, "rx_partial_wait"))
		rx_partial_wait();
	else if (!strcmp(name, "rx_short"))
		rx_failed(true);
	else if (!strcmp(name, "rx_error"))
		rx_failed(false);
	else if (!strcmp(name, "rx_unknown_late"))
		rx_unknown_late();
	else
		return false;
	return true;
}
