// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../../../../net/xdp/xsk_xdev_ext_core.h"

static unsigned int tests_run;
static unsigned int tests_failed;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	tests_run++;                                                        \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		tests_failed++;                                               \
	}                                                                   \
} while (0)

static void init_journal(struct xsk_xdev_ext_journal_core *journal,
			 struct xsk_xdev_ext_record_core *records, uint32_t count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		records[i] = (struct xsk_xdev_ext_record_core){};
	EXPECT_EQ(xsk_xdev_ext_core_init(journal, records, count), 0);
}

static void test_single_packet(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 128, &seq), 0);
	EXPECT_EQ(seq, 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), 0);
	EXPECT_EQ(journal.native_descs_pending, 1);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(journal.native_descs_pending, 0);
	EXPECT_EQ(journal.retire_cursor, journal.tail);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), true);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->length, 128);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
}

static void test_partial_multibuffer_completion(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 3, 4096, &seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 2), 0);
	EXPECT_EQ(journal.native_descs_pending, 1);
	EXPECT_EQ(journal.retire_cursor, seq);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(journal.native_descs_pending, 0);
	EXPECT_EQ(journal.retire_cursor, journal.tail);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), true);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 3);
}

static void test_terminal_hole_waits_for_native_prefix(void)
{
	struct xsk_xdev_ext_record_core records[8];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, terminal = UINT64_MAX, last = UINT64_MAX;

	init_journal(&journal, records, 8);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &terminal), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, terminal, -EPERM, 0), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 256, &last), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, last), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), true);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, first);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, terminal);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -EPERM);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 2);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, last);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
}

static void test_completion_crosses_records_and_wraps(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;
	unsigned int i;

	init_journal(&journal, records, 4);
	for (i = 0; i < 10; i++) {
		EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1 + (i & 1),
					       100 + i, &seq), 0);
		EXPECT_EQ(seq, i);
		EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), 0);
		EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1 + (i & 1)), 0);
		EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1 + (i & 1));
	}
}

static void test_overrun_is_atomic(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 512, &seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 3), -EOVERFLOW);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_front_any(&journal)->retired, 0);
}

static void test_tail_rollback(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, second = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_rollback_tail(&journal, second), 2);
	EXPECT_EQ(xsk_xdev_ext_core_rollback_tail(&journal, first), -EBUSY);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
}

static void test_stop_cancels_once(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, second = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_stop(&journal, -ECANCELED), 2);
	EXPECT_EQ(xsk_xdev_ext_core_stop(&journal, -ECANCELED), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 1, &second), -ESHUTDOWN);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -ECANCELED);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -ECANCELED);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 2);
}

static void test_terminal_holes_do_not_consume_native_credit(void)
{
	struct xsk_xdev_ext_record_core records[8];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, terminal = UINT64_MAX;
	uint64_t last = UINT64_MAX;

	init_journal(&journal, records, 8);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &terminal), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, terminal, -EPERM, 0), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 256, &last), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, last), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 2), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, first);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, terminal);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 2);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, last);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
}

static void test_partial_overrun_is_atomic(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, second = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(records[first & journal.mask].retired, 1);
	EXPECT_EQ(records[second & journal.mask].retired, 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs_result(&journal, 4,
						     -ECANCELED), -EOVERFLOW);
	EXPECT_EQ(records[first & journal.mask].retired, 1);
	EXPECT_EQ(records[first & journal.mask].result, 0);
	EXPECT_EQ(records[second & journal.mask].retired, 0);
	EXPECT_EQ(records[second & journal.mask].result, 0);
	EXPECT_EQ(journal.native_descs_pending, 3);
	EXPECT_EQ(journal.retire_cursor, first);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 4), -EOVERFLOW);
	EXPECT_EQ(records[first & journal.mask].retired, 1);
	EXPECT_EQ(records[second & journal.mask].retired, 0);
}

static void test_teardown_completion_result_is_sticky(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, second = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs_result(&journal, 2,
						     -ECANCELED), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -ECANCELED);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->bytes_done, 0);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 2);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(records[second & journal.mask].retired, 1);
	EXPECT_EQ(records[second & journal.mask].result, -ECANCELED);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs_result(&journal, 1, 0), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -ECANCELED);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->bytes_done, 0);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 2);
}

static void test_exact_completion_gates_and_order(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, second = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_exact(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 128, &second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_exact(&journal, second), 0);

	/* A later skb may be destroyed first, but FIFO publication is stable. */
	EXPECT_EQ(xsk_xdev_ext_core_complete_exact(&journal, second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_result(&journal, second, 0, 128), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);

	/* The destructor may also run synchronously before native returns. */
	EXPECT_EQ(xsk_xdev_ext_core_complete_exact(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_exact(&journal, first), -EALREADY);
	EXPECT_EQ(xsk_xdev_ext_core_set_result(&journal, first, 0, 64), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), true);
	EXPECT_EQ(xsk_xdev_ext_core_set_result(&journal, first, 0, 64), -EALREADY);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, second);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
}

static void test_exact_result_before_destructor(void)
{
	struct xsk_xdev_ext_record_core records[2];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;

	init_journal(&journal, records, 2);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 512, &seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_exact(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_result(&journal, seq, 0, 512), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_exact(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), true);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 2);
}

static void test_busy_cancels_cq_but_keeps_callback_record(void)
{
	struct xsk_xdev_ext_record_core records[2];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;

	init_journal(&journal, records, 2);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 512, &seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_exact(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_exact(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_tail_cq(&journal, seq), 2);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_tail_cq(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_result(&journal, seq, -EAGAIN, 0), 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), true);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -EAGAIN);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 0);
}

static void test_native_tail_cancel_keeps_fifo_identity(void)
{
	struct xsk_xdev_ext_record_core records[8];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, rejected = UINT64_MAX;
	uint64_t terminal = UINT64_MAX, last = UINT64_MAX;

	init_journal(&journal, records, 8);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 128, &rejected), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, rejected), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 32, &terminal), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, terminal, -EPERM, 0), 0);

	/* Ready policy holes do not change which native tail was rejected. */
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 1, -EIO), 0);
	EXPECT_EQ(journal.native_descs_pending, 1);
	EXPECT_EQ(records[rejected & journal.mask].state, XSK_XDEV_EXT_RECORD_READY);
	EXPECT_EQ(records[rejected & journal.mask].result, -EIO);
	EXPECT_EQ(records[rejected & journal.mask].bytes_done, 0);
	EXPECT_EQ(records[rejected & journal.mask].retired, 1);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);

	/* A later accepted packet remains a distinct completion identity. */
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 256, &last), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, last), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, first);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, rejected);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, terminal);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, last);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
}

static void test_native_tail_cancel_is_packet_atomic(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, second = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &second), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, second), 0);

	/* A descriptor count may not split an admitted multi-buffer packet. */
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 2, -EIO), -EINVAL);
	EXPECT_EQ(journal.native_descs_pending, 3);
	EXPECT_EQ(records[first & journal.mask].state, XSK_XDEV_EXT_RECORD_NATIVE);
	EXPECT_EQ(records[second & journal.mask].state, XSK_XDEV_EXT_RECORD_NATIVE);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 3, -EIO), 0);
	EXPECT_EQ(journal.native_descs_pending, 0);
	EXPECT_EQ(journal.retire_cursor, journal.tail);
	EXPECT_EQ(records[first & journal.mask].result, -EIO);
	EXPECT_EQ(records[second & journal.mask].result, -EIO);

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 1, -EIO), -EBUSY);
	EXPECT_EQ(journal.native_descs_pending, 1);
	EXPECT_EQ(records[first & journal.mask].retired, 1);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 0, -EIO), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 1, 0), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_cancel_native_tail(&journal, 2, -EIO),
		  -EOVERFLOW);
}

static void test_native_tail_error_waits_for_device_retirement(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t first = UINT64_MAX, failed = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 128, &failed), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, failed), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_tail_result(&journal, 1,
						      -EMSGSIZE), 0);
	EXPECT_EQ(journal.native_descs_pending, 2);
	EXPECT_EQ(records[failed & journal.mask].state, XSK_XDEV_EXT_RECORD_NATIVE);
	EXPECT_EQ(records[failed & journal.mask].result, -EMSGSIZE);
	EXPECT_EQ(records[failed & journal.mask].bytes_done, 0);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);

	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, first);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
	EXPECT_EQ(xsk_xdev_ext_core_ready(&journal), false);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->sequence, failed);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -EMSGSIZE);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->bytes_done, 0);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 2, 128, &first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, first), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_tail_result(&journal, 1,
						      -EIO), -EINVAL);
	EXPECT_EQ(records[first & journal.mask].result, 0);
	EXPECT_EQ(records[first & journal.mask].bytes_done, 128);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_tail_result(&journal, 2,
						      -EIO), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_tail_result(&journal, 2,
						      -EIO), -EALREADY);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_tail_result(&journal, 0,
						      -EIO), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_tail_result(&journal, 2, 0),
		  -EINVAL);
}

static void test_strict_transitions_and_overflow(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t seq = UINT64_MAX;

	EXPECT_EQ(xsk_xdev_ext_core_init(&journal, records, 3), -EINVAL);
	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 0, 1, &seq), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 0, &seq), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, (uint32_t)INT_MAX + 1U,
				       1, &seq), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, seq, 1, 0), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, seq, -EIO, 1), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_set_native_exact(&journal, seq), 0);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs_result(&journal, 0, 1), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_core_complete_descs(&journal, 1), -EOVERFLOW);
	EXPECT_EQ(xsk_xdev_ext_core_rollback_tail(&journal, seq), -EBUSY);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, seq, 0, 64), -EBUSY);

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &seq), 0);
	records[0].length = 0;
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), -EPROTO);

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &seq), 0);
	records[0].cq_descs = 0;
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), -EPROTO);

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &seq), 0);
	records[0].bytes_done = 1;
	EXPECT_EQ(xsk_xdev_ext_core_set_native(&journal, seq), -EPROTO);

	init_journal(&journal, records, 4);
	journal.head = UINT64_MAX;
	journal.tail = UINT64_MAX;
	journal.retire_cursor = UINT64_MAX;
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &seq), -EOVERFLOW);
}

static void test_stop_preserves_ready_and_rejects_reserved(void)
{
	struct xsk_xdev_ext_record_core records[4];
	struct xsk_xdev_ext_journal_core journal;
	uint64_t ready = UINT64_MAX, pending = UINT64_MAX;

	init_journal(&journal, records, 4);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 64, &ready), 0);
	EXPECT_EQ(xsk_xdev_ext_core_set_ready(&journal, ready, -EPERM, 0), 0);
	EXPECT_EQ(xsk_xdev_ext_core_reserve(&journal, 1, 128, &pending), 0);
	EXPECT_EQ(xsk_xdev_ext_core_stop(&journal, -ECANCELED), -EBUSY);
	EXPECT_EQ(journal.stopped, false);
	EXPECT_EQ(xsk_xdev_ext_core_rollback_tail(&journal, pending), 1);
	EXPECT_EQ(xsk_xdev_ext_core_stop(&journal, -ECANCELED), 0);
	EXPECT_EQ(xsk_xdev_ext_core_front(&journal)->result, -EPERM);
	EXPECT_EQ(xsk_xdev_ext_core_pop(&journal), 1);
}

int main(void)
{
	test_single_packet();
	test_partial_multibuffer_completion();
	test_terminal_hole_waits_for_native_prefix();
	test_completion_crosses_records_and_wraps();
	test_overrun_is_atomic();
	test_tail_rollback();
	test_stop_cancels_once();
	test_terminal_holes_do_not_consume_native_credit();
	test_partial_overrun_is_atomic();
	test_teardown_completion_result_is_sticky();
	test_exact_completion_gates_and_order();
	test_exact_result_before_destructor();
	test_busy_cancels_cq_but_keeps_callback_record();
	test_native_tail_cancel_keeps_fifo_identity();
	test_native_tail_cancel_is_packet_atomic();
	test_native_tail_error_waits_for_device_retirement();
	test_strict_transitions_and_overflow();
	test_stop_preserves_ready_and_rejects_reserved();

	if (tests_failed) {
		fprintf(stderr, "FAIL: %u of %u checks failed\n",
			tests_failed, tests_run);
		return 1;
	}
	printf("PASS: %u checks\n", tests_run);
	return 0;
}
