/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XDP_XSK_XDEV_EXT_CORE_H
#define _NET_XDP_XSK_XDEV_EXT_CORE_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/stddef.h>
#include <linux/types.h>

typedef u32 xsk_xdev_ext_u32;
typedef u64 xsk_xdev_ext_u64;
#else
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint32_t xsk_xdev_ext_u32;
typedef uint64_t xsk_xdev_ext_u64;
#endif

#define XSK_XDEV_EXT_U64_MAX ((xsk_xdev_ext_u64)~0ULL)

/*
 * This state machine does no internal synchronization. Its owner must hold
 * the per-pool journal lock around every operation, including read helpers.
 */
enum xsk_xdev_ext_record_state {
	XSK_XDEV_EXT_RECORD_FREE = 0,
	XSK_XDEV_EXT_RECORD_RESERVED,
	XSK_XDEV_EXT_RECORD_NATIVE,
	XSK_XDEV_EXT_RECORD_READY,
};

struct xsk_xdev_ext_record_core {
	xsk_xdev_ext_u64 sequence;
	xsk_xdev_ext_u64 length;
	xsk_xdev_ext_u64 bytes_done;
	/* Packet descriptors, CQ entries still owed, and native retirements. */
	xsk_xdev_ext_u32 nr_descs;
	xsk_xdev_ext_u32 cq_descs;
	xsk_xdev_ext_u32 retired;
	int result;
	enum xsk_xdev_ext_record_state state;
	bool exact_completion;
	bool native_result_known;
};

struct xsk_xdev_ext_journal_core {
	struct xsk_xdev_ext_record_core *records;
	xsk_xdev_ext_u64 head;
	xsk_xdev_ext_u64 tail;
	xsk_xdev_ext_u64 retire_cursor;
	xsk_xdev_ext_u64 native_descs_pending;
	xsk_xdev_ext_u32 capacity;
	xsk_xdev_ext_u32 mask;
	bool stopped;
};

static inline bool xsk_xdev_ext_core_power_of_two(xsk_xdev_ext_u32 value)
{
	return value && !(value & (value - 1));
}

static inline void
xsk_xdev_ext_core_clear_record(struct xsk_xdev_ext_record_core *record)
{
	record->sequence = 0;
	record->length = 0;
	record->bytes_done = 0;
	record->nr_descs = 0;
	record->cq_descs = 0;
	record->retired = 0;
	record->result = 0;
	record->state = XSK_XDEV_EXT_RECORD_FREE;
	record->exact_completion = false;
	record->native_result_known = false;
}

static inline int
xsk_xdev_ext_core_validate_journal(const struct xsk_xdev_ext_journal_core *journal)
{
	if (!journal || !journal->records ||
	    !xsk_xdev_ext_core_power_of_two(journal->capacity) ||
	    journal->capacity > INT_MAX ||
	    journal->mask != journal->capacity - 1)
		return -EINVAL;
	if (journal->head > journal->tail ||
	    journal->tail - journal->head > journal->capacity)
		return -EPROTO;
	if (journal->retire_cursor < journal->head ||
	    journal->retire_cursor > journal->tail ||
	    journal->native_descs_pending >
		(journal->tail - journal->head) * (xsk_xdev_ext_u64)INT_MAX)
		return -EPROTO;
	return 0;
}

static inline int
xsk_xdev_ext_core_validate_result(const struct xsk_xdev_ext_record_core *record,
			     int result, xsk_xdev_ext_u64 bytes_done)
{
	if (result > 0 || bytes_done > record->length)
		return -EINVAL;
	if (result < 0 && bytes_done)
		return -EINVAL;
	return 0;
}

static inline int
xsk_xdev_ext_core_validate_record(const struct xsk_xdev_ext_journal_core *journal,
			     xsk_xdev_ext_u64 sequence,
			     const struct xsk_xdev_ext_record_core *record)
{
	if (record->state <= XSK_XDEV_EXT_RECORD_FREE ||
	    record->state > XSK_XDEV_EXT_RECORD_READY ||
	    record->sequence != sequence || !record->length ||
	    !record->nr_descs ||
	    record->nr_descs > INT_MAX ||
	    record->cq_descs > record->nr_descs ||
	    record->retired > record->nr_descs)
		return -EPROTO;
	if (!record->exact_completion && record->cq_descs != record->nr_descs)
		return -EPROTO;

	if (record->state == XSK_XDEV_EXT_RECORD_RESERVED &&
	    (record->retired || record->exact_completion ||
	     record->native_result_known || record->result ||
	     record->bytes_done))
		return -EPROTO;
	if (record->state == XSK_XDEV_EXT_RECORD_NATIVE) {
		if (!record->exact_completion &&
		    (!record->native_result_known ||
		     (!record->result && record->bytes_done != record->length)))
			return -EPROTO;
		if (record->exact_completion && record->retired &&
		    record->retired != record->nr_descs)
			return -EPROTO;
		if (record->exact_completion && !record->native_result_known &&
		    (record->result || record->bytes_done))
			return -EPROTO;
	}
	if (record->state == XSK_XDEV_EXT_RECORD_READY && !record->native_result_known)
		return -EPROTO;
	if (record->native_result_known) {
		if (xsk_xdev_ext_core_validate_result(record, record->result, record->bytes_done))
			return -EPROTO;
	}

	(void)journal;
	return 0;
}

static inline int
xsk_xdev_ext_core_init(struct xsk_xdev_ext_journal_core *journal,
		  struct xsk_xdev_ext_record_core *records, xsk_xdev_ext_u32 count)
{
	xsk_xdev_ext_u32 i;

	if (!journal || !records || !xsk_xdev_ext_core_power_of_two(count) ||
	    count > INT_MAX)
		return -EINVAL;

	for (i = 0; i < count; i++)
		xsk_xdev_ext_core_clear_record(&records[i]);

	journal->records = records;
	journal->head = 0;
	journal->tail = 0;
	journal->retire_cursor = 0;
	journal->native_descs_pending = 0;
	journal->capacity = count;
	journal->mask = count - 1;
	journal->stopped = false;
	return 0;
}

static inline int
xsk_xdev_ext_core_lookup(struct xsk_xdev_ext_journal_core *journal,
		    xsk_xdev_ext_u64 sequence,
		    struct xsk_xdev_ext_record_core **record_out)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	if (!record_out)
		return -EINVAL;
	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (sequence < journal->head || sequence >= journal->tail)
		return -ENOENT;

	record = &journal->records[sequence & journal->mask];
	error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
	if (error)
		return error;
	*record_out = record;
	return 0;
}

static inline int
xsk_xdev_ext_core_reserve(struct xsk_xdev_ext_journal_core *journal,
		     xsk_xdev_ext_u32 nr_descs, xsk_xdev_ext_u64 length,
		     xsk_xdev_ext_u64 *sequence)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	if (!sequence || !nr_descs || nr_descs > INT_MAX || !length)
		return -EINVAL;
	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (journal->stopped)
		return -ESHUTDOWN;
	if (journal->tail - journal->head == journal->capacity)
		return -ENOSPC;
	/* Keep head <= tail so every range and capacity check stays exact. */
	if (journal->tail == XSK_XDEV_EXT_U64_MAX)
		return -EOVERFLOW;

	record = &journal->records[journal->tail & journal->mask];
	if (record->state != XSK_XDEV_EXT_RECORD_FREE)
		return -EPROTO;

	record->sequence = journal->tail;
	record->length = length;
	record->bytes_done = 0;
	record->nr_descs = nr_descs;
	record->cq_descs = nr_descs;
	record->retired = 0;
	record->result = 0;
	record->state = XSK_XDEV_EXT_RECORD_RESERVED;
	record->exact_completion = false;
	record->native_result_known = false;
	*sequence = journal->tail++;
	return 0;
}

static inline int
xsk_xdev_ext_core_set_native(struct xsk_xdev_ext_journal_core *journal,
			xsk_xdev_ext_u64 sequence)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	error = xsk_xdev_ext_core_lookup(journal, sequence, &record);
	if (error)
		return error;
	if (record->state != XSK_XDEV_EXT_RECORD_RESERVED)
		return -EBUSY;
	if (XSK_XDEV_EXT_U64_MAX - journal->native_descs_pending <
	    record->nr_descs)
		return -EOVERFLOW;
	record->state = XSK_XDEV_EXT_RECORD_NATIVE;
	record->result = 0;
	record->bytes_done = record->length;
	record->native_result_known = true;
	if (!journal->native_descs_pending ||
	    sequence < journal->retire_cursor)
		journal->retire_cursor = sequence;
	journal->native_descs_pending += record->nr_descs;
	return 0;
}

/* COPY completion is exact and needs both destructor and return-result gates. */
static inline int
xsk_xdev_ext_core_set_native_exact(struct xsk_xdev_ext_journal_core *journal,
			      xsk_xdev_ext_u64 sequence)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	error = xsk_xdev_ext_core_lookup(journal, sequence, &record);
	if (error)
		return error;
	if (record->state != XSK_XDEV_EXT_RECORD_RESERVED)
		return -EBUSY;
	record->state = XSK_XDEV_EXT_RECORD_NATIVE;
	record->exact_completion = true;
	return 0;
}

static inline int
xsk_xdev_ext_core_set_ready(struct xsk_xdev_ext_journal_core *journal,
		       xsk_xdev_ext_u64 sequence, int result,
		       xsk_xdev_ext_u64 bytes_done)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	error = xsk_xdev_ext_core_lookup(journal, sequence, &record);
	if (error)
		return error;
	if (record->state != XSK_XDEV_EXT_RECORD_RESERVED)
		return -EBUSY;
	error = xsk_xdev_ext_core_validate_result(record, result, bytes_done);
	if (error)
		return error;
	record->result = result;
	record->bytes_done = bytes_done;
	record->native_result_known = true;
	record->state = XSK_XDEV_EXT_RECORD_READY;
	return 0;
}

static inline int
xsk_xdev_ext_core_set_result(struct xsk_xdev_ext_journal_core *journal,
			xsk_xdev_ext_u64 sequence, int result,
			xsk_xdev_ext_u64 bytes_done)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	error = xsk_xdev_ext_core_lookup(journal, sequence, &record);
	if (error)
		return error;
	if (record->state == XSK_XDEV_EXT_RECORD_READY &&
	    record->exact_completion && record->native_result_known)
		return -EALREADY;
	if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
	    !record->exact_completion)
		return -EBUSY;
	if (record->native_result_known)
		return -EALREADY;
	error = xsk_xdev_ext_core_validate_result(record, result, bytes_done);
	if (error)
		return error;
	record->result = result;
	record->bytes_done = bytes_done;
	record->native_result_known = true;
	if (record->retired == record->nr_descs)
		record->state = XSK_XDEV_EXT_RECORD_READY;
	return 0;
}

static inline int
xsk_xdev_ext_core_complete_exact(struct xsk_xdev_ext_journal_core *journal,
			    xsk_xdev_ext_u64 sequence)
{
	struct xsk_xdev_ext_record_core *record;
	int error;

	error = xsk_xdev_ext_core_lookup(journal, sequence, &record);
	if (error)
		return error;
	if (record->state == XSK_XDEV_EXT_RECORD_READY &&
	    record->exact_completion &&
	    record->retired == record->nr_descs)
		return -EALREADY;
	if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
	    !record->exact_completion)
		return -EBUSY;
	if (record->retired)
		return -EALREADY;
	record->retired = record->nr_descs;
	if (record->native_result_known)
		record->state = XSK_XDEV_EXT_RECORD_READY;
	return 0;
}

static inline int
xsk_xdev_ext_core_complete_descs_result(struct xsk_xdev_ext_journal_core *journal,
				   xsk_xdev_ext_u32 nr_descs, int result)
{
	xsk_xdev_ext_u64 available = 0;
	xsk_xdev_ext_u64 sequence;
	xsk_xdev_ext_u32 remaining = nr_descs;
	int error;

	if (result > 0)
		return -EINVAL;
	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (nr_descs > journal->native_descs_pending)
		return -EOVERFLOW;

	/* Validate every record this transaction will touch before mutation. */
	for (sequence = journal->retire_cursor;
	     available < nr_descs && sequence < journal->tail; sequence++) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[sequence & journal->mask];

		error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
		if (error)
			return error;
		if (record->state == XSK_XDEV_EXT_RECORD_NATIVE &&
		    !record->exact_completion)
			available += record->nr_descs - record->retired;
	}
	if (available < nr_descs)
		return -EPROTO;

	sequence = journal->retire_cursor;
	while (remaining) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[sequence & journal->mask];
		xsk_xdev_ext_u32 pending;
		xsk_xdev_ext_u32 completed;

		if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
		    record->exact_completion) {
			sequence++;
			continue;
		}
		pending = record->nr_descs - record->retired;
		completed = remaining < pending ? remaining : pending;
		record->retired += completed;
		remaining -= completed;
		/* A teardown error stays attached through later retire credits. */
		if (completed && result < 0 && !record->result) {
			record->result = result;
			record->bytes_done = 0;
		}
		if (record->retired == record->nr_descs)
			record->state = XSK_XDEV_EXT_RECORD_READY;
		if (completed == pending)
			sequence++;
	}
	journal->native_descs_pending -= nr_descs;
	journal->retire_cursor = journal->native_descs_pending ?
		sequence : journal->tail;
	return 0;
}

static inline int
xsk_xdev_ext_core_complete_descs(struct xsk_xdev_ext_journal_core *journal,
			    xsk_xdev_ext_u32 nr_descs)
{
	return xsk_xdev_ext_core_complete_descs_result(journal, nr_descs, 0);
}

/* Attach a known driver-side error to newest accepted native records. */
static inline int
xsk_xdev_ext_core_set_native_tail_result(struct xsk_xdev_ext_journal_core *journal,
				    xsk_xdev_ext_u32 nr_descs, int result)
{
	xsk_xdev_ext_u64 sequence;
	xsk_xdev_ext_u64 available = 0;
	xsk_xdev_ext_u32 remaining = nr_descs;
	int error;

	if (!nr_descs || result >= 0)
		return -EINVAL;
	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (nr_descs > journal->native_descs_pending)
		return -EOVERFLOW;

	for (sequence = journal->tail;
	     sequence > journal->head && available < nr_descs;) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[(--sequence) & journal->mask];
		xsk_xdev_ext_u32 pending;

		error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
		if (error)
			return error;
		if (record->state == XSK_XDEV_EXT_RECORD_RESERVED)
			return -EBUSY;
		if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
		    record->exact_completion)
			continue;
		if (record->retired)
			return -EBUSY;
		if (record->result < 0)
			return -EALREADY;
		pending = record->nr_descs;
		if (pending > nr_descs - available)
			return -EINVAL;
		available += pending;
	}
	if (available < nr_descs)
		return -EPROTO;

	for (sequence = journal->tail; remaining;) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[(--sequence) & journal->mask];

		if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
		    record->exact_completion)
			continue;
		record->result = result;
		record->bytes_done = 0;
		remaining -= record->nr_descs;
	}
	return 0;
}

/*
 * Reject the newest whole native records before a driver submits them.  The
 * descriptor count is expressed in the same dense native stream returned by
 * the XSK peek helpers; READY policy holes and exact COPY records are skipped.
 * Validation is completed before any record is changed so a count that would
 * split a multi-buffer packet leaves the journal untouched.
 */
static inline int
xsk_xdev_ext_core_cancel_native_tail(struct xsk_xdev_ext_journal_core *journal,
				xsk_xdev_ext_u32 nr_descs, int result)
{
	xsk_xdev_ext_u64 sequence;
	xsk_xdev_ext_u64 available = 0;
	xsk_xdev_ext_u32 remaining = nr_descs;
	int error;

	if (!nr_descs || result >= 0)
		return -EINVAL;
	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (nr_descs > journal->native_descs_pending)
		return -EOVERFLOW;

	/* Validate the newest whole native records before mutating any of them. */
	for (sequence = journal->tail;
	     sequence > journal->head && available < nr_descs;) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[(--sequence) & journal->mask];
		xsk_xdev_ext_u32 pending;

		error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
		if (error)
			return error;
		if (record->state == XSK_XDEV_EXT_RECORD_RESERVED)
			return -EBUSY;
		if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
		    record->exact_completion)
			continue;
		if (record->retired)
			return -EBUSY;
		pending = record->nr_descs;
		if (pending > nr_descs - available)
			return -EINVAL;
		available += pending;
	}
	if (available < nr_descs)
		return -EPROTO;

	for (sequence = journal->tail; remaining;) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[(--sequence) & journal->mask];

		if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
		    record->exact_completion)
			continue;
		record->retired = record->nr_descs;
		record->result = result;
		record->bytes_done = 0;
		record->native_result_known = true;
		record->state = XSK_XDEV_EXT_RECORD_READY;
		remaining -= record->nr_descs;
	}

	journal->native_descs_pending -= nr_descs;
	if (!journal->native_descs_pending)
		journal->retire_cursor = journal->tail;
	return 0;
}

static inline bool
xsk_xdev_ext_core_ready(const struct xsk_xdev_ext_journal_core *journal)
{
	const struct xsk_xdev_ext_record_core *record;

	if (xsk_xdev_ext_core_validate_journal(journal) ||
	    journal->head == journal->tail)
		return false;
	record = &journal->records[journal->head & journal->mask];
	return !xsk_xdev_ext_core_validate_record(journal, journal->head, record) &&
	       record->state == XSK_XDEV_EXT_RECORD_READY;
}

static inline const struct xsk_xdev_ext_record_core *
xsk_xdev_ext_core_front(const struct xsk_xdev_ext_journal_core *journal)
{
	if (!xsk_xdev_ext_core_ready(journal))
		return NULL;
	return &journal->records[journal->head & journal->mask];
}

static inline const struct xsk_xdev_ext_record_core *
xsk_xdev_ext_core_front_any(const struct xsk_xdev_ext_journal_core *journal)
{
	const struct xsk_xdev_ext_record_core *record;

	if (xsk_xdev_ext_core_validate_journal(journal) ||
	    journal->head == journal->tail)
		return NULL;
	record = &journal->records[journal->head & journal->mask];
	if (xsk_xdev_ext_core_validate_record(journal, journal->head, record))
		return NULL;
	return record;
}

static inline int xsk_xdev_ext_core_pop(struct xsk_xdev_ext_journal_core *journal)
{
	struct xsk_xdev_ext_record_core *record;
	int cq_descs;
	int error;

	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (journal->head == journal->tail)
		return -ENOENT;
	record = &journal->records[journal->head & journal->mask];
	error = xsk_xdev_ext_core_validate_record(journal, journal->head, record);
	if (error)
		return error;
	if (record->state != XSK_XDEV_EXT_RECORD_READY)
		return -EAGAIN;

	cq_descs = (int)record->cq_descs;
	xsk_xdev_ext_core_clear_record(record);
	journal->head++;
	if (journal->retire_cursor < journal->head)
		journal->retire_cursor = journal->head;
	return cq_descs;
}

static inline int
xsk_xdev_ext_core_rollback_tail(struct xsk_xdev_ext_journal_core *journal,
			   xsk_xdev_ext_u64 sequence)
{
	struct xsk_xdev_ext_record_core *record;
	int nr_descs;
	int error;

	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (sequence < journal->head || sequence >= journal->tail)
		return -ENOENT;
	if (sequence != journal->tail - 1)
		return -EBUSY;
	record = &journal->records[sequence & journal->mask];
	error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
	if (error)
		return error;
	if (record->state != XSK_XDEV_EXT_RECORD_RESERVED)
		return -EBUSY;

	nr_descs = (int)record->nr_descs;
	xsk_xdev_ext_core_clear_record(record);
	journal->tail--;
	if (journal->retire_cursor > journal->tail)
		journal->retire_cursor = journal->tail;
	return nr_descs;
}

static inline int
xsk_xdev_ext_core_cancel_tail_cq(struct xsk_xdev_ext_journal_core *journal,
			    xsk_xdev_ext_u64 sequence)
{
	struct xsk_xdev_ext_record_core *record;
	int cq_descs;
	int error;

	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (sequence < journal->head || sequence >= journal->tail)
		return -ENOENT;
	if (sequence != journal->tail - 1)
		return -EBUSY;
	record = &journal->records[sequence & journal->mask];
	error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
	if (error)
		return error;
	if (record->state != XSK_XDEV_EXT_RECORD_NATIVE ||
	    !record->exact_completion)
		return -EBUSY;

	cq_descs = (int)record->cq_descs;
	record->cq_descs = 0;
	return cq_descs;
}

static inline int
xsk_xdev_ext_core_stop(struct xsk_xdev_ext_journal_core *journal, int result)
{
	xsk_xdev_ext_u64 sequence;
	xsk_xdev_ext_u64 native_descs_pending = 0;
	int canceled = 0;
	int error;

	if (result >= 0)
		return -EINVAL;
	error = xsk_xdev_ext_core_validate_journal(journal);
	if (error)
		return error;
	if (journal->stopped)
		return 0;

	/* Validate first so stop is atomic in the presence of corruption. */
	for (sequence = journal->head; sequence < journal->tail; sequence++) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[sequence & journal->mask];

		error = xsk_xdev_ext_core_validate_record(journal, sequence, record);
		if (error)
			return error;
		/* A pre-native record still owns a put/rollback disposition. */
		if (record->state == XSK_XDEV_EXT_RECORD_RESERVED)
			return -EBUSY;
		if (record->state == XSK_XDEV_EXT_RECORD_NATIVE &&
		    !record->exact_completion)
			native_descs_pending += record->nr_descs - record->retired;
		if (record->state != XSK_XDEV_EXT_RECORD_READY)
			canceled++;
	}
	if (native_descs_pending != journal->native_descs_pending)
		return -EPROTO;

	journal->stopped = true;
	journal->native_descs_pending = 0;
	journal->retire_cursor = journal->tail;
	for (sequence = journal->head; sequence < journal->tail; sequence++) {
		struct xsk_xdev_ext_record_core *record =
			&journal->records[sequence & journal->mask];

		if (record->state == XSK_XDEV_EXT_RECORD_READY)
			continue;
		record->result = result;
		record->bytes_done = 0;
		record->native_result_known = true;
		record->state = XSK_XDEV_EXT_RECORD_READY;
	}
	return canceled;
}

#endif /* _NET_XDP_XSK_XDEV_EXT_CORE_H */
