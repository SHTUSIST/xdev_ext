// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../../net/xdp/xsk_xdev_ext_core.h"

#define FAKE_RECORDS 32U
#define FAKE_MAX_DESCS 64U
#define FAKE_MAX_EVENTS 64U
#define FAKE_ZC_MAX_SEGS 3U
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

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

enum fake_policy_action {
	FAKE_POLICY_NATIVE,
	FAKE_POLICY_TERMINAL,
};

struct fake_tx_desc {
	uint64_t addr;
	uint32_t len;
	unsigned int packet_id;
	bool contd;
	bool valid;
	enum fake_policy_action action;
};

struct fake_socket {
	struct fake_tx_desc tx[FAKE_MAX_DESCS];
	unsigned int id;
	unsigned int producer;
	unsigned int consumer;
	bool discard_until_eop;
};

struct fake_native_desc {
	uint64_t sequence;
	unsigned int socket_id;
	unsigned int packet_id;
	unsigned int segment;
	uint32_t len;
};

struct fake_record_meta {
	uint64_t sequence;
	unsigned int socket_id;
	unsigned int packet_id;
	unsigned int callback_count;
	bool token_live;
	bool live;
};

struct fake_callback_event {
	uint64_t sequence;
	uint64_t bytes_done;
	unsigned int socket_id;
	unsigned int packet_id;
	unsigned int step;
	int result;
};

struct fake_cq_entry {
	uint64_t sequence;
	unsigned int socket_id;
	unsigned int packet_id;
	unsigned int step;
};

struct fake_pool {
	struct xsk_xdev_ext_record_core records[FAKE_RECORDS];
	struct xsk_xdev_ext_journal_core journal;
	struct fake_record_meta meta[FAKE_RECORDS];
	struct fake_callback_event callbacks[FAKE_MAX_EVENTS];
	struct fake_cq_entry cq[FAKE_MAX_DESCS];
	unsigned int nr_callbacks;
	unsigned int nr_cq;
	unsigned int dispatches;
	unsigned int rr_next;
	unsigned int clock;
};

struct fake_packet {
	const struct fake_tx_desc *descs;
	uint64_t length;
	unsigned int nr_descs;
	unsigned int packet_id;
	enum fake_policy_action action;
};

static void fake_pool_init(struct fake_pool *pool)
{
	memset(pool, 0, sizeof(*pool));
	EXPECT_EQ(xsk_xdev_ext_core_init(&pool->journal, pool->records,
				    FAKE_RECORDS), 0);
}

static void fake_socket_init(struct fake_socket *socket, unsigned int id)
{
	memset(socket, 0, sizeof(*socket));
	socket->id = id;
}

static void fake_push_packet(struct fake_socket *socket,
			     unsigned int packet_id,
			     const uint32_t *lengths, unsigned int nr_descs,
			     enum fake_policy_action action)
{
	unsigned int i;

	EXPECT_EQ(nr_descs > 0, true);
	EXPECT_EQ(socket->producer + nr_descs <= FAKE_MAX_DESCS, true);
	for (i = 0; i < nr_descs; i++) {
		struct fake_tx_desc *desc = &socket->tx[socket->producer++];

		desc->addr = ((uint64_t)socket->id << 48) |
			     ((uint64_t)packet_id << 16) | i;
		desc->len = lengths[i];
		desc->packet_id = packet_id;
		desc->contd = i + 1 < nr_descs;
		desc->valid = true;
		desc->action = action;
	}
}

static void fake_push_desc(struct fake_socket *socket, unsigned int packet_id,
			   uint32_t length, bool contd,
			   enum fake_policy_action action)
{
	struct fake_tx_desc *desc;

	EXPECT_EQ(socket->producer < FAKE_MAX_DESCS, true);
	desc = &socket->tx[socket->producer++];
	*desc = (struct fake_tx_desc) {
		.addr = ((uint64_t)socket->id << 48) |
			((uint64_t)packet_id << 16) | socket->producer,
		.len = length,
		.packet_id = packet_id,
		.contd = contd,
		.valid = true,
		.action = action,
	};
}

static int fake_scan_packet(const struct fake_socket *socket,
			    struct fake_packet *packet)
{
	unsigned int cursor = socket->consumer;
	uint64_t length = 0;
	unsigned int nr_descs = 0;
	unsigned int packet_id;
	enum fake_policy_action action;

	if (cursor == socket->producer)
		return -ENOENT;
	packet_id = socket->tx[cursor].packet_id;
	action = socket->tx[cursor].action;
	while (cursor < socket->producer) {
		const struct fake_tx_desc *desc = &socket->tx[cursor++];

		if (desc->packet_id != packet_id || desc->action != action ||
		    UINT64_MAX - length < desc->len)
			return -EINVAL;
		length += desc->len;
		nr_descs++;
		if (!desc->contd) {
			packet->descs = &socket->tx[socket->consumer];
			packet->length = length;
			packet->nr_descs = nr_descs;
			packet->packet_id = packet_id;
			packet->action = action;
			return 0;
		}
	}
	return -EAGAIN;
}

static int fake_policy_dispatch(struct fake_pool *pool,
				const struct fake_packet *packet)
{
	pool->dispatches++;
	return packet->action;
}

static int fake_admit_packet(struct fake_pool *pool, struct fake_socket *socket,
			     const struct fake_packet *packet,
			     struct fake_native_desc *native,
			     unsigned int native_capacity,
			     unsigned int *nr_native)
{
	struct fake_record_meta *meta;
	uint64_t sequence;
	unsigned int i;
	int action;
	int error;

	if (packet->action == FAKE_POLICY_NATIVE &&
	    packet->nr_descs > native_capacity - *nr_native)
		return -ENOSPC;
	error = xsk_xdev_ext_core_reserve(&pool->journal, packet->nr_descs,
				     packet->length, &sequence);
	if (error)
		return error;

	meta = &pool->meta[sequence & pool->journal.mask];
	if (meta->live)
		return -EPROTO;
	*meta = (struct fake_record_meta) {
		.sequence = sequence,
		.socket_id = socket->id,
		.packet_id = packet->packet_id,
		.live = true,
	};

	action = fake_policy_dispatch(pool, packet);
	if (action == FAKE_POLICY_TERMINAL) {
		error = xsk_xdev_ext_core_set_ready(&pool->journal, sequence,
					       -EPERM, 0);
	} else {
		meta->token_live = true;
		error = xsk_xdev_ext_core_set_native(&pool->journal, sequence);
		if (!error) {
			for (i = 0; i < packet->nr_descs; i++) {
				struct fake_native_desc *out = &native[(*nr_native)++];

				*out = (struct fake_native_desc) {
					.sequence = sequence,
					.socket_id = socket->id,
					.packet_id = packet->packet_id,
					.segment = i,
					.len = packet->descs[i].len,
				};
			}
		}
	}
	if (error)
		return error;
	socket->consumer += packet->nr_descs;
	return 0;
}

static int fake_policy_complete(struct fake_pool *pool,
				const struct xsk_xdev_ext_record_core *record,
				struct fake_record_meta *meta)
{
	struct fake_callback_event *event;

	if (!meta->live || meta->sequence != record->sequence ||
	    meta->callback_count)
		return -EALREADY;
	if (pool->nr_callbacks == FAKE_MAX_EVENTS)
		return -ENOSPC;

	meta->callback_count++;
	event = &pool->callbacks[pool->nr_callbacks++];
	*event = (struct fake_callback_event) {
		.sequence = record->sequence,
		.bytes_done = record->bytes_done,
		.socket_id = meta->socket_id,
		.packet_id = meta->packet_id,
		.step = ++pool->clock,
		.result = record->result,
	};
	return 0;
}

static int fake_drain(struct fake_pool *pool)
{
	int drained = 0;

	while (xsk_xdev_ext_core_ready(&pool->journal)) {
		const struct xsk_xdev_ext_record_core *record;
		struct fake_record_meta *meta;
		uint64_t sequence;
		unsigned int socket_id;
		unsigned int packet_id;
		int nr_cq;
		int error;

		record = xsk_xdev_ext_core_front(&pool->journal);
		sequence = record->sequence;
		meta = &pool->meta[sequence & pool->journal.mask];
		socket_id = meta->socket_id;
		packet_id = meta->packet_id;
		if (meta->token_live) {
			error = fake_policy_complete(pool, record, meta);
			if (error)
				return error;
		}
		nr_cq = xsk_xdev_ext_core_pop(&pool->journal);
		if (nr_cq < 0)
			return nr_cq;
		if ((unsigned int)nr_cq > FAKE_MAX_DESCS - pool->nr_cq)
			return -ENOSPC;
		while (nr_cq--) {
			pool->cq[pool->nr_cq++] = (struct fake_cq_entry) {
				.sequence = sequence,
				.socket_id = socket_id,
				.packet_id = packet_id,
				.step = ++pool->clock,
			};
		}
		meta->live = false;
		drained++;
	}
	return drained;
}

static int fake_single_peek(struct fake_pool *pool, struct fake_socket *socket,
			    struct fake_native_desc *native)
{
	struct fake_packet packet;
	unsigned int nr_native = 0;
	int error;

	if (socket->consumer == socket->producer)
		return -ENOENT;
	if (socket->discard_until_eop || socket->tx[socket->consumer].contd) {
		socket->discard_until_eop = true;
		while (socket->consumer < socket->producer) {
			const struct fake_tx_desc *desc =
				&socket->tx[socket->consumer++];

			if (!desc->contd) {
				socket->discard_until_eop = false;
				break;
			}
		}
		return 0;
	}
	error = fake_scan_packet(socket, &packet);
	if (error)
		return error;
	if (packet.nr_descs != 1)
		return -EMSGSIZE;
	error = fake_admit_packet(pool, socket, &packet, native, 1, &nr_native);
	if (error)
		return error;
	return (int)nr_native;
}

static unsigned int
fake_discard_overlimit_batch(struct fake_socket *socket,
			     unsigned int work_budget)
{
	unsigned int available = socket->producer - socket->consumer;
	unsigned int discarded = 0;
	unsigned int i;

	if (!work_budget)
		return 0;
	if (!socket->discard_until_eop) {
		if (available < FAKE_ZC_MAX_SEGS)
			return 0;
		for (i = 0; i < FAKE_ZC_MAX_SEGS; i++)
			if (!socket->tx[socket->consumer + i].contd)
				return 0;
		socket->discard_until_eop = true;
	}

	while (discarded < work_budget &&
	       socket->consumer < socket->producer) {
		const struct fake_tx_desc *desc =
			&socket->tx[socket->consumer++];

		discarded++;
		if (!desc->contd) {
			socket->discard_until_eop = false;
			break;
		}
	}
	return discarded;
}

static unsigned int fake_copy_xmit_bounded(struct fake_pool *pool,
					   struct fake_socket *socket,
					   unsigned int budget)
{
	unsigned int consumed = 0;

	while (consumed < budget && socket->consumer < socket->producer) {
		const struct fake_tx_desc *desc =
			&socket->tx[socket->consumer++];

		consumed++;
		if (socket->discard_until_eop) {
			if (!desc->contd)
				socket->discard_until_eop = false;
			continue;
		}
		if (!desc->valid) {
			socket->discard_until_eop = desc->contd;
			continue;
		}
		if (!desc->contd)
			pool->dispatches++;
	}
	return consumed;
}

static int fake_batch_peek(struct fake_pool *pool, struct fake_socket **sockets,
			   unsigned int nr_sockets,
			   struct fake_native_desc *native,
			   unsigned int native_capacity)
{
	unsigned int nr_native = 0;
	unsigned int idle = 0;

	if (!nr_sockets)
		return -EINVAL;
	while (idle < nr_sockets) {
		struct fake_socket *socket = sockets[pool->rr_next];
		struct fake_packet packet;
		int error;

		pool->rr_next = (pool->rr_next + 1) % nr_sockets;
		error = fake_scan_packet(socket, &packet);
		if (error == -ENOENT || error == -EAGAIN) {
			idle++;
			continue;
		}
		if (error)
			return error;
		if (packet.action == FAKE_POLICY_NATIVE &&
		    packet.nr_descs > native_capacity - nr_native) {
			idle++;
			continue;
		}
		error = fake_admit_packet(pool, socket, &packet, native,
					  native_capacity, &nr_native);
		if (error)
			return error;
		idle = 0;
	}
	return (int)nr_native;
}

static int fake_driver_complete(struct fake_pool *pool, unsigned int nr_descs)
{
	int error;

	error = xsk_xdev_ext_core_complete_descs(&pool->journal, nr_descs);
	if (error)
		return error;
	error = fake_drain(pool);
	return error < 0 ? error : 0;
}

static int fake_driver_cancel_tail(struct fake_pool *pool,
				   unsigned int nr_descs, int result)
{
	int error;

	error = xsk_xdev_ext_core_cancel_native_tail(&pool->journal, nr_descs,
						result);
	if (error)
		return error;
	error = fake_drain(pool);
	return error < 0 ? error : 0;
}

static int fake_driver_mark_tail_error(struct fake_pool *pool,
				       unsigned int nr_descs, int result)
{
	return xsk_xdev_ext_core_set_native_tail_result(&pool->journal, nr_descs,
						   result);
}

static int fake_teardown(struct fake_pool *pool, int *nr_canceled)
{
	int canceled;
	int error;

	canceled = xsk_xdev_ext_core_stop(&pool->journal, -ECANCELED);
	if (canceled < 0)
		return canceled;
	error = fake_drain(pool);
	if (error < 0)
		return error;
	*nr_canceled = canceled;
	return 0;
}

static unsigned int fake_packet_callback_count(const struct fake_pool *pool,
					       unsigned int packet_id)
{
	unsigned int count = 0;
	unsigned int i;

	for (i = 0; i < pool->nr_callbacks; i++)
		if (pool->callbacks[i].packet_id == packet_id)
			count++;
	return count;
}

static void test_single_peek_delays_cq_until_retirement(void)
{
	const uint32_t lengths[] = { 128 };
	struct fake_native_desc native = {};
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 1);
	fake_push_packet(&socket, 10, lengths, 1, FAKE_POLICY_NATIVE);

	EXPECT_EQ(fake_single_peek(&pool, &socket, &native), 1);
	EXPECT_EQ(native.packet_id, 10);
	EXPECT_EQ(pool.dispatches, 1);
	EXPECT_EQ(pool.journal.native_descs_pending, 1);
	EXPECT_EQ(fake_drain(&pool), 0);
	EXPECT_EQ(pool.nr_callbacks, 0);
	EXPECT_EQ(pool.nr_cq, 0);

	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 1);
	EXPECT_EQ(pool.callbacks[0].packet_id, 10);
	EXPECT_EQ(pool.callbacks[0].result, 0);
	EXPECT_EQ(pool.callbacks[0].bytes_done, 128);
	EXPECT_EQ(pool.nr_cq, 1);
	EXPECT_EQ(pool.callbacks[0].step < pool.cq[0].step, true);
}

static void test_single_peek_discards_split_overlimit_per_socket(void)
{
	const uint32_t valid[] = { 128 };
	struct fake_native_desc native = {};
	struct fake_socket first;
	struct fake_socket second;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&first, 20);
	fake_socket_init(&second, 21);

	/* The first socket exposes only the over-limit packet's prefix. */
	fake_push_desc(&first, 80, 64, true, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_single_peek(&pool, &first, &native), 0);
	EXPECT_EQ(first.consumer, 1);
	EXPECT_EQ(pool.dispatches, 0);
	EXPECT_EQ(pool.journal.tail, 0);

	/* Its discard state must not suppress another shared-UMEM socket. */
	fake_push_packet(&second, 81, valid, 1, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_single_peek(&pool, &second, &native), 1);
	EXPECT_EQ(native.packet_id, 81);
	EXPECT_EQ(pool.dispatches, 1);
	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);

	/* The later EOP is the same invalid packet, never a new operation. */
	fake_push_desc(&first, 80, 96, false, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_single_peek(&pool, &first, &native), 0);
	EXPECT_EQ(first.consumer, 2);
	EXPECT_EQ(pool.dispatches, 1);
	EXPECT_EQ(pool.journal.head, pool.journal.tail);
}

static void test_batch_overlimit_tail_is_discarded_with_bounded_work(void)
{
	const uint32_t oversized[] = { 1, 2, 3, 4, 5, 6, 7 };
	const uint32_t valid[] = { 128 };
	struct fake_native_desc native[1] = {};
	struct fake_socket *sockets[1];
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 22);
	sockets[0] = &socket;
	fake_push_packet(&socket, 82, oversized,
			 ARRAY_SIZE(oversized),
			 FAKE_POLICY_NATIVE);

	EXPECT_EQ(fake_discard_overlimit_batch(&socket, 2), 2);
	EXPECT_EQ(socket.consumer, 2);
	EXPECT_EQ(socket.discard_until_eop, true);
	EXPECT_EQ(fake_discard_overlimit_batch(&socket, 2), 2);
	EXPECT_EQ(socket.consumer, 4);
	EXPECT_EQ(socket.discard_until_eop, true);
	EXPECT_EQ(fake_discard_overlimit_batch(&socket, 2), 2);
	EXPECT_EQ(socket.consumer, 6);
	EXPECT_EQ(socket.discard_until_eop, true);
	EXPECT_EQ(fake_discard_overlimit_batch(&socket, 2), 1);
	EXPECT_EQ(socket.consumer, 7);
	EXPECT_EQ(socket.discard_until_eop, false);
	EXPECT_EQ(pool.dispatches, 0);
	EXPECT_EQ(pool.journal.tail, 0);

	/* The packet after EOP is the first unit eligible for policy dispatch. */
	fake_push_packet(&socket, 83, valid, 1, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_batch_peek(&pool, sockets, 1, native, 1), 1);
	EXPECT_EQ(native[0].packet_id, 83);
	EXPECT_EQ(pool.dispatches, 1);
}

static void test_copy_invalid_contd_never_redispatches_its_tail(void)
{
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 23);
	fake_push_desc(&socket, 84, 64, true, FAKE_POLICY_NATIVE);
	fake_push_desc(&socket, 84, 96, false, FAKE_POLICY_NATIVE);
	fake_push_desc(&socket, 85, 128, false, FAKE_POLICY_NATIVE);
	socket.tx[0].valid = false;

	EXPECT_EQ(fake_copy_xmit_bounded(&pool, &socket, 2), 2);
	EXPECT_EQ(socket.consumer, 2);
	EXPECT_EQ(socket.discard_until_eop, false);
	EXPECT_EQ(pool.dispatches, 0);
	EXPECT_EQ(fake_copy_xmit_bounded(&pool, &socket, 1), 1);
	EXPECT_EQ(socket.consumer, 3);
	EXPECT_EQ(pool.dispatches, 1);
}

static void test_batch_is_dense_around_terminal_fifo_hole(void)
{
	const uint32_t first[] = { 64 };
	const uint32_t terminal[] = { 96 };
	const uint32_t last[] = { 128 };
	struct fake_native_desc native[4] = {};
	struct fake_socket *sockets[1];
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 2);
	sockets[0] = &socket;
	fake_push_packet(&socket, 20, first, 1, FAKE_POLICY_NATIVE);
	fake_push_packet(&socket, 21, terminal, 1, FAKE_POLICY_TERMINAL);
	fake_push_packet(&socket, 22, last, 1, FAKE_POLICY_NATIVE);

	EXPECT_EQ(fake_batch_peek(&pool, sockets, 1, native, 4), 2);
	EXPECT_EQ(pool.dispatches, 3);
	EXPECT_EQ(native[0].packet_id, 20);
	EXPECT_EQ(native[1].packet_id, 22);
	EXPECT_EQ(pool.nr_callbacks, 0);
	EXPECT_EQ(pool.nr_cq, 0);

	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 1);
	EXPECT_EQ(pool.callbacks[0].packet_id, 20);
	EXPECT_EQ(pool.callbacks[0].result, 0);
	EXPECT_EQ(fake_packet_callback_count(&pool, 21), 0);
	EXPECT_EQ(pool.nr_cq, 2);
	EXPECT_EQ(pool.cq[0].packet_id, 20);
	EXPECT_EQ(pool.cq[1].packet_id, 21);

	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 2);
	EXPECT_EQ(pool.callbacks[1].packet_id, 22);
	EXPECT_EQ(pool.nr_cq, 3);
}

static void test_multibuffer_retires_only_as_a_whole_packet(void)
{
	const uint32_t lengths[] = { 100, 200, 300 };
	struct fake_native_desc native[3] = {};
	struct fake_socket *sockets[1];
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 3);
	sockets[0] = &socket;
	fake_push_packet(&socket, 30, lengths, 3, FAKE_POLICY_NATIVE);

	EXPECT_EQ(fake_batch_peek(&pool, sockets, 1, native, 3), 3);
	EXPECT_EQ(native[0].sequence, native[1].sequence);
	EXPECT_EQ(native[1].sequence, native[2].sequence);
	EXPECT_EQ(native[0].segment, 0);
	EXPECT_EQ(native[1].segment, 1);
	EXPECT_EQ(native[2].segment, 2);
	EXPECT_EQ(fake_driver_complete(&pool, 2), 0);
	EXPECT_EQ(pool.nr_callbacks, 0);
	EXPECT_EQ(pool.nr_cq, 0);
	EXPECT_EQ(xsk_xdev_ext_core_front_any(&pool.journal)->retired, 2);

	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 1);
	EXPECT_EQ(pool.callbacks[0].packet_id, 30);
	EXPECT_EQ(pool.callbacks[0].bytes_done, 600);
	EXPECT_EQ(pool.nr_cq, 3);
	EXPECT_EQ(pool.cq[0].packet_id, 30);
	EXPECT_EQ(pool.cq[1].packet_id, 30);
	EXPECT_EQ(pool.cq[2].packet_id, 30);
	EXPECT_EQ(pool.callbacks[0].step < pool.cq[0].step, true);
}

static void test_shared_umem_batch_is_fair_and_packet_contiguous(void)
{
	const uint32_t two_segments[] = { 64, 96 };
	const uint32_t one_segment[] = { 128 };
	struct fake_native_desc native[6] = {};
	struct fake_socket *sockets[2];
	struct fake_socket first;
	struct fake_socket second;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&first, 10);
	fake_socket_init(&second, 11);
	sockets[0] = &first;
	sockets[1] = &second;
	fake_push_packet(&first, 40, two_segments, 2, FAKE_POLICY_NATIVE);
	fake_push_packet(&first, 42, one_segment, 1, FAKE_POLICY_NATIVE);
	fake_push_packet(&second, 41, two_segments, 2, FAKE_POLICY_NATIVE);
	fake_push_packet(&second, 43, one_segment, 1, FAKE_POLICY_NATIVE);

	EXPECT_EQ(fake_batch_peek(&pool, sockets, 2, native, 6), 6);
	EXPECT_EQ(native[0].packet_id, 40);
	EXPECT_EQ(native[1].packet_id, 40);
	EXPECT_EQ(native[2].packet_id, 41);
	EXPECT_EQ(native[3].packet_id, 41);
	EXPECT_EQ(native[4].packet_id, 42);
	EXPECT_EQ(native[5].packet_id, 43);
	EXPECT_EQ(native[0].socket_id, 10);
	EXPECT_EQ(native[2].socket_id, 11);
	EXPECT_EQ(native[4].socket_id, 10);
	EXPECT_EQ(native[5].socket_id, 11);
	EXPECT_EQ(native[0].sequence, native[1].sequence);
	EXPECT_EQ(native[2].sequence, native[3].sequence);
	EXPECT_EQ(native[1].sequence != native[2].sequence, true);

	EXPECT_EQ(fake_driver_complete(&pool, 6), 0);
	EXPECT_EQ(pool.nr_callbacks, 4);
	EXPECT_EQ(pool.callbacks[0].packet_id, 40);
	EXPECT_EQ(pool.callbacks[1].packet_id, 41);
	EXPECT_EQ(pool.callbacks[2].packet_id, 42);
	EXPECT_EQ(pool.callbacks[3].packet_id, 43);
	EXPECT_EQ(pool.nr_cq, 6);
}

static void test_driver_tail_cancel_preserves_fifo(void)
{
	const uint32_t first[] = { 64 };
	const uint32_t rejected[] = { 80, 96 };
	struct fake_native_desc native[3] = {};
	struct fake_socket *sockets[1];
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 4);
	sockets[0] = &socket;
	fake_push_packet(&socket, 50, first, 1, FAKE_POLICY_NATIVE);
	fake_push_packet(&socket, 51, rejected, 2, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_batch_peek(&pool, sockets, 1, native, 3), 3);

	EXPECT_EQ(fake_driver_cancel_tail(&pool, 2, -EIO), 0);
	EXPECT_EQ(pool.journal.native_descs_pending, 1);
	EXPECT_EQ(pool.nr_callbacks, 0);
	EXPECT_EQ(pool.nr_cq, 0);
	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 2);
	EXPECT_EQ(pool.callbacks[0].packet_id, 50);
	EXPECT_EQ(pool.callbacks[0].result, 0);
	EXPECT_EQ(pool.callbacks[1].packet_id, 51);
	EXPECT_EQ(pool.callbacks[1].result, -EIO);
	EXPECT_EQ(pool.callbacks[1].bytes_done, 0);
	EXPECT_EQ(pool.nr_cq, 3);
	EXPECT_EQ(fake_driver_complete(&pool, 1), -EOVERFLOW);
}

static void test_mlx_error_marker_waits_for_retirement(void)
{
	const uint32_t first[] = { 64 };
	const uint32_t failed[] = { 9000 };
	struct fake_native_desc native[2] = {};
	struct fake_socket *sockets[1];
	struct fake_socket socket;
	struct fake_pool pool;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 5);
	sockets[0] = &socket;
	fake_push_packet(&socket, 60, first, 1, FAKE_POLICY_NATIVE);
	fake_push_packet(&socket, 61, failed, 1, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_batch_peek(&pool, sockets, 1, native, 2), 2);

	EXPECT_EQ(fake_driver_mark_tail_error(&pool, 1, -EMSGSIZE), 0);
	EXPECT_EQ(pool.journal.native_descs_pending, 2);
	EXPECT_EQ(pool.nr_callbacks, 0);
	EXPECT_EQ(pool.nr_cq, 0);
	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 1);
	EXPECT_EQ(pool.callbacks[0].packet_id, 60);
	EXPECT_EQ(pool.callbacks[0].result, 0);
	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 2);
	EXPECT_EQ(pool.callbacks[1].packet_id, 61);
	EXPECT_EQ(pool.callbacks[1].result, -EMSGSIZE);
	EXPECT_EQ(pool.callbacks[1].bytes_done, 0);
	EXPECT_EQ(pool.nr_cq, 2);
}

static void test_teardown_cancels_pending_and_completes_exactly_once(void)
{
	const uint32_t partial[] = { 64, 64 };
	const uint32_t terminal[] = { 32 };
	const uint32_t pending[] = { 128 };
	struct fake_native_desc native[3] = {};
	struct fake_socket *sockets[1];
	struct fake_socket socket;
	struct fake_pool pool;
	unsigned int callbacks;
	unsigned int cq_entries;
	int canceled = -1;

	fake_pool_init(&pool);
	fake_socket_init(&socket, 6);
	sockets[0] = &socket;
	fake_push_packet(&socket, 70, partial, 2, FAKE_POLICY_NATIVE);
	fake_push_packet(&socket, 71, terminal, 1, FAKE_POLICY_TERMINAL);
	fake_push_packet(&socket, 72, pending, 1, FAKE_POLICY_NATIVE);
	EXPECT_EQ(fake_batch_peek(&pool, sockets, 1, native, 3), 3);
	EXPECT_EQ(fake_driver_complete(&pool, 1), 0);
	EXPECT_EQ(pool.nr_callbacks, 0);
	EXPECT_EQ(pool.nr_cq, 0);

	EXPECT_EQ(fake_teardown(&pool, &canceled), 0);
	EXPECT_EQ(canceled, 2);
	EXPECT_EQ(pool.nr_callbacks, 2);
	EXPECT_EQ(pool.callbacks[0].packet_id, 70);
	EXPECT_EQ(pool.callbacks[0].result, -ECANCELED);
	EXPECT_EQ(pool.callbacks[0].bytes_done, 0);
	EXPECT_EQ(pool.callbacks[1].packet_id, 72);
	EXPECT_EQ(pool.callbacks[1].result, -ECANCELED);
	EXPECT_EQ(pool.nr_cq, 4);
	EXPECT_EQ(fake_packet_callback_count(&pool, 70), 1);
	EXPECT_EQ(fake_packet_callback_count(&pool, 71), 0);
	EXPECT_EQ(fake_packet_callback_count(&pool, 72), 1);

	callbacks = pool.nr_callbacks;
	cq_entries = pool.nr_cq;
	EXPECT_EQ(fake_teardown(&pool, &canceled), 0);
	EXPECT_EQ(canceled, 0);
	EXPECT_EQ(pool.nr_callbacks, callbacks);
	EXPECT_EQ(pool.nr_cq, cq_entries);
	EXPECT_EQ(fake_driver_complete(&pool, 1), -EOVERFLOW);
	EXPECT_EQ(pool.nr_callbacks, callbacks);
	EXPECT_EQ(pool.nr_cq, cq_entries);
}

int main(void)
{
	test_single_peek_delays_cq_until_retirement();
	test_single_peek_discards_split_overlimit_per_socket();
	test_batch_overlimit_tail_is_discarded_with_bounded_work();
	test_copy_invalid_contd_never_redispatches_its_tail();
	test_batch_is_dense_around_terminal_fifo_hole();
	test_multibuffer_retires_only_as_a_whole_packet();
	test_shared_umem_batch_is_fair_and_packet_contiguous();
	test_driver_tail_cancel_preserves_fifo();
	test_mlx_error_marker_waits_for_retirement();
	test_teardown_cancels_pending_and_completes_exactly_once();

	if (tests_failed) {
		fprintf(stderr, "FAIL: %u of %u checks failed\n",
			tests_failed, tests_run);
		return 1;
	}
	printf("PASS: %u checks\n", tests_run);
	return 0;
}
