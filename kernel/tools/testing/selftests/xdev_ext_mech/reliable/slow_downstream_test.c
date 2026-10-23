// SPDX-License-Identifier: GPL-2.0
/* Executes the production reliable state helpers for a slow receiver chain.
 *
 * A receiver whose NVMe/CE stage is still running holds every segment of a
 * group (SUBMITTED). Retransmissions of that group must neither reach the
 * device chain again nor consume the sender's loss budget: the receiver
 * answers HELD, which restores the budget without completing the group or
 * raising credit. Only the final chain completion produces the ACK.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"

#ifndef RELIABLE_HEADER
#define RELIABLE_HEADER "include/linux/xdev_ext_mech_reliable_core.h"
#endif
#include RELIABLE_HEADER

#ifdef XDEV_EXT_REL_HELD
#define HAVE_HELD 1
#else
#define HAVE_HELD 0
#endif

static unsigned checks, failures;
#define EXPECT_EQ(expr, expected) do { \
    long long actual_ = (long long)(expr); \
    long long expected_ = (long long)(expected); \
    checks++; \
    if (actual_ != expected_) { \
        fprintf(stderr, "FAIL %s:%d %s: %lld != %lld\n", \
                __func__, __LINE__, #expr, actual_, expected_); \
        failures++; \
    } \
} while (0)
#define REQUIRE_HELD() do { \
    if (!HAVE_HELD) { \
        checks++; failures++; \
        fprintf(stderr, "FAIL %s: receiver has no HELD reply for a SUBMITTED group\n", __func__); \
        return; \
    } \
} while (0)

static const struct xdev_ext_rel_cfg config = {
    .session = 270019, .first_group = 1, .timeout_ns = 100,
    .window = 4, .max_attempts = 3, .group_bytes = 8192, .seg_len = 1408,
};

static struct xdev_ext_rel_msg data_msg(__u64 group, __u16 index, __u32 attempt)
{
    struct xdev_ext_rel_msg m = {
        .session = config.session, .group = group, .attempt = attempt,
        .type = XDEV_EXT_REL_DATA, .total_len = 8192, .index = index, .count = 6,
        .relative_offset = (__u32)index * 1408,
        .payload_len = index == 5 ? 1152 : 1408,
    };
    return m;
}

static struct xdev_ext_rel_msg control_msg(__u8 type, __u64 group, __u32 attempt, __u64 credit)
{
    struct xdev_ext_rel_msg m = {
        .session = config.session, .group = group, .attempt = attempt,
        .type = type, .credit = credit,
    };
    return m;
}

/* Deliver one attempt of group @g to the receiver; returns device submits. */
static unsigned deliver(struct xdev_ext_rel_rx *rx, __u64 g, __u32 attempt, int *last)
{
    unsigned i, submits = 0;

    for (i = 0; i < 6; i++) {
        struct xdev_ext_rel_msg m = data_msg(g, i, attempt);
        int action = xdev_ext_rel_rx_inspect(rx, &m);

        if (action == XDEV_EXT_REL_HOLD) {
            action = xdev_ext_rel_rx_commit(rx, &m);
            submits += action == XDEV_EXT_REL_SUBMIT;
        }
        *last = action;
    }
    return submits;
}

static void slow_chain_beyond_budget_completes_exactly_once(void)
{
    struct xdev_ext_rel_tx tx;
    struct xdev_ext_rel_rx rx;
    struct xdev_ext_rel_msg ack;
    unsigned attempt, submits = 0;
    __u64 credit;
    int last = 0;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 0), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, 1, 0, false, 0), XDEV_EXT_REL_NONE);
    submits += deliver(&rx, 1, 1, &last);
    EXPECT_EQ(submits, 1);
    credit = tx.credit;
    /* The downstream stage stays busy for 3x the old loss budget. */
    for (attempt = 2; attempt <= 3 * config.max_attempts + 1; attempt++) {
        __u64 now = (__u64)(attempt - 1) * 100;

        EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, now), XDEV_EXT_REL_SEND);
        if (tx.entry[1].terminal)
            return;
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, now), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, attempt, 0, false, now), XDEV_EXT_REL_NONE);
        submits += deliver(&rx, 1, attempt, &last);
#if HAVE_HELD
        EXPECT_EQ(last, XDEV_EXT_REL_REPLAY_HELD);
        ack = control_msg(XDEV_EXT_REL_HELD, 1, attempt, rx.credit);
        EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_NONE);
#endif
        EXPECT_EQ(tx.credit, credit);
        EXPECT_EQ(tx.entry[1].acked, 0);
        EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
    }
    EXPECT_EQ(submits, 1);
    REQUIRE_HELD();
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 1, 0), XDEV_EXT_REL_REPLAY_ACK);
    ack = control_msg(XDEV_EXT_REL_ACK, 1, attempt - 1, rx.credit);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
#if HAVE_HELD
    EXPECT_EQ(tx.retransmits, 3 * config.max_attempts);
    EXPECT_EQ(tx.held_acks, 3 * config.max_attempts);
#endif
}

static void silent_receiver_still_exhausts_budget(void)
{
    REQUIRE_HELD();
#if HAVE_HELD
    struct xdev_ext_rel_tx tx;
    unsigned attempt;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    /* Attempt 2 is reported HELD, then the receiver goes silent: exactly
     * max_attempts further unanswered attempts end in UNKNOWN. */
    for (attempt = 1; attempt <= 2 + config.max_attempts; attempt++) {
        __u64 now = (__u64)attempt * 1000;

        if (attempt > 1)
            EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, now), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, now), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, attempt, 0, false, now), XDEV_EXT_REL_NONE);
        if (attempt == 2) {
            struct xdev_ext_rel_msg held = control_msg(XDEV_EXT_REL_HELD, 1, 2, 5);
            EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &held), XDEV_EXT_REL_NONE);
        }
    }
    EXPECT_EQ(tx.entry[1].attempt, 2 + config.max_attempts);
    EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, UINT64_MAX), XDEV_EXT_REL_UNKNOWN);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, UINT64_MAX), XDEV_EXT_REL_BAD);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
#endif
}

static void held_never_completes_credits_or_confirms_future(void)
{
    REQUIRE_HELD();
#if HAVE_HELD
    struct xdev_ext_rel_tx tx, before;
    struct xdev_ext_rel_msg m;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 0), XDEV_EXT_REL_SEND);
    before = tx;
    /* A future attempt cannot have been seen by the receiver. */
    m = control_msg(XDEV_EXT_REL_HELD, 1, 2, 5);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_BAD);
    EXPECT_EQ(memcmp(&tx, &before, sizeof(tx)), 0);
    /* HELD carries no data fields. */
    m = control_msg(XDEV_EXT_REL_HELD, 1, 1, 5);
    m.count = 6;
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_BAD);
    EXPECT_EQ(memcmp(&tx, &before, sizeof(tx)), 0);
    m = control_msg(XDEV_EXT_REL_HELD, 2, 1, 5);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_STALE);
    EXPECT_EQ(memcmp(&tx, &before, sizeof(tx)), 0);
    /* A valid, larger credit in HELD is ignored, even while native is pending. */
    m = control_msg(XDEV_EXT_REL_HELD, 1, 1, 6);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_NONE);
    EXPECT_EQ(tx.credit, 5);
    EXPECT_EQ(tx.entry[1].acked, 0);
    EXPECT_EQ(tx.entry[1].held_attempt, 1);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_STALE);
    EXPECT_EQ(tx.held_acks, 1);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, 1, 0, false, 10), XDEV_EXT_REL_NONE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
    EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, 110), XDEV_EXT_REL_SEND);
#endif
}

static void receiver_replies_held_only_while_submitted(void)
{
    struct xdev_ext_rel_rx rx;
    struct xdev_ext_rel_msg m;
    int last = 0;

    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    EXPECT_EQ(deliver(&rx, 1, 1, &last), 1);
    m = data_msg(1, 3, 2);
#if HAVE_HELD
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_REPLAY_HELD);
    xdev_ext_rel_rx_reply(&rx, 1, XDEV_EXT_REL_REPLAY_HELD);
    EXPECT_EQ(xdev_ext_rel_rx_reply_type(&rx, 1), XDEV_EXT_REL_HELD);
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 1, 0), XDEV_EXT_REL_REPLAY_ACK);
    /* Completion supersedes a still-pending HELD for the same slot. */
    EXPECT_EQ(xdev_ext_rel_rx_reply_type(&rx, 1), XDEV_EXT_REL_ACK);
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_REPLAY_ACK);
#else
    REQUIRE_HELD();
#endif
    /* A failed chain is never reported HELD or ACKed. */
    EXPECT_EQ(deliver(&rx, 2, 1, &last), 1);
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 2, -EIO), XDEV_EXT_REL_NONE);
    m = data_msg(2, 0, 2);
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_RECYCLE);
#if HAVE_HELD
    xdev_ext_rel_rx_reply(&rx, 2, XDEV_EXT_REL_REPLAY_HELD);
    EXPECT_EQ(xdev_ext_rel_rx_reply_type(&rx, 2), XDEV_EXT_REL_ACK);
#endif
}

static void held_wire_identity(void)
{
    REQUIRE_HELD();
#if HAVE_HELD
    struct xdev_ext_rel_msg m = control_msg(XDEV_EXT_REL_HELD, 7, 3, 9), got;
    __u8 hdr[64];

    EXPECT_EQ(xdev_ext_rel_wire_encode(hdr, &m), 0);
    EXPECT_EQ(hdr[4], 3);
    EXPECT_EQ(hdr[6], 3);
    hdr[56] = hdr[57] = hdr[58] = hdr[59] = 0xff;
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, 0, 0, &config, &got), 0);
    EXPECT_EQ(got.type, XDEV_EXT_REL_HELD);
    EXPECT_EQ(got.credit, 9);
    m.payload_len = 1;
    EXPECT_EQ(xdev_ext_rel_wire_encode(hdr, &m), -EINVAL);
    m = control_msg(4, 7, 3, 9);
    EXPECT_EQ(xdev_ext_rel_wire_encode(hdr, &m), -EINVAL);
#endif
}

int main(void)
{
    slow_chain_beyond_budget_completes_exactly_once();
    silent_receiver_still_exhausts_budget();
    held_never_completes_credits_or_confirms_future();
    receiver_replies_held_only_while_submitted();
    held_wire_identity();
    printf("reliable slow downstream: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
