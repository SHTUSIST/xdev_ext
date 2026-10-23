// SPDX-License-Identifier: GPL-2.0
/* Executes production state helpers. No reliability implementation lives here. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_core.h"

#ifndef RELIABLE_HEADER
#define RELIABLE_HEADER "include/linux/xdev_ext_mech_reliable_core.h"
#endif

#if __has_include(RELIABLE_HEADER)
#include RELIABLE_HEADER
#define HAVE_RELIABLE 1
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

static void existing_group_admission(void)
{
    struct xdev_ext_mech_group group;

    xdev_ext_mech_group_init(&group, 1, 3);
    EXPECT_EQ(xdev_ext_mech_group_add(&group, 1, 2, 3), 0);
    EXPECT_EQ(xdev_ext_mech_group_full(&group), false);
    EXPECT_EQ(xdev_ext_mech_group_add(&group, 1, 0, 3), 0);
    EXPECT_EQ(xdev_ext_mech_group_add(&group, 1, 2, 3), -EEXIST);
    EXPECT_EQ(xdev_ext_mech_group_add(&group, 1, 1, 3), 0);
    EXPECT_EQ(xdev_ext_mech_group_full(&group), true);
}

#ifdef HAVE_RELIABLE
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

static struct xdev_ext_rel_msg ack_msg(__u64 group, __u64 credit)
{
    struct xdev_ext_rel_msg m = {
        .session = config.session, .group = group, .attempt = 1,
        .type = XDEV_EXT_REL_ACK, .credit = credit,
    };
    return m;
}

static void local_tx_is_not_chain_ack(void)
{
    struct xdev_ext_rel_tx tx;
    struct xdev_ext_rel_msg ack = ack_msg(1, 6);

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 1), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, 1, 0, false, 10), XDEV_EXT_REL_NONE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
    EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, 109), XDEV_EXT_REL_NONE);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
    EXPECT_EQ(tx.base_group, 2);
    EXPECT_EQ(tx.credit, 6);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_STALE);
    EXPECT_EQ(tx.credit, 6);
}

static void ack_before_native_completion_pins_frames(void)
{
    struct xdev_ext_rel_tx tx;
    struct xdev_ext_rel_msg ack = ack_msg(1, 6);

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 1), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_NONE);
    EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, 1000000), XDEV_EXT_REL_NONE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, 1, 0, false, 10), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
}

static void retry_budget_and_stale_completions(void)
{
    struct xdev_ext_rel_tx tx;
    unsigned attempt;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    for (attempt = 1; attempt <= config.max_attempts; attempt++) {
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, attempt * 100), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, attempt * 100), XDEV_EXT_REL_BACKPRESSURE);
        EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, UINT64_MAX), XDEV_EXT_REL_NONE);
        if (attempt > 1) {
            EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, attempt - 1, 0, false, 0), XDEV_EXT_REL_STALE);
            EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
        }
        EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, attempt, 0, false, attempt * 100), XDEV_EXT_REL_NONE);
        EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, attempt * 100 + 99), XDEV_EXT_REL_NONE);
        EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, attempt * 100 + 100),
                  attempt < config.max_attempts ? XDEV_EXT_REL_SEND : XDEV_EXT_REL_UNKNOWN);
    }
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
}

static void accepted_native_error_is_unknown(void)
{
    struct xdev_ext_rel_tx tx;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 1), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, 1, -EIO, true, 2), XDEV_EXT_REL_UNKNOWN);
    EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, 1, UINT64_MAX), XDEV_EXT_REL_UNKNOWN);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 3), XDEV_EXT_REL_BAD);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), -EBUSY);
    /* An ambiguity report is not DMA quiescence. A later actual drain
     * proof can release native ownership, but cannot certify delivery. */
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, 1, 1, 0, false, 4), XDEV_EXT_REL_UNKNOWN);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
}

static void credit_never_counts_duplicate_ack_twice(void)
{
    struct xdev_ext_rel_tx tx;
    struct xdev_ext_rel_msg ack;
    unsigned g;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    for (g = 1; g <= 4; g++) {
        EXPECT_EQ(xdev_ext_rel_tx_open(&tx, g, 8192, 6), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, g, 0), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, g, 1, 0, false, 1), XDEV_EXT_REL_NONE);
    }
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 5, 8192, 6), XDEV_EXT_REL_BACKPRESSURE);
    ack = ack_msg(2, 5);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 2), 0);
    EXPECT_EQ(tx.base_group, 1);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_STALE);
    EXPECT_EQ(tx.credit, 5);
    /* Even a large valid credit cannot overwrite the oldest unacked slot. */
    ack = ack_msg(4, 9);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 4), 0);
    EXPECT_EQ(tx.credit, 9);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 5, 8192, 6), XDEV_EXT_REL_BACKPRESSURE);
    ack = ack_msg(1, 6);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
    EXPECT_EQ(tx.base_group, 3);
    EXPECT_EQ(tx.credit, 9);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 5, 8192, 6), XDEV_EXT_REL_SEND);
}

static void malformed_identity_does_not_mutate(void)
{
    struct xdev_ext_rel_tx tx, before;
    struct xdev_ext_rel_rx rx, rx_before;
    struct xdev_ext_rel_msg m = ack_msg(1, 6);

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 1, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, 1, 0), XDEV_EXT_REL_SEND);
    before = tx;
    m.session++;
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_BAD);
    EXPECT_EQ(memcmp(&tx, &before, sizeof(tx)), 0);
    m = ack_msg(1, UINT64_MAX);
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &m), XDEV_EXT_REL_BAD);
    EXPECT_EQ(memcmp(&tx, &before, sizeof(tx)), 0);
    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    rx_before = rx;
    m = data_msg(1, 0, 1);
    m.count--;
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_BAD);
    EXPECT_EQ(memcmp(&rx, &rx_before, sizeof(rx)), 0);
}

static void oldest_replayed_ack_carries_full_window_progress(void)
{
    struct xdev_ext_rel_tx tx, before;
    struct xdev_ext_rel_rx rx;
    struct xdev_ext_rel_msg m, ack;
    unsigned group, index, downstream_accepted = 0;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    for (group = 1; group <= 4; group++) {
        EXPECT_EQ(xdev_ext_rel_tx_open(&tx, group, 8192, 6), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, group, 0), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, group, 1, 0, false, 1), XDEV_EXT_REL_NONE);
        for (index = 0; index < 6; index++) {
            int action;
            m = data_msg(group, index, 1);
            EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_HOLD);
            action = xdev_ext_rel_rx_commit(&rx, &m);
            EXPECT_EQ(action, index == 5 ? XDEV_EXT_REL_SUBMIT : XDEV_EXT_REL_HOLD);
            downstream_accepted += action == XDEV_EXT_REL_SUBMIT;
        }
        EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, group, 0), XDEV_EXT_REL_REPLAY_ACK);
        /* All original ACKs are lost. */
    }
    EXPECT_EQ(tx.base_group, 1);
    EXPECT_EQ(tx.next_group, 5);
    EXPECT_EQ(rx.base_group, 5);
    EXPECT_EQ(rx.credit, 9);
    EXPECT_EQ(downstream_accepted, 4);

    m = data_msg(1, 0, 2);
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_REPLAY_ACK);
    ack = ack_msg(1, rx.credit);
    ack.attempt = 2;
    /* Actual receiver progress is beyond 1+window+1=6, but no further
     * than sender next_group+window=9. This ACK must recover group 1. */
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(tx.credit, 9);
    EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, 1), 0);
    EXPECT_EQ(tx.base_group, 2);
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 5, 8192, 6), XDEV_EXT_REL_SEND);
    /* Credit alone cannot cross oldest-unacked + window. */
    EXPECT_EQ(xdev_ext_rel_tx_open(&tx, 6, 8192, 6), XDEV_EXT_REL_BACKPRESSURE);

    before = tx;
    ack = ack_msg(2, 11); /* next_group=6, so upper bound is 10. */
    EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_BAD);
    EXPECT_EQ(memcmp(&tx, &before, sizeof(tx)), 0);
}

static void missing_data_retransmit_submits_once(void)
{
    struct xdev_ext_rel_rx rx;
    struct xdev_ext_rel_msg m;
    unsigned i, submits = 0, replays = 0;

    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    /* First attempt loses segment 2 and arrives in reverse order. */
    for (i = 6; i-- > 0;) {
        if (i == 2)
            continue;
        m = data_msg(1, i, 1);
        EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_HOLD);
        EXPECT_EQ(xdev_ext_rel_rx_commit(&rx, &m), XDEV_EXT_REL_HOLD);
    }
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 1, 0), XDEV_EXT_REL_BAD);
    for (i = 0; i < 6; i++) {
        int action;
        m = data_msg(1, i, 2);
        action = xdev_ext_rel_rx_inspect(&rx, &m);
        /* After the missing segment submits, the rest of the attempt is HELD. */
        EXPECT_EQ(action, i == 2 ? XDEV_EXT_REL_HOLD :
                  i < 2 ? XDEV_EXT_REL_RECYCLE : XDEV_EXT_REL_REPLAY_HELD);
        if (action == XDEV_EXT_REL_HOLD) {
            action = xdev_ext_rel_rx_commit(&rx, &m);
            EXPECT_EQ(action, XDEV_EXT_REL_SUBMIT);
            submits += action == XDEV_EXT_REL_SUBMIT;
        }
    }
    /* A full retransmit while devices are pending must not ACK or resubmit;
     * it only reports HELD, which neither completes nor credits. */
    for (i = 0; i < 6; i++) {
        m = data_msg(1, i, 3);
        EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_REPLAY_HELD);
    }
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 1, 0), XDEV_EXT_REL_REPLAY_ACK);
    EXPECT_EQ(rx.credit, 6);
    for (i = 0; i < 6; i++) {
        m = data_msg(1, i, 4);
        replays += xdev_ext_rel_rx_inspect(&rx, &m) == XDEV_EXT_REL_REPLAY_ACK;
    }
    EXPECT_EQ(submits, 1);
    EXPECT_EQ(replays, 6);
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 1, 0), XDEV_EXT_REL_STALE);
}

static void rejected_hold_and_failed_chain_never_ack(void)
{
    struct xdev_ext_rel_rx rx;
    struct xdev_ext_rel_msg m;
    unsigned i;

    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    m = data_msg(1, 0, 1);
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_HOLD);
    /* Actual C admission failed: deliberately do not commit. */
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_HOLD);
    for (i = 0; i < 6; i++) {
        m = data_msg(1, i, 1);
        EXPECT_EQ(xdev_ext_rel_rx_commit(&rx, &m), i == 5 ? XDEV_EXT_REL_SUBMIT : XDEV_EXT_REL_HOLD);
    }
    EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, 1, -EIO), XDEV_EXT_REL_NONE);
    EXPECT_EQ(rx.credit, 5);
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_RECYCLE);
    m = data_msg(5, 0, 1);
    EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_BACKPRESSURE);
}

static void flow_far_exceeds_window_without_duplicate_devices(void)
{
    struct xdev_ext_rel_tx tx;
    struct xdev_ext_rel_rx rx;
    struct xdev_ext_rel_msg m, ack;
    unsigned group, index, native_accepted = 0, downstream_accepted = 0;

    EXPECT_EQ(xdev_ext_rel_tx_init(&tx, &config), 0);
    EXPECT_EQ(xdev_ext_rel_rx_init(&rx, &config), 0);
    for (group = 1; group <= 1024; group++) {
        EXPECT_EQ(xdev_ext_rel_tx_open(&tx, group, 8192, 6), XDEV_EXT_REL_SEND);
        EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, group, group * 1000), XDEV_EXT_REL_SEND);
        native_accepted++;
        EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, group, 1, 0, false, group * 1000), XDEV_EXT_REL_NONE);
        for (index = 0; index < 6; index++) {
            int action;
            m = data_msg(group, index, 1);
            EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_HOLD);
            action = xdev_ext_rel_rx_commit(&rx, &m);
            EXPECT_EQ(action, index == 5 ? XDEV_EXT_REL_SUBMIT : XDEV_EXT_REL_HOLD);
            downstream_accepted += action == XDEV_EXT_REL_SUBMIT;
        }
        EXPECT_EQ(xdev_ext_rel_rx_finish(&rx, group, 0), XDEV_EXT_REL_REPLAY_ACK);
        /* Lose first ACK every third group; replay original DATA only. */
        if (!(group % 3)) {
            EXPECT_EQ(xdev_ext_rel_tx_poll(&tx, group, group * 1000 + 100), XDEV_EXT_REL_SEND);
            EXPECT_EQ(xdev_ext_rel_tx_native_begin(&tx, group, group * 1000 + 100), XDEV_EXT_REL_SEND);
            native_accepted++;
            for (index = 0; index < 6; index++) {
                m = data_msg(group, index, 2);
                EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_REPLAY_ACK);
            }
            EXPECT_EQ(xdev_ext_rel_tx_native_done(&tx, group, 2, 0, false, group * 1000 + 101), XDEV_EXT_REL_NONE);
        }
        ack = ack_msg(group, rx.credit);
        EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_COMPLETE);
        EXPECT_EQ(xdev_ext_rel_tx_retire(&tx, group), 0);
        EXPECT_EQ(xdev_ext_rel_tx_ack(&tx, &ack), XDEV_EXT_REL_STALE);
        if (group > config.window) {
            m = data_msg(group - config.window, 0, 1);
            EXPECT_EQ(xdev_ext_rel_rx_inspect(&rx, &m), XDEV_EXT_REL_STALE);
        }
    }
    EXPECT_EQ(downstream_accepted, 1024);
    EXPECT_EQ(native_accepted, 1024 + 1024 / 3);
    EXPECT_EQ(tx.base_group, 1025);
    EXPECT_EQ(rx.base_group, 1025);
}

static __u32 crc32c(__u32 crc, const __u8 *p, unsigned len)
{
    unsigned i, bit;
    for (i = 0; i < len; i++) {
        crc ^= p[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
    }
    return crc;
}

static void wire_version_and_crc_are_explicit(void)
{
    struct xdev_ext_rel_msg m = data_msg(2, 2, 1), got;
    __u8 hdr[64], canonical[64], payload[1408] = { 1, 2, 3 };
    __u32 crc, stored;

    EXPECT_EQ(xdev_ext_rel_wire_encode(hdr, &m), 0);
    EXPECT_EQ(hdr[0], 'N'); EXPECT_EQ(hdr[3], '3');
    EXPECT_EQ(hdr[4], 3); EXPECT_EQ(hdr[5], 64);
    EXPECT_EQ(hdr[6], XDEV_EXT_REL_DATA);
    memcpy(canonical, hdr, sizeof(hdr));
    memset(canonical + 56, 0, 4);
    crc = crc32c(0xffffffffU, canonical, 64);
    crc = crc32c(crc, payload, sizeof(payload));
    stored = crc ^ 0xffffffffU;
    hdr[56] = stored >> 24; hdr[57] = stored >> 16;
    hdr[58] = stored >> 8; hdr[59] = stored;
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, sizeof(payload), crc, &config, &got), 0);
    EXPECT_EQ(got.group, 2); EXPECT_EQ(got.index, 2);
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, sizeof(payload), crc ^ 1, &config, &got), XDEV_EXT_REL_BAD);
    hdr[4] = 2;
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, sizeof(payload), crc, &config, &got), XDEV_EXT_REL_BAD);
    hdr[4] = 3; hdr[44] = 1;
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, sizeof(payload), crc, &config, &got), XDEV_EXT_REL_BAD);
}
#endif

int main(void)
{
    existing_group_admission();
#ifdef HAVE_RELIABLE
    local_tx_is_not_chain_ack();
    ack_before_native_completion_pins_frames();
    retry_budget_and_stale_completions();
    accepted_native_error_is_unknown();
    credit_never_counts_duplicate_ack_twice();
    malformed_identity_does_not_mutate();
    oldest_replayed_ack_carries_full_window_progress();
    missing_data_retransmit_submits_once();
    rejected_hold_and_failed_chain_never_ack();
    flow_far_exceeds_window_without_duplicate_devices();
    wire_version_and_crc_are_explicit();
#else
    checks++;
    failures++;
    fprintf(stderr, "FAIL: production reliable state helper is absent: %s\n", RELIABLE_HEADER);
#endif
    printf("reliability behavior: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
