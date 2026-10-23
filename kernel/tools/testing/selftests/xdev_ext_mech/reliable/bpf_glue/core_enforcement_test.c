// SPDX-License-Identifier: GPL-2.0
/*
 * C side of the reliable transport after its protocol decisions moved to
 * BPF: the always-compiled enforcement helpers of
 * xdev_ext_mech_reliable_core.h. A program decides; these helpers accept or
 * refuse its decision against receiver/sender custody, window and credit.
 * A refusal is an errno and leaves the state byte-for-byte unchanged.
 * Production header only; no reliability rule is implemented here. Built
 * without XDEV_EXT_REL_C_GLUE.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"

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
#define EXPECT(c) EXPECT_EQ(!!(c), 1)

static const struct xdev_ext_rel_cfg cfg = {
    .session = 9, .first_group = 1, .timeout_ns = 100,
    .window = 4, .max_attempts = 3, .group_bytes = 8192, .seg_len = 1408,
};

static __u32 sw_crc32c(__u32 crc, const void *buf, size_t len)
{
    const __u8 *p = buf;
    int k;

    while (len--) {
        crc ^= *p++;
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1)));
    }
    return crc;
}

static struct xdev_ext_rel_msg data(__u64 g, __u16 i, __u32 attempt)
{
    return (struct xdev_ext_rel_msg){
        .session = cfg.session, .group = g, .attempt = attempt, .type = XDEV_EXT_REL_DATA,
        .total_len = 8192, .index = i, .count = 6, .relative_offset = i * 1408u,
        .payload_len = i == 5 ? 1152 : 1408,
    };
}

static struct xdev_ext_rel_msg control(__u8 type, __u64 g, __u32 attempt, __u64 credit)
{
    return (struct xdev_ext_rel_msg){
        .session = cfg.session, .group = g, .attempt = attempt, .type = type, .credit = credit,
    };
}

/* Receive every segment of @g and let the device chain finish it with @status
 * (status -1: leave it SUBMITTED). */
static void complete_group(struct xdev_ext_rel_rx *r, __u64 g, int status)
{
    __u16 i;

    for (i = 0; i < 6; i++)
        EXPECT_EQ(xdev_ext_rel_rx_claim(r, g, i, 1),
                  i == 5 ? XDEV_EXT_REL_SUBMIT : XDEV_EXT_REL_HOLD);
    if (status != -1)
        xdev_ext_rel_rx_finish(r, g, status);
}

/* ---------------------------------------------------------------- RX wire */

static void wire_verify_checks_framing_and_crc_only(void)
{
    __u8 hdr[64], payload[1408];
    struct xdev_ext_rel_msg m = data(3, 1, 2);
    __u32 crc;
    unsigned i;

    for (i = 0; i < sizeof(payload); i++)
        payload[i] = (__u8)(i * 13 + 7);
    EXPECT_EQ(xdev_ext_rel_wire_encode(hdr, &m), 0);
    crc = sw_crc32c(sw_crc32c(~0U, hdr, 64), payload, sizeof(payload));
    xdev_ext_rel_put(hdr + 56, crc ^ ~0U, 4);
    EXPECT_EQ(xdev_ext_rel_wire_verify(hdr, crc), 0);
    EXPECT_EQ(xdev_ext_rel_wire_verify(hdr, crc ^ 1), -EBADMSG);

    /* Identity, session and reserved bytes are the program's to judge. */
    xdev_ext_rel_put(hdr + 8, 0xdeadULL, 8);
    hdr[7] = 1;
    memset(hdr + 56, 0, 4);
    crc = sw_crc32c(sw_crc32c(~0U, hdr, 64), payload, sizeof(payload));
    xdev_ext_rel_put(hdr + 56, crc ^ ~0U, 4);
    EXPECT_EQ(xdev_ext_rel_wire_verify(hdr, crc), 0);

    hdr[4] = 2;
    EXPECT_EQ(xdev_ext_rel_wire_verify(hdr, crc), -EBADMSG);
    hdr[4] = XDEV_EXT_REL_VERSION;
    hdr[5] = 63;
    EXPECT_EQ(xdev_ext_rel_wire_verify(hdr, crc), -EBADMSG);
    hdr[5] = 64;
    hdr[0] ^= 0x80;
    EXPECT_EQ(xdev_ext_rel_wire_verify(hdr, crc), -EBADMSG);
}

static void cumulative_ack_has_ack_layout(void)
{
    struct xdev_ext_rel_msg m = control(XDEV_EXT_REL_ACK_CUM, 3, 1, 7), out;
    __u8 hdr[64];
    __u32 crc;

    EXPECT_EQ(XDEV_EXT_REL_ACK_CUM, 4);
    EXPECT_EQ(xdev_ext_rel_layout(&cfg, &m), 0);
    m.total_len = 8192;
    EXPECT_EQ(xdev_ext_rel_layout(&cfg, &m), XDEV_EXT_REL_BAD);
    m.total_len = 0;
    m.credit = 0;
    EXPECT_EQ(xdev_ext_rel_layout(&cfg, &m), XDEV_EXT_REL_BAD);
    m.credit = 7;
    EXPECT_EQ(xdev_ext_rel_wire_encode(hdr, &m), 0);
    EXPECT_EQ(hdr[6], XDEV_EXT_REL_ACK_CUM);
    crc = sw_crc32c(~0U, hdr, 64);
    xdev_ext_rel_put(hdr + 56, crc ^ ~0U, 4);
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, 0, crc, &cfg, &out), 0);
    EXPECT_EQ(out.type, XDEV_EXT_REL_ACK_CUM);
    EXPECT_EQ(out.group, 3);
    EXPECT_EQ(out.credit, 7);
    EXPECT_EQ(xdev_ext_rel_wire_decode(hdr, 0, crc ^ 1, &cfg, &out), XDEV_EXT_REL_BAD);
}

/* ---------------------------------------------------------------- RX view */

static void view_reports_slot_and_window(void)
{
    struct xdev_ext_rel_rx r;
    struct xdev_ext_rel_rx_view v;

    EXPECT_EQ(sizeof(struct xdev_ext_rel_rx_view), 64);
    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    memset(&v, 0xa5, sizeof(v));
    xdev_ext_rel_rx_view_fill(&r, 0, 1, &v);
    EXPECT_EQ(v.group, 1);
    EXPECT_EQ(v.slot_group, 0);
    EXPECT_EQ(v.base_group, 1);
    EXPECT_EQ(v.credit, 5);
    EXPECT_EQ(v.present, 0);
    EXPECT_EQ(v.state, XDEV_EXT_REL_RX_EMPTY);
    EXPECT_EQ(v.owed, 0);
    /* The provider fills these two; view_fill leaves them zero. */
    EXPECT_EQ(v.owed_count, 0);
    EXPECT_EQ(v.must_emit, 0);
    EXPECT_EQ(v.rsvd[0] | v.rsvd[1] | v.rsvd[2], 0);

    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 0, 1), XDEV_EXT_REL_HOLD);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 3, 2), XDEV_EXT_REL_HOLD);
    xdev_ext_rel_rx_view_fill(&r, 77, 2, &v);
    EXPECT_EQ(v.group, 2);
    EXPECT_EQ(v.slot_group, 2);
    EXPECT_EQ(v.present, 0x9);
    EXPECT_EQ(v.state, XDEV_EXT_REL_RX_COLLECT);
    EXPECT_EQ(v.count, 6);
    EXPECT_EQ(v.total_len, 8192);
    EXPECT_EQ(v.latest_attempt, 2);
    EXPECT_EQ(v.owed, 77);
    /* Group 6 maps to the same slot: the view shows what the slot holds. */
    xdev_ext_rel_rx_view_fill(&r, 0, 6, &v);
    EXPECT_EQ(v.group, 6);
    EXPECT_EQ(v.slot_group, 2);
    EXPECT_EQ(v.present, 0x9);
}

/* ----------------------------------------------------------- RX custody */

static void claim_takes_each_segment_once(void)
{
    struct xdev_ext_rel_rx r, before;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, -1);
    EXPECT_EQ(r.entry[1].state, XDEV_EXT_REL_RX_SUBMITTED);
    EXPECT_EQ(r.entry[1].present, 0x3f);

    /* Replayed index: a second custody claim of the same segment. */
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 4, 1), XDEV_EXT_REL_HOLD);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_claim_check(&r, 2, 4, 1), -EEXIST);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 4, 3), -EEXIST);
    EXPECT(!memcmp(&r, &before, sizeof(r)));

    /* Submitted, finished and failed groups take no more custody. */
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 1, 0, 2), -EEXIST);
    xdev_ext_rel_rx_finish(&r, 1, 0);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 1, 0, 2), -EEXIST);
    complete_group(&r, 3, -EIO);
    EXPECT_EQ(r.entry[3].state, XDEV_EXT_REL_RX_FAILED);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 3, 0, 2), -EEXIST);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
}

static void claim_refuses_groups_outside_the_window(void)
{
    struct xdev_ext_rel_rx r, before;
    struct xdev_ext_rel_cfg late = cfg;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 5, 0, 1), -ERANGE);     /* == credit */
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 900, 0, 1), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, ~0ULL - 2, 0, 1), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 0, 0, 1), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 6, 1), -EINVAL);     /* index >= count */
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 0, 0), -EINVAL);     /* attempt 0 */
    EXPECT(!memcmp(&r, &before, sizeof(r)));

    late.first_group = 10;
    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &late), 0);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 9, 0, 1), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 13, 0, 1), XDEV_EXT_REL_HOLD);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 14, 0, 1), -ERANGE);

    /* A retired group whose slot now holds a newer group is below base. */
    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, 0);
    EXPECT_EQ(r.base_group, 2);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 5, 0, 1), XDEV_EXT_REL_HOLD);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 1, 1, 1), -ERANGE);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
}

static void claim_check_is_pure(void)
{
    struct xdev_ext_rel_rx r, before;
    __u64 g;
    __u16 i;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, 0);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 1, 1), XDEV_EXT_REL_HOLD);
    before = r;
    for (g = 0; g < 10; g++)
        for (i = 0; i < 8; i++)
            (void)xdev_ext_rel_rx_claim_check(&r, g, i, 2);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
    EXPECT_EQ(xdev_ext_rel_rx_claim_check(&r, 2, 2, 2), 0);
    EXPECT_EQ(xdev_ext_rel_rx_claim_check(&r, 4, 0, 1), 0);
}

/* -------------------------------------------------------- RX duplicates */

static void verdict_owes_ack_only_for_finished_groups(void)
{
    struct xdev_ext_rel_rx r, before;
    __u64 owed = 0;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, 0);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 1, 2, 2, XDEV_EXT_REL_REPLAY_ACK), 1);
    EXPECT_EQ(owed, 1);
    EXPECT_EQ(r.entry[1].reply, XDEV_EXT_REL_ACK);
    EXPECT_EQ(r.dup_suppressed, 1);
    EXPECT_EQ(r.entry[1].latest_attempt, 2);

    /* An ACK claims downstream completion: refused for a collecting group. */
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 0, 1), XDEV_EXT_REL_HOLD);
    before = r;
    owed = 0;
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 0, 1, XDEV_EXT_REL_REPLAY_ACK), -EINVAL);
    EXPECT_EQ(owed, 0);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
    complete_group(&r, 3, -1);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 3, 0, 1, XDEV_EXT_REL_REPLAY_ACK), -EINVAL);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
    EXPECT_EQ(owed, 0);

    /* Below base the group is finished even after its slot was reused. */
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 5, 0, 1), XDEV_EXT_REL_HOLD);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 1, 0, 4, XDEV_EXT_REL_REPLAY_ACK), 1);
    EXPECT_EQ(owed, 1);
    EXPECT_EQ(r.entry[1].group, 5);
    EXPECT_EQ(r.entry[1].reply, 0);
    EXPECT_EQ(r.entry[1].latest_attempt, 1);
}

static void verdict_held_never_displaces_an_owed_reply(void)
{
    struct xdev_ext_rel_rx r, before;
    __u64 owed = 0;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 2, -1);  /* SUBMITTED: device chain still running */
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 3, 2, XDEV_EXT_REL_REPLAY_HELD), 1);
    EXPECT_EQ(owed, 2);
    EXPECT_EQ(r.entry[2].reply, XDEV_EXT_REL_HELD);
    EXPECT_EQ(r.entry[2].latest_attempt, 2);
    EXPECT_EQ(r.dup_suppressed, 1);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 4, 3, XDEV_EXT_REL_REPLAY_HELD), -EBUSY);
    EXPECT_EQ(owed, 2);
    EXPECT(!memcmp(&r, &before, sizeof(r)));

    /* HELD is only true while the chain runs. */
    owed = 0;
    complete_group(&r, 1, 0);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 1, 0, 2, XDEV_EXT_REL_REPLAY_HELD), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 3, 0, 2, XDEV_EXT_REL_REPLAY_HELD), -EINVAL);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
    EXPECT_EQ(owed, 0);
}

static void verdict_drops_and_counts(void)
{
    struct xdev_ext_rel_rx r, before;
    __u64 owed = 0;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 2, 0, 1), XDEV_EXT_REL_HOLD);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 0, 3, XDEV_EXT_REL_RECYCLE), 0);
    EXPECT_EQ(r.dup_suppressed, 1);
    EXPECT_EQ(r.entry[2].latest_attempt, 3);
    EXPECT_EQ(r.entry[2].present, 1);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 0, 2, XDEV_EXT_REL_RECYCLE), 0);
    EXPECT_EQ(r.entry[2].latest_attempt, 3);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 1, 0, 1, XDEV_EXT_REL_STALE), 0);
    EXPECT_EQ(r.dup_suppressed, 3);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 9, 0, 1, XDEV_EXT_REL_BACKPRESSURE), 0);
    EXPECT_EQ(r.dup_suppressed, 3);
    EXPECT_EQ(owed, 0);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 0, 9, XDEV_EXT_REL_BAD), 0);
    EXPECT(!memcmp(&r, &before, sizeof(r)));

    /* HOLD is a check here; custody is taken at hold commit. */
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 1, 4, XDEV_EXT_REL_HOLD), 0);
    EXPECT_EQ(r.entry[2].present, 1);
    EXPECT_EQ(r.entry[2].latest_attempt, 4);
    EXPECT_EQ(r.dup_suppressed, 3);
    before = r;
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 0, 4, XDEV_EXT_REL_HOLD), -EEXIST);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 7, 0, 4, XDEV_EXT_REL_HOLD), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 1, 4, XDEV_EXT_REL_SUBMIT), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 1, 4, 99), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 0, 1, 4, XDEV_EXT_REL_RECYCLE), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 1, 0, XDEV_EXT_REL_RECYCLE), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, ~0ULL, 1, 1, XDEV_EXT_REL_STALE), -ERANGE);
    EXPECT(!memcmp(&r, &before, sizeof(r)));
    EXPECT_EQ(owed, 0);
}

/* ------------------------------------------------------ control contents */

static void control_contents_are_bounded(void)
{
    struct xdev_ext_rel_rx r;
    struct xdev_ext_rel_msg m;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, 0);
    EXPECT_EQ(r.credit, 6);
    m = control(XDEV_EXT_REL_ACK, 1, 1, 6);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), 0);
    m.credit = 5;
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), 0);
    m.credit = 7;   /* advertises more than the receiver admits */
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -ERANGE);
    m.credit = 4;   /* below the initial window */
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -ERANGE);
    m = control(XDEV_EXT_REL_ACK, 1, 1, 6);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), -EINVAL);   /* not the owed group */
    m.session = 10;
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -EINVAL);
    m = control(XDEV_EXT_REL_ACK, 1, 1, 6);
    m.total_len = 8192;
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -EINVAL);
    m = data(1, 0, 1);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -EINVAL);
    m = control(XDEV_EXT_REL_HELD, 1, 1, 6);  /* HELD for a finished group */
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -EINVAL);

    /* Chain still running: HELD with an attempt the receiver has seen. */
    complete_group(&r, 2, -1);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 3, 0, 1), XDEV_EXT_REL_HOLD);
    {
        __u64 owed = 0;
        EXPECT_EQ(xdev_ext_rel_rx_verdict(&r, &owed, 2, 0, 2, XDEV_EXT_REL_REPLAY_HELD), 1);
    }
    m = control(XDEV_EXT_REL_HELD, 2, 2, 6);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), 0);
    m.attempt = 3;
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), -EINVAL);
    m = control(XDEV_EXT_REL_ACK, 2, 2, 6);   /* ACK before the chain finished */
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), -EINVAL);
    m = control(XDEV_EXT_REL_ACK, 3, 1, 6);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 3, &m), -EINVAL);

    /* A retired group stays ACKable after its slot is reused. */
    xdev_ext_rel_rx_finish(&r, 2, 0);
    EXPECT_EQ(r.base_group, 3);
    EXPECT_EQ(xdev_ext_rel_rx_claim(&r, 5, 0, 1), XDEV_EXT_REL_HOLD);
    m = control(XDEV_EXT_REL_ACK, 1, 1, 7);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), 0);

    /* A failed group is never acknowledged, even with a HELD owed. */
    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, -1);
    xdev_ext_rel_rx_finish(&r, 1, -EIO);
    m = control(XDEV_EXT_REL_ACK, 1, 1, 5);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -EINVAL);
}

static void cumulative_ack_only_below_base(void)
{
    struct xdev_ext_rel_rx r;
    struct xdev_ext_rel_msg m;

    EXPECT_EQ(xdev_ext_rel_rx_init(&r, &cfg), 0);
    complete_group(&r, 1, 0);
    complete_group(&r, 2, 0);
    complete_group(&r, 4, 0);             /* finished, but 3 is not: base stays 3 */
    EXPECT_EQ(r.base_group, 3);
    m = control(XDEV_EXT_REL_ACK_CUM, 2, 1, r.credit);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), 0);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), 0);
    m.group = 1;
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), 0);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), -EINVAL);  /* below the owed group */
    m.group = 3;                          /* claims group 3 finished */
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 1, &m), -EINVAL);
    m.group = 4;
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 4, &m), -EINVAL);  /* 4 done, 3 not */
    m = control(XDEV_EXT_REL_ACK, 4, 1, r.credit);                /* per-group ACK of 4 is fine */
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 4, &m), 0);
    m = control(XDEV_EXT_REL_ACK_CUM, 2, 1, r.credit + 1);
    EXPECT_EQ(xdev_ext_rel_rx_control_check(&r, 2, &m), -ERANGE);
}

/* ----------------------------------------------------------- TX control */

static void tx_send_once(struct xdev_ext_rel_tx *t, __u64 g)
{
    EXPECT_EQ(xdev_ext_rel_tx_open(t, g, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(t, g, 0), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(t, g, 1, 0, false, 0), XDEV_EXT_REL_NONE);
}

static void tx_control_refuses_ack_beyond_window(void)
{
    struct xdev_ext_rel_tx t, before;

    EXPECT_EQ(xdev_ext_rel_tx_init(&t, &cfg), 0);
    tx_send_once(&t, 1);
    before = t;
    /* next_group 2 + window 4 = 6 is the largest credit the sender can trust. */
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 7, XDEV_EXT_REL_ACK), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, ~0ULL, XDEV_EXT_REL_ACK), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 4, XDEV_EXT_REL_ACK), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 7, XDEV_EXT_REL_HELD), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 7, XDEV_EXT_REL_ACK_CUM), -ERANGE);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 0, XDEV_EXT_REL_ACK), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 0, 1, 6, XDEV_EXT_REL_ACK), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 0, 6, XDEV_EXT_REL_ACK), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 6, XDEV_EXT_REL_DATA), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 6, 0), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 6, 5), -EINVAL);
    EXPECT(!memcmp(&t, &before, sizeof(t)));

    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 6, XDEV_EXT_REL_ACK), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(t.credit, 6);
    EXPECT_EQ(t.entry[1].acked, 1);
    before = t;
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 6, XDEV_EXT_REL_ACK), -ESTALE);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 3, 1, 6, XDEV_EXT_REL_ACK), -ESTALE);
    EXPECT(!memcmp(&t, &before, sizeof(t)));
}

static void tx_control_held_and_pending_native(void)
{
    struct xdev_ext_rel_tx t, before;

    EXPECT_EQ(xdev_ext_rel_tx_init(&t, &cfg), 0);
    EXPECT_EQ(xdev_ext_rel_tx_open(&t, 1, 8192, 6), XDEV_EXT_REL_SEND);
    before = t;
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 5, XDEV_EXT_REL_ACK), -EINVAL);  /* never sent */
    EXPECT(!memcmp(&t, &before, sizeof(t)));
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&t, 1, 0), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 2, 5, XDEV_EXT_REL_HELD), -EINVAL);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 5, XDEV_EXT_REL_HELD), XDEV_EXT_REL_NONE);
    EXPECT_EQ(t.entry[1].held_attempt, 1);
    EXPECT_EQ(t.held_acks, 1);
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 5, XDEV_EXT_REL_HELD), -ESTALE);
    /* ACK while the NIC still owns the frames: acked, not yet terminal. */
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 1, 1, 5, XDEV_EXT_REL_ACK), XDEV_EXT_REL_NONE);
    EXPECT_EQ(t.entry[1].acked, 1);
    EXPECT_EQ(t.entry[1].terminal, 0);
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&t, 1, 1, 0, false, 1), XDEV_EXT_REL_COMPLETE);
}

static void tx_cumulative_ack_completes_every_sent_group_up_to(void)
{
    struct xdev_ext_rel_tx t, before;

    EXPECT_EQ(xdev_ext_rel_tx_init(&t, &cfg), 0);
    tx_send_once(&t, 1);
    tx_send_once(&t, 2);
    EXPECT_EQ(xdev_ext_rel_tx_open(&t, 3, 8192, 6), XDEV_EXT_REL_SEND);
    EXPECT_EQ(xdev_ext_rel_tx_native_begin(&t, 3, 0), XDEV_EXT_REL_SEND);   /* NIC owns 3 */
    EXPECT_EQ(xdev_ext_rel_tx_open(&t, 4, 8192, 6), XDEV_EXT_REL_SEND);     /* 4 never sent */
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 4, 1, 7, XDEV_EXT_REL_ACK_CUM), XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(t.entry[1].terminal, XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(t.entry[2].terminal, XDEV_EXT_REL_COMPLETE);
    EXPECT_EQ(t.entry[3].acked, 1);
    EXPECT_EQ(t.entry[3].terminal, 0);
    EXPECT_EQ(t.entry[0].acked, 0);           /* group 4 (slot 0) was never sent */
    EXPECT_EQ(t.credit, 7);
    before = t;
    EXPECT_EQ(xdev_ext_rel_tx_control(&t, 2, 1, 7, XDEV_EXT_REL_ACK_CUM), -ESTALE);
    EXPECT(!memcmp(&t, &before, sizeof(t)));
    EXPECT_EQ(xdev_ext_rel_tx_native_done(&t, 3, 1, 0, false, 1), XDEV_EXT_REL_COMPLETE);
}

/* tx_control is tx_ack's state transition with an errno for each refusal. */
static void tx_control_matches_tx_ack(void)
{
    static const __u8 types[] = { XDEV_EXT_REL_ACK, XDEV_EXT_REL_HELD, XDEV_EXT_REL_DATA };
    unsigned g, a, c, k, step;

    for (step = 0; step < 4; step++)
        for (g = 0; g < 7; g++)
            for (a = 0; a < 4; a++)
                for (c = 0; c < 9; c++)
                    for (k = 0; k < 3; k++) {
                        struct xdev_ext_rel_tx old_t, new_t;
                        struct xdev_ext_rel_msg m = control(types[k], g, a, c);
                        int old_rc, new_rc;
                        unsigned s;

                        EXPECT_EQ(xdev_ext_rel_tx_init(&old_t, &cfg), 0);
                        for (s = 1; s <= step; s++) {
                            EXPECT_EQ(xdev_ext_rel_tx_open(&old_t, s, 8192, 6), XDEV_EXT_REL_SEND);
                            if (s != 2)
                                EXPECT_EQ(xdev_ext_rel_tx_native_begin(&old_t, s, 0), XDEV_EXT_REL_SEND);
                            if (s == 3)
                                EXPECT_EQ(xdev_ext_rel_tx_native_done(&old_t, s, 1, 0, false, 0),
                                          XDEV_EXT_REL_NONE);
                        }
                        new_t = old_t;
                        old_rc = xdev_ext_rel_tx_ack(&old_t, &m);
                        new_rc = xdev_ext_rel_tx_control(&new_t, g, a, c, types[k]);
                        EXPECT(!memcmp(&old_t, &new_t, sizeof(old_t)));
                        if (old_rc == XDEV_EXT_REL_COMPLETE || old_rc == XDEV_EXT_REL_NONE)
                            EXPECT_EQ(new_rc, old_rc);
                        else if (old_rc == XDEV_EXT_REL_STALE)
                            EXPECT_EQ(new_rc, -ESTALE);
                        else
                            EXPECT(new_rc == -EINVAL || new_rc == -ERANGE);
                    }
}

static void selected_group_rechecked_by_c(void)
{
 struct xdev_ext_rel_tx t,before;
 EXPECT_EQ(xdev_ext_rel_tx_init(&t,&cfg),0);
 tx_send_once(&t,1);
 before=t;
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,0,100),-ERANGE);
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,9,100),-ERANGE);
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,2,100),-ESTALE);
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,1,99),-EAGAIN);
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,1,100),0);
 EXPECT(!memcmp(&t,&before,sizeof(t)));
 t.entry[1].native_pending=1;
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,1,100),-EAGAIN);
 t.entry[1].native_pending=0; t.entry[1].attempt=3;
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,1,100),-EREMOTEIO);
 t.entry[1].attempt=1; t.entry[1].acked=1;
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,1,100),-ESTALE);
 t.entry[1].acked=0; t.entry[1].terminal=XDEV_EXT_REL_UNKNOWN;
 EXPECT_EQ(xdev_ext_rel_tx_select_check(&t,1,100),-ESTALE);
}

int main(void)
{
    selected_group_rechecked_by_c();
    wire_verify_checks_framing_and_crc_only();
    cumulative_ack_has_ack_layout();
    view_reports_slot_and_window();
    claim_takes_each_segment_once();
    claim_refuses_groups_outside_the_window();
    claim_check_is_pure();
    verdict_owes_ack_only_for_finished_groups();
    verdict_held_never_displaces_an_owed_reply();
    verdict_drops_and_counts();
    control_contents_are_bounded();
    cumulative_ack_only_below_base();
    tx_control_refuses_ack_beyond_window();
    tx_control_held_and_pending_native();
    tx_cumulative_ack_completes_every_sent_group_up_to();
    tx_control_matches_tx_ack();
    printf("reliable core enforcement: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
