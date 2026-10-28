/* Independent userspace ownership seam tests, not GPU/DMA simulation. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hft_core.h"

#define REQUIRE(expr) do { if (!(expr)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; \
} } while (0)

static int ready(struct hft_slot *slot)
{
    hft_slot_init(slot, 3);
    REQUIRE(hft_slot_reusable(slot));
    REQUIRE(hft_slot_read_begin(slot, 101) == 0);
    REQUIRE(!hft_slot_reusable(slot));
    REQUIRE(hft_slot_read_complete(slot, 101, 512, 512) == 0);
    REQUIRE(slot->phase == HFT_READY);
    REQUIRE(!hft_slot_reusable(slot));
    return 0;
}

static int result_more_then_notification(void)
{
    struct hft_slot slot;
    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 552, HFT_CQE_MORE) == 0);
    REQUIRE(slot.phase == HFT_WAIT_RELEASE);
    REQUIRE(!hft_slot_reusable(&slot));
    REQUIRE(hft_slot_read_begin(&slot, 201) < 0);
    REQUIRE(hft_slot_send_begin(&slot, 202, 552) < 0);
    REQUIRE(!hft_slot_reusable(&slot));
    REQUIRE(hft_slot_cqe(&slot, 102, 0, HFT_CQE_NOTIF) == 0);
    REQUIRE(hft_slot_reusable(&slot));
    REQUIRE(hft_slot_read_begin(&slot, 201) == 0);
    return 0;
}

static int terminal_result_without_notification(void)
{
    struct hft_slot slot;
    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 552, 0) == 0);
    REQUIRE(hft_slot_reusable(&slot));
    REQUIRE(hft_slot_cqe(&slot, 102, 0, HFT_CQE_NOTIF) < 0);
    REQUIRE(!hft_slot_reusable(&slot));
    return 0;
}

static int errors_and_short_io(void)
{
    struct hft_slot slot;
    const int errors[] = {0, 511, -EIO, -EINTR, -EOPNOTSUPP};
    size_t i;
    for (i = 0; i < sizeof(errors)/sizeof(errors[0]); ++i) {
        hft_slot_init(&slot, 0);
        REQUIRE(hft_slot_read_begin(&slot, 11) == 0);
        REQUIRE(hft_slot_read_complete(&slot, 11, errors[i], 512) < 0);
        REQUIRE(hft_slot_reusable(&slot));
        REQUIRE(ready(&slot) == 0);
        REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
        REQUIRE(hft_slot_cqe(&slot, 102, errors[i], 0) < 0);
        REQUIRE(hft_slot_reusable(&slot));
        REQUIRE(ready(&slot) == 0);
        REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
        REQUIRE(hft_slot_cqe(&slot, 102, errors[i], HFT_CQE_MORE) < 0);
        REQUIRE(!hft_slot_reusable(&slot));
        REQUIRE(hft_slot_cqe(&slot, 102, 0, HFT_CQE_NOTIF) == 0);
        REQUIRE(hft_slot_reusable(&slot));
    }
    return 0;
}

static int wrong_tokens_flags_order_and_duplicates(void)
{
    struct hft_slot slot;
    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    REQUIRE(hft_slot_cqe(&slot, 999, 552, HFT_CQE_MORE) < 0);
    REQUIRE(slot.phase == HFT_UNKNOWN);
    REQUIRE(!hft_slot_reusable(&slot));
    REQUIRE(hft_slot_cqe(&slot, 102, 0, HFT_CQE_NOTIF) < 0);
    REQUIRE(!hft_slot_reusable(&slot));

    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 0, HFT_CQE_NOTIF) < 0);
    REQUIRE(slot.phase == HFT_UNKNOWN);
    REQUIRE(!hft_slot_reusable(&slot));

    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 552, 0x80) < 0);
    REQUIRE(!hft_slot_reusable(&slot));

    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 552, HFT_CQE_MORE) == 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 0,
                         HFT_CQE_NOTIF | HFT_CQE_COPIED) == 0);
    REQUIRE(hft_slot_reusable(&slot));
    REQUIRE(hft_slot_cqe(&slot, 102, 0, HFT_CQE_NOTIF) < 0);
    REQUIRE(!hft_slot_reusable(&slot));
    return 0;
}

static int accepted_failure_never_replayed_or_released(void)
{
    struct hft_slot slot;
    REQUIRE(ready(&slot) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 102, 552) == 0);
    hft_slot_unknown(&slot);
    REQUIRE(slot.phase == HFT_UNKNOWN);
    REQUIRE(!hft_slot_reusable(&slot));
    REQUIRE(hft_slot_send_begin(&slot, 103, 552) < 0);
    REQUIRE(hft_slot_read_begin(&slot, 104) < 0);
    REQUIRE(hft_slot_cqe(&slot, 102, 552, 0) < 0);
    REQUIRE(!hft_slot_reusable(&slot));
    return 0;
}

static int stale_read_generation_and_live_token_preserved(void)
{
    struct hft_slot slot;
    hft_slot_init(&slot, 0);
    REQUIRE(hft_slot_read_begin(&slot, 10) == 0);
    REQUIRE(hft_slot_read_begin(&slot, 11) < 0);
    REQUIRE(hft_slot_read_complete(&slot, 10, 512, 512) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 10, 552) < 0);
    REQUIRE(hft_slot_send_begin(&slot, 12, 552) == 0);
    REQUIRE(hft_slot_send_begin(&slot, 13, 552) < 0);
    REQUIRE(hft_slot_cqe(&slot, 12, 552, 0) == 0);
    REQUIRE(hft_slot_read_begin(&slot, 20) == 0);
    REQUIRE(hft_slot_read_complete(&slot, 10, 512, 512) < 0);
    REQUIRE(!hft_slot_reusable(&slot));
    return 0;
}

static int guards_are_outside_payload_and_lengths_checked(void)
{
    unsigned char allocation[16+512+16];
    size_t i;
    memset(allocation, 0xa5, 16);
    memset(allocation+16, 0x77, 512);
    memset(allocation+528, 0x5a, 16);
    REQUIRE(hft_guards_ok(allocation, sizeof(allocation), 16, 512));
    allocation[128] ^= 1;
    REQUIRE(hft_guards_ok(allocation, sizeof(allocation), 16, 512));
    for (i = 0; i < sizeof(allocation); ++i) {
        if (i >= 16 && i < 528)
            continue;
        allocation[i] ^= 1;
        REQUIRE(!hft_guards_ok(allocation, sizeof(allocation), 16, 512));
        allocation[i] ^= 1;
    }
    REQUIRE(!hft_guards_ok(allocation, sizeof(allocation), SIZE_MAX, 512));
    REQUIRE(!hft_guards_ok(allocation, sizeof(allocation), 16, SIZE_MAX));
    REQUIRE(!hft_guards_ok(allocation, sizeof(allocation), 512, 512));
    return 0;
}

int main(void)
{
    REQUIRE(result_more_then_notification() == 0);
    REQUIRE(terminal_result_without_notification() == 0);
    REQUIRE(errors_and_short_io() == 0);
    REQUIRE(wrong_tokens_flags_order_and_duplicates() == 0);
    REQUIRE(accepted_failure_never_replayed_or_released() == 0);
    REQUIRE(stale_read_generation_and_live_token_preserved() == 0);
    REQUIRE(guards_are_outside_payload_and_lengths_checked() == 0);
    puts("ownership: 7 groups PASS (software lifecycle only)");
    return 0;
}
