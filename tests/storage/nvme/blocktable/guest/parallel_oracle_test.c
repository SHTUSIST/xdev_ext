// SPDX-License-Identifier: GPL-2.0
/* Test-only controls for the original full-allocation byte oracle. These do
 * not model a kernel, select a mechanism, open a device or prove native DMA. */
#include <stdio.h>
#include <string.h>
#include "oracle.h"

static unsigned char window[8 * BT_GROUP];
static unsigned char a[BT_REGISTERED], b[BT_REGISTERED];

static void fill(unsigned char *memory, unsigned slot)
{
    memset(memory, BT_POISON, BT_REGISTERED);
    memcpy(memory + BT_HEADER, window + slot * BT_GROUP, BT_GROUP);
}

static int check(int condition, const char *name)
{
    if (!condition) fprintf(stderr, "parallel byte-oracle control failed: %s\n", name);
    return !condition;
}

int main(void)
{
    /* Independent fixture data, not an implementation of NVMe selection.
     * Different slots differ at every position, so fallback/wrong selection
     * cannot pass by observing only common padding or an empty source. */
    for (unsigned slot = 0; slot < 8; slot++)
        for (unsigned i = 0; i < BT_GROUP; i++)
            window[slot * BT_GROUP + i] = (unsigned char)(i * 17U + slot * 29U);
    fill(a, 2); fill(b, 5);
    int failures = 0;
    failures += check(bt_verify(a, window + 2 * BT_GROUP, 0) == SIZE_MAX, "A exact");
    failures += check(bt_verify(b, window + 5 * BT_GROUP, 0) == SIZE_MAX, "B exact");
    failures += check(bt_verify(a, window + 5 * BT_GROUP, 0) != SIZE_MAX, "A/B swap");
    failures += check(bt_verify(b, window + 2 * BT_GROUP, 0) != SIZE_MAX, "B/A swap");
    failures += check(bt_verify(a, window, 0) != SIZE_MAX, "A default slot");
    failures += check(bt_verify(b, window, 0) != SIZE_MAX, "B default slot");
    fill(b, 7);
    failures += check(bt_verify(b, window + 7 * BT_GROUP, 0) == SIZE_MAX, "B continuation exact");
    failures += check(bt_verify(b, window + 5 * BT_GROUP, 0) != SIZE_MAX, "B stale prior payload");

    const size_t positions[] = {
        0, BT_HEADER - 1, BT_HEADER, BT_HEADER + BT_GROUP - 1,
        BT_HEADER + BT_GROUP, BT_FRAME - 1, BT_FRAME, BT_REGISTERED - 1
    };
    for (unsigned i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
        a[positions[i]] ^= 1;
        failures += check(bt_verify(a, window + 2 * BT_GROUP, 0) == positions[i],
                          "A payload/header/padding/unused-frame mutation");
        a[positions[i]] ^= 1;
        failures += check(bt_verify(a, window + 2 * BT_GROUP, 0) == SIZE_MAX,
                          "A restored after mutation");
    }
    /* Checking B never changes A; the continuation must leave A's complete
     * completed-owner allocation equal to its independent slot2 snapshot. */
    failures += check(bt_verify(a, window + 2 * BT_GROUP, 0) == SIZE_MAX,
                      "A remains exact after B continuation");
    if (failures) return 1;
    puts("BLOCKTABLE_PARALLEL_ORACLE_CONTROLS=PASS scope=host-byte-oracle-only");
    return 0;
}
