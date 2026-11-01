// SPDX-License-Identifier: GPL-2.0
/* Selfcheck catches a byte checker that misses final payload/guard/frame bytes. */
#include <stdio.h>
#include <string.h>
#include "oracle.h"
static unsigned char memory[BT_REGISTERED], expected[BT_GROUP];
int main(void)
{
    memset(memory, BT_POISON, sizeof(memory));
    memset(expected, 0x31, sizeof(expected));
    memcpy(memory + BT_HEADER, expected, sizeof(expected));
    if (bt_verify(memory, expected, 0) != SIZE_MAX) return 1;
    size_t positions[] = {BT_HEADER, BT_HEADER + BT_GROUP - 1,
                          0, BT_HEADER - 1, BT_HEADER + BT_GROUP,
                          BT_FRAME - 1, BT_FRAME, BT_REGISTERED - 1};
    for (unsigned i = 0; i < sizeof(positions)/sizeof(positions[0]); i++) {
        memory[positions[i]] ^= 1;
        if (bt_verify(memory, expected, 0) != positions[i]) {
            fprintf(stderr, "oracle missed corruption at %zu\n", positions[i]);
            return 1;
        }
        memory[positions[i]] ^= 1;
    }
    memset(memory, BT_POISON, sizeof(memory));
    if (bt_verify(memory, NULL, 0) != SIZE_MAX) return 1;
    memory[BT_REGISTERED - 1] ^= 1;
    if (bt_verify(memory, NULL, 0) != BT_REGISTERED - 1) return 1;
    puts("BLOCKTABLE_ORACLE_SELFCHECK=PASS mutations=9 scope=host-oracle-only");
    return 0;
}
