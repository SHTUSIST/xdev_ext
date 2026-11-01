/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BLOCKTABLE_GUEST_ORACLE_H
#define BLOCKTABLE_GUEST_ORACLE_H
#include <stddef.h>
#include <stdint.h>
#define BT_FRAME 65536U
#define BT_REGISTERED (4U * BT_FRAME)
#define BT_HEADER 128U
#define BT_GROUP 4096U
#define BT_POISON 0xa6U
static size_t bt_verify(const unsigned char *memory, const unsigned char *expected, unsigned frame)
{
    size_t begin = (size_t)frame * BT_FRAME + BT_HEADER;
    for (size_t i = 0; i < BT_REGISTERED; i++) {
        unsigned char want = expected && i >= begin && i - begin < BT_GROUP
                           ? expected[i - begin] : BT_POISON;
        if (memory[i] != want) return i;
    }
    return SIZE_MAX;
}
#endif
