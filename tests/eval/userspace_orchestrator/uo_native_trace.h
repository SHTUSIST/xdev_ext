/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UO_NATIVE_TRACE_H
#define UO_NATIVE_TRACE_H
#include <stdint.h>
#include <errno.h>
/* Each logical group issues exactly one vector command. Fixed I/O is excluded. */
static inline uint64_t uo_native_cookie(uint64_t generation)
{
	return generation < (UINT64_MAX >> 8) ? ((generation + 1) << 8) | 1 : 0;
}
static inline int uo_native_cookie_decode(uint64_t cookie, uint32_t depth,
					 uint32_t *slot, uint64_t *generation)
{
	if (!depth || (cookie & 255) != 1 || !(cookie >> 8))
		return -EPROTO;
	*generation = (cookie >> 8) - 1;
	*slot = *generation % depth;
	return 0;
}
#endif
