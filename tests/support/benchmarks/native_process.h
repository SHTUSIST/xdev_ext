/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_NATIVE_PROCESS_H
#define XDEV_NATIVE_PROCESS_H
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Kernel nsec_to_clock_t(start_boottime), exported by proc as field 22. */
static inline int native_process_start_ticks(uint64_t *ticks)
{
	char line[4096], *at, *end;
	FILE *f = fopen("/proc/self/stat", "r");
	int field;

	if (!f)
		return -errno;
	at = fgets(line, sizeof(line), f);
	fclose(f);
	if (!at || !(at = strrchr(line, ')')))
		return -EPROTO;
	at += 2;
	for (field = 3; field < 22; field++) {
		at = strchr(at, ' ');
		if (!at)
			return -EPROTO;
		at++;
	}
	errno = 0;
	*ticks = strtoull(at, &end, 10);
	return errno || end == at ? -EPROTO : 0;
}
#endif
