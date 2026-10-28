/* SPDX-License-Identifier: GPL-2.0 */
#define STACK_INTERNAL
#include "stack_kernel_compat.h"
void get_random_bytes(void *, size_t);
bool cancel_delayed_work(struct delayed_work *);
int sysfs_emit_at(char *, int, const char *, ...);
#define time_after_eq(a,b) ((long)((a)-(b)) >= 0)
