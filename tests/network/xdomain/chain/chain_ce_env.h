/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_CE_ENV_H
#define CHAIN_CE_ENV_H
/* Same file/page ABI as the existing chain; only kernel primitives are replaced. */
#include "chain_core_env.h"
#include "chain_nvme_env.h"

struct mutex { unsigned depth; };
#define __MUTEX_INITIALIZER(n) { 0 }
#define LIST_HEAD_INIT(n) { &(n), &(n) }
#undef mutex_lock
#undef mutex_unlock
#define mutex_lock(m) do { assert(!(m)->depth); (m)->depth++; } while (0)
#define mutex_unlock(m) do { assert((m)->depth == 1); (m)->depth--; } while (0)
#define __init
#define __counted_by(n)
#define late_initcall_sync(fn)
#define kvzalloc(n, flags) chain_kzalloc(n)
#define struct_size(p, m, n) (sizeof(*(p)) + sizeof((p)->m[0]) * (n))
#define VM_MAP 0
#define PAGE_KERNEL 0
struct hrtimer { unsigned unused; };
#endif
