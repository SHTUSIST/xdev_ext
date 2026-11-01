/* SPDX-License-Identifier: GPL-2.0 */
#include "../../../cref/host/bpf/bpf_helpers.h"
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define BPF_MAP_TYPE_HASH 1
void *bpf_map_lookup_elem(const void *map, const void *key);
