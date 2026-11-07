/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KV_CE_PLACE_H
#define KV_CE_PLACE_H
/*
 * Destination of one host-2 restore for kv_ce_place.bpf.c, written by
 * kv_restore into the program's .bss before each START: keys first_key ..
 * first_key + groups - 1, group i at byte dst_off + i * group_bytes of the
 * CE window (the CUDA VMM allocation).  Program-local, not a kernel ABI.
 */
struct kv_ce_target {
	__u64 first_key;
	__u64 groups;		/* 0: no restore; every batch is refused */
	__u64 dst_off;
};

#endif /* KV_CE_PLACE_H */
