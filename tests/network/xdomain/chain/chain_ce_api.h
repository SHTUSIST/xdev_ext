/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_CE_API_H
#define CHAIN_CE_API_H
/* Native CE class/common-copy runtime with a deterministic simulator boundary.
 * Readback copies directly from the simulator window; it never consults plans.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CHAIN_CE_WINDOW_BYTES (256U * 1024U)
#define CHAIN_CE_POISON 0xa7
struct file;
struct xdev_ext_mech_session;

struct chain_ce_stats {
	unsigned accepted, completed, pending, copies, rejected, host_unbinds, region_unbinds;
	unsigned stale_replays;
	uint64_t bytes;
};

/* Observation only: actual lease metadata, copied under its domain mutex. */
struct chain_ce_lease_snapshot {
	uint32_t active_batches;
	bool quarantined, slot_active, target_range;
	uint64_t generation, range_start, range_len;
};
struct chain_ce_lease_snapshot chain_ce_lease_snapshot(
	struct xdev_ext_mech_session *session, unsigned stage, unsigned slot);

/* Called once per case, before the CE stage binds its simulator fd. */
int chain_ce_init_class(void);
struct file *chain_ce_file(void);
/* Completion pump: returns 1 iff one accepted request completed, else 0. */
int chain_ce_run_one(void);
void chain_ce_hold(bool hold);
/* Next submit returns this status synchronously; 0 disables injection. */
void chain_ce_fail_submit(int status);
/* Accepted requests capture this simulator mode at submission. */
enum chain_ce_mode { CHAIN_CE_OK, CHAIN_CE_PRE_SUBMIT, CHAIN_CE_AMBIGUOUS };
void chain_ce_mode(enum chain_ce_mode mode);
/* Complete one held request, optionally executing its actual simulator copy.
 * Use bytes_done == UINT64_MAX to report the exact simulator copy count. */
int chain_ce_complete_next(int status, bool hw_submitted, bool copy, uint64_t bytes_done);
/* Replay the last ticket through the actual CE completion entry. */
void chain_ce_replay_last(void);
void chain_ce_replay_last_as(int status, bool hw_submitted, uint64_t bytes_done);
struct chain_ce_stats chain_ce_stats(void);
/* Out-of-band verification of the entire device window and untouched guards. */
int chain_ce_read(size_t offset, void *dst, size_t bytes);
void chain_ce_poison(unsigned char value);
#endif
