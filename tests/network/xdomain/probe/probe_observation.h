/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDOMAIN_PROBE_OBSERVATION_H
#define XDOMAIN_PROBE_OBSERVATION_H
#include "stack_kernel_compat.h"

/* Raw observations only: no probe success predicate or state transitions. */
struct probe_observation {
 unsigned up, logged_in, remote_logged_in, receive_ready, endpoints;
 unsigned requester_binds, data_posts, data_callbacks, native_data_callbacks;
 unsigned native_data_running;
 unsigned retry_failures, retries_exhausted;
 uint64_t link_ups;
 uint64_t local_inc, remote_inc, accepted_inc, response_inc;
 uint64_t announced, consumed;
};
int probe_observe(struct stack_world *, unsigned endpoint,
                  struct probe_observation *);
struct probe_native_facts {
 unsigned accepted, pending, retired, rx128, rx4096, tx128, tx4096;
};
int probe_native_facts(struct stack_world *, unsigned, struct probe_native_facts *);
size_t probe_live_allocations(unsigned endpoint, size_t bytes);
void probe_hold_tx(unsigned endpoint, unsigned type, bool hold);
void probe_corrupt_data(unsigned endpoint, unsigned type, unsigned offset,
                        bool repair_checksum);
void probe_corrupt_repeated(unsigned endpoint, unsigned type, unsigned offset);
void probe_stop_link(unsigned endpoint);
struct probe_retention_facts {
 unsigned generations, retained_generations;
 uint64_t retained_bytes, live_coherent_bytes;
};
void probe_retention_facts(unsigned endpoint, struct probe_retention_facts *);
int probe_show_snapshot(unsigned endpoint, char *buffer);
#endif
