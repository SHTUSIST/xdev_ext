/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBRARY_INTEGRATION_BOUNDARY_H
#define LIBRARY_INTEGRATION_BOUNDARY_H
struct library_observation {
 unsigned int xsk_closes,umem_unmaps,active_maps;
 unsigned int create_requests,start_requests,stop_requests,stats_requests;
 unsigned int delete_attempts,early_network_cleanup,early_backing_release;
 unsigned int kernel_release_observed,start_saw_valid_fill,custody_violations;
 unsigned int live_xsk_aliases;
};
void library_fixture_init(const char *root);
void library_fixture_payload_prepare(void);
int library_fixture_payload_unchanged(void);
int library_fixture_rings_unseeded(void);
int library_fixture_nonfill_untouched(void);
int library_fixture_fill_valid(void);
struct library_observation library_fixture_observe(void);
void library_fixture_stop_retains(void);
void library_fixture_release_available(void);
void library_fixture_fail_next_rule_delete(void);
#endif
