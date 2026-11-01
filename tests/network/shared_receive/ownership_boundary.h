/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWNERSHIP_BOUNDARY_H
#define OWNERSHIP_BOUNDARY_H
#include <stdint.h>
#include <linux/ethtool.h>
extern unsigned int fixture_netns;
extern int fixture_crash_after_insert;
extern unsigned int fixture_unconditional_detach;
void fixture_init(const char *root);
int fixture_borrowed(unsigned int queue);
void fixture_foreign_xdp(uint32_t id);
uint32_t fixture_current_xdp(void);
int fixture_rule_count(void);
int fixture_get_rule(unsigned int index,struct ethtool_rx_flow_spec *out);
void fixture_replace_rule(const struct ethtool_rx_flow_spec *rule);
void fixture_add_foreign_rule(uint32_t dst_ip,uint16_t dst_port);
int fixture_pin_count(void);
int fixture_corrupt_pin(const char *name);
#endif
