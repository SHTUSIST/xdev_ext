/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_EPOCH_CONTROL_H
#define XDEV_EXT_EPOCH_CONTROL_H
#include "check_contract.h"
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_policy.h>
#ifdef __cplusplus
extern "C" {
#endif
struct tb_epoch_io {
 void *opaque;
 int (*ring_setup)(void *);      /* fd or negative errno */
 int (*event_open)(void *);      /* fd or negative errno */
 int (*mech)(void *, int ring_fd, uint32_t op, void *arg);
 int (*poll_event)(void *, int event_fd, uint64_t deadline_ns); /* 1 ready, 0 timeout */
 int (*event_read)(void *, int event_fd, uint64_t *value);
 uint64_t (*now_ns)(void *);
 int (*fd_close)(void *, int fd);
};
struct tb_epoch {
 struct tb_guard *guard;
 struct tb_epoch_io io;
 int ring_fd, event_fd;
 uint64_t session_id, groups, first_seq;
 uint32_t nr_stages;
 enum tb_epoch_fate fate;
 int first_error, stop_error;
 bool created, arm_attempted, start_attempted, start_accepted, stop_proved;
};
struct tb_epoch_result {
 enum tb_epoch_fate fate;
 int first_error, stop_error;
 bool start_accepted, stop_proved, stats_valid, transport_valid;
 struct xdev_ext_mech_stats stats;
 struct xdev_ext_mech_transport_stats_v4 transport;
};
int tb_epoch_init(struct tb_epoch *, struct tb_guard *,
                  const struct tb_epoch_io *); /* NULL io selects real syscalls */
int tb_epoch_open(struct tb_epoch *, const struct xdev_ext_mech_create *);
int tb_epoch_start(struct tb_epoch *, uint64_t groups, uint64_t first_seq);
int tb_epoch_wait(struct tb_epoch *, uint64_t deadline_ns,
                  struct tb_epoch_result *);
int tb_epoch_snapshot(struct tb_epoch *, struct tb_epoch_result *);
int tb_epoch_stop(struct tb_epoch *, uint64_t deadline_ns,
                  struct tb_epoch_result *);
int tb_epoch_close(struct tb_epoch *);

#ifdef __cplusplus
}
#endif
#endif /* XDEV_EXT_EPOCH_CONTROL_H */
