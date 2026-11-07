/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NVME_CE_RANDOM_PRIVATE_LOADER_H
#define NVME_CE_RANDOM_PRIVATE_LOADER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "contract.h"
struct bpf_object;
struct bpf_link;
struct rr_private {
	struct bpf_object *object;
	struct bpf_link *nvme, *ce;
	int map_fd, nvme_fd, ce_fd;
	bool frozen;
};
int rr_private_open(struct rr_private *p, const char *object, size_t records,
		const char *evidence);
int rr_private_fill_freeze(struct rr_private *p, uint64_t session,
		const struct rr_request *rows, size_t count, const char *evidence);
void rr_private_close(struct rr_private *p);
#endif
